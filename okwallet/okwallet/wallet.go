package okwallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/mempool"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	dcrerrors "github.com/decred/dcrwallet/errors"
	"github.com/decred/slog"
	"os"
	"strconv"
)

const (
	// maxProtocolVersion is the max protocol version the server supports.
	maxProtocolVersion = wire.NodeCFVersion
)

var (
	backendLog = slog.NewBackend(logWriter{})

	rpcsLog = backendLog.Logger("RPCS")

	// sanityVerifyFlags are the flags used to enable and disable features of
	// the txscript engine used for sanity checking of transactions signed by
	// the wallet.
	sanityVerifyFlags = mempool.BaseStandardVerifyFlags
)

// SignatureError records the underlying error when validating a transaction
// input signature.
type SignatureError struct {
	InputIndex uint32
	Error      error
}

// logWriter implements an io.Writer that outputs to both standard output and
// the write-end pipe of an initialized log rotator.
type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)
	return len(p), nil
}

// rpcInvalidError is a convenience function to convert an invalid parameter
// error to an RPC error with the appropriate code set.
func rpcInvalidError(fmtStr string, args ...interface{}) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCInvalidParameter,
		fmt.Sprintf(fmtStr, args...))
}

// rpcDecodeHexError is a convenience function for returning a nicely formatted
// RPC error which indicates the provided hex string failed to decode.
func rpcDecodeHexError(gotHex string) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCDecodeHexString,
		fmt.Sprintf("Argument must be hexadecimal string (not %q)",
			gotHex))
}

// rpcAddressKeyError is a convenience function to convert an address/key error to
// an RPC error with the appropriate code set.  It also logs the error to the
// RPC server subsystem since internal errors really should not occur.  The
// context parameter is only used in the log message and may be empty if it's
// not needed.
func rpcAddressKeyError(fmtStr string, args ...interface{}) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCInvalidAddressOrKey,
		fmt.Sprintf(fmtStr, args...))
}

// rpcInternalError is a convenience function to convert an internal error to
// an RPC error with the appropriate code set.  It also logs the error to the
// RPC server subsystem since internal errors really should not occur.  The
// context parameter is only used in the log message and may be empty if it's
// not needed.
func rpcInternalError(errStr, context string) *dcrjson.RPCError {
	logStr := errStr
	if context != "" {
		logStr = context + ": " + errStr
	}
	rpcsLog.Error(logStr)
	return dcrjson.NewRPCError(dcrjson.ErrRPCInternal.Code, errStr)
}

func rpcError(code dcrjson.RPCErrorCode, err error) *dcrjson.RPCError {
	return &dcrjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

func rpcErrorf(code dcrjson.RPCErrorCode, format string, args ...interface{}) *dcrjson.RPCError {
	return &dcrjson.RPCError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func messageToHex(msg wire.Message) (string, error) {
	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, maxProtocolVersion); err != nil {
		context := fmt.Sprintf("Failed to encode msg of type %T", msg)
		return "", rpcInternalError(err.Error(), context)
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcErrorf(dcrjson.ErrRPCDecodeHexString, "hex string decode failed: %v", err)
	}
	return decoded, nil
}

func getChainParams(netType string) (*chaincfg.Params, error) {
	var chainParams *chaincfg.Params

	if "main" == netType {
		chainParams = &chaincfg.MainNetParams
	} else if "testnet" == netType {
		chainParams = &chaincfg.TestNet3Params
	} else {
		return nil, errors.New("unknown net type")
	}

	return chainParams, nil
}

//reference: Wallet.SignTransaction in project dcrwallet
func signTransaction(chainParams *chaincfg.Params, tx *wire.MsgTx, hashType txscript.SigHashType, additionalPrevScripts map[wire.OutPoint][]byte,
	additionalKeysByAddress map[string]*dcrutil.WIF, p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error) {
	const op dcrerrors.Op = "wallet.signTransaction"

	var doneFuncs []func()
	defer func() {
		for _, f := range doneFuncs {
			f()
		}
	}()

	var signErrors []SignatureError

	for i, txIn := range tx.TxIn {
		// For an SSGen tx, skip the first input as it is a stake base
		// and doesn't need to be signed.
		if i == 0 {
			if stake.IsSSGen(tx) {
				// Put some garbage in the signature script.
				txIn.SignatureScript = []byte{0xDE, 0xAD, 0xBE, 0xEF}
				continue
			}
		}

		prevOutScript, ok := additionalPrevScripts[txIn.PreviousOutPoint]
		if !ok {
			return nil, dcrerrors.E(op, fmt.Errorf("%v not found", txIn.PreviousOutPoint))
		}

		// Set up our callbacks that we pass to txscript so it can
		// look up the appropriate keys and scripts by address.
		getKey := txscript.KeyClosure(func(addr dcrutil.Address) (
			chainec.PrivateKey, bool, error) {
			if len(additionalKeysByAddress) == 0 {
				return nil, false, fmt.Errorf("keys map by address is empty for get key")
			}

			addrStr := addr.EncodeAddress()
			wif, ok := additionalKeysByAddress[addrStr]
			if !ok {
				return nil, false,
					fmt.Errorf("no key for address (needed: %v, have %v)",
						addr.EncodeAddress(), additionalKeysByAddress)
			}
			return wif.PrivKey, true, nil
		})
		getScript := txscript.ScriptClosure(func(
			addr dcrutil.Address) ([]byte, error) {
			// If keys were provided then we can only use the
			// redeem scripts provided with our inputs, too.
			if len(additionalKeysByAddress) == 0 {
				return nil, errors.New("keys map by address is empty for get script")
			}

			addrStr := addr.EncodeAddress()
			script, ok := p2shRedeemScriptsByAddress[addrStr]
			if !ok {
				return nil, errors.New("no script for address")
			}
			return script, nil
		})

		// SigHashSingle inputs can only be signed if there's a
		// corresponding output. However this could be already signed,
		// so we always verify the output.
		if (hashType&txscript.SigHashSingle) !=
			txscript.SigHashSingle || i < len(tx.TxOut) {
			// Check for alternative checksig scripts and
			// set the signature suite accordingly.
			ecType := dcrec.STEcdsaSecp256k1
			class := txscript.GetScriptClass(txscript.DefaultScriptVersion, prevOutScript)
			if class == txscript.PubkeyAltTy ||
				class == txscript.PubkeyHashAltTy {
				var err error
				ecType, err = txscript.ExtractPkScriptAltSigType(prevOutScript)
				if err != nil {
					return nil, dcrerrors.E(op, errors.New("unknown checksigalt signature suite specified"))
				}
			}

			script, err := txscript.SignTxOutput(chainParams,
				tx, i, prevOutScript, hashType, getKey,
				getScript, txIn.SignatureScript, ecType)
			// Failure to sign isn't an error, it just means that
			// the tx isn't complete.
			if err != nil {
				signErrors = append(signErrors, SignatureError{
					InputIndex: uint32(i),
					Error:      dcrerrors.E(op, err),
				})
				continue
			}
			txIn.SignatureScript = script
		}

		// Either it was already signed or we just signed it.
		// Find out if it is completely satisfied or still needs more.
		vm, err := txscript.NewEngine(prevOutScript, tx, i,
			sanityVerifyFlags, txscript.DefaultScriptVersion, nil)
		if err == nil {
			err = vm.Execute()
		}
		if err != nil {
			multisigNotEnoughSigs := false
			class, addr, _, _ := txscript.ExtractPkScriptAddrs(
				txscript.DefaultScriptVersion,
				additionalPrevScripts[txIn.PreviousOutPoint],
				chainParams)

			if txscript.IsErrorCode(err, txscript.ErrInvalidStackOperation) &&
				class == txscript.ScriptHashTy {
				redeemScript, _ := getScript(addr[0])
				redeemClass := txscript.GetScriptClass(
					txscript.DefaultScriptVersion, redeemScript)
				if redeemClass == txscript.MultiSigTy {
					multisigNotEnoughSigs = true
				}
			}
			// Only report an error for the script engine in the event
			// that it's not a multisignature underflow, indicating that
			// we didn't have enough signatures in front of the
			// redeemScript rather than an actual error.
			if !multisigNotEnoughSigs {
				signErrors = append(signErrors, SignatureError{
					InputIndex: uint32(i),
					Error:      dcrerrors.E(op, err),
				})
			}
		}
	}

	return signErrors, nil
}

//reference: some code in signRawTransaction o dcrwallet project.
func GetAddressByPrivateKey(netType string, privk string) (string, error) {
	chainParams, err := getChainParams(netType)
	if err != nil {
		return "", err
	}

	wif, err := dcrutil.DecodeWIF(privk)
	if err != nil {
		return "", fmt.Errorf("decode key error: %v", err)
	}

	if !wif.IsForNet(chainParams) {
		return "", errors.New("key intended for different network")
	}

	var addr dcrutil.Address
	switch wif.DSA() {
	case dcrec.STEcdsaSecp256k1:
		addr, err = dcrutil.NewAddressSecpPubKey(wif.SerializePubKey(), chainParams)
		if err != nil {
			return "", err
		}
	case dcrec.STEd25519:
		addr, err = dcrutil.NewAddressEdwardsPubKey(wif.SerializePubKey(), chainParams)
		if err != nil {
			return "", err
		}
	case dcrec.STSchnorrSecp256k1:
		addr, err = dcrutil.NewAddressSecSchnorrPubKey(wif.SerializePubKey(), chainParams)
		if err != nil {
			return "", err
		}
	}

	return addr.EncodeAddress(), nil
}

//reference: handleCreateRawTransaction
func CreateRawTransaction(netType string, inputs string, addressAmount string, lockTimeStr string, expiryStr string) (string, error) {
	chainParams, err := getChainParams(netType)
	if err != nil {
		return "", err
	}

	var lockTime, expiry *int64
	if len(lockTimeStr) > 0 {
		_lockTime, err := strconv.ParseInt(lockTimeStr, 10, 64)
		if err != nil {
			return "", fmt.Errorf("convert %s to int64 failed. %v", lockTimeStr, err)
		}
		lockTime = &_lockTime
	}
	if len(expiryStr) > 0 {
		_expiry, err := strconv.ParseInt(expiryStr, 10, 64)
		if err != nil {
			return "", fmt.Errorf("convert %s to int64 failed. %v", expiryStr, err)
		}
		expiry = &_expiry
	}

	cmd, err := dcrjson.NewCmd("createrawtransaction", inputs, addressAmount, lockTime, expiry)
	if err != nil {
		return "", err
	}
	c := cmd.(*dcrjson.CreateRawTransactionCmd)

	// Validate expiry, if given.
	if c.Expiry != nil && *c.Expiry < 0 {
		return "", rpcInvalidError("Expiry out of range")
	}

	// Validate the locktime, if given.
	if c.LockTime != nil &&
		(*c.LockTime < 0 ||
			*c.LockTime > int64(wire.MaxTxInSequenceNum)) {
		return "", rpcInvalidError("Locktime out of range")
	}

	// Add all transaction inputs to a new transaction after performing
	// some validity checks.
	mtx := wire.NewMsgTx()
	for _, input := range c.Inputs {
		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return "", rpcDecodeHexError(input.Txid)
		}

		if !(input.Tree == wire.TxTreeRegular ||
			input.Tree == wire.TxTreeStake) {
			return "", rpcInvalidError("Tx tree must be regular or stake")
		}

		prevOutV := wire.NullValueIn
		if input.Amount > 0 {
			amt, err := dcrutil.NewAmount(input.Amount)
			if err != nil {
				return "", rpcInvalidError(err.Error())
			}
			prevOutV = int64(amt)
		}

		prevOut := wire.NewOutPoint(txHash, input.Vout, input.Tree)
		txIn := wire.NewTxIn(prevOut, prevOutV, []byte{})
		if c.LockTime != nil && *c.LockTime != 0 {
			txIn.Sequence = wire.MaxTxInSequenceNum - 1
		}
		mtx.AddTxIn(txIn)
	}

	// Add all transaction outputs to the transaction after performing
	// some validity checks.
	for encodedAddr, amount := range c.Amounts {
		// Ensure amount is in the valid range for monetary amounts.
		if amount <= 0 || amount > dcrutil.MaxAmount {
			return "", rpcInvalidError("Invalid amount: 0 >= %v > %v", amount, dcrutil.MaxAmount)
		}

		// Decode the provided address.
		addr, err := dcrutil.DecodeAddress(encodedAddr)
		if err != nil {
			return "", rpcAddressKeyError("Could not decode address: %v", err)
		}

		// Ensure the address is one of the supported types and that
		// the network encoded with the address matches the network the
		// server is currently on.
		switch addr.(type) {
		case *dcrutil.AddressPubKeyHash:
		case *dcrutil.AddressScriptHash:
		default:
			return "", rpcAddressKeyError("Invalid type: %T", addr)
		}
		if !addr.IsForNet(chainParams) {
			return "", rpcAddressKeyError("Wrong network: %v", addr)
		}

		// Create a new script which pays to the provided address.
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return "", rpcInternalError(err.Error(), "Pay to address script")
		}

		atomic, err := dcrutil.NewAmount(amount)
		if err != nil {
			return "", rpcInternalError(err.Error(), "New amount")
		}

		txOut := wire.NewTxOut(int64(atomic), pkScript)
		mtx.AddTxOut(txOut)
	}

	// Set the Locktime, if given.
	if c.LockTime != nil {
		mtx.LockTime = uint32(*c.LockTime)
	}

	// Set the Expiry, if given.
	if c.Expiry != nil {
		mtx.Expiry = uint32(*c.Expiry)
	}

	// Return the serialized and hex-encoded transaction.  Note that this
	// is intentionally not directly returning because the first return
	// value is a string and it would result in returning an empty string to
	// the client instead of nothing (nil) in the case of an error.
	mtxHex, err := messageToHex(mtx)
	if err != nil {
		return "", err
	}
	return mtxHex, nil
}

//reference: signRawTransaction in project dcrwallet
//rawtx: 00011
//inputs:`[{"txid":"123","vout":1,"tree":0,"scriptPubKey":"00","redeemScript":"01"}]`
//privkeys:`["abc"]`
//flags: "ALL"
func SignRawTransaction(netType, rawTxStr, inputsStr, privKeysStr, flags string) (string, error) {
	chainParams, err := getChainParams(netType)
	if err != nil {
		return "", err
	}

	c, err := dcrjson.NewCmd("signawtransaction", rawTxStr, inputsStr, privKeysStr, flags)
	if err != nil {
		return "", err
	}
	cmd := c.(*dcrjson.SignRawTransactionCmd)

	// TODO: Switch to hex.NewDecoder (introduced in Go 1.10)
	tx := wire.NewMsgTx()
	rawTx, err := hex.DecodeString(cmd.RawTx)
	if err != nil {
		return "", rpcError(dcrjson.ErrRPCDeserialization, err)
	}
	err = tx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return "", rpcError(dcrjson.ErrRPCDeserialization, err)
	}

	var hashType txscript.SigHashType
	switch *cmd.Flags {
	case "ALL":
		hashType = txscript.SigHashAll
	case "NONE":
		hashType = txscript.SigHashNone
	case "SINGLE":
		hashType = txscript.SigHashSingle
	case "ALL|ANYONECANPAY":
		hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	case "NONE|ANYONECANPAY":
		hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	case "SINGLE|ANYONECANPAY":
		hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	case "ssgen": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	case "ssrtx": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	default:
		return "", rpcErrorf(dcrjson.ErrRPCInvalidParameter, "invalid sighash flag")
	}

	// TODO: really we probably should look these up with dcrd anyway to
	// make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	var cmdInputs []dcrjson.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputSha, err := chainhash.NewHashFromStr(rti.Txid)
		if err != nil {
			return "", rpcError(dcrjson.ErrRPCInvalidParameter, err)
		}

		script, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return "", err
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		// Note that redeemScript is NOT only the redeemscript
		// required to be appended to the end of a P2SH output
		// spend, but the entire signature script for spending
		// *any* outpoint with dummy values inserted into it
		// that can later be replacing by txscript's sign.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return "", err
			}

			addr, err := dcrutil.NewAddressScriptHash(redeemScript, chainParams)
			if err != nil {
				return "", err
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[wire.OutPoint{
			Hash:  *inputSha,
			Tree:  rti.Tree,
			Index: rti.Vout,
		}] = script
	}

	// Parse list of private keys, if present. If there are any keys here
	// they are the keys that we may use for signing. If empty we will
	// use any keys known to us already.
	var keys map[string]*dcrutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*dcrutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := dcrutil.DecodeWIF(key)
			if err != nil {
				return "", rpcError(dcrjson.ErrRPCDeserialization, err)
			}

			if !wif.IsForNet(chainParams) {
				return "", rpcErrorf(dcrjson.ErrRPCInvalidParameter, "key intended for different network")
			}

			var addr dcrutil.Address
			switch wif.DSA() {
			case dcrec.STEcdsaSecp256k1:
				addr, err = dcrutil.NewAddressSecpPubKey(wif.SerializePubKey(),
					chainParams)
				if err != nil {
					return "", err
				}
			case dcrec.STEd25519:
				addr, err = dcrutil.NewAddressEdwardsPubKey(
					wif.SerializePubKey(),
					chainParams)
				if err != nil {
					return "", err
				}
			case dcrec.STSchnorrSecp256k1:
				addr, err = dcrutil.NewAddressSecSchnorrPubKey(
					wif.SerializePubKey(),
					chainParams)
				if err != nil {
					return "", err
				}
			}
			keys[addr.EncodeAddress()] = wif
		}
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	signErrs, err := signTransaction(chainParams, tx, hashType, inputs, keys, scripts)
	if err != nil {
		return "", err
	}

	// TODO: Switch to strings.Builder and hex.NewEncoder (introduced in Go 1.10)
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	err = tx.Serialize(&buf)
	if err != nil {
		return "", err
	}

	signErrors := make([]dcrjson.SignRawTransactionError, 0, len(signErrs))
	for _, e := range signErrs {
		input := tx.TxIn[e.InputIndex]
		signErrors = append(signErrors, dcrjson.SignRawTransactionError{
			TxID:      input.PreviousOutPoint.Hash.String(),
			Vout:      input.PreviousOutPoint.Index,
			ScriptSig: hex.EncodeToString(input.SignatureScript),
			Sequence:  input.Sequence,
			Error:     e.Error.Error(),
		})
	}

	result, err := json.Marshal(dcrjson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: len(signErrors) == 0,
		Errors:   signErrors,
	})
	if err != nil {
		return "", err
	}

	return string(result), nil
}
