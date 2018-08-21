package main

// #include <jni.h>
import "C"

import (
	"github.com/decred/dcrd/okwallet/okwallet"
	"regexp"
)

const (
	GET_ADDRESS_BY_PRIVATE_KEY_CMD = "getaddressbyprivatekey"
	CREATE_RAW_TRANSACTION_CMD     = "createrawtransaction"
	SIGN_RAW_TRANSACTION           = "signrawtransaction"
)

func setErrorResult(env *C.JNIEnv, errMsg string) C.jobjectArray {
	result := newStringObjectArray(env, 1)
	setObjectArrayStringElement(env, result, 0, errMsg)
	return result
}

func getAddressByPrivateKeyExecute(env *C.JNIEnv, netType string, args []string) C.jobjectArray {
	if len(args) != 1 {
		return setErrorResult(env, "error: "+GET_ADDRESS_BY_PRIVATE_KEY_CMD+" wrong argument count")
	}

	addr, err := okwallet.GetAddressByPrivateKey(netType, args[0])
	if err != nil {
		return setErrorResult(env, "error: "+err.Error())
	}

	result := newStringObjectArray(env, 1)
	setObjectArrayStringElement(env, result, 0, addr)

	return result
}

func createRawTransactionExecute(env *C.JNIEnv, netType string, args []string) C.jobjectArray {
	if len(args) != 4 {
		return setErrorResult(env, "error: "+CREATE_RAW_TRANSACTION_CMD+" wrong argument count")
	}

	rawTx, err := okwallet.CreateRawTransaction(netType, args[0], args[1], args[2], args[3])
	if err != nil {
		return setErrorResult(env, "error: "+err.Error())
	}

	result := newStringObjectArray(env, 1)
	setObjectArrayStringElement(env, result, 0, rawTx)

	return result
}

func SignRawTransactionExecute(env *C.JNIEnv, netType string, args []string) C.jobjectArray {
	if len(args) != 4 {
		return setErrorResult(env, "error: "+SIGN_RAW_TRANSACTION+" wrong argument count")
	}

	signedTx, err := okwallet.SignRawTransaction(netType, args[0], args[1], args[2], args[3])
	if err != nil {
		return setErrorResult(env, "error: "+err.Error())
	}

	result := newStringObjectArray(env, 1)
	setObjectArrayStringElement(env, result, 0, signedTx)

	return result
}

//export Java_com_okcoin_vault_jni_sia_Siaj_execute
func Java_com_okcoin_vault_jni_sia_Siaj_execute(env *C.JNIEnv, _ C.jclass, netTypej C.jstring, jcommand C.jstring) C.jobjectArray {
	netType, err := jstring2string(env, netTypej)
	if err != nil {
		return setErrorResult(env, "error: "+err.Error())
	}
	command, err := jstring2string(env, jcommand)
	if err != nil {
		return setErrorResult(env, "error: "+err.Error())
	}

	sepExp, err := regexp.Compile(`\s+`)
	if err != nil {
		return setErrorResult(env, "error: "+err.Error())
	}

	args := sepExp.Split(command, -1)
	if len(args) < 2 {
		return setErrorResult(env, "error: invalid command")
	}

	switch args[0] {
	case GET_ADDRESS_BY_PRIVATE_KEY_CMD:
		return getAddressByPrivateKeyExecute(env, netType, args[1:])
	case CREATE_RAW_TRANSACTION_CMD:
		return createRawTransactionExecute(env, netType, args[1:])
	case SIGN_RAW_TRANSACTION:
		return SignRawTransactionExecute(env, netType, args[1:])
	default:
		return setErrorResult(env, "error: unknown command: "+args[0])
	}
	return setErrorResult(env, "error: unknown command: "+args[0])
}

func main() {}
