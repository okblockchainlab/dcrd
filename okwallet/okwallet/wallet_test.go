package okwallet

import (
	"testing"
)

func TestGetAddressByPrivateKey(t *testing.T) {
	prikey1 := `PtWTh9iJ53s5h4MdRhDvz2he2dbZg8hjAJcrJ3fpk34Vcq92LuEYY`
	addr1 := `TseFQTGF1jbiNxnoxeNnjZ8fQhFSuyngM84`
	prikey2 := `PtWTijFxBn8esQLPweK1miDByJENQyZ3rBSHFjzZCym2VJGAndhwx`
	addr2 := `Tsn545kxwZF2r7XVdyAwamtjxWEe3bCQAiX`

	addr, err := GetAddressByPrivateKey("testnet", prikey1)
	if err != nil {
		t.Fatal(err)
	}
	if addr != addr1 {
		t.Fatal("get address from key " + prikey1 + " error. expect " + addr1 + " but return " + addr)
	}

	addr, err = GetAddressByPrivateKey("testnet", prikey2)
	if err != nil {
		t.Fatal(err)
	}
	if addr != addr2 {
		t.Fatal("get address from key " + prikey2 + " error. expect " + addr2 + " but return " + addr)
	}
}

func TestCreateRawTransaction(t *testing.T) {
	inputs := `[{"txid":"a6c492ac1740d6f38c056ed2e45166c7e015614cd2f8428ae1425dd7dbf2f9c8","vout":0,"tree":0,"txtype":0,"address":"TseFQTGF1jbiNxnoxeNnjZ8fQhFSuyngM84","account":"default","scriptPubKey":"76a914911c6152572870b5323815ca16b302222082b24a88ac","amount":15,"confirmations":3,"spendable":true}]`
	to := `{"Tsn545kxwZF2r7XVdyAwamtjxWEe3bCQAiX": 0.2}`
	const expect = `0100000001c8f9f2dbd75d42e18a42f8d24c6115e0c76651e4d26e058cf3d64017ac92c4a60000000000ffffffff01002d31010000000000001976a914e6e838dee0da1112168a8ac7231f17093be0a9e288ac000000000000000001002f68590000000000000000ffffffff00`

	rawTx, err := CreateRawTransaction("testnet", inputs, to, "", "")
	if err != nil {
		t.Fatal(err)
	}

	if expect != rawTx {
		msg := `createrawtransaction failed. expect ` + expect + " but return " + rawTx
		t.Fatal(msg)
	}
}

func TestSignRawTransaction(t *testing.T) {
	rawTx := `0100000001c8f9f2dbd75d42e18a42f8d24c6115e0c76651e4d26e058cf3d64017ac92c4a60000000000ffffffff01002d31010000000000001976a914e6e838dee0da1112168a8ac7231f17093be0a9e288ac000000000000000001002f68590000000000000000ffffffff00`
	inputs := `[{"txid":"a6c492ac1740d6f38c056ed2e45166c7e015614cd2f8428ae1425dd7dbf2f9c8","vout":0,"tree":0,"txtype":0,"address":"TseFQTGF1jbiNxnoxeNnjZ8fQhFSuyngM84","account":"default","scriptPubKey":"76a914911c6152572870b5323815ca16b302222082b24a88ac","amount":15,"confirmations":3,"spendable":true}]`
	privkeys := `["PtWTh9iJ53s5h4MdRhDvz2he2dbZg8hjAJcrJ3fpk34Vcq92LuEYY"]`
	flags := "ALL"
	const expect = `{"hex":"0100000001c8f9f2dbd75d42e18a42f8d24c6115e0c76651e4d26e058cf3d64017ac92c4a60000000000ffffffff01002d31010000000000001976a914e6e838dee0da1112168a8ac7231f17093be0a9e288ac000000000000000001002f68590000000000000000ffffffff6a47304402202e573529b75398a41cfa5ea2c7529974a34b88a5d41311e73eb5815a4c4037d8022015dcf1f6546bcbd779f079c4e3adece0f922baafbcd200b5a8a1af0bf054b67e0121034e864c7dc122bfe6c591250758892ab6a7f0ad8f5b9d9c69d10833b34066359a","complete":true}`

	signedTx, err := SignRawTransaction("testnet", rawTx, inputs, privkeys, flags)
	if err != nil {
		t.Fatal(err)
	}

	if expect != signedTx {
		msg := `signrawtransaction failed. expect ` + expect + " but return " + signedTx
		t.Fatal(msg)
	}
}
