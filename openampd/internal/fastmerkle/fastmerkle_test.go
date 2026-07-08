package fastmerkle

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestDeriveIssuanceIDs(t *testing.T) {
	data, err := os.ReadFile("../elements/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var v struct {
		PrevoutHashInternal string `json:"prevout_hash_internal"`
		Vout                uint32 `json:"vout"`
		ContractDigest      string `json:"contract_digest"`
		Entropy             string `json:"entropy"`
		Asset               string `json:"asset"`
		Token               string `json:"token"`
	}
	if err := json.Unmarshal(raw["issuance_ids"], &v); err != nil {
		t.Fatal(err)
	}
	to32 := func(s string) [32]byte {
		b, _ := hex.DecodeString(s)
		var out [32]byte
		copy(out[:], b)
		return out
	}
	entropy, asset, token := DeriveIssuanceIDs(to32(v.PrevoutHashInternal), v.Vout, to32(v.ContractDigest))
	if hex.EncodeToString(entropy[:]) != v.Entropy {
		t.Errorf("entropy = %x want %s", entropy, v.Entropy)
	}
	if hex.EncodeToString(asset[:]) != v.Asset {
		t.Errorf("asset = %x want %s", asset, v.Asset)
	}
	if hex.EncodeToString(token[:]) != v.Token {
		t.Errorf("token = %x want %s", token, v.Token)
	}
}
