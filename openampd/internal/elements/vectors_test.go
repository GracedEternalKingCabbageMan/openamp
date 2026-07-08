package elements

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func loadVectors(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func hb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hb32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], hb(t, s))
	return out
}

func TestTaggedHashes(t *testing.T) {
	raw := loadVectors(t)
	var vs []struct{ Tag, Msg, Hash string }
	if err := json.Unmarshal(raw["tagged"], &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		got := TaggedHash(v.Tag, hb(t, v.Msg))
		if hex.EncodeToString(got[:]) != v.Hash {
			t.Errorf("TaggedHash(%s, %s) = %x, want %s", v.Tag, v.Msg, got, v.Hash)
		}
	}
}

func TestEnclaveConstruction(t *testing.T) {
	raw := loadVectors(t)
	var v struct {
		UserX           string `json:"user_x"`
		PolicyX         string `json:"policy_x"`
		IssuerX         string `json:"issuer_x"`
		Nums            string `json:"nums"`
		TransferScript  string `json:"transfer_script"`
		ClawScript      string `json:"claw_script"`
		Spk             string `json:"spk"`
		Negflag         int    `json:"negflag"`
		TransferControl string `json:"transfer_control"`
		ClawControl     string `json:"claw_control"`
	}
	if err := json.Unmarshal(raw["enclave"], &v); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(NUMS[:]) != v.Nums {
		t.Fatalf("NUMS mismatch")
	}
	issuer := hb32(t, v.IssuerX)
	tree, err := EnclaveTree(hb32(t, v.UserX), hb32(t, v.PolicyX), &issuer)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tree.Leaves["transfer"].Script); got != v.TransferScript {
		t.Errorf("transfer script = %s want %s", got, v.TransferScript)
	}
	if got := hex.EncodeToString(tree.Leaves["claw"].Script); got != v.ClawScript {
		t.Errorf("claw script = %s want %s", got, v.ClawScript)
	}
	if got := hex.EncodeToString(tree.ScriptPubKey()); got != v.Spk {
		t.Errorf("spk = %s want %s", got, v.Spk)
	}
	if (tree.Parity && v.Negflag != 1) || (!tree.Parity && v.Negflag != 0) {
		t.Errorf("parity = %v want negflag %d", tree.Parity, v.Negflag)
	}
	for name, want := range map[string]string{"transfer": v.TransferControl, "claw": v.ClawControl} {
		cb, err := tree.ControlBlock(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(cb); got != want {
			t.Errorf("%s control = %s want %s", name, got, want)
		}
	}

	// single-leaf variant
	var v1 struct {
		Spk     string `json:"spk"`
		Negflag int    `json:"negflag"`
		Control string `json:"control"`
	}
	if err := json.Unmarshal(raw["enclave_single"], &v1); err != nil {
		t.Fatal(err)
	}
	tree1, err := EnclaveTree(hb32(t, v.UserX), hb32(t, v.PolicyX), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tree1.ScriptPubKey()); got != v1.Spk {
		t.Errorf("single spk = %s want %s", got, v1.Spk)
	}
	cb, _ := tree1.ControlBlock("transfer")
	if got := hex.EncodeToString(cb); got != v1.Control {
		t.Errorf("single control = %s want %s", got, v1.Control)
	}
}

type sighashVec struct {
	Tx       string   `json:"tx"`
	Spent    []string `json:"spent"`
	Genesis  string   `json:"genesis"`
	Input    int      `json:"input"`
	Leaf     string   `json:"leaf"`
	Hashtype byte     `json:"hashtype"`
	Sighash  string   `json:"sighash"`
}

func runSighashVec(t *testing.T, v sighashVec) {
	raw := hb(t, v.Tx)
	tx, err := DeserializeTx(raw)
	if err != nil {
		t.Fatal(err)
	}
	// codec round-trip
	if !bytes.Equal(tx.Serialize(), raw) {
		t.Fatalf("codec round-trip mismatch:\n got %x\nwant %x", tx.Serialize(), raw)
	}
	var spent []*SpentOutput
	for _, s := range v.Spent {
		o, err := DeserializeTxOut(bytes.NewReader(hb(t, s)))
		if err != nil {
			t.Fatal(err)
		}
		spent = append(spent, &SpentOutput{Asset: o.Asset, Value: o.Value, ScriptPubKey: o.ScriptPubKey})
	}
	// genesis in vectors is display order; sighash wants internal
	gd := hb(t, v.Genesis)
	var genesis [32]byte
	for i := 0; i < 32; i++ {
		genesis[i] = gd[31-i]
	}
	got, err := TaprootSighash(tx, spent, v.Hashtype, genesis, v.Input, hb(t, v.Leaf))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != v.Sighash {
		t.Errorf("sighash = %x want %s", got, v.Sighash)
	}
}

func TestSighashVectors(t *testing.T) {
	raw := loadVectors(t)
	var vs []sighashVec
	if err := json.Unmarshal(raw["sighash"], &vs); err != nil {
		t.Fatal(err)
	}
	for i, v := range vs {
		t.Logf("vector %d hashtype %d", i, v.Hashtype)
		runSighashVec(t, v)
	}
	var vi sighashVec
	if err := json.Unmarshal(raw["sighash_issuance"], &vi); err != nil {
		t.Fatal(err)
	}
	runSighashVec(t, vi)
}

func TestSchnorr(t *testing.T) {
	raw := loadVectors(t)
	var v struct{ Sec, Pub, Msg, Sig string }
	if err := json.Unmarshal(raw["schnorr"], &v); err != nil {
		t.Fatal(err)
	}
	// our signing must verify against the framework's pubkey, and the
	// framework's signature must verify under btcec.
	pk, err := schnorr.ParsePubKey(hb(t, v.Pub))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.ParseSignature(hb(t, v.Sig))
	if err != nil {
		t.Fatal(err)
	}
	var msg [32]byte
	copy(msg[:], hb(t, v.Msg))
	if !sig.Verify(msg[:], pk) {
		t.Fatal("framework signature does not verify under btcec")
	}
	ours, err := SignSchnorr(hb(t, v.Sec), msg)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := schnorr.ParseSignature(ours)
	if err != nil {
		t.Fatal(err)
	}
	if !sig2.Verify(msg[:], pk) {
		t.Fatal("our signature does not verify")
	}
	if got := XOnlyFromPriv(hb(t, v.Sec)); hex.EncodeToString(got[:]) != v.Pub {
		t.Fatalf("xonly = %x want %s", got, v.Pub)
	}
}
