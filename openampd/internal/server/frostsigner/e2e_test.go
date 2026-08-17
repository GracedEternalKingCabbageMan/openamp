package frostsigner

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// End-to-end proof that the frost backend sits behind the seam invisibly: a
// server constructed with Signer: "frost" (exactly what -signer=frost gives
// the daemon) issues a restricted asset whose policy key is a FROST group key,
// then completes a hosted transfer whose policy co-signature the 2-of-3 quorum
// produced — and that witness signature verifies as plain BIP340 under the
// on-chain policy key. The node is a mock elementsd; nothing about enclaves,
// contracts, or the wallet flow knows the backend changed.

const (
	e2eFeeID     = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	e2eWalletSpk = "0014000000000000000000000000000000000000f00d"
)

// e2eNode is a minimal mock elementsd. Broadcasts are registered under their
// REAL txid so later builds resolve them as prevouts (the issuance output IS
// the transfer's funding).
type e2eNode struct {
	rawTxs     map[string]string
	scan       map[string][]map[string]any
	unspent    []map[string]any
	blechSeq   int
	blechAddrs map[string]string
	blechConf  map[string]string
	broadcasts []string
}

func newE2ENode() *e2eNode {
	return &e2eNode{
		rawTxs: map[string]string{}, scan: map[string][]map[string]any{},
		blechAddrs: map[string]string{}, blechConf: map[string]string{},
	}
}

func (n *e2eNode) handler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"result": v, "error": nil}) }
	str := func(i int) string {
		if i >= len(req.Params) {
			return ""
		}
		var s string
		_ = json.Unmarshal(req.Params[i], &s)
		return s
	}
	switch req.Method {
	case "getblockhash":
		reply(strings.Repeat("11", 32))
	case "getrawtransaction":
		if raw, ok := n.rawTxs[str(0)]; ok {
			reply(raw)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": nil,
			"error": map[string]any{"code": -5, "message": "No such mempool or blockchain transaction"}})
	case "scantxoutset":
		var descs []string
		if len(req.Params) > 1 {
			_ = json.Unmarshal(req.Params[1], &descs)
		}
		var us []map[string]any
		for _, d := range descs {
			spk := strings.TrimSuffix(strings.TrimPrefix(d, "raw("), ")")
			us = append(us, n.scan[spk]...)
		}
		reply(map[string]any{"success": true, "unspents": us})
	case "listunspent":
		reply(n.unspent)
	case "gettxout":
		reply(map[string]any{"confirmations": 1})
	case "getnewaddress":
		if str(1) == "blech32" {
			n.blechSeq++
			addr := "tsqb-e2e-" + strings.Repeat("a", n.blechSeq)
			n.blechAddrs[addr] = "0014" + strings.Repeat("b1", 18) + hex.EncodeToString([]byte{byte(n.blechSeq), 0})
			n.blechConf[addr] = "02" + strings.Repeat("c2", 31) + hex.EncodeToString([]byte{byte(n.blechSeq)})
			reply(addr)
			return
		}
		reply("e2e-wallet-addr")
	case "getaddressinfo":
		if spk, ok := n.blechAddrs[str(0)]; ok {
			reply(map[string]any{"scriptPubKey": spk, "unconfidential": "", "confidential_key": n.blechConf[str(0)]})
			return
		}
		reply(map[string]any{"scriptPubKey": e2eWalletSpk, "unconfidential": ""})
	case "decodescript":
		reply(map[string]any{"address": "e2e-enclave-unconf"})
	case "createblindedaddress":
		reply("tsqb-e2e-enclave")
	case "signrawtransactionwithwallet":
		reply(map[string]any{"hex": str(0), "complete": true})
	case "testmempoolaccept":
		reply([]any{map[string]any{"allowed": true}})
	case "sendrawtransaction":
		hexTx := str(0)
		tx, err := elements.DeserializeTx(mustHexBytes(hexTx))
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": nil,
				"error": map[string]any{"code": -22, "message": "TX decode failed"}})
			return
		}
		txid := tx.TxID()
		n.rawTxs[txid] = hexTx
		n.broadcasts = append(n.broadcasts, hexTx)
		reply(txid)
	default:
		reply(nil) // createwallet/loadwallet/importaddress/importblindingkey/rescanblockchain
	}
}

func mustHexBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// do drives the server's real router, returning status and decoded JSON.
func do(t *testing.T, h http.Handler, method, path, bearer string, body map[string]any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestFrost_IssueAndTransferEndToEnd(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node := newE2ENode()
	ts := httptest.NewServer(http.HandlerFunc(node.handler))
	t.Cleanup(ts.Close)
	cl, err := rpc.New(ts.URL, "u:p")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{
		FeeAsset: e2eFeeID, FeeSats: 100, DemoIssuer: true, IssuerToken: "tok", Signer: "frost",
	}, st, cl, cl)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Routes()

	// Registered parties; the holder's enclave key signs the transfer leaf.
	var holderPriv [32]byte
	if _, err := rand.Read(holderPriv[:]); err != nil {
		t.Fatal(err)
	}
	holderX := elements.XOnlyFromPriv(holderPriv[:])
	regUser := func(x string) string {
		code, out := do(t, h, "POST", "/v1/users", "", map[string]any{"pubkeys": []string{x}})
		if code != 200 {
			t.Fatalf("register: %d %v", code, out)
		}
		return out["aid"].(string)
	}
	holderAID := regUser(hex.EncodeToString(holderX[:]))
	randUser := func() string {
		var priv [32]byte
		if _, err := rand.Read(priv[:]); err != nil {
			t.Fatal(err)
		}
		x := elements.XOnlyFromPriv(priv[:])
		return regUser(hex.EncodeToString(x[:]))
	}
	recipientAID := randUser()
	issuerAID := randUser()

	// Fee/funding coin.
	fund := &elements.Tx{Version: 2}
	fund.Out = append(fund.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(e2eFeeID)), Value: elements.ExplicitValue(100000),
		Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(e2eWalletSpk),
	})
	fund.NormalizeWitness()
	node.rawTxs[fund.TxID()] = hex.EncodeToString(fund.Serialize())
	node.unspent = []map[string]any{{
		"txid": fund.TxID(), "vout": 0, "amount": 100000.0 / 1e8, "asset": e2eFeeID,
		"scriptPubKey": e2eWalletSpk, "spendable": true, "amountblinder": "", "assetblinder": "",
	}}

	// Issue under the frost backend.
	code, out := do(t, h, "POST", "/v1/issuer/assets", "tok", map[string]any{
		"name": "FROSTX", "ticker": "FROSTX", "precision": 8, "atoms": 1000,
		"holder_aid": holderAID, "issuer_aid": issuerAID,
	})
	if code != 200 {
		t.Fatalf("frost issuance failed: %d %v", code, out)
	}
	assetID := out["asset"].(string)
	issueTxid := out["txid"].(string)

	// The recorded policy key IS the FROST group key stored for the asset.
	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	groupHex, ok := keys["frost:"+assetID+":group"]
	if !ok {
		t.Fatalf("no frost group key bound to asset %s (keys: %v)", assetID, keys)
	}
	for i := 1; i <= 3; i++ {
		if _, ok := keys["frost:"+assetID+":share:"+string(rune('0'+i))]; !ok {
			t.Fatalf("missing frost share %d for asset %s", i, assetID)
		}
	}
	code, assetOut := do(t, h, "GET", "/v1/assets/"+assetID, "", nil)
	if code != 200 || assetOut["policy_pub"] != groupHex {
		t.Fatalf("asset policy_pub %v != stored group key %s", assetOut["policy_pub"], groupHex)
	}

	// The issuance output is the holder's enclave coin; the fee change (vout 2)
	// refunds the wallet for the transfer's fee input.
	code, addrOut := do(t, h, "GET", "/v1/users/"+holderAID+"/address?asset="+assetID, "", nil)
	if code != 200 {
		t.Fatalf("address: %d %v", code, addrOut)
	}
	enclaveSpk := addrOut["script_pubkey"].(string)
	node.scan[enclaveSpk] = []map[string]any{{
		"txid": issueTxid, "vout": 0, "asset": assetID, "amount": 1000.0 / 1e8,
		"scriptPubKey": enclaveSpk, "height": 1,
	}}
	node.unspent = []map[string]any{{
		"txid": issueTxid, "vout": 2, "amount": (100000.0 - 100.0) / 1e8, "asset": e2eFeeID,
		"scriptPubKey": e2eWalletSpk, "spendable": true, "amountblinder": "", "assetblinder": "",
	}}

	// Hosted transfer, co-signed by the frost quorum at completion.
	code, build := do(t, h, "POST", "/v1/transfers", "", map[string]any{
		"asset": assetID, "sender_aid": holderAID, "recipient_aid": recipientAID,
		"atoms": 400, "fee_mode": "sponsor",
	})
	if code != 200 {
		t.Fatalf("transfer build failed: %d %v", code, build)
	}
	toSign := build["to_sign"].([]any)[0].(map[string]any)
	shHex := toSign["sighash"].(string)
	var sh [32]byte
	copy(sh[:], mustHexBytes(shHex))
	userSig, err := elements.SignSchnorr(holderPriv[:], sh)
	if err != nil {
		t.Fatal(err)
	}
	code, done := do(t, h, "POST", "/v1/transfers/"+build["id"].(string)+"/complete", "", map[string]any{
		"sigs": map[string]string{"0": hex.EncodeToString(userSig)},
	})
	if code != 200 {
		t.Fatalf("transfer complete failed: %d %v", code, done)
	}

	// The broadcast witness carries the quorum's policy signature, and it
	// verifies as ordinary BIP340 under the group (policy) key.
	sent, err := elements.DeserializeTx(mustHexBytes(node.broadcasts[len(node.broadcasts)-1]))
	if err != nil {
		t.Fatal(err)
	}
	wit := sent.InWit[0].ScriptWitness
	if len(wit) != 4 {
		t.Fatalf("expected [policySig, userSig, leaf, control] witness, got %d items", len(wit))
	}
	pub, err := schnorr.ParsePubKey(mustHexBytes(groupHex))
	if err != nil {
		t.Fatal(err)
	}
	policySig, err := schnorr.ParseSignature(wit[0])
	if err != nil {
		t.Fatalf("policy witness item is not a schnorr signature: %v", err)
	}
	if !policySig.Verify(sh[:], pub) {
		t.Fatal("the frost quorum's policy signature does not verify under the on-chain policy key")
	}
}
