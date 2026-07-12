package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// OA-8 (opt-in confidential per call, no node flag) and OA-LM (transparency-log
// minimization). Both are additive: a transparent issuance is byte-unchanged and
// only a confidential request reaches the per-call blinding path; the log chain
// is untouched and only the category-event payload becomes a set-hash.

// --- an issuance mock node modelling a -blindedaddresses=0 wallet -------------
//
// The default address (plain getnewaddress) carries NO confidential_key, exactly
// like node000 under -blindedaddresses=0. Only a per-call blech32 address
// (getnewaddress "" "blech32") returns a confidential_key. So if a confidential
// issuance succeeds against this node, it succeeded WITHOUT the node flag.
type issueNode struct {
	defaultAddr string
	defaultSpk  string
	fundTxid    string
	broadcast   string

	blechAddrs    map[string]string // blech32 addr -> its scriptPubKey
	blechConf     map[string]string // blech32 addr -> its confidential_key (blinding pubkey)
	blechSeq      int
	blechAsked    bool // a per-call blech32 address was requested
	blindCalled   bool // rawblindrawtransaction was invoked
	lastBroadcast string
}

func newIssueNode() *issueNode {
	return &issueNode{
		defaultAddr: "sq1defaultwalletaddr",
		defaultSpk:  "0014" + strings.Repeat("aa", 20),
		fundTxid:    strings.Repeat("f0", 32),
		broadcast:   strings.Repeat("b7", 32),
		blechAddrs:  map[string]string{},
		blechConf:   map[string]string{},
	}
}

func (n *issueNode) handler(w http.ResponseWriter, r *http.Request) {
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

	// One funding coin of the fee asset, used both as the issuance funding input
	// (listunspent minconf 1) and as a blinding source (listunspent all).
	fundCoin := map[string]any{
		"txid": n.fundTxid, "vout": 0, "amount": 100000.0 / 1e8,
		"asset": oa4FeeID, "scriptPubKey": n.defaultSpk, "spendable": true,
		"confidential": false, "amountblinder": "", "assetblinder": "",
	}

	switch req.Method {
	case "gettxout":
		reply(map[string]any{"confirmations": 1, "value": 100000.0 / 1e8})
	case "listunspent":
		reply([]any{fundCoin})
	case "getnewaddress":
		if str(1) == "blech32" {
			n.blechAsked = true
			n.blechSeq++
			addr := fmt.Sprintf("tsqb-percall-%d", n.blechSeq)
			n.blechAddrs[addr] = "0014" + fmt.Sprintf("%040x", 0xb0000+n.blechSeq)
			n.blechConf[addr] = "02" + fmt.Sprintf("%064x", 0xc0000+n.blechSeq)
			reply(addr)
			return
		}
		reply(n.defaultAddr)
	case "getaddressinfo":
		addr := str(0)
		if spk, ok := n.blechAddrs[addr]; ok {
			// A per-call blinded address: it carries a confidential_key.
			reply(map[string]any{"scriptPubKey": spk, "unconfidential": "", "confidential_key": n.blechConf[addr]})
			return
		}
		// The default address: NO confidential_key (a -blindedaddresses=0 wallet).
		reply(map[string]any{"scriptPubKey": n.defaultSpk, "unconfidential": "", "confidential_key": ""})
	case "decodescript":
		reply(map[string]any{"address": "sqenclaveunconf"})
	case "createblindedaddress":
		reply("tsqb-enclave-confidential")
	case "rawblindrawtransaction":
		n.blindCalled = true
		reply(str(0)) // echo the tx hex unchanged: structurally valid, round-trips
	case "signrawtransactionwithwallet":
		reply(map[string]any{"hex": str(0), "complete": true})
	case "sendrawtransaction":
		n.lastBroadcast = str(0)
		reply(n.broadcast)
	default:
		reply(nil) // createwallet/loadwallet/importaddress/importblindingkey
	}
}

func newIssueServer(t *testing.T) (*Server, *store.Store, *issueNode) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node := newIssueNode()
	ts := httptest.NewServer(http.HandlerFunc(node.handler))
	t.Cleanup(ts.Close)
	cl, err := rpc.New(ts.URL, "u:p")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg: Config{FeeAsset: oa4FeeID, FeeSats: 100, DemoIssuer: true},
		st:  st, node: cl, wallet: cl,
		pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(st),
	}
	for i := range s.genesis {
		s.genesis[i] = byte(i + 1)
	}
	return s, st, node
}

func callIssue(t *testing.T, s *Server, body map[string]any) (int, map[string]any, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/assets", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleIssue(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// TestOA8_TransparentIssuanceByteUnchanged proves the default (transparent) path
// is untouched by OA-8: every output nonce is null, the token/fee-change outputs
// go to the ordinary wallet address, and NO per-call blinded address and NO
// blinding RPC are used. This is the byte-identity guarantee for BONDX and every
// pre-OA-8 asset.
func TestOA8_TransparentIssuanceByteUnchanged(t *testing.T) {
	s, st, node := newIssueServer(t)
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)

	code, _, body := callIssue(t, s, map[string]any{
		"name": "BONDX", "ticker": "BONDX", "precision": 8, "atoms": 1000000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID,
	})
	if code != 200 {
		t.Fatalf("transparent issuance failed: %d %s", code, body)
	}
	if node.blechAsked {
		t.Fatal("a transparent issuance must NOT request a per-call blinded address")
	}
	if node.blindCalled {
		t.Fatal("a transparent issuance must NOT call rawblindrawtransaction")
	}

	tx, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.In) != 1 || tx.In[0].Issuance == nil {
		t.Fatalf("expected one issuance input, got %d", len(tx.In))
	}
	if len(tx.Out) != 4 {
		t.Fatalf("expected 4 outputs (holder, token, change, fee), got %d", len(tx.Out))
	}
	// Every output nonce is null: nothing is blinded on the transparent path.
	for i, o := range tx.Out {
		if len(o.Nonce) != 1 || o.Nonce[0] != 0 {
			t.Fatalf("output %d has a non-null nonce %x on a transparent issuance", i, o.Nonce)
		}
	}
	// Token (out 1) and fee-change (out 2) go to the ordinary wallet address.
	if hex.EncodeToString(tx.Out[1].ScriptPubKey) != node.defaultSpk {
		t.Fatalf("token output spk = %x, want the ordinary wallet spk", tx.Out[1].ScriptPubKey)
	}
	if hex.EncodeToString(tx.Out[2].ScriptPubKey) != node.defaultSpk {
		t.Fatalf("fee-change output spk = %x, want the ordinary wallet spk", tx.Out[2].ScriptPubKey)
	}
	// The fee output has no scriptPubKey (the network fee).
	if len(tx.Out[3].ScriptPubKey) != 0 {
		t.Fatalf("fee output must have an empty scriptPubKey, got %x", tx.Out[3].ScriptPubKey)
	}
}

// TestOA8_ConfidentialIssuanceOnUnblindedWallet proves a confidential asset
// issues to a blech32 (blinded) enclave output on a -blindedaddresses=0-style
// wallet: the enclave output blinds to the holder's key and the token/fee-change
// outputs blind to per-call blech32 addresses, none of which the node flag
// provides. The default address here has no confidential_key, so success can
// only come from the per-call blech32 path.
func TestOA8_ConfidentialIssuanceOnUnblindedWallet(t *testing.T) {
	s, st, node := newIssueServer(t)
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)

	// The wallet is -blindedaddresses=0: its default address carries no key.
	info, err := s.wallet.GetAddressInfo(node.defaultAddr)
	if err != nil {
		t.Fatal(err)
	}
	if info.ConfidentialKey != "" {
		t.Fatal("harness invalid: the default address must model an unblinded wallet")
	}

	code, out, body := callIssue(t, s, map[string]any{
		"name": "CONFX", "ticker": "CONFX", "precision": 8, "atoms": 1000000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID, "confidential": true,
	})
	if code != 200 {
		t.Fatalf("confidential issuance failed on a -blindedaddresses=0 wallet: %d %s", code, body)
	}
	if !node.blechAsked {
		t.Fatal("confidential issuance must request a per-call blech32 address (no node flag)")
	}
	if !node.blindCalled {
		t.Fatal("confidential issuance must blind the transaction")
	}

	tx, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Out) != 4 {
		t.Fatalf("expected 4 outputs, got %d", len(tx.Out))
	}
	// The enclave (holder) output pays the holder's enclave script and carries a
	// blinding nonce: a confidential (blech32) enclave output.
	assetID, _ := out["asset"].(string)
	var asset *store.Asset
	st.View(func(state *store.State) {
		if a, ok := state.Assets[assetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		t.Fatalf("issued asset %q not recorded", assetID)
	}
	holderTree, err := s.treeFor(holder, asset)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tx.Out[0].ScriptPubKey) != hex.EncodeToString(holderTree.ScriptPubKey()) {
		t.Fatal("enclave output does not pay the holder enclave script")
	}
	if !isBlindingNonce(tx.Out[0].Nonce) {
		t.Fatalf("enclave output is not blinded (nonce %x): expected a confidential enclave output", tx.Out[0].Nonce)
	}
	// The token (out 1) and fee-change (out 2) are blinded to per-call addresses.
	if !isBlindingNonce(tx.Out[1].Nonce) {
		t.Fatalf("token output must be blinded, nonce %x", tx.Out[1].Nonce)
	}
	if !isBlindingNonce(tx.Out[2].Nonce) {
		t.Fatalf("fee-change output must be blinded, nonce %x", tx.Out[2].Nonce)
	}
}

// isBlindingNonce reports whether an output nonce is a 33-byte compressed
// blinding public key (a blinded output), not the 1-byte null nonce.
func isBlindingNonce(nonce []byte) bool {
	return len(nonce) == 33 && (nonce[0] == 0x02 || nonce[0] == 0x03)
}

// --- OA-LM: category-event log minimization ----------------------------------

// TestLM_CategoryEventLogsSetHashNotRawList proves a category event records a
// set-hash commitment that recomputes from the known set and does NOT contain
// the raw category labels.
func TestLM_CategoryEventLogsSetHashNotRawList(t *testing.T) {
	s, st, _ := newOA3Server(t)
	user := regUser(t, st, nil)

	cats := []string{"US_PERSON", "ACCREDITED", "REG_S"}
	b, _ := json.Marshal(map[string]any{"aid": user.AID, "categories": cats})
	req := httptest.NewRequest("POST", "/v1/categories", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleCategories(rec, req)
	if rec.Code != 200 {
		t.Fatalf("set-categories failed: %d %s", rec.Code, rec.Body.String())
	}

	entries, err := readLog(st)
	if err != nil {
		t.Fatal(err)
	}
	var found *store.LogEntry
	for i := range entries {
		if entries[i].Action == "categories" {
			found = &entries[i]
		}
	}
	if found == nil {
		t.Fatal("no categories log entry written")
	}

	// The raw labels must NOT appear in the public log payload.
	payload := string(found.Data)
	for _, c := range cats {
		if strings.Contains(payload, c) {
			t.Fatalf("raw category %q leaked into the transparency log: %s", c, payload)
		}
	}

	// The payload is a versioned commitment that recomputes from the known set.
	var got struct {
		Version        int    `json:"v"`
		AID            string `json:"aid"`
		CategoriesHash string `json:"categories_hash"`
	}
	if err := json.Unmarshal(found.Data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 {
		t.Fatalf("expected format version 1, got %d", got.Version)
	}
	if got.CategoriesHash == "" {
		t.Fatal("no categories_hash in the log entry")
	}
	if got.CategoriesHash != store.CategorySetHash(cats) {
		t.Fatalf("logged set-hash does not recompute from the known set:\n got %s\nwant %s",
			got.CategoriesHash, store.CategorySetHash(cats))
	}
	// Order- and duplicate-independent: the same set in any order/multiplicity
	// yields the same commitment.
	shuffled := []string{"REG_S", "ACCREDITED", "US_PERSON", "REG_S"}
	if store.CategorySetHash(shuffled) != got.CategoriesHash {
		t.Fatal("set-hash must be order- and duplicate-stable")
	}
	// A different set yields a different commitment (the hash is binding).
	if store.CategorySetHash([]string{"ACCREDITED"}) == got.CategoriesHash {
		t.Fatal("set-hash must change when the set changes")
	}
}
