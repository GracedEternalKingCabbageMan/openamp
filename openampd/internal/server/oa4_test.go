package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// OA-4 / M6 section 2-3: the mixed-asset proof (checkTransfer tolerates a
// foreign payment leg) and the hosted-builder payment leg (POST /v1/transfers
// with an optional payment {asset, atoms, from_address, to_address}, completed
// with both the enclave and the ordinary payment signatures).

const (
	oa4USDX    = "2a515539da5e6a60caa7766ecd65bac0c10d15717ddd2088844ba58f4d04b9de"
	oa4FeeID   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	oa4FromSpk = "0014000000000000000000000000000000000000dead"
	oa4ToSpk   = "0014000000000000000000000000000000000000beef"
	oa4FeeSpk  = "0014000000000000000000000000000000000000cafe"
	oa4ChgSpk  = "0014000000000000000000000000000000000000face"
)

// explicitOut builds an explicit (transparent) output.
func explicitOut(assetID string, atoms uint64, spkHex string) *elements.TxOut {
	return &elements.TxOut{
		Asset:        elements.ExplicitAsset(elements.MustHex32(assetID)),
		Value:        elements.ExplicitValue(atoms),
		Nonce:        elements.NullNonce(),
		ScriptPubKey: mustHexBytes(spkHex),
	}
}

// --- section 2: the mixed-asset proof ---------------------------------------

// TestOA4_MixedAssetProof proves checkTransfer accepts a two-asset transaction:
// the restricted delivery leg (escrow -> investor enclave) alongside an
// explicit USDX payment leg (escrow -> issuer ordinary address) and a self-paid
// fee, all transparent, in ONE tx. If this fails, closing v2 is infeasible.
func TestOA4_MixedAssetProof(t *testing.T) {
	s, st, _ := newOA3Server(t)
	escrow := regUser(t, st, nil)
	investor := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	asset := oa3Asset(t, issuer.AID, store.Rules{PrimaryAIDs: []string{escrow.AID}})
	if err := st.Update(func(state *store.State) error { state.Assets[asset.ID] = asset; return nil }); err != nil {
		t.Fatal(err)
	}

	investorTree, err := s.treeFor(investor, asset)
	if err != nil {
		t.Fatal(err)
	}

	tx := &elements.Tx{Version: 2}
	// Restricted delivery leg: 1000 atoms to the investor enclave.
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(asset.ID)), Value: elements.ExplicitValue(1000),
		Nonce: elements.NullNonce(), ScriptPubKey: investorTree.ScriptPubKey(),
	})
	// Foreign payment leg: 500000 USDX to an ordinary (non-enclave) address.
	tx.Out = append(tx.Out, explicitOut(oa4USDX, 500000, oa4ToSpk))
	// Self-paid fee, in the fee asset (not the restricted asset).
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(oa4FeeID)), Value: elements.ExplicitValue(100),
		Nonce: elements.NullNonce(), ScriptPubKey: nil,
	})

	atomsOut := map[string]uint64{}
	if err := s.checkTransfer(tx, asset, escrow, atomsOut); err != nil {
		t.Fatalf("MIXED-ASSET PROOF FAILED: checkTransfer rejected the payment leg: %v", err)
	}
	if atomsOut[investor.AID] != 1000 {
		t.Fatalf("restricted leg mis-accounted: got %d atoms to investor, want 1000", atomsOut[investor.AID])
	}
}

// TestOA4_MixedAssetProof_ConfidentialPaymentOutputRejected confirms the whole
// tx must stay transparent: a confidential (blinded) payment output is refused,
// so closing v2's transparency invariant holds.
func TestOA4_MixedAssetProof_ConfidentialPaymentOutputRejected(t *testing.T) {
	s, st, _ := newOA3Server(t)
	escrow := regUser(t, st, nil)
	investor := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	asset := oa3Asset(t, issuer.AID, store.Rules{})
	if err := st.Update(func(state *store.State) error { state.Assets[asset.ID] = asset; return nil }); err != nil {
		t.Fatal(err)
	}
	investorTree, _ := s.treeFor(investor, asset)

	tx := &elements.Tx{Version: 2}
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(asset.ID)), Value: elements.ExplicitValue(1000),
		Nonce: elements.NullNonce(), ScriptPubKey: investorTree.ScriptPubKey(),
	})
	// A confidential asset commitment (0x0a prefix) in the payment output.
	confAsset := make([]byte, 33)
	confAsset[0] = 0x0a
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: confAsset, Value: elements.ExplicitValue(500000), Nonce: elements.NullNonce(),
		ScriptPubKey: mustHexBytes(oa4ToSpk),
	})

	if err := s.checkTransfer(tx, asset, escrow, map[string]uint64{}); err == nil {
		t.Fatal("expected checkTransfer to refuse a confidential payment output")
	}
}

// --- section 3: the hosted-builder payment leg ------------------------------

// oa4Node is a mock elementsd for the build/complete flow.
type oa4Node struct {
	rawTxs     map[string]string            // txid -> raw hex (getrawtransaction / spentOutputs)
	scan       map[string][]rpc.ScanUnspent // spk -> UTXOs (scantxoutset)
	feeUnspent []rpc.Unspent                // listunspent (fee funding)
	addrSpk    map[string]string            // address -> scriptPubKey hex (getaddressinfo)
	newAddr    string                       // getnewaddress
	broadcast  string                       // sendrawtransaction return txid
}

func newOA4Node() *oa4Node {
	return &oa4Node{
		rawTxs:  map[string]string{},
		scan:    map[string][]rpc.ScanUnspent{},
		addrSpk: map[string]string{},
		newAddr: "sqtestchangeaddr",
	}
}

func (n *oa4Node) handler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"result": v, "error": nil}) }
	switch req.Method {
	case "getrawtransaction":
		var txid string
		_ = json.Unmarshal(req.Params[0], &txid)
		if raw, ok := n.rawTxs[txid]; ok {
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
		var us []rpc.ScanUnspent
		for _, d := range descs {
			spk := strings.TrimSuffix(strings.TrimPrefix(d, "raw("), ")")
			us = append(us, n.scan[spk]...)
		}
		reply(map[string]any{"success": true, "unspents": us})
	case "listunspent":
		reply(n.feeUnspent)
	case "getnewaddress":
		reply(n.newAddr)
	case "getaddressinfo":
		var addr string
		_ = json.Unmarshal(req.Params[0], &addr)
		reply(map[string]any{"scriptPubKey": n.addrSpk[addr], "unconfidential": ""})
	case "signrawtransactionwithwallet":
		var hexTx string
		_ = json.Unmarshal(req.Params[0], &hexTx)
		reply(map[string]any{"hex": hexTx, "complete": true})
	case "sendrawtransaction":
		reply(n.broadcast)
	default:
		reply(nil)
	}
}

// oa4Fixture wires a Server (node == wallet == the mock) and registers an
// escrow (with its enclave key), an investor and an issuer under a transparent
// restricted asset whose policy key the LocalKeySigner holds.
type oa4Fixture struct {
	s        *Server
	st       *store.Store
	node     *oa4Node
	asset    *store.Asset
	escrow   *store.User
	escrowKy []byte
	investor *store.User
}

func newOA4Fixture(t *testing.T) *oa4Fixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node := newOA4Node()
	ts := httptest.NewServer(http.HandlerFunc(node.handler))
	t.Cleanup(ts.Close)
	cl, err := rpc.New(ts.URL, "u:p")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg: Config{FeeAsset: oa4FeeID, FeeSats: 100},
		st:  st, node: cl, wallet: cl,
		pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(st),
	}
	for i := range s.genesis {
		s.genesis[i] = byte(i + 1)
	}

	escrow, escrowKy := regUserWithKey(t, st)
	investor := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	asset := oa7Asset(t, st, issuer.AID) // transparent, policy key stored

	f := &oa4Fixture{s: s, st: st, node: node, asset: asset, escrow: escrow, escrowKy: escrowKy, investor: investor}

	// Escrow enclave restricted coin: 1000 atoms.
	escrowTree, _ := s.treeFor(escrow, asset)
	escrowSpk := hex.EncodeToString(escrowTree.ScriptPubKey())
	enclavePrev := &elements.Tx{Version: 2}
	enclavePrev.Out = append(enclavePrev.Out, enclaveOut(t, s, escrow, asset, 1000))
	enclavePrev.NormalizeWitness()
	ePrevID := enclavePrev.TxID()
	node.rawTxs[ePrevID] = hex.EncodeToString(enclavePrev.Serialize())
	node.scan[escrowSpk] = []rpc.ScanUnspent{{TxID: ePrevID, Vout: 0, Asset: asset.ID, Amount: 1000.0 / 1e8, ScriptPubKey: escrowSpk, Height: 1}}

	// Fee coin: 100000 sats of the fee asset.
	feePrev := &elements.Tx{Version: 2}
	feePrev.Out = append(feePrev.Out, explicitOut(oa4FeeID, 100000, oa4FeeSpk))
	feePrev.NormalizeWitness()
	fPrevID := feePrev.TxID()
	node.rawTxs[fPrevID] = hex.EncodeToString(feePrev.Serialize())
	node.feeUnspent = []rpc.Unspent{{TxID: fPrevID, Vout: 0, Amount: 100000.0 / 1e8, Asset: oa4FeeID, ScriptPubKey: oa4FeeSpk, Spendable: true}}

	// Payment coin: 500000 USDX at the escrow's ordinary from_address.
	payPrev := &elements.Tx{Version: 2}
	payPrev.Out = append(payPrev.Out, explicitOut(oa4USDX, 500000, oa4FromSpk))
	payPrev.NormalizeWitness()
	pPrevID := payPrev.TxID()
	node.rawTxs[pPrevID] = hex.EncodeToString(payPrev.Serialize())
	node.scan[oa4FromSpk] = []rpc.ScanUnspent{{TxID: pPrevID, Vout: 0, Asset: oa4USDX, Amount: 500000.0 / 1e8, ScriptPubKey: oa4FromSpk, Height: 1}}

	node.addrSpk[node.newAddr] = oa4ChgSpk
	node.addrSpk["escrow-usdx-addr"] = oa4FromSpk
	node.addrSpk["issuer-payout-addr"] = oa4ToSpk
	node.broadcast = strings.Repeat("77", 32)
	return f
}

// regUserWithKey registers a user and returns it plus its enclave private key.
func regUserWithKey(t *testing.T, st *store.Store) (*store.User, []byte) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	x := elements.XOnlyFromPriv(priv[:])
	xh := hex.EncodeToString(x[:])
	aid := store.AID([]string{xh})
	u := &store.User{AID: aid, Pubkeys: []string{xh}}
	if err := st.Update(func(s *store.State) error { s.Users[aid] = u; return nil }); err != nil {
		t.Fatal(err)
	}
	return u, priv[:]
}

type buildResp struct {
	ID     string `json:"id"`
	Tx     string `json:"tx"`
	ToSign []struct {
		Input   int    `json:"input"`
		Sighash string `json:"sighash"`
		Pubkey  string `json:"pubkey"`
	} `json:"to_sign"`
	PaymentInputs []int `json:"payment_inputs"`
}

func callBuild(t *testing.T, s *Server, body map[string]any) (int, buildResp, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/transfers", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleTransferBuild(rec, req)
	var out buildResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func callComplete(t *testing.T, s *Server, id string, body map[string]any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/transfers/"+id+"/complete", bytes.NewReader(b))
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.handleTransferComplete(rec, req)
	return rec.Code, rec.Body.String()
}

// TestOA4_BuildWithPayment_CompletesAtomically drives the full atomic path: a
// /v1/transfers WITH a payment leg builds a two-asset tx, and /complete with
// BOTH the enclave signature and the payment-input witness co-signs and
// broadcasts.
func TestOA4_BuildWithPayment_CompletesAtomically(t *testing.T) {
	f := newOA4Fixture(t)
	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
		"payment": map[string]any{
			"asset": oa4USDX, "atoms": 500000,
			"from_address": "escrow-usdx-addr", "to_address": "issuer-payout-addr",
		},
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	if len(resp.PaymentInputs) != 1 {
		t.Fatalf("expected 1 payment input, got %v", resp.PaymentInputs)
	}
	if len(resp.ToSign) != 1 {
		t.Fatalf("expected 1 enclave input to sign, got %d", len(resp.ToSign))
	}

	tx, err := elements.DeserializeTx(mustHexBytes(resp.Tx))
	if err != nil {
		t.Fatal(err)
	}
	// Inputs: enclave(0), fee(1), payment(2). Outputs: restricted, payment, fee-change, fee.
	if len(tx.In) != 3 {
		t.Fatalf("expected 3 inputs (enclave, fee, payment), got %d", len(tx.In))
	}
	if resp.PaymentInputs[0] != 2 {
		t.Fatalf("payment input index = %d, want 2", resp.PaymentInputs[0])
	}
	assertHasUSDXOutput(t, tx, 500000, oa4ToSpk)

	// The caller signs the enclave input (its escrow enclave key).
	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, err := elements.SignSchnorr(f.escrowKy, sh32)
	if err != nil {
		t.Fatal(err)
	}
	// The caller signs the payment input with its own wallet: model that by
	// filling the payment input's witness on a body-identical copy of the tx.
	payTx, _ := elements.DeserializeTx(mustHexBytes(resp.Tx))
	payTx.NormalizeWitness()
	payTx.InWit[2].ScriptWitness = [][]byte{bytes.Repeat([]byte{0x33}, 64)}

	code, body = callComplete(t, f.s, resp.ID, map[string]any{
		"sigs":       map[string]string{"0": hex.EncodeToString(sig)},
		"payment_tx": hex.EncodeToString(payTx.Serialize()),
	})
	if code != 200 {
		t.Fatalf("complete failed: %d %s", code, body)
	}
	if !strings.Contains(body, f.node.broadcast) {
		t.Fatalf("expected broadcast txid in response, got %s", body)
	}

	// Consume-once: a replay of the same id is refused (never double-settle).
	code, _ = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 404 {
		t.Fatalf("replay of a consumed transfer should 404, got %d", code)
	}
}

// TestOA4_PaymentPersistsAcrossRestart proves the pending build survives a
// restart: a fresh Server (empty in-memory cache) sharing the same store
// completes the atomic transfer from the persisted record.
func TestOA4_PaymentPersistsAcrossRestart(t *testing.T) {
	f := newOA4Fixture(t)
	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
		"payment": map[string]any{"asset": oa4USDX, "atoms": 500000,
			"from_address": "escrow-usdx-addr", "to_address": "issuer-payout-addr"},
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	// A restart: a new Server with an empty pending cache, same store + node.
	s2 := &Server{cfg: f.s.cfg, st: f.st, node: f.s.node, wallet: f.s.wallet,
		pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(f.st), genesis: f.s.genesis}

	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	payTx, _ := elements.DeserializeTx(mustHexBytes(resp.Tx))
	payTx.NormalizeWitness()
	payTx.InWit[2].ScriptWitness = [][]byte{bytes.Repeat([]byte{0x33}, 64)}

	code, body = callComplete(t, s2, resp.ID, map[string]any{
		"sigs":       map[string]string{"0": hex.EncodeToString(sig)},
		"payment_tx": hex.EncodeToString(payTx.Serialize()),
	})
	if code != 200 {
		t.Fatalf("complete after restart failed: %d %s", code, body)
	}
}

// TestOA4_BuildWithoutPayment_IsUnchanged proves the additive guarantee: a
// /v1/transfers WITHOUT payment behaves exactly as the M5 flow (no payment
// input, no payment_inputs in the response, a plain single-leg delivery), and
// still completes.
func TestOA4_BuildWithoutPayment_IsUnchanged(t *testing.T) {
	f := newOA4Fixture(t)
	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	if strings.Contains(body, "payment_inputs") {
		t.Fatalf("a no-payment build must not surface payment_inputs: %s", body)
	}
	if len(resp.PaymentInputs) != 0 {
		t.Fatalf("expected no payment inputs, got %v", resp.PaymentInputs)
	}
	tx, err := elements.DeserializeTx(mustHexBytes(resp.Tx))
	if err != nil {
		t.Fatal(err)
	}
	// Inputs: enclave(0), fee(1). Outputs: restricted, fee-change, fee. No USDX.
	if len(tx.In) != 2 {
		t.Fatalf("expected 2 inputs (enclave, fee), got %d", len(tx.In))
	}
	for i, o := range tx.Out {
		if hex.EncodeToString(o.Asset) == hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(oa4USDX))) {
			t.Fatalf("output %d unexpectedly carries USDX in a no-payment build", i)
		}
	}

	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 200 {
		t.Fatalf("no-payment complete failed: %d %s", code, body)
	}
}

func assertHasUSDXOutput(t *testing.T, tx *elements.Tx, atoms uint64, spkHex string) {
	t.Helper()
	want := hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(oa4USDX)))
	for _, o := range tx.Out {
		if hex.EncodeToString(o.Asset) != want {
			continue
		}
		amt, _ := elements.ExplicitValueAmount(o.Value)
		if amt == atoms && hex.EncodeToString(o.ScriptPubKey) == spkHex {
			return
		}
	}
	t.Fatalf("expected a %d-atom USDX output to %s in the built tx", atoms, spkHex)
}
