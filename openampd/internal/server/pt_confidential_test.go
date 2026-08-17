package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// decodeJSON unmarshals a response body, failing the test on error.
func decodeJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

// PT: per-transfer confidentiality. An asset is never "a confidential asset";
// any holder may move or receive ANY restricted asset confidentially in a
// given transaction, the unified UTXO read absorbs mixed (explicit + blinded)
// enclave sets everywhere, and the legacy per-asset flag is inert.

// commitmentOut builds an output whose asset/value are commitment-style bytes
// (a blinded output as it appears on-chain) paying the given scriptPubKey.
func commitmentOut(spk []byte) *elements.TxOut {
	asset := append([]byte{0x0a}, mustHexBytes(strings.Repeat("ab", 32))...)
	value := append([]byte{0x09}, mustHexBytes(strings.Repeat("cd", 32))...)
	nonce := append([]byte{0x02}, mustHexBytes(strings.Repeat("ef", 32))...)
	return &elements.TxOut{Asset: asset, Value: value, Nonce: nonce, ScriptPubKey: spk}
}

// seedBlindedEnclaveCoin registers a blinded enclave coin for a user: the raw
// prevout (commitment-style bytes) so spentOutputs/sighashes resolve, plus the
// watch wallet's unblinded listing carrying the blinders.
func seedBlindedEnclaveCoin(t *testing.T, s *Server, node *oa4Node, u *store.User, asset *store.Asset, atoms uint64, marker byte) (txid string) {
	t.Helper()
	tree, err := s.treeFor(u, asset)
	if err != nil {
		t.Fatal(err)
	}
	spk := tree.ScriptPubKey()
	prev := &elements.Tx{Version: 2, LockTime: uint32(marker)} // marker: distinct txid per call
	prev.Out = append(prev.Out, commitmentOut(spk))
	prev.NormalizeWitness()
	id := prev.TxID()
	node.rawTxs[id] = hex.EncodeToString(prev.Serialize())
	node.confUnspent = append(node.confUnspent, rpc.ConfUnspent{
		TxID: id, Vout: 0, ScriptPubKey: hex.EncodeToString(spk),
		Amount: float64(atoms) / 1e8, Asset: asset.ID,
		AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
	})
	return id
}

// TestPT_MixedLifecycle drives the full per-transfer arc on ONE ordinary
// (transparently minted) asset: an explicit enclave coin moves CONFIDENTIALLY
// (outputs blinded to the derived keys, per-call blinded fee change, blinding
// RPC over the explicit input via the prevout fallback), then the resulting
// mixed enclave set (blinded change + a fresh explicit coin) moves
// TRANSPARENTLY (asset legs explicit as requested, with the one blinded
// balancing fee-change output consensus requires over blinded inputs),
// selecting across both coins.
func TestPT_MixedLifecycle(t *testing.T) {
	f := newOA4Fixture(t) // escrow holds 1000 explicit atoms; asset has no flags

	// --- Phase A: explicit coin, confidential transfer ---
	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 400, "fee_mode": "sponsor", "confidential": true,
	})
	if code != 200 {
		t.Fatalf("confidential build failed: %d %s", code, body)
	}
	if !f.node.blindCalled {
		t.Fatal("a confidential transfer must run the blinding RPC (input blinders supplied, zero for the explicit input)")
	}
	tx, err := elements.DeserializeTx(mustHexBytes(resp.Tx))
	if err != nil {
		t.Fatal(err)
	}
	investorTree, _ := f.s.treeFor(f.investor, f.asset)
	escrowTree, _ := f.s.treeFor(f.escrow, f.asset)
	if hex.EncodeToString(tx.Out[0].ScriptPubKey) != hex.EncodeToString(investorTree.ScriptPubKey()) {
		t.Fatal("recipient output does not pay the investor enclave")
	}
	if !isBlindingNonce(tx.Out[0].Nonce) {
		t.Fatalf("recipient output must blind to the investor's derived key, nonce %x", tx.Out[0].Nonce)
	}
	if hex.EncodeToString(tx.Out[1].ScriptPubKey) != hex.EncodeToString(escrowTree.ScriptPubKey()) || !isBlindingNonce(tx.Out[1].Nonce) {
		t.Fatalf("change output must blind back to the sender's enclave key, nonce %x", tx.Out[1].Nonce)
	}
	if hex.EncodeToString(tx.Out[0].Nonce) == hex.EncodeToString(tx.Out[1].Nonce) {
		t.Fatal("recipient and sender blinding keys must be distinct derivations")
	}
	if !isBlindingNonce(tx.Out[2].Nonce) {
		t.Fatalf("fee change must be a per-call blinded wallet output, nonce %x", tx.Out[2].Nonce)
	}
	// The pre-blind explicit copy is persisted for the policy check.
	if rec, ok := f.st.GetPendingTransfer(resp.ID); !ok || rec.ExplicitTxHex == "" {
		t.Fatalf("a blinded build must persist its pre-blind explicit copy (ok=%v)", ok)
	}
	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 200 {
		t.Fatalf("confidential complete failed: %d %s", code, body)
	}

	// --- Phase B: mixed enclave set, transparent transfer of the change ---
	// New chain state: the blinded 600-atom change plus a fresh 100-atom
	// explicit coin.
	f.node.blindCalled = false
	escrowSpk := hex.EncodeToString(escrowTree.ScriptPubKey())
	seedBlindedEnclaveCoin(t, f.s, f.node, f.escrow, f.asset, 600, 0x01)
	freshPrev := &elements.Tx{Version: 2, LockTime: 0x02}
	freshPrev.Out = append(freshPrev.Out, enclaveOut(t, f.s, f.escrow, f.asset, 100))
	freshPrev.NormalizeWitness()
	freshID := freshPrev.TxID()
	f.node.rawTxs[freshID] = hex.EncodeToString(freshPrev.Serialize())
	f.node.scan[escrowSpk] = []rpc.ScanUnspent{{TxID: freshID, Vout: 0, Asset: f.asset.ID, Amount: 100.0 / 1e8, ScriptPubKey: escrowSpk, Height: 2}}

	code, resp, body = callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 650, "fee_mode": "sponsor", "confidential": false,
	})
	if code != 200 {
		t.Fatalf("transparent build over a mixed set failed: %d %s", code, body)
	}
	if len(resp.ToSign) != 2 {
		t.Fatalf("expected BOTH coins selected (explicit preferred, blinded to cover the rest), got %d inputs", len(resp.ToSign))
	}
	tx, err = elements.DeserializeTx(mustHexBytes(resp.Tx))
	if err != nil {
		t.Fatal(err)
	}
	// Asset legs are explicit, exactly as requested.
	if amt, ok := elements.ExplicitValueAmount(tx.Out[0].Value); !ok || amt != 650 {
		t.Fatalf("recipient output must be explicit 650 atoms, got %x", tx.Out[0].Value)
	}
	if len(tx.Out[0].Nonce) != 1 || tx.Out[0].Nonce[0] != 0 {
		t.Fatalf("recipient output must carry a null nonce on a transparent build, got %x", tx.Out[0].Nonce)
	}
	if amt, ok := elements.ExplicitValueAmount(tx.Out[1].Value); !ok || amt != 50 {
		t.Fatalf("change output must be explicit 50 atoms, got %x", tx.Out[1].Value)
	}
	if len(tx.Out[1].Nonce) != 1 || tx.Out[1].Nonce[0] != 0 {
		t.Fatalf("change output must carry a null nonce, got %x", tx.Out[1].Nonce)
	}
	// The one blinded output consensus requires over blinded inputs: fee change.
	if !isBlindingNonce(tx.Out[2].Nonce) {
		t.Fatalf("fee change must blind to absorb the blinded input's factors, nonce %x", tx.Out[2].Nonce)
	}
	if !f.node.blindCalled {
		t.Fatal("a transparent build spending a blinded input must still run the blinding RPC")
	}
	sigs := map[string]string{}
	for i, ts := range resp.ToSign {
		sh := mustHexBytes(ts.Sighash)
		copy(sh32[:], sh)
		sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
		sigs[strconv.Itoa(resp.ToSign[i].Input)] = hex.EncodeToString(sig)
	}
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": sigs})
	if code != 200 {
		t.Fatalf("transparent complete over a mixed set failed: %d %s", code, body)
	}
}

func intToStr(i int) string {
	return string(rune('0' + i)) // input indices in these fixtures are single digits
}

// TestPT_AddressEndpointBothForms proves GET /address serves both forms for
// ANY asset: the plain request returns the bech32m address (and still imports
// the script + blinding key into the watch wallet, so later blinded receipts
// are readable), ?confidential=1 promotes the blech32 form to the primary
// address, and both responses carry address_confidential.
func TestPT_AddressEndpointBothForms(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	user := regUser(t, st, nil)
	asset, _ := clawAsset(t, st, issuer.AID, false) // an ordinary asset, no flags

	get := func(query string) (int, map[string]any) {
		req := httptest.NewRequest("GET", "/v1/users/"+user.AID+"/address?asset="+asset.ID+query, nil)
		req.SetPathValue("aid", user.AID)
		rec := httptest.NewRecorder()
		s.handleAddress(rec, req)
		var out map[string]any
		decodeJSON(t, rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := get("")
	if code != 200 {
		t.Fatalf("plain address failed: %d %v", code, out)
	}
	if out["address"] != "sqenclaveunconf" {
		t.Fatalf("plain request must return the unblinded address, got %v", out["address"])
	}
	if out["address_confidential"] != "tsqb-enclave-confidential" {
		t.Fatalf("the blinded form must always be included, got %v", out["address_confidential"])
	}
	if out["confidential"] != false {
		t.Fatalf("confidential must echo the request (false), got %v", out["confidential"])
	}
	// The PLAIN request must already import script + blinding key, so a blinded
	// receipt to this enclave is readable even if the holder never asked for
	// the blech32 form.
	if node.imports.Load() < 1 || node.blindImports.Load() < 1 {
		t.Fatalf("plain address request must import script+key into the watch wallet, got %d/%d",
			node.imports.Load(), node.blindImports.Load())
	}

	code, out = get("&confidential=1")
	if code != 200 {
		t.Fatalf("confidential address failed: %d %v", code, out)
	}
	if out["address"] != "tsqb-enclave-confidential" {
		t.Fatalf("?confidential=1 must return the blech32 address, got %v", out["address"])
	}
	if out["confidential"] != true {
		t.Fatalf("confidential must echo the request (true), got %v", out["confidential"])
	}
}

// TestPT_UnifiedBalanceDedupes proves the unified read counts an explicit UTXO
// once even when BOTH sources list it (scantxoutset and the watch wallet's
// listunspent on the imported script), and adds watch-only blinded UTXOs.
func TestPT_UnifiedBalanceDedupes(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder := regUser(t, st, nil)
	asset, _ := clawAsset(t, st, issuer.AID, false)
	tree, _ := s.treeFor(holder, asset)
	spk := hex.EncodeToString(tree.ScriptPubKey())

	// One explicit coin, listed by BOTH sources (same outpoint).
	expTxid := strings.Repeat("31", 32)
	node.scan[spk] = []rpc.ScanUnspent{{TxID: expTxid, Vout: 0, Asset: asset.ID, Amount: 100.0 / 1e8, ScriptPubKey: spk, Height: 1}}
	node.confUnspent = append(node.confUnspent, rpc.ConfUnspent{
		TxID: expTxid, Vout: 0, ScriptPubKey: spk, Amount: 100.0 / 1e8, Asset: asset.ID,
	})
	// One blinded coin only the watch wallet sees.
	node.confUnspent = append(node.confUnspent, rpc.ConfUnspent{
		TxID: strings.Repeat("32", 32), Vout: 0, ScriptPubKey: spk, Amount: 250.0 / 1e8, Asset: asset.ID,
		AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
	})

	req := httptest.NewRequest("GET", "/v1/users/"+holder.AID+"/balance?asset="+asset.ID, nil)
	req.SetPathValue("aid", holder.AID)
	rec := httptest.NewRecorder()
	s.handleBalance(rec, req)
	var out struct {
		Atoms uint64 `json:"atoms"`
		UTXOs int    `json:"utxos"`
	}
	decodeJSON(t, rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Atoms != 350 || out.UTXOs != 2 {
		t.Fatalf("unified balance must dedupe by outpoint: want 350 atoms over 2 utxos, got %d over %d (%s)",
			out.Atoms, out.UTXOs, rec.Body.String())
	}
}

// TestPT_LegacyConfidentialFlagReadsUnified proves a stored asset carrying the
// legacy Confidential=true flag reads balances over the SAME unified view: its
// explicit UTXOs (which the old per-asset branch would have missed, reading
// only the watch wallet) count alongside its blinded ones.
func TestPT_LegacyConfidentialFlagReadsUnified(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder := regUser(t, st, nil)
	asset, _ := clawAsset(t, st, issuer.AID, false)
	makeConfidential(t, st, asset.ID) // legacy flag: must be inert
	tree, _ := s.treeFor(holder, asset)
	spk := hex.EncodeToString(tree.ScriptPubKey())

	node.scan[spk] = []rpc.ScanUnspent{{TxID: strings.Repeat("41", 32), Vout: 0, Asset: asset.ID, Amount: 500.0 / 1e8, ScriptPubKey: spk, Height: 1}}
	node.confUnspent = append(node.confUnspent, rpc.ConfUnspent{
		TxID: strings.Repeat("42", 32), Vout: 0, ScriptPubKey: spk, Amount: 250.0 / 1e8, Asset: asset.ID,
		AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
	})

	req := httptest.NewRequest("GET", "/v1/users/"+holder.AID+"/balance?asset="+asset.ID, nil)
	req.SetPathValue("aid", holder.AID)
	rec := httptest.NewRecorder()
	s.handleBalance(rec, req)
	var out struct {
		Atoms uint64 `json:"atoms"`
	}
	decodeJSON(t, rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Atoms != 750 {
		t.Fatalf("legacy-flag asset must read the unified balance (750), got %d (%s)", out.Atoms, rec.Body.String())
	}
}

// TestPT_CosignRefusalKeysOnBlindedOutputsNotAsset proves the cosign refusal
// moved from the asset flag to the transaction: a fully explicit self-built
// transfer of an asset carrying the legacy Confidential=true flag co-signs
// fine, while a transaction containing a blinded OUTPUT is refused with the
// transparent-only message, and a CLAIMED input spending a blinded prevout is
// refused with its own message.
func TestPT_CosignRefusalKeysOnBlindedOutputsNotAsset(t *testing.T) {
	s, st, rawTxs := newOA7Server(t)
	escrow := regUser(t, st, nil)
	recipient := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	asset := oa7Asset(t, st, issuer.AID)
	makeConfidential(t, st, asset.ID) // legacy flag: no longer a refusal reason

	prev := &elements.Tx{Version: 2}
	prev.Out = append(prev.Out,
		enclaveOut(t, s, escrow, asset, 100), // vout 0: explicit enclave coin
	)
	escrowTree, _ := s.treeFor(escrow, asset)
	prev.Out = append(prev.Out, commitmentOut(escrowTree.ScriptPubKey())) // vout 1: blinded enclave coin
	prev.NormalizeWitness()
	prevID := prev.TxID()
	rawTxs[prevID] = hex.EncodeToString(prev.Serialize())

	// (a) Explicit tx of the legacy-flagged asset: co-signed (no asset refusal).
	tx := &elements.Tx{Version: 2}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 0}})
	tx.Out = append(tx.Out, enclaveOut(t, s, recipient, asset, 100))
	tx.NormalizeWitness()
	code, body := callCosign(t, s, tx, asset, escrow.AID, []int{0})
	if code != 200 {
		t.Fatalf("an explicit self-built transfer must co-sign regardless of the legacy asset flag, got %d: %s", code, body)
	}

	// (b) A blinded OUTPUT in the submitted tx: refused, transparent-only.
	txB := &elements.Tx{Version: 2}
	txB.In = append(txB.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 0}})
	txB.Out = append(txB.Out, commitmentOut(escrowTree.ScriptPubKey()))
	txB.NormalizeWitness()
	code, body = callCosign(t, s, txB, asset, escrow.AID, []int{0})
	if code != 400 || !strings.Contains(body, "transparent-only") {
		t.Fatalf("a blinded output must refuse with the transparent-only message, got %d: %s", code, body)
	}

	// (c) A CLAIMED input spending a blinded prevout: refused with its message.
	txC := &elements.Tx{Version: 2}
	txC.In = append(txC.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 1}})
	txC.Out = append(txC.Out, enclaveOut(t, s, recipient, asset, 100))
	txC.NormalizeWitness()
	code, body = callCosign(t, s, txC, asset, escrow.AID, []int{0})
	if code != 400 || !strings.Contains(body, "spends a blinded enclave output") {
		t.Fatalf("a claimed blinded input must be refused, got %d: %s", code, body)
	}
}

// TestPT_ClawbackMixedInputsBlindsSweep proves a clawback sweeping a MIXED
// holder set (one explicit coin, one blinded coin) totals both, blinds the
// seized output (the blinded amounts stay private), and broadcasts in one
// legacy call.
func TestPT_ClawbackMixedInputsBlindsSweep(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, false) // server-held issuer key
	fundClawback(t, s, node, holder, asset, 400)    // explicit 400 (scan + raw)
	seedBlindedEnclaveCoin(t, s, node, holder, asset, 600, 0x03)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "mixed sweep",
	})
	if code != 200 {
		t.Fatalf("mixed clawback failed: %d %s", code, body)
	}
	if got := uint64(out["atoms"].(float64)); got != 1000 {
		t.Fatalf("sweep must total the mixed set (1000 atoms), got %d", got)
	}
	if !node.blindCalled {
		t.Fatal("a sweep over any blinded input must blind the transaction")
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	issuerTree, _ := s.treeFor(issuer, asset)
	if hex.EncodeToString(sent.Out[0].ScriptPubKey) != hex.EncodeToString(issuerTree.ScriptPubKey()) {
		t.Fatal("seized output does not pay the issuer enclave")
	}
	if !isBlindingNonce(sent.Out[0].Nonce) {
		t.Fatalf("the seized output must blind when any swept input is blinded, nonce %x", sent.Out[0].Nonce)
	}
	if !isBlindingNonce(sent.Out[1].Nonce) {
		t.Fatalf("the fee change must blind too, nonce %x", sent.Out[1].Nonce)
	}
}

// TestPT_PaymentLegRefusesConfidential proves the OA-4 atomic payment leg only
// combines with a fully transparent build: "confidential": true is refused up
// front, and a transparent request that would need blinded coins is refused at
// selection.
func TestPT_PaymentLegRefusesConfidential(t *testing.T) {
	f := newOA4Fixture(t)
	payment := map[string]any{
		"asset": oa4USDX, "atoms": 500000,
		"from_address": "escrow-usdx-addr", "to_address": "issuer-payout-addr",
	}
	code, _, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor", "confidential": true, "payment": payment,
	})
	if code != 400 || !strings.Contains(body, "payment leg") {
		t.Fatalf("payment + confidential must be refused, got %d: %s", code, body)
	}

	// Replace the escrow's explicit coin with a blinded one: a transparent
	// payment build can no longer be funded explicitly and must be refused.
	escrowTree, _ := f.s.treeFor(f.escrow, f.asset)
	f.node.scan[hex.EncodeToString(escrowTree.ScriptPubKey())] = nil
	seedBlindedEnclaveCoin(t, f.s, f.node, f.escrow, f.asset, 1000, 0x04)
	code, _, body = callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor", "payment": payment,
	})
	if code != 409 || !strings.Contains(body, "explicit enclave coins") {
		t.Fatalf("payment over blinded funding must be refused, got %d: %s", code, body)
	}
}
