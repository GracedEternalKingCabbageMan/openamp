package server

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// W-5: confidential-path completions. A confidential asset's clawback sweep
// blinds the seized output (instead of leaking the amount against blinded
// inputs), a confidential DR mint blinds the minted enclave output, and the
// watch wallet reconciles its imports (plus one rescan) on startup.

// makeConfidential flips a stored asset to confidential.
func makeConfidential(t *testing.T, st *store.Store, assetID string) {
	t.Helper()
	if err := st.Update(func(s *store.State) error {
		s.Assets[assetID].Confidential = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// fundClawbackConf seeds the mock for a CONFIDENTIAL clawback: the holder's
// enclave coin is a blinded UTXO the watch wallet reports (with blinders), plus
// a fee coin and the change address. Mirrors fundClawback for the blinded case.
func fundClawbackConf(t *testing.T, s *Server, node *oa4Node, holder *store.User, asset *store.Asset, atoms uint64) {
	t.Helper()
	holderTree, err := s.treeFor(holder, asset)
	if err != nil {
		t.Fatal(err)
	}
	holderSpk := hex.EncodeToString(holderTree.ScriptPubKey())
	enclavePrev := &elements.Tx{Version: 2}
	enclavePrev.Out = append(enclavePrev.Out, enclaveOut(t, s, holder, asset, atoms))
	enclavePrev.NormalizeWitness()
	ePrevID := enclavePrev.TxID()
	node.rawTxs[ePrevID] = hex.EncodeToString(enclavePrev.Serialize())
	// The watch wallet unblinds the enclave coin: listunspent reports it with
	// its blinders (a confidential UTXO), never scantxoutset.
	node.confUnspent = append(node.confUnspent, rpc.ConfUnspent{
		TxID: ePrevID, Vout: 0, ScriptPubKey: holderSpk,
		Amount: float64(atoms) / 1e8, Asset: asset.ID,
		AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
		Confidential: true,
	})

	feePrev := &elements.Tx{Version: 2}
	feePrev.Out = append(feePrev.Out, explicitOut(oa4FeeID, 100000, oa4FeeSpk))
	feePrev.NormalizeWitness()
	fPrevID := feePrev.TxID()
	node.rawTxs[fPrevID] = hex.EncodeToString(feePrev.Serialize())
	node.feeUnspent = []rpc.Unspent{{TxID: fPrevID, Vout: 0, Amount: 100000.0 / 1e8, Asset: oa4FeeID, ScriptPubKey: oa4FeeSpk, Spendable: true}}

	node.addrSpk[node.newAddr] = oa4ChgSpk
	node.broadcast = strings.Repeat("77", 32)
}

// TestW5_ConfidentialClawback_TwoPhase proves a confidential asset's two-phase
// clawback build blinds the seized output and the fee change (the >=2 blinded
// outputs discipline), computes the issuer sighashes over the BLINDED tx (the
// pending build IS the blinded tx with a fixed txid), keeps the
// reason-before-signing property, and completes idempotently: a replay returns
// the same txid and never re-broadcasts.
func TestW5_ConfidentialClawback_TwoPhase(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, issuerPriv := clawAsset(t, st, issuer.AID, true) // external issuer
	makeConfidential(t, st, asset.ID)
	asset.Confidential = true
	fundClawbackConf(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "confidential seizure",
	})
	if code != 200 {
		t.Fatalf("confidential clawback build failed: %d %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("build must broadcast nothing, saw %d sends", node.sends)
	}
	if !node.blindCalled {
		t.Fatal("a confidential clawback build must blind the transaction")
	}
	if !logHasClawbackReason(t, st, "confidential seizure") {
		t.Fatal("the reason must be logged before any signature")
	}

	// The pending build is the BLINDED sweep: seized output (0) blinds to the
	// issuer's enclave key, the fee change (1) to a per-call blech32 output.
	id, _ := out["id"].(string)
	pc, ok := st.GetPendingClawback(id)
	if !ok {
		t.Fatal("no pending clawback persisted")
	}
	built, err := elements.DeserializeTx(mustHexBytes(pc.TxHex))
	if err != nil {
		t.Fatal(err)
	}
	issuerTree, _ := s.treeFor(issuer, asset)
	if hex.EncodeToString(built.Out[0].ScriptPubKey) != hex.EncodeToString(issuerTree.ScriptPubKey()) {
		t.Fatal("seized output does not pay the issuer enclave")
	}
	if !isBlindingNonce(built.Out[0].Nonce) {
		t.Fatalf("seized output must be blinded for a confidential asset, nonce %x", built.Out[0].Nonce)
	}
	if !isBlindingNonce(built.Out[1].Nonce) {
		t.Fatalf("fee-change output must be blinded (>=2 blinded outputs), nonce %x", built.Out[1].Nonce)
	}
	// The logged txid is the blinded tx's txid: the fixed txid a retry rebroadcasts.
	fixedTxid := built.TxID()

	// COMPLETE: issuer signs the blinded-tx sighashes; the broadcast bytes carry
	// the same txid as the pending build (witnesses don't change a txid).
	toSign, _ := out["to_sign"].([]any)
	sigs := signToSign(t, toSign[0], issuerPriv)
	code, out2, body := callClawbackComplete(t, s, id, map[string]any{"sigs": sigs})
	if code != 200 {
		t.Fatalf("confidential clawback complete failed: %d %s", code, body)
	}
	if node.sends != 1 {
		t.Fatalf("complete must broadcast exactly once, saw %d", node.sends)
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if sent.TxID() != fixedTxid {
		t.Fatalf("broadcast txid %s != the pending build's fixed txid %s", sent.TxID(), fixedTxid)
	}

	// Retry (persist-before-broadcast idempotency): the identical tx, same txid,
	// no second broadcast.
	code, out2, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sigs})
	if code != 200 || out2["idempotent"] != true {
		t.Fatalf("replay must be idempotent: %d %s", code, body)
	}
	if node.sends != 1 {
		t.Fatalf("replay must not re-broadcast, saw %d sends", node.sends)
	}
}

// TestW5_ConfidentialClawback_LegacySingleCall proves the legacy (server-held
// issuer key) clawback of a confidential asset also blinds the seized output
// and still completes in one gated call.
func TestW5_ConfidentialClawback_LegacySingleCall(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, false) // server holds the issuer key
	makeConfidential(t, st, asset.ID)
	asset.Confidential = true
	fundClawbackConf(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "legacy confidential sweep",
	})
	if code != 200 {
		t.Fatalf("legacy confidential clawback failed: %d %s", code, body)
	}
	if out["txid"] != node.broadcast {
		t.Fatalf("legacy clawback must broadcast in one call, got %s", body)
	}
	if !node.blindCalled {
		t.Fatal("a confidential clawback must blind the transaction")
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if !isBlindingNonce(sent.Out[0].Nonce) {
		t.Fatalf("seized output must be blinded, nonce %x", sent.Out[0].Nonce)
	}
}

// TestW5_ConfidentialReissueBlindsMint proves a DR mint of a confidential asset
// carries the holder's blinding nonce on the minted enclave output and runs the
// blinding RPC, so the minted amount never leaks, while the reserve-before-
// broadcast double-mint guard records the mint as before.
func TestW5_ConfidentialReissueBlindsMint(t *testing.T) {
	f := newOA4Fixture(t)
	tokenID := strings.Repeat("44", 32)
	if err := f.st.Update(func(s *store.State) error {
		a := s.Assets[f.asset.ID]
		a.Confidential = true
		a.Entropy = strings.Repeat("33", 32)
		a.Token = tokenID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The blinded reissuance token lives in the server wallet with a non-zero
	// asset blinder (already re-blinded), so the mint proceeds directly.
	f.node.confUnspent = append(f.node.confUnspent, rpc.ConfUnspent{
		TxID: strings.Repeat("aa", 32), Vout: 1, ScriptPubKey: "0014" + strings.Repeat("dd", 20),
		Amount: 1.0, Asset: tokenID,
		AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
		Confidential: true,
	})

	code, body := callReissue(t, f.s, map[string]any{
		"asset": f.asset.ID, "target_aid": f.investor.AID, "atoms": 500, "request_id": "conf-mint-1",
	})
	if code != 200 {
		t.Fatalf("confidential reissue failed: %d %s", code, body)
	}
	if !f.node.blindCalled {
		t.Fatal("a confidential reissue must blind the transaction")
	}
	sent, err := elements.DeserializeTx(mustHexBytes(f.node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	investorTree, _ := f.s.treeFor(f.investor, f.asset)
	if hex.EncodeToString(sent.Out[0].ScriptPubKey) != hex.EncodeToString(investorTree.ScriptPubKey()) {
		t.Fatal("minted output does not pay the target enclave")
	}
	if !isBlindingNonce(sent.Out[0].Nonce) {
		t.Fatalf("a confidential DR mint's enclave output must carry a blinding nonce, got %x", sent.Out[0].Nonce)
	}
	// The idempotency record completed (reserve -> broadcast -> mark).
	if txid, ok := f.st.GetReissue("conf-mint-1"); !ok || txid != f.node.broadcast {
		t.Fatalf("mint not recorded: txid=%q ok=%v", txid, ok)
	}
	if _, ok := f.st.GetPendingReissue("conf-mint-1"); ok {
		t.Fatal("reservation must be cleared once the mint is recorded")
	}
}

// TestW5_TransparentReissueMintStaysExplicit pins the byte-identity guarantee:
// with no enclave nonce the minted output keeps the null nonce, exactly the
// pre-W5 transparent reissuance bytes.
func TestW5_TransparentReissueMintStaysExplicit(t *testing.T) {
	p := reissueParams{
		assetDisplay:    elements.MustHex32(oa4USDX),
		entropyInternal: [32]byte{1}, precision: 8,
		tokenTxid: strings.Repeat("11", 32), tokenVout: 1,
		tokenAbf: [32]byte{2}, tokenAtoms: 1_0000_0000,
		tokenChangeNonce: mustHexBytes("02" + strings.Repeat("cd", 32)),
		tokenChangeSpk:   mustHexBytes("0014" + strings.Repeat("cc", 20)),
		reissueAtoms:     500000, enclaveSpk: mustHexBytes("5120" + strings.Repeat("ab", 32)),
		feeTxid: strings.Repeat("22", 32), feeVout: 0,
		feeChangeSats: 90000, feeChangeNonce: mustHexBytes("02" + strings.Repeat("ee", 32)),
		feeChangeSpk:    mustHexBytes("0014" + strings.Repeat("ff", 20)),
		feeAssetDisplay: elements.MustHex32(oa4FeeID), feeSats: 100,
	}
	tx := buildReissuanceTx(p)
	if len(tx.Out[0].Nonce) != 1 || tx.Out[0].Nonce[0] != 0 {
		t.Fatalf("transparent mint output must keep the null nonce, got %x", tx.Out[0].Nonce)
	}
}

// TestW5_WatchReconcileImportsAndRescansOnce proves the startup reconcile
// re-imports every (holder, asset) pair of a confidential asset idempotently
// and runs exactly one rescan pass, and that startWatchReconcile is bounded to
// one run per process regardless of how often it is invoked.
func TestW5_WatchReconcileImportsAndRescansOnce(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	regUser(t, st, nil) // a second registered user
	asset, _ := clawAsset(t, st, issuer.AID, false)
	makeConfidential(t, st, asset.ID)

	// Direct (synchronous) run: 2 users x 1 confidential asset = 2 pairs, each
	// re-imported (script + blinding key), then ONE rescan.
	s.reconcileWatchWallet()
	if node.imports.Load() != 2 || node.blindImports.Load() != 2 {
		t.Fatalf("expected 2 script + 2 blinding-key imports, got %d/%d", node.imports.Load(), node.blindImports.Load())
	}
	if node.rescans.Load() != 1 {
		t.Fatalf("expected exactly 1 rescan pass, got %d", node.rescans.Load())
	}

	// The once-guard: invoking the startup hook repeatedly launches at most one
	// further (background) run.
	s.startWatchReconcile()
	s.startWatchReconcile()
	deadline := time.Now().Add(2 * time.Second)
	for node.rescans.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // give a hypothetical second run time to appear
	if got := node.rescans.Load(); got != 2 {
		t.Fatalf("startWatchReconcile must run at most once per process, saw %d total rescans", got)
	}
}

// TestW5_WatchReconcileNoConfidentialAssetsIsNoop proves a deployment with no
// confidential assets neither imports nor rescans.
func TestW5_WatchReconcileNoConfidentialAssetsIsNoop(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	clawAsset(t, st, issuer.AID, false) // transparent

	s.reconcileWatchWallet()
	if node.imports.Load() != 0 || node.blindImports.Load() != 0 || node.rescans.Load() != 0 {
		t.Fatalf("no confidential assets: expected no imports/rescan, got %d/%d/%d",
			node.imports.Load(), node.blindImports.Load(), node.rescans.Load())
	}
}
