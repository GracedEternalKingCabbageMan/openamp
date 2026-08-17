package server

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// W-8: the PolicySigner seam. SignPolicy carries a truthful PolicyContext (what
// a future FROST quorum member sees before signing), and the policy key is
// bound to its asset id BEFORE broadcast so a crash can no longer strand a
// live asset's key as policy-pending:*.

// recordingSigner wraps a PolicySigner and captures every SignPolicy context.
type recordingSigner struct {
	inner PolicySigner
	ctxs  []PolicyContext
}

func (r *recordingSigner) GeneratePolicyKey() ([32]byte, string, error) {
	return r.inner.GeneratePolicyKey()
}
func (r *recordingSigner) Adopt(ref, assetID string) error { return r.inner.Adopt(ref, assetID) }
func (r *recordingSigner) PolicyPubKey(assetID string) ([32]byte, bool) {
	return r.inner.PolicyPubKey(assetID)
}
func (r *recordingSigner) SignPolicy(assetID string, sighash [32]byte, ctx PolicyContext) ([]byte, error) {
	r.ctxs = append(r.ctxs, ctx)
	return r.inner.SignPolicy(assetID, sighash, ctx)
}

// TestW8_TransferSignContext proves a hosted transfer co-signature carries
// {Action: transfer, the sender's AID, the broadcast tx's txid, the input index}.
func TestW8_TransferSignContext(t *testing.T) {
	f := newOA4Fixture(t)
	rec := &recordingSigner{inner: f.s.signer}
	f.s.signer = rec

	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 200 {
		t.Fatalf("complete failed: %d %s", code, body)
	}

	if len(rec.ctxs) != 1 {
		t.Fatalf("expected 1 policy signature, got %d", len(rec.ctxs))
	}
	ctx := rec.ctxs[0]
	sent, err := elements.DeserializeTx(mustHexBytes(f.node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Action != "transfer" || ctx.AID != f.escrow.AID || ctx.InputIndex != 0 {
		t.Fatalf("untruthful context: %+v", ctx)
	}
	if ctx.TxID != sent.TxID() {
		t.Fatalf("context txid %s != broadcast txid %s", ctx.TxID, sent.TxID())
	}
}

// TestW8_BurnSignContext proves a burn completion (same completion path) is
// signed under Action "burn", not "transfer".
func TestW8_BurnSignContext(t *testing.T) {
	f := newOA4Fixture(t)
	makeBurnable(t, f.st, f.asset.ID)
	rec := &recordingSigner{inner: f.s.signer}
	f.s.signer = rec

	code, resp, body := callBurn(t, f.s, map[string]any{
		"asset": f.asset.ID, "holder_aid": f.escrow.AID, "atoms": 400,
	})
	if code != 200 {
		t.Fatalf("burn build failed: %d %s", code, body)
	}
	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 200 {
		t.Fatalf("burn complete failed: %d %s", code, body)
	}
	if len(rec.ctxs) != 1 || rec.ctxs[0].Action != "burn" || rec.ctxs[0].AID != f.escrow.AID {
		t.Fatalf("burn must sign under a burn context: %+v", rec.ctxs)
	}
}

// TestW8_ClawbackSignContext proves a clawback co-signature carries the swept
// holder's AID and the public reason, so a quorum member would see it is
// authorizing a seizure, not a routine transfer.
func TestW8_ClawbackSignContext(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	rec := &recordingSigner{inner: s.signer}
	s.signer = rec
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, false)
	fundClawback(t, s, node, holder, asset, 1000)

	code, _, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "court order 99",
	})
	if code != 200 {
		t.Fatalf("clawback failed: %d %s", code, body)
	}
	if len(rec.ctxs) != 1 {
		t.Fatalf("expected 1 policy signature, got %d", len(rec.ctxs))
	}
	ctx := rec.ctxs[0]
	if ctx.Action != "clawback" || ctx.AID != holder.AID || ctx.Reason != "court order 99" || ctx.InputIndex != 0 {
		t.Fatalf("untruthful clawback context: %+v", ctx)
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if ctx.TxID != sent.TxID() {
		t.Fatalf("context txid %s != broadcast txid %s", ctx.TxID, sent.TxID())
	}
}

// TestW8_CosignSignContext proves the raw co-sign path passes a transfer
// context with the claimed input indices.
func TestW8_CosignSignContext(t *testing.T) {
	s, st, rawTxs := newOA7Server(t)
	rec := &recordingSigner{inner: s.signer}
	s.signer = rec
	escrow := regUser(t, st, nil)
	recipient := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	asset := oa7Asset(t, st, issuer.AID)

	prev := &elements.Tx{Version: 2}
	prev.Out = append(prev.Out, enclaveOut(t, s, escrow, asset, 100))
	prev.NormalizeWitness()
	prevID := prev.TxID()
	rawTxs[prevID] = hex.EncodeToString(prev.Serialize())

	tx := &elements.Tx{Version: 2}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 0}})
	tx.Out = append(tx.Out, enclaveOut(t, s, recipient, asset, 100))
	tx.NormalizeWitness()

	code, body := callCosign(t, s, tx, asset, escrow.AID, []int{0})
	if code != 200 {
		t.Fatalf("cosign failed: %d %s", code, body)
	}
	if len(rec.ctxs) != 1 {
		t.Fatalf("expected 1 policy signature, got %d", len(rec.ctxs))
	}
	ctx := rec.ctxs[0]
	if ctx.Action != "transfer" || ctx.AID != escrow.AID || ctx.TxID != tx.TxID() || ctx.InputIndex != 0 {
		t.Fatalf("untruthful cosign context: %+v", ctx)
	}
}

// TestW8_AdoptBeforeBroadcast_CrashWindow proves the policy key is bound to its
// asset id even when the broadcast fails: the crash window that used to strand
// a live asset's key as policy-pending:* is gone, and the failure mode left
// behind (a bound key for an asset that never reached the chain) is harmless.
func TestW8_AdoptBeforeBroadcast_CrashWindow(t *testing.T) {
	s, st, node := newIssueServer(t)
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	node.sendErr = "connection lost mid-broadcast"

	code, _, body := callIssue(t, s, map[string]any{
		"name": "CRSH", "ticker": "CRSH", "precision": 8, "atoms": 1000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID,
	})
	if code != 502 {
		t.Fatalf("expected 502 for a failed broadcast, got %d: %s", code, body)
	}

	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	var bound, pending int
	for name := range keys {
		if strings.HasPrefix(name, "policy:") {
			bound++
		}
		if strings.HasPrefix(name, "policy-pending:") {
			pending++
		}
	}
	if bound != 1 {
		t.Fatalf("the policy key must be BOUND (adopted before broadcast), found %d bound keys", bound)
	}
	if pending != 0 {
		t.Fatalf("no policy-pending:* key may survive the broadcast attempt, found %d", pending)
	}
	// The bound key refers to no stored asset: harmless, GC-able.
	var assets int
	st.View(func(state *store.State) { assets = len(state.Assets) })
	if assets != 0 {
		t.Fatalf("a failed broadcast must persist no asset, found %d", assets)
	}
}

// TestW8_AdoptOnSuccessfulIssue proves the normal path still ends with exactly
// one bound policy:<assetID> key for the recorded asset and nothing pending.
func TestW8_AdoptOnSuccessfulIssue(t *testing.T) {
	s, st, _ := newIssueServer(t)
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)

	code, out, body := callIssue(t, s, map[string]any{
		"name": "OKAY", "ticker": "OKAY", "precision": 8, "atoms": 1000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID,
	})
	if code != 200 {
		t.Fatalf("issuance failed: %d %s", code, body)
	}
	assetID, _ := out["asset"].(string)
	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["policy:"+assetID]; !ok {
		t.Fatal("the issued asset's policy key must be bound")
	}
	for name := range keys {
		if strings.HasPrefix(name, "policy-pending:") {
			t.Fatalf("stray staged key %s after a successful issuance", name)
		}
	}
}
