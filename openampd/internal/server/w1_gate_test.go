package server

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// W-1: a testmempoolaccept gate in front of EVERY broadcast of a server-built
// spend. A transaction the node rejects is refused with 502 (carrying the
// node's reject-reason), broadcasts nothing, spends nothing, and leaves a
// refusal-style entry in the transparency log.

// logHasRefusalWithReason reports whether the log carries a refused entry for
// the action with the given reject_reason.
func logHasRefusalWithReason(t *testing.T, st *store.Store, action, reason string) bool {
	t.Helper()
	entries, err := readLog(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action != action {
			continue
		}
		var d struct {
			Refused      bool   `json:"refused"`
			RejectReason string `json:"reject_reason"`
		}
		_ = json.Unmarshal(e.Data, &d)
		if d.Refused && d.RejectReason == reason {
			return true
		}
	}
	return false
}

// TestW1_RejectedIssuanceBroadcastsNothing proves a node-rejected issuance
// (transparent path) spends nothing: no sendrawtransaction, no asset record,
// and a refusal-style log entry carrying the node's reject-reason.
func TestW1_RejectedIssuanceBroadcastsNothing(t *testing.T) {
	s, st, node := newIssueServer(t)
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	node.mempoolReject = "bad-txns-in-belowout"

	code, _, body := callIssue(t, s, map[string]any{
		"name": "REJX", "ticker": "REJX", "precision": 8, "atoms": 1000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID,
	})
	if code != 502 {
		t.Fatalf("expected 502 for a node-rejected issuance, got %d: %s", code, body)
	}
	if !strings.Contains(body, "bad-txns-in-belowout") {
		t.Fatalf("response must carry the node's reject-reason: %s", body)
	}
	if node.sends != 0 {
		t.Fatalf("a rejected issuance must broadcast nothing, saw %d sends", node.sends)
	}
	var assets int
	st.View(func(state *store.State) { assets = len(state.Assets) })
	if assets != 0 {
		t.Fatalf("a rejected issuance must persist no asset, found %d", assets)
	}
	if !logHasRefusalWithReason(t, st, "issue", "bad-txns-in-belowout") {
		t.Fatal("a rejected issuance must leave a refusal-style log entry with the reject-reason")
	}
}

// TestW1_ConfidentialIssuanceGated proves the confidential issuance path runs
// through the same gate: a rejection broadcasts nothing there too.
func TestW1_ConfidentialIssuanceGated(t *testing.T) {
	s, st, node := newIssueServer(t)
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	node.mempoolReject = "bad-txns-nonstandard"

	code, _, body := callIssue(t, s, map[string]any{
		"name": "CREJ", "ticker": "CREJ", "precision": 8, "atoms": 1000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID, "confidential": true,
	})
	if code != 502 {
		t.Fatalf("expected 502, got %d: %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("a rejected confidential issuance must broadcast nothing, saw %d sends", node.sends)
	}
	if !node.blindCalled {
		t.Fatal("harness invalid: the confidential path should have blinded before the gate")
	}
}

// TestW1_IssuanceGateChecksExactBroadcastBytes proves the gate is purely
// additive on the transparent path: the bytes submitted to testmempoolaccept
// are the exact bytes subsequently broadcast (the byte-identity guarantee, with
// the existing OA-8 byte-identity tests still covering the tx structure).
func TestW1_IssuanceGateChecksExactBroadcastBytes(t *testing.T) {
	s, st, node := newIssueServer(t)
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)

	code, _, body := callIssue(t, s, map[string]any{
		"name": "GATX", "ticker": "GATX", "precision": 8, "atoms": 1000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID,
	})
	if code != 200 {
		t.Fatalf("issuance failed: %d %s", code, body)
	}
	if node.mempoolChecks != 1 {
		t.Fatalf("expected exactly one gate check, got %d", node.mempoolChecks)
	}
	if node.lastMempoolCheck == "" || node.lastMempoolCheck != node.lastBroadcast {
		t.Fatal("the gate must check the exact bytes that get broadcast")
	}
}

// TestW1_RejectedTransferBroadcastsNothing proves the hosted transfer
// completion path (cosignAndBroadcast) is gated: a node-rejected transfer is
// 502, unbroadcast, and refusal-logged.
func TestW1_RejectedTransferBroadcastsNothing(t *testing.T) {
	f := newOA4Fixture(t)
	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	f.node.mempoolReject = "txn-mempool-conflict"

	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 502 {
		t.Fatalf("expected 502 for a node-rejected transfer, got %d: %s", code, body)
	}
	if !strings.Contains(body, "txn-mempool-conflict") {
		t.Fatalf("response must carry the reject-reason: %s", body)
	}
	if f.node.sends != 0 {
		t.Fatalf("a rejected transfer must broadcast nothing, saw %d sends", f.node.sends)
	}
	if !logHasRefusalWithReason(t, f.st, "transfer", "txn-mempool-conflict") {
		t.Fatal("a rejected transfer must leave a refusal-style log entry")
	}
}

// TestW1_RejectedBurnBroadcastsNothing confirms the burn completion (which
// flows through the same transfer completion path) is covered by the gate, and
// its refusal is logged under the burn action.
func TestW1_RejectedBurnBroadcastsNothing(t *testing.T) {
	f := newOA4Fixture(t)
	makeBurnable(t, f.st, f.asset.ID)
	code, resp, body := callBurn(t, f.s, map[string]any{
		"asset": f.asset.ID, "holder_aid": f.escrow.AID, "atoms": 400,
	})
	if code != 200 {
		t.Fatalf("burn build failed: %d %s", code, body)
	}
	f.node.mempoolReject = "bad-txns-inputs-missingorspent"

	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 502 {
		t.Fatalf("expected 502 for a node-rejected burn, got %d: %s", code, body)
	}
	if f.node.sends != 0 {
		t.Fatalf("a rejected burn must broadcast nothing, saw %d sends", f.node.sends)
	}
	if !logHasRefusalWithReason(t, f.st, "burn", "bad-txns-inputs-missingorspent") {
		t.Fatal("a rejected burn must leave a refusal-style log entry")
	}
}

// TestW1_RejectedLegacyClawbackBroadcastsNothing proves the legacy single-call
// clawback is gated before its broadcast.
func TestW1_RejectedLegacyClawbackBroadcastsNothing(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, false) // server-held issuer key
	fundClawback(t, s, node, holder, asset, 1000)
	node.mempoolReject = "bad-txns-invalid-witness"

	code, _, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "gated sweep",
	})
	if code != 502 {
		t.Fatalf("expected 502 for a node-rejected clawback, got %d: %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("a rejected clawback must broadcast nothing, saw %d sends", node.sends)
	}
	if !logHasRefusalWithReason(t, st, "clawback", "bad-txns-invalid-witness") {
		t.Fatal("a rejected clawback must leave a refusal-style log entry")
	}
}

// TestW1_RejectedClawbackCompleteKeepsPending proves the two-phase completion
// is gated AND stays retryable: a rejection consumes nothing (the pending build
// survives), so a later completion with the identical stored tx still works.
func TestW1_RejectedClawbackCompleteKeepsPending(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, issuerPriv := clawAsset(t, st, issuer.AID, true) // external issuer
	fundClawback(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "gated two-phase",
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	id, _ := out["id"].(string)
	toSign, _ := out["to_sign"].([]any)
	sigs := signToSign(t, toSign[0], issuerPriv)

	node.mempoolReject = "bad-txns-invalid-witness"
	code, _, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sigs})
	if code != 502 {
		t.Fatalf("expected 502 for a node-rejected completion, got %d: %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("a rejected completion must broadcast nothing, saw %d sends", node.sends)
	}
	if _, ok := st.GetPendingClawback(id); !ok {
		t.Fatal("a rejected completion must not consume the pending build")
	}

	// The gate lifted: the identical stored build completes and broadcasts once.
	node.mempoolReject = ""
	code, out, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sigs})
	if code != 200 || out["txid"] != node.broadcast {
		t.Fatalf("retry after the gate lifted must complete: %d %s", code, body)
	}
	if node.sends != 1 {
		t.Fatalf("expected exactly one broadcast after retry, saw %d", node.sends)
	}
}
