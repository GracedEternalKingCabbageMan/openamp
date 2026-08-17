package server

import (
	"encoding/hex"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Blinded-change consolidation: the manual endpoint and the automatic trigger
// in the fee pickers' failure path. FeeSats is 100 throughout, so dustReserve
// is 200.

// seedBlindedFeeCoins gives the mock wallet n blinded fee-asset coins of
// `atoms` each and clears any explicit fee coin.
func seedBlindedFeeCoins(node *oa4Node, n int, atoms uint64) {
	node.feeUnspent = nil
	for i := 0; i < n; i++ {
		node.confUnspent = append(node.confUnspent, rpc.ConfUnspent{
			TxID: strings.Repeat(hex.EncodeToString([]byte{byte(0x60 + i)}), 32), Vout: 0,
			ScriptPubKey: "0014" + strings.Repeat("dd", 20),
			Amount:       float64(atoms) / 1e8, Asset: oa4FeeID, Spendable: true,
			AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
		})
	}
}

func countConsolidations(t *testing.T, st *store.Store) int {
	t.Helper()
	entries, err := readLog(st)
	if err != nil {
		if os.IsNotExist(err) {
			return 0 // nothing ever logged
		}
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == "consolidate" {
			n++
		}
	}
	return n
}

// TestConsolidate_SpendsBlindedIntoMajorityExplicit drives the manual endpoint:
// the blinded coins become one EXPLICIT output carrying everything except the
// fee and the dust reserve, one blinded (per-call blech32) balancing output of
// exactly the dust reserve, and the fee.
func TestConsolidate_SpendsBlindedIntoMajorityExplicit(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	node.addrSpk[node.newAddr] = oa4ChgSpk
	seedBlindedFeeCoins(node, 3, 5000) // 15000 total

	req := httptest.NewRequest("POST", "/v1/issuer/consolidate", nil)
	rec := httptest.NewRecorder()
	s.handleConsolidate(rec, req)
	if rec.Code != 200 {
		t.Fatalf("consolidate failed: %d %s", rec.Code, rec.Body.String())
	}
	if !node.blindCalled {
		t.Fatal("a consolidation spends blinded inputs and must run the blinding RPC")
	}
	if node.mempoolChecks == 0 {
		t.Fatal("a consolidation must pass the testmempoolaccept gate")
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if len(sent.In) != 3 {
		t.Fatalf("expected all 3 blinded coins spent, got %d inputs", len(sent.In))
	}
	if len(sent.Out) != 3 {
		t.Fatalf("expected [explicit, blinded dust, fee], got %d outputs", len(sent.Out))
	}
	// vout 0: explicit majority output to the fresh wallet address.
	amt, ok := elements.ExplicitValueAmount(sent.Out[0].Value)
	if !ok || amt != 15000-100-200 {
		t.Fatalf("explicit output must carry sum-fee-dust = 14700, got %d (ok=%v)", amt, ok)
	}
	if len(sent.Out[0].Nonce) != 1 || sent.Out[0].Nonce[0] != 0 {
		t.Fatalf("the sweep destination must be EXPLICIT, nonce %x", sent.Out[0].Nonce)
	}
	if hex.EncodeToString(sent.Out[0].ScriptPubKey) != oa4ChgSpk {
		t.Fatalf("explicit output pays %x, want the fresh wallet address", sent.Out[0].ScriptPubKey)
	}
	// vout 1: the blinded balancing output carries exactly the dust reserve.
	if amt, _ := elements.ExplicitValueAmount(sent.Out[1].Value); amt != 200 {
		t.Fatalf("dust output must carry 2*FeeSats = 200, got %d", amt)
	}
	if !isBlindingNonce(sent.Out[1].Nonce) {
		t.Fatalf("dust output must be blinded (per-call blech32), nonce %x", sent.Out[1].Nonce)
	}
	// vout 2: fee.
	if len(sent.Out[2].ScriptPubKey) != 0 {
		t.Fatal("last output must be the fee")
	}
	if got := countConsolidations(t, st); got != 1 {
		t.Fatalf("expected 1 consolidate log entry, got %d", got)
	}
}

// TestConsolidate_AutoTriggerFiresOnceThenRetries proves the automatic path: a
// hosted transfer with NO explicit fee coin but blinded fee change broadcasts
// exactly one consolidation, then completes the original transfer funded
// directly from the consolidation's explicit output.
func TestConsolidate_AutoTriggerFiresOnceThenRetries(t *testing.T) {
	f := newOA4Fixture(t)
	seedBlindedFeeCoins(f.node, 4, 5000) // 20000 total; no explicit fee coin

	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
	})
	if code != 200 {
		t.Fatalf("build over blinded-only fee funds failed: %d %s", code, body)
	}
	if got := countConsolidations(t, f.st); got != 1 {
		t.Fatalf("the trigger must fire exactly once, got %d consolidations", got)
	}
	if f.node.sends != 1 {
		t.Fatalf("exactly the consolidation must have broadcast at build time, got %d sends", f.node.sends)
	}

	// The transfer's fee input IS the consolidation's explicit output (vout 0).
	consolidation, err := elements.DeserializeTx(mustHexBytes(f.node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	built, err := elements.DeserializeTx(mustHexBytes(resp.Tx))
	if err != nil {
		t.Fatal(err)
	}
	feeIn := built.In[len(built.In)-1]
	if displayHash(feeIn.Prevout.Hash) != consolidation.TxID() || feeIn.Prevout.N != 0 {
		t.Fatalf("fee input %s:%d, want the consolidation output %s:0",
			displayHash(feeIn.Prevout.Hash), feeIn.Prevout.N, consolidation.TxID())
	}

	// The original operation completes over that 0-conf output.
	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, _ := elements.SignSchnorr(f.escrowKy, sh32)
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 200 {
		t.Fatalf("complete after auto-consolidation failed: %d %s", code, body)
	}
	if f.node.sends != 2 {
		t.Fatalf("expected consolidation + transfer broadcasts, got %d sends", f.node.sends)
	}
	if got := countConsolidations(t, f.st); got != 1 {
		t.Fatalf("completion must not consolidate again, got %d", got)
	}
}

// TestConsolidate_AllExplicitWalletNeverConsolidates proves the trigger is
// inert when an explicit fee coin exists: the ordinary build spends it and no
// consolidation happens even though blinded fee coins are ALSO present.
func TestConsolidate_AllExplicitWalletNeverConsolidates(t *testing.T) {
	f := newOA4Fixture(t) // explicit fee coin present
	f.node.confUnspent = append(f.node.confUnspent, rpc.ConfUnspent{
		TxID: strings.Repeat("66", 32), Vout: 0, ScriptPubKey: "0014" + strings.Repeat("dd", 20),
		Amount: 5000.0 / 1e8, Asset: oa4FeeID, Spendable: true,
		AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
	})
	code, resp, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	if got := countConsolidations(t, f.st); got != 0 {
		t.Fatalf("an explicit-funded build must never consolidate, got %d", got)
	}
	if f.node.sends != 0 {
		t.Fatalf("nothing may broadcast at build time, got %d sends", f.node.sends)
	}
	_ = resp
}

// TestConsolidate_NothingToConsolidate: no blinded fee coins at all -> the
// endpoint 409s and a fee-less build still fails with the usual 503.
func TestConsolidate_NothingToConsolidate(t *testing.T) {
	f := newOA4Fixture(t)
	f.node.feeUnspent = nil // no explicit coin, and no blinded coins either

	code, _, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
	})
	if code != 503 || !strings.Contains(body, "no fee funds") {
		t.Fatalf("want the usual 503, got %d %s", code, body)
	}
	req := httptest.NewRequest("POST", "/v1/issuer/consolidate", nil)
	rec := httptest.NewRecorder()
	f.s.handleConsolidate(rec, req)
	if rec.Code != 409 {
		t.Fatalf("endpoint with nothing to consolidate must 409, got %d %s", rec.Code, rec.Body.String())
	}
	if got := countConsolidations(t, f.st); got != 0 {
		t.Fatalf("no consolidation may be logged, got %d", got)
	}
}

// TestConsolidate_TooSmallBalanceDoesNotSweep: blinded coins whose total cannot
// yield a usable explicit coin are left alone (sweeping them would burn the
// whole balance as fee + dust).
func TestConsolidate_TooSmallBalanceDoesNotSweep(t *testing.T) {
	f := newOA4Fixture(t)
	seedBlindedFeeCoins(f.node, 1, 250) // 250 <= fee(100) + dust(200)

	code, _, body := callBuild(t, f.s, map[string]any{
		"asset": f.asset.ID, "sender_aid": f.escrow.AID, "recipient_aid": f.investor.AID,
		"atoms": 1000, "fee_mode": "sponsor",
	})
	if code != 503 {
		t.Fatalf("want 503 (nothing usable), got %d %s", code, body)
	}
	if f.node.sends != 0 || countConsolidations(t, f.st) != 0 {
		t.Fatalf("a too-small blinded balance must not be swept (sends=%d)", f.node.sends)
	}
}
