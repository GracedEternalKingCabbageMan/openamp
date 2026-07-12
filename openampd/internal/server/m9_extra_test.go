package server

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// M9 extra coverage (tests-owner additions to the implementer's m9_test.go). These
// harden the fund-safety envelope of the two-phase clawback: a holder with MORE
// than one enclave UTXO must have EVERY input swept atomically and only after all
// of the issuer's signatures arrive (a partial signature set broadcasts nothing);
// a completion for an unknown/expired build is refused; and the legacy single-call
// path creates NO pending build (so the two families never cross).

// fundClawbackN seeds the holder with n enclave UTXOs of the given atom amounts
// (each a distinct prevout) plus a fee coin, so a multi-input clawback sweep can be
// assembled. It mirrors fundClawback but for an arbitrary UTXO count.
func fundClawbackN(t *testing.T, s *Server, node *oa4Node, holder *store.User, asset *store.Asset, amounts []uint64) uint64 {
	t.Helper()
	holderTree, err := s.treeFor(holder, asset)
	if err != nil {
		t.Fatal(err)
	}
	holderSpk := hex.EncodeToString(holderTree.ScriptPubKey())
	var scan []rpc.ScanUnspent
	var total uint64
	for i, atoms := range amounts {
		prev := &elements.Tx{Version: 2}
		// A distinct filler output shifts each prevout's txid so the UTXOs differ.
		prev.Out = append(prev.Out, explicitOut(oa4FeeID, uint64(1000+i), oa4FeeSpk))
		prev.Out = append(prev.Out, enclaveOut(t, s, holder, asset, atoms))
		prev.NormalizeWitness()
		id := prev.TxID()
		node.rawTxs[id] = hex.EncodeToString(prev.Serialize())
		scan = append(scan, rpc.ScanUnspent{TxID: id, Vout: 1, Asset: asset.ID, Amount: float64(atoms) / 1e8, ScriptPubKey: holderSpk, Height: 1})
		total += atoms
	}
	node.scan[holderSpk] = scan

	feePrev := &elements.Tx{Version: 2}
	feePrev.Out = append(feePrev.Out, explicitOut(oa4FeeID, 100000, oa4FeeSpk))
	feePrev.NormalizeWitness()
	fPrevID := feePrev.TxID()
	node.rawTxs[fPrevID] = hex.EncodeToString(feePrev.Serialize())
	node.feeUnspent = []rpc.Unspent{{TxID: fPrevID, Vout: 0, Amount: 100000.0 / 1e8, Asset: oa4FeeID, ScriptPubKey: oa4FeeSpk, Spendable: true}}

	node.addrSpk[node.newAddr] = oa4ChgSpk
	node.broadcast = strings.Repeat("77", 32)
	return total
}

// TestM9_TwoPhaseClawback_MultiUTXO_AllInputsAtomic proves a clawback over a holder
// with several enclave UTXOs returns one L_claw sighash per input (each tagged with
// the asset's issuer x-only), broadcasts NOTHING until ALL of the issuer's
// signatures are supplied, and then sweeps the full sum in a single broadcast. A
// partial signature set (one input missing) is refused with no broadcast, and the
// pending build survives that refusal so the genuine completion still works.
func TestM9_TwoPhaseClawback_MultiUTXO_AllInputsAtomic(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, issuerPriv := clawAsset(t, st, issuer.AID, true)
	total := fundClawbackN(t, s, node, holder, asset, []uint64{400, 350, 250})

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "multi-utxo seizure",
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	if _, hasTxid := out["txid"]; hasTxid {
		t.Fatalf("build must not broadcast: %s", body)
	}
	if node.sends != 0 {
		t.Fatalf("build broadcast %d times, want 0", node.sends)
	}
	toSign, _ := out["to_sign"].([]any)
	if len(toSign) != 3 {
		t.Fatalf("expected 3 L_claw inputs to sign, got %d: %s", len(toSign), body)
	}
	// Every to_sign entry names the asset's issuer x-only (which key must sign) and
	// carries the input index the enclave input sits at (0..n-1, fee input excluded).
	issuerX := elements.XOnlyFromPriv(issuerPriv)
	seen := map[int]bool{}
	sigs := map[string]string{}
	for _, e := range toSign {
		m := e.(map[string]any)
		if m["pubkey"] != hex.EncodeToString(issuerX[:]) {
			t.Fatalf("to_sign pubkey must be the issuer x-only, got %v", m["pubkey"])
		}
		idx := int(m["input"].(float64))
		if idx < 0 || idx > 2 || seen[idx] {
			t.Fatalf("unexpected/duplicate input index %d", idx)
		}
		seen[idx] = true
		for k, v := range signToSign(t, e, issuerPriv) {
			sigs[k] = v
		}
	}
	id, _ := out["id"].(string)

	// A PARTIAL signature set (drop input 1) must be refused and broadcast nothing.
	partial := map[string]string{"0": sigs["0"], "2": sigs["2"]}
	code, _, body = callClawbackComplete(t, s, id, map[string]any{"sigs": partial})
	if code != 400 {
		t.Fatalf("partial signature set must be refused, got %d: %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("a refused completion must broadcast nothing, saw %d", node.sends)
	}
	// The pending build survived the refusal (consume-once only on success).
	if _, ok := st.GetPendingClawback(id); !ok {
		t.Fatal("a refused completion must not consume the pending build")
	}

	// The full set completes: one broadcast, the whole balance swept atomically.
	code, out, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sigs})
	if code != 200 {
		t.Fatalf("full completion failed: %d %s", code, body)
	}
	if node.sends != 1 {
		t.Fatalf("completion must broadcast exactly once, saw %d", node.sends)
	}
	if got := uint64(out["atoms"].(float64)); got != total {
		t.Fatalf("expected the full %d atoms swept, got %d", total, got)
	}
	// Consumed: the pending build is gone and a replay short-circuits to the txid.
	if _, ok := st.GetPendingClawback(id); ok {
		t.Fatal("a completed clawback must consume its pending build")
	}
}

// TestM9_ClawbackComplete_MissingSigs_NoBroadcast proves an empty (or short)
// signature map is refused with no broadcast, so a completion cannot slip through
// without the issuer's authorization for every enclave input.
func TestM9_ClawbackComplete_MissingSigs_NoBroadcast(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, true)
	fundClawback(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "audit",
	})
	if code != 200 {
		t.Fatalf("build failed: %d %s", code, body)
	}
	id, _ := out["id"].(string)

	code, _, body = callClawbackComplete(t, s, id, map[string]any{"sigs": map[string]string{}})
	if code != 400 {
		t.Fatalf("empty sigs must be refused, got %d: %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("a refused completion must broadcast nothing, saw %d", node.sends)
	}
	// The build is still resumable after the refusal.
	if _, ok := st.GetPendingClawback(id); !ok {
		t.Fatal("the pending build must survive a refused completion")
	}
}

// TestM9_ClawbackComplete_UnknownID_404 proves a completion for a build id that was
// never created (or has expired) is refused and never broadcasts. This also covers
// a legacy asset: a legacy clawback creates no pending build, so any id posted to
// complete is unknown.
func TestM9_ClawbackComplete_UnknownID_404(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	_ = st
	code, _, body := callClawbackComplete(t, s, "deadbeefdeadbeef", map[string]any{
		"sigs": map[string]string{"0": strings.Repeat("11", 64)},
	})
	if code != 404 {
		t.Fatalf("unknown clawback id must be 404, got %d: %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("an unknown-id completion must broadcast nothing, saw %d", node.sends)
	}
}

// TestM9_LegacyClawback_CreatesNoPending proves the legacy single-call sweep never
// persists a two-phase pending build, so the external-issuer state (pending_clawbacks)
// stays empty for a server-held-key asset and a replay can never find a build to
// complete. The two clawback families do not cross.
func TestM9_LegacyClawback_CreatesNoPending(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, false) // server holds the issuer key
	fundClawback(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "legacy sweep",
	})
	if code != 200 || out["txid"] != node.broadcast {
		t.Fatalf("legacy clawback must broadcast in one call: %d %s", code, body)
	}
	var pendingCount int
	st.View(func(state *store.State) { pendingCount = len(state.PendingClawbacks) })
	if pendingCount != 0 {
		t.Fatalf("a legacy clawback must create no pending build, found %d", pendingCount)
	}
}

// TestM9_IssueExternalKey_ContractGoldenParity proves that supplying an external
// issuer_pubkey changes ONLY the issuer_pubkey value in the contract: the rest of
// the canonical document is byte-identical to a server-generated-key issuance with
// the same request. So the OA-1 goldens (BONDX and every M1-M8 asset) are untouched
// by M9; only the key origin differs.
func TestM9_IssueExternalKey_ContractGoldenParity(t *testing.T) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	extX := elements.XOnlyFromPriv(priv[:])
	extHex := hex.EncodeToString(extX[:])
	serverHex := strings.Repeat("aa", 32)

	req := &issueRequest{Name: "BONDX", Ticker: "BONDX", Precision: 8}
	external, err := canonicalJSON(req.buildContract(extHex, oa1PolicyPub, true))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := canonicalJSON(req.buildContract(serverHex, oa1PolicyPub, true))
	if err != nil {
		t.Fatal(err)
	}
	// The two contracts differ in exactly one field: the issuer_pubkey value.
	if strings.Replace(string(external), extHex, serverHex, 1) != string(legacy) {
		t.Fatalf("external key must change only issuer_pubkey.\nexternal: %s\nlegacy:   %s", external, legacy)
	}
	// And the external contract commits to the external key.
	if !strings.Contains(string(external), `"issuer_pubkey":"`+extHex+`"`) {
		t.Fatalf("external contract must carry the entity key: %s", external)
	}
}
