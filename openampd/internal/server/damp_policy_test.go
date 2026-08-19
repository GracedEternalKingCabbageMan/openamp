package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Policy updates for a network-enforced asset: the freeze path, end to end
// against the mock node.
//
// Every test here asserts one of two things: that a legitimate freeze advances
// the published policy AND the on-chain verifier output together, or that a
// malformed one is refused with NOTHING broadcast and NOTHING published. The
// second class matters more: a policy update that half happens leaves holders
// building transfers against a commitment the chain does not hold.

// dampPolicyFixture is an issued damp asset with an issuer key this test process
// controls, its verifier output visible to the mock node's scan, and the
// vectors it was derived against.
type dampPolicyFixture struct {
	s    *Server
	st   *store.Store
	node *dampNode
	v    dampVec

	asset      string
	vAsset     string
	q          uint64
	pi0        string
	issuerPriv *btcec.PrivateKey
	issuerX    string
	// the verifier output the next update must consume
	vTxid string
	vVout uint32
}

func newDampPolicyFixture(t *testing.T) *dampPolicyFixture {
	t.Helper()
	v := loadDampVectors(t)
	s, st, node := newDampServer(t, v)

	// The issuer update key is EXTERNAL to the server by construction, so the test
	// plays the issuer: it holds the key and signs the snapshots.
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerX := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))

	body := dampPrepareBody(v)
	body["issuer_update_key"] = issuerX
	code, prep := dampPrepare(t, s, body)
	if code != 200 {
		t.Fatalf("issuance prepare: %d %v", code, prep)
	}
	prepareID, _ := prep["prepare_id"].(string)
	pi0, _ := prep["pi"].(string)
	code, out := dampComplete(t, s, prepareID, map[string]any{
		"user_cmr": v.Programs.UCMR, "verifier_cmrs": v.shapeCMRs(), "issuer_cmr": v.Programs.GCMR,
		"pi": pi0, "verifier_spk": v.VerifierCovenant.ScriptPubKey,
	})
	if code != 200 {
		t.Fatalf("issuance complete: %d %v", code, out)
	}
	assetID, _ := out["asset"].(string)
	vAssetID, _ := out["verifier_asset"].(string)
	txids, _ := out["txids"].(map[string]any)
	issueTxid, _ := txids["asset_issue"].(string)

	f := &dampPolicyFixture{
		s: s, st: st, node: node, v: v,
		asset: assetID, vAsset: vAssetID, q: 1, pi0: pi0,
		issuerPriv: priv, issuerX: issuerX,
		// The issuance transaction locks q of V into C_V at vout 2 (damp_issue.go's
		// output order), which is where an update finds it.
		vTxid: issueTxid, vVout: 2,
	}
	f.publishVerifierOutput(t, v.VerifierCovenant.ScriptPubKey, issueTxid, 2)
	return f
}

// publishVerifierOutput makes the verifier coin visible to the mock node's
// scantxoutset, which is how the server locates the outpoint an update consumes.
func (f *dampPolicyFixture) publishVerifierOutput(t *testing.T, spk, txid string, vout uint32) {
	t.Helper()
	f.node.scanUnspents[spk] = map[string]any{
		"txid": txid, "vout": vout, "amount": float64(f.q) / 1e8,
		"asset": f.vAsset, "scriptPubKey": spk,
	}
}

func (f *dampPolicyFixture) policyPrepare(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	if _, has := body["asset"]; !has {
		body["asset"] = f.asset
	}
	return postJSON(t, f.s.handleDampPolicyPrepare, "/v1/issuer/damp-policy", body)
}

func (f *dampPolicyFixture) policyComplete(t *testing.T, id string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/damp-policy/"+id+"/complete", bytes.NewReader(b))
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	f.s.handleDampPolicyComplete(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// sign is the issuer signing the 32 bytes prepare returned.
func (f *dampPolicyFixture) sign(t *testing.T, toSign string) string {
	t.Helper()
	var msg [32]byte
	raw, err := hex.DecodeString(toSign)
	if err != nil || len(raw) != 32 {
		t.Fatalf("to_sign is not a 32-byte hex message: %q", toSign)
	}
	copy(msg[:], raw)
	sig, err := elements.SignSchnorr(f.issuerPriv.Serialize(), msg)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sig)
}

// nextVerifier is a stand-in for `opendamp derive` against the new policy: a
// different program CMR, and the C_V scriptPubKey it derives. The CMR itself is
// opaque to this server (it cannot compile Simplicity), which is exactly why the
// checks it CAN make are the ones under test.
func (f *dampPolicyFixture) nextVerifier(t *testing.T, marker byte) (menu []string, spkHex string) {
	t.Helper()
	// A whole new MENU, not one program: every shape is recompiled against the
	// new policy, so every leaf of the taptree moves and so does the address.
	next := f.v.shapeCMRBytes()
	for i := range next {
		next[i][0] ^= marker
	}
	g := [32]byte{}
	copy(g[:], mustHexBytes(f.v.Programs.GCMR))
	cov, err := elements.VerifierCovenant(next, g)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(next))
	for _, c := range next {
		out = append(out, hex.EncodeToString(c[:]))
	}
	return out, hex.EncodeToString(cov.ScriptPubKey())
}

// respend builds the finished issuer-path spend the way `opendamp issuer-update`
// would: the current verifier output in, the recreated verifier output under the
// new policy out. The Simplicity witness is irrelevant to what this server
// checks (consensus checks that), so the test does not fabricate one.
func (f *dampPolicyFixture) respend(txid string, vout uint32, nextSPK string) string {
	tx := &elements.Tx{Version: 2}
	tx.In = append(tx.In, &elements.TxIn{
		Prevout: elements.OutPoint{Hash: internalHash(txid), N: vout},
	})
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(f.vAsset)),
		Value: elements.ExplicitValue(f.q), Nonce: elements.NullNonce(),
		ScriptPubKey: mustHexBytes(nextSPK),
	})
	tx.NormalizeWitness()
	return hex.EncodeToString(tx.Serialize())
}

// --- the headline: a freeze advances the policy and the chain together --------

func TestDampPolicy_FreezeRemovesHolderAndAdvancesPi(t *testing.T) {
	f := newDampPolicyFixture(t)
	sendsBefore := len(f.node.sends)
	frozenHolder := f.v.whitelistKeys()[2]
	frozenOutpoint := map[string]any{"txid": strings.Repeat("7c", 32), "vout": 3}

	code, prep := f.policyPrepare(t, map[string]any{
		"remove_whitelist": []string{frozenHolder},
		"add_blacklist":    []any{frozenOutpoint},
		"reason":           "court order 2026-1188: freeze the holder and the coin it names",
	})
	if code != 200 {
		t.Fatalf("policy prepare: %d %v", code, prep)
	}
	// Nothing is signed, published or broadcast by a prepare.
	if len(f.node.sends) != sendsBefore {
		t.Fatalf("prepare broadcast %d transactions; it must broadcast none", len(f.node.sends)-sendsBefore)
	}
	if latest, _ := f.st.LatestSnapshot(f.asset); latest.Seq != 0 {
		t.Fatalf("prepare published seq %d; it must publish nothing", latest.Seq)
	}

	// THE REASON IS IN THE PUBLIC LOG BEFORE ANYTHING IS SIGNED. This is the
	// clawback discipline: an issuer cannot build a freeze whose justification is
	// added afterwards.
	entries, err := readLog(f.st)
	if err != nil {
		t.Fatal(err)
	}
	var reasonSeq uint64
	for _, e := range entries {
		if e.Action != "damp-policy" {
			continue
		}
		var d map[string]any
		_ = json.Unmarshal(e.Data, &d)
		if d["phase"] == "prepare" && strings.Contains(fmt.Sprint(d["reason"]), "court order 2026-1188") {
			reasonSeq = e.Seq
			if d["asset"] != f.asset || fmt.Sprint(d["seq"]) != "1" {
				t.Fatalf("the logged prepare names the wrong asset or seq: %v", d)
			}
		}
	}
	if reasonSeq == 0 {
		t.Fatal("the reason must be in the transparency log after prepare, before any signature exists")
	}

	piNext, _ := prep["pi_next"].(string)
	if piNext == "" || piNext == f.pi0 {
		t.Fatalf("pi must advance: pi_0 = %s, pi_next = %v", f.pi0, prep["pi_next"])
	}
	if prep["prev_pi"] != f.pi0 {
		t.Fatalf("prev_pi = %v, want the published pi_0 %s", prep["prev_pi"], f.pi0)
	}
	if fmt.Sprint(prep["seq"]) != "1" {
		t.Fatalf("seq = %v, want 1", prep["seq"])
	}
	wl, _ := prep["whitelist"].([]any)
	if len(wl) != len(f.v.whitelistKeys())-1 {
		t.Fatalf("the holder list must lose exactly the frozen holder: %v", wl)
	}
	for _, e := range wl {
		if e == frozenHolder {
			t.Fatalf("the frozen holder %s is still on the list", frozenHolder)
		}
	}
	bl, _ := prep["blacklist"].([]any)
	if len(bl) != 1 {
		t.Fatalf("the frozen-coin list must carry exactly the named outpoint: %v", bl)
	}
	// The listed entry is the covenant's own policy key for that outpoint, not the
	// outpoint: internal txid order then a big-endian vout. A display-order txid
	// here would produce a root that looks right and freezes nothing.
	wantKey := hex.EncodeToString(func() []byte {
		k, _ := dampOutpointRef{Txid: strings.Repeat("7c", 32), Vout: 3}.key()
		return k[:]
	}())
	if bl[0] != wantKey {
		t.Fatalf("blacklist entry = %v, want the outpoint policy key %s", bl[0], wantKey)
	}
	if prep["verifier_cmr_current"] != f.v.Programs.PCMR {
		t.Fatalf("prepare must name the CURRENT verifier program so a caller can spot an unchanged derivation: %v", prep["verifier_cmr_current"])
	}
	vout, _ := prep["verifier_outpoint"].(map[string]any)
	if vout["txid"] != f.vTxid || fmt.Sprint(vout["vout"]) != "2" {
		t.Fatalf("the update must consume the current rules output %s:2, got %v", f.vTxid, vout)
	}

	// Complete it, the way the issuer's toolchain would.
	policyID, _ := prep["policy_id"].(string)
	toSign, _ := prep["to_sign"].(string)
	nextCMR, nextSPK := f.nextVerifier(t, 0x01)
	code, out := f.policyComplete(t, policyID, map[string]any{
		"sig": f.sign(t, toSign), "verifier_cmrs": nextCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(f.vTxid, f.vVout, nextSPK),
	})
	if code != 200 {
		t.Fatalf("policy complete: %d %v", code, out)
	}
	if len(f.node.sends) != sendsBefore+1 {
		t.Fatalf("complete must broadcast exactly one transaction, got %d", len(f.node.sends)-sendsBefore)
	}

	// The snapshot chain: gapless seq, prev_pi linking back, and a document that
	// verifies offline under the issuer key.
	latest, ok := f.st.LatestSnapshot(f.asset)
	if !ok || latest.Seq != 1 || latest.Pi != piNext {
		t.Fatalf("seq 1 must be published with pi_next: %+v", latest)
	}
	var published damp.Snapshot
	if err := json.Unmarshal(latest.Canonical, &published); err != nil {
		t.Fatal(err)
	}
	published.IssuerSig = latest.IssuerSig
	if err := published.Validate(); err != nil {
		t.Fatalf("the published policy is not self-consistent: %v", err)
	}
	if err := published.Verify(f.issuerX); err != nil {
		t.Fatalf("the published policy must verify under the issuer update key: %v", err)
	}
	if published.PrevPi == nil || *published.PrevPi != f.pi0 {
		t.Fatalf("prev_pi must chain to pi_0: %v", published.PrevPi)
	}
	if genesis, ok := f.st.SnapshotAt(f.asset, 0); !ok || genesis.Pi != f.pi0 {
		t.Fatalf("seq 0 must still be served unchanged: %+v", genesis)
	}

	// The asset's binding now points at the deployed policy, so every later read
	// (and the next update's derive document) answers about what is on chain.
	var bound *store.DampBinding
	f.st.View(func(st *store.State) { bound = st.Assets[f.asset].Damp })
	if bound.Pi != piNext || !sameCMRMenu(bound.VerifierCMRs, nextCMR) || bound.VerifierSPK != nextSPK {
		t.Fatalf("the asset binding did not move to the new policy: %+v", bound)
	}
	if len(bound.Whitelist) != len(f.v.whitelistKeys())-1 {
		t.Fatalf("the stored holder list must move with its root: %v", bound.Whitelist)
	}

	// And the freeze is reversible: restoring the holder is one more seq.
	f.publishVerifierOutput(t, nextSPK, f.node.lastTxid(t), 0)
	code, prep2 := f.policyPrepare(t, map[string]any{
		"add_whitelist":    []string{frozenHolder},
		"remove_blacklist": []any{frozenOutpoint},
		"reason":           "court order 2026-1188 discharged",
	})
	if code != 200 {
		t.Fatalf("reversing prepare: %d %v", code, prep2)
	}
	if fmt.Sprint(prep2["seq"]) != "2" || prep2["prev_pi"] != piNext {
		t.Fatalf("the reversal must chain onto seq 1: %v", prep2)
	}
	if prep2["pi_next"] == f.pi0 {
		t.Fatal("pi is committed at a seq, so restoring the same holder list must NOT reproduce pi_0")
	}
}

// lastTxid is the txid of the most recent broadcast.
func (n *dampNode) lastTxid(t *testing.T) string {
	t.Helper()
	if len(n.sends) == 0 {
		t.Fatal("nothing was broadcast")
	}
	tx, err := elements.DeserializeTx(mustHexBytes(n.sends[len(n.sends)-1]))
	if err != nil {
		t.Fatal(err)
	}
	return tx.TxID()
}

// --- refusals: nothing broadcast, nothing published --------------------------

func TestDampPolicy_WrongSignatureRefused(t *testing.T) {
	f := newDampPolicyFixture(t)
	sendsBefore := len(f.node.sends)
	code, prep := f.policyPrepare(t, map[string]any{
		"remove_whitelist": []string{f.v.whitelistKeys()[2]},
		"reason":           "regulator direction",
	})
	if code != 200 {
		t.Fatalf("prepare: %d %v", code, prep)
	}
	policyID, _ := prep["policy_id"].(string)
	toSign, _ := prep["to_sign"].(string)
	nextCMR, nextSPK := f.nextVerifier(t, 0x02)

	// A signature by SOME key, just not the issuer update key the asset id commits
	// to. This is the whole authorization of a policy update, so it must be
	// checked before any structural opinion is formed about the transaction.
	other, _ := btcec.NewPrivateKey()
	var msg [32]byte
	copy(msg[:], mustHexBytes(toSign))
	wrong, _ := elements.SignSchnorr(other.Serialize(), msg)

	code, out := f.policyComplete(t, policyID, map[string]any{
		"sig": hex.EncodeToString(wrong), "verifier_cmrs": nextCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(f.vTxid, f.vVout, nextSPK),
	})
	if code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "does not verify") {
		t.Fatalf("a foreign signature must be refused 400: %d %v", code, out)
	}
	if len(f.node.sends) != sendsBefore {
		t.Fatal("a refused update must broadcast nothing")
	}
	if latest, _ := f.st.LatestSnapshot(f.asset); latest.Seq != 0 {
		t.Fatalf("a refused update must publish nothing, latest seq = %d", latest.Seq)
	}
	// Still retryable with the right signature, and the SAME id: a refusal does
	// not consume the prepare.
	code, out = f.policyComplete(t, policyID, map[string]any{
		"sig": f.sign(t, toSign), "verifier_cmrs": nextCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(f.vTxid, f.vVout, nextSPK),
	})
	if code != 200 {
		t.Fatalf("the same prepare must still complete with the right signature: %d %v", code, out)
	}
}

func TestDampPolicy_StaleDerivationRefused(t *testing.T) {
	f := newDampPolicyFixture(t)
	sendsBefore := len(f.node.sends)
	code, prep := f.policyPrepare(t, map[string]any{
		"remove_whitelist": []string{f.v.whitelistKeys()[2]},
		"reason":           "sanctions listing",
	})
	if code != 200 {
		t.Fatalf("prepare: %d %v", code, prep)
	}
	policyID, _ := prep["policy_id"].(string)
	sig := f.sign(t, prep["to_sign"].(string))
	_, nextSPK := f.nextVerifier(t, 0x03)

	// (a) The CURRENT program: a derivation that ran against the old policy. It
	// would recreate the old C_V, so the freeze would publish and not bind.
	code, out := f.policyComplete(t, policyID, map[string]any{
		"sig": sig, "verifier_cmrs": f.v.shapeCMRs(),
		"signed_tx": f.respend(f.vTxid, f.vVout, nextSPK),
	})
	if code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "CURRENT policy") {
		t.Fatalf("an unchanged verifier program must be refused 409: %d %v", code, out)
	}

	// (b) A CMR and a scriptPubKey that do not belong to each other: the paste
	// error that would fund an address nothing can spend.
	otherCMR, _ := f.nextVerifier(t, 0x04)
	code, out = f.policyComplete(t, policyID, map[string]any{
		"sig": sig, "verifier_cmrs": otherCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(f.vTxid, f.vVout, nextSPK),
	})
	if code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "verifier_spk mismatch") {
		t.Fatalf("a CMR/scriptPubKey mismatch must be refused 409: %d %v", code, out)
	}

	if len(f.node.sends) != sendsBefore {
		t.Fatal("neither refusal may broadcast anything")
	}
	if latest, _ := f.st.LatestSnapshot(f.asset); latest.Seq != 0 {
		t.Fatalf("neither refusal may publish anything, latest seq = %d", latest.Seq)
	}
}

func TestDampPolicy_RespendShapeRefused(t *testing.T) {
	f := newDampPolicyFixture(t)
	sendsBefore := len(f.node.sends)
	code, prep := f.policyPrepare(t, map[string]any{
		"add_blacklist": []any{map[string]any{"txid": strings.Repeat("aa", 32), "vout": 0}},
		"reason":        "stolen-coin report",
	})
	if code != 200 {
		t.Fatalf("prepare: %d %v", code, prep)
	}
	policyID, _ := prep["policy_id"].(string)
	sig := f.sign(t, prep["to_sign"].(string))
	nextCMR, nextSPK := f.nextVerifier(t, 0x05)

	// (a) Spends some other coin: not this asset's rules output at all.
	code, out := f.policyComplete(t, policyID, map[string]any{
		"sig": sig, "verifier_cmrs": nextCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(strings.Repeat("bb", 32), 0, nextSPK),
	})
	if code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "rules output") {
		t.Fatalf("a spend of the wrong coin must be refused 409: %d %v", code, out)
	}

	// (b) Spends the right coin but does not recreate the rules output under the
	// new policy: that is a HALT dressed as an update, and it would leave the
	// asset unable to transfer at all while a snapshot claimed otherwise.
	_, strangerSPK := f.nextVerifier(t, 0x06)
	code, out = f.policyComplete(t, policyID, map[string]any{
		"sig": sig, "verifier_cmrs": nextCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(f.vTxid, f.vVout, strangerSPK),
	})
	if code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "does not recreate") {
		t.Fatalf("a spend that does not recreate the rules output must be refused 409: %d %v", code, out)
	}

	if len(f.node.sends) != sendsBefore {
		t.Fatal("neither refusal may broadcast anything")
	}
	if latest, _ := f.st.LatestSnapshot(f.asset); latest.Seq != 0 {
		t.Fatalf("neither refusal may publish anything, latest seq = %d", latest.Seq)
	}
}

func TestDampPolicy_ReplayIsIdempotent(t *testing.T) {
	f := newDampPolicyFixture(t)
	sendsBefore := len(f.node.sends)
	code, prep := f.policyPrepare(t, map[string]any{
		"remove_whitelist": []string{f.v.whitelistKeys()[1]},
		"reason":           "insolvency order",
	})
	if code != 200 {
		t.Fatalf("prepare: %d %v", code, prep)
	}
	policyID, _ := prep["policy_id"].(string)
	nextCMR, nextSPK := f.nextVerifier(t, 0x07)
	body := map[string]any{
		"sig": f.sign(t, prep["to_sign"].(string)), "verifier_cmrs": nextCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(f.vTxid, f.vVout, nextSPK),
	}
	code, first := f.policyComplete(t, policyID, body)
	if code != 200 {
		t.Fatalf("complete: %d %v", code, first)
	}
	code, second := f.policyComplete(t, policyID, body)
	if code != 200 || second["idempotent"] != true || second["txid"] != first["txid"] {
		t.Fatalf("a replay must return the same txid without re-broadcasting: %d %v", code, second)
	}
	if len(f.node.sends) != sendsBefore+1 {
		t.Fatalf("a replay must not broadcast again: %d transactions", len(f.node.sends)-sendsBefore)
	}
	// And it must not have published seq 2.
	if latest, _ := f.st.LatestSnapshot(f.asset); latest.Seq != 1 {
		t.Fatalf("a replay must not publish a second policy, latest seq = %d", latest.Seq)
	}
}

// --- height bounds travel with the holder they bind ---------------------------

// TestDampPolicy_HeightBoundsRoundTrip: a lockup or a receive window is part of
// the holder's LEAF, so it has to survive every hop of a policy update. If it did
// not, the published root would omit it and the commitment would be one no
// deployed program answers to, which fails every transfer rather than merely
// losing a restriction.
func TestDampPolicy_HeightBoundsRoundTrip(t *testing.T) {
	f := newDampPolicyFixture(t)
	holders := f.v.whitelistKeys()
	newcomer, _ := btcec.NewPrivateKey()
	newcomerX := hex.EncodeToString(schnorr.SerializePubKey(newcomer.PubKey()))

	// Admit a holder WITH a receive window, and put a lockup on an existing one, in
	// the same change.
	code, prep := f.policyPrepare(t, map[string]any{
		"add_whitelist": []any{map[string]any{"key": newcomerX, "recv_after": 94800}},
		"set_windows":   []any{map[string]any{"key": holders[1], "send_after": 95200}},
		"reason":        "subscription agreement: 12-month holding period",
	})
	if code != 200 {
		t.Fatalf("prepare: %d %v", code, prep)
	}

	// The published document carries the bounds, and an unbounded holder is still a
	// bare key (which is what keeps every pre-bounds document byte-identical).
	snapRaw, _ := json.Marshal(prep["snapshot"])
	var snap damp.Snapshot
	if err := json.Unmarshal(snapRaw, &snap); err != nil {
		t.Fatal(err)
	}
	bounds := map[string][2]uint32{}
	bare := 0
	for _, e := range snap.Predicates.Whitelist.Entries {
		if e.Unbounded() {
			bare++
			continue
		}
		bounds[e.Key] = [2]uint32{e.SendAfter, e.RecvAfter}
	}
	if bounds[newcomerX] != [2]uint32{0, 94800} {
		t.Fatalf("the admitted holder must carry its receive window: %v", bounds)
	}
	if bounds[holders[1]] != [2]uint32{95200, 0} {
		t.Fatalf("the existing holder must carry its lockup: %v", bounds)
	}
	if bare != len(holders)-1 {
		t.Fatalf("every other holder must stay unbounded, got %d bare of %d", bare, len(holders))
	}
	if !strings.Contains(string(snapRaw), `"recv_after":94800`) {
		t.Fatalf("the canonical document must serialize the bound: %s", snapRaw)
	}

	// The document is self-consistent: its declared root is the root over the
	// LEAVES, bounds included. Validate is what proves that, and it is the check
	// that would have caught a keys-only root.
	if err := snap.Validate(); err != nil {
		t.Fatalf("the updated policy must be self-consistent: %v", err)
	}

	// Publishing it keeps the bounds, so the NEXT update starts from them rather
	// than silently dropping them.
	policyID, _ := prep["policy_id"].(string)
	nextCMR, nextSPK := f.nextVerifier(t, 0x11)
	code, out := f.policyComplete(t, policyID, map[string]any{
		"sig": f.sign(t, prep["to_sign"].(string)), "verifier_cmrs": nextCMR, "verifier_spk": nextSPK,
		"signed_tx": f.respend(f.vTxid, f.vVout, nextSPK),
	})
	if code != 200 {
		t.Fatalf("complete: %d %v", code, out)
	}
	var bound *store.DampBinding
	f.st.View(func(st *store.State) { bound = st.Assets[f.asset].Damp })
	kept := map[string][2]uint32{}
	for _, e := range bound.Whitelist {
		kept[e.Key] = [2]uint32{e.SendAfter, e.RecvAfter}
	}
	if kept[newcomerX] != [2]uint32{0, 94800} || kept[holders[1]] != [2]uint32{95200, 0} {
		t.Fatalf("the stored holder list must keep the bounds: %v", kept)
	}

	// A second change that touches neither bound must carry both forward, and the
	// document it publishes must still be self-consistent with the bounded root.
	f.publishVerifierOutput(t, nextSPK, f.node.lastTxid(t), 0)
	code, prep2 := f.policyPrepare(t, map[string]any{
		"remove_whitelist": []string{holders[2]},
		"reason":           "court order 2026-1200",
	})
	if code != 200 {
		t.Fatalf("second prepare: %d %v", code, prep2)
	}
	snapRaw2, _ := json.Marshal(prep2["snapshot"])
	var snap2 damp.Snapshot
	if err := json.Unmarshal(snapRaw2, &snap2); err != nil {
		t.Fatal(err)
	}
	carried := 0
	for _, e := range snap2.Predicates.Whitelist.Entries {
		if !e.Unbounded() {
			carried++
		}
	}
	if carried != 2 {
		t.Fatalf("an unrelated change must carry both bounds forward, got %d: %s", carried, snapRaw2)
	}
	if err := snap2.Validate(); err != nil {
		t.Fatalf("the carried-forward policy must be self-consistent: %v", err)
	}
}

// TestDampPolicy_BoundsRefusals: setting bounds is refused where it would mean
// something the issuer did not ask for.
func TestDampPolicy_BoundsRefusals(t *testing.T) {
	f := newDampPolicyFixture(t)
	holders := f.v.whitelistKeys()
	stranger, _ := btcec.NewPrivateKey()
	strangerX := hex.EncodeToString(schnorr.SerializePubKey(stranger.PubKey()))
	sendsBefore := len(f.node.sends)

	// Bounds for someone who cannot hold the token at all.
	code, out := f.policyPrepare(t, map[string]any{
		"set_windows": []any{map[string]any{"key": strangerX, "send_after": 100}},
		"reason":      "lockup",
	})
	if code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "no height bounds to set") {
		t.Fatalf("bounds for a holder who is not admitted must be refused: %d %v", code, out)
	}
	// Bounds identical to the ones already published: a sequence number and a
	// transaction for nothing.
	code, out = f.policyPrepare(t, map[string]any{
		"set_windows": []any{map[string]any{"key": holders[0], "send_after": 0, "recv_after": 0}},
		"reason":      "lift the lockup",
	})
	if code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "already has exactly those height bounds") {
		t.Fatalf("a no-op bound change must be refused: %d %v", code, out)
	}
	if len(f.node.sends) != sendsBefore {
		t.Fatal("a refused prepare must broadcast nothing")
	}
}

// --- request-shape refusals --------------------------------------------------

func TestDampPolicy_RequestRefusals(t *testing.T) {
	f := newDampPolicyFixture(t)
	holders := f.v.whitelistKeys()
	// A perfectly valid key that simply is not on this asset's list.
	stranger, _ := btcec.NewPrivateKey()
	strangerX := hex.EncodeToString(schnorr.SerializePubKey(stranger.PubKey()))

	cases := []struct {
		name string
		body map[string]any
		code int
		want string
	}{
		{"no reason", map[string]any{"remove_whitelist": []string{holders[2]}}, 400, "a reason is required"},
		{"no change", map[string]any{"reason": "housekeeping"}, 400, "changes nothing"},
		{"empty list", map[string]any{"reason": "wind down", "remove_whitelist": holders}, 400, "cannot be emptied"},
		{"duplicate holder", map[string]any{"reason": "onboard", "add_whitelist": []string{holders[0]}}, 400, "can already hold"},
		{"absent holder", map[string]any{"reason": "freeze", "remove_whitelist": []string{strangerX}}, 400, "not on this asset's holder list"},
		{"absent listing", map[string]any{"reason": "lift", "remove_blacklist": []any{map[string]any{"txid": strings.Repeat("cc", 32), "vout": 1}}}, 400, "not frozen"},
		{"unknown asset", map[string]any{"asset": strings.Repeat("ab", 32), "reason": "freeze", "remove_whitelist": []string{holders[2]}}, 404, "unknown asset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sends := len(f.node.sends)
			code, out := f.policyPrepare(t, tc.body)
			if code != tc.code || !strings.Contains(fmt.Sprint(out["error"]), tc.want) {
				t.Fatalf("want %d containing %q, got %d %v", tc.code, tc.want, code, out)
			}
			if len(f.node.sends) != sends {
				t.Fatal("a refused prepare must broadcast nothing")
			}
		})
	}
}

// TestDampPolicy_CosignAssetRefused: the co-signed tier has no published policy
// to update, and saying so names the controls it DOES have.
func TestDampPolicy_CosignAssetRefused(t *testing.T) {
	v := loadDampVectors(t)
	s, st, node := newDampServer(t, v)
	if err := st.Update(func(state *store.State) error {
		state.Assets["cosigned"] = &store.Asset{ID: "cosigned", Ticker: "CSN"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	code, out := postJSON(t, s.handleDampPolicyPrepare, "/v1/issuer/damp-policy", map[string]any{
		"asset": "cosigned", "reason": "freeze", "remove_whitelist": []string{v.whitelistKeys()[0]},
	})
	if code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "co-signed, not network-enforced") {
		t.Fatalf("want 409 naming the co-signed controls, got %d %v", code, out)
	}
	if len(node.sends) != 0 {
		t.Fatal("nothing may be broadcast")
	}
}

// TestDampPolicy_NotConfigured: with no CMR pinning file the endpoints answer the
// same capability refusal every damp endpoint gives, so a client can tell "this
// deployment cannot" from "this request is wrong".
func TestDampPolicy_NotConfigured(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{}, st: st}
	code, out := postJSON(t, s.handleDampPolicyPrepare, "/v1/issuer/damp-policy", map[string]any{
		"asset": strings.Repeat("11", 32), "reason": "freeze",
	})
	if code != 501 || out["error"] != dampNotConfigured {
		t.Fatalf("want 501 %q, got %d %v", dampNotConfigured, code, out)
	}
}

// --- the register a network-enforced asset actually has -----------------------

// TestDamp_RegisterComesFromTheHolderList reproduces the live pilot defect: an
// asset with units on chain reported a supply of 0 and an empty holder map,
// because the scan enumerated openampd's REGISTERED users and a network-enforced
// holder never has to register. The holder list is the population, and this test
// has no registered users at all.
func TestDamp_RegisterComesFromTheHolderList(t *testing.T) {
	v := loadDampVectors(t)
	s, st, node := newDampServer(t, v)

	// The pilot's two holders and its 600/400 split after an offline transfer.
	const (
		keyA = "32ef65772acc320c0c2a664c70e3728bf1e0c2f3702053afb08a8bc79a8292e8"
		keyB = "2f1bd972deaa29fb301ebf7d825176c4c0698f42a9d793eeee9f3daba05807da"
	)
	assetID := "c6fa7325613fe80ccefbb75e07fc3809ee0745aa4c05294fa5c5898ff8e693d6"
	asset := &store.Asset{
		ID: assetID, Ticker: "PILOT", Name: "Pilot", Precision: 0, Enforcement: "damp",
		Damp: &store.DampBinding{
			VerifierAsset: strings.Repeat("5a", 32), VerifierAmount: 1,
			UserCMR: v.Programs.UCMR, VerifierCMR: v.Programs.PCMR, VerifierCMRs: v.shapeCMRs(), IssuerCMR: v.Programs.GCMR,
			Whitelist: damp.KeyEntries([]string{keyA, keyB}), Tree: damp.TreeDMTv1,
		},
	}
	if err := st.Update(func(state *store.State) error {
		state.Assets[assetID] = asset
		state.Height = 94_711
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	spkFor := func(key string) string {
		raw, err := dampHolderSPK(asset, key)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	spkA, spkB := spkFor(keyA), spkFor(keyB)
	node.scanUnspents[spkA] = map[string]any{
		"txid": strings.Repeat("31", 32), "vout": 0, "amount": 600.0 / 1e8,
		"asset": assetID, "scriptPubKey": spkA,
	}
	node.scanUnspents[spkB] = map[string]any{
		"txid": strings.Repeat("32", 32), "vout": 1, "amount": 400.0 / 1e8,
		"asset": assetID, "scriptPubKey": spkB,
	}

	var users int
	st.View(func(state *store.State) { users = len(state.Users) })
	if users != 0 {
		t.Fatal("the point of this test is that a network-enforced holder need not be registered")
	}

	rec := httptest.NewRecorder()
	s.handleHolders(rec, httptest.NewRequest("GET", "/v1/issuer/holders?asset="+assetID, nil))
	var holders map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &holders)
	if fmt.Sprint(holders["total_atoms"]) != "1000" {
		t.Fatalf("the register must total the 1000 units on chain: %s", rec.Body.String())
	}
	byAID, _ := holders["holders"].(map[string]any)
	aidA, aidB := store.AID([]string{keyA}), store.AID([]string{keyB})
	if fmt.Sprint(byAID[aidA]) != "600" || fmt.Sprint(byAID[aidB]) != "400" {
		t.Fatalf("both holders must appear with their own balance: %s", rec.Body.String())
	}
	keys, _ := holders["holder_keys"].(map[string]any)
	if keys[aidA] != keyA || keys[aidB] != keyB {
		t.Fatalf("each row must name the key it belongs to: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.handleSupply(rec, httptest.NewRequest("GET", "/v1/supply?asset="+assetID, nil))
	var supply map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &supply)
	if fmt.Sprint(supply["circulating_atoms"]) != "1000" {
		t.Fatalf("circulating supply must be chain-derived from the holder list: %s", rec.Body.String())
	}

	// A holder REMOVED from the list stops being scanned, which is what keeps the
	// register honest after a freeze: their coins are still on chain, but they are
	// no longer a holder this policy admits.
	if err := st.Update(func(state *store.State) error {
		state.Assets[assetID].Damp.Whitelist = damp.KeyEntries([]string{keyA})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.handleSupply(rec, httptest.NewRequest("GET", "/v1/supply?asset="+assetID, nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &supply)
	if fmt.Sprint(supply["circulating_atoms"]) != "600" {
		t.Fatalf("after the list drops a holder the scan must follow it: %s", rec.Body.String())
	}
}
