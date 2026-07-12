package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// M9: an external issuer key at issuance (the entity's own browser key becomes
// the enclave issuer half) and a two-phase clawback (build returns the L_claw
// sighashes; complete adds the issuer's signature and broadcasts). Both are
// additive: a no-issuer_pubkey issuance and a legacy (server-held-key) clawback
// behave exactly as before M9.

// newM9Server wires a Server whose node and wallet are the shared oa4Node mock.
func newM9Server(t *testing.T, cfg Config) (*Server, *store.Store, *oa4Node) {
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
	s := &Server{cfg: cfg, st: st, node: cl, wallet: cl,
		pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(st)}
	for i := range s.genesis {
		s.genesis[i] = byte(i + 1)
	}
	return s, st, node
}

// clawAsset registers a clawback-enabled asset. When external, IssuerExternal is
// set and only the policy key is stored; otherwise the issuer key is stored too
// (the legacy single-call path). It returns the asset and the issuer private key.
func clawAsset(t *testing.T, st *store.Store, issuerAID string, external bool) (*store.Asset, []byte) {
	t.Helper()
	var ipriv [32]byte
	if _, err := rand.Read(ipriv[:]); err != nil {
		t.Fatal(err)
	}
	ipub := elements.XOnlyFromPriv(ipriv[:])
	var ppriv [32]byte
	if _, err := rand.Read(ppriv[:]); err != nil {
		t.Fatal(err)
	}
	ppub := elements.XOnlyFromPriv(ppriv[:])
	asset := &store.Asset{
		ID:             strings.Repeat("cd", 32),
		Ticker:         "M9T",
		Name:           "M9 Clawback Asset",
		Precision:      0,
		PolicyPub:      hex.EncodeToString(ppub[:]),
		IssuerPub:      hex.EncodeToString(ipub[:]),
		IssuerExternal: external,
		IssuerAID:      issuerAID,
		Clawback:       true,
	}
	if err := st.Update(func(s *store.State) error { s.Assets[asset.ID] = asset; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveKey("policy:"+asset.ID, hex.EncodeToString(ppriv[:])); err != nil {
		t.Fatal(err)
	}
	if !external {
		if err := st.SaveKey("issuer:"+asset.ID, hex.EncodeToString(ipriv[:])); err != nil {
			t.Fatal(err)
		}
	}
	return asset, ipriv[:]
}

// fundClawback seeds the mock with the holder's enclave coin (of amount atoms)
// and a fee coin, plus the change address, so a clawback sweep can be assembled.
func fundClawback(t *testing.T, s *Server, node *oa4Node, holder *store.User, asset *store.Asset, atoms uint64) {
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
	node.scan[holderSpk] = []rpc.ScanUnspent{{TxID: ePrevID, Vout: 0, Asset: asset.ID, Amount: float64(atoms) / 1e8, ScriptPubKey: holderSpk, Height: 1}}

	feePrev := &elements.Tx{Version: 2}
	feePrev.Out = append(feePrev.Out, explicitOut(oa4FeeID, 100000, oa4FeeSpk))
	feePrev.NormalizeWitness()
	fPrevID := feePrev.TxID()
	node.rawTxs[fPrevID] = hex.EncodeToString(feePrev.Serialize())
	node.feeUnspent = []rpc.Unspent{{TxID: fPrevID, Vout: 0, Amount: 100000.0 / 1e8, Asset: oa4FeeID, ScriptPubKey: oa4FeeSpk, Spendable: true}}

	node.addrSpk[node.newAddr] = oa4ChgSpk
	node.broadcast = strings.Repeat("77", 32)
}

func callClawback(t *testing.T, s *Server, body map[string]any) (int, map[string]any, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/clawback", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleClawback(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func callClawbackComplete(t *testing.T, s *Server, id string, body map[string]any) (int, map[string]any, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/clawback/"+id+"/complete", bytes.NewReader(b))
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.handleClawbackComplete(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// TestM9_TwoPhaseClawback_BroadcastsOnlyAfterIssuerSignature proves the external
// clawback build broadcasts NOTHING (it only returns the L_claw sighashes), and
// the sweep is broadcast ONLY once the issuer's signature completes it. A replay
// of complete returns the same txid and never re-broadcasts (consume-once).
func TestM9_TwoPhaseClawback_BroadcastsOnlyAfterIssuerSignature(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, issuerPriv := clawAsset(t, st, issuer.AID, true) // external issuer key
	fundClawback(t, s, node, holder, asset, 1000)

	// BUILD: returns sighashes, persists a pending clawback, broadcasts nothing.
	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "court order 42",
	})
	if code != 200 {
		t.Fatalf("clawback build failed: %d %s", code, body)
	}
	if _, hasTxid := out["txid"]; hasTxid {
		t.Fatalf("external build must not broadcast (no txid): %s", body)
	}
	if node.sends != 0 {
		t.Fatalf("build must broadcast nothing, saw %d sends", node.sends)
	}
	toSign, _ := out["to_sign"].([]any)
	if len(toSign) != 1 {
		t.Fatalf("expected 1 L_claw input to sign, got %v", out["to_sign"])
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("build did not return a pending id: %s", body)
	}
	// The pending clawback is persisted (survives restart).
	if _, ok := st.GetPendingClawback(id); !ok {
		t.Fatal("build did not persist a pending clawback")
	}
	// The reason is in the public log before any signature.
	if !logHasClawbackReason(t, st, "court order 42") {
		t.Fatal("build must log the reason before signing")
	}

	// The issuer signs the real L_claw sighash with its external key.
	sig0 := signToSign(t, toSign[0], issuerPriv)

	// COMPLETE: adds the issuer signature, co-signs with the policy key, broadcasts.
	code, out, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sig0})
	if code != 200 {
		t.Fatalf("clawback complete failed: %d %s", code, body)
	}
	if out["txid"] != node.broadcast {
		t.Fatalf("expected broadcast txid %s, got %s", node.broadcast, body)
	}
	if node.sends != 1 {
		t.Fatalf("complete must broadcast exactly once, saw %d sends", node.sends)
	}

	// Idempotent replay: returns the same txid, never a second broadcast.
	code, out, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sig0})
	if code != 200 || out["txid"] != node.broadcast || out["idempotent"] != true {
		t.Fatalf("replay must be idempotent with the same txid: %d %s", code, body)
	}
	if node.sends != 1 {
		t.Fatalf("replay must not re-broadcast, saw %d sends", node.sends)
	}
}

// TestM9_TwoPhaseClawback_RejectsWrongIssuerSignature proves complete refuses a
// signature that is not the asset's issuer key over the real sighash, so a sweep
// cannot be completed without the genuine issuer authorization.
func TestM9_TwoPhaseClawback_RejectsWrongIssuerSignature(t *testing.T) {
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
	toSign, _ := out["to_sign"].([]any)

	// Sign with an UNRELATED key, not the asset's issuer key.
	var wrong [32]byte
	if _, err := rand.Read(wrong[:]); err != nil {
		t.Fatal(err)
	}
	sig := signToSign(t, toSign[0], wrong[:])
	code, _, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sig})
	if code != 400 {
		t.Fatalf("expected 400 for a wrong issuer signature, got %d: %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("a rejected completion must broadcast nothing, saw %d sends", node.sends)
	}
}

// TestM9_LegacyClawback_SingleCallUnchanged proves a legacy (server-held issuer
// key, IssuerExternal false) asset still claws back in ONE call that signs both
// parts and broadcasts, returning {txid, atoms} exactly as before M9. There is no
// build/complete step for it.
func TestM9_LegacyClawback_SingleCallUnchanged(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, false) // server holds the issuer key
	fundClawback(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "legacy sweep",
	})
	if code != 200 {
		t.Fatalf("legacy clawback failed: %d %s", code, body)
	}
	if out["txid"] != node.broadcast {
		t.Fatalf("legacy clawback must broadcast in one call, got %s", body)
	}
	if got := uint64(out["atoms"].(float64)); got != 1000 {
		t.Fatalf("expected 1000 atoms swept, got %d", got)
	}
	if _, hasToSign := out["to_sign"]; hasToSign {
		t.Fatalf("legacy clawback must not return to_sign sighashes: %s", body)
	}
	if node.sends != 1 {
		t.Fatalf("legacy clawback must broadcast exactly once, saw %d sends", node.sends)
	}
}

// TestM9_IssueExternalIssuerKey proves an issuance carrying an external
// issuer_pubkey puts the entity key in the contract, records IssuerExternal, and
// stores NO issuer private key (the server never holds it).
func TestM9_IssueExternalIssuerKey(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100, DemoIssuer: true})
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	node.feeUnspent = []rpc.Unspent{{TxID: strings.Repeat("55", 32), Vout: 0, Amount: 100000.0 / 1e8, Asset: oa4FeeID, ScriptPubKey: oa4FeeSpk, Spendable: true}}
	node.addrSpk[node.newAddr] = oa4ChgSpk
	node.broadcast = strings.Repeat("88", 32)

	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	xonly := elements.XOnlyFromPriv(priv[:])
	xhex := hex.EncodeToString(xonly[:])

	code, out, body := callIssue(t, s, map[string]any{
		"name": "EXTA", "ticker": "EXTA", "precision": 0, "atoms": 1000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID, "issuer_pubkey": xhex,
	})
	if code != 200 {
		t.Fatalf("external issuance failed: %d %s", code, body)
	}
	if out["issuer_external"] != true {
		t.Fatalf("response must flag issuer_external for an external key: %s", body)
	}
	contract, _ := out["contract"].(map[string]any)
	if contract["issuer_pubkey"] != xhex {
		t.Fatalf("contract issuer_pubkey must be the entity key %s, got %v", xhex, contract["issuer_pubkey"])
	}
	assetID, _ := out["asset"].(string)
	var asset *store.Asset
	st.View(func(state *store.State) {
		if a, ok := state.Assets[assetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil || !asset.IssuerExternal || asset.IssuerPub != xhex {
		t.Fatalf("asset must record IssuerExternal + the entity key: %#v", asset)
	}
	keys, _ := st.LoadKeys()
	if _, held := keys["issuer:"+assetID]; held {
		t.Fatal("the server must NOT store the issuer private key for an external-key asset")
	}
}

// TestM9_IssueWithoutIssuerKey_LegacyUnchanged proves a no-issuer_pubkey issuance
// keeps the pre-M9 behaviour: a server-generated issuer key is stored, the asset
// is not marked external, and the response carries no issuer_external field.
func TestM9_IssueWithoutIssuerKey_LegacyUnchanged(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100, DemoIssuer: true})
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	node.feeUnspent = []rpc.Unspent{{TxID: strings.Repeat("55", 32), Vout: 0, Amount: 100000.0 / 1e8, Asset: oa4FeeID, ScriptPubKey: oa4FeeSpk, Spendable: true}}
	node.addrSpk[node.newAddr] = oa4ChgSpk
	node.broadcast = strings.Repeat("88", 32)

	code, out, body := callIssue(t, s, map[string]any{
		"name": "LEGA", "ticker": "LEGA", "precision": 0, "atoms": 1000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID,
	})
	if code != 200 {
		t.Fatalf("legacy issuance failed: %d %s", code, body)
	}
	if _, has := out["issuer_external"]; has {
		t.Fatalf("a no-key issuance response must not carry issuer_external: %s", body)
	}
	assetID, _ := out["asset"].(string)
	var asset *store.Asset
	st.View(func(state *store.State) {
		if a, ok := state.Assets[assetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil || asset.IssuerExternal {
		t.Fatalf("a no-key issuance must not be external: %#v", asset)
	}
	keys, _ := st.LoadKeys()
	if _, held := keys["issuer:"+assetID]; !held {
		t.Fatal("a legacy issuance must store the server-generated issuer key")
	}
}

// TestM9_IssueRejectsMalformedIssuerKey proves a malformed external issuer_pubkey
// is refused (32-byte x-only, valid curve point).
func TestM9_IssueRejectsMalformedIssuerKey(t *testing.T) {
	s, st, _ := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100, DemoIssuer: true})
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	for _, bad := range []string{"abcd", strings.Repeat("zz", 32), strings.Repeat("00", 32)} {
		code, _, body := callIssue(t, s, map[string]any{
			"name": "BAD", "ticker": "BAD", "precision": 0, "atoms": 1,
			"holder_aid": holder.AID, "issuer_aid": issuer.AID, "issuer_pubkey": bad,
		})
		if code != 400 {
			t.Fatalf("expected 400 for malformed issuer_pubkey %q, got %d: %s", bad, code, body)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// signToSign signs the sighash of a to_sign entry with priv and returns the
// {input: sig} map the complete endpoint expects.
func signToSign(t *testing.T, entry any, priv []byte) map[string]string {
	t.Helper()
	m, _ := entry.(map[string]any)
	shHex, _ := m["sighash"].(string)
	input := int(m["input"].(float64))
	var sh [32]byte
	copy(sh[:], mustHexBytes(shHex))
	sig, err := elements.SignSchnorr(priv, sh)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{strconv.Itoa(input): hex.EncodeToString(sig)}
}

func logHasClawbackReason(t *testing.T, st *store.Store, reason string) bool {
	t.Helper()
	data, err := readLog(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range data {
		if e.Action == "clawback" {
			var d struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(e.Data, &d)
			if d.Reason == reason {
				return true
			}
		}
	}
	return false
}
