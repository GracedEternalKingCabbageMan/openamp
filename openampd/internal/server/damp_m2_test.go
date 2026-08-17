package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// OpenDAMP M2: the enforcement election is plumbed through issuance ("cosign"
// stays byte-identical, "damp" is refused with a capability error and zero
// side effects) and the snapshot service is live (validated, sequenced,
// signature-checked publication of policy snapshots).

// newM2Server wires a Server with no node/wallet: every path under test here
// is pure data plane and must never touch the chain.
func newM2Server(t *testing.T, cfg Config) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg, st: st, pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(st)}
	return s, st
}

// TestM2_CosignByteIdentity extends the OA-1 byte-identity pattern to the
// enforcement election: an enforcement:"cosign" issuance builds the EXACT
// contract bytes of an enforcement-absent one (which are the pinned pre-OA-1
// bytes), so no existing asset id can shift.
func TestM2_CosignByteIdentity(t *testing.T) {
	absent := baseReq()
	cosign := baseReq()
	cosign.Enforcement = "cosign"

	a, err := canonicalJSON(absent.buildContract(oa1IssuerPub, oa1PolicyPub, true))
	if err != nil {
		t.Fatal(err)
	}
	c, err := canonicalJSON(cosign.buildContract(oa1IssuerPub, oa1PolicyPub, true))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, c) {
		t.Fatalf("cosign election changed the contract bytes:\n absent: %s\n cosign: %s", a, c)
	}
	want := `{"issuer_pubkey":"` + oa1IssuerPub + `","name":"BONDX","openamp":{"burn_allowed":false,"clawback":true,"policy_pubkey":"` + oa1PolicyPub + `","type":"restricted","version":1},"precision":8,"ticker":"BONDX","version":0}`
	if string(c) != want {
		t.Fatalf("cosign contract is not the pinned pre-M2 shape.\n got: %s\nwant: %s", c, want)
	}
	if strings.Contains(string(c), "enforcement") {
		t.Fatalf("enforcement key must never appear for cosign: %s", c)
	}
}

func postIssue(t *testing.T, s *Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/assets", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleIssue(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// storeIsPristine asserts the issuance refusal had zero side effects: no
// assets, no users beyond the given, no stored keys, no pending state.
func storeIsPristine(t *testing.T, st *store.Store) {
	t.Helper()
	st.View(func(state *store.State) {
		if len(state.Assets) != 0 {
			t.Fatalf("refused issuance persisted an asset: %+v", state.Assets)
		}
		if len(state.PendingTransfers) != 0 || len(state.PendingClawbacks) != 0 || len(state.PendingReissues) != 0 {
			t.Fatal("refused issuance left pending state")
		}
	})
	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("refused issuance persisted keys: %v", keys)
	}
}

// TestM2_DampIssuanceRefused: with no CMR pinning file configured, enforcement
// "damp" on the CO-SIGNED endpoint is a 501 capability error with the exact
// documented body, a logged refusal, and no side effects. (When network
// enforcement IS configured this same election is routed to
// /v1/issuer/damp-assets instead; see TestDamp_HostedIssueRoutesToDampEndpoint.)
func TestM2_DampIssuanceRefused(t *testing.T) {
	s, st := newM2Server(t, Config{DemoIssuer: true})
	code, out := postIssue(t, s, map[string]any{
		"name": "DampCo", "ticker": "DMP", "atoms": 1000,
		"holder_aid": "h", "issuer_aid": "i",
		"enforcement": "damp", "verifier_amount": 1000,
	})
	if code != 501 {
		t.Fatalf("want 501, got %d: %v", code, out)
	}
	if out["error"] != dampNotConfigured {
		t.Fatalf("wrong capability error: %v", out["error"])
	}
	storeIsPristine(t, st)

	// The refusal is in the transparency log.
	raw, err := os.ReadFile(st.LogPath())
	if err != nil {
		t.Fatalf("no transparency log written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var entry store.LogEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Action != "issue" {
		t.Fatalf("refusal logged under action %q", entry.Action)
	}
	var data map[string]any
	json.Unmarshal(entry.Data, &data)
	if data["refused"] != true || data["enforcement"] != "damp" {
		t.Fatalf("refusal entry malformed: %s", entry.Data)
	}
}

// TestM2_EnforcementValidation: unknown values 400, and verifier_amount is
// refused outside damp — all before any side effect.
func TestM2_EnforcementValidation(t *testing.T) {
	s, st := newM2Server(t, Config{DemoIssuer: true})
	code, out := postIssue(t, s, map[string]any{
		"name": "X", "ticker": "X", "enforcement": "bogus",
	})
	if code != 400 || !strings.Contains(out["error"].(string), "enforcement must be") {
		t.Fatalf("bogus enforcement: want 400, got %d %v", code, out)
	}
	code, out = postIssue(t, s, map[string]any{
		"name": "X", "ticker": "X", "enforcement": "cosign", "verifier_amount": 5,
	})
	if code != 400 || !strings.Contains(out["error"].(string), "verifier_amount") {
		t.Fatalf("cosign+verifier_amount: want 400, got %d %v", code, out)
	}
	code, out = postIssue(t, s, map[string]any{
		"name": "X", "ticker": "X", "verifier_amount": 5,
	})
	if code != 400 || !strings.Contains(out["error"].(string), "verifier_amount") {
		t.Fatalf("absent+verifier_amount: want 400, got %d %v", code, out)
	}
	storeIsPristine(t, st)
}

// --- snapshot service ---------------------------------------------------------

const m2Token = "m2-test-token"

// m2Snapshot builds a valid signed snapshot for asset with the given seq and
// blacklist entries, chained onto prevPi (nil for seq 0).
func m2Snapshot(t *testing.T, priv *btcec.PrivateKey, assetHex string, seq uint64, prevPi *string, blacklist ...[32]byte) *damp.Snapshot {
	t.Helper()
	tree := damp.NewSMT()
	entries := make([]string, 0, len(blacklist))
	for _, k := range blacklist {
		tree.Insert(k)
		entries = append(entries, hex.EncodeToString(k[:]))
	}
	root := tree.Root()
	s := &damp.Snapshot{
		V:             1,
		Asset:         assetHex,
		VerifierAsset: strings.Repeat("77", 32),
		Q:             1000,
		Seq:           seq,
		PrevPi:        prevPi,
		Tree:          damp.TreeSMTv1,
		Predicates: damp.Predicates{
			Blacklist: damp.PredicateList{Root: hex.EncodeToString(root[:]), Entries: entries},
		},
	}
	pi, err := s.ComputePi()
	if err != nil {
		t.Fatal(err)
	}
	s.Pi = hex.EncodeToString(pi[:])
	if err := s.Sign(priv.Serialize()); err != nil {
		t.Fatal(err)
	}
	return s
}

// postSnapshot sends the snapshot through the real route table (auth included).
func postSnapshot(t *testing.T, h http.Handler, token string, snap *damp.Snapshot, issuerPubkey string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if issuerPubkey != "" {
		var m map[string]any
		json.Unmarshal(body, &m)
		m["issuer_pubkey"] = issuerPubkey
		body, _ = json.Marshal(m)
	}
	req := httptest.NewRequest("POST", "/v1/issuer/snapshots", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func getSnapshot(t *testing.T, h http.Handler, query string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/v1/snapshots"+query, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// TestM2_SnapshotRoundTrip: post seq 0 and seq 1 (TOFU key), read back latest,
// exact seq, and the 404s; verify the served document verifies offline.
func TestM2_SnapshotRoundTrip(t *testing.T) {
	s, st := newM2Server(t, Config{IssuerToken: m2Token})
	h := s.Routes()
	priv, _ := btcec.NewPrivateKey()
	pubHex := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	assetHex := strings.Repeat("42", 32)

	// Unauthorized post refused.
	snap0 := m2Snapshot(t, priv, assetHex, 0, nil, damp.OutpointKey([32]byte{1}, 0))
	if code, _ := postSnapshot(t, h, "wrong", snap0, pubHex); code != 401 {
		t.Fatalf("bad token: want 401, got %d", code)
	}
	// First snapshot of an unknown asset requires the key.
	if code, out := postSnapshot(t, h, m2Token, snap0, ""); code != 400 || !strings.Contains(out["error"].(string), "issuer_pubkey is required") {
		t.Fatalf("keyless TOFU post: want 400, got %d %v", code, out)
	}
	code, out := postSnapshot(t, h, m2Token, snap0, pubHex)
	if code != 200 {
		t.Fatalf("seq 0 post failed: %d %v", code, out)
	}
	if out["pi"] != snap0.Pi || out["seq"] != float64(0) {
		t.Fatalf("post response wrong: %v", out)
	}

	// Chain seq 1 onto pi 0.
	snap1 := m2Snapshot(t, priv, assetHex, 1, &snap0.Pi,
		damp.OutpointKey([32]byte{1}, 0), damp.OutpointKey([32]byte{2}, 3))
	if code, out := postSnapshot(t, h, m2Token, snap1, ""); code != 200 {
		t.Fatalf("seq 1 post failed: %d %v", code, out)
	}

	// GET latest.
	code, got := getSnapshot(t, h, "?asset="+assetHex)
	if code != 200 || got["seq"] != float64(1) || got["pi"] != snap1.Pi {
		t.Fatalf("latest: %d %v", code, got)
	}
	// The served document re-verifies offline: canonical bytes -> Snapshot,
	// Validate, then Verify against the pinned key the server returns.
	rawSnap, _ := json.Marshal(got["snapshot"])
	var served damp.Snapshot
	if err := json.Unmarshal(rawSnap, &served); err != nil {
		t.Fatal(err)
	}
	served.IssuerSig = got["issuer_sig"].(string)
	if err := served.Validate(); err != nil {
		t.Fatalf("served snapshot invalid: %v", err)
	}
	if err := served.Verify(got["issuer_pub"].(string)); err != nil {
		t.Fatalf("served snapshot signature: %v", err)
	}

	// GET exact seq, and the 404s.
	if code, got := getSnapshot(t, h, "?asset="+assetHex+"&seq=0"); code != 200 || got["pi"] != snap0.Pi {
		t.Fatalf("seq=0: %d %v", code, got)
	}
	if code, _ := getSnapshot(t, h, "?asset="+assetHex+"&seq=2"); code != 404 {
		t.Fatalf("seq=2 should 404, got %d", code)
	}
	if code, _ := getSnapshot(t, h, "?asset="+strings.Repeat("43", 32)); code != 404 {
		t.Fatalf("unknown asset should 404, got %d", code)
	}
	if code, _ := getSnapshot(t, h, ""); code != 400 {
		t.Fatalf("missing asset param should 400, got %d", code)
	}
	if code, _ := getSnapshot(t, h, "?asset="+assetHex+"&seq=x"); code != 400 {
		t.Fatalf("bad seq should 400, got %d", code)
	}

	// The publication is in the transparency log.
	raw, _ := os.ReadFile(st.LogPath())
	if !strings.Contains(string(raw), `"snapshot"`) || !strings.Contains(string(raw), snap1.Pi) {
		t.Fatal("snapshot publication not logged")
	}
}

// TestM2_SnapshotSequencing: gaps, wrong first seq, and broken prev_pi links
// are refused with 409.
func TestM2_SnapshotSequencing(t *testing.T) {
	s, _ := newM2Server(t, Config{IssuerToken: m2Token})
	h := s.Routes()
	priv, _ := btcec.NewPrivateKey()
	pubHex := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	assetHex := strings.Repeat("44", 32)

	// First must be 0.
	pi0 := strings.Repeat("aa", 32)
	if code, out := postSnapshot(t, h, m2Token, m2Snapshot(t, priv, assetHex, 1, &pi0), pubHex); code != 409 {
		t.Fatalf("first seq 1: want 409, got %d %v", code, out)
	}
	snap0 := m2Snapshot(t, priv, assetHex, 0, nil)
	if code, out := postSnapshot(t, h, m2Token, snap0, pubHex); code != 200 {
		t.Fatalf("seq 0: %d %v", code, out)
	}
	// Gap: seq 2 next.
	if code, out := postSnapshot(t, h, m2Token, m2Snapshot(t, priv, assetHex, 2, &snap0.Pi), pubHex); code != 409 || !strings.Contains(out["error"].(string), "seq must be 1") {
		t.Fatalf("seq gap: want 409, got %d %v", code, out)
	}
	// Replay of seq 0 is also a 409 (not idempotent-accepted: pi may differ).
	if code, _ := postSnapshot(t, h, m2Token, snap0, pubHex); code != 409 {
		t.Fatalf("seq replay: want 409")
	}
	// Wrong prev_pi.
	wrongPrev := strings.Repeat("bb", 32)
	if code, out := postSnapshot(t, h, m2Token, m2Snapshot(t, priv, assetHex, 1, &wrongPrev), pubHex); code != 409 || !strings.Contains(out["error"].(string), "prev_pi") {
		t.Fatalf("wrong prev_pi: want 409, got %d %v", code, out)
	}
	// Correct chain still accepted afterwards.
	if code, out := postSnapshot(t, h, m2Token, m2Snapshot(t, priv, assetHex, 1, &snap0.Pi), pubHex); code != 200 {
		t.Fatalf("valid seq 1 refused: %d %v", code, out)
	}
}

// TestM2_SnapshotBadSignature: a signature by the wrong key, a tampered one,
// a key swap mid-chain, and a missing signature are all refused.
func TestM2_SnapshotBadSignature(t *testing.T) {
	s, _ := newM2Server(t, Config{IssuerToken: m2Token})
	h := s.Routes()
	priv, _ := btcec.NewPrivateKey()
	pubHex := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	other, _ := btcec.NewPrivateKey()
	otherPub := hex.EncodeToString(schnorr.SerializePubKey(other.PubKey()))
	assetHex := strings.Repeat("45", 32)

	// Signed by priv but claiming otherPub.
	snap := m2Snapshot(t, priv, assetHex, 0, nil)
	if code, out := postSnapshot(t, h, m2Token, snap, otherPub); code != 400 || !strings.Contains(out["error"].(string), "issuer_sig") {
		t.Fatalf("wrong key: want 400, got %d %v", code, out)
	}
	// Tampered signature bytes.
	bad := *snap
	sb, _ := hex.DecodeString(bad.IssuerSig)
	sb[3] ^= 0x01
	bad.IssuerSig = hex.EncodeToString(sb)
	if code, _ := postSnapshot(t, h, m2Token, &bad, pubHex); code != 400 {
		t.Fatalf("tampered sig: want 400")
	}
	// Missing signature.
	unsigned := *snap
	unsigned.IssuerSig = ""
	if code, out := postSnapshot(t, h, m2Token, &unsigned, pubHex); code != 400 || !strings.Contains(out["error"].(string), "issuer_sig is required") {
		t.Fatalf("missing sig: want 400, got %d %v", code, out)
	}
	// Establish the chain under priv, then try to continue it under other:
	// the pinned key must win.
	if code, _ := postSnapshot(t, h, m2Token, snap, pubHex); code != 200 {
		t.Fatal("valid seq 0 refused")
	}
	splice := m2Snapshot(t, other, assetHex, 1, &snap.Pi)
	if code, _ := postSnapshot(t, h, m2Token, splice, otherPub); code != 400 {
		t.Fatalf("key swap mid-chain: want 400")
	}
}

// TestM2_SnapshotWrongRoot: Validate refuses a snapshot whose declared
// blacklist root does not match its entries, and one whose pi does not match
// its header.
func TestM2_SnapshotWrongRoot(t *testing.T) {
	s, _ := newM2Server(t, Config{IssuerToken: m2Token})
	h := s.Routes()
	priv, _ := btcec.NewPrivateKey()
	pubHex := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	assetHex := strings.Repeat("46", 32)

	snap := m2Snapshot(t, priv, assetHex, 0, nil, damp.OutpointKey([32]byte{9}, 0))
	snap.Predicates.Blacklist.Root = strings.Repeat("ee", 32)
	snap.Sign(priv.Serialize()) // re-sign so only the root is wrong
	if code, out := postSnapshot(t, h, m2Token, snap, pubHex); code != 400 || !strings.Contains(out["error"].(string), "root mismatch") {
		t.Fatalf("wrong root: want 400 root mismatch, got %d %v", code, out)
	}

	snap2 := m2Snapshot(t, priv, assetHex, 0, nil)
	snap2.Pi = strings.Repeat("ee", 32)
	snap2.Sign(priv.Serialize())
	if code, out := postSnapshot(t, h, m2Token, snap2, pubHex); code != 400 || !strings.Contains(out["error"].(string), "pi mismatch") {
		t.Fatalf("wrong pi: want 400 pi mismatch, got %d %v", code, out)
	}
}

// TestM2_SnapshotKnownAsset: for an asset this daemon issued, the signature
// must verify against the STORED IssuerPub; a request-supplied key must match
// it, and a snapshot signed by any other key is refused.
func TestM2_SnapshotKnownAsset(t *testing.T) {
	s, st := newM2Server(t, Config{IssuerToken: m2Token})
	h := s.Routes()
	issuerPriv, _ := btcec.NewPrivateKey()
	issuerPub := hex.EncodeToString(schnorr.SerializePubKey(issuerPriv.PubKey()))
	assetHex := strings.Repeat("47", 32)
	if err := st.Update(func(state *store.State) error {
		state.Assets[assetHex] = &store.Asset{
			ID: assetHex, Ticker: "KWN", IssuerPub: issuerPub, IssuerExternal: true,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Signed by a stranger: refused even with the stranger's key supplied.
	stranger, _ := btcec.NewPrivateKey()
	strangerPub := hex.EncodeToString(schnorr.SerializePubKey(stranger.PubKey()))
	snapBad := m2Snapshot(t, stranger, assetHex, 0, nil)
	if code, out := postSnapshot(t, h, m2Token, snapBad, strangerPub); code != 400 || !strings.Contains(out["error"].(string), "registered issuer key") {
		t.Fatalf("stranger key: want 400, got %d %v", code, out)
	}
	if code, _ := postSnapshot(t, h, m2Token, snapBad, ""); code != 400 {
		t.Fatal("stranger sig without key hint must still fail against stored IssuerPub")
	}
	// Signed by the registered issuer: accepted with no key hint needed.
	snap := m2Snapshot(t, issuerPriv, assetHex, 0, nil)
	if code, out := postSnapshot(t, h, m2Token, snap, ""); code != 200 {
		t.Fatalf("registered issuer refused: %d %v", code, out)
	}
	code, got := getSnapshot(t, h, "?asset="+assetHex)
	if code != 200 || got["issuer_pub"] != issuerPub {
		t.Fatalf("stored snapshot not pinned to the registered key: %v", got)
	}
}
