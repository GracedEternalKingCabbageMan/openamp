package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Blinding-key rotation (docs/blinding-key-rotation.md, implemented): versioned
// master secrets, a per-asset epoch in the derivation, watch-wallet re-import
// on rotation, and — the invariant everything else hangs off — epoch 0 stays
// byte-identical to the pre-rotation derivation forever.

// The epoch-0 (v1) derivation pinned as a fixed vector, computed independently
// of the implementation: SHA256(master || "openamp-blind-v1" || assetID ||
// holderXonly) for master aa*32, assetID "bb"*32 (the ASCII hex string),
// holder cc*32. If this fails, existing blinded UTXOs became unreadable.
const (
	rotV1Master = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rotV1Asset  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rotV1Priv   = "e1eadaba2ff7be3c03a99ec387760590be5a9b4fbb12e8a3a0050b8aa49ab535"
	// The epoch-1 (v2) derivation with master-v1 ALSO aa*32: SHA256(master_v1 ||
	// "openamp-blind-v2" || assetID || 00000001 || holderXonly). Pins the wire
	// shape of the versioned derivation.
	rotV2E1Priv = "481cfd5c1a83f21278b6f3b0987dc5a8583b4c4847db2fbba58afcce0f6b745f"
)

func rotHolderX() [32]byte {
	var x [32]byte
	for i := range x {
		x[i] = 0xcc
	}
	return x
}

// TestRotation_V1DerivationPinned proves epoch 0 reproduces the original
// derivation byte-exactly (fixed vector), that blindingKey for an unknown or
// epoch-0 asset routes through it, and that the v2 shape matches its vector.
func TestRotation_V1DerivationPinned(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveKey("blind-master", rotV1Master); err != nil {
		t.Fatal(err)
	}
	s := &Server{st: st}

	priv, _, err := s.blindingKeyAt(rotV1Asset, rotHolderX(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(priv); got != rotV1Priv {
		t.Fatalf("epoch-0 derivation drifted (existing blinded UTXOs would become unreadable):\n got %s\nwant %s", got, rotV1Priv)
	}
	// blindingKey (current-epoch path) for an asset with no record = epoch 0.
	priv2, _, err := s.blindingKey(rotV1Asset, rotHolderX())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv, priv2) {
		t.Fatal("blindingKey must derive at epoch 0 for an unrotated asset")
	}
	// v2 shape, epoch 1.
	if err := st.SaveKey("blind-master-v1", rotV1Master); err != nil {
		t.Fatal(err)
	}
	privV2, _, err := s.blindingKeyAt(rotV1Asset, rotHolderX(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(privV2); got != rotV2E1Priv {
		t.Fatalf("epoch-1 (v2) derivation drifted:\n got %s\nwant %s", got, rotV2E1Priv)
	}
	// A never-cut epoch must refuse, not invent material.
	if _, _, err := s.blindingKeyAt(rotV1Asset, rotHolderX(), 7); err == nil {
		t.Fatal("deriving at an epoch whose master was never provisioned must fail")
	}
}

func callRotate(t *testing.T, s *Server, asset string) (int, map[string]any, string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"asset": asset})
	req := httptest.NewRequest("POST", "/v1/issuer/rotate-blinding", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleRotateBlinding(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// TestRotation_RotateBumpsEpochAndReimports drives the endpoint: the epoch
// bumps, a new master is provisioned (and the old one retained), every
// registered holder's enclave gets a NEW key imported into the watch wallet,
// served keys change while the epoch-0 key still re-derives unchanged, and the
// public log entry carries a commitment, never key material.
func TestRotation_RotateBumpsEpochAndReimports(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	regUser(t, st, nil) // a second holder; both get re-imported
	asset, _ := clawAsset(t, st, issuer.AID, false)

	holderX := rotHolderX()
	privE0, pubE0, err := s.blindingKey(asset.ID, holderX)
	if err != nil {
		t.Fatal(err)
	}

	imports := node.blindImports.Load()
	code, out, body := callRotate(t, s, asset.ID)
	if code != 200 {
		t.Fatalf("rotate failed: %d %s", code, body)
	}
	if out["epoch"].(float64) != 1 {
		t.Fatalf("epoch = %v, want 1", out["epoch"])
	}
	if got := node.blindImports.Load() - imports; got != 2 {
		t.Fatalf("expected 2 holder re-imports (both registered users), got %d", got)
	}

	// Epoch persisted; the old master retained alongside the new one.
	var epoch uint32
	st.View(func(state *store.State) { epoch = state.Assets[asset.ID].BlindEpoch })
	if epoch != 1 {
		t.Fatalf("stored BlindEpoch = %d, want 1", epoch)
	}
	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["blind-master"]; !ok {
		t.Fatal("rotation must retain the epoch-0 master")
	}
	if _, ok := keys["blind-master-v1"]; !ok {
		t.Fatal("rotation must provision blind-master-v1")
	}

	// Served keys now come from epoch 1; the epoch-0 key re-derives unchanged.
	privE1, pubE1, err := s.blindingKey(asset.ID, holderX)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(privE1, privE0) || bytes.Equal(pubE1, pubE0) {
		t.Fatal("post-rotation keys must differ from epoch 0")
	}
	again, _, err := s.blindingKeyAt(asset.ID, holderX, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, privE0) {
		t.Fatal("epoch-0 key must re-derive byte-identically after rotation")
	}

	// The public log commits to the re-import set; no derived key leaks.
	entries, err := readLog(st)
	if err != nil {
		t.Fatal(err)
	}
	var rot *store.LogEntry
	for i := range entries {
		if entries[i].Action == "rotate-blinding" {
			rot = &entries[i]
		}
	}
	if rot == nil {
		t.Fatal("no rotate-blinding log entry")
	}
	payload := string(rot.Data)
	for _, secret := range []string{hex.EncodeToString(privE0), hex.EncodeToString(privE1),
		hex.EncodeToString(pubE0), hex.EncodeToString(pubE1), keys["blind-master-v1"]} {
		if strings.Contains(payload, secret) {
			t.Fatalf("key material leaked into the transparency log: %s", payload)
		}
	}
	if !strings.Contains(payload, `"scripts_hash"`) || !strings.Contains(payload, `"epoch":1`) {
		t.Fatalf("rotation log entry must carry the epoch and a set-hash commitment: %s", payload)
	}

	// A second rotation reaches epoch 2 with its own master; v1 retained.
	code, out, body = callRotate(t, s, asset.ID)
	if code != 200 || out["epoch"].(float64) != 2 {
		t.Fatalf("second rotation: %d %s", code, body)
	}
	keys, _ = st.LoadKeys()
	for _, want := range []string{"blind-master", "blind-master-v1", "blind-master-v2"} {
		if _, ok := keys[want]; !ok {
			t.Fatalf("missing retained master %s after two rotations", want)
		}
	}
}

// TestRotation_MixedEpochBalanceExact funds a holder with a blinded coin under
// epoch 0, rotates, funds another under epoch 1, and proves the balance is the
// exact sum: the unified read is epoch-agnostic because the watch wallet keeps
// every epoch's keys imported.
func TestRotation_MixedEpochBalanceExact(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder := regUser(t, st, nil)
	asset, _ := clawAsset(t, st, issuer.AID, false)

	// Epoch-0 funding: the enclave output blinds to the epoch-0 key.
	holderX := elements32(t, holder.Pubkeys[0])
	nonceE0, err := s.enclaveConfNonce(asset.ID, holderX, enclaveSpkHex(t, s, holder, asset))
	if err != nil {
		t.Fatal(err)
	}
	seedBlindedEnclaveCoin(t, s, node, holder, asset, 600, 0x51)

	if code, _, body := callRotate(t, s, asset.ID); code != 200 {
		t.Fatalf("rotate failed: %d %s", code, body)
	}

	// Epoch-1 funding: new outputs blind to the NEW key (different nonce).
	nonceE1, err := s.enclaveConfNonce(asset.ID, holderX, enclaveSpkHex(t, s, holder, asset))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nonceE0, nonceE1) {
		t.Fatal("outputs after rotation must blind to a different key")
	}
	seedBlindedEnclaveCoin(t, s, node, holder, asset, 250, 0x52)

	req := httptest.NewRequest("GET", "/v1/users/"+holder.AID+"/balance?asset="+asset.ID, nil)
	req.SetPathValue("aid", holder.AID)
	rec := httptest.NewRecorder()
	s.handleBalance(rec, req)
	var out struct {
		Atoms uint64 `json:"atoms"`
		UTXOs int    `json:"utxos"`
	}
	decodeJSON(t, rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Atoms != 850 || out.UTXOs != 2 {
		t.Fatalf("mixed-epoch balance must be exact: want 850 over 2 utxos, got %d over %d (%s)",
			out.Atoms, out.UTXOs, rec.Body.String())
	}
}

// TestRotation_ReconcileImportsEveryEpoch proves the startup reconcile imports
// pairs x epochs, so a restored data directory regains every epoch's keys.
func TestRotation_ReconcileImportsEveryEpoch(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	asset, _ := clawAsset(t, st, issuer.AID, false)
	if code, _, body := callRotate(t, s, asset.ID); code != 200 {
		t.Fatalf("rotate failed: %d %s", code, body)
	}
	before := node.blindImports.Load()
	s.reconcileWatchWallet()
	// One registered user (the issuer) x two epochs (0 and 1).
	if got := node.blindImports.Load() - before; got != 2 {
		t.Fatalf("reconcile must import every epoch of every pair: got %d imports, want 2", got)
	}
	if node.rescans.Load() == 0 {
		t.Fatal("reconcile must run its rescan pass")
	}
}

// TestRotation_UnknownAsset404s keeps the endpoint honest.
func TestRotation_UnknownAsset404s(t *testing.T) {
	s, _, _ := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	if code, _, _ := callRotate(t, s, strings.Repeat("00", 32)); code != 404 {
		t.Fatalf("rotating an unknown asset must 404, got %d", code)
	}
}

// elements32 parses a 32-byte hex into an array (test-local convenience).
func elements32(t *testing.T, h string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", h)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func enclaveSpkHex(t *testing.T, s *Server, u *store.User, a *store.Asset) string {
	t.Helper()
	tree, err := s.treeFor(u, a)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(tree.ScriptPubKey())
}
