package damp

import (
	"strings"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The covenant-facing policy construction must reproduce the vectors the Rust
// implementation spends against on regtest. A mismatch here means this server
// would publish a pi no deployed covenant is instantiated with, and every
// transfer would fail at consensus.
func TestCovenantPolicyMatchesVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "opendamp", "vectors", "addresses.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("opendamp vectors unavailable (%v)", err)
	}
	var v struct {
		Asset              string `json:"asset"`
		AssetInternalBytes string `json:"asset_internal_bytes"`
		DMT                struct {
			Depth     int    `json:"depth"`
			EmptyRoot string `json:"empty_root"`
		} `json:"dmt_v1"`
		Policy struct {
			Pi               string `json:"pi"`
			Seq              uint64 `json:"seq"`
			WhitelistRoot    string `json:"whitelist_root"`
			WhitelistEntries []struct {
				Key       string `json:"key"`
				SendAfter uint32 `json:"send_after"`
				RecvAfter uint32 `json:"recv_after"`
			} `json:"whitelist_entries"`
			TransferLimit           uint64   `json:"transfer_limit"`
			BlacklistRoot           string   `json:"blacklist_root"`
			BlacklistedOutpointKeys []string `json:"blacklisted_outpoint_keys"`
		} `json:"policy"`
		Programs struct {
			UCMR   string `json:"u_cmr"`
			PCMR   string `json:"p_cmr_canonical"`
			GCMR   string `json:"g_cmr"`
			Shapes []struct {
				Shape string `json:"shape"`
				CMR   string `json:"cmr"`
			} `json:"verifier_shapes"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	// The whitelist root over the vectors' own entries, height bounds and all:
	// the bounds live in the leaf, so a root computed without them is a
	// different root and the covenant would answer to neither.
	entries := make([]WhitelistEntry, 0, len(v.Policy.WhitelistEntries))
	for _, e := range v.Policy.WhitelistEntries {
		b, err := hex.DecodeString(e.Key)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad whitelist entry %q", e.Key)
		}
		var k [32]byte
		copy(k[:], b)
		entries = append(entries, WhitelistEntry{Key: k, SendAfter: e.SendAfter, RecvAfter: e.RecvAfter})
	}
	wl, err := WhitelistRootWithWindows(entries)
	if err != nil {
		t.Fatalf("WhitelistRoot: %v", err)
	}
	if got := hex.EncodeToString(wl[:]); got != v.Policy.WhitelistRoot {
		t.Fatalf("whitelist root = %s, want %s", got, v.Policy.WhitelistRoot)
	}

	// The blacklist root over the vectors' listed outpoint keys. This is an
	// INTERVAL tree, a different shape from the whitelist's, because
	// non-membership has to be affordable inside the covenant.
	blKeys := make([][32]byte, 0, len(v.Policy.BlacklistedOutpointKeys))
	for _, e := range v.Policy.BlacklistedOutpointKeys {
		b, err := hex.DecodeString(e)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad blacklist entry %q", e)
		}
		var k [32]byte
		copy(k[:], b)
		blKeys = append(blKeys, k)
	}
	bl, err := BlacklistRoot(blKeys)
	if err != nil {
		t.Fatalf("BlacklistRoot: %v", err)
	}
	if got := hex.EncodeToString(bl[:]); got != v.Policy.BlacklistRoot {
		t.Fatalf("blacklist root = %s, want %s", got, v.Policy.BlacklistRoot)
	}

	// pi over both roots. The blacklist slot carries a real root now that the
	// covenant enforces non-membership; an empty blacklist still commits to the
	// guard interval's root, never to zero.
	var assetInternal [32]byte
	ai, err := hex.DecodeString(v.AssetInternalBytes)
	if err != nil || len(ai) != 32 {
		t.Fatalf("bad asset_internal_bytes %q", v.AssetInternalBytes)
	}
	copy(assetInternal[:], ai)
	rules := RulesRootCovenant(&bl, &wl, v.Policy.TransferLimit, nil)
	pi := PiCovenant(assetInternal, v.Policy.Seq, rules)
	if got := hex.EncodeToString(pi[:]); got != v.Policy.Pi {
		t.Fatalf("pi = %s, want %s", got, v.Policy.Pi)
	}
}

func TestLoadProgramRegistryAcceptsVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "opendamp", "vectors", "addresses.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("opendamp vectors unavailable (%v)", err)
	}
	reg, err := LoadProgramRegistry(path)
	if err != nil {
		t.Fatalf("LoadProgramRegistry: %v", err)
	}
	if reg.UserCMR == [32]byte{} || reg.IssuerCMR == [32]byte{} {
		t.Fatal("registry loaded a zero CMR")
	}
	if len(reg.VerifierCMRs) < 2 {
		t.Fatalf("expected a menu of verifier shapes, got %d", len(reg.VerifierCMRs))
	}
	for i, c := range reg.VerifierCMRs {
		if c == [32]byte{} {
			t.Fatalf("verifier shape %d loaded a zero CMR", i)
		}
	}
	if reg.VerifierCMR() != reg.VerifierCMRs[0] {
		t.Fatal("the canonical shape must be the first leaf of the menu")
	}
}

func TestLoadProgramRegistryRefusesPartialSets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(p, []byte(`{"u_cmr":"`+hex.EncodeToString(make([]byte, 32))+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProgramRegistry(p); err == nil {
		t.Fatal("a registry missing the verifier shape menu and g_cmr must be refused")
	}
}

// A pinning file from before the shape menu must be refused with an
// explanation, not read as a one-leaf taptree: that derives a real but WRONG
// address, and the mistake would only surface when a holder could not spend.
func TestLoadProgramRegistryRefusesAPreMenuFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "premenu.json")
	z := hex.EncodeToString(make([]byte, 32))
	body := `{"u_cmr":"` + z + `","p_cmr":"` + z + `","g_cmr":"` + z + `"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadProgramRegistry(p)
	if err == nil {
		t.Fatal("a single p_cmr must not be accepted as a menu")
	}
	if !strings.Contains(err.Error(), "verifier_shapes") {
		t.Fatalf("the error must name what is missing: %v", err)
	}
}
