package damp

import (
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
			Pi               string   `json:"pi"`
			Seq              uint64   `json:"seq"`
			WhitelistRoot    string   `json:"whitelist_root"`
			WhitelistEntries []string `json:"whitelist_entries"`
		} `json:"policy"`
		Programs struct {
			UCMR string `json:"u_cmr"`
			PCMR string `json:"p_cmr"`
			GCMR string `json:"g_cmr"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	// The whitelist root over the vectors' own entries.
	keys := make([][32]byte, 0, len(v.Policy.WhitelistEntries))
	for _, e := range v.Policy.WhitelistEntries {
		b, err := hex.DecodeString(e)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad whitelist entry %q", e)
		}
		var k [32]byte
		copy(k[:], b)
		keys = append(keys, k)
	}
	wl, err := WhitelistRoot(keys)
	if err != nil {
		t.Fatalf("WhitelistRoot: %v", err)
	}
	if got := hex.EncodeToString(wl[:]); got != v.Policy.WhitelistRoot {
		t.Fatalf("whitelist root = %s, want %s", got, v.Policy.WhitelistRoot)
	}

	// pi over that root, with the blacklist slot deliberately empty (this build
	// carries no in-covenant blacklist; see opendamp/STATUS.md).
	var assetInternal [32]byte
	ai, err := hex.DecodeString(v.AssetInternalBytes)
	if err != nil || len(ai) != 32 {
		t.Fatalf("bad asset_internal_bytes %q", v.AssetInternalBytes)
	}
	copy(assetInternal[:], ai)
	rules := RulesRootCovenant(nil, &wl, 0, nil)
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
	if reg.UserCMR == [32]byte{} || reg.VerifierCMR == [32]byte{} || reg.IssuerCMR == [32]byte{} {
		t.Fatal("registry loaded a zero CMR")
	}
}

func TestLoadProgramRegistryRefusesPartialSets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(p, []byte(`{"u_cmr":"`+hex.EncodeToString(make([]byte, 32))+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProgramRegistry(p); err == nil {
		t.Fatal("a registry missing p_cmr and g_cmr must be refused")
	}
}
