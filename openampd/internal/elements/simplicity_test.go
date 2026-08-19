package elements

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The Go derivation of OpenDAMP covenant addresses must agree with the Rust
// implementation that actually spends them on chain, byte for byte, or a
// network-enforcement issuance would mint into an address no covenant can
// spend. These vectors are produced by the opendamp crate (whose regtest proof
// spends exactly these outputs), so a disagreement here is a real defect on one
// side, never a stylistic difference.
type dampVectors struct {
	NUMS                  string `json:"nums_internal_key"`
	SimplicityLeafVersion int    `json:"simplicity_leaf_version"`
	Programs              struct {
		UCMR         string `json:"u_cmr"`
		UTapleafHash string `json:"u_tapleaf_hash"`
		PCMR         string `json:"p_cmr_canonical"`
		PTapleafHash string `json:"p_tapleaf_hash_canonical"`
		Shapes       []struct {
			Shape        string `json:"shape"`
			CMR          string `json:"cmr"`
			Tapleaf      string `json:"tapleaf"`
			ControlBlock string `json:"control_block"`
			Canonical    bool   `json:"canonical"`
		} `json:"verifier_shapes"`
		GCMR         string `json:"g_cmr"`
		GTapleafHash string `json:"g_tapleaf_hash"`
	} `json:"programs"`
	UserCovenants []struct {
		OwnerXOnly      string `json:"owner_xonly"`
		TapDataHash     string `json:"tapdata_hash"`
		UserTapleafHash string `json:"user_tapleaf_hash"`
		MerkleRoot      string `json:"merkle_root"`
		OutputKey       string `json:"output_key"`
		ParityOdd       bool   `json:"output_key_parity_odd"`
		ScriptPubKey    string `json:"script_pubkey"`
		ControlBlock    string `json:"control_block"`
	} `json:"user_covenants"`
	VerifierCovenant struct {
		MerkleRoot          string `json:"merkle_root"`
		OutputKey           string `json:"output_key"`
		ParityOdd           bool   `json:"output_key_parity_odd"`
		ScriptPubKey        string `json:"script_pubkey"`
		ControlBlockPrimary string `json:"control_block_primary"`
		ControlBlockIssuer  string `json:"control_block_issuer"`
	} `json:"verifier_covenant"`
}

func loadDampVectors(t *testing.T) *dampVectors {
	t.Helper()
	path := filepath.Join("..", "..", "..", "opendamp", "vectors", "addresses.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("opendamp vectors unavailable (%v)", err)
	}
	var v dampVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func TestSimplicityConstantsMatchVectors(t *testing.T) {
	v := loadDampVectors(t)
	if got := hex.EncodeToString(NUMS[:]); got != v.NUMS {
		t.Fatalf("NUMS = %s, vectors say %s", got, v.NUMS)
	}
	if LeafVersionSimplicity != byte(v.SimplicityLeafVersion) {
		t.Fatalf("leaf version = %#x, vectors say %#x", LeafVersionSimplicity, v.SimplicityLeafVersion)
	}
}

func TestSimplicityLeafHashesMatchVectors(t *testing.T) {
	v := loadDampVectors(t)
	for _, c := range []struct{ name, cmr, want string }{
		{"user", v.Programs.UCMR, v.Programs.UTapleafHash},
		{"verifier-primary-canonical", v.Programs.PCMR, v.Programs.PTapleafHash},
		{"issuer", v.Programs.GCMR, v.Programs.GTapleafHash},
	} {
		got := SimplicityLeafHash(MustHex32(c.cmr))
		if hex.EncodeToString(got[:]) != c.want {
			t.Fatalf("%s tapleaf hash = %s, want %s", c.name, hex.EncodeToString(got[:]), c.want)
		}
	}
}

func TestUserCovenantMatchesVectors(t *testing.T) {
	v := loadDampVectors(t)
	if len(v.UserCovenants) == 0 {
		t.Fatal("vectors carry no user covenants")
	}
	cmr := MustHex32(v.Programs.UCMR)
	for _, uc := range v.UserCovenants {
		owner := MustHex32(uc.OwnerXOnly)
		if got := TapDataHash(owner); hex.EncodeToString(got[:]) != uc.TapDataHash {
			t.Fatalf("TapData(%s) = %s, want %s", uc.OwnerXOnly, hex.EncodeToString(got[:]), uc.TapDataHash)
		}
		out, err := UserCovenant(cmr, owner)
		if err != nil {
			t.Fatalf("UserCovenant(%s): %v", uc.OwnerXOnly, err)
		}
		if hex.EncodeToString(out.Root[:]) != uc.MerkleRoot {
			t.Fatalf("root = %s, want %s", hex.EncodeToString(out.Root[:]), uc.MerkleRoot)
		}
		if hex.EncodeToString(out.OutputKey[:]) != uc.OutputKey {
			t.Fatalf("output key = %s, want %s", hex.EncodeToString(out.OutputKey[:]), uc.OutputKey)
		}
		if out.Parity != uc.ParityOdd {
			t.Fatalf("parity = %v, want %v", out.Parity, uc.ParityOdd)
		}
		if got := hex.EncodeToString(out.ScriptPubKey()); got != uc.ScriptPubKey {
			t.Fatalf("spk = %s, want %s", got, uc.ScriptPubKey)
		}
		if got := hex.EncodeToString(out.ControlBlock); got != uc.ControlBlock {
			t.Fatalf("control block = %s, want %s", got, uc.ControlBlock)
		}
	}
}

func TestVerifierCovenantMatchesVectors(t *testing.T) {
	v := loadDampVectors(t)
	out, err := VerifierCovenant(shapeMenu(v), MustHex32(v.Programs.GCMR))
	if err != nil {
		t.Fatalf("VerifierCovenant: %v", err)
	}
	if hex.EncodeToString(out.Root[:]) != v.VerifierCovenant.MerkleRoot {
		t.Fatalf("root = %s, want %s", hex.EncodeToString(out.Root[:]), v.VerifierCovenant.MerkleRoot)
	}
	if hex.EncodeToString(out.OutputKey[:]) != v.VerifierCovenant.OutputKey {
		t.Fatalf("output key = %s, want %s", hex.EncodeToString(out.OutputKey[:]), v.VerifierCovenant.OutputKey)
	}
	if got := hex.EncodeToString(out.ScriptPubKey()); got != v.VerifierCovenant.ScriptPubKey {
		t.Fatalf("spk = %s, want %s", got, v.VerifierCovenant.ScriptPubKey)
	}
	if got := hex.EncodeToString(out.ControlBlock); got != v.VerifierCovenant.ControlBlockPrimary {
		t.Fatalf("primary control block = %s, want %s", got, v.VerifierCovenant.ControlBlockPrimary)
	}
	issuerCB, err := IssuerPathControlBlock(shapeMenu(v), MustHex32(v.Programs.GCMR))
	if err != nil {
		t.Fatalf("IssuerPathControlBlock: %v", err)
	}
	if got := hex.EncodeToString(issuerCB); got != v.VerifierCovenant.ControlBlockIssuer {
		t.Fatalf("issuer control block = %s, want %s", got, v.VerifierCovenant.ControlBlockIssuer)
	}
}

// shapeMenu is the ordered list of primary-program CMRs the verifier taptree is
// built from: one per transaction shape, canonical first.
func shapeMenu(v *dampVectors) [][32]byte {
	out := make([][32]byte, 0, len(v.Programs.Shapes))
	for _, sh := range v.Programs.Shapes {
		out = append(out, MustHex32(sh.CMR))
	}
	return out
}

// Every shape must open against the same output key, which is the whole point
// of putting them in one taptree: one address, several programs.
func TestEveryShapeControlBlockMatchesVectors(t *testing.T) {
	v := loadDampVectors(t)
	menu := shapeMenu(v)
	if len(menu) < 2 {
		t.Fatalf("expected a menu of shapes, got %d", len(menu))
	}
	for i, sh := range v.Programs.Shapes {
		cb, err := ShapePathControlBlock(menu, MustHex32(v.Programs.GCMR), i)
		if err != nil {
			t.Fatalf("ShapePathControlBlock(%s): %v", sh.Shape, err)
		}
		if got := hex.EncodeToString(cb); got != sh.ControlBlock {
			t.Errorf("%s control block = %s, want %s", sh.Shape, got, sh.ControlBlock)
		}
	}
}
