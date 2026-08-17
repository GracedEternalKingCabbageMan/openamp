package damp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// rep returns a 32-byte array filled with b (test fixture helper).
func rep(b byte) [32]byte {
	var o [32]byte
	for i := range o {
		o[i] = b
	}
	return o
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex32 fixture %q", s)
	}
	var o [32]byte
	copy(o[:], b)
	return o
}

// TestTaggedHashConstruction proves taggedHash is the BIP340 construction by
// recomputing a policy commitment with a manual SHA256(SHA256(tag) ||
// SHA256(tag) || msg) chain, independent of the helper under test.
func TestTaggedHashConstruction(t *testing.T) {
	h := PolicyHeader{Version: 1, Asset: rep(0x11), Seq: 7, RulesRoot: rep(0x22)}
	got := h.Commitment()

	tagHash := sha256.Sum256([]byte("OpenDAMP/policy/v1"))
	manual := sha256.New()
	manual.Write(tagHash[:])
	manual.Write(tagHash[:])
	manual.Write([]byte{0x01}) // version_u8
	asset := rep(0x11)
	manual.Write(asset[:])
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], 7)
	manual.Write(seq[:])
	rules := rep(0x22)
	manual.Write(rules[:])
	var want [32]byte
	copy(want[:], manual.Sum(nil))

	if got != want {
		t.Fatalf("taggedHash construction mismatch: got %x want %x", got, want)
	}
}

// TestPolicyCommitmentGolden pins the policy commitment for a fixed header.
// If this changes, every deployed pi changes: regenerate only for a
// deliberate, versioned format break.
func TestPolicyCommitmentGolden(t *testing.T) {
	h := PolicyHeader{Version: 1, Asset: rep(0x11), Seq: 7, RulesRoot: rep(0x22)}
	want := "84f79147b327228e8cb1d861b42f689fda4144f2fcd8ba4d86b62d636b444b68"
	if got := hex.EncodeToString(func() []byte { c := h.Commitment(); return c[:] }()); got != want {
		t.Fatalf("policy commitment golden changed:\n got  %s\n want %s", got, want)
	}
	// Every header field must be covered by the commitment.
	base := h.Commitment()
	for name, alt := range map[string]PolicyHeader{
		"version":    {Version: 2, Asset: h.Asset, Seq: h.Seq, RulesRoot: h.RulesRoot},
		"asset":      {Version: h.Version, Asset: rep(0x12), Seq: h.Seq, RulesRoot: h.RulesRoot},
		"seq":        {Version: h.Version, Asset: h.Asset, Seq: 8, RulesRoot: h.RulesRoot},
		"rules_root": {Version: h.Version, Asset: h.Asset, Seq: h.Seq, RulesRoot: rep(0x23)},
	} {
		if alt.Commitment() == base {
			t.Fatalf("commitment does not cover %s", name)
		}
	}
}

// TestOutpointKey pins the golden vector and re-derives the definition
// SHA256(txid || BE32(vout)) independently.
func TestOutpointKey(t *testing.T) {
	txid := rep(0x33)
	got := OutpointKey(txid, 1)
	want := hex32(t, "7513a798795e8f17798e4fb6a2b2bad113ce9b9e73329275de99ca331cd78e68")
	if got != want {
		t.Fatalf("outpoint key golden changed: got %x want %x", got, want)
	}
	manual := sha256.Sum256(append(append([]byte{}, txid[:]...), 0, 0, 0, 1))
	if got != manual {
		t.Fatalf("OutpointKey is not SHA256(txid || BE32(vout)): got %x want %x", got, manual)
	}
	if OutpointKey(txid, 2) == got {
		t.Fatal("vout not covered")
	}
}

// TestRulesRoot pins the all-absent golden, re-derives the fixed-order Merkle
// shape manually, and proves each predicate slot is covered.
func TestRulesRoot(t *testing.T) {
	absent := RulesRoot([32]byte{}, [32]byte{}, 0, [32]byte{})
	if got, want := hex.EncodeToString(absent[:]), "90534fe0aff6db9edb29eee74e78a386916a581c8e6465349493e1a6c87241e1"; got != want {
		t.Fatalf("all-absent rules_root golden changed:\n got  %s\n want %s", got, want)
	}

	// Manual recomputation of the tree shape for enabled predicates:
	// node(node(bl, wl), node(limitC, windows)) with node = SHA256(0x01||l||r).
	bl, wl, wh := rep(0xa1), rep(0xa2), rep(0xa3)
	limit := uint64(1000)
	limitC := LimitCommitment(limit)
	if got, want := hex.EncodeToString(limitC[:]), "eb090c03d70675c3050cb31e99c08a078c8a39c42bb427378916179a7e485403"; got != want {
		t.Fatalf("limit commitment golden changed:\n got  %s\n want %s", got, want)
	}
	node := func(l, r [32]byte) [32]byte {
		h := sha256.New()
		h.Write([]byte{0x01})
		h.Write(l[:])
		h.Write(r[:])
		var o [32]byte
		copy(o[:], h.Sum(nil))
		return o
	}
	want := node(node(bl, wl), node(limitC, wh))
	if got := RulesRoot(bl, wl, limit, wh); got != want {
		t.Fatalf("rules_root shape mismatch: got %x want %x", got, want)
	}

	// Coverage: flipping any one slot changes the root.
	base := RulesRoot(bl, wl, limit, wh)
	for name, alt := range map[string][32]byte{
		"blacklist": RulesRoot(rep(0xb1), wl, limit, wh),
		"whitelist": RulesRoot(bl, rep(0xb2), limit, wh),
		"limit":     RulesRoot(bl, wl, limit+1, wh),
		"windows":   RulesRoot(bl, wl, limit, rep(0xb3)),
	} {
		if alt == base {
			t.Fatalf("rules_root does not cover %s", name)
		}
	}
	// Zero limit commits to zeros, not LimitCommitment(0).
	if RulesRoot(bl, wl, 0, wh) != node(node(bl, wl), node([32]byte{}, wh)) {
		t.Fatal("absent limit must commit to 32 zero bytes")
	}
}
