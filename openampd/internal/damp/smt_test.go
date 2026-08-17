package damp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// TestSMTGoldens pins the empty root and two incremental roots. These become
// the roots wallets and (later) Simplicity verifiers recompute; regenerate
// only for a deliberate, versioned format break.
func TestSMTGoldens(t *testing.T) {
	if got, want := hex.EncodeToString(func() []byte { r := EmptyRoot(); return r[:] }()),
		"6155289130893872355eac98042d22aefa2c2e708bea169402760e3b55f9a2dc"; got != want {
		t.Fatalf("empty root golden changed:\n got  %s\n want %s", got, want)
	}
	tr := NewSMT()
	tr.Insert(rep(0xaa))
	if got, want := hex.EncodeToString(func() []byte { r := tr.Root(); return r[:] }()),
		"a40fe48f8d385de0c82ab5d0189c00f2f461b0036a4818772475446ca0ce0651"; got != want {
		t.Fatalf("single-key root golden changed:\n got  %s\n want %s", got, want)
	}
	tr.Insert(rep(0xbb))
	if got, want := hex.EncodeToString(func() []byte { r := tr.Root(); return r[:] }()),
		"0458971a9ddfe7109e885411dd89720fbfec798c53104dcd49a4a24242d16e62"; got != want {
		t.Fatalf("two-key root golden changed:\n got  %s\n want %s", got, want)
	}
}

// TestSMTEmptyTree: the empty tree proves non-membership of anything and
// refuses membership proofs.
func TestSMTEmptyTree(t *testing.T) {
	tr := NewSMT()
	root := tr.Root()
	if root != EmptyRoot() {
		t.Fatal("empty tree root != EmptyRoot()")
	}
	for _, k := range [][32]byte{{}, rep(0x01), rep(0xff)} {
		p, err := tr.ProveNonMember(k)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 33 {
			t.Fatalf("empty-tree proof should carry no siblings, len=%d", len(p))
		}
		if !VerifyNonMember(root, k, p) {
			t.Fatalf("non-membership in empty tree must verify for %x", k)
		}
		if VerifyMember(root, k, p) {
			t.Fatalf("membership must NOT verify in empty tree for %x", k)
		}
	}
	if _, err := tr.ProveMember(rep(0x01)); err == nil {
		t.Fatal("ProveMember on absent key must error")
	}
}

// adjacentKey flips the lowest bit, producing a key whose SMT path shares 255
// levels with the original — the worst case for sibling handling.
func adjacentKey(k [32]byte) [32]byte {
	k[31] ^= 0x01
	return k
}

// TestSMTRoundTrips is the table-driven membership/non-membership round trip,
// including adjacent keys and delete-restores-root.
func TestSMTRoundTrips(t *testing.T) {
	kA := rep(0xaa)
	kAdj := adjacentKey(kA) // shares all but the last path bit with kA
	cases := []struct {
		name    string
		present [][32]byte
		absent  [][32]byte
	}{
		{"single", [][32]byte{kA}, [][32]byte{rep(0xbb), adjacentKey(rep(0xbb))}},
		{"adjacent-pair", [][32]byte{kA, kAdj}, [][32]byte{rep(0xab), {}}},
		{"spread", [][32]byte{{}, rep(0x01), rep(0x80), rep(0xff), kA, kAdj}, [][32]byte{rep(0x7f), adjacentKey(rep(0xff))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewSMT()
			for _, k := range tc.present {
				tr.Insert(k)
			}
			root := tr.Root()

			// Insertion order must not matter.
			tr2 := NewSMT()
			for i := len(tc.present) - 1; i >= 0; i-- {
				tr2.Insert(tc.present[i])
			}
			if tr2.Root() != root {
				t.Fatal("root depends on insertion order")
			}

			for _, k := range tc.present {
				p, err := tr.ProveMember(k)
				if err != nil {
					t.Fatal(err)
				}
				if !VerifyMember(root, k, p) {
					t.Fatalf("membership proof failed for %x", k)
				}
				if VerifyNonMember(root, k, p) {
					t.Fatalf("membership proof must not double as non-membership for %x", k)
				}
				if _, err := tr.ProveNonMember(k); err == nil {
					t.Fatalf("ProveNonMember must refuse present key %x", k)
				}
			}
			for _, k := range tc.absent {
				p, err := tr.ProveNonMember(k)
				if err != nil {
					t.Fatal(err)
				}
				if !VerifyNonMember(root, k, p) {
					t.Fatalf("non-membership proof failed for %x", k)
				}
				if VerifyMember(root, k, p) {
					t.Fatalf("non-membership proof must not double as membership for %x", k)
				}
			}

			// Delete every key: the root returns to EmptyRoot and every former
			// member becomes provably absent.
			for _, k := range tc.present {
				tr.Delete(k)
			}
			if tr.Root() != EmptyRoot() {
				t.Fatal("delete did not restore the empty root")
			}
			p, err := tr.ProveNonMember(tc.present[0])
			if err != nil || !VerifyNonMember(tr.Root(), tc.present[0], p) {
				t.Fatal("deleted key must be provably absent")
			}
		})
	}
}

// TestSMTProofRejection: wrong root, wrong key, and every practical tamper of
// the encoding must fail verification.
func TestSMTProofRejection(t *testing.T) {
	tr := NewSMT()
	kA, kB := rep(0xaa), rep(0xbb)
	tr.Insert(kA)
	tr.Insert(kB)
	root := tr.Root()
	proof, err := tr.ProveMember(kA)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyMember(root, kA, proof) {
		t.Fatal("baseline proof must verify")
	}

	if VerifyMember(rep(0x01), kA, proof) {
		t.Fatal("wrong root accepted")
	}
	if VerifyMember(root, kB, proof) {
		t.Fatal("wrong key accepted (kB's proof differs)")
	}
	if VerifyMember(root, adjacentKey(kA), proof) {
		t.Fatal("adjacent key accepted with kA's proof")
	}

	tampered := func(mut func(p []byte)) []byte {
		cp := append([]byte(nil), proof...)
		mut(cp)
		return cp
	}
	tampers := map[string][]byte{
		"version byte":       tampered(func(p []byte) { p[0] = 0x02 }),
		"bitmap bit flipped": tampered(func(p []byte) { p[1] ^= 0x80 }),
		"sibling bit":        tampered(func(p []byte) { p[len(p)-1] ^= 0x01 }),
		"truncated":          proof[:len(proof)-32],
		"extended":           append(append([]byte(nil), proof...), make([]byte, 32)...),
		"empty":              {},
	}
	for name, p := range tampers {
		if VerifyMember(root, kA, p) {
			t.Fatalf("tampered proof (%s) accepted", name)
		}
	}

	// A proof that explicitly encodes an empty sibling (instead of using the
	// bitmap) must be rejected: one canonical encoding per statement.
	nonCanon := append([]byte(nil), proof...)
	// find first unset bitmap bit and set it, appending the matching empty hash
	// at the right position; easiest deep tamper: set the deepest bit and append
	// empty leaf hash (32 zero bytes) at the end.
	if nonCanon[32]&0x01 == 0 { // depth 255 bit
		nonCanon[32] |= 0x01
		nonCanon = append(nonCanon, make([]byte, 32)...)
		if VerifyMember(root, kA, nonCanon) {
			t.Fatal("non-canonical proof (explicit empty sibling) accepted")
		}
	}
}

// TestSMTProofEncoding pins the wire layout: version byte, 256-bit MSB-first
// bitmap, then 32-byte siblings in increasing depth order.
func TestSMTProofEncoding(t *testing.T) {
	tr := NewSMT()
	kA := rep(0xaa)
	kAdj := adjacentKey(kA)
	tr.Insert(kA)
	tr.Insert(kAdj)
	proof, err := tr.ProveMember(kA)
	if err != nil {
		t.Fatal(err)
	}
	// kA and kAdj diverge only at depth 255, so the proof has exactly one
	// non-empty sibling: the leaf of kAdj at the deepest level.
	if len(proof) != 33+32 {
		t.Fatalf("expected exactly one sibling, len=%d", len(proof))
	}
	if proof[0] != ProofVersion {
		t.Fatalf("version byte = %#x", proof[0])
	}
	// Depth 255 = last bit of the bitmap = LSB of byte 32 (MSB-first order).
	if proof[32] != 0x01 {
		t.Fatalf("bitmap should mark only depth 255, byte 32 = %#x", proof[32])
	}
	for i := 1; i < 32; i++ {
		if proof[i] != 0 {
			t.Fatalf("bitmap byte %d should be zero, = %#x", i, proof[i])
		}
	}
	wantSib := sha256.Sum256(append([]byte{0x00}, kAdj[:]...))
	if hex.EncodeToString(proof[33:]) != hex.EncodeToString(wantSib[:]) {
		t.Fatalf("sibling should be leaf(kAdj):\n got  %x\n want %x", proof[33:], wantSib)
	}
}

// TestSMTManyKeys exercises a larger deterministic key set for stability under
// insert/delete churn.
func TestSMTManyKeys(t *testing.T) {
	tr := NewSMT()
	var keys [][32]byte
	for i := 0; i < 64; i++ {
		keys = append(keys, sha256.Sum256([]byte(fmt.Sprintf("key-%d", i))))
	}
	for _, k := range keys {
		tr.Insert(k)
	}
	root := tr.Root()
	for i, k := range keys {
		p, err := tr.ProveMember(k)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyMember(root, k, p) {
			t.Fatalf("member %d failed", i)
		}
	}
	// Remove half; the removed become non-members, the rest still verify.
	for i := 0; i < 32; i++ {
		tr.Delete(keys[i])
	}
	root2 := tr.Root()
	if root2 == root {
		t.Fatal("root unchanged after deletes")
	}
	for i := 0; i < 32; i++ {
		p, err := tr.ProveNonMember(keys[i])
		if err != nil || !VerifyNonMember(root2, keys[i], p) {
			t.Fatalf("deleted key %d not provably absent", i)
		}
	}
	for i := 32; i < 64; i++ {
		p, err := tr.ProveMember(keys[i])
		if err != nil || !VerifyMember(root2, keys[i], p) {
			t.Fatalf("kept key %d no longer provable", i)
		}
	}
}
