package dmt

import (
	"encoding/hex"
	"testing"
)

func mustKey(t *testing.T, s string) Key {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	if len(b) != KeySize {
		t.Fatalf("key %q is %d bytes, want %d", s, len(b), KeySize)
	}
	var k Key
	copy(k[:], b)
	return k
}

// The keys and root of examples/snapshot-seq0.json, cross-checked against the
// Rust implementation via vectors/addresses.json.
const (
	alice = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
	bob   = "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"
	carol = "462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b"

	wantLeafGuardLo = "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9"
	wantLeafGuardHi = "5e16d316ecd5773e50c3b02737d424192b02f25b4245822079181c557aafda7d"
	wantEmptyRoot   = "e69f2dc2186b1cca0ed37d851b60121a87832be1ff7f61d58bc4931d26c844cf"
	wantThreeRoot   = "dc9d33e167118409fba74538497bf7a984166cd60dc92ee62e4ad5283cf52118"
)

func TestGuardLeafGoldenVectors(t *testing.T) {
	if got := hex.EncodeToString(sliceOf(LeafHash(GuardLo))); got != wantLeafGuardLo {
		t.Errorf("leaf(GuardLo) = %s, want %s", got, wantLeafGuardLo)
	}
	if got := hex.EncodeToString(sliceOf(LeafHash(GuardHi))); got != wantLeafGuardHi {
		t.Errorf("leaf(GuardHi) = %s, want %s", got, wantLeafGuardHi)
	}
}

func TestEmptyRootGoldenVector(t *testing.T) {
	tree, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	if got := hex.EncodeToString(sliceOf(tree.Root())); got != wantEmptyRoot {
		t.Errorf("empty root = %s, want %s", got, wantEmptyRoot)
	}
}

func TestThreeKeyRootAndSlotsGoldenVector(t *testing.T) {
	// Deliberately NOT in sorted order: the tree must sort them itself.
	tree, err := New([]Key{mustKey(t, alice), mustKey(t, bob), mustKey(t, carol)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := hex.EncodeToString(sliceOf(tree.Root())); got != wantThreeRoot {
		t.Fatalf("root = %s, want %s (Rust and Go must agree byte for byte)",
			got, wantThreeRoot)
	}
	// Sorting is on the key bytes, so carol (0x46..) precedes bob (0x4d..).
	for _, tc := range []struct {
		key  string
		slot uint16
	}{
		{alice, 1},
		{carol, 2},
		{bob, 3},
	} {
		slot, ok := tree.SlotOf(mustKey(t, tc.key))
		if !ok {
			t.Errorf("%s should be a member", tc.key[:8])
			continue
		}
		if slot != tc.slot {
			t.Errorf("slot(%s) = %d, want %d", tc.key[:8], slot, tc.slot)
		}
	}
}

func TestMembershipRoundTrip(t *testing.T) {
	tree, err := New([]Key{mustKey(t, alice), mustKey(t, bob), mustKey(t, carol)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	root := tree.Root()
	for _, k := range []Key{
		mustKey(t, alice), mustKey(t, bob), mustKey(t, carol), GuardLo, GuardHi,
	} {
		p, ok := tree.Prove(k)
		if !ok {
			t.Fatalf("no proof for %x", k)
		}
		if !Verify(root, k, p) {
			t.Errorf("proof for %x does not verify", k)
		}
		// The witness encoding must agree with the bitmap.
		levels := p.Levels()
		for j := 0; j < Depth; j++ {
			wantRight := (p.Index>>uint(j))&1 == 1
			if levels[j].IsRight != wantRight {
				t.Errorf("level %d IsRight = %v, want %v", j, levels[j].IsRight, wantRight)
			}
			if levels[j].Sibling != p.Siblings[j] {
				t.Errorf("level %d sibling mismatch", j)
			}
		}
	}
}

func TestNonMemberHasNoProofAndCannotBorrowOne(t *testing.T) {
	// A tree WITHOUT carol: carol must be unprovable, and reusing another
	// member's proof must not verify for her.
	tree, err := New([]Key{mustKey(t, alice), mustKey(t, bob)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := tree.Prove(mustKey(t, carol)); ok {
		t.Fatal("carol is not a member; Prove must fail")
	}
	alicesProof, ok := tree.Prove(mustKey(t, alice))
	if !ok {
		t.Fatal("alice must be provable")
	}
	if Verify(tree.Root(), mustKey(t, carol), alicesProof) {
		t.Fatal("alice's proof must not verify for carol")
	}
}

func TestRootChangesWithTheSet(t *testing.T) {
	one, err := New([]Key{mustKey(t, alice)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	two, err := New([]Key{mustKey(t, alice), mustKey(t, bob)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if one.Root() == two.Root() {
		t.Fatal("adding a key must change the root")
	}
}

func TestRejectsDuplicatesAndGuards(t *testing.T) {
	if _, err := New([]Key{mustKey(t, alice), mustKey(t, alice)}); err == nil {
		t.Error("duplicate keys must be rejected")
	}
	if _, err := New([]Key{GuardHi}); err == nil {
		t.Error("a guard-valued key must be rejected")
	}
	if _, err := New([]Key{GuardLo}); err == nil {
		t.Error("a guard-valued key must be rejected")
	}
}

func TestNodeHashIsPositional(t *testing.T) {
	// The most likely porting bug is copying taproot's sorted TapBranch. dmt-v1
	// node() must be order-sensitive.
	a := LeafHash(mustKey(t, alice))
	b := LeafHash(mustKey(t, bob))
	if NodeHash(a, b) == NodeHash(b, a) {
		t.Fatal("node() must NOT sort its children")
	}
}

func TestAdjacencyBracketsAnAbsentKey(t *testing.T) {
	tree, err := New([]Key{mustKey(t, alice), mustKey(t, bob)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	root := tree.Root()
	lo, hi, loProof, hiProof, ok := tree.Adjacent(mustKey(t, carol))
	if !ok {
		t.Fatal("carol is absent, so an adjacency proof must exist")
	}
	// carol (0x46..) sits between alice (0x1b..) and bob (0x4d..).
	if lo != mustKey(t, alice) || hi != mustKey(t, bob) {
		t.Errorf("bracket = (%x, %x), want (alice, bob)", lo, hi)
	}
	if !Verify(root, lo, loProof) || !Verify(root, hi, hiProof) {
		t.Error("both bracket proofs must verify")
	}
	if hiProof.Index != loProof.Index+1 {
		t.Errorf("bracket slots must be adjacent: %d then %d",
			loProof.Index, hiProof.Index)
	}
	// A member has no adjacency proof.
	if _, _, _, _, ok := tree.Adjacent(mustKey(t, alice)); ok {
		t.Error("a member must not get an adjacency proof")
	}
}

func TestAdjacencyUsesGuardsAtTheEdges(t *testing.T) {
	tree, err := New([]Key{mustKey(t, bob)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// alice (0x1b..) is below the only member, so the low bracket is GuardLo.
	lo, hi, _, _, ok := tree.Adjacent(mustKey(t, alice))
	if !ok {
		t.Fatal("expected an adjacency proof")
	}
	if lo != GuardLo || hi != mustKey(t, bob) {
		t.Errorf("bracket = (%x, %x), want (GuardLo, bob)", lo, hi)
	}
	// A key above every member brackets against GuardHi.
	var high Key
	high[0] = 0xfe
	lo, hi, _, _, ok = tree.Adjacent(high)
	if !ok {
		t.Fatal("expected an adjacency proof")
	}
	if lo != mustKey(t, bob) || hi != GuardHi {
		t.Errorf("bracket = (%x, %x), want (bob, GuardHi)", lo, hi)
	}
}

func TestManyKeysBuildAndProve(t *testing.T) {
	// Exercise the padding path with an odd count that is not a power of two.
	keys := make([]Key, 0, 1000)
	for i := 0; i < 1000; i++ {
		var k Key
		k[0] = byte(i >> 8)
		k[1] = byte(i)
		k[31] = 0x01 // keep it clear of both guards
		keys = append(keys, k)
	}
	tree, err := New(keys)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	root := tree.Root()
	for _, i := range []int{0, 1, 499, 998, 999} {
		p, ok := tree.Prove(keys[i])
		if !ok {
			t.Fatalf("key %d must be provable", i)
		}
		if !Verify(root, keys[i], p) {
			t.Errorf("proof for key %d does not verify", i)
		}
	}
}

func sliceOf(h [32]byte) []byte { return h[:] }
