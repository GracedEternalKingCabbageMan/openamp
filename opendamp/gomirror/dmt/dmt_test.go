package dmt

import (
	"crypto/sha256"
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

	wantLeafGuardLo = "9e1736c43d19118e6ce4302118af337109491ecc52757dfb949bad6a7940b0c2"
	wantLeafGuardHi = "dc8c3b446f21ee93e5ea4d016c916e8ffd952e3f594462fe0f2a0befe3580c59"
	wantEmptyRoot   = "b883626f07bded09c45c76719b43e85945c0ac41ee370d47932f269dd6eabfed"
	wantThreeRoot   = "66327e6c8cf6cfff8e1c0661e2469d4aa5ae5aa65206003f6758ff1180619a50"
)

func TestGuardLeafGoldenVectors(t *testing.T) {
	if got := hex.EncodeToString(sliceOf(LeafHash(Unrestricted(GuardLo)))); got != wantLeafGuardLo {
		t.Errorf("leaf(GuardLo) = %s, want %s", got, wantLeafGuardLo)
	}
	if got := hex.EncodeToString(sliceOf(LeafHash(Unrestricted(GuardHi)))); got != wantLeafGuardHi {
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
	tree, err := New([]Entry{
		Unrestricted(mustKey(t, alice)),
		Unrestricted(mustKey(t, bob)),
		Unrestricted(mustKey(t, carol)),
	})
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
	tree, err := New([]Entry{
		Unrestricted(mustKey(t, alice)),
		Unrestricted(mustKey(t, bob)),
		Unrestricted(mustKey(t, carol)),
	})
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
		levels := p.Path.Levels()
		for j := 0; j < Depth; j++ {
			wantRight := (p.Path.Index>>uint(j))&1 == 1
			if levels[j].IsRight != wantRight {
				t.Errorf("level %d IsRight = %v, want %v", j, levels[j].IsRight, wantRight)
			}
			if levels[j].Sibling != p.Path.Siblings[j] {
				t.Errorf("level %d sibling mismatch", j)
			}
		}
	}
}

func TestNonMemberHasNoProofAndCannotBorrowOne(t *testing.T) {
	// A tree WITHOUT carol: carol must be unprovable, and reusing another
	// member's proof must not verify for her.
	tree, err := New([]Entry{Unrestricted(mustKey(t, alice)), Unrestricted(mustKey(t, bob))})
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
	one, err := New([]Entry{Unrestricted(mustKey(t, alice))})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	two, err := New([]Entry{Unrestricted(mustKey(t, alice)), Unrestricted(mustKey(t, bob))})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if one.Root() == two.Root() {
		t.Fatal("adding a key must change the root")
	}
}

func TestRejectsDuplicatesAndGuards(t *testing.T) {
	if _, err := New([]Entry{Unrestricted(mustKey(t, alice)), Unrestricted(mustKey(t, alice))}); err == nil {
		t.Error("duplicate keys must be rejected")
	}
	if _, err := New([]Entry{Unrestricted(GuardHi)}); err == nil {
		t.Error("a guard-valued key must be rejected")
	}
	if _, err := New([]Entry{Unrestricted(GuardLo)}); err == nil {
		t.Error("a guard-valued key must be rejected")
	}
}

func TestNodeHashIsPositional(t *testing.T) {
	// The most likely porting bug is copying taproot's sorted TapBranch. dmt-v1
	// node() must be order-sensitive.
	a := LeafHash(Unrestricted(mustKey(t, alice)))
	b := LeafHash(Unrestricted(mustKey(t, bob)))
	if NodeHash(a, b) == NodeHash(b, a) {
		t.Fatal("node() must NOT sort its children")
	}
}

func TestAdjacencyBracketsAnAbsentKey(t *testing.T) {
	tree, err := New([]Entry{Unrestricted(mustKey(t, alice)), Unrestricted(mustKey(t, bob))})
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
	if hiProof.Path.Index != loProof.Path.Index+1 {
		t.Errorf("bracket slots must be adjacent: %d then %d",
			loProof.Path.Index, hiProof.Path.Index)
	}
	// A member has no adjacency proof.
	if _, _, _, _, ok := tree.Adjacent(mustKey(t, alice)); ok {
		t.Error("a member must not get an adjacency proof")
	}
}

func TestAdjacencyUsesGuardsAtTheEdges(t *testing.T) {
	tree, err := New([]Entry{Unrestricted(mustKey(t, bob))})
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
	keys := make([]Entry, 0, 1000)
	for i := 0; i < 1000; i++ {
		var k Key
		k[0] = byte(i >> 8)
		k[1] = byte(i)
		k[31] = 0x01 // keep it clear of both guards
		keys = append(keys, Unrestricted(k))
	}
	tree, err := New(keys)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	root := tree.Root()
	for _, i := range []int{0, 1, 499, 998, 999} {
		p, ok := tree.Prove(keys[i].Key)
		if !ok {
			t.Fatalf("key %d must be provable", i)
		}
		if !Verify(root, keys[i].Key, p) {
			t.Errorf("proof for key %d does not verify", i)
		}
	}
}

func sliceOf(h [32]byte) []byte { return h[:] }

func sha256sum(b []byte) Key {
	h := sha256.Sum256(b)
	var k Key
	copy(k[:], h[:])
	return k
}

// ---------------------------------------------------------------- blacklist

const (
	// Independently recomputed from SPEC-dmt-v1.md; the Rust implementation
	// pins the same literals.
	wantIntervalGuards = "1fd8164b6e61192e120f01ca504c786a6e193abe0265104c1303a9b1e09afc39"
	wantIntervalPad    = "507647244d0d51f754f23c5f23c4f9e6a84eeabd0524bd20fe2d932f539be8d4"
	wantEmptyBLRoot    = "009a25ef01f6cade2d114b8315aab47bf5599e3a1386c2f1d414f0e8d6dbf301"
)

func kb(t *testing.T, b byte) Key {
	t.Helper()
	var k Key
	k[0] = b
	k[31] = b
	return k
}

func TestBlacklistGoldenVectors(t *testing.T) {
	if got := hex.EncodeToString(sliceOf(IntervalLeafHash(GuardLo, GuardHi))); got != wantIntervalGuards {
		t.Errorf("interval(GuardLo,GuardHi) = %s, want %s", got, wantIntervalGuards)
	}
	if got := hex.EncodeToString(sliceOf(IntervalLeafHash(GuardHi, GuardHi))); got != wantIntervalPad {
		t.Errorf("interval(GuardHi,GuardHi) = %s, want %s", got, wantIntervalPad)
	}
	tree, err := NewIntervalTree(nil)
	if err != nil {
		t.Fatalf("NewIntervalTree(nil): %v", err)
	}
	if got := hex.EncodeToString(sliceOf(tree.Root())); got != wantEmptyBLRoot {
		t.Errorf("empty blacklist root = %s, want %s", got, wantEmptyBLRoot)
	}
}

func TestListedKeysAreUnprovableAndUnlistedOnesAreNot(t *testing.T) {
	listed := []Key{kb(t, 10), kb(t, 20), kb(t, 30)}
	tree, err := NewIntervalTree(listed)
	if err != nil {
		t.Fatalf("NewIntervalTree: %v", err)
	}
	root := tree.Root()
	// A listed key has no proof. That is the freeze.
	for _, k := range listed {
		if _, ok := tree.ProveAbsent(k); ok {
			t.Errorf("listed key %x must not be provable absent", k)
		}
	}
	for _, k := range []Key{kb(t, 1), kb(t, 15), kb(t, 25), kb(t, 99)} {
		p, ok := tree.ProveAbsent(k)
		if !ok {
			t.Fatalf("unlisted key %x must be provable", k)
		}
		if !VerifyAbsent(root, k, p) {
			t.Errorf("non-membership proof for %x does not verify", k)
		}
	}
}

func TestIntervalCannotBeStretchedOrEdited(t *testing.T) {
	tree, err := NewIntervalTree([]Key{kb(t, 20)})
	if err != nil {
		t.Fatalf("NewIntervalTree: %v", err)
	}
	root := tree.Root()
	p, ok := tree.ProveAbsent(kb(t, 10))
	if !ok {
		t.Fatal("expected a proof")
	}
	// Containment is strict, so the interval below a listed key does not cover it.
	if VerifyAbsent(root, kb(t, 20), p) {
		t.Error("an interval must not cover its own endpoint")
	}
	// Editing an endpoint changes the leaf, so the path no longer reaches the root.
	edited := *p
	edited.Hi = kb(t, 99)
	if VerifyAbsent(root, kb(t, 50), &edited) {
		t.Error("an edited interval must not verify")
	}
}

func TestEmptyBlacklistProvesEverythingAbsent(t *testing.T) {
	tree, err := NewIntervalTree(nil)
	if err != nil {
		t.Fatalf("NewIntervalTree: %v", err)
	}
	p, ok := tree.ProveAbsent(kb(t, 7))
	if !ok {
		t.Fatal("expected a proof")
	}
	if p.Lo != GuardLo || p.Hi != GuardHi {
		t.Errorf("expected the guard-to-guard interval, got (%x, %x)", p.Lo, p.Hi)
	}
	if !VerifyAbsent(tree.Root(), kb(t, 7), p) {
		t.Error("proof must verify")
	}
}

func TestWindowBoundsAreBoundIntoTheLeaf(t *testing.T) {
	key := kb(t, 1)
	open, err := New([]Entry{Unrestricted(key)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	locked, err := New([]Entry{{Key: key, SendAfter: 500}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if open.Root() == locked.Root() {
		t.Fatal("differing windows must give differing roots")
	}
	p, ok := locked.Prove(key)
	if !ok {
		t.Fatal("expected a proof")
	}
	if p.Entry.SendAfter != 500 {
		t.Errorf("proof must carry the committed bound, got %d", p.Entry.SendAfter)
	}
	if !Verify(locked.Root(), key, p) {
		t.Error("proof must verify")
	}
	// Claiming a shorter lockup breaks the leaf and so the path.
	lying := *p
	lying.Entry.SendAfter = 0
	if Verify(locked.Root(), key, &lying) {
		t.Fatal("a holder must not be able to shorten their own lockup")
	}
}

func TestLeafDomainsAreSeparate(t *testing.T) {
	// A whitelist membership proof must not be replayable as a blacklist
	// non-membership proof. The leading domain byte is what prevents it.
	if LeafHash(Unrestricted(kb(t, 1))) == IntervalLeafHash(kb(t, 1), kb(t, 1)) {
		t.Fatal("whitelist and blacklist leaf domains must differ")
	}
}

func TestOutpointKeyIsTxidThenBigEndianVout(t *testing.T) {
	var txid [32]byte
	for i := range txid {
		txid[i] = 0xab
	}
	got := OutpointKey(txid, 256)
	// Recomputed inline: SHA256(txid || 00 00 01 00).
	want := func() Key {
		b, _ := hex.DecodeString("00000100")
		h := sha256sum(append(append([]byte{}, txid[:]...), b...))
		return h
	}()
	if got != want {
		t.Errorf("OutpointKey = %x, want %x", got, want)
	}
}
