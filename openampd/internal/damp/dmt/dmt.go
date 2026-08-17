// Package dmt implements dmt-v1, the sorted dense Merkle tree that OpenDAMP
// Simplicity covenants verify membership proofs against.
//
// This is a mirror of the Rust implementation in opendamp/src/dmt.rs (kept in
// step with opendamp/gomirror/dmt, its standalone twin) and is
// byte-for-byte compatible with it; opendamp/SPEC-dmt-v1.md is authoritative.
// Standard library only, no dependencies.
//
// Two details are easy to get wrong when porting:
//
//   - node() is POSITIONAL. It does not sort its children. (The taproot
//     TapBranch/elements hash used for the covenant tree itself does sort, which
//     is a different function entirely.)
//   - keys sort by unsigned bytewise comparison of the 32-byte key, not by
//     insertion order and not by any display form.
//   - a whitelist leaf commits the key AND its two height windows. Hashing the
//     key alone produces a different root and every proof fails at consensus.
package dmt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
)

const (
	// Depth of the tree: every membership proof carries exactly this many
	// sibling hashes.
	Depth = 16
	// Slots is the number of leaf slots, 1<<Depth.
	Slots = 1 << Depth
	// KeySize is the fixed key length in bytes.
	KeySize = 32
	// Capacity is how many real keys fit once the two guards are reserved.
	Capacity = Slots - 2
)

// Key is a 32-byte tree key: a BIP340 x-only public key for the whitelist, or
// SHA256(txid||BE32(vout)) for an outpoint blacklist.
type Key [KeySize]byte

// GuardLo occupies slot 0 and GuardHi every slot above the real keys, so that
// the sorted key sequence is total and adjacency proofs always exist.
var (
	GuardLo = Key{}
	GuardHi = func() Key {
		var k Key
		for i := range k {
			k[i] = 0xff
		}
		return k
	}()
)

// Entry is a whitelist entry: an approved key plus its two height windows.
//
// SendAfter is the lockup: the holder cannot own a regulated INPUT until the
// transaction proves a locktime height at or above it. RecvAfter is the receive
// window (the Reg S pattern): the holder cannot own a regulated OUTPUT until the
// same bound is proven. Zero means unrestricted and costs nothing at consensus.
//
// The bounds live in the leaf, so the one membership proof that shows a key is
// approved also shows which windows bind it.
type Entry struct {
	Key       Key
	SendAfter uint32
	RecvAfter uint32
}

// Unrestricted builds an entry with no height windows.
func Unrestricted(key Key) Entry { return Entry{Key: key} }

func putBE32(h io.Writer, v uint32) {
	h.Write([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// LeafHash returns SHA256(0x00 || key || BE32(SendAfter) || BE32(RecvAfter)).
func LeafHash(e Entry) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(e.Key[:])
	putBE32(h, e.SendAfter)
	putBE32(h, e.RecvAfter)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash returns SHA256(0x01 || left || right). Positional: children are NOT
// sorted.
func NodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Path is the Merkle path of a leaf: 16 sibling hashes bottom-up plus the leaf
// slot. Bit j of Index (LSB first) is 1 exactly when the running node at level j
// is the right child.
type Path struct {
	Siblings [Depth][32]byte
	Index    uint16
}

// Proof is a whitelist membership proof: the entry proven plus its path. The
// entry travels with the proof because the covenant rebuilds the leaf from it.
type Proof struct {
	Entry Entry
	Path  Path
}

// Level pairs a sibling hash with whether the running node is the right child
// at that level. This is the order the Simplicity witness expects.
type Level struct {
	Sibling [32]byte
	IsRight bool
}

// Levels returns the path in covenant-witness order, bottom-up.
func (p *Path) Levels() [Depth]Level {
	var out [Depth]Level
	for j := 0; j < Depth; j++ {
		out[j] = Level{
			Sibling: p.Siblings[j],
			IsRight: (p.Index>>uint(j))&1 == 1,
		}
	}
	return out
}

func (p *Path) fold(leaf [32]byte) [32]byte {
	node := leaf
	for j := 0; j < Depth; j++ {
		if (p.Index>>uint(j))&1 == 1 {
			node = NodeHash(p.Siblings[j], node)
		} else {
			node = NodeHash(node, p.Siblings[j])
		}
	}
	return node
}

// Verify recomputes the root from the proof and compares it with root. The key
// must match the entry the proof carries, so a proof cannot be moved to a
// different key.
func Verify(root [32]byte, key Key, p *Proof) bool {
	if p.Entry.Key != key {
		return false
	}
	return p.Path.fold(LeafHash(p.Entry)) == root
}

// Tree is a built dmt-v1 tree over a set of real keys.
type Tree struct {
	entries []Entry      // sorted by key, unique, guards excluded
	levels  [][][32]byte // levels[0] = occupied leaf prefix; levels[Depth] = {root}
	pad     [][32]byte   // pad[j] = hash of an all-GuardHi subtree of height j
}

// ErrEmptyDuplicate and friends are returned by New for inputs that would make
// slot assignment ambiguous.
var (
	ErrDuplicate = errors.New("dmt-v1: duplicate key")
	ErrGuard     = errors.New("dmt-v1: key collides with a guard value")
)

// New builds the tree over entries, in any order. Slot order is by key; keys
// must be unique and distinct from both guards.
func New(entries []Entry) (*Tree, error) {
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].Key[:], sorted[j].Key[:]) < 0
	})
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Key == sorted[i-1].Key {
			return nil, fmt.Errorf("%w: %x", ErrDuplicate, sorted[i].Key)
		}
	}
	for _, e := range sorted {
		if e.Key == GuardLo || e.Key == GuardHi {
			return nil, fmt.Errorf("%w: %x", ErrGuard, e.Key)
		}
	}
	if len(sorted) > Capacity {
		return nil, fmt.Errorf("dmt-v1: capacity is %d keys, got %d", Capacity, len(sorted))
	}

	pad := make([][32]byte, Depth+1)
	pad[0] = LeafHash(Unrestricted(GuardHi))
	for j := 0; j < Depth; j++ {
		pad[j+1] = NodeHash(pad[j], pad[j])
	}

	levels := make([][][32]byte, Depth+1)
	level0 := make([][32]byte, 0, len(sorted)+1)
	level0 = append(level0, LeafHash(Unrestricted(GuardLo)))
	for _, e := range sorted {
		level0 = append(level0, LeafHash(e))
	}
	levels[0] = level0
	for j := 0; j < Depth; j++ {
		prev := levels[j]
		next := make([][32]byte, 0, (len(prev)+1)/2)
		for i := 0; i < len(prev); i += 2 {
			left := prev[i]
			right := pad[j]
			if i+1 < len(prev) {
				right = prev[i+1]
			}
			next = append(next, NodeHash(left, right))
		}
		levels[j+1] = next
	}
	return &Tree{entries: sorted, levels: levels, pad: pad}, nil
}

// Entries returns the sorted entries (guards excluded).
func (t *Tree) Entries() []Entry {
	out := make([]Entry, len(t.entries))
	copy(out, t.entries)
	return out
}

// EntryOf returns the committed entry for key, if approved.
func (t *Tree) EntryOf(key Key) (Entry, bool) {
	if key == GuardLo || key == GuardHi {
		return Unrestricted(key), true
	}
	i := sort.Search(len(t.entries), func(i int) bool {
		return bytes.Compare(t.entries[i].Key[:], key[:]) >= 0
	})
	if i < len(t.entries) && t.entries[i].Key == key {
		return t.entries[i], true
	}
	return Entry{}, false
}

// Root returns the tree root.
func (t *Tree) Root() [32]byte {
	return t.levels[Depth][0]
}

// SlotOf returns the leaf slot of key and whether it is present. Both guards are
// members: GuardLo is slot 0 and GuardHi is the first padding slot.
func (t *Tree) SlotOf(key Key) (uint16, bool) {
	if key == GuardLo {
		return 0, true
	}
	if key == GuardHi {
		return uint16(len(t.entries) + 1), true
	}
	i := sort.Search(len(t.entries), func(i int) bool {
		return bytes.Compare(t.entries[i].Key[:], key[:]) >= 0
	})
	if i < len(t.entries) && t.entries[i].Key == key {
		return uint16(i + 1), true
	}
	return 0, false
}

func (t *Tree) nodeAt(level, idx int) [32]byte {
	if idx < len(t.levels[level]) {
		return t.levels[level][idx]
	}
	return t.pad[level]
}

// Prove returns a membership proof for key, or false if key is not in the tree.
func (t *Tree) Prove(key Key) (*Proof, bool) {
	slot, ok := t.SlotOf(key)
	if !ok {
		return nil, false
	}
	entry, ok := t.EntryOf(key)
	if !ok {
		return nil, false
	}
	p := &Proof{Entry: entry, Path: Path{Index: slot}}
	idx := int(slot)
	for j := 0; j < Depth; j++ {
		p.Path.Siblings[j] = t.nodeAt(j, idx^1)
		idx >>= 1
	}
	return p, true
}

// Adjacent returns the two keys bracketing an absent key: the greatest member
// below it and the least member above it, together with their proofs. This is
// the non-membership (blacklist) construction of SPEC-dmt-v1.md section 7. It
// is provided for the policy server; the covenant in this version does NOT
// verify non-membership.
func (t *Tree) Adjacent(key Key) (lo, hi Key, loProof, hiProof *Proof, ok bool) {
	if _, present := t.SlotOf(key); present {
		return lo, hi, nil, nil, false
	}
	// Slot sequence including guards: 0=GuardLo, 1..n=keys, n+1=GuardHi.
	i := sort.Search(len(t.entries), func(i int) bool {
		return bytes.Compare(t.entries[i].Key[:], key[:]) >= 0
	})
	// i is the count of real keys below `key`, so the predecessor is slot i and
	// the successor is slot i+1 in the guarded sequence.
	lo = GuardLo
	if i > 0 {
		lo = t.entries[i-1].Key
	}
	hi = GuardHi
	if i < len(t.entries) {
		hi = t.entries[i].Key
	}
	loProof, ok = t.Prove(lo)
	if !ok {
		return lo, hi, nil, nil, false
	}
	hiProof, ok = t.Prove(hi)
	if !ok {
		return lo, hi, nil, nil, false
	}
	return lo, hi, loProof, hiProof, true
}

// ---------------------------------------------------------------- blacklist

// IntervalLeafHash returns SHA256(0x02 || lo || hi), the leaf of the blacklist
// tree.
//
// The blacklist stores the GAPS between listed keys rather than the keys
// themselves. Listing k_1 < ... < k_n yields the n+1 intervals
// (GuardLo, k_1), (k_1, k_2), ..., (k_n, GuardHi), and proving a key absent means
// exhibiting the single interval that strictly contains it. That keeps
// non-membership to one membership proof with no slot arithmetic, which is what
// makes it affordable inside the covenant; a listed key is an interval endpoint
// and the containment test is strict, so no interval can cover it.
//
// The leaf domain byte differs from a whitelist leaf's (0x00), so a whitelist
// proof can never be replayed as a blacklist proof or the other way round.
func IntervalLeafHash(lo, hi Key) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x02})
	h.Write(lo[:])
	h.Write(hi[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// OutpointKey returns the blacklist policy key of an outpoint:
// SHA256(txid || BE32(vout)). txidInternal must be in internal (consensus) byte
// order - the order the input_prev_outpoint jet yields, NOT the reversed order
// txids are displayed in.
func OutpointKey(txidInternal [32]byte, vout uint32) Key {
	h := sha256.New()
	h.Write(txidInternal[:])
	var be [4]byte
	be[0] = byte(vout >> 24)
	be[1] = byte(vout >> 16)
	be[2] = byte(vout >> 8)
	be[3] = byte(vout)
	h.Write(be[:])
	var out Key
	copy(out[:], h.Sum(nil))
	return out
}

// IntervalProof is a non-membership proof: the covering interval plus the
// membership proof of its leaf.
type IntervalProof struct {
	Lo   Key
	Hi   Key
	Path Path
}

// IntervalTree is the blacklist tree over a set of listed keys.
type IntervalTree struct {
	keys   []Key
	levels [][][32]byte
	pad    [][32]byte
}

// NewIntervalTree builds the blacklist tree over the listed keys, in any order.
func NewIntervalTree(keys []Key) (*IntervalTree, error) {
	sorted := make([]Key, len(keys))
	copy(sorted, keys)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, fmt.Errorf("%w: %x", ErrDuplicate, sorted[i])
		}
	}
	for _, k := range sorted {
		if k == GuardLo || k == GuardHi {
			return nil, fmt.Errorf("%w: %x", ErrGuard, k)
		}
	}
	// n listed keys produce n+1 interval leaves.
	if len(sorted)+1 > Slots {
		return nil, fmt.Errorf("dmt-v1: blacklist capacity is %d keys", Slots-1)
	}

	pad := make([][32]byte, Depth+1)
	pad[0] = IntervalLeafHash(GuardHi, GuardHi)
	for j := 0; j < Depth; j++ {
		pad[j+1] = NodeHash(pad[j], pad[j])
	}

	level0 := make([][32]byte, 0, len(sorted)+1)
	lo := GuardLo
	for _, k := range sorted {
		level0 = append(level0, IntervalLeafHash(lo, k))
		lo = k
	}
	level0 = append(level0, IntervalLeafHash(lo, GuardHi))

	levels := make([][][32]byte, Depth+1)
	levels[0] = level0
	for j := 0; j < Depth; j++ {
		prev := levels[j]
		next := make([][32]byte, 0, (len(prev)+1)/2)
		for i := 0; i < len(prev); i += 2 {
			left := prev[i]
			right := pad[j]
			if i+1 < len(prev) {
				right = prev[i+1]
			}
			next = append(next, NodeHash(left, right))
		}
		levels[j+1] = next
	}
	return &IntervalTree{keys: sorted, levels: levels, pad: pad}, nil
}

// Keys returns the sorted listed keys.
func (t *IntervalTree) Keys() []Key {
	out := make([]Key, len(t.keys))
	copy(out, t.keys)
	return out
}

// Root returns the blacklist root, which the covenant carries as BL_ROOT.
func (t *IntervalTree) Root() [32]byte {
	return t.levels[Depth][0]
}

func (t *IntervalTree) nodeAt(level, idx int) [32]byte {
	if idx < len(t.levels[level]) {
		return t.levels[level][idx]
	}
	return t.pad[level]
}

// ProveAbsent proves key is NOT listed. It returns false when the key IS
// listed, which is the point: a frozen outpoint cannot be given a proof.
func (t *IntervalTree) ProveAbsent(key Key) (*IntervalProof, bool) {
	if key == GuardLo || key == GuardHi {
		return nil, false
	}
	i := sort.Search(len(t.keys), func(i int) bool {
		return bytes.Compare(t.keys[i][:], key[:]) >= 0
	})
	if i < len(t.keys) && t.keys[i] == key {
		return nil, false // listed
	}
	lo := GuardLo
	if i > 0 {
		lo = t.keys[i-1]
	}
	hi := GuardHi
	if i < len(t.keys) {
		hi = t.keys[i]
	}
	p := Path{Index: uint16(i)}
	idx := i
	for j := 0; j < Depth; j++ {
		p.Siblings[j] = t.nodeAt(j, idx^1)
		idx >>= 1
	}
	return &IntervalProof{Lo: lo, Hi: hi, Path: p}, true
}

// VerifyAbsent checks a non-membership proof exactly as the covenant does:
// strict containment, then the Merkle path over the interval leaf.
func VerifyAbsent(root [32]byte, key Key, p *IntervalProof) bool {
	if bytes.Compare(p.Lo[:], key[:]) >= 0 || bytes.Compare(key[:], p.Hi[:]) >= 0 {
		return false
	}
	return p.Path.fold(IntervalLeafHash(p.Lo, p.Hi)) == root
}
