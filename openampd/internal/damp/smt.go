package damp

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"sort"
)

// smtDepth is the fixed tree depth: one level per key bit.
const smtDepth = 256

// ProofVersion is the leading byte of every smt-v1 proof (see package doc).
const ProofVersion = 0x01

// emptyAt[h] is the hash of an empty subtree of height h; emptyAt[0] is the
// empty leaf (32 zero bytes) and emptyAt[smtDepth] the empty tree's root.
var emptyAt = func() [smtDepth + 1][32]byte {
	var e [smtDepth + 1][32]byte
	for h := 1; h <= smtDepth; h++ {
		e[h] = nodeHash(e[h-1], e[h-1])
	}
	return e
}()

// EmptyRoot returns the root of an empty smt-v1 tree, which is also the root
// an enabled-but-empty predicate list commits to (distinct from the all-zero
// commitment of an absent predicate).
func EmptyRoot() [32]byte { return emptyAt[smtDepth] }

func nodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func leafHash(key [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(key[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// keyBit returns bit d of the key, MSB-first (d = 0 is the top bit of key[0]).
func keyBit(key [32]byte, d int) byte {
	return (key[d/8] >> (7 - uint(d%8))) & 1
}

// SMT is a sparse Merkle tree ("smt-v1") over 32-byte keys mapping to
// present/absent. It is a commitment structure, not a database: the key set
// is held in memory and roots/proofs are recomputed on demand, which is the
// right trade at registrar scale (policy lists, not chain state). Not safe
// for concurrent use.
type SMT struct {
	keys map[[32]byte]struct{}
}

// NewSMT returns an empty tree.
func NewSMT() *SMT { return &SMT{keys: map[[32]byte]struct{}{}} }

// Insert marks key present (idempotent).
func (t *SMT) Insert(key [32]byte) { t.keys[key] = struct{}{} }

// Delete marks key absent (idempotent).
func (t *SMT) Delete(key [32]byte) { delete(t.keys, key) }

// Has reports whether key is present.
func (t *SMT) Has(key [32]byte) bool {
	_, ok := t.keys[key]
	return ok
}

// Len returns the number of present keys.
func (t *SMT) Len() int { return len(t.keys) }

// sortedKeys returns the key set in ascending byte order, which makes the
// recursive subtree computation deterministic and partitionable.
func (t *SMT) sortedKeys() [][32]byte {
	out := make([][32]byte, 0, len(t.keys))
	for k := range t.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		for x := 0; x < 32; x++ {
			if a[x] != b[x] {
				return a[x] < b[x]
			}
		}
		return false
	})
	return out
}

// subtree hashes the subtree at the given depth containing exactly the given
// keys (all of which share the path prefix above depth). keys must be sorted;
// because keys are sorted and path bits are MSB-first, the left/right
// partition at each depth is a contiguous split.
func subtree(keys [][32]byte, depth int) [32]byte {
	if len(keys) == 0 {
		return emptyAt[smtDepth-depth]
	}
	if depth == smtDepth {
		// Exactly one key can reach a full-depth leaf (keys are 256 bits).
		return leafHash(keys[0])
	}
	split := sort.Search(len(keys), func(i int) bool { return keyBit(keys[i], depth) == 1 })
	return nodeHash(subtree(keys[:split], depth+1), subtree(keys[split:], depth+1))
}

// Root returns the current root (EmptyRoot() for an empty tree).
func (t *SMT) Root() [32]byte { return subtree(t.sortedKeys(), 0) }

// prove builds the compact proof (see the package doc for the encoding) for
// key against the current key set, regardless of the key's own presence: the
// siblings along the key's path are the same either way.
func (t *SMT) prove(key [32]byte) []byte {
	keys := t.sortedKeys()
	var bitmap [32]byte
	var sibs [][32]byte
	for d := 0; d < smtDepth; d++ {
		split := sort.Search(len(keys), func(i int) bool { return keyBit(keys[i], d) == 1 })
		var path, sibling [][32]byte
		if keyBit(key, d) == 0 {
			path, sibling = keys[:split], keys[split:]
		} else {
			path, sibling = keys[split:], keys[:split]
		}
		sib := subtree(sibling, d+1)
		if sib != emptyAt[smtDepth-1-d] {
			bitmap[d/8] |= 1 << (7 - uint(d%8))
			sibs = append(sibs, sib)
		}
		keys = path
	}
	proof := make([]byte, 0, 33+32*len(sibs))
	proof = append(proof, ProofVersion)
	proof = append(proof, bitmap[:]...)
	for _, s := range sibs {
		proof = append(proof, s[:]...)
	}
	return proof
}

// ProveMember returns a membership proof for a present key; it is an error to
// ask for one when the key is absent.
func (t *SMT) ProveMember(key [32]byte) ([]byte, error) {
	if !t.Has(key) {
		return nil, fmt.Errorf("smt: key not present; a membership proof would not verify")
	}
	return t.prove(key), nil
}

// ProveNonMember returns a non-membership proof for an absent key; it is an
// error to ask for one when the key is present.
func (t *SMT) ProveNonMember(key [32]byte) ([]byte, error) {
	if t.Has(key) {
		return nil, fmt.Errorf("smt: key present; a non-membership proof would not verify")
	}
	return t.prove(key), nil
}

// foldProof recomputes the root implied by proof for the given key and leaf
// hash. It refuses malformed encodings (bad version, wrong length, or a
// supplied sibling equal to the empty hash of its level, which must be
// encoded via the bitmap for canonicality).
func foldProof(key [32]byte, leaf [32]byte, proof []byte) ([32]byte, error) {
	if len(proof) < 33 || proof[0] != ProofVersion {
		return [32]byte{}, fmt.Errorf("smt: bad proof header")
	}
	var bitmap [32]byte
	copy(bitmap[:], proof[1:33])
	n := 0
	for _, b := range bitmap {
		n += bits.OnesCount8(b)
	}
	if len(proof) != 33+32*n {
		return [32]byte{}, fmt.Errorf("smt: proof length %d does not match bitmap (%d siblings)", len(proof), n)
	}
	// Siblings are encoded in increasing depth order; fold from the leaf up.
	cur := leaf
	for d := smtDepth - 1; d >= 0; d-- {
		var sib [32]byte
		if bitmap[d/8]&(1<<(7-uint(d%8))) != 0 {
			n--
			copy(sib[:], proof[33+32*n:33+32*n+32])
			if sib == emptyAt[smtDepth-1-d] {
				return [32]byte{}, fmt.Errorf("smt: non-canonical proof: empty sibling encoded explicitly at depth %d", d)
			}
		} else {
			sib = emptyAt[smtDepth-1-d]
		}
		if keyBit(key, d) == 0 {
			cur = nodeHash(cur, sib)
		} else {
			cur = nodeHash(sib, cur)
		}
	}
	return cur, nil
}

// VerifyMember reports whether proof proves key PRESENT under root.
func VerifyMember(root, key [32]byte, proof []byte) bool {
	got, err := foldProof(key, leafHash(key), proof)
	return err == nil && got == root
}

// VerifyNonMember reports whether proof proves key ABSENT under root.
func VerifyNonMember(root, key [32]byte, proof []byte) bool {
	got, err := foldProof(key, [32]byte{}, proof)
	return err == nil && got == root
}
