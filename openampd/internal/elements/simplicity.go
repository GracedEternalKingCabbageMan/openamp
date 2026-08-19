package elements

import (
	"bytes"
	"fmt"
)

// Taproot derivation for Simplicity covenant outputs (OpenDAMP).
//
// A Simplicity leaf commits to a program's 32-byte CMR under leaf version
// 0xbe, not to a script: the consensus interpreter requires exactly 32 leaf
// bytes and a two-item remaining witness stack for a 0xbe leaf
// (src/script/interpreter.cpp), so the leaf hash covers the CMR with the
// ordinary compact-size length prefix.
//
// The hidden-data leaf is the Simplicity state pattern: a leaf whose "hash"
// is a tagged hash of the data itself, so a fixed program plus a per-owner
// data leaf yields a per-owner address without changing the program. The tag
// is the bare string "TapData" with NO /elements suffix, unlike the branch
// and tweak tags: src/simplicity/jets.c simplicity_tapdata_init pre-loads a
// SHA-256 midstate with the doubled hash of exactly that tag.
const (
	LeafVersionSimplicity = 0xbe

	// TagTapData is deliberately unsuffixed; see above.
	TagTapData = "TapData"
)

// TapLeafHashVersion is TapLeafHash for an arbitrary leaf version, where the
// leaf bytes are a script for tapscript (0xc4) and a CMR for Simplicity
// (0xbe): H_TapLeaf(version || compact_size(len) || leaf).
func TapLeafHashVersion(version byte, leaf []byte) [32]byte {
	var buf bytes.Buffer
	buf.WriteByte(version)
	writeVarBytes(&buf, leaf)
	return TaggedHash(TagTapLeaf, buf.Bytes())
}

// SimplicityLeafHash is the tapleaf hash of a Simplicity program's CMR.
func SimplicityLeafHash(cmr [32]byte) [32]byte {
	return TapLeafHashVersion(LeafVersionSimplicity, cmr[:])
}

// TapDataHash is the hidden data leaf D(x) = H_TapData(x).
func TapDataHash(data [32]byte) [32]byte {
	return TaggedHash(TagTapData, data[:])
}

// CovenantOutput is a derived Simplicity covenant output.
type CovenantOutput struct {
	Root      [32]byte
	OutputKey [32]byte
	Parity    bool
	// LeafHash of the executable program leaf, and the control block that
	// spends through it.
	LeafHash     [32]byte
	ControlBlock []byte
}

// ScriptPubKey is the segwit v1 output script OP_1 <32-byte output key>.
func (c *CovenantOutput) ScriptPubKey() []byte {
	spk := make([]byte, 34)
	spk[0] = 0x51
	spk[1] = 0x20
	copy(spk[2:], c.OutputKey[:])
	return spk
}

// UserCovenant derives C_U(X) = P2TR(NUMS, TapBranch(TapLeaf_0xbe(cmr), TapData(X)))
// for the OpenDAMP user covenant: one executable program leaf plus the hidden
// owner-key data leaf. The internal key is NUMS, so no key-path spend exists.
func UserCovenant(cmr, owner [32]byte) (*CovenantOutput, error) {
	leaf := SimplicityLeafHash(cmr)
	data := TapDataHash(owner)
	root := TapBranchHash(leaf, data)
	return finishCovenant(leaf, data, root)
}

// VerifierCovenant derives C_V(pi) from the MENU of primary programs plus the
// issuer update path.
//
// There is one primary program per transaction SHAPE -- how many input and
// output slots it scans -- because Simplicity's cost bound is static over the
// whole program, so a single program sized for the widest transfer charges
// every ordinary transfer for slots it never touches. Every shape commits to
// the same policy, and each asserts its own bounds, so they all live in one
// address and a narrow leaf cannot be used for a wide transaction.
//
// The tree mirrors opendamp/src/tapscript.rs exactly, and has to: a different
// arrangement of the same leaves is a different address.
//
//	root = TapBranch( L(shapes[0]),  perfect_tree(L(shapes[1..]), L(issuer)) )
//
// The canonical shape sits alone at depth 1 so the leaf a wallet reaches for
// most often carries the shortest control block.
//
// `shapeCMRs` must be in the crate's SHAPES order, canonical first.
func VerifierCovenant(shapeCMRs [][32]byte, issuerCMR [32]byte) (*CovenantOutput, error) {
	root, paths, err := verifierTapTree(shapeCMRs, issuerCMR)
	if err != nil {
		return nil, err
	}
	out, parity, err := TweakPubKey(NUMS, root[:])
	if err != nil {
		return nil, fmt.Errorf("tweak covenant key: %w", err)
	}
	canonical := SimplicityLeafHash(shapeCMRs[0])
	return &CovenantOutput{
		Root: root, OutputKey: out, Parity: parity, LeafHash: canonical,
		ControlBlock: controlBlockForPath(parity, paths[0]),
	}, nil
}

// IssuerPathControlBlock is the control block for spending a verifier output
// through the issuer update path instead of a primary path.
func IssuerPathControlBlock(shapeCMRs [][32]byte, issuerCMR [32]byte) ([]byte, error) {
	root, paths, err := verifierTapTree(shapeCMRs, issuerCMR)
	if err != nil {
		return nil, err
	}
	_, parity, err := TweakPubKey(NUMS, root[:])
	if err != nil {
		return nil, err
	}
	return controlBlockForPath(parity, paths[len(paths)-1]), nil
}

// ShapePathControlBlock is the control block for spending through the primary
// leaf at index `i` of the menu.
func ShapePathControlBlock(shapeCMRs [][32]byte, issuerCMR [32]byte, i int) ([]byte, error) {
	if i < 0 || i >= len(shapeCMRs) {
		return nil, fmt.Errorf("shape index %d out of range for a menu of %d", i, len(shapeCMRs))
	}
	root, paths, err := verifierTapTree(shapeCMRs, issuerCMR)
	if err != nil {
		return nil, err
	}
	_, parity, err := TweakPubKey(NUMS, root[:])
	if err != nil {
		return nil, err
	}
	return controlBlockForPath(parity, paths[i]), nil
}

// verifierTapTree returns the merkle root and, for each leaf in menu order
// (shapes then the issuer leaf), its merkle path bottom-up.
func verifierTapTree(shapeCMRs [][32]byte, issuerCMR [32]byte) ([32]byte, [][][32]byte, error) {
	var zero [32]byte
	if len(shapeCMRs) == 0 {
		return zero, nil, fmt.Errorf("the verifier taptree needs at least one primary leaf")
	}
	leaves := make([][32]byte, 0, len(shapeCMRs)+1)
	for _, c := range shapeCMRs {
		leaves = append(leaves, SimplicityLeafHash(c))
	}
	leaves = append(leaves, SimplicityLeafHash(issuerCMR))

	// Everything except the canonical leaf forms a perfect binary tree, which
	// is what makes the uniform depth assignment a valid taptree.
	rest := leaves[1:]
	if len(rest)&(len(rest)-1) != 0 {
		return zero, nil, fmt.Errorf(
			"the verifier menu leaves %d non-canonical leaves, which is not a power of two; "+
				"the taptree depths would not sum to one", len(rest))
	}
	restRoot, restPaths := perfectTree(rest)

	root := TapBranchHash(leaves[0], restRoot)
	paths := make([][][32]byte, len(leaves))
	paths[0] = [][32]byte{restRoot}
	for i, p := range restPaths {
		paths[i+1] = append(append([][32]byte{}, p...), leaves[0])
	}
	return root, paths, nil
}

// perfectTree folds a power-of-two number of leaves into a balanced tree and
// returns the root plus each leaf's bottom-up sibling path.
func perfectTree(leaves [][32]byte) ([32]byte, [][][32]byte) {
	paths := make([][][32]byte, len(leaves))
	level := append([][32]byte{}, leaves...)
	// index -> which leaves sit under it
	groups := make([][]int, len(leaves))
	for i := range leaves {
		groups[i] = []int{i}
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, len(level)/2)
		nextGroups := make([][]int, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			for _, li := range groups[i] {
				paths[li] = append(paths[li], level[i+1])
			}
			for _, li := range groups[i+1] {
				paths[li] = append(paths[li], level[i])
			}
			next = append(next, TapBranchHash(level[i], level[i+1]))
			nextGroups = append(nextGroups, append(append([]int{}, groups[i]...), groups[i+1]...))
		}
		level, groups = next, nextGroups
	}
	return level[0], paths
}

// controlBlockForPath builds (leaf_version | parity) || NUMS || path..., where
// the path is bottom-up. A Simplicity spend carries leaf version 0xbe.
func controlBlockForPath(parity bool, path [][32]byte) []byte {
	cb := make([]byte, 0, 1+32+32*len(path))
	v := byte(LeafVersionSimplicity)
	if parity {
		v |= 1
	}
	cb = append(cb, v)
	cb = append(cb, NUMS[:]...)
	for _, n := range path {
		cb = append(cb, n[:]...)
	}
	return cb
}

func finishCovenant(execLeaf, sibling, root [32]byte) (*CovenantOutput, error) {
	out, parity, err := TweakPubKey(NUMS, root[:])
	if err != nil {
		return nil, fmt.Errorf("tweak covenant key: %w", err)
	}
	return &CovenantOutput{
		Root: root, OutputKey: out, Parity: parity, LeafHash: execLeaf,
		ControlBlock: controlBlockFor(parity, sibling[:]),
	}, nil
}

// controlBlockFor builds (leaf_version | parity) || NUMS || sibling for a
// two-leaf tree. The leaf version in a control block is the version of the
// leaf being spent, so a Simplicity spend carries 0xbe.
func controlBlockFor(parity bool, sibling []byte) []byte {
	cb := make([]byte, 0, 1+32+len(sibling))
	v := byte(LeafVersionSimplicity)
	if parity {
		v |= 1
	}
	cb = append(cb, v)
	cb = append(cb, NUMS[:]...)
	cb = append(cb, sibling...)
	return cb
}
