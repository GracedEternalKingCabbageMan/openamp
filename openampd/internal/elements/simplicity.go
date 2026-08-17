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

// VerifierCovenant derives C_V(pi) = P2TR(NUMS, TapBranch(TapLeaf_0xbe(primary),
// TapLeaf_0xbe(issuer))): the policy-parameterized primary path and the issuer
// update path. The primary leaf is the one a holder transfer spends through.
func VerifierCovenant(primaryCMR, issuerCMR [32]byte) (*CovenantOutput, error) {
	primary := SimplicityLeafHash(primaryCMR)
	issuer := SimplicityLeafHash(issuerCMR)
	root := TapBranchHash(primary, issuer)
	return finishCovenant(primary, issuer, root)
}

// IssuerPathControlBlock is the control block for spending a verifier output
// through the issuer update path instead of the primary path.
func IssuerPathControlBlock(primaryCMR, issuerCMR [32]byte) ([]byte, error) {
	primary := SimplicityLeafHash(primaryCMR)
	issuer := SimplicityLeafHash(issuerCMR)
	root := TapBranchHash(primary, issuer)
	_, parity, err := TweakPubKey(NUMS, root[:])
	if err != nil {
		return nil, err
	}
	return controlBlockFor(parity, primary[:]), nil
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
