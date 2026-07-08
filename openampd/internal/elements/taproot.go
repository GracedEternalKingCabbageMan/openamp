package elements

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Elements uses distinct BIP340 tags from Bitcoin.
const (
	TagTapLeaf    = "TapLeaf/elements"
	TagTapBranch  = "TapBranch/elements"
	TagTapTweak   = "TapTweak/elements"
	TagTapSighash = "TapSighash/elements"

	LeafVersionTapscript = 0xc4
)

// NUMS is the BIP341 nothing-up-my-sleeve point; enclave outputs use it as
// the internal key so no key-path spend exists.
var NUMS = MustHex32("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

// MustHex32 parses a 64-char hex string into a 32-byte array (no reversal).
func MustHex32(s string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("MustHex32: bad input " + s)
	}
	copy(out[:], b)
	return out
}

func TaggedHash(tag string, chunks ...[]byte) [32]byte {
	th := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(th[:])
	h.Write(th[:])
	for _, c := range chunks {
		h.Write(c)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// TapLeafHash of a tapscript leaf: H_TapLeaf(version || compact_size(len) || script).
func TapLeafHash(script []byte) [32]byte {
	var buf bytes.Buffer
	buf.WriteByte(LeafVersionTapscript)
	writeVarBytes(&buf, script)
	return TaggedHash(TagTapLeaf, buf.Bytes())
}

// TapBranchHash combines two node hashes in lexicographic order.
func TapBranchHash(a, b [32]byte) [32]byte {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	return TaggedHash(TagTapBranch, a[:], b[:])
}

// TweakPubKey computes Q = P + H_TapTweak(P||root)*G for an x-only internal
// key, returning the output key and its Y parity.
func TweakPubKey(internal [32]byte, root []byte) (outputKey [32]byte, parity bool, err error) {
	t := TaggedHash(TagTapTweak, internal[:], root)
	pk, err := schnorr.ParsePubKey(internal[:])
	if err != nil {
		return outputKey, false, fmt.Errorf("internal key: %w", err)
	}
	var p, tg, q secp.JacobianPoint
	pk.AsJacobian(&p)
	var scalar secp.ModNScalar
	if overflow := scalar.SetBytes(&t); overflow != 0 {
		return outputKey, false, fmt.Errorf("tweak overflow")
	}
	secp.ScalarBaseMultNonConst(&scalar, &tg)
	secp.AddNonConst(&p, &tg, &q)
	q.ToAffine()
	xb := q.X.Bytes()
	copy(outputKey[:], xb[:])
	return outputKey, q.Y.IsOdd(), nil
}

// Leaf is a named tapscript leaf.
type Leaf struct {
	Name   string
	Script []byte
}

// TapTree is a constructed two-level tree (one or two leaves; all openampd
// enclave trees are at most two leaves).
type TapTree struct {
	Internal  [32]byte
	OutputKey [32]byte
	Parity    bool
	Root      [32]byte
	Leaves    map[string]*LeafInfo
}

type LeafInfo struct {
	Script       []byte
	Hash         [32]byte
	MerkleBranch []byte // sibling hashes, leaf to root
}

// BuildTree constructs a taproot tree from one or two leaves with the given
// internal key. Matches test_framework taproot_construct for these shapes.
func BuildTree(internal [32]byte, leaves ...Leaf) (*TapTree, error) {
	if len(leaves) == 0 || len(leaves) > 2 {
		return nil, fmt.Errorf("BuildTree supports 1 or 2 leaves, got %d", len(leaves))
	}
	tree := &TapTree{Internal: internal, Leaves: map[string]*LeafInfo{}}
	infos := make([]*LeafInfo, len(leaves))
	for i, l := range leaves {
		infos[i] = &LeafInfo{Script: l.Script, Hash: TapLeafHash(l.Script)}
		tree.Leaves[l.Name] = infos[i]
	}
	if len(leaves) == 1 {
		tree.Root = infos[0].Hash
	} else {
		tree.Root = TapBranchHash(infos[0].Hash, infos[1].Hash)
		infos[0].MerkleBranch = infos[1].Hash[:]
		infos[1].MerkleBranch = infos[0].Hash[:]
	}
	out, parity, err := TweakPubKey(internal, tree.Root[:])
	if err != nil {
		return nil, err
	}
	tree.OutputKey = out
	tree.Parity = parity
	return tree, nil
}

// ScriptPubKey is the segwit v1 output script OP_1 <32-byte output key>.
func (t *TapTree) ScriptPubKey() []byte {
	spk := make([]byte, 34)
	spk[0] = 0x51
	spk[1] = 0x20
	copy(spk[2:], t.OutputKey[:])
	return spk
}

// ControlBlock for spending via the named leaf.
func (t *TapTree) ControlBlock(name string) ([]byte, error) {
	leaf, ok := t.Leaves[name]
	if !ok {
		return nil, fmt.Errorf("no leaf %q", name)
	}
	cb := make([]byte, 0, 33+len(leaf.MerkleBranch))
	first := byte(LeafVersionTapscript)
	if t.Parity {
		first |= 1
	}
	cb = append(cb, first)
	cb = append(cb, t.Internal[:]...)
	cb = append(cb, leaf.MerkleBranch...)
	return cb, nil
}

// --- enclave construction --------------------------------------------------

// CheckSigPair builds <a> OP_CHECKSIGVERIFY <b> OP_CHECKSIG.
func CheckSigPair(a, b [32]byte) []byte {
	s := make([]byte, 0, 70)
	s = append(s, 0x20)
	s = append(s, a[:]...)
	s = append(s, 0xad) // OP_CHECKSIGVERIFY
	s = append(s, 0x20)
	s = append(s, b[:]...)
	s = append(s, 0xac) // OP_CHECKSIG
	return s
}

// EnclaveTree builds the Tier A enclave for a holder: transfer leaf
// (user+policy) and, when clawback is enabled, the clawback leaf
// (issuer+policy). Spec: openamp contract-v1 §4.
func EnclaveTree(userX, policyX [32]byte, issuerX *[32]byte) (*TapTree, error) {
	leaves := []Leaf{{Name: "transfer", Script: CheckSigPair(userX, policyX)}}
	if issuerX != nil {
		leaves = append(leaves, Leaf{Name: "claw", Script: CheckSigPair(*issuerX, policyX)})
	}
	return BuildTree(NUMS, leaves...)
}

// SignSchnorr signs a 32-byte message with a BIP340 signature.
func SignSchnorr(privKey []byte, msg [32]byte) ([]byte, error) {
	priv, _ := btcec.PrivKeyFromBytes(privKey)
	sig, err := schnorr.Sign(priv, msg[:])
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

// XOnlyFromPriv returns the BIP340 x-only public key of a private key.
func XOnlyFromPriv(privKey []byte) [32]byte {
	_, pub := btcec.PrivKeyFromBytes(privKey)
	var out [32]byte
	copy(out[:], schnorr.SerializePubKey(pub))
	return out
}
