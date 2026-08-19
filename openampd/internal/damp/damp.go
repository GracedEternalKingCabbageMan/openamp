// Package damp is the OpenDAMP M2 policy-commitment library: the commitment
// constructions an OpenDAMP verifier covenant checks on-chain, computed
// off-chain by the policy server (and by wallets assembling proofs). It
// implements the formats frozen in the node repo's
// doc/sequentia/opendamp-design.md sections 3 and 4:
//
//   - the policy commitment pi over a PolicyHeader (section 3.1),
//   - the "dmt-v1" sorted dense Merkle tree the covenants verify against, in
//     dmt/ and covenant.go (sections 3.2, 3.3),
//   - the rules_root Merkle over the four predicate commitments,
//   - the snapshot/v1 publication document (section 4) with canonical JSON,
//     BIP340 issuer signature and self-validation.
//
// Everything here is consensus-adjacent: the proof encoding becomes the wire
// format inside Simplicity witnesses (M1/M3), and the snapshot canonical bytes
// are content-addressed and committed into asset contracts. Treat every byte
// layout in this package as frozen once an asset ships against it.
//
// # One tree, one pi
//
// An earlier revision carried a second format, "smt-v1": a depth-256 sparse
// Merkle tree from an early draft of the design document, with its own parallel
// pi construction and its own proof encoding. Nothing on chain could read it --
// a depth-256 proof does not fit the Simplicity budget, which is precisely why
// dmt-v1 exists -- and it survived as a document format whose Validate path
// skipped every consistency check dmt-v1 gets. A snapshot declaring it was
// accepted almost unexamined and would have committed funds to an address no
// holder could spend. It was removed on 2026-08-19, along with the second pi
// construction, and Validate now refuses anything but dmt-v1 by name.
package damp

import (
	"crypto/sha256"
	"encoding/binary"
)

// Tagged-hash domains (BIP340 construction, OpenDAMP-specific tags).
const (
	TagPolicy   = "OpenDAMP/policy/v1"
	TagSnapshot = "OpenDAMP/snapshot/v1"
	TagLimit    = "OpenDAMP/limit/v1"
	TagWindows  = "OpenDAMP/windows/v1"
)

// TreeDMTv1 is the only snapshot "tree" value this library implements, and the
// only one any covenant can verify against (opendamp/SPEC-dmt-v1.md): a sorted
// dense tree of depth 16. A dmt-v1 snapshot is therefore a CONSENSUS-BEARING
// document, and its pi is the covenant's pi -- PiCovenant over INTERNAL-order
// asset bytes and RulesRootCovenant, both in covenant.go.
//
// An earlier revision also carried "smt-v1", a depth-256 sparse Merkle tree
// from an early draft of the design document, with its own parallel pi
// construction. Nothing on chain could read it: a depth-256 proof does not fit
// the Simplicity budget, which is why dmt-v1 exists. It survived as a document
// format whose Validate path skipped every consistency check dmt-v1 gets, so a
// snapshot declaring it was accepted almost unexamined and would have locked
// funds behind an address no holder could spend. It is gone, along with the
// second pi construction, and Validate now refuses anything but dmt-v1.
const TreeDMTv1 = "dmt-v1"

// taggedHash is the BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
// Implemented locally (mirroring elements.TaggedHash) so this package's
// commitments have no dependency outside the standard library.
func taggedHash(tag string, chunks ...[]byte) [32]byte {
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

// PolicyHeader is the preimage of the policy commitment pi (design doc 3.1).
// Asset is the 32 asset-id bytes exactly as they appear (hex-decoded) in the
// snapshot's "asset" field, i.e. display order; the commitment covers those
// bytes verbatim.
type PolicyHeader struct {
	Version   uint8
	Asset     [32]byte
	Seq       uint64
	RulesRoot [32]byte
}

// Commitment computes pi = H_"OpenDAMP/policy/v1"(version_u8 || asset ||
// seq_be64 || rules_root).
func (h PolicyHeader) Commitment() [32]byte {
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], h.Seq)
	return taggedHash(TagPolicy, []byte{h.Version}, h.Asset[:], seq[:], h.RulesRoot[:])
}

// OutpointKey is the policy key of an input outpoint for the blacklist
// predicate (design doc 3.2): SHA256(txid || BE32(vout)). Owner-key entries for
// the whitelist predicate are the raw 32-byte x-only key itself (hashed by the
// tree's leaf rule like any key).
//
// BYTE ORDER IS THE CALLER'S: pass the txid in the order the consumer uses, and
// the two consumers differ. The snapshot document uses display order (matching
// PolicyHeader.Asset); the covenant reads a transaction's prevout, so a key the
// on-chain blacklist must match is built from the txid in INTERNAL order. Feed
// the wrong order and the proof simply never matches, silently.
func OutpointKey(txid [32]byte, vout uint32) [32]byte {
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], vout)
	h := sha256.New()
	h.Write(txid[:])
	h.Write(v[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// LimitCommitment commits a nonzero transfer limit:
// H_"OpenDAMP/limit/v1"(BE64(limit)). A zero (absent) limit commits to 32
// zero bytes; callers use RulesRoot which applies that rule.
func LimitCommitment(limit uint64) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], limit)
	return taggedHash(TagLimit, b[:])
}

