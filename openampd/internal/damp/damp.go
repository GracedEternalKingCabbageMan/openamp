// Package damp is the OpenDAMP M2 policy-commitment library: the commitment
// constructions an OpenDAMP verifier covenant checks on-chain, computed
// off-chain by the policy server (and by wallets assembling proofs). It
// implements the formats frozen in the node repo's
// doc/sequentia/opendamp-design.md sections 3 and 4:
//
//   - the policy commitment pi over a PolicyHeader (section 3.1),
//   - the "smt-v1" sparse Merkle tree over 32-byte policy keys with
//     membership and non-membership proofs (sections 3.2, 3.3),
//   - the rules_root Merkle over the four predicate commitments,
//   - the snapshot/v1 publication document (section 4) with canonical JSON,
//     BIP340 issuer signature and self-validation.
//
// Everything here is consensus-adjacent: the SMT proof encoding becomes the
// wire format inside Simplicity witnesses (M1/M3), and the snapshot canonical
// bytes are content-addressed and committed into asset contracts. Treat every
// byte layout in this package as frozen once an asset ships against it.
//
// # smt-v1
//
// A fixed-depth (256) binary tree over 32-byte keys mapping each key to
// present/absent. Path bits are read MSB-first: bit d of a key (d = 0 is the
// most significant bit of key[0]) selects the child at depth d, 0 = left.
//
//	leaf(present key) = SHA256(0x00 || key)
//	leaf(absent)      = 32 zero bytes
//	node              = SHA256(0x01 || left || right)
//	empty[0]          = 32 zero bytes            (empty subtree of height 0)
//	empty[h]          = SHA256(0x01 || empty[h-1] || empty[h-1])
//
// The root of an empty tree is empty[256] (a fixed non-zero constant), which
// keeps "enabled but empty predicate" distinct from "predicate absent"
// (all-zero commitment) in RulesRoot.
//
// # smt-v1 proof encoding (canonical, versioned)
//
//	byte 0        : 0x01 (proof format version)
//	bytes 1..32   : 256-bit sibling bitmap. Bit d (depth d along the path,
//	                0 = the sibling of the root's chosen child) is bit
//	                (7 - d%8) of byte 1 + d/8, i.e. MSB-first, matching the
//	                key bit order. Bit d is set iff the sibling subtree at
//	                depth d is non-empty.
//	then          : one 32-byte sibling hash per set bit, in increasing
//	                depth order.
//
// A proof therefore has length 33 + 32*popcount(bitmap). Verification folds
// from the leaf up, substituting the precomputed empty-subtree hash for every
// unset bit. The same encoding serves membership (leaf = SHA256(0x00||key))
// and non-membership (leaf = 32 zero bytes) proofs.
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

// Snapshot "tree" values this library implements.
//
//   - TreeSMTv1 is the design document's depth-256 sparse Merkle tree. It is
//     the pure-M2 document format: nothing on chain reads it, and its pi is
//     built from RulesRoot (below) over display-order asset bytes.
//   - TreeDMTv1 is the tree the SHIPPED covenants actually verify against
//     (opendamp/SPEC-dmt-v1.md): a sorted dense tree of depth 16. A dmt-v1
//     snapshot is therefore a CONSENSUS-BEARING document, and its pi is the
//     covenant's pi — PiCovenant over INTERNAL-order asset bytes and
//     RulesRootCovenant, both in covenant.go. The two pi constructions are
//     deliberately different and each is pinned to its own vectors; a snapshot
//     declares which one applies by its tree field. Never compute one with the
//     other's rules_root.
//
// The design doc also reserves "cmt-v1" (Cartesian Merkle tree), which is not
// supported here; Validate refuses it.
const (
	TreeSMTv1 = "smt-v1"
	TreeDMTv1 = "dmt-v1"
)

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

// RulesRoot is the fixed-order Merkle root over the four predicate
// commitments (design doc 3.1), using the smt-v1 interior node hash
// SHA256(0x01 || left || right):
//
//	rules_root = node( node(blacklist_root, whitelist_root),
//	                   node(limit_commitment, windows_hash) )
//
// An absent predicate commits to 32 zero bytes: pass a zero blacklistRoot /
// whitelistRoot / windowsHash for a disabled predicate, and limit 0 for no
// transfer limit (committed as zeros; nonzero limits commit via
// LimitCommitment).
func RulesRoot(blacklistRoot, whitelistRoot [32]byte, limit uint64, windowsHash [32]byte) [32]byte {
	var limitC [32]byte
	if limit != 0 {
		limitC = LimitCommitment(limit)
	}
	left := nodeHash(blacklistRoot, whitelistRoot)
	right := nodeHash(limitC, windowsHash)
	return nodeHash(left, right)
}
