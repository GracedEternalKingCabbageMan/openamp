# OpenDAMP M2: policy-commitment library and snapshot service

Companion to the protocol specification `doc/sequentia/opendamp-design.md` in
the Sequentia node repository. That document is authoritative for the formats;
this note records what the M2 milestone delivers in `openampd`, what it
deliberately refuses, and the wire formats it freezes.

## What M2 delivers

- **`internal/damp`, the policy-commitment library**: the policy commitment
  `pi` over a `PolicyHeader` (design doc 3.1), the `smt-v1` sparse Merkle tree
  over 32-byte policy keys with membership and non-membership proofs, the
  outpoint and owner-key policy keys, the fixed-order `rules_root` over the
  four predicate commitments, and the `snapshot/v1` document with canonical
  JSON, content hash, BIP340 issuer signature and self-validation. All
  commitments are golden-vectored in the package tests; treat a golden change
  as a format break.

- **The snapshot service** (design doc section 4), live now because it is pure
  data plane:
  - `POST /v1/issuer/snapshots` (bearer-gated): accepts a full snapshot
    document, runs `Validate()` (predicate roots recomputed from inline
    entries, `pi` recomputed from the header), verifies the issuer signature,
    enforces gapless `seq` (first is 0) and `prev_pi` chaining per asset,
    persists, and writes a `snapshot` entry to the hash-chained transparency
    log. For an asset this daemon issued, the signature must verify against
    the stored issuer key; for an external asset the first snapshot pins its
    key trust-on-first-use and every later snapshot must chain under the same
    key (see the trust note in `internal/server/snapshots.go`).
  - `GET /v1/snapshots?asset=<id>[&seq=n]` (public): latest by default, exact
    version on request, 404 when unknown. The response carries the stored
    canonical bytes verbatim plus `issuer_sig` and the pinned `issuer_pub`,
    so any client can re-verify offline.

- **The enforcement election plumbed through issuance**: `POST
  /v1/issuer/assets` accepts `"enforcement"` with values `"cosign"` and
  `"damp"` (anything else is a 400), plus `"verifier_amount"` for the damp
  shape. Omitted and `"cosign"` are the same election and add nothing to the
  contract. `store.Asset` gained an omitempty `enforcement` field for future
  damp assets; nothing ever writes `"cosign"` into it.

## What is deliberately refused

- **Damp issuance** returns `501` with body error `network enforcement is not
  yet available on this policy server`, logs a refusal, and has zero side
  effects. The verifier covenant and the fixed user program are the M1/M3
  milestones; until their CMRs exist there is nothing sound to commit into a
  contract. The refusal happens before any key generation or funding
  selection. The contract fields the election will add (design doc section 5:
  `enforcement`, `verifier_asset`, `verifier_amount`, `issuer_update_key`,
  `genesis_policy`, `genesis_snapshot_hash`) are documented at the refusal
  site in `internal/server/issue.go`.
- **`cmt-v1` snapshots**: the library implements `smt-v1` only and
  `Validate()` refuses any other `tree` value.
- **URL-only predicate lists**: the M2 snapshot service requires inline
  entries so the declared roots are always recomputable server-side.

## Frozen invariants

The canonical contract JSON is consensus-grade. The `cosign` election is the
absent state everywhere: an `enforcement: "cosign"` issuance produces contract
bytes identical to an enforcement-absent one, and stored assets never carry an
explicit `"cosign"`. Pre-existing assets (BONDX and every asset on the live
testnet) are byte-identical before and after M2; the byte-identity tests in
`internal/server/damp_m2_test.go` and `oa1_test.go` pin this.

## Wire formats frozen by M2

### smt-v1

Fixed-depth (256) binary tree over 32-byte keys, present/absent values. Path
bits are MSB-first (bit 0 is the top bit of the first key byte, 0 = left).

    leaf(present key) = SHA256(0x00 || key)
    leaf(absent)      = 32 zero bytes
    node              = SHA256(0x01 || left || right)
    empty[0]          = 32 zero bytes
    empty[h]          = SHA256(0x01 || empty[h-1] || empty[h-1])

The empty tree's root is `empty[256]`
(`6155289130893872355eac98042d22aefa2c2e708bea169402760e3b55f9a2dc`), which
keeps an enabled-but-empty list distinct from an absent predicate (32 zero
bytes in `rules_root`).

Policy keys: blacklist entries are `SHA256(txid || BE32(vout))` over the
display-order txid bytes; whitelist entries are the raw 32-byte x-only owner
key.

### smt-v1 proof encoding

This encoding becomes the proof format inside Simplicity witnesses in M1/M3,
so it is canonical and versioned:

    byte 0      : 0x01 (proof format version)
    bytes 1..32 : 256-bit sibling bitmap, MSB-first by depth (bit d set iff
                  the sibling subtree at depth d along the key's path is
                  non-empty)
    then        : one 32-byte sibling hash per set bit, in increasing depth
                  order

Length is exactly `33 + 32 * popcount(bitmap)`. Verifiers substitute the
precomputed empty-subtree hash for every unset bit and reject a proof that
encodes an empty sibling explicitly, so each statement has exactly one valid
encoding. Membership and non-membership use the same encoding and differ only
in the leaf value.

### Commitments

    pi          = H_"OpenDAMP/policy/v1"(version_u8 || asset_32 || seq_be64 || rules_root)
    rules_root  = node(node(blacklist_root, whitelist_root),
                       node(limit_commitment, windows_hash))
    limit_commitment = H_"OpenDAMP/limit/v1"(BE64(limit)), or 32 zero bytes when no limit
    windows_hash     = H_"OpenDAMP/windows/v1"(canonical JSON of the windows array),
                       or 32 zero bytes when empty
    snapshot hash    = SHA256(canonical JSON without issuer_sig)
    issuer_sig       = BIP340 over H_"OpenDAMP/snapshot/v1"(snapshot hash)

All `H_tag` are BIP340 tagged hashes: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.

### Canonical JSON

Object keys sorted at every nesting level, compact separators (no
insignificant whitespace), numbers as plain JSON integers (full uint64 range
preserved), `issuer_sig` excluded from the canonical bytes it signs, `prev_pi`
explicitly `null` for the genesis snapshot. The snapshot service stores and
serves these exact bytes; the content hash commits to them verbatim.
