# OpenDAMP M2: policy-commitment library and snapshot service

Companion to the protocol specification `doc/sequentia/opendamp-design.md` in
the Sequentia node repository. That document is authoritative for the formats;
this note records what the M2 milestone delivers in `openampd`, what it
deliberately refuses, and the wire formats it freezes.

## What M2 delivers

- **`internal/damp`, the policy-commitment library**: the policy commitment
  `pi` over a `PolicyHeader` (design doc 3.1), the `dmt-v1` sorted dense Merkle
  tree the covenants verify against (membership for the whitelist, interval
  non-membership for the blacklist), the outpoint and owner-key policy keys,
  the fixed-order `rules_root` over the four predicate commitments, and the
  `snapshot/v1` document with canonical JSON, content hash, BIP340 issuer
  signature and self-validation. All commitments are golden-vectored in the
  package tests; treat a golden change as a format break.

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
- **Any `tree` but `dmt-v1`**: it is the only format any covenant can verify
  against, and `Validate()` refuses the rest by name. The design document once
  reserved `smt-v1` and `cmt-v1`, and the library did carry an `smt-v1`
  document format with its own parallel `pi`; a depth-256 proof does not fit
  the Simplicity budget, so nothing on chain could ever read it, and its
  validation path skipped every consistency check `dmt-v1` gets. It was removed
  on 2026-08-19: a snapshot declaring it would have committed funds to an
  address no holder could spend.
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

### dmt-v1

A sorted dense Merkle tree of depth 16 (65,536 slots, 65,534 real keys). Slot 0
and every slot above the real keys hold structural guards, so the key sequence
is total and every real key has a predecessor and a successor.

    leaf(entry)      = SHA256(0x00 || key || BE32(send_after) || BE32(recv_after))
    node(left,right) = SHA256(0x01 || left || right)     (positional, NOT sorted)
    interval(lo,hi)  = SHA256(0x02 || lo || hi)
    guard(key)       = SHA256(0x03 || key)

Guards hash under their own domain byte, and that is a security property rather
than tidiness: as ordinary key leaves they were provable whitelist members, and
because a recipient key reaches `C_U(Y)` only through a hash, a holder could pay
regulated units to `C_U(0xff..ff)` and destroy them permanently.

The whitelist proves membership; the blacklist stores the GAPS between listed
keys and proves non-membership by exhibiting the interval that strictly contains
the key, which is one ordinary membership proof rather than an adjacency
argument. The empty blacklist still has a root (its guard interval), so "freeze
nothing" is a commitment like any other.

Policy keys: blacklist entries are `SHA256(txid || BE32(vout))` with the txid in
**internal** (consensus) byte order, which is what the `input_prev_outpoint` jet
yields; whitelist entries are the raw 32-byte x-only owner key.

Byte-for-byte specification, golden vectors and the witness encoding the
covenant consumes: `opendamp/SPEC-dmt-v1.md`.

### Commitments

    pi          = H_"OpenDAMP/policy/v1"(version_u8 || asset_32 || seq_be64 || rules_root)
    rules_root  = node(node(blacklist_root, whitelist_root),
                       node(limit_commitment, windows_hash))
    limit_commitment = H_"OpenDAMP/limit/v1"(BE64(limit)), or 32 zero bytes when no limit
    windows_hash     = 32 zero bytes. A height bound belongs to the holder it
                       binds, inside that holder's whitelist leaf; the separate
                       class-keyed windows array no shipped covenant reads is
                       refused by Validate rather than committed to
    snapshot hash    = SHA256(canonical JSON without issuer_sig)
    issuer_sig       = BIP340 over H_"OpenDAMP/snapshot/v1"(snapshot hash)

All `H_tag` are BIP340 tagged hashes: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.

### Canonical JSON

Object keys sorted at every nesting level, compact separators (no
insignificant whitespace), numbers as plain JSON integers (full uint64 range
preserved), `issuer_sig` excluded from the canonical bytes it signs, `prev_pi`
explicitly `null` for the genesis snapshot. The snapshot service stores and
serves these exact bytes; the content hash commits to them verbatim.
