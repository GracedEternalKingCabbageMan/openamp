# dmt-v1: the dense Merkle tree OpenDAMP covenants verify against

Status: implemented and consensus-exercised (Rust: `src/dmt.rs`; Go mirror:
`gomirror/dmt/`; golden vectors: `vectors/addresses.json` under `dmt_v1`).

`dmt-v1` replaces the design document's `smt-v1` / `cmt-v1` placeholder for the
whitelist predicate. The reason is covenant feasibility: a depth-256 sparse
Merkle tree costs 256 hash levels per proof inside the Simplicity program, and
the verifier already scans up to seven outputs. A dense tree of depth 16 costs
16 levels, which is what actually fits the Simplicity budget (see STATUS.md for
the measured numbers).

The tree is **sorted**, which is what makes non-membership provable by
adjacency later without changing the format. Nothing in this version enforces
non-membership on-chain; the ordering is specified now so that adding the
blacklist predicate is a program change, not a format change.

## 1. Parameters

| name    | value  | meaning                                  |
|---------|--------|------------------------------------------|
| `D`     | 16     | tree depth: 16 sibling hashes per proof  |
| `SLOTS` | 65536  | `1 << D`, total leaf slots               |
| capacity| 65534  | `SLOTS - 2`, real keys (two guards)      |

A key is always exactly 32 bytes. For the whitelist it is a BIP340 x-only
public key, serialized as its 32-byte big-endian x coordinate. For a future
blacklist it is `SHA256(txid || BE32(vout))` over the outpoint, with `txid` in
internal (consensus) byte order — the same bytes the `input_prev_outpoint` jet
returns, not the reversed display form.

## 2. Slot assignment

Let `k_1 < k_2 < ... < k_n` be the real keys, sorted **ascending by unsigned
bytewise comparison** of their 32-byte encoding, and deduplicated. Then:

```
slot 0            = GUARD_LO = 00 * 32
slot i (1..=n)    = k_i
slot n+1 .. 65535 = GUARD_HI = ff * 32
```

The guards make the sorted sequence total: every real key has a predecessor and
a successor inside the tree, which is exactly what an adjacency (non-membership)
proof needs. A key equal to `GUARD_LO` or `GUARD_HI` is **rejected** at build
time, as is a duplicate key: both would make slot assignment ambiguous.

## 3. Hashing

All hashes are plain SHA-256 (single, not double) over the byte strings shown.
There is no tagged-hash domain separation — the leading domain byte does that
job, and keeping it a bare SHA-256 is what the `sha_256_ctx_8_*` jets compute
most cheaply.

```
leaf(key)        = SHA256( 0x00 || key )                    (33 bytes hashed)
node(left,right) = SHA256( 0x01 || left || right )          (65 bytes hashed)
```

`node` is **positional**: it does NOT sort its children. (Contrast the taproot
`TapBranch/elements` hash used for the covenant tree itself, which does sort.)
Mixing the two up is the single most likely porting bug, so a mirror
implementation should check the golden vectors in section 6.

## 4. Root

Level 0 is the 65,536 leaf hashes in slot order. Level `j+1` is formed by
hashing adjacent pairs of level `j`:

```
level[j+1][i] = node( level[j][2i], level[j][2i+1] )
```

`root = level[16][0]`.

Because every slot above `n` holds `GUARD_HI`, whole subtrees of the upper range
are identical. An implementation computes them once:

```
pad[0]   = leaf(GUARD_HI)
pad[j+1] = node( pad[j], pad[j] )
```

and treats any level-`j` index beyond the materialized prefix as `pad[j]`. This
makes building O(n) rather than O(65536); both implementations do it and both
produce the same root as the naive dense computation.

## 5. Membership proof

A proof for the key at slot `s` is:

- `siblings[0..15]`: 16 × 32 bytes, **bottom-up** — `siblings[j]` is the sibling
  of the running node at level `j`.
- `index`: `u16`, the slot `s`. Bit `j` of `s` (LSB first) is 1 exactly when the
  running node at level `j` is the **right** child.

Verification:

```
node = leaf(key)
for j in 0..16:
    if (index >> j) & 1 == 1: node = node(siblings[j], node)
    else:                     node = node(node, siblings[j])
accept iff node == root
```

### Covenant witness encoding

The Simplicity program consumes the proof as `[(u256, bool); 16]`, one pair per
level in the same bottom-up order, where the `bool` is "the running node is the
right child at this level" — i.e. bit `j` of `index`. The index is therefore
carried implicitly by the bitmap and is not a separate witness field. The
verifier program folds this array with `wl_step` and compares the result against
the `WL_ROOT` parameter compiled into `P(pi)`.

`(sibling, is_right)` order is fixed by the Rust `Proof::levels()` and the Go
`Proof.Levels()`; both are part of this specification.

## 6. Golden vectors

Pinned in `vectors/addresses.json` (`dmt_v1` object) and asserted by both
implementations' tests:

```
GUARD_LO           = 0000...00  (32 bytes)
GUARD_HI           = ffff...ff  (32 bytes)
leaf(GUARD_LO)     = 7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9
leaf(GUARD_HI)     = 5e16d316ecd5773e50c3b02737d424192b02f25b4245822079181c557aafda7d
root(empty tree)   = e69f2dc2186b1cca0ed37d851b60121a87832be1ff7f61d58bc4931d26c844cf
```

and for the three-key whitelist of `examples/snapshot-seq0.json`
(alice `1b84c556…`, bob `4d4b6cd1…`, carol `462779ad…`):

```
root = dc9d33e167118409fba74538497bf7a984166cd60dc92ee62e4ad5283cf52118
slots: 0 = GUARD_LO
       1 = 1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f  (alice)
       2 = 462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b  (carol)
       3 = 4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766  (bob)
       4.. = GUARD_HI
```

Note the slots: sorting is on the key bytes, so carol precedes bob. A mirror
that sorts on anything else (insertion order, hex string of the display form)
will produce a different root and every proof will fail at consensus.

## 7. Non-membership (specified, not yet enforced)

An adjacency proof for a key `x` absent from the tree is: the two keys `l` and
`r` occupying adjacent slots `s` and `s+1` with `l < x < r`, plus a membership
proof for each. Because the guards bracket the range, such a pair always exists
for any `x` not in the tree. The covenant would check `l < x`, `x < r`,
`slot(r) == slot(s) + 1`, and both membership proofs.

This is **not implemented in the covenant** in this version, and no blacklist
root is committed in pi — see STATUS.md, degradation (a). The format above is
fixed so that enabling it later does not invalidate published snapshots.

## 8. Versioning

The snapshot's `tree` field must read `"dmt-v1"`. A tool that does not recognise
the value must refuse to build a transfer rather than guess: a wrong tree format
produces proofs that fail at consensus, which looks like a chain problem and is
not.
