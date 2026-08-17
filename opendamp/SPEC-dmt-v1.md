# dmt-v1: the dense Merkle tree OpenDAMP covenants verify against

Status: implemented and consensus-exercised, both predicates (Rust:
`src/dmt.rs`; Go mirror: `gomirror/dmt/`; golden vectors:
`vectors/addresses.json` under `dmt_v1`).

`dmt-v1` replaces the design document's `smt-v1` / `cmt-v1` placeholder for both
the whitelist and the blacklist predicates. The reason is covenant feasibility: a depth-256 sparse
Merkle tree costs 256 hash levels per proof inside the Simplicity program, and
the verifier already scans up to seven outputs. A dense tree of depth 16 costs
16 levels, which is what actually fits the Simplicity budget (see STATUS.md for
the measured numbers).

The tree is **sorted**, which is what makes non-membership provable. Two leaf
domains share the same node hashing and depth:

- **key leaves** (`0x00`), used by the whitelist, prove membership of a key AND
  the two height windows committed for it (section 9);
- **interval leaves** (`0x02`), used by the blacklist, prove *non*-membership of
  a key by exhibiting the gap that contains it (section 7).

Both predicates are enforced in-covenant.

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

A whitelist **entry** is a triple `(key, send_after, recv_after)` — the approved
key and its two height windows, both `u32` heights with 0 meaning unrestricted.
Slot order is by **key only**; the windows ride along in the leaf.

Let `k_1 < k_2 < ... < k_n` be the entries' keys, sorted **ascending by unsigned
bytewise comparison** of their 32-byte encoding, and deduplicated. Then:

```
slot 0            = GUARD_LO = 00 * 32,  windows (0, 0)
slot i (1..=n)    = entry with key k_i
slot n+1 .. 65535 = GUARD_HI = ff * 32,  windows (0, 0)
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
leaf(entry)       = SHA256( 0x00 || key
                            || BE32(send_after) || BE32(recv_after) )  (41 bytes)
node(left,right)  = SHA256( 0x01 || left || right )                    (65 bytes)
interval(lo,hi)   = SHA256( 0x02 || lo || hi )                         (65 bytes)
```

A whitelist leaf commits the key **and** its windows. Hashing the key alone
produces a different root and every proof fails at consensus; this is the most
likely porting mistake after the positional `node`.

The domain byte is what keeps the two leaf kinds apart: a whitelist membership
proof can never be replayed as a blacklist non-membership proof, or the other
way round, even if the two roots were somehow equal. Both implementations assert
this.

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

- the **entry** proven, `(key, send_after, recv_after)`, because the verifier
  rebuilds the leaf from it and reads the windows out of it;
- `siblings[0..15]`: 16 × 32 bytes, **bottom-up** — `siblings[j]` is the sibling
  of the running node at level `j`;
- `index`: `u16`, the slot `s`. Bit `j` of `s` (LSB first) is 1 exactly when the
  running node at level `j` is the **right** child.

Verification:

```
node = leaf(entry)      // and the entry's key must equal the key being proven
for j in 0..16:
    if (index >> j) & 1 == 1: node = node(siblings[j], node)
    else:                     node = node(node, siblings[j])
accept iff node == root
```

### Covenant witness encoding

The Simplicity program consumes a whitelist slot as
`(Pubkey, u32, u32, [(u256, bool); 16])` — the key, `send_after`, `recv_after`,
then the path as one pair per level in bottom-up order, where the `bool` is "the running node is the
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
GUARD_LO           = 0000...00  (32 bytes), windows (0, 0)
GUARD_HI           = ffff...ff  (32 bytes), windows (0, 0)
leaf(GUARD_LO)     = 9e1736c43d19118e6ce4302118af337109491ecc52757dfb949bad6a7940b0c2
leaf(GUARD_HI)     = dc8c3b446f21ee93e5ea4d016c916e8ffd952e3f594462fe0f2a0befe3580c59
root(empty tree)   = b883626f07bded09c45c76719b43e85945c0ac41ee370d47932f269dd6eabfed
```

and for the three-key whitelist of `examples/snapshot-seq0.json`
(alice `1b84c556…`, bob `4d4b6cd1…`, carol `462779ad…`):

(all three unrestricted, windows `(0, 0)`):

```
root = 66327e6c8cf6cfff8e1c0661e2469d4aa5ae5aa65206003f6758ff1180619a50
slots: 0 = GUARD_LO
       1 = 1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f  (alice)
       2 = 462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b  (carol)
       3 = 4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766  (bob)
       4.. = GUARD_HI
```

Note the slots: sorting is on the key bytes, so carol precedes bob. A mirror
that sorts on anything else (insertion order, hex string of the display form)
will produce a different root and every proof will fail at consensus.

## 7. The blacklist tree: non-membership by interval

The blacklist is a second dmt-v1 tree, at the same depth, whose leaves are the
**gaps between** listed keys rather than the keys themselves. Listing
`k_1 < ... < k_n` (sorted, unique, neither guard) produces exactly `n+1` interval
leaves, in this slot order:

```
slot 0        = interval(GUARD_LO, k_1)
slot i        = interval(k_i, k_{i+1})        for 1 <= i <= n-1
slot n        = interval(k_n, GUARD_HI)
slot n+1 ..   = interval(GUARD_HI, GUARD_HI)  (padding)
```

An empty blacklist is the single leaf `interval(GUARD_LO, GUARD_HI)`.

**Non-membership proof** of a key `k`: the covering interval `(lo, hi)` plus a
16-level membership proof of its leaf, encoded exactly as in section 5.
Verification is

```
require lo < k              (strict, unsigned bytewise)
require k  < hi             (strict)
fold the 16 levels starting from interval(lo, hi) and require the root
```

**Why this and not an adjacency proof over slot indices.** The obvious
construction — prove two membership leaves and show their slots are consecutive
— needs the proof *index* reconstructed and incremented inside the covenant. A
dense tree gives no cheap handle on that (the index lives only as a 16-bit
direction bitmap, and SimplicityHL's folds do not expose the loop counter), and
it costs two folds instead of one. Carrying adjacency inside the leaf makes
non-membership a single ordinary membership proof: measured at 928 WU per
regulated input against roughly double for the alternative.

**Why a listed key cannot be proven absent.** A listed key is an interval
*endpoint*, and both comparisons are strict. The interval below `k_i` ends at
`k_i` (so `k < hi` fails) and the one above starts at `k_i` (so `lo < k` fails).
No other leaf contains it, and forging one is a Merkle forgery. That is the
freeze.

**Why the padding is inert.** `interval(GUARD_HI, GUARD_HI)` really is in the
tree and really has a valid path, but `GUARD_HI < k < GUARD_HI` is unsatisfiable,
so it authorises nothing.

### The outpoint policy key

```
k_out = SHA256( txid || BE32(vout) )
```

`txid` is in **internal (consensus) byte order** — the bytes the
`input_prev_outpoint` jet yields — not the reversed order txids are displayed
in. `BE32` is the 4-byte big-endian index, which is what `sha_256_ctx_8_add_4`
writes. Getting either wrong produces proofs that verify off-chain and fail at
consensus.

Golden vectors, agreed by the Rust implementation, the Go mirror and an
independent Python recomputation:

```
interval(GUARD_LO, GUARD_HI) = 1fd8164b6e61192e120f01ca504c786a6e193abe0265104c1303a9b1e09afc39
interval(GUARD_HI, GUARD_HI) = 507647244d0d51f754f23c5f23c4f9e6a84eeabd0524bd20fe2d932f539be8d4
root(empty blacklist)        = 009a25ef01f6cade2d114b8315aab47bf5599e3a1386c2f1d414f0e8d6dbf301
```

## 8. Height windows

Each whitelist entry carries two heights, both committed in its leaf:

| field | binds | meaning |
|---|---|---|
| `send_after` | the **owner of a regulated input** | a lockup: the holder cannot spend until this height |
| `recv_after` | the **owner of a regulated output** | a receive window (the Reg S pattern): the holder cannot be paid until this height |

Zero means unrestricted, and costs nothing to enforce.

**How a covenant proves a height.** It cannot read the chain height. Instead the
verifier calls `check_lock_height(bound)`, which succeeds exactly when
`bound <= lockHeight(tx)`, where

```
lockHeight(tx) = (tx is NOT final  &&  tx.nLockTime < 500000000) ? tx.nLockTime : 0
```

and "final" means every input sequence is `0xffffffff`. So the covenant forces
the spender to *claim* a height through `nLockTime`, and consensus's own locktime
rule refuses to mine a transaction whose claim has not yet come true. Both halves
are necessary, and the regtest test proves them separately (STATUS.md §4, proofs
10c and 10e). Note the two consequences:

- A **final** transaction has `lockHeight = 0`, so it can satisfy no nonzero
  bound. A spender cannot dodge the window by ignoring `nLockTime`; this is why
  the builder sets every sequence to `0xfffffffe`.
- A **timestamp** locktime (>= 500,000,000) also yields `lockHeight = 0`. The
  windows are heights only, and the builder rejects a timestamp outright.

Because the bounds live in the leaf, one membership fold proves both that a key
is approved and which windows bind it. A holder cannot present a shorter lockup
than the issuer committed to: changing either bound changes the leaf, so the path
no longer reaches the root. Both implementations assert exactly that.

## 9. Versioning

The snapshot's `tree` field must read `"dmt-v1"`. A tool that does not recognise
the value must refuse to build a transfer rather than guess: a wrong tree format
produces proofs that fail at consensus, which looks like a chain problem and is
not.

The same principle governs the snapshot as a whole: the CLI parses it with
`deny_unknown_fields`, so a predicate this build cannot enforce is a hard error
rather than a silently ignored field. An issuer must not be able to publish a
rule that does not bind.
