# OpenDAMP M1/M3: what is consensus-enforced, and what is not

Scope of this crate: milestones **M1** (the real Simplicity covenants, with a
functional proof on `elementsregtest`) and **M3** (offline transfer
construction) of `doc/sequentia/opendamp-design.md` in the Sequentia
repository. M2 (policy service in the operator daemon, `enforcement` election
through issuance, registry validation) is not in scope.

Nothing here is deployed to any live chain.

**The headline: every predicate the design document specifies for the covenant is
enforced by consensus — confinement, the whitelist, the blacklist, the transfer
limit and the height windows. Removing a holder from the whitelist stops that
holder SPENDING; listing an outpoint stops that UTXO alone; a limit caps what
leaves a sender in one transfer; a lockup or receive window binds to a height.
Every one of them is proved against a real node (section 4).**

**And the covenants no longer carry any padding.** A canonical transfer is
**1,582 vB**, the node's own vsize, against roughly 7,459 vB before. Two things
did it: Sequentia now grants four weight units of Simplicity execution per
witness byte instead of one, and P is compiled once per transaction *shape*
rather than once for the widest transfer imaginable. Section 3.

## 0. What the 2026-08-19 review changed

An adversarial review of this crate against the DAMP paper found three defects
and one false claim. All four are fixed here; they are called out because two of
them were silent, and because one of the fixes is not the one the review
proposed.

1. **A guard slot was a provable whitelist member.** `dmt-v1` put `GUARD_LO` and
   `GUARD_HI` in the tree as ordinary `0x00`-domain key leaves with unrestricted
   windows, so `Tree::prove` returned a valid proof for either. The covenant
   could not tell one from an approved key, because a recipient key reaches
   `C_U(Y)` only through `H_TapData(Y)` — a plain hash, which does not require Y
   to be a point on the curve. A holder could pay regulated units to
   `C_U(0xff..ff)`, satisfy confinement, the whitelist and the receive window,
   and destroy them permanently: neither guard is a valid x-only key, so U's
   BIP340 check can never succeed and v1 has no clawback. Guards now hash under
   their own domain byte, `0x03`, at zero cost to the covenant.
2. **A receive window bound the sender's own change.** `recv_after` restricts
   acquisition; applying it to change turned it into a spend prohibition, so a
   holder inside a Reg S window could not transact at all unless a UTXO happened
   to equal the payment exactly. Change is now recognised by script equality
   against the sender's own `C_U` and exempt from the window, the membership
   fold and the explicit-value requirement.
3. **pi was not committed.** The design document said `C_V(pi)` commits to one
   policy *version*; the program took the roots and the limit, so it committed
   to one rule *set*, and a rollback to an earlier snapshot with identical rules
   would have reused the same address. pi is now a compile-time parameter that
   reaches the DAG, for 2,807 milli-weight-units.
4. **The confinement invariant was unstated, and the halt broke it.** See
   section 2 — this is the one where the proposed fix did not survive contact.

## 1. Enforced by consensus (proved on elementsregtest)

Every item below fails at the node — not merely in the builder — when violated.

### U, the user covenant (`programs/user.simf`)

1. **State binding.** The program recomputes its own locking script from the
   witness-supplied owner key: `P2TR(NUMS, TapBranch(TapLeaf_0xbe(own CMR),
   TapData(X)))`, and requires equality with the current input's actual script
   hash. The self-reference is resolved with `jet::tapleaf_hash()`, which
   returns the currently executing leaf's hash — consensus has already checked
   that against the control block, so no CMR constant is embedded.
2. **Custody.** `bip_0340_verify(X, sig_all_hash, sigma)`.
3. **Position and asset.** The current input index is not 0, and the current
   input carries explicit asset A.
4. **Verifier presence.** Input 0 carries explicit asset V in amount exactly q.

U enforces custody, not policy. A frozen holder still satisfies U for their own
coins; it is P(pi) that stops them. What check 4 does *not* establish is in
section 2.

### P(pi), the verifier primary path (`programs/verifier.simf.in`)

1. **Position and identity.** Current input index is 0, carrying explicit V in
   amount exactly q.
2. **Verifier recreation.** Output 0 carries explicit V in amount exactly q and
   its script hash equals the current input's script hash, so C_V(pi) is
   recreated at the same address under the same policy.
3. **The sender, proven once.** A witness-supplied key with one dmt-v1
   membership proof against `WL_ROOT`, and its committed lockup applied through
   `check_lock_height(send_after)`. **This is the freeze.**
4. **Owner scan over the input slots** (`num_inputs <= N_max` asserted). For
   every input carrying A:
   - its asset id must be **explicit** (a blinded input fails — see below);
   - its script must equal `C_U(sender)`, which is what makes "all regulated
     inputs share one owner" structural rather than a separate assertion;
   - the input's outpoint must **not** be in the committed blacklist, proven by
     exhibiting the dmt-v1 interval leaf that strictly contains
     `SHA256(txid || BE32(vout))` — **this is the per-outpoint freeze**;
   - and at least one input must carry A, so only a holder can advance the
     verifier output.
5. **Confinement scan over the output slots** (`num_outputs <= N_max` asserted).
   For every output that exists:
   - the asset id must be **explicit**;
   - an output carrying A must either pay `C_U(sender)`, in which case it is
     **change** and needs no proof, no receive window and no explicit value; or
     pay `C_U(Y)` for a witness-supplied recipient key `Y`, which must carry a
     whitelist membership proof, must have an open receive window
     (`check_lock_height(recv_after)` — the Reg S pattern), and must expose an
     explicit value.
6. **Transfer limit.** The sum of every A output paying an owner *other than the
   sender* must not exceed the committed limit, computed with an overflow check
   so a wrapping sum cannot slip under it.
7. **A is never a fee output.** Enforced by the same script equality as 5: a fee
   output has an empty scriptPubKey, whose hash can never equal a P2TR script's.
   Fee outputs in *other* assets pass, which is what the any-asset fee market
   requires.
8. **pi is committed** (check 0 in the source), so the address distinguishes a
   policy version from a different version with identical rules.

Both bounds are **asserted, not assumed**. Without `num_inputs <= N_max` an
extra regulated input would sit past the scan and spend unchecked; likewise for
outputs. Exceeding either bound makes the transaction unspendable rather than
unchecked — and the builder refuses to construct one, naming the bound
(`tests/builder.rs`), which it previously did for outputs only.

**On blinded inputs.** Scanned inputs must carry explicit asset ids, not only
outputs. The confinement induction already implies no blinded A UTXO can exist,
but relying on that would make the freeze depend on an argument instead of a
check: a coin of A behind an asset commitment would otherwise skip the owner
scan entirely. The cost is that fees must come from an explicit UTXO, which
matches transparent-by-default and is what the builder does anyway.

### G(I), the issuer path (`programs/issuer.simf`)

`bip_0340_verify(I, sig_all_hash, sigma)` — the update path (recreate C_V under
pi') and the halt path (burn V). Compromise of I permits policy revocation or
denial of service, never theft: no path lets the issuer spend a holder's C_U
output.

### Structural properties that follow

- **The policy version is bound into the address.** The roots, the limit and pi
  all enter P through its compile-time arguments, so a different policy is a
  different CMR and therefore a different C_V address. P(pi0) cannot spend
  C_V(pi1) (proof 4c).
- **A proof is bound to what it authorises.** The covenant recomputes C_U(key)
  from the *same* witness key it proves membership for, so a genuine proof
  cannot be reused for a different party — neither to pay someone else (proof
  4b) nor to spend someone else's input (proof 7e).
- **A stale proof is worthless.** A proof valid under the previous policy
  version fails the new root (proofs 7c, 8c).
- **Halt is effective.** Once V is burned nothing can satisfy input 0 (6b, 6c).

### Why a bad proof cannot be submitted at all

This deserves stating precisely, because it is what makes the freeze airtight
rather than merely likely:

1. Consensus rejects a redeem program containing FAIL nodes, so a spend must
   present a **pruned** program.
2. Pruning replays the program against the transaction, so a witness the
   covenant rejects **cannot be pruned** — pruning itself fails. Asserted by
   `bad_witness_cannot_be_pruned` in `tests/regtest.rs` and observed in proofs
   7c and 8c.
3. Therefore the only submittable form of a bad-proof spend still carries its
   FAIL nodes, and the node refuses it outright (proofs 7d, 8d).

Both doors are shut, and the regtest test walks through both.

## 2. NOT enforced

**No covenant predicate from the design document is unenforced.** Sections 3.2
(blacklist), 3.3 (whitelist), 3.4 (transfer limit) and 3.5 (height windows) are
all live, along with the confinement core of 2.1–2.3.

### The invariant no covenant can check

U's check 4 asks that *some* output carrying q of V sits at input zero. It does
not ask that the output is a verifier covenant, and U cannot: C_V(pi) is a
different address for every policy version, while U is fixed for the life of the
asset and committed inside every C_U address. So confinement rests on

> **q units of V must never exist outside a verifier covenant.**

If that is broken, whoever controls the stray output can place it at input zero
and let any holder spend their C_U with no whitelist, no blacklist, no limit and
no window, on their own signature alone.

The review proposed closing this in U, by requiring output zero to recreate
input zero's script unless the issuer signed. **It was implemented and then
removed, because it does not work**: a holder of stray V pays it back to the
same address, which satisfies the equality exactly. Simplicity exposes another
input's script pubkey but not which leaf it executed, so nothing a fixed U can
read distinguishes a real C_V(pi) from an imitation. Keeping the check would
have cost a witness field and a branch in exchange for reassurance it could not
provide.

What closes it is operational, and the tooling now enforces both halves:

- **A halt BURNS V.** `IssuerReq::halt_to_burn` sends it to a bare `OP_RETURN`,
  which can never be an input, so after a halt no q-of-V output exists at all
  and A is frozen — which is what a halt is supposed to mean.
  `halt_leaves_live_verifier_asset()` names the alternative for a caller that
  insists on parking it somewhere spendable.
- **V's reissuance authority is as sensitive as I.** Minting q of V to an
  ordinary address is a complete bypass. Retaining it to run parallel verifier
  outputs means retaining a second key of the same criticality.

### Deliberately outside the covenant

- **Velocity and holder caps** (design doc 3.6). These need global chain state a
  covenant cannot see; the design document puts them with the registrar, and they
  stay there.
- **Confidential values.** The covenant requires explicit asset ids on every
  input and output it scans, and explicit *values* on limited payments. Blinded
  values are permitted on change and on non-A outputs, and are untested here.
- **Redemption.** No redemption branch, as the design document specifies for v1.

And a rule the tooling enforces rather than warns about: the snapshot parser
uses `deny_unknown_fields` throughout, so a predicate this build cannot enforce is
a **hard error**, not an ignored field. An issuer cannot publish a policy that
does not bind. A `limit` of 0 is likewise refused, because it would forbid every
payment and is almost certainly a mistake for "no limit" (which is `null`).

## 3. Budget: measured, not estimated

Simplicity buys execution budget with witness bytes, and on Sequentia one
witness byte buys **four** weight units of execution rather than one
(`SIMPLICITY_BUDGET_PER_WITNESS_BYTE`, `src/script/script.h` in the node),
capped at 4,000,050. The cost side is a **static** bound over the whole program
DAG that does not shrink when a branch goes untaken.

That multiplier is why there is no padding. Under the one-to-one rule the
verifier's functional witness was a few kilobytes against a cost bound of twenty
thousand weight units, so it had to haul 22,528 bytes of inert data that existed
only to be counted — every node storing and relaying it, and the block it
crowded out being the scarce thing. Four is chosen against the block: total
Simplicity cost in a block is bounded by the block's weight times the
multiplier, so a Sequentia block at 400,000 weight units admits at most
1,600,000 weight units of Simplicity work, against the 4,000,000 Liquid already
accepts at a 4,000,000-weight block and a multiplier of one.

### The shape menu

P is compiled once per **shape** — a pair (N_max_inputs, N_max_outputs) — and
every shape is a leaf of the same C_V(pi) taptree. A single program sized for
the widest transfer charges every ordinary transfer for slots it never touches,
because the cost bound is static. Each leaf asserts its own bounds, so a narrow
leaf cannot be used for a wide transaction, and `programs::shape_for` picks the
narrowest leaf that fits.

| leaf | inputs | outputs | static cost | min witness stack | margin |
|---|---|---|---|---|---|
| `p3x5` **canonical** | 3 | 5 |  7,523,320 mWU | 3,739 B | 1.99x |
| `p3x4` | 3 | 4 |  6,413,483 mWU | 3,718 B | 2.33x |
| `p4x6` | 4 | 6 |  9,667,652 mWU | 3,785 B | 1.57x |
| `p5x7` | 5 | 7 | 11,812,618 mWU | 3,834 B | 1.30x |

"Min witness stack" is the smallest witness a legitimate spend can present — the
sender proof, one filled input slot and one filled output slot — which is the
worst case, because anything richer carries more proof bytes and therefore buys
*more* budget against an unchanged static cost. `tests/cost_profile.rs` asserts
every margin, so a widened scan fails there rather than producing an unspendable
leaf.

No shape has fewer than three inputs, and that is forced: a transfer cannot pay
its fee in A, and the verifier input's q of V is returned whole to output zero,
so the fee must come from an ordinary input that is neither. The 1-input shapes
an earlier sizing exercise considered could not have paid a fee at all.

Leaf depths put the canonical shape alone at depth 1, so the leaf a wallet
reaches for most often carries a 65-byte control block and the rest carry 129.

### Measured, for the canonical transfer

| quantity | value |
|---|---|
| P(pi) static cost | 7,411,916 milli-WU = **7,412 WU** |
| P(pi) witness stack | **3,634 B**, none of it padding |
| P(pi) budget bought | 14,586 WU |
| headroom | **7,174 WU**, 49% |
| U witness stack (per user input) | **633 B** |
| finalized transfer | 4,858 B, **1,582 vB** |
| per block, at 89,999 vB of payload | **56** (was 12) |

### Where the cost goes

| component | static cost |
|---|---|
| whole P(pi), canonical shape | 7,523,320 mWU |
| whitelist folds, whole program | 3,981,170 mWU |
| blacklist non-membership, both input slots | 1,855,218 mWU |
| committing pi | 2,807 mWU |

The whitelist folds still dominate, and would dominate more but for hoisting:
because all regulated inputs of a transfer belong to one owner, the sender is
proven **once** and each input slot then only compares its script against
`C_U(sender)`. That removed a 16-level Merkle fold and a taproot reconstruction
from every input slot after the first, and removed the recipient key and proof
from the witness of every change output.

One number worth keeping in view: a whitelist slot's fold costs about 796,000
milli-weight-units while the jets it executes sum to about 58,000. The compiled
program costs roughly **thirteen times** the jets it runs, so the dominant term
is SimplicityHL's structural overhead rather than the cryptography. If a
hand-written program or a later compiler closes even half of that, every number
above improves with it.

## 4. Regtest proof (the acceptance bar)

`tests/regtest.rs`, ignored by default:

```
cargo test --test regtest -- --ignored --nocapture
```

It spawns `/home/aejkohl/Sequentia/src/sequentiad` (override with
`OPENDAMP_NODE_BIN`) on `elementsregtest` with `-evbparams=simplicity:-1:::`,
`-anyonecanspendaremine=1`, `-initialfreecoins=…`,
`-con_default_blinded_addresses=0`, and asserts `getdeploymentinfo` reports
simplicity **active before any 0xbe output is funded** — an unenforced Simplicity
leaf is anyone-can-spend, so funding one on a chain without the rule active would
be a fund-loss bug, not a test failure.

The node must also grant four weight units per witness byte. On a node still
using the Elements one-to-one rule these covenants are unspendable, and
`attach_verifier` says so by name rather than emitting a transaction the node
would reject.

Proofs, from a passing run (a fresh chain each time, so the txids identify a run
rather than being stable):

| proof | result |
|---|---|
| 1. issue A and V, fund C_U(alice) and C_V(pi0) | funded |
| 2. alice → bob, **no third party signature** | confirms; 1,582 vB |
| 3a/3b. an unconfined A output: builder, then **node** | `Jet failed` / `Assertion failed inside jet` |
| 4a/4b. carol unproven, then bob's proof reused to pay carol | builder refuses / **node** refuses |
| 4c. **node** rejects P(pi0) spending C_V(pi1) | `Witness program hash mismatch` |
| 5a/5b. issuer update pi0 → pi1 (adds carol), then alice → carol | both confirm |
| **7a. issuer update REMOVING alice (the freeze)** | confirms |
| 7b–7e. alice cannot spend: no proof, stale proof unprunable, unpruned form refused, bob's identity refused | four distinct refusals |
| 7f–7h. bob still spends; alice restored; alice spends again | the freeze is per holder and reversible |
| **8a–8f. blacklist one outpoint, refuse it four ways, lift it, spend it** | per-outpoint freeze |
| **9a–9d. a transfer limit, refused at limit+1 by builder and node, confirmed at exactly the limit with change that does not count** | limit binds |
| **10a–10f. lockup and receive window: builder, consensus finality, and the covenant's own check, separately** | both halves of the height reduction |
| **11a. issuer update: alice cannot RECEIVE for 1,000 blocks** | confirms |
| **11b. alice spends a quarter of her UTXO and keeps the change anyway** | a receive window does not stop change |
| **11c. paying alice is still refused while her window is shut** | and it still binds a real acquisition |
| 6a/6c. halt: V burned to OP_RETURN, absent from the UTXO set | nothing left to put at input zero |
| 6b. **node** rejects any transfer after the halt | `missing-inputs` |

Proofs 11a–11c are new, and are the regression test for the change/receive-window
defect: before the fix, 11b was impossible.

### On the refusal proofs, precisely

Two distinct techniques, because they prove different things:

- **Splice** (3b, 4b, 7e). A transaction the covenant rejects cannot be pruned,
  and an unpruned program is refused merely for containing FAIL nodes — which
  would prove nothing about the rule. So the verifier's witness is taken from a
  well-formed spend of the *same transaction shape*: P(pi) carries no signature
  and nothing else transaction-dependent, so what consensus runs is a valid,
  FAIL-free P(pi) against the offending transaction. The user input is signed for
  that transaction and passes on its own, so the only check that can fail is the
  one under test — hence `Assertion failed inside jet` rather than something
  incidental, and the test asserts on that string.
- **Stale proof** (7c/7d, 8c/8d). For a freeze there is no valid spend of the
  same shape to splice from, because the whole point is that no valid witness
  exists. So the test walks the two doors instead: pruning fails locally, and the
  unpruned form is refused by the node.

`tests/covenant.rs` proves the same logic on the BitMachine against the exact
`ElementsEnv` consensus uses, with no node. `tests/builder.rs` covers the
refusals the builder owns, and `tests/cost_profile.rs` the budget arithmetic.

## 5. Design decisions worth recording

**U is per-asset.** A, V and q enter U through compile-time Arguments, so each
regulated asset has its own U and CMR. A network-wide U reading A, V and q from
the transaction pattern has no sound construction for q.

**dmt-v1 instead of the design document's smt-v1/cmt-v1.** A depth-256 sparse
Merkle tree costs 256 hash levels per proof. Depth 16 over a sorted dense tree
(65,534 keys) is what fits. Neither reserved alternative is implemented
anywhere any more: `openampd` used to carry an smt-v1 document format whose
validation skipped every consistency check dmt-v1 gets, and it is gone.

**Guards hash under 0x03.** They exist to make the sorted sequence total and for
nothing else, so they are not key leaves. See section 0 for what happened when
they were.

**The blacklist stores intervals, not keys.** Non-membership in a *dense* tree
would otherwise need an adjacency argument over proof indices, and a dense tree
gives no cheap handle on the index. Putting the gap in the leaf makes
non-membership one ordinary membership proof. Full construction, and why a
listed key cannot be proven absent: `SPEC-dmt-v1.md` section 7.

**All regulated inputs of a transfer share one owner.** The transfer limit needs
this twice over: a limit is per sender, and change is identified relative to one.
It is now structural rather than checked — every A input's script must equal
`C_U(sender)` — which is both cheaper and harder to get wrong. The cost is that
two holders cannot co-spend into a single transfer; that is a stated v1
restriction.

**Height windows live in the whitelist leaf, not a tree of their own.** A
separate window tree would have meant a second membership fold per slot for
information that belongs to the same key the first fold already proves. Binding
`send_after` and `recv_after` into the leaf makes them free and makes them
unforgeable.

**Fixed input-zero position** for the verifier, as the design document accepts.

Mirrors: `src/dmt.rs`, `gomirror/dmt/` (stdlib-only Go, tests asserting the same
golden roots), and `openampd/internal/damp/dmt/`. The Go side also mirrors the
verifier taptree, and `TestEveryShapeControlBlockMatchesVectors` checks every
leaf's control block against the Rust vectors.

## 6. What remains

Nothing in the covenant. What is left is integration and operations.

1. **More than three regulated inputs per transfer.** A wider shape is a leaf,
   not a redesign: add it to `SHAPES` and the taptree grows by one leaf. The
   menu stops at `p5x7` because the leaf count has to stay a power of two plus
   the canonical leaf for the depth assignment to be a valid taptree, which is
   asserted rather than assumed.
2. **Confidential values on non-A outputs and on change.** Permitted by the
   covenant, untested; needs a regtest case with a blinded change output.
3. **External signature ingestion in the CLI.** `transfer-build` prints each user
   input's `sig_all_hash` and the library accepts an externally produced BIP340
   signature, but `transfer-finalize` still signs only from a supplied private
   key. A `--sig INDEX:HEX` flag is the missing piece for hardware and FROST
   signers.
4. **Parallel verifier outputs** (design doc section 6). Untouched; the single
   verifier output is a spending race, which a busy asset will hit before it
   hits the 56-per-block size ceiling.
5. **Snapshot signing and publication — DONE, in M2.**
6. **Golden CMR vectors under CI.** `vectors/addresses.json` pins U/G CMRs and
   every shape's CMR, tapleaf, control block and address, plus the dmt-v1
   constants. The Go tests read it, so a CMR that moves without the vectors
   moving fails there; nothing yet fails a *build*.
7. **Tree depth.** D = 16 caps a whitelist at 65,534 holders. D = 12 would save
   about 110 vB per transfer and cap it at 4,094. That trade was worth making
   when the pad existed, because depth drove the pad; without a pad it is a
   small saving against a 16x capacity cut, so D stays 16. It is one constant
   (`dmt::DEPTH`, which the covenant template reads) if an issuer ever wants
   otherwise.
8. **Live testnet pilot** (M4). The anyone-can-spend hazard makes
   `getdeploymentinfo` reporting simplicity active a hard precondition for
   funding any covenant address, on any chain — and so is the node granting four
   weight units per witness byte, which arrived in Sequentia Core 24.3.0.
