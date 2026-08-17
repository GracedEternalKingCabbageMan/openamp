# OpenDAMP M1/M3: what is consensus-enforced, and what is not

Scope of this crate: milestones **M1** (the real Simplicity covenants, with a
functional proof on `elementsregtest`) and **M3** (offline transfer
construction) of `doc/sequentia/opendamp-design.md` in the Sequentia
repository. M2 (policy service in the operator daemon, `enforcement` election
through issuance, registry validation) is not in scope and is not started here.

Nothing here is deployed to any live chain. Nothing here is committed to git.

**The headline: the DAMP core plus the whitelist predicate are enforced by
consensus and proved against a real node. The blacklist, the transfer limit and
the height windows are NOT enforced. They are degradation (a) below, and a
snapshot carrying them must not be described to an issuer as binding.**

## 1. Enforced by consensus (proved on elementsregtest)

Every item below fails at the node — not merely in the builder — when violated.
Section 4 gives the transaction ids.

### U, the user covenant (`programs/user.simf`)

1. **State binding.** The program recomputes its own locking script from the
   witness-supplied owner key: `P2TR(NUMS, TapBranch(TapLeaf_0xbe(own CMR),
   TapData(X)))`, and requires equality with the current input's actual script
   hash. The self-reference is resolved with `jet::tapleaf_hash()`, which
   returns the currently executing leaf's hash — consensus has already checked
   that against the control block, so no CMR constant is embedded. A witness
   cannot substitute a different key: substituting one changes the recomputed
   script and the check fails.
2. **Custody.** `bip_0340_verify(X, sig_all_hash, sigma)`.
3. **Position and asset.** The current input index is not 0, and the current
   input carries explicit asset A.
4. **Verifier presence.** Input 0 carries explicit asset V in amount exactly q.

### P(pi), the verifier primary path (`programs/verifier.simf`)

1. **Position and identity.** Current input index is 0, carrying explicit V in
   amount exactly q.
2. **Verifier recreation.** Output 0 carries explicit V in amount exactly q and
   its script hash equals the current input's script hash — so C_V(pi) is
   recreated at the same address, under the same policy.
3. **A holder authorised this.** At least one of inputs 1..7 carries explicit
   asset A. By the confinement induction that input is a C_U, which
   independently required its owner's signature.
4. **Bounded scan.** `num_outputs <= 8` (N_max = 8), and outputs 1..7 are each
   checked:
   - the asset id must be **explicit** (a confidential asset id fails);
   - an output carrying A must pay `P2TR(NUMS, TapBranch(TapLeaf_0xbe(U_cmr),
     TapData(Y)))` for the witness-supplied recipient key Y, rebuilt with the
     taproot-construction jets;
   - that same Y must carry a dmt-v1 membership proof verifying against the
     whitelist root committed in P's arguments.
5. **A is never a fee output.** Enforced by the same script equality as 4: a fee
   output has an empty scriptPubKey, whose hash can never equal a P2TR script's
   hash. This makes Rule 1 of the OpenAMP design consensus-enforced for
   OpenDAMP assets. Fee outputs in *other* assets pass, which is what the
   any-asset fee market requires.

### G(I), the issuer path (`programs/issuer.simf`)

`bip_0340_verify(I, sig_all_hash, sigma)`. This is the update path (recreate
C_V under pi') and the halt path (send V anywhere else). Compromise of I permits
policy revocation or denial of service, never theft: no path lets the issuer
spend a holder's C_U output.

### Structural properties that follow

- **The policy version is bound into the address.** pi enters P through its
  compile-time arguments, so a different whitelist root is a different CMR and
  therefore a different C_V address. P(pi1) cannot spend C_V(pi0): the node
  rejects it with a witness-program mismatch (proof 4c).
- **A membership proof is bound to the output it authorises.** The covenant
  recomputes C_U(Y) from the *same* witness key it proves membership for, so a
  genuine proof for a whitelisted holder cannot be reused to pay someone else
  (proof 4b).
- **Halt is effective.** Once V leaves C_V there is no output that can satisfy
  input 0, so no transfer can be built at all (proof 6b).

## 2. NOT enforced — degradations, in the documented order

### (a) In-covenant blacklist: DROPPED

The design document's freeze mechanism (section 3.2: a non-membership proof per
regulated input against a committed blacklist root) is **not implemented in the
covenant**. Consequences, stated plainly:

- A court-order freeze of a specific outpoint is **not** enforced by the chain
  in this build. The issuer's tools for it are the ones that were always
  available: publish a policy update that removes the holder from the whitelist
  (which stops them *receiving*, not spending), or halt the verifier output
  (which stops all transfers of the asset).
- Removing a key from the whitelist does not freeze the coins that key already
  holds. Nothing in P checks the *owner* of an input, only the *recipient* of an
  output. A de-whitelisted holder can still spend to a whitelisted recipient.
  This is a real gap, not a subtlety: whitelisting here is
  receive-side only.
- `pi` commits the empty hash for the blacklist slot rather than a root, and the
  CLI does so deliberately (`pi_of` in `src/bin/opendamp.rs`). Committing a root
  that no program reads would advertise enforcement that does not exist.

The adjacency (non-membership) construction is specified in SPEC-dmt-v1.md
section 7 and **implemented in the Go mirror** (`Tree.Adjacent`), so the policy
server can serve the proofs before the covenant verifies them. Adding it to P is
a program change, and the measured cost is affordable: two membership folds per
regulated input (2 x 772 = 1,544 WU static) against the 1,122 WU that the two
proofs' own witness bytes buy back, so roughly 420 WU net per input. Against
3,666 WU of headroom that is several inputs. The reason it is not here is
implementation time, not budget.

### (b) In-covenant whitelist: KEPT

Not degraded. It is enforced as described in section 1.

### Also not implemented (design doc sections 3.4, 3.5, 3.6)

- **Transfer limit** (3.4). The snapshot may carry `limit` and it enters pi's
  `rules_root`, but no program reads it. Not enforced.
- **Height windows** (3.5). Not implemented at all.
- **Velocity, holder caps** (3.6). Off-chain by design; unchanged.
- **Confidential values.** The covenant requires explicit *asset ids* on every
  output it scans, and this build's transaction builder produces explicit
  *values* too. Confidential values on non-A outputs are permitted by the
  covenant but untested here.
- **Redemption.** No redemption branch, as the design document specifies for v1.

## 3. Budget: measured, not estimated

Simplicity buys execution budget with witness bytes — budget = serialized
witness-stack size + 50 weight units, capped at 4,000,050 — while the cost side
is a **static** bound over the whole program DAG that does not shrink when a
branch goes untaken.

Measured for a two-A-output transfer (payment + change), N_max = 8, D = 16:

| quantity | value |
|---|---|
| P(pi) static cost | 11,070,880 milli-WU = **11,071 WU** |
| P(pi) witness stack | **14,687 B** (12,288 B of it pad) |
| P(pi) budget bought | **14,737 WU** |
| headroom | **3,666 WU (33%)** |
| U witness stack (per user input) | **633 B** |
| U static cost | 228,208 milli-WU = 229 WU, against 683 WU bought |
| finalized transfer size | ~15.9 kB |

Consensus cap 4,000,050 WU is not remotely approached; the binding constraint is
the witness bytes the padding costs in fees and block space. Standard-transaction
limits are satisfied: the 80-byte stack-item limit applies only to tapscript
(leaf version 0xc0), not to Simplicity leaves (0xbe).

The 33% headroom above is the **worst** case, measured with only two of the seven
output slots carrying proofs. Cost is static, so filling more slots leaves it
unchanged while each additional proof adds 561 witness bytes and therefore 561 WU
of budget: a seven-A-output transfer has *more* headroom than a two-output one,
not less.

Cost per check, measured by `tests/cost_profile.rs` (which asserts these bands so
that a change breaking the arithmetic fails a test rather than a node):

| component | static cost |
|---|---|
| whole P(pi) | 11,070,880 milli-WU |
| one output slot (asset check + C_U(Y) recomputation + membership fold) | 1,012,306 milli-WU = **1,012 WU** |
| ...of which the dmt-v1 membership fold, D=16 | 772,296 milli-WU = 772 WU |
| ...of which the C_U(Y) taproot recomputation | 149,621 milli-WU = 150 WU |

A used slot's own witness (33-byte key + 16 × 33-byte proof levels = 561 B) buys
561 WU back, so **a check of this shape costs about 450 WU net**.

### Why there is a pad at all, and why it is shaped this way

Three things were tried; only the third works, and the reasoning is worth
recording because it is not obvious:

1. **Taproot annex padding** — what `rust-simplicity`'s `Cost::get_padding`
   produces — is unusable on this network. `IsWitnessStandard` in
   `src/policy/policy.cpp` rejects any taproot spend carrying an annex, so such
   a transaction would not relay.
2. **A bounded list (`List<u8, N>`) inside the Simplicity witness** is
   cost-neutral: the type's own static cost grows about as fast per byte of bound
   as the budget that byte buys, so the deficit never closes. Measured: at bound
   8192 the deficit was 9,714 B; at bound 32768 it was 33,999 B.
3. **A fixed-size array, read on every execution.** `[u256; 384]` costs about
   306 milli-WU per byte and buys 1,000, a 3.3x margin. It must be *read*: an
   unused witness is dropped by pruning, and pruning is mandatory because
   consensus rejects a redeem program containing FAIL nodes (the node says
   "Program has FAIL node"). `absorb` therefore touches every word with
   `eq_256(x, x)` — always true, no semantics. The size is fixed at compile time
   and is part of the CMR, which is what the template registry pins.

`BUDGET_PAD_WORDS` in `src/programs.rs` must stay equal to both the array length
and the `array_fold` bound in `programs/verifier.simf`. `attach_verifier`
re-checks the budget on every build and fails loudly rather than producing a
transaction the node would reject.

## 4. Regtest proof (the acceptance bar)

`tests/regtest.rs`, ignored by default:

```
cargo test --test regtest -- --ignored --nocapture
```

It spawns `/home/aejkohl/Sequentia/src/sequentiad` (override with
`OPENDAMP_NODE_BIN`) on `elementsregtest` with `-evbparams=simplicity:-1:::`,
`-anyonecanspendaremine=1`, `-initialfreecoins=…`, `-con_default_blinded_addresses=0`,
and asserts `getdeploymentinfo` reports simplicity **active before any 0xbe
output is funded** — an unenforced Simplicity leaf is anyone-can-spend, so
funding one on a chain without the rule active would be a fund-loss bug, not a
test failure.

Transaction ids from the run of 2026-08-17 (fresh chain each run, so these are
illustrative of a passing run, not stable identifiers):

| proof | result |
|---|---|
| 1. issue A and V, fund C_U(alice) and C_V(pi0) | A `daa8284c…`, V `56b97cd9…` |
| 2. alice → bob transfer, **no third party signature** | confirmed `ebc9cf8bdb3c9244ec68dbb15f7965d4e4a729f9fd620d83fb90863eb998bce5` |
| 3a. builder/BitMachine refuses an unconfined A output | `Jet failed during execution` |
| 3b. **node** rejects the unconfined A output | `mempool-script-verify-flag-failed (Assertion failed inside jet)` |
| 4a. builder refuses carol (no proof exists under pi0) | `recipient key 462779ad… is not in the whitelist` |
| 4b. **node** rejects bob's genuine proof reused to pay carol | `mempool-script-verify-flag-failed (Assertion failed inside jet)` |
| 4c. **node** rejects P(pi1) spending C_V(pi0) | `mempool-script-verify-flag-failed (Witness program hash mismatch)` |
| 5a. issuer update pi0 → pi1 via G(I), adding carol | confirmed `c7a03b9d6cf3d2c1f274bdf7a46a88bc924164d61ab309a2ad24a420eeed38c5` |
| 5b. alice → carol under pi1 | confirmed `fc14e41520202ff4d595f9e7e3046aaac235aa54f6c9e2c12be2ec8497d733c5` |
| 6a. halt: V to a plain address via G(I) | confirmed `baff8fca926c03cd43aa7b5041fd6ab0e1bc5e8ad660a65998b196c4d1831f91` |
| 6b. **node** rejects a post-halt transfer | `mempool-script-verify-flag-failed (Witness program hash mismatch)` |

### On the refusal proofs, precisely

A transaction the covenant rejects cannot be pruned (pruning needs a successful
run) and an unpruned program is refused merely for containing FAIL nodes — which
would prove nothing about the rule. So proofs 3b and 4b splice the verifier's
witness from a well-formed spend of the *same transaction shape*: P(pi) carries
no signature and nothing else transaction-dependent, so what consensus then runs
is a valid, FAIL-free P(pi) against the offending transaction. The user input is
signed for that transaction and passes on its own (U enforces custody, not
policy), so the only check that can fail is the verifier's output scan. That is
why the node's answer is `Assertion failed inside jet` and not something
incidental, and the test asserts on that string rather than on "rejected".

`tests/covenant.rs` (7 tests, run by default, no node needed) proves the same
logic on the BitMachine against the exact `ElementsEnv` consensus uses, plus a
wrong-signing-key refusal and the fee-in-A builder refusal.

## 5. Design decisions worth recording

**U is per-asset.** A, V and q enter U through compile-time Arguments, so each
regulated asset has its own U and its own CMR in the registry. The alternative —
one network-wide U reading A, V and q from the transaction pattern — has no
sound construction for q (nothing in the transaction states what the correct
verifier amount is), and per-asset U keeps the program smaller. The cost is one
registry entry per asset, which the registry needs anyway for P.

**dmt-v1 instead of the design document's smt-v1/cmt-v1.** A depth-256 sparse
Merkle tree costs 256 hash levels per proof; the verifier needs up to 7 proofs.
Depth 16 over a sorted dense tree (65,534 keys) is what fits. The tree is sorted
specifically so that non-membership becomes an adjacency proof later without a
format change. Byte encodings: `SPEC-dmt-v1.md`. Mirrors: `src/dmt.rs`,
`gomirror/dmt/` (stdlib-only Go, with tests asserting the same golden roots).

**Fixed input-zero position** for the verifier, as the design document accepts
for v1.

## 6. What remains

Ordered by what blocks what.

1. **Owner-side enforcement.** P checks output recipients only. Enforcing
   whitelist membership (or blacklist non-membership) on *inputs* is what makes
   a freeze bind. This is the most important gap and it is where the blacklist
   work should start: proving something about input 1..7's owner requires the
   owner key in the witness and a script recomputation per input, at roughly the
   same cost as the existing per-output check.
2. **Budget room for (1).** Measured: a check of the same shape as the existing
   per-output one costs ~1,012 WU static and buys ~561 WU back through its own
   proof bytes, so ~450 WU net. Against 3,666 WU of headroom that is roughly
   eight such checks — enough for a per-input owner check across all seven
   regulated input slots, though with little margin left for the transfer limit
   on top. If more room is needed, cheapest first: narrow D from 16 to 12
   (4,094 keys, saves ~193 WU per fold), reduce N_max from 8 to 4 (halves the
   output scan), or accept a larger pad and a bigger transaction.
3. **Transfer limit and height windows** (design doc 3.4, 3.5). Both are
   straightforward next to (1): the limit needs explicit values and a bounded
   sum; the windows need `lock_time` comparison plus a class-keyed list.
4. **Confidential values on non-A outputs.** Permitted by the covenant,
   untested. Needs a regtest case with a blinded change output.
5. **External signature ingestion in the CLI.** `transfer-build` already prints
   each user input's `sig_all_hash`, and the library accepts an externally
   produced BIP340 signature (`programs::user_witness` +
   `txbuild::attach_simplicity`), but `transfer-finalize` currently signs only
   from a supplied private key. A `--sig INDEX:HEX` flag is the missing piece
   for hardware and FROST signers.
6. **Parallel verifier outputs** (design doc section 6). Untouched. The single
   verifier output is a spending race, which on a busy asset is the first thing
   holders will hit.
7. **Snapshot signing and publication.** `issuer_sig` over the canonical
   snapshot is specified in the design document and not implemented here; it
   belongs with M2's policy service.
8. **Golden CMR vectors under CI.** `vectors/addresses.json` is generated by
   `opendamp vectors` and pins U/P/G CMRs, tapleaf and TapData hashes, output
   keys, script pubkeys, control blocks and both chains' addresses. Nothing yet
   fails a build when a CMR moves; it should.
9. **Live testnet pilot** (M4). Not started. The anyone-can-spend hazard makes
   `getdeploymentinfo` reporting simplicity active a hard precondition for
   funding any covenant address, on any chain.
