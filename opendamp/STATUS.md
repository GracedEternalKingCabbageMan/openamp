# OpenDAMP M1/M3: what is consensus-enforced, and what is not

Scope of this crate: milestones **M1** (the real Simplicity covenants, with a
functional proof on `elementsregtest`) and **M3** (offline transfer
construction) of `doc/sequentia/opendamp-design.md` in the Sequentia
repository. M2 (policy service in the operator daemon, `enforcement` election
through issuance, registry validation) is not in scope.

Nothing here is deployed to any live chain.

**The headline: every predicate the design document specifies for the covenant is
now enforced by consensus — confinement, the whitelist, the blacklist, the
transfer limit and the height windows. Removing a holder from the whitelist stops
that holder SPENDING; listing an outpoint stops that UTXO alone; a limit caps what
leaves a sender in one transfer; a lockup or receive window binds to a height.
Every one of them is proved against a real node (section 4).**

Section 2 is empty of unenforced covenant predicates. What remains off-chain is
what the design document itself puts off-chain (velocity, holder caps), plus the
non-covenant work listed in section 6.

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
coins; it is P(pi) that stops them.

### P(pi), the verifier primary path (`programs/verifier.simf`)

1. **Position and identity.** Current input index is 0, carrying explicit V in
   amount exactly q.
2. **Verifier recreation.** Output 0 carries explicit V in amount exactly q and
   its script hash equals the current input's script hash, so C_V(pi) is
   recreated at the same address under the same policy.
3. **Owner scan over inputs 1..3** (`num_inputs <= 4` asserted; see section 3
   for why 4). For every input carrying A:
   - its asset id must be **explicit** (a blinded input fails — see below);
   - its script must equal `C_U(X_i)` for the witness-supplied owner key `X_i`,
     which binds `X_i` to that input;
   - `X_i` must be a member of the committed whitelist — **this is the freeze**;
   - `X_i`'s **lockup** must have expired (`check_lock_height(send_after)`);
   - every regulated input must have the **same** owner (section 5);
   - the input's outpoint must **not** be in the committed blacklist, proven by
     exhibiting the dmt-v1 interval leaf that strictly contains
     `SHA256(txid || BE32(vout))` — **this is the per-outpoint freeze**;
   - and at least one input must carry A, so only a holder can advance the
     verifier output.
4. **Confinement scan over outputs 1..5** (`num_outputs <= 6` asserted). For
   every output that exists:
   - the asset id must be **explicit**;
   - an output carrying A must pay `C_U(Y)` for the witness-supplied recipient
     key `Y`, rebuilt with the taproot-construction jets;
   - that `Y` must carry a whitelist membership proof;
   - `Y`'s **receive window** must have opened (`check_lock_height(recv_after)`)
     — the Reg S pattern.
5. **Transfer limit.** The sum of every A output paying an owner *other than the
   sender* must not exceed the committed limit, computed with an overflow check
   so a wrapping sum cannot slip under it. Change — an output paying the sender
   back — does not count and may keep a blinded value; a payment to anyone else
   must expose an explicit value, or the limit could be evaded behind a value
   commitment. Change is identified by **recipient key equal to the sender's**,
   never by output position, which the spender chooses.
6. **A is never a fee output.** Enforced by the same script equality as 4: a fee
   output has an empty scriptPubKey, whose hash can never equal a P2TR script's.
   Fee outputs in *other* assets pass, which is what the any-asset fee market
   requires.

Both bounds are **asserted, not assumed**. Without `num_inputs <= 4` an extra
regulated input would sit past the scan and spend unchecked; likewise for
outputs. Exceeding either bound makes the transaction unspendable rather than
unchecked.

**On blinded inputs.** Scanned inputs must carry explicit asset ids, not only
outputs. The confinement induction already implies no blinded A UTXO can exist,
but relying on that would make the freeze depend on an argument instead of a
check: a coin of A behind an asset commitment would otherwise skip the owner
scan entirely. The cost is that fees must come from an explicit UTXO, which
matches transparent-by-default and is what the builder does anyway.

### G(I), the issuer path (`programs/issuer.simf`)

`bip_0340_verify(I, sig_all_hash, sigma)` — the update path (recreate C_V under
pi') and the halt path (send V anywhere else). Compromise of I permits policy
revocation or denial of service, never theft: no path lets the issuer spend a
holder's C_U output.

### Structural properties that follow

- **The policy version is bound into the address.** Both roots enter P through
  its compile-time arguments, so a different whitelist *or* blacklist root is a
  different CMR and therefore a different C_V address. P(pi0) cannot spend
  C_V(pi1) (proof 4c).
- **A proof is bound to what it authorises.** The covenant recomputes C_U(key)
  from the *same* witness key it proves membership for, so a genuine proof
  cannot be reused for a different party — neither to pay someone else (proof
  4b) nor to spend someone else's input (proof 7e).
- **A stale proof is worthless.** A proof valid under the previous policy
  version fails the new root (proofs 7c, 8c).
- **Halt is effective.** Once V leaves C_V nothing can satisfy input 0 (6b).

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

What is deliberately outside the covenant:

- **Velocity and holder caps** (design doc 3.6). These need global chain state a
  covenant cannot see; the design document puts them with the registrar, and they
  stay there.
- **Confidential values.** The covenant requires explicit asset ids on every
  input and output it scans, and explicit *values* on limited payments. Blinded
  values are permitted on change and on non-A outputs, and are untested here.
- **Redemption.** No redemption branch, as the design document specifies for v1.

And a rule the tooling now enforces rather than warns about: the snapshot parser
uses `deny_unknown_fields` throughout, so a predicate this build cannot enforce is
a **hard error**, not an ignored field. An issuer cannot publish a policy that
does not bind. A `limit` of 0 is likewise refused, because it would forbid every
payment and is almost certainly a mistake for "no limit" (which is `null`).

## 3. Budget: measured, not estimated

Simplicity buys execution budget with witness bytes — budget = serialized
witness-stack size + 50 weight units, capped at 4,000,050 — while the cost side
is a **static** bound over the whole program DAG that does not shrink when a
branch goes untaken.

Measured for a transfer with one regulated input and two A outputs (payment plus
change), at `N_max_inputs = 4`, `N_max_outputs = 6`, `D = 16`:

| quantity | value |
|---|---|
| P(pi) static cost | 21,831,549 milli-WU = **21,832 WU** |
| P(pi) witness stack | **26,830 B** (22,528 B of it pad) |
| P(pi) budget bought | **26,880 WU** |
| headroom | **5,048 WU**, a 23% margin over cost |
| U witness stack (per user input) | **633 B** |
| U static cost | 228,208 milli-WU = 229 WU, against 683 WU bought |
| finalized transfer size | ~28 kB |

The consensus cap of 4,000,050 WU is nowhere near; the binding constraint is what
the padding costs in fees and block space. Standard-transaction limits are
satisfied — the 80-byte stack-item limit applies only to tapscript (leaf version
0xc0), not to Simplicity leaves (0xbe).

That margin is the **worst** case, measured with only one of three input
slots and two of five output slots carrying proofs. Cost is static, so filling
more slots leaves it unchanged while each additional proof adds witness bytes and
therefore budget: a fuller transfer has *more* headroom, not less.

Cost per check, from `tests/cost_profile.rs` (which asserts these bands, so
arithmetic that stops holding fails a test rather than a node):

| component | static cost |
|---|---|
| whole P(pi), unpruned | 21,998,655 milli-WU |
| one OUTPUT slot (asset + amount + C_U(Y) + whitelist fold + window) | 1,441,203 = **1,441 WU** |
| one INPUT slot (asset + C_U(X) + whitelist fold + window + blacklist) | 2,423,316 = **2,423 WU** |
| ...of which blacklist non-membership | 928,521 = 929 WU |
| ...of which the two 256-bit comparisons | 93,658 = 94 WU |
| a dmt-v1 membership fold, D = 16 | 796,234 = 796 WU |
| the transfer limit, marginal (single sender + change detection + sum + bound) | 73,756 = **74 WU** |
| the height windows, marginal (lock jets + two words per leaf) | 184,312 = **184 WU** |

A used output slot's witness is 569 B and a used input slot's is 1,161 B, each
buying an equal number of WU back, so an output check costs ~872 WU net and an
input check ~1,262 WU net.

### The last two predicates were cheap; landing them was not

The limit and the windows cost **258 WU between them** — the windows because the
bounds ride inside the whitelist leaf that was already being folded, so they add
no Merkle work at all, and the limit because it is arithmetic rather than hashing.

Landing them nonetheless raised P(pi) by 2,567 WU at equal pad (16,268 → 18,835
WU before the pad was grown). The difference is restructuring, not enforcement:
`check_output` now reads `output_amount` rather than only `output_asset`, returns
a `u64`, and every whitelist slot's witness grew from a 2-tuple to a 4-tuple. Both
figures are quoted because only one of them answers "what does this rule cost",
and the other answers "what did this change cost".

### Why N_max_inputs = 4 and N_max_outputs = 6

Both were 8 before the owner scan existed. Adding seven input slots would have
cost ~7,100 WU of static budget, which the pad can buy but only by growing the
transaction to roughly 27 kB. Right-sizing the bounds to what a transfer actually
needs was the better trade, and it kept the transaction near its previous size
while adding both new checks:

- **6 outputs**: verifier recreation, up to two payments, sender change,
  fee-asset change, and the fee output.
- **4 inputs**: the verifier, up to **two** regulated inputs, and one fee input.

The limitation to state plainly: **a transfer may spend at most two UTXOs of A**.
A holder with more must consolidate across several transactions. Raising it is a
budget purchase — ~2,015 WU and ~65 pad words per extra input slot, about 2 kB of
transaction — not a design change.

### Why there is a pad at all, and why it is shaped this way

Three approaches were tried; only the third works:

1. **Taproot annex padding** — what `rust-simplicity`'s `Cost::get_padding`
   produces — is unusable: `IsWitnessStandard` rejects any taproot spend carrying
   an annex, so it would not relay.
2. **A bounded list (`List<u8, N>`)** is cost-neutral: the type's own static cost
   grows about as fast per byte of bound as the budget that byte buys. Measured:
   at bound 8192 the deficit was 9,714 B; at bound 32768, 33,999 B.
3. **A fixed-size array, read on every execution.** `[u256; 704]` costs ~306
   milli-WU per byte and buys 1,000. It must be *read*: an unused witness is
   dropped by pruning (pinned by `tests/pruning.rs`: 32 B survives when one word
   is read, 1024 B when all are absorbed), and pruning is mandatory. `absorb`
   touches every word with `eq_256(x, x)` — always true, no semantics.

`BUDGET_PAD_WORDS` in `src/programs.rs` must equal both the array length and the
`array_fold` bound in `programs/verifier.simf`. `attach_verifier` re-checks the
budget on every build and fails loudly rather than emitting a transaction the
node would reject.

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

From the run of 2026-08-17 (a fresh chain each run, so these identify a passing
run rather than being stable):

| proof | result |
|---|---|
| 1. issue A and V, fund C_U(alice) and C_V(pi0 = wl {alice,bob}) | `ebb2dbb6…`, `802f2535…` |
| 2. alice → bob, **no third party signature** | `68ca9c7102408121d38cee47eda6ff317be7dae1ac8dc022d9c525380037676b` |
| 3a. builder/BitMachine refuses an unconfined A output | `Jet failed during execution` |
| 3b. **node** rejects it | `Assertion failed inside jet` |
| 4a. builder refuses carol as recipient (no proof under pi0) | `not in the whitelist` |
| 4b. **node** rejects bob's proof reused to pay carol | `Assertion failed inside jet` |
| 4c. **node** rejects P(pi0) spending C_V(pi1) | `Witness program hash mismatch` |
| 5a. issuer update pi0 → pi1 (adds carol) | `99c830f28c896e75b7d60c67701ee041d83604443481ccaff0f82e4746e8dcf8` |
| 5b. alice → carol under pi1 | `764fa7d031da324463a7f93c8aa028e0aad703b87c824761eb3ff9e8b2c9fee3` |
| **7a. issuer update pi1 → pi2 REMOVING alice (the freeze)** | `b4c8d17a4ce28b4644bd759eb1e2031d976c3dcf49756305b481d6d8ccb261a9` |
| 7b. alice cannot spend: no owner proof exists under pi2 | `owner key 1b84c556… is not in the whitelist: these coins are frozen` |
| 7c. her stale pi1 proof fails the pi2 fold, so it cannot be pruned | `Jet failed during execution` |
| 7d. **node** rejects the only submittable form of it | `Program has FAIL node` |
| 7e. **node** rejects bob's whitelisted identity used for alice's input | `Assertion failed inside jet` |
| 7f. bob still spends under pi2 — the freeze is per holder | `90b28afc4d6627855dd2d0c99c714a6c9eeed392925a7b759d2e4e9d96675f18` |
| 7g. issuer update pi2 → pi3 restoring alice | `3ace58dc1da331d0ff90c9f7f5cffb93d6abba0dccbf57deb40f85c0796639c5` |
| 7h. alice spends again — the freeze is reversible | `0b2d5b441a49bc43a87cbfeea64eacfadc0d613afb5cfd39a209198bb65fe4b5` |
| **8a. issuer update pi3 → pi4 blacklisting one of alice's outpoints** | `1cf9bc14204f2a6f2aae4ce74e35e8d8e8209b0a0737c266c9d764a6fbf59804` |
| 8b. alice cannot spend that outpoint: no interval covers it | `outpoint …:2 is blacklisted: these coins are frozen` |
| 8c. the pre-freeze interval proof fails the pi4 root | `Jet failed during execution` |
| 8d. **node** rejects the only submittable form of it | `Program has FAIL node` |
| 8e. issuer update pi4 → pi5 lifting the listing | `51977fe15af5865f125d929eae57beb398866503abeb94261b0ece6d82f06b00` |
| 8f. the same outpoint spends once unlisted | `bfb09d1251569e81a2de0e9ccd015af1cf1146e773753d628375a16d367f7d9f` |
| **9a. issuer update pi5 → pi6 setting a transfer limit of 20,000,000** | `bba0f2659980361e6e8e0e7076b19489eb5984cc5daf71a747cf0b021e7080de` |
| 9b. builder refuses a payment of limit + 1 | `pays 20000001 atoms to other owners, over the committed transfer limit` |
| 9c. **node** rejects the over-limit payment | `Assertion failed inside jet` |
| 9d. a payment of exactly the limit confirms, alongside 120,000,000 of change that does **not** count | `58bff41c29119eb09647ab278cc3a3c3f384279e549101dc2259ee7c620bdc32` |
| **10a. issuer update pi6 → pi7 at height 115: alice locked up, carol unable to receive, until height 120** | `4ac9c86e09db8e56a2625a6afef005282e727abc0e2df63a0c0f7a3d4d88a630` |
| 10b. builder refuses a transfer claiming no height | `needs locktime >= 120 (a height window applies)` |
| 10c. **consensus** rejects an honest claim of height 120 made at height 116 | `non-final` |
| 10d. builder refuses an understated height | `needs locktime >= 120 … asks for 117` |
| 10e. **node** rejects an understated height that is otherwise perfectly minable | `Assertion failed inside jet` |
| 10f. the same honest transaction confirms once the chain reaches the bound | `944b021ad8653311f8ac7c82590322194c4ad839075655f3bc4338b38bd2103c` |
| 6a. halt: V to a plain address | `d4d312bb07ead240d91c80ae47b9ed82d1ae761e469b21433657d8bf4cb1fed8` |
| 6b. **node** rejects any transfer after the halt | `Witness program hash mismatch` |

### Both halves of the height reduction, separately

A covenant cannot read the chain height, so the windows work in two steps and the
test proves each on its own:

- **10c** is consensus refusing a claim that has not come true: the covenant was
  satisfied by a locktime of 120, and the node still would not take the
  transaction at height 116.
- **10e** is the covenant refusing an understated claim: at height 122 a locktime
  of 117 is perfectly minable, so the mempool's finality rule has nothing to say,
  and the transaction is rejected on `check_lock_height` alone.

Neither half is sufficient by itself, which is why both are asserted rather than
one being inferred from the other.

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

`tests/covenant.rs` (7 tests) proves the same logic on the BitMachine against the
exact `ElementsEnv` consensus uses, with no node.

## 5. Design decisions worth recording

**U is per-asset.** A, V and q enter U through compile-time Arguments, so each
regulated asset has its own U and CMR. A network-wide U reading A, V and q from
the transaction pattern has no sound construction for q.

**dmt-v1 instead of the design document's smt-v1/cmt-v1.** A depth-256 sparse
Merkle tree costs 256 hash levels per proof, and the verifier needs up to eight.
Depth 16 over a sorted dense tree (65,534 keys) is what fits.

**The blacklist stores intervals, not keys.** Non-membership in a *dense* tree
would otherwise need an adjacency argument over proof indices, and a dense tree
gives no cheap handle on the index (it exists only as a direction bitmap, and
SimplicityHL's folds do not expose the loop counter). Putting the gap in the leaf
makes non-membership one ordinary membership proof: 928 WU per input instead of
roughly double. Full construction, and why a listed key cannot be proven absent:
`SPEC-dmt-v1.md` section 7.

**All regulated inputs of a transfer must share one owner.** The transfer limit
needs this twice over: a limit is per sender, and change is identified by the
recipient key equalling the sender's, which presupposes a well-defined sender.
Rather than make the rule conditional on a limit being set — two program shapes,
and a subtle difference between them — it is unconditional. The cost is that two
holders cannot co-spend into a single transfer. That is a stated v1 restriction,
not an oversight, and it is cheap to lift later by making the check conditional.

**Height windows live in the whitelist leaf, not a tree of their own.** A separate
window tree would have meant a second membership fold per slot — 796 WU each,
eight slots — for information that belongs to the same key the first fold already
proves. Binding `send_after` and `recv_after` into the leaf makes them free and
makes them unforgeable: a holder cannot claim a shorter lockup, because changing
either bound changes the leaf and the path stops reaching the root.

**Fixed input-zero position** for the verifier, as the design document accepts.

Mirrors: `src/dmt.rs`, `gomirror/dmt/` (stdlib-only Go, tests asserting the same
golden roots), and for the blacklist constants an independent Python
recomputation as a third opinion.

## 6. What remains

Nothing in the covenant. What is left is integration and operations.

1. **More than two regulated inputs per transfer.** A budget purchase, not a
   design change: ~2,423 WU and ~110 pad words per extra input slot. Lifting the
   single-sender restriction goes with it (make the owner-agreement check
   conditional on a limit being committed).
2. **Confidential values on non-A outputs and on change.** Permitted by the
   covenant, untested; needs a regtest case with a blinded change output.
3. **External signature ingestion in the CLI.** `transfer-build` prints each user
   input's `sig_all_hash` and the library accepts an externally produced BIP340
   signature, but `transfer-finalize` still signs only from a supplied private
   key. A `--sig INDEX:HEX` flag is the missing piece for hardware and FROST
   signers.
4. **Parallel verifier outputs** (design doc section 6). Untouched; the single
   verifier output is a spending race, which a busy asset will hit first.
5. **Snapshot signing and publication.** `issuer_sig` over the canonical snapshot
   belongs with M2's policy service.
6. **Golden CMR vectors under CI.** `vectors/addresses.json` pins U/P/G CMRs,
   tapleaf and TapData hashes, output keys, script pubkeys, control blocks, both
   chains' addresses, per-holder window bounds and the dmt-v1 constants. Nothing
   yet fails a build when a CMR moves; it should.
7. **Transaction size.** A transfer is ~28 kB, almost all of it budget padding.
   That is a real fee cost on a live chain and the honest lever on it is the
   Simplicity cost model, not this crate: every check here is already paid for at
   the cheapest shape found. Reducing `D` from 16 to 12 (4,094 holders) would
   save ~199 WU per fold across eight slots.
8. **Live testnet pilot** (M4). The anyone-can-spend hazard makes
   `getdeploymentinfo` reporting simplicity active a hard precondition for
   funding any covenant address, on any chain.
