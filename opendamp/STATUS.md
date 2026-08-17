# OpenDAMP M1/M3: what is consensus-enforced, and what is not

Scope of this crate: milestones **M1** (the real Simplicity covenants, with a
functional proof on `elementsregtest`) and **M3** (offline transfer
construction) of `doc/sequentia/opendamp-design.md` in the Sequentia
repository. M2 (policy service in the operator daemon, `enforcement` election
through issuance, registry validation) is not in scope.

Nothing here is deployed to any live chain.

**The headline: the DAMP core, the whitelist and the blacklist are all enforced
by consensus. Removing a holder from the whitelist stops that holder SPENDING,
and listing an outpoint stops that UTXO alone. The freeze is real, per-holder
and per-outpoint, and both are reversible by a further policy update. All of it
is proved against a real node (section 4).**

Two predicates from the design document remain unenforced and are named in
section 2: the transfer limit and the height windows.

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
   - that `Y` must carry a whitelist membership proof.
5. **A is never a fee output.** Enforced by the same script equality as 4: a fee
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

- **Transfer limit** (design doc 3.4). A snapshot may carry `limit` and it enters
  pi's `rules_root`, but no program reads it. The CLI warns when a snapshot sets
  one.
- **Height windows** (3.5). Not implemented.
- **Velocity, holder caps** (3.6). Off-chain by design; unchanged.
- **Confidential values.** The covenant requires explicit asset ids on every
  input and output it scans; this build's transaction builder also produces
  explicit values. Confidential *values* on non-A outputs are permitted by the
  covenant but untested.
- **Redemption.** No redemption branch, as the design document specifies for v1.

## 3. Budget: measured, not estimated

Simplicity buys execution budget with witness bytes — budget = serialized
witness-stack size + 50 weight units, capped at 4,000,050 — while the cost side
is a **static** bound over the whole program DAG that does not shrink when a
branch goes untaken.

Measured for a transfer with one regulated input and two A outputs (payment plus
change), at `N_max_inputs = 4`, `N_max_outputs = 6`, `D = 16`:

| quantity | value |
|---|---|
| P(pi) static cost | 16,267,739 milli-WU = **16,268 WU** |
| P(pi) witness stack | **20,301 B** (16,384 B of it pad) |
| P(pi) budget bought | **20,351 WU** |
| headroom | **4,083 WU (20%)** |
| U witness stack (per user input) | **633 B** |
| U static cost | 228,208 milli-WU = 229 WU, against 683 WU bought |
| finalized transfer size | ~21.5 kB |

The consensus cap of 4,000,050 WU is nowhere near; the binding constraint is what
the padding costs in fees and block space. Standard-transaction limits are
satisfied — the 80-byte stack-item limit applies only to tapscript (leaf version
0xc0), not to Simplicity leaves (0xbe).

The 20% headroom is the **worst** case, measured with only one of three input
slots and two of five output slots carrying proofs. Cost is static, so filling
more slots leaves it unchanged while each additional proof adds witness bytes and
therefore budget: a fuller transfer has *more* headroom, not less.

Cost per check, from `tests/cost_profile.rs` (which asserts these bands, so
arithmetic that stops holding fails a test rather than a node):

| component | static cost |
|---|---|
| whole P(pi), unpruned | 16,434,845 milli-WU |
| one OUTPUT slot (asset + C_U(Y) + whitelist fold) | 1,012,306 = **1,012 WU** |
| one INPUT slot (asset + C_U(X) + whitelist fold + blacklist) | 2,015,401 = **2,015 WU** |
| ...of which blacklist non-membership | 928,009 = 928 WU |
| ...of which the two 256-bit comparisons | 93,658 = 94 WU |
| a dmt-v1 membership fold, D = 16 | 772,296 = 772 WU |

A used output slot's witness is 561 B and a used input slot's is 1,153 B, each
buying an equal number of WU back, so an output check costs ~450 WU net and an
input check ~862 WU net.

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
3. **A fixed-size array, read on every execution.** `[u256; 512]` costs ~306
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
| 1. issue A and V, fund C_U(alice) and C_V(pi0 = wl {alice,bob}) | `832b28c0…`, `dc4191be…` |
| 2. alice → bob, **no third party signature** | `5053f61da24ae941fcad2dce4d5bf6793aad4f39043fbdc51cb6120483d1ec1a` |
| 3a. builder/BitMachine refuses an unconfined A output | `Jet failed during execution` |
| 3b. **node** rejects it | `Assertion failed inside jet` |
| 4a. builder refuses carol as recipient (no proof under pi0) | `not in the whitelist` |
| 4b. **node** rejects bob's proof reused to pay carol | `Assertion failed inside jet` |
| 4c. **node** rejects P(pi0) spending C_V(pi1) | `Witness program hash mismatch` |
| 5a. issuer update pi0 → pi1 (adds carol) | `5b55399e3b14ad2dc0963b6d94960b7eb4be2b286b38d6fa60749f99ffff3a0d` |
| 5b. alice → carol under pi1 | `a973068b20deba59555285d52221901a8b24ba0f1a0a2490324de79ca4c0ff61` |
| **7a. issuer update pi1 → pi2 REMOVING alice (the freeze)** | `92ff15f49da08f81bec8d91f4083e81aab0bc2fd7fb2655aee9063b68f6cd78d` |
| 7b. alice cannot spend: no owner proof exists under pi2 | `owner key 1b84c556… is not in the whitelist: these coins are frozen` |
| 7c. her stale pi1 proof fails the pi2 fold, so it cannot be pruned | `Jet failed during execution` |
| 7d. **node** rejects the only submittable form of it | `Program has FAIL node` |
| 7e. **node** rejects bob's whitelisted identity used for alice's input | `Assertion failed inside jet` |
| 7f. bob still spends under pi2 — the freeze is per holder | `6e0b5fa3a05c9a39ee9d5c35c01b788424870a33a64bd40fd4c9bbd7e1486efd` |
| 7g. issuer update pi2 → pi3 restoring alice | `3f306d9162d307ba0a374c5682b30654b19f3f08fe95ac52ad5d520577686d08` |
| 7h. alice spends again — the freeze is reversible | `ce55c9da3aa3b88c83eafe13f63a3abfbd0c0caef6fe04cb7ea727b801cce496` |
| **8a. issuer update pi3 → pi4 blacklisting one of alice's outpoints** | `8ccab87952f9c5bfbed8e06cf10e77e8cb9534b61a8f2888955dc6461d43f98e` |
| 8b. alice cannot spend that outpoint: no interval covers it | `outpoint …:2 is blacklisted: these coins are frozen` |
| 8c. the pre-freeze interval proof fails the pi4 root | `Jet failed during execution` |
| 8d. **node** rejects the only submittable form of it | `Program has FAIL node` |
| 8e. issuer update pi4 → pi5 lifting the listing | `be0876ffbb41079b3f391f5cb214de19d3237a2fc7304dc1e4f438876a2e5d5f` |
| 8f. the same outpoint spends once unlisted | `e613247268f6308656ab0314bed04dda9a2cd2acc14c25d620ccc436e1062c30` |
| 6a. halt: V to a plain address | `20a9a232cae9091589ccae98519b173aaed71b47d38d62825cb79a4a27e18c51` |
| 6b. **node** rejects any transfer after the halt | `Witness program hash mismatch` |

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

**Fixed input-zero position** for the verifier, as the design document accepts.

Mirrors: `src/dmt.rs`, `gomirror/dmt/` (stdlib-only Go, tests asserting the same
golden roots), and for the blacklist constants an independent Python
recomputation as a third opinion.

## 6. What remains

1. **Transfer limit and height windows** (design doc 3.4, 3.5). The limit needs
   explicit values and a bounded sum; the windows need `lock_time` comparison
   plus a class-keyed list. Budget: 4,083 WU of headroom, or buy more with pad.
2. **More than two regulated inputs per transfer.** A budget purchase, not a
   design change: ~2,015 WU and ~65 pad words per extra input slot.
3. **Confidential values on non-A outputs.** Permitted by the covenant,
   untested; needs a regtest case with a blinded change output.
4. **External signature ingestion in the CLI.** `transfer-build` prints each user
   input's `sig_all_hash` and the library accepts an externally produced BIP340
   signature, but `transfer-finalize` still signs only from a supplied private
   key. A `--sig INDEX:HEX` flag is the missing piece for hardware and FROST
   signers.
5. **Parallel verifier outputs** (design doc section 6). Untouched; the single
   verifier output is a spending race, which a busy asset will hit first.
6. **Snapshot signing and publication.** `issuer_sig` over the canonical snapshot
   belongs with M2's policy service.
7. **Golden CMR vectors under CI.** `vectors/addresses.json` pins U/P/G CMRs,
   tapleaf and TapData hashes, output keys, script pubkeys, control blocks, both
   chains' addresses and the dmt-v1 constants. Nothing yet fails a build when a
   CMR moves; it should.
8. **Live testnet pilot** (M4). The anyone-can-spend hazard makes
   `getdeploymentinfo` reporting simplicity active a hard precondition for
   funding any covenant address, on any chain.
