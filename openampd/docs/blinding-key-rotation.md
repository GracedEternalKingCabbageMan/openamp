# Blinding-key rotation

Implemented. How openampd rotates the master blinding secret that all
confidential-enclave blinding keys derive from, what a rotation can and cannot
repair, and how it interacts with the FROST policy-key backend.

## Where we are

Confidentiality is opt-in PER TRANSFER, not per asset: any holder can receive
or move any restricted asset blinded in a given transaction, so EVERY
registered (holder, asset) pair — not a "confidential subset" — has a blinding
key, derived deterministically from a master secret in the daemon's 0600 keys
file. Determinism is the feature: the server can always re-derive and
re-import a key into the watch wallet (the W-5c reconcile depends on it). The
cost is a single point of compromise, which rotation bounds in time.

## Threat model

- **Master-secret compromise deanonymizes retroactively.** An attacker holding
  a master derives every blinding key it ever produced and unblinds every
  matching confidential enclave output on the PUBLIC chain — past, present,
  and (until rotation) future. Confidentiality, not funds: blinding keys
  cannot spend. Spending needs the enclave 2-of-2 (user key + policy key),
  which is a different key family entirely.
- Exposure paths: keys-file exfiltration (backup leak, host compromise), and
  any future bug that logs or serves derived material.
- Out of scope here: the policy signing keys (see the FROST section) and the
  issuer keys.

## The wire facts

**Derivation.** Per-(holder, asset) blinding key, keyed by the asset's current
epoch (`Asset.BlindEpoch`, default 0; `blind_epoch` in state.json, omitted at
0 so pre-rotation records are byte-identical):

    epoch 0:  priv = SHA256(master      || "openamp-blind-v1" || assetID || holderXonly)
    epoch N:  priv = SHA256(master_v[N] || "openamp-blind-v2" || assetID || epoch_be32 || holderXonly)

Epoch 0 is the ORIGINAL derivation, frozen byte-for-byte (pinned by
`TestRotation_V1DerivationPinned`): nothing already on-chain or already
imported changes out from under the watch wallet, ever. `assetID` is the
ASCII display-hex string; `epoch_be32` is the epoch as 4 big-endian bytes;
`pub = priv*G` compressed.

**Masters.** The keys file holds `blind-master` (epoch 0, per install,
generated on first use) and `blind-master-v<N>` for every epoch a rotation has
reached. Masters are global — epoch N is the same secret for every asset —
created once by the first rotation to reach N, and NEVER deleted: old epochs'
outputs stay unblindable by the server and auditors. Deriving at an epoch
whose master does not exist is an error, never silent generation.

**Rotation.** `POST /v1/issuer/rotate-blinding {"asset": <id>}` (bearer-gated):

1. provisions `blind-master-v<epoch+1>` if this install has never reached it;
2. bumps the asset's `BlindEpoch` (persisted before the imports, so a crash
   mid-import fails safe — the startup reconcile re-imports everything);
3. re-imports every registered holder's enclave script plus its NEW blinding
   key into the watch wallet (old keys stay imported);
4. logs `rotate-blinding` with the asset, the new epoch, the holder count and
   a set-hash commitment over the re-imported scripts — never key material
   (the category set-hash discipline).

Addresses served after rotation (GET /address, and the blinding nonces of
transfer/burn/clawback/reissue outputs) derive at the new epoch immediately.

**Reads.** Balances and coin selection never depend on epochs: the unified
UTXO read goes through the watch wallet, which holds every epoch's imported
keys, so mixed-epoch enclave sets stay exact
(`TestRotation_MixedEpochBalanceExact`). The W-5c startup reconcile imports
pairs x epochs 0..current, plus its one rescan pass.

**Migration is re-blind-on-touch.** No forced sweep. The next transaction that
touches a holder's enclave blinds its outputs to the new epoch's key; funds
migrate at the pace they move anyway. An issuer wanting a hard cutover drives
self-transfers.

## What rotation cannot fix

- **Already-public chain data.** Outputs blinded under a compromised epoch are
  permanently unblindable by whoever holds that epoch's secret. The chain is
  immutable; rotation only protects outputs created AFTER the cut. Treat a
  compromise as a disclosure event for all prior confidential history of the
  affected epoch's blinded outputs, not as something rotation repairs.
- **The server-sees-everything design.** The policy server intentionally holds
  all blinding keys (issuer oversight). Rotation narrows the blast radius in
  time; it does not change that trust model.

## FROST-keys interaction

None cryptographically, and that is the point to preserve:

- The FROST backend (internal/server/frostsigner) covers the POLICY signing
  keys. Blinding keys are a separate family; compromising one family never
  yields the other. Keep it that way — do not derive blinding keys from FROST
  group material, or a resharing would silently invalidate re-derivation.
- Organizationally, the same custody upgrade applies: a blinding master could
  move behind a threshold scheme (e.g. shares of `master_v[N]`, or the watch
  wallet on a hardened host). That is a deployment decision, not a derivation
  change, and nothing here blocks it.
- Timing: blinding-key epochs shipped independently of FROST, as designed.
