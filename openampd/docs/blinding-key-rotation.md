# Blinding-key rotation

Design note (decision-ready, no code). How openampd would rotate the master
blinding secret that all confidential-enclave blinding keys derive from, what a
rotation can and cannot repair, and how it interacts with the FROST policy-key
plan.

## Where we are

Every per-(holder, asset) blinding key is derived deterministically from ONE
master secret in the daemon's 0600 keys file:

    priv = SHA256(master || "openamp-blind-v1" || assetID || holderXonly)

Determinism is the feature: the server can always re-derive and re-import a
key into the watch wallet (the W-5c reconcile depends on it). The cost is a
single point of compromise.

## Threat model

- **Master-secret compromise deanonymizes retroactively.** An attacker holding
  `master` derives every blinding key ever issued and unblinds every
  confidential enclave output on the PUBLIC chain — past, present, and (until
  rotation) future. Confidentiality, not funds: blinding keys cannot spend.
  Spending needs the enclave 2-of-2 (user key + policy key), which is a
  different key family entirely.
- Exposure paths: keys-file exfiltration (backup leak, host compromise), and
  any future bug that logs or serves derived material.
- Out of scope here: the policy signing keys (see the FROST section) and the
  issuer keys.

## Proposed rotation

1. **Versioned master secrets.** Keep `blind-master` as epoch 0; add
   `blind-master-v<N>` entries. Old epochs are retained (never deleted) so
   historical outputs stay unblindable by the server and auditors.
2. **Per-asset epoch in the derivation string.** Record on each asset a
   `blind_epoch` (default 0 for existing assets, current epoch for new ones)
   and derive with a versioned tag:

       priv = SHA256(master[N] || "openamp-blind-v2" || epoch || assetID || holderXonly)

   Existing assets keep the v1 derivation for epoch 0 byte-for-byte, so nothing
   already on-chain or already imported changes out from under the watch
   wallet.
3. **Re-blind-on-touch migration.** No forced sweep. The next transaction that
   touches a holder's enclave (transfer change, DR mint, clawback) blinds its
   outputs to the NEW epoch's key. Funds migrate to the new epoch at the pace
   they move anyway; an issuer wanting a hard cutover can drive self-transfers.
4. **Watch-wallet re-import.** On rotation, import the new-epoch blinding key
   for every registered pair alongside the old one (the watch wallet holds
   both; unblinding tries all imported keys). The W-5c startup reconcile
   already iterates all pairs — it extends to iterating pairs x live epochs,
   plus its one rescan pass.

Operationally: rotation is one issuer-surface call ("cut a new epoch"),
requires no holder action, and never blocks transfers mid-migration.

## What rotation cannot fix

- **Already-public chain data.** Outputs blinded under a compromised epoch are
  permanently unblindable by whoever holds that epoch's secret. The chain is
  immutable; rotation only protects outputs created AFTER the cut. Treat a
  compromise as a disclosure event for all prior confidential history of the
  affected assets, not as something rotation repairs.
- **The server-sees-everything design.** The policy server intentionally holds
  all blinding keys (issuer oversight). Rotation narrows the blast radius in
  time; it does not change that trust model.

## FROST-keys interaction

None cryptographically, and that is the point to preserve:

- The FROST plan (internal/server/frostsigner) covers the POLICY signing keys.
  Blinding keys are a separate family; compromising one family never yields
  the other. Keep it that way — do not derive blinding keys from FROST group
  material, or a resharing would silently invalidate re-derivation.
- Organizationally, the same custody upgrade applies: the blinding master
  could move behind a threshold scheme (e.g. shares of `master[N]`, or the
  watch wallet on a hardened host). That is a deployment decision, not a
  derivation change, and nothing in this design blocks it.
- Timing: blinding-key epochs can ship before, after, or without FROST.

## Decision needed

Adopt the four-part rotation (versioned masters, per-asset epoch, re-blind on
touch, watch re-import) as the committed design, so the `blind_epoch` field can
be added to the asset record before more confidential assets are issued —
retrofitting the epoch later multiplies the reconcile surface for every asset
issued in the meantime.
