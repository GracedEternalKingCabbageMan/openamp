# OpenAMP contract format v1

STATUS: frozen with M0 (2026-07-08). Fields marked M1+ are reserved and not yet interpreted by any implementation.

The contract is the machine-readable issuance document of an OpenAMP asset. Its hash is committed into the asset's issuance entropy, so the asset ID itself proves which policy key and which terms govern the asset. Verification needs no registry and no consensus state.

## 1. Contract JSON

```json
{
  "name": "Example Bond 2027",
  "ticker": "BONDX",
  "precision": 8,
  "version": 0,
  "issuer_pubkey": "<hex>",
  "openamp": {
    "version": 1,
    "type": "restricted",
    "policy_pubkey": "<32-byte x-only hex>",
    "tier": "A",
    "clawback": true,
    "burn_allowed": true,
    "policy_endpoints": ["https://amp.example-issuer.com"],
    "terms_hash": "<sha256 hex>"
  }
}
```

Field rules:

- `openamp.version`: this specification's version, `1`.
- `openamp.type`: `"restricted"` (enclave-enforced) or `"tracked"` (reporting only, no on-chain restriction).
- `openamp.policy_pubkey`: the asset-wide policy key `K_policy`, 32-byte x-only, lowercase hex. For restricted assets this key must co-sign every transfer. It may be a threshold (FROST) key; on-chain it is always one point.
- `openamp.tier`: `"A"` (server-enforced containment) or `"B"` (covenant-enforced containment; leaf spec lands with M2).
- `openamp.clawback`: whether the enclave tree contains the clawback leaf (default `true`). Committed here so holders accept the terms at purchase time; it cannot be retrofitted.
- `openamp.burn_allowed`: whether `OP_RETURN` burns of the asset are permitted policy (and, under Tier B, covenant-permitted).
- `openamp.policy_endpoints` (M1+): base URLs of the policy server API.
- `openamp.terms_hash` (optional): sha256 of the legal terms document.
- Top-level `name`, `ticker`, `precision`, `version`, `issuer_pubkey` follow the Sequentia asset-registry conventions (`precision` mirrors the on-chain issuance denomination).

## 2. Canonicalization and hashing

- Canonical form: UTF-8 JSON with lexicographically sorted keys and no insignificant whitespace (separators `,` and `:`). This is Python's `json.dumps(contract, sort_keys=True, separators=(",", ":"))`.
- `contract_digest = sha256(canonical_bytes)` (single SHA256, raw 32 bytes).
- RPC/display form (as passed to `issueasset`/`rawissueasset` `contract_hash` and as shown by node RPCs): the digest hex **byte-reversed**, matching the Liquid asset-registry convention and the node's uint256 display order.

## 3. Asset binding

With `prevout` the issuance input's outpoint and `H2` = double-SHA256, `M(l, r)` = the SHA256 midstate of the 64-byte block `l || r` (Elements fast merkle root of two leaves):

```
entropy = M(H2(serialize(prevout)), contract_digest)
asset   = M(entropy, 0x00 * 32)
token   = M(entropy, 0x01 || 0x00 * 31)     # reissuance token, explicit issuance
```

All values in internal byte order; display hex is reversed. A verifier holding the contract JSON recomputes this chain and compares against the asset ID it observes on-chain. If they match, `openamp.policy_pubkey` provably governs the asset. The reference implementation (pure python, no node code) is `derive_issuance_ids` in the M0 proof.

## 4. Tier A enclave outputs

An enclave output for holder key `K_user` is the taproot output:

- internal key: the BIP341 NUMS point `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` (no key-path spend exists),
- script tree (Elements tagged hashes `TapLeaf/elements`, `TapBranch/elements`, `TapTweak/elements`; leaf version `0xc0`):
  - transfer leaf: `<K_user> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG`
  - clawback leaf (iff `clawback`): `<K_issuer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG`

Witness stack for either leaf, bottom to top: `<policy signature> <user-or-issuer signature> <leaf script> <control block>`. Signatures are BIP340 Schnorr over the Elements taproot sighash (`SIGHASH_DEFAULT`).

Issuance mints directly into enclave outputs. The reissuance token is issuer-held and outside the enclave; issuer tooling must keep custody of it and mint only into enclave outputs.

## 5. Rule 1 (fees)

A restricted asset never appears in a fee output. The policy server refuses to co-sign any transaction with a fee output (empty `scriptPubKey`) in the asset; Sequentia's default-deny fee-asset whitelist makes such a transaction non-paying at every producer regardless; Tier B additionally makes it invalid by consensus. Fee funding options: sender self-pays in an ordinary asset (no issuer involvement), fee conversion (issuer or registered broker takes a fee-equivalent enclave output of the asset and attaches the real fee, atomically in the same transaction), or sponsorship.

## 6. M1+ reserved

Account IDs (AID), the registration and co-signing REST protocol (PSET round-trip), policy documents (categories, velocity, vesting, holder caps), the transparency log format, and the Tier B covenant leaf are specified with M1/M2.
