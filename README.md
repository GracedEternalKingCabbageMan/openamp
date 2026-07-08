# OpenAMP

Open-source issuer-governed assets for the Sequentia network: a self-hostable equivalent of Blockstream's AMP2. Issuers manage regulated assets (securities, funds, bonds) whose every transfer is co-signed by an issuer-controlled policy server, with registration/KYC whitelisting, categories, velocity limits, holder caps, lock-in and vesting, freezing, clawback under disclosed terms, ownership reports, and a hash-chained transparency log that can be anchored on-chain. It requires **zero consensus changes**: the daemon (`openampd`, written in Go) talks to an ordinary Sequentia node over JSON-RPC, and all enforcement lives in taproot script plus the policy server's signature.

This is testnet software. Everything here runs against the Sequentia public testnet (parent chain: Bitcoin testnet4); there is no mainnet.

Design document: [`doc/sequentia/openamp-design.md`](https://github.com/GracedEternalKingCabbageMan/Sequentia/blob/HEAD/doc/sequentia/openamp-design.md) in the node repository. Frozen format specifications live under [`spec/`](spec/).

## Status

- `openampd` is live on the Sequentia public testnet behind `https://sequentiatestnet.com/openamp/` (REST API only, no web UI). The demo restricted asset **BONDX** was issued and transferred through it on 2026-07-08:

  ```
  curl -s https://sequentiatestnet.com/openamp/v1/assets
  ```

- Working today (committed code): registration, enclave addresses and balances, hosted transfers with fee conversion or sponsorship, raw co-signing of self-built transactions, hosted issuance (demo mode) of transparent or confidential assets, opt-in confidential (blinded) restricted assets end to end (blinded issuance and transfers, watch-wallet unblinding, blinded co-signing), freezes, categories, per-asset rules (velocity, holder cap, lock-in, vesting), clawback, ownership reports, transparency log with on-chain anchoring, and a reorg-aware chain follower.
- In progress (not in this repository yet): a FROST threshold backend for the policy key. The committed daemon signs with a single local policy key per asset behind the `PolicySigner` interface; the FROST quorum backend is the mainnet swap-in. See "Trust model" below for what is design intent versus committed code.

## Trust model

- **Enclave outputs.** A restricted asset exists only in taproot outputs with a NUMS internal key (no key-path spend) and script leaves `<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG` (transfer) and, if enabled at issuance, `<K_issuer> CHECKSIGVERIFY <K_policy> CHECKSIG` (clawback). Every spend therefore needs the policy server's signature in addition to the holder's: enforcement is server-side, not consensus-side.
- **The asset ID commits to the policy key.** The issuance contract JSON (which names `K_policy`) is hashed into the asset's issuance entropy, so anyone holding the contract can verify offline that a given asset ID is governed by a given policy key. No registry state, no consensus lookup. Format: [`spec/contract-v1.md`](spec/contract-v1.md).
- **Policy key backend.** On-chain, `K_policy` is always a single x-only key, so the signing backend is swappable without any chain migration. The committed backend is `LocalKeySigner` (one software key per asset, stored in a 0600 file): appropriate for testnet and demos only. The `PolicySigner` interface in `openampd/internal/server/signer.go` is the seam for a production FROST threshold (or MPC/HSM) backend, where `K_policy` is the FROST group public key and signing runs a t-of-n quorum off-chain. That backend is designed for but **not yet implemented in this repository**.
- **Confidentiality is opt-in per asset.** Sequentia is transparent by default with opt-in confidentiality, and OpenAMP follows: an asset issued with `confidential: true` lives in blinded enclave outputs (amounts and asset tags hidden on-chain), while the policy server holds the per-holder blinding keys in a node watch wallet, so the issuer sees and reports every holding and outside observers see nothing. This is exactly AMP2's model on Liquid; it is narrower than a normal Sequentia confidential address (the issuer always sees the amount). No confidential-transaction crypto is reimplemented: the node's `rawblindrawtransaction`/unblind machinery does the work, and the holder still only signs the returned sighashes.
- **Fees (Rule 1).** A restricted asset never appears in a fee output, so it can never be swept into a block producer's coinbase. The policy server refuses to co-sign such a transaction, and Sequentia's default-deny fee-asset whitelist makes it non-paying at every producer regardless. Holders still pay costs in the restricted asset via fee conversion (the issuer takes a fee-equivalent slice into its own enclave and attaches the real fee in an ordinary asset, atomically in the same transaction), or the server sponsors the fee, or the sender self-pays in an ordinary asset with no issuer involvement.
- **Transparency log.** Every registration, rule change, freeze, transfer approval, refusal, and clawback is appended to a hash-chained public log (`GET /v1/log`); clawbacks are logged before they are signed. The issuer can anchor the log head on-chain in an OP_RETURN (`POST /v1/issuer/anchor`).
- **Reorg awareness.** Sequentia reorganizes whenever Bitcoin reorganizes (anchoring is supreme). The chain follower detects forks and re-marks transfer records above the fork point as unconfirmed, so velocity accounting and reports reflect only the surviving chain.

## REST API

Base URL of the public testnet instance: `https://sequentiatestnet.com/openamp` (local default: `http://127.0.0.1:8722`). All bodies are JSON; unknown fields are rejected. Errors are `{"error": "<message>"}` with a meaningful HTTP status; policy refusals are HTTP 403 and are recorded in the transparency log.

### Wallet surface (no authentication)

| Method and path | Purpose |
|---|---|
| `POST /v1/users` | Register a pubkey set, returns the account ID (AID) |
| `GET /v1/users/{aid}` | Registration status |
| `GET /v1/users/{aid}/address?asset=<id>` | Enclave address and spend data for an asset |
| `GET /v1/users/{aid}/balance?asset=<id>` | Confirmed enclave balance |
| `POST /v1/transfers` | Build a hosted transfer (fee conversion or sponsorship) |
| `POST /v1/transfers/{id}/complete` | Submit the holder's signatures, co-sign and broadcast |
| `POST /v1/cosign` | Co-sign a self-built transaction (fee self-paid) |
| `GET /v1/assets` | All assets with their contracts |
| `GET /v1/assets/{id}` | One asset |
| `GET /v1/log` | The transparency log (JSON lines) |

**`POST /v1/users`**, body `{"pubkeys": ["<x-only hex>", ...]}`, response `{"aid": "<40-char hex>"}`. The AID is `sha256("openamp-aid-v1" || sorted pubkey hex)` truncated to 20 bytes. Registering the same key set twice returns the same AID. `pubkeys[0]` is the active enclave key.

**`GET /v1/users/{aid}/address?asset=<id>`** returns everything a wallet needs to receive and later spend from its enclave:

```json
{
  "aid": "...", "asset": "...",
  "address": "<unblinded taproot address>",
  "script_pubkey": "<hex>",
  "user_pubkey": "<x-only hex>",
  "transfer_leaf": "<leaf script hex>", "transfer_control": "<control block hex>",
  "claw_leaf": "<hex, only if the asset has clawback>", "claw_control": "<hex>"
}
```

**`GET /v1/users/{aid}/balance?asset=<id>`** returns `{"aid", "asset", "atoms", "utxos"}` from a confirmed UTXO-set scan.

**`POST /v1/transfers`**, body:

```json
{"asset": "<id>", "sender_aid": "...", "recipient_aid": "...",
 "atoms": 1000, "fee_mode": "convert"}
```

`fee_mode` is `"convert"` (a fee-equivalent slice of the asset, `rules.fee_convert_atoms`, goes to the issuer's enclave and the server attaches the real fee) or `"sponsor"` (the server pays the fee and takes nothing). Self-paid transactions use `POST /v1/cosign` instead. Response:

```json
{"id": "<transfer id>", "tx": "<unsigned tx hex>",
 "to_sign": [{"input": 0, "sighash": "<32-byte hex>", "pubkey": "<x-only hex>"}],
 "convert_atoms": 100, "fee_sats": 1000}
```

The wallet signs each sighash with BIP340 Schnorr under its enclave key. Pending transfers expire after 15 minutes.

**`POST /v1/transfers/{id}/complete`**, body `{"sigs": {"<input index>": "<64-byte schnorr sig hex>"}}`. The server verifies the holder's signatures, runs the policy engine, attaches the policy signatures and its own fee-input signature, broadcasts, and returns `{"txid": "..."}`. A policy refusal returns 403 with the reason.

**`POST /v1/cosign`** for self-built transactions (the sender attaches its own ordinary-asset fee), body:

```json
{"tx": "<tx hex>", "asset": "<id>", "sender_aid": "...", "inputs": [0, 1]}
```

`inputs` are the indices spending the sender's enclave outputs. The server checks that each claimed input really is the sender's enclave output, that no unclaimed input spends this asset's enclaves, and runs the same policy engine. Response (the caller assembles the witnesses and broadcasts):

```json
{"sigs": [{"input": 0, "sighash": "...", "policy_sig": "...",
           "leaf": "...", "control": "..."}]}
```

Witness stack for an enclave input, bottom to top: `<policy sig> <user sig> <leaf script> <control block>`.

**Policy engine.** Both approval paths re-derive everything from the transaction and the chain (request metadata is never trusted) and refuse when: the sender or a non-issuer recipient is frozen; any output's asset or value is blinded; the restricted asset appears in a fee output; an output pays the asset to a non-enclave script (OP_RETURN burns allowed only if the contract permits them); a recipient lacks a required category; the asset is inside its lock-in window (issuer-bound conversion exempt if configured); the sender's velocity window would be exceeded; the holder cap would be exceeded; or the sender's vested balance is insufficient.

### Issuer surface (`Authorization: Bearer <issuer token>`)

| Method and path | Purpose |
|---|---|
| `POST /v1/issuer/assets` | Issue a restricted asset (requires `-demoissuer`) |
| `POST /v1/issuer/freeze` | Freeze or unfreeze a user |
| `POST /v1/issuer/categories` | Set a user's categories |
| `POST /v1/issuer/rules` | Replace an asset's policy rules |
| `POST /v1/issuer/clawback` | Claw back a holder's enclave UTXOs |
| `GET /v1/issuer/holders?asset=<id>` | Ownership report |
| `POST /v1/issuer/anchor` | Anchor the transparency-log head on-chain |

If no issuer token is configured, every issuer request is rejected (401).

**`POST /v1/issuer/assets`**, body:

```json
{"name": "OpenAMP Demo Bond", "ticker": "BONDX", "precision": 8,
 "atoms": 100000000000000, "holder_aid": "...", "issuer_aid": "...",
 "clawback": true, "burn_allowed": true,
 "rules": {"fee_convert_atoms": 100},
 "terms_hash": "<sha256 hex, optional>", "endpoint": "<base URL, optional>"}
```

Mints directly into the initial holder's enclave; `clawback` defaults to true and cannot be retrofitted either way. Response: `{"asset", "token", "entropy", "txid", "contract", "contract_hash"}`. Hosted issuance holds the issuer key server-side and therefore requires the `-demoissuer` flag (testnet demo only; a production issuer keeps that key offline).

**Rules object** (used at issuance and by `POST /v1/issuer/rules` with body `{"asset": "<id>", "rules": {...}}`):

```json
{"allowed_categories": ["accredited"],
 "velocity_window_blocks": 1000, "velocity_max_atoms": 500000,
 "holder_cap": 50,
 "lockin_until_height": 12000, "convert_during_lockin": true,
 "vesting": [{"aid": "...", "atoms": 1000000, "until_height": 20000}],
 "fee_convert_atoms": 100}
```

All fields optional; zero/empty means no restriction.

**`POST /v1/issuer/freeze`**: `{"aid": "...", "frozen": true}`. **`POST /v1/issuer/categories`**: `{"aid": "...", "categories": ["accredited"]}`.

**`POST /v1/issuer/clawback`**: `{"asset": "<id>", "holder_aid": "...", "reason": "<required>"}`. The reason is written to the public transparency log before the transaction is signed; the seized funds move to the issuer's enclave through the disclosed clawback leaf. Response: `{"txid", "atoms"}`. Fails for assets issued without a clawback leaf.

**`GET /v1/issuer/holders?asset=<id>`** returns `{"asset", "height", "holders": {"<aid>": atoms}, "total_atoms"}` from a confirmed UTXO-set scan.

**`POST /v1/issuer/anchor`** (empty body) commits `OPENAMP:<seq>:<log head hash>` in an OP_RETURN and returns `{"txid", "seq", "head"}`.

### Transparency log

`GET /v1/log` serves the raw log: one JSON object per line, `{"seq", "prev", "time", "action", "data", "hash"}`, where `hash = sha256("<seq>|<prev>|<time>|<action>|<data-json>")` and `prev` is the previous entry's hash. Any client can re-verify the chain and compare its head against the latest on-chain anchor.

Note on the live demo asset: BONDX was issued before the contract-v1 freeze, so its on-chain contract JSON carries a legacy `"tier": "A"` field and no `"confidential"` field. Verify pre-freeze contracts as-is (the hash commits to the exact bytes); new issuances follow [`spec/contract-v1.md`](spec/contract-v1.md).

## End-to-end walkthrough

Against your own `openampd` (see "Build, run, test" and [`deploy/DEPLOY.md`](deploy/DEPLOY.md)); the live instance works the same for the unauthenticated endpoints. `keygen` and `signer` are demo helpers from this repository.

```sh
# 0. demo keys (name, private key, x-only pubkey) for issuer, alice, bob
go run ./openampd/cmd/keygen
# issuer 7f3a... 8fcd...
# alice  92b1... 55aa...
# bob    0cc4... 77ee...

# 1. register the three accounts (returns AIDs)
curl -s localhost:8722/v1/users -d '{"pubkeys":["<issuer-xonly>"]}'
curl -s localhost:8722/v1/users -d '{"pubkeys":["<alice-xonly>"]}'
curl -s localhost:8722/v1/users -d '{"pubkeys":["<bob-xonly>"]}'

# 2. issuer mints 1,000,000.00000000 BONDX into alice's enclave
curl -s localhost:8722/v1/issuer/assets \
  -H "Authorization: Bearer $ISSUER_TOKEN" \
  -d '{"name":"OpenAMP Demo Bond","ticker":"BONDX","precision":8,
       "atoms":100000000000000,"holder_aid":"<alice-aid>",
       "issuer_aid":"<issuer-aid>","burn_allowed":true,
       "rules":{"fee_convert_atoms":100}}'
# -> {"asset":"<asset-id>", "txid":..., "contract":..., "contract_hash":...}

# 3. alice's enclave address and balance for the new asset
curl -s "localhost:8722/v1/users/<alice-aid>/address?asset=<asset-id>"
curl -s "localhost:8722/v1/users/<alice-aid>/balance?asset=<asset-id>"

# 4. alice sends 5000 atoms to bob, fee converted from the asset
curl -s localhost:8722/v1/transfers \
  -d '{"asset":"<asset-id>","sender_aid":"<alice-aid>",
       "recipient_aid":"<bob-aid>","atoms":5000,"fee_mode":"convert"}'
# -> {"id":"<tid>", "to_sign":[{"input":0,"sighash":"<h>", ...}], ...}

# 5. alice signs each sighash with her enclave key and completes
go run ./openampd/cmd/signer <alice-priv> <h>       # -> <64-byte sig hex>
curl -s localhost:8722/v1/transfers/<tid>/complete \
  -d '{"sigs":{"0":"<sig-hex>"}}'
# -> {"txid":"..."}   (or 403 with the policy refusal reason)

# 6. the decision trail
curl -s localhost:8722/v1/log
```

The same flow, driven programmatically against a regtest node, is the committed integration proof [`test/functional/feature_openamp_daemon.py`](https://github.com/GracedEternalKingCabbageMan/Sequentia/blob/claude/sequentia-bitcoin-sidechain-w6xady/test/functional/feature_openamp_daemon.py) in the node repository.

## How openampd uses the Sequentia node

`openampd` needs one Sequentia node (`elementsd`) with a funded wallet and nothing else; there are no consensus changes, no patched node, no indexer. RPC usage:

- chain queries: `getblockcount`, `getblockhash`, `getblock` (follower), `gettxout` (prevout resolution), `scantxoutset` (enclave balances and holder reports), `decodescript` (address rendering), `dumpassetlabels` (fee-asset default);
- wallet operations: `listunspent`, `getnewaddress`, `getaddressinfo`, `signrawtransactionwithwallet`, `sendrawtransaction`, and `createrawtransaction` + `fundrawtransaction` for log anchors.

Enclave transactions are built by openampd's own minimal Elements codec (`openampd/internal/elements`): explicit assets and values end to end, Elements taproot with the `/elements` tagged hashes and leaf version `0xc4`, and the Elements taproot sighash. Byte-exactness is enforced by golden vectors generated from the node repository's functional-test framework. Issuance entropy and asset/token IDs are derived in `openampd/internal/fastmerkle` (the Elements two-leaf fast merkle root).

The node pays and accepts fees per Sequentia's open fee market: openampd attaches its fees in one configurable ordinary asset (`-feeasset`, defaulting to the chain's policy asset), which must be on the producers' accepted-fee-asset whitelist.

## Build, run, test

Requires Go 1.26+ (dependencies are vendored, so builds work offline).

```sh
git clone https://github.com/GracedEternalKingCabbageMan/openamp.git
cd openamp
go build ./...
go test ./...
go build -o openampd/openampd ./openampd/cmd/openampd
```

Run against a node:

```sh
./openampd/openampd \
  -rpc http://127.0.0.1:7041 \
  -rpcauth user:pass \            # or cookie:/path/to/.cookie
  -rpcwallet mywallet \
  -issuertoken <long-random-token> \
  -feeasset <display hex of the fee asset> \
  -demoissuer                     # testnet demos only: issuer keys server-side
```

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `127.0.0.1:8722` | HTTP listen address |
| `-datadir` | `~/.openampd` | state directory (`state.json`, `keys.json` 0600, `transparency.log`) |
| `-rpc` | `http://127.0.0.1:7041` | elementsd RPC URL |
| `-rpcauth` | (required) | `user:pass` or `cookie:<path>` |
| `-rpcwallet` | (none) | wallet name, appended as `/wallet/<name>` |
| `-issuertoken` | (none) | bearer token gating `/v1/issuer/*`; empty locks the issuer API |
| `-feeasset` | chain policy asset | display hex of the ordinary asset openampd pays fees in |
| `-feesats` | `1000` | flat fee attached to server-funded transactions, in fee-asset atoms |
| `-demoissuer` | off | hold issuer keys server-side (testnet demo only) |
| `-follow` | `2s` | chain follower poll interval |

Production deployment (systemd unit, Caddy reverse proxy, secrets handling): [`deploy/DEPLOY.md`](deploy/DEPLOY.md).

## Repository layout

```
openampd/cmd/openampd/      the daemon (flags, wiring, chain follower start)
openampd/cmd/keygen/        demo BIP340 keypair generator
openampd/cmd/signer/        demo client-side sighash signer
openampd/internal/server/   HTTP API, policy engine, issuance, transfers,
                            clawback, PolicySigner seam, chain follower
openampd/internal/elements/ minimal Elements tx codec, taproot, sighash
                            (golden-vectored; see tools/gen_vectors.py)
openampd/internal/fastmerkle/  issuance entropy and asset/token id derivation
openampd/internal/rpc/      minimal JSON-RPC client for elementsd
openampd/internal/store/    JSON state store, 0600 key file, transparency log
spec/                       frozen formats (contract v1)
deploy/                     systemd unit + deploy runbook
tools/gen_vectors.py        golden-vector generator (runs against the node
                            repo's functional-test framework)
vendor/                     vendored Go dependencies (offline builds)
```

Regenerating the golden vectors (needs a checkout of the node repository):

```sh
PYTHONPATH=$SEQ_REPO/test/functional python3 tools/gen_vectors.py \
  > openampd/internal/elements/testdata/vectors.json
go test ./openampd/internal/elements
```

### Milestone artifacts

- [`test/functional/feature_openamp_m0.py`](https://github.com/GracedEternalKingCabbageMan/Sequentia/blob/claude/sequentia-bitcoin-sidechain-w6xady/test/functional/feature_openamp_m0.py) (node repo): the M0 proof; demonstrates on regtest that enclave issuance, policy-co-signed transfer, clawback, and the contract-to-asset-ID binding all work against unmodified consensus.
- [`test/functional/feature_openamp_daemon.py`](https://github.com/GracedEternalKingCabbageMan/Sequentia/blob/claude/sequentia-bitcoin-sidechain-w6xady/test/functional/feature_openamp_daemon.py) (node repo): end-to-end integration of a real `openampd` process with a regtest node, covering the hosted-transfer, rules, freeze, and clawback flows.
- `openampd/internal/elements/testdata/vectors.json`: golden vectors proving the Go Elements primitives byte-exact against the node's test framework.

## Ecosystem

| Repo | One-liner |
|---|---|
| [`Sequentia`](https://github.com/GracedEternalKingCabbageMan/Sequentia) | The Sequentia node (`elementsd` fork of Elements 23.3.3): consensus, anchoring, proof of stake, open fee market, plus the canonical protocol documentation in `doc/sequentia/`. |
| [`sequentia-registry`](https://github.com/GracedEternalKingCabbageMan/sequentia-registry) | Sequentia Asset Registry service (asset metadata). |
| [`SWK`](https://github.com/GracedEternalKingCabbageMan/SWK) | Sequentia Wallet Kit: a fork of Blockstream LWK, providing a Rust wallet library, CLI, and WASM bindings for building Sequentia (and Bitcoin testnet4) wallets. |
| [`ambra`](https://github.com/GracedEternalKingCabbageMan/ambra) | Ambra: non-custodial dual-chain (Bitcoin testnet4 + Sequentia) mobile wallet, a Flutter UI over a Rust core built on SWK. |

## Contributing

Pull requests against `main`. Run `go build ./... && go test ./...` before submitting; if you touch `openampd/internal/elements`, regenerate or extend the golden vectors rather than weakening the tests. Secrets (RPC credentials, issuer tokens, keys) never belong in this repository.
