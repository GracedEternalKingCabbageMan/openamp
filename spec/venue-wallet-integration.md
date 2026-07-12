# OpenAMP integration specification: venues and wallets

**Audience:** (1) the agent implementing restricted-asset markets on SeqDEX (repos `seqdex`: seqobd, seqob-maker, seqob-settler), and (2) anyone making SWK (the Sequentia Wallet Kit, repo `SWK`, branch `sequentia`) and wallets built on it (the Sequentia web wallet, repo `sequentia-web-wallet`; Ambra, repo `ambra`) work with OpenAMP restricted assets. This document is self-contained: it requires no other document, and every claim about openampd behavior carries a code reference into `~/openamp/openampd`. It originated as Section 9 of the SeqPal overhaul plan (`SeqPal/OVERHAUL.md`) and supersedes it; the plan now points here.

Status of referenced future work: items marked **(M5)**, **(M6)**, **(M8)** are milestones of the SeqPal overhaul that deliver platform-side dependencies (the wallet sign card ships in M5; the OA-7 cosign fix and the mixed-asset regtest proof land in M6; the eligibility and listings endpoints land in M8). Do not build on those dependencies until the named milestone is deployed; everything else here is implementable now.

---

## Part 0. Shared foundations

### 0.1 What a restricted asset is

A restricted asset is an ordinary Elements issuance on the Sequentia network whose entire supply lives in 2-of-2 taproot "enclaves": leaf version 0xc4, transfer leaf `<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG`, NUMS internal key, plus an optional clawback leaf `<K_issuer> CHECKSIGVERIFY <K_policy> CHECKSIG` disclosed at issuance (`internal/elements/taproot.go:180-207`). Every spend of an enclave UTXO requires a co-signature from the policy server, openampd (public base `https://sequentiatestnet.com/openamp`). Holders are identified by AID. The asset's rules (allowed_categories, lockin_until_height, velocity, holder_cap, per-AID vesting; the OA-3 extensions add category_denies, holder_caps_by_category, and primary_aids sender scoping) are enforced in `checkTransfer` (`internal/server/transfer.go`). The asset ID commits to the policy key via the issuance contract_hash. The policy server refuses with HTTP 403 plus a specific reason string and appends every decision to a public hash-chained transparency log anchored on-chain via OP_RETURN.

The policy key is per-asset (`server.go:393-402`), so a holder's enclave address differs per asset.

### 0.2 AID

`AID = hex(first 20 bytes of sha256("openamp-aid-v1" || pubkey-hex-strings sorted lexicographically, concatenated as UTF-8))` (`internal/store/store.go:258-268`). Pubkeys are 64-hex BIP340 x-only keys. The AID hashes the sorted pubkey SET: registering a different key, or a second key, produces a different AID. Clients must compute the AID locally and assert equality with the server's answer; a fixed cross-implementation test vector against the Go `store.AID` is part of wallet conformance.

### 0.3 Endpoint reference

All under `/openamp` on the live box (Caddy strips the prefix). Public unless noted.

- `POST /v1/users` `{pubkeys:["<64-hex x-only>", ...]}` -> `{aid}`. Idempotent; re-registering an existing AID leaves the server-side record (categories, frozen) untouched (`server.go:154-181`).
- `GET /v1/users/{aid}` -> `{aid, pubkeys, categories[], frozen}` (`server.go:183-196`). NOTE: `categories` and `frozen` are `omitempty` in the store struct (`store.go:22-23`), so they are ABSENT from the JSON when the list is empty or the user is not frozen. Clients must default them (no categories, not frozen), never treat absence as an error.
- `GET /v1/users/{aid}/address?asset=` -> `{address, script_pubkey, user_pubkey, transfer_leaf, transfer_control, claw_leaf?, claw_control?, confidential}` (`server.go:224-267`). Confidential assets return a blech32 address.
- `GET /v1/users/{aid}/balance?asset=` -> `{aid, asset, atoms, utxos}`; `utxos` is a COUNT. Confirmed-only; no scan height, no pending amounts, no utxo detail (`server.go:269-287, 411-439`).
- `GET /v1/assets` and `GET /v1/assets/{id}` -> full asset record incl. `rules` and `contract` (restriction legend + terms_hash inside the contract's `openamp` block) (`server.go:198-222`).
- `POST /v1/transfers` (hosted builder) and `POST /v1/transfers/{id}/complete` -> see 1.6.
- `POST /v1/cosign` (self-built transactions) -> see 2.4.
- `GET /v1/log` -> hash-chained transparency log (refusals, cosigns, anchors).
- Bearer-token-gated `/v1/issuer/*` endpoints exist for the platform only; wallets and venues never hold that token.

### 0.4 Signing formats (normative for every client)

1. **Enclave-spend signatures are plain (untagged) BIP340 over the Elements taproot sighash**: SIGHASH_DEFAULT, committing to the genesis hash and the transfer leaf (`transfer.go:485-493`). The server supplies its computed digest in `to_sign`, but the wallet MUST recompute the digest itself from the transaction and prevouts and sign its OWN result, refusing on mismatch (see 0.4(3); a supplied digest is a cross-check, never the thing you sign). Signatures must verify under the FIRST registered pubkey of the sender's AID (`transfer.go:505`, `server.go:394`).
2. **Everything else is signed TAGGED**: link challenges, login challenges, and document hashes are never signed raw. The wallet signs `BIP340_sign(tagged_hash(tag, message))` where `tagged_hash(tag, m) = sha256(sha256(tag) || sha256(tag) || m)`:
   - tag `"openamp-challenge-v1"` for wallet-link and login challenges (message = the UTF-8 challenge string);
   - tag `"openamp-document-v1"` for document e-signatures (message = the 32-byte document hash).
   Verifiers apply the same tagged hash. Rationale: a malicious "challenge" chosen by an attacker can then never equal a spendable transfer sighash (that would require a preimage of the tagged hash); without this, any challenge-signing surface is a signing oracle over arbitrary digests.
3. **A wallet MUST NEVER blind-sign an externally supplied enclave digest.** Signing an opaque 32-byte digest with the m/5/0 key is an enclave-drain oracle: a hostile requester can hand the wallet the taproot sighash of a transaction spending the victim's own enclave UTXO to the attacker (the enclave script and balance are public via `GET /address` and `GET /balance`), then obtain the policy co-signature from the public `POST /v1/cosign` and broadcast. Therefore the ONLY permitted enclave-spend signing path (hosted transfers 1.6 and DEX settlement 2.3/2.4) is: the wallet receives the FULL transaction plus, for each enclave input it is asked to sign, the prevout (asset, value, script), the leaf script, and the control block; the wallet RECOMPUTES the Elements taproot sighash itself (never trusting a supplied digest), DECODES the transaction, and DISPLAYS the real effects (which of my enclave UTXOs are spent, asset and amount out, what I receive and to which of my addresses, every recipient) before signing. This makes SWK-6 (client-side sighash recomputation) MANDATORY, not optional. No surface ever signs a bare digest handed in from outside.
4. **Determinism**: BIP340 aux-rand is verifier-irrelevant, but SWK's signer MUST sign deterministically (no aux rand), matching Ambra's `openamp_sign_sighash` (`ambra_core/src/api/mod.rs:1046`), so cross-implementation signature test vectors are possible.
5. **Wire encoding**: `atoms` is a JSON NUMBER (uint64), never a string; openampd decodes into a bare Go `uint64` and rejects strings (`transfer.go:291`). Sig maps in `/complete` are keyed by input index as a DECIMAL STRING (`transfer.go:515-580`). Signatures are 128-hex (64 bytes); pubkeys are 64-hex x-only.

### 0.5 What openampd does NOT provide (design around it)

1. No webhooks or push: poll `GET /v1/log` with a cursor, or poll balances.
2. No unconfirmed balances, scan height, utxo detail, or per-holder history: clients need their own explorer/chain watcher for pending state, confirmations, and Bitcoin anchor depth.
3. Freeze is GLOBAL per user across every asset on the instance (`server.go:293-316`).
4. Pending hosted transfers are volatile: in-memory, 15-minute TTL, lost on restart (`transfer.go:496-506`); treat drafts as short-lived and rebuild on 404.
5. Categories are replace-whole-list writes by the platform only; clients read, never write.
6. No reorg read surface: openampd re-marks its transfer records internally but exposes no event for it; run your own chain watcher (the Sequentia network follows Bitcoin reorgs in real time; nothing is final at 0-conf).
7. Hosted-flow sighashes are server-computed, but a conforming wallet MUST recompute them locally and refuse to sign on mismatch (0.4(3)); openampd supplies `tx` in the `/v1/transfers` response precisely so the client can. Blind-signing server digests is NOT conformant.
8. `/v1/cosign` velocity-counts approvals even if never broadcast (`transfer.go:727-733`): never cosign for quotes.
9. Recipients must pre-exist: transfers to an unregistered party or plain address are impossible (`transfer.go:60-62, 307-310`); receive UX leads with "share your AID".

### 0.6 First-principles UI duties (binding on every wallet and venue surface)

- The restricted asset is ONE ROW AMONG EQUALS next to BTC and every other asset; no privileged framing; deliveries appear unprompted in the unmodified wallet.
- Dual-chain: BTC (testnet4) stays first-class beside enclave rows.
- Transparent-by-default: enclave addresses are ordinary tb1 P2TR; blech32 only for opt-in confidential assets, presented as opt-in.
- Confirmations plus Bitcoin anchor depth on every state; NOTHING labeled final at 0-conf.
- Custody honesty: positions render with "self-custodial subject to disclosed clawback and co-sign powers".
- Fee amounts display in the fee asset's OWN units, never "sat/vB".
- Naming: "the Sequentia network" (never "SEQ" for the network); the token is "the Sequence token (SEQ)". No em dashes in copy.

---

## Part 1. Wallet specification (SWK and wallets built on it)

### 1.1 Canonical enclave key: BIP32 path m/5/0

One dedicated, otherwise-unused keypair per wallet seed, derived at **m/5/0** from the BIP39 seed (empty passphrase), matching Ambra (`ambra_core/src/api/mod.rs:992-1030`; m/2/0 is the staker key, m/3/0 the SeqDEX HTLC key, m/1017' the seqln key). The x-only form of its pubkey is the registered OpenAMP identity.

**The web wallet currently violates this**: it reuses the m/3/0 HTLC keypair (`index.html:922` via `SWK/lwk_wasm/src/seqdex_htlc.rs:74-99`). That is doubly wrong: the same secret guards live HTLC swap funds (a signing surface over arbitrary digests with that key could authorize an HTLC spend), and the same mnemonic yields different AIDs in Ambra vs the web wallet, so restricted holdings do not follow the seed across wallets. Migration (1.9) is mandatory before the sign card ships.

### 1.2 SWK kit work items

| # | Component | Item | Size |
|---|---|---|---|
| SWK-1 | lwk_wasm (+ lwk_signer) | `Signer.openampXonlyPubkey()` and `Signer.openampSignSighash(digest_hex)` at m/5/0, following the `htlcKeypair` pattern (`lwk_wasm/src/seqdex_htlc.rs:67-99`) but WITHOUT exporting the secret to JS: signing happens inside Rust, deterministic (no aux rand; the existing wasm `Keypair.signSchnorr` at `lwk_wasm/src/keypair.rs:88-99` uses randomized aux via secp256k1 `sign_schnorr` and is NOT suitable as-is). Add `openampSignTagged(tag, message_hex)` implementing 0.4(2). | S |
| SWK-2 | lwk_wollet | New `openamp.rs` module behind a new `openamp` feature (do NOT retrofit `amp2.rs`: AMP2 is descriptor-registered P2WSH multisig with PSET-level cosign, `amp2.rs:150-207`, architecturally unrelated; reuse only its async+blocking HTTP-client pattern). Typed client for the 0.3 endpoints, AID type with the store.AID derivation, enclave-address struct (script, leaf, control), hosted-transfer state machine (create -> sighashes -> sign -> complete). | L |
| SWK-3 | lwk_wasm | `#[wasm_bindgen] Openamp` wrapper over SWK-2, mirroring the existing `Amp2` wrapper shape (`lwk_wasm/src/amp2.rs:60-102`): registerUser, enclaveAddress, balance, assetInfo, createTransfer, completeTransfer, cosign, log. | M |
| SWK-4 | lwk_wollet | Contract JSON fidelity: the typed `Contract` struct DROPS the contract's `openamp` block and `contract_hash()` recomputes from the lossy struct, so registry verification (`RegistryAssetData::new` -> `asset_ids`) currently REJECTS every OpenAMP asset and the restriction legend is unreachable (`contract.rs:48-72,113-116`; `registry.rs:558-581`). Carry the raw `serde_json::Value` alongside the typed struct, hash the original bytes, expose an `openamp()` accessor, thread it into registry data. | M |
| SWK-5 | lwk_wollet | Bless the upstream raw-scriptpubkey wallet variant (`DescOrSpks::Spks`, `descriptor.rs:31-33,266-283`; scanned via esplora, `wollet.rs:295-311`) over enclave scriptPubKeys as an OPTIONAL trust-minimizing cross-check of openampd `/balance` (which stays the source of truth). Test it against a transparent taproot enclave spk; document that the spk set is frozen at construction (new enclave address = rebuild). | S |
| SWK-6 | lwk_wollet + lwk_wasm | **MANDATORY** (it is the safety mechanism of 0.4(3), not an optimization): `enclaveSighash(tx_hex, input_index, prevouts, leaf_script, control_block)` computing the Elements taproot sighash (SIGHASH_DEFAULT, genesis-committed) for a foreign NUMS script-path input, plus `decodeEnclaveSpend(tx_hex, prevouts, my_aid, my_scripts)` returning the human-readable effects (my inputs spent, asset/amount out, my receipts, all recipients) that the wallet displays before signing. Existing hand-rolled precedents to generalize: `lwk_wasm/src/seqob_covenant.rs` (script-path witness + sighash), `TxBuilder::add_external_utxos`. Note `SwSigner.sign(pset)` cannot sign enclave inputs at all (own-key-path only, `software.rs:324-400`), so this is the only path. | M |
| SWK-7 | lwk_bindings | UniFFI `Openamp` wrapper: DEFERRED until a non-wasm consumer materializes (Ambra has its own FFI). | S |
| SWK-T | tests | Conformance vectors: (a) AID vector identical to Go `store.AID` for a fixed pubkey; (b) deterministic BIP340 signature vector identical to Ambra's `openamp_sign_sighash` for a fixed seed and digest; (c) tagged-hash vectors for both tags, DEFINED BY THIS SPEC (no reference implementation exists yet: neither Ambra nor openampd implements the tagged path today; the platform verifier lands with the SeqPal M5/M8 code and must be tested against these vectors); (d) an enclave-sighash recomputation vector: given a known tx + prevouts + leaf, SWK's `enclaveSighash` must equal the digest openampd returns in `to_sign` (this is the check that makes 0.4(3) enforceable). | S |

### 1.3 Registration and identity lifecycle

On wallet open (before first sync), lazily and fault-tolerantly: derive m/5/0, compute the AID locally, `POST /v1/users`, ASSERT server AID == local AID (the current web wallet trusts `j.aid` blindly, `index.html:928`; conformance requires the assertion), then load `GET /v1/assets`. Registration failure must never block the rest of the wallet.

### 1.4 Receive

Per-asset enclave deposit address from `GET /v1/users/{aid}/address?asset=`, displayed WITH the AID (counterparties need the AID for hosted sends; the address is what on-chain payers use). QR-encode both (the ordinary receive path already has QR; parity is required). Blech32 answers render with opt-in-confidential copy.

### 1.5 Balance and state honesty

openampd `/balance` is the source of truth (confirmed atoms only; it also reflects policy state). Wallet duties beyond polling it into the ordinary asset list: (a) restricted rows join the reference-currency headline total once the ticker prices (the web wallet currently excludes them: `refKey:null` at `index.html:2582`, total loop `addToTotal` at `:2536-2538`); (b) a just-sent transfer's txid is tracked against the explorer until confirmed, with a pending chip and anchor depth (0.6); (c) frozen status from `GET /v1/users/{aid}` surfaces as a banner; (d) the restriction legend, terms_hash link, lockup wording ("until Sequentia block H"), and the clawback/co-sign qualifier render on the asset's detail surface.

### 1.6 Hosted send (the standard wallet transfer path)

1. `POST /v1/transfers {"asset", "sender_aid", "recipient_aid", "atoms": <JSON number>, "fee_mode": "convert"}` -> `{id, tx, to_sign:[{input, sighash, pubkey}], convert_atoms, fee_sats}`. Expect: 404 unregistered recipient, 409 insufficient confirmed balance, 503 policy fee wallet dry (`transfer.go:286-513`).
2. For each `to_sign[i]`: recompute the sighash locally from the returned `tx` plus the enclave prevout, leaf, and control block (SWK-6), and ABORT if it does not match the server's digest. Decode `tx` and show the real effects.
3. Confirm-before-sign modal: what is being spent, recipient AID, amount, converted fee in the ASSET'S OWN units.
4. Sign the LOCALLY RECOMPUTED digest with the m/5/0 key (plain BIP340, deterministic).
5. `POST /v1/transfers/{id}/complete {"sigs": {"<input index>": "<128-hex>"}}` -> `{txid}`; on 403 surface the reason VERBATIM and link the transparency log; on 404 the draft expired (15 min): rebuild, never blind-retry.
6. Track the txid per 1.5(b).

**Known interop bug (fix + contract-test in the web wallet):** the shipped send path posts `atoms` as a JSON string (`index.html:2980`), which openampd's `uint64` decode rejects (`transfer.go:291`). Verify against the live server, then fix to a number.

Fee mode: hardcode `"convert"` and display `convert_atoms`; expose `"sponsor"` only if a platform signals it.

### 1.7 Inbound detection

No push exists (0.5). On each sync: re-poll balances (delta = inbound receipt), re-poll `GET /v1/users/{aid}` (freeze/categories). Optionally tail `GET /v1/log` with a cursor for a restricted-transfer history surface; history conformance is: restricted transfers visible with explorer-linked txids and confirmation state.

### 1.8 The generic "sign an OpenAMP request" card (ships with SeqPal overhaul M5)

One neutral card in the shared wallet (no platform branding). It handles ONLY tagged, non-spending signatures. It can NEVER authorize an enclave spend, by construction: it has no raw-digest mode at all (0.4(3)).

- **Challenge mode** (wallet-link proofs, login challenges): input a challenge string; sign tagged `"openamp-challenge-v1"` (0.4(2)); output signature + x-only pubkey + AID.
- **Document mode** (e-signatures): input a 32-byte document hash; sign tagged `"openamp-document-v1"`.

Transport: paste-in/copy-out always works; deep link `#oamp-sign?payload=<base64url JSON {mode, challenge|doc_hash, callback?, label?}>` pre-fills the card; an optional callback URL POSTs the result ONLY after the user confirms, with the requesting origin displayed. No auto-signing, ever. Because both modes are domain-separated by tagged hashing, a hostile deep link cannot turn this card into a spend authorization: producing a signature valid as a transfer sighash would require a preimage of the tagged hash.

**Enclave-spend signing is a separate, non-deep-linkable surface** (used by hosted sends, 1.6, and DEX settlement, 2.3): it accepts a full transaction plus prevouts, leaf, and control block; recomputes the sighash; shows the decoded effects; and signs only after explicit confirmation (0.4(3)). It has no callback-POST transport reachable from an arbitrary origin: a venue reaches it through an authenticated session the user established (2.3 channel (b)), or the user pastes the settlement request in and copies the signature out, having seen exactly what it spends.

### 1.9 Web wallet work items

| # | Item | Size |
|---|---|---|
| WW-1 | Switch identity to m/5/0 via SWK-1; add the local-AID assertion (1.3). **Migration (requires the platform; do not promise otherwise):** on first run, also derive the legacy m/3/0 identity; if its AID holds any balance, register the new AID and run a one-time migration. A freshly registered AID has NO categories (`server.go:169-174`), and `checkTransfer` refuses any recipient lacking a permitted category whenever the asset sets `allowed_categories` (`transfer.go:76-97`), so a self-transfer old-AID -> new-AID 403s on exactly the gated assets it targets. The platform must therefore first copy the holder's categories onto the new AID via the bearer-gated `POST /v1/issuer/categories` (an identity-migration endpoint on the issuing platform is the clean form). Only then does the wallet move each asset by a hosted transfer whose sender is the OLD AID, signed with the RETAINED legacy m/3/0 key (SWK-1 must therefore keep m/3/0 signing available during migration, not just m/5/0). Holder caps (both AIDs counted mid-migration), vesting, and velocity can still refuse: surface those reasons verbatim and let the platform resolve them. Until migrated, show legacy balances read-only under a "legacy identity" note. | M |
| WW-2 | The sign card (1.8), including the deep-link route in `init()` (the wallet currently parses no hash/query at startup) and POST-back with origin consent. | M |
| WW-3 | Send handoff deep link `#oamp-send?asset=<id>&to=<aid>&atoms=<n>`: opens the Send tab prefilled; the existing restricted-send review path takes over. (This is the SeqPal "Transfer button hands off to the wallet" hook.) | S |
| WW-4 | Price restricted rows and include them in the headline reference-currency total (1.5(a)). | S |
| WW-5 | Restriction legend + terms link + clawback/co-sign qualifier + frozen/eligibility status surfaces (1.5(c,d)); enable send-from-row (drop `movable:false`). | S |
| WW-6 | Restricted transfer history + pending/confirmation/anchor chips (1.5(b), 1.7). | M |
| WW-7 | QR for AID and enclave deposit address (1.4). | S |
| WW-8 | Fix the atoms encoding bug + add a contract test against a live/regtest openampd (1.6). | S |
| WW-9 | NOTED, separate workstream: the mnemonic sits plaintext in localStorage while wallet-link is marketed as the safer key home; at-rest encryption deserves its own pass. | L |

Ambra already derives m/5/0 and signs deterministically; its remaining duties are the UI-conformance surfaces (1.4, 1.5, 1.7) and eventually the card (1.8) in mobile form. Out of scope here.

### 1.10 Recovery story (what the seed does and does not restore)

From seed alone: m/5/0 -> AID -> idempotent re-registration (server record with categories and frozen state survives, `server.go:169-174`) -> balances re-queryable and spendable. NOT recoverable without the platform: category grants (platform-stamped only), platform identity/claims records, pending hosted transfers, document history. Lost-seed recovery is the platform's clawback-and-redeliver runbook; the wallet's duty is only to make a fresh AID registerable and linkable.

---

## Part 2. Venue specification (SeqDEX)

### 2.1 Objective

List restricted assets on the SeqDEX order book with policy-gated settlement, so eligible registered holders trade them against ordinary assets (for example USDX), while every restriction (eligibility categories, lockups, Reg S windows, per-AID vesting, holder caps, velocity, freeze) remains enforced by the policy server at settlement time, for the life of the asset.

### 2.2 Preconditions for any restricted-asset market

1. **Buyer registration:** the buyer must hold a registered AID BEFORE any fill can settle; restricted outputs may only pay registered enclaves; a plain wallet address cannot receive the asset at all.
2. **Buyer eligibility:** buyer categories (`GET /v1/users/{aid}`) must match asset rules (`GET /v1/assets/{id}`). Categories are stamped only by the platform; SeqDEX cannot grant them. An advisory preflight `GET /seqpal/api/eligibility?aid=&asset=` -> `{eligible, reasons[]}` is delivered by the SeqPal overhaul's M8; treat it as advisory and verify it is live before depending on it. The policy server's refusal at co-sign time is the gate.
3. **Listing authorization:** markets for restricted assets are issuer-authorized. seqpald exposes `GET /seqpal/api/listings` -> `[{asset, ticker, issuer_authorized, legend, terms_hash}]` (M8); the issuer grants it from their platform account; the venue checks at market creation. Display the restriction legend on the market page.
4. **Asset metadata:** use the Sequentia asset registry for display (ticker, name, precision, contract with the openamp block).
5. **Confidential assets are excluded:** `/v1/cosign` rejects confidential assets; do not list them (hosted-flow settlement only; atomic swap legs are transparent-asset-only).

### 2.3 Seller signing at fill time (the liveness model; design it first)

Enclave sighashes exist only AFTER `/v1/cosign` returns, because they depend on the final assembled transaction. Restricted-leg orders therefore CANNOT be pre-signed at rest: SeqDEX's resting-signed-intent model does not apply to the restricted side, and the seller must be reachable to sign at fill time. The settler MUST send the seller the full settlement transaction plus the prevouts, leaf script, and control block for each enclave input, never a bare digest: the seller's wallet recomputes the sighash and displays the real effects before signing (0.4(3)); a wallet that blind-signs a supplied digest can be drained. Two supported channels: (a) the wallet's enclave-spend signing surface (1.8), reached by pasting the settlement request in and copying the signature out, or (b) an authenticated SeqDEX client session the seller established, which presents the same decoded effects and signs on confirmation. Neither channel may be driven by an arbitrary-origin deep link with an auto-POST callback. If the seller is unreachable at match time, the fill fails cleanly: requeue or cancel per venue policy; never hold the buyer's funds against an unsignable settlement. At ORDER PLACEMENT, sellers prove control of the AID by signing a venue-issued challenge (tagged `"openamp-challenge-v1"`, 0.4(2)) with a pubkey registered to that AID, alongside a balance check via `GET /v1/users/{aid}/balance?asset=`.

### 2.4 Settlement model

Settlement of a fill is a single atomic swap transaction with a restricted leg and a payment leg, routed through `POST /v1/cosign` (`transfer.go:637-736`):

Request: `{"tx": "<full raw tx hex>", "asset": "<restricted asset id>", "sender_aid": "<seller aid>", "inputs": [<indices of the tx inputs that spend the seller's enclave>]}`.

The settler builds the transaction: inputs = seller's enclave UTXOs (restricted asset) + buyer's ordinary UTXOs (payment asset + fee); outputs = restricted asset to the BUYER'S REGISTERED ENCLAVE for this asset (script from `GET /v1/users/{aid}/address?asset=`), payment asset to the seller's ordinary address, changes, one explicit fee output. Constraints enforced by openampd: **the ENTIRE transaction must be transparent** (every output explicit asset and value, not only the restricted leg: `checkTransfer` rejects any confidential asset or value commitment anywhere in the tx, `transfer.go:42-47`), so the payment leg, all change, and the fee output must be unblinded; no restricted asset in any fee output; every restricted output must pay a registered user's enclave for this asset (OP_RETURN allowed only if the contract has burn_allowed); exactly one fee asset per transaction (Sequentia mempool rule); sender not frozen; every recipient not frozen and holding an allowed category; lockin/vesting/velocity/holder-cap/category-deny rules all apply. On approval, openampd returns policy signatures WITHOUT broadcasting: `{"sigs":[{"input","sighash","policy_sig","leaf","control"}]}`. The settler then: collects the seller's BIP340 signatures over each returned sighash (2.3), assembles enclave witness stacks as `[policy_sig, user_sig, leaf, control]` bottom to top, has the buyer sign their own payment/fee inputs normally, and broadcasts.

Known behaviors to design around: (a) a cosign writes a TransferRecord and a log entry EVEN IF the tx is never broadcast, and velocity counts it (`transfer.go:727-733`): do not cosign for quotes; (b) pending hosted-transfer state is irrelevant here (cosign is stateless); (c) prevouts are resolved mempool-inclusive (`getrawtransaction` with mempool), but policy checks (velocity, holder caps, balances) run against confirmed chain state, so settling from unconfirmed enclave outputs is discouraged; verify against `handleCosign`/`spentOutputs` before relying on either behavior.

### 2.5 Required openampd precondition (named explicitly)

**The `/v1/cosign` unclaimed-enclave-input containment fix (OA-7).** The comment at `transfer.go:671-673` promises that no unclaimed input may be an enclave output of this asset, but the current code validates only the CLAIMED inputs; there is no loop rejecting unclaimed enclave inputs. Confirmed unimplemented. It is fixed as the FIRST task of the SeqPal overhaul's M6. **Do not build settlement on `/v1/cosign` until this fix is confirmed deployed** (verify: a crafted tx with an enclave input outside the claimed set must be rejected).

**Mixed-asset tolerance.** Whether `checkTransfer` tolerates a foreign payment leg alongside the restricted leg in one transaction is settled by a regtest functional test in the node repo (feature_openamp_* pattern), added by the overhaul's M6. Reference that test; if it is not yet merged when SeqDEX work starts, replicate it first: build a two-asset transaction (restricted leg + explicit USDX leg + self-paid fee) on regtest and confirm cosign approval and broadcast.

### 2.6 Order lifecycle and gating

- **Order placement:** seller AID-control proof + balance check (2.3). Buyers pass the advisory preflight before their order rests; badge ineligible books "registration and eligibility required".
- **Fill:** re-run the preflight at match time; then settle per 2.4.
- **Refusal handling:** a 403 from `/v1/cosign` is a NORMAL outcome (eligibility expired, freeze landed, cap filled, vesting binds). Cancel or requeue, surface the reason verbatim to both parties, link the transparency-log entry, never retry a refused settlement unchanged.
- **Finality:** ecosystem 0-conf policy applies: nothing labeled final at 0-conf; min_anchor_depth is a per-offer dial (default 0); surface confirmations plus Bitcoin anchor depth like every other market; run the venue's own chain watcher for reorg regressions (0.5(6)).

### 2.7 Regulatory notes to carry into the venue (platform-layer controls, labeled)

The policy server enforces eligibility; the following are platform-layer records the venue surfaces or notes, not co-sign-enforced: (a) counterparty capture: both sides of every fill are identified registered AIDs resolvable to platform identities; retain fill records (travel-rule-style); (b) a market-abuse and insider-dealing acknowledgment is recorded by the platform before an investor's secondary trading is enabled; do not advertise restricted markets to accounts without it; (c) restrictions persist for the life of the asset: lockups, Reg S windows, per-AID vesting (the Rule 144 approximation stamped on US-tranche purchasers; the further US resale conditions of Section 4(a)(7) and Rule 904 are platform-layer records, so a co-sign approval is not a legal opinion on the resale), and per-category holder caps refuse fills at co-sign time; render these as market-page facts; (d) venue licensing: operating a matching order book in these securities with US-person participants raises Exchange Act exchange/ATS registration questions (Regulation ATS), and in the EU/UK the MTF/OTF perimeter; a production venue must gate participation accordingly or restrict access to jurisdictions it has analyzed; the demo venue carries this note on the market page as production analysis.

### 2.8 Structural exclusions (do not attempt)

- **Covenant CLOB:** the passive covenant order book ("the order is the coin") is structurally incompatible: the enclave leaf script is not a covenant order script, and wrapping one in the other would break the 2-of-2 policy model. Restricted assets use the active settler path only.
- **Lightning:** restricted assets cannot traverse Lightning (enclave co-signing is incompatible with LN channel outputs). LN may not serve the restricted side at all, and an LN payment leg cannot be part of a single atomic on-chain settlement; treat LN as out of scope.

### 2.9 Venue API touchpoints (essentials)

- `POST /openamp/v1/users` `{pubkeys:[x-only hex]}` -> `{aid}`. Public, idempotent.
- `GET /openamp/v1/users/{aid}` -> `{aid, pubkeys, categories[], frozen}`. Public. `categories`/`frozen` are omitted when empty/false: default them.
- `GET /openamp/v1/users/{aid}/address?asset=` -> enclave script + leaf/control blocks. Public.
- `GET /openamp/v1/users/{aid}/balance?asset=` -> `{atoms, utxos}`. Confirmed only. Public.
- `GET /openamp/v1/assets/{id}` -> full record incl. rules and contract (legend, terms_hash). Public.
- `POST /openamp/v1/cosign` -> policy sigs per 2.4. Public, 403 on refusal, logs even without broadcast.
- `GET /openamp/v1/log` -> transparency log. Public.
- `GET /seqpal/api/eligibility?aid=&asset=` -> `{eligible, reasons[]}`. Advisory (M8).
- `GET /seqpal/api/listings` -> `[{asset, ticker, issuer_authorized, legend, terms_hash}]`. Listing gate (M8).
- Explorer: `https://sequentiatestnet.com/tx/{txid}`, `/asset/{id}`; `/prices` for reference display.

---

## Part 3. Conformance checklists

**A wallet conforms when:** it derives the m/5/0 identity and passes the AID and signature test vectors (SWK-T); registers idempotently with the local-AID assertion; shows per-asset enclave receive (AID + address + QR, blech32 as opt-in confidential); shows confirmed enclave balances as ordinary rows priced into the headline total, with legend/terms/lockup/custody-qualifier detail and frozen/eligibility status; completes a hosted send end to end (recomputing every sighash locally and displaying decoded effects before signing, refusing on mismatch) with verbatim 403 surfacing and pending/confirmation/anchor chips; hosts the two-mode tagged sign card (no raw-digest mode anywhere) with consent-gated transport; restores everything key-derived from seed alone.

**A venue conforms when:** it lists only issuer-authorized restricted markets with the legend displayed; gates placement on AID-control proof and balance; treats preflights as advisory and 403s as normal outcomes surfaced verbatim with log links; settles per 2.4 only after OA-7 is confirmed deployed and the mixed-asset proof exists; sends sellers full transactions plus prevouts/leaf/control, never bare digests; never labels anything final at 0-conf; retains counterparty fill records; carries the 2.7 regulatory notes on market pages.

## Part 4. Dependency summary

| Dependency | Where | Blocks |
|---|---|---|
| OA-7 cosign containment fix | openampd (SeqPal overhaul M6, first task) | all venue settlement (2.4) |
| Mixed-asset regtest proof | node repo (M6) | venue settlement confidence (2.5) |
| Sign card + enclave-spend signing surface | sequentia-web-wallet (M5; WW-2) + SWK-6 | venue seller channel (a); platform wallet-link |
| Eligibility + listings endpoints | seqpald (M8) | venue preflight + listing gate (2.2) |
| SWK-1..4 | SWK | wallet conformance (Part 1); SWK-4 also unblocks registry verification of OpenAMP assets |
| m/5/0 migration (WW-1) | sequentia-web-wallet | the sign card must NOT ship on the m/3/0 key |
