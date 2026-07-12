# Followup: atomic BTC to restricted-asset swaps via adaptor signatures

**This is a followup to `spec/venue-wallet-integration.md`, section 2.4b.** It specifies the "true atomicity" path that 2.4b names as an open design item. Read 2.4b first; this document assumes its vocabulary (enclave, AID, `/v1/cosign`, the 2-of-2 transfer leaf, why a restricted leg can never sit in an HTLC output). Audience: the agent building SeqDEX restricted-asset markets and the SWK/wallet work behind them. Status: a design specification to implement, not yet built. Every openampd claim carries a code reference into `~/openamp/openampd`.

The goal: a buyer holding native Bitcoin (parent chain, testnet4) acquires a SeqPal-managed restricted asset in a trade that is atomic (either both legs happen or neither), with no trusted swap escrow, no change to the enclave script, and eligibility still enforced by the policy server. Payment is orthogonal to eligibility: the policy server constrains who may hold the asset, never what the buyer paid with.

Sections 1 through 10 specify the on-chain BTC case and were adversarially verified. Section 11 extends the same machinery to Lightning BTC over a hold-invoice bridge, because a SeqDEX normally lets Lightning buy unrestricted assets and buyers will expect the same for restricted ones; the asset leg is the stable primitive and the BTC leg is the pluggable rail. Section 12 is the open questions.

---

## 1. Why this is not an HTLC swap, and what replaces the hashlock

A restricted asset may only ever land on a registered enclave scriptPubKey (`transfer.go:62`, "restricted asset to an out-of-enclave destination"; OP_RETURN burn is the only other legal form). A hash-locked output is not an enclave, so the classic BTC-against-ordinary-asset HTLC swap cannot carry the restricted leg. Adaptor signatures replace the hashlock: they need no script support at all, so the enclave script is untouched and the coupling lives entirely in the signatures.

**The key enabler, unique to this architecture.** An enclave spend needs two BIP340 signatures over the same taproot sighash: the holder's user signature and the policy signature. `POST /v1/cosign` already returns the policy signature for a specific, fully-formed transaction WITHOUT broadcasting (`transfer.go:722-735`), and openampd computes it as a normal signature over the input's sighash (`transfer.go:712-724`, `SignPolicy` at `signer.go:106`). So the adaptor lock can be applied to the USER signature only; the policy signature is an ordinary signature the network verifies against `K_policy` in the leaf. Nothing about adaptor signatures is visible to consensus or to openampd: the completed user signature is a plain BIP340 signature, which is exactly what `<K_user> CHECKSIGVERIFY` expects.

Both chains use Schnorr, so both legs use BIP340 Schnorr adaptor signatures uniformly (no ECDSA adaptor on the Bitcoin side). This is a NEW, un-vendored, security-critical primitive: the `secp256k1-zkp` version SWK currently vendors (0.11.0) exposes only an ECDSA adaptor module, and the Sequentia enclave leg is BIP340, which an ECDSA adaptor cannot serve. A BIP340 Schnorr adaptor (sign, complete, extract, verify) must therefore be either built in-house on top of the vendored `schnorrsig` and point/scalar operations, with careful handling of the BIP340 nonce parity and negation (which also governs whether `extract(b, b̂)` actually recovers `t`), and independently audited; or obtained by upgrading to a `secp256k1-zkp` release that ships a `schnorr_adaptor` module. Do not build on the assumption that the primitive already exists. See section 8.

---

## 2. The construction

### 2.1 Roles and the single secret

- **Buyer** holds BTC, wants the asset. Must already be a registered, eligible AID (eligibility is checked at cosign time, section 4).
- **Seller** holds the asset in their enclave, wants BTC.
- **Secret** `t` with adaptor point `T = t*G`. The buyer generates `t` and reveals it by claiming the asset, but only after the gated exchange of 2.3 has given the seller a verified BTC-leg presignature; the ordering is what makes the reveal safe for the seller.

### 2.2 The two legs

- **TX_asset** (Sequentia): spends the seller's enclave UTXO, delivers the asset to the buyer's enclave (plus a seller change enclave output if needed, plus an explicit fee input and output in an ordinary Sequentia asset, since cosigned transactions are self-fee-paid, 2.4). Its enclave input needs the seller's user signature and the policy signature. All outputs must be transparent and enclave-shaped (2.4).
- **TX_pay** (Bitcoin): spends the buyer's BTC funding output, pays the seller. Its input needs the buyer's signature.

### 2.3 Adaptor coupling, and the exchange ordering that makes it safe

The coupling: the buyer generates `t` and can complete the seller's asset-leg adaptor signature `b̂` to a valid user signature `b = complete(b̂, t)`; the seller cannot complete the buyer's BTC-leg adaptor signature `â` until `t` becomes public, which happens when the buyer's completed `b` lands on-chain (the seller then computes `t = extract(b, b̂)`).

The ORDER of exchange is load-bearing, not cosmetic. The buyer already holds `t`, so if the buyer ever holds `b̂` before the seller holds a verified `â`, the buyer can claim the asset and simply never hand over `â`: the seller would then know `t` but have no presignature to complete over the buyer's key, and the seller gets neither the BTC nor a claim. The setup therefore proceeds strictly in this order, and each gate is a normative wallet rule:

1. Buyer and seller agree on TX_asset (delivers the asset to the buyer) and TX_pay (pays the seller in BTC).
2. Buyer funds the BTC output: a P2TR output spendable by the seller path (the completed `a = complete(â, t)`) OR by the buyer after `CLTV = T_btc_refund`. The buyer waits for this funding output to CONFIRM.
3. Buyer sends the seller `T` and the BTC-leg adaptor signature `â`.
4. Seller GATES on all of: `adaptorVerify(K_buyer, tx_pay_sighash, T, â)` passes; TX_pay pays the agreed amount to the seller; the funding output is on-chain and confirmed with the seller path spendable only via `complete(â, t)`. Seeing the TX_pay template is not enough; the seller must hold a verified `â` over a confirmed output. Only if every check passes does the seller proceed.
5. Seller places the reservation (section 6) on the enclave UTXO for the exact TX_asset, and only now releases the asset-leg adaptor signature `b̂` to the buyer.
6. Buyer completes `b = complete(b̂, t)`, requests the claim-time policy cosign for the reserved TX_asset (section 3), assembles the witness `[policy_sig, b, leaf, control]` bottom to top (2.4), broadcasts TX_asset, receives the asset. The completed `b` is now on-chain.
7. Seller extracts `t = extract(b, b̂)`, completes `a = complete(â, t)`, broadcasts TX_pay, receives the BTC, before `T_btc_refund` (this is a real seller-liveness duty, section 5).

Atomicity, given this ordering: the buyer cannot obtain the asset without publishing `b`, which reveals `t`; and the seller, having gated on a verified `â` over a confirmed funding output, can always complete `â` with that `t`. If the buyer never claims, `t` is never revealed, the seller cannot complete `â`, and both parties keep their original coins (subject to the refund paths and the seller-liveness caveat in section 5). No third party holds funds or learns the swap secret.

---

## 3. Two problems the naive version has, and the design that removes them

If the seller obtains the policy signature at SETUP time and hands the whole bundle to the buyer, two real defects follow, both verified in code:

1. **Velocity pollution and griefing (Problem A).** Every `/v1/cosign` writes a velocity-counted `TransferRecord` with `Height: -1` (`transfer.go:729-731`), and the velocity window counts records with `rec.Height < 0` indefinitely (`transfer.go:123`). A cosign for a swap that is never broadcast therefore consumes the seller's velocity budget forever and can be used to grief a seller's own future transfers.
2. **Encumbrance with no revocation (Problem B).** Once the buyer holds `b̂` plus the policy signature, the buyer can broadcast TX_asset at any time. The policy server cannot revoke a signature it already issued. The seller's only cancel is to double-spend their own enclave UTXO (a self-transfer, itself needing a cosign), which races the buyer's broadcast.

**Recommended design: cosign at CLAIM time, not setup, with a policy-server reservation.** Do not obtain the policy signature during setup. Instead:

- At setup the seller places a time-boxed RESERVATION on the enclave UTXO (section 6). openampd records it and, until the deadline, refuses to cosign any spend of that UTXO other than the exact reserved TX_asset. This gives the buyer a guaranteed claim window and removes the double-spend race away from the deadline boundary.
- At claim time the buyer (the transaction is public; cosign is a public endpoint, 2.9) requests the policy signature for the exact reserved TX_asset. openampd cosigns it only before the deadline. Eligibility, freeze, lockup, holder-cap, and velocity are all checked fresh at this moment (`checkTransfer`, `transfer.go:20`).
- The reservation is LATCHED, which closes the boundary race. The instant openampd cosigns the reserved TX_asset, it marks the outpoint CONSUMED and will never cosign a reclaim of it, even after the deadline. Without this latch there is a real hole: a TX_asset cosigned at `deadline - 1` remains broadcastable while the seller obtains a reclaim cosign at the deadline, and if the reclaim wins the mempool race the seller regains the asset AND, using the now-public `t`, completes `â` to also take the BTC, so the buyer loses principal. A stuck-but-still-owned enclave UTXO (if the buyer cosigns but never broadcasts) is an acceptable griefing outcome; a buyer losing principal is not. The reclaim path therefore opens ONLY for reservations that expired with no claim cosign ever issued.

This resolves both problems. Problem A disappears because a cosign (and its velocity-counted record) happens only when the buyer actually claims, so abandoned swaps cost nothing. Problem B disappears because the policy server, not a mempool race, arbitrates the mutually exclusive outcomes (a claim cosign latches the outpoint consumed; a reclaim is possible only after expiry with no claim): every enclave spend needs the policy co-signature, so the policy server can enforce the timelock the scriptless enclave cannot. This is the elegant part: openampd supplies the refund-timelock semantics the enclave leaf lacks.

The cost is a modest, well-contained openampd feature (section 6), a claim-time liveness requirement on the always-online policy server, and one genuine counterparty-liveness duty that remains on the seller: after `t` is revealed, the seller must claim the BTC within their window (section 5). The claim-time-cosign design removes the ENCUMBRANCE and velocity problems; it does not remove the seller's need to be online to collect once the asset has moved.

---

## 4. Eligibility, still enforced

At the claim-time cosign, `checkTransfer` runs against confirmed chain state: the buyer (recipient) must be a registered AID holding an allowed category, not frozen, and TX_asset must satisfy lockup, vesting, velocity, holder-cap, and category-deny rules (`transfer.go:20-167`). A swap to an ineligible buyer is refused at claim, exactly as any transfer would be. So a buyer must complete SeqPal ID registration and hold the right category before the swap can settle, and the swap inherits every restriction the asset carries. The BTC payment changes none of this.

**Abort branch: seller frozen mid-swap.** If the SELLER is globally frozen between reservation and claim, the buyer's claim cosign 403s ("sender frozen", `transfer.go:21`) and the seller cannot reclaim either, because a reclaim is a self-transfer and hits the same frozen-sender check. The asset is stuck in the enclave until the freeze lifts. No principal is lost (the buyer's BTC refunds at `T_btc_refund` since `t` never revealed), but the seller's UTXO is immobilized meanwhile; the venue should surface this state rather than present it as a silent hang.

---

## 5. Timelocks and the refund matrix

The BTC leg can carry native timelocks; the enclave leg cannot (its leaf is a fixed 2-of-2 with no timelock branch), which is why the policy-server reservation stands in for the enclave-side timelock.

- **Buyer's BTC funding output** is a P2TR output spendable by (seller path: the completed adaptor signature `a`) OR (buyer refund: buyer's key after `CLTV = T_btc_refund`). If the swap never completes, the buyer reclaims their BTC after `T_btc_refund`.
- **Seller's enclave UTXO** has no script timelock. The reservation deadline `T_resv` plays that role: before `T_resv` only the reserved TX_asset is cosignable; the reclaim opens only if `T_resv` passes with no claim cosign ever issued (section 3's latch). `T_resv` must be enforced against the ANCHORED Bitcoin height the Sequentia chain has committed to, NOT the raw Sequentia block height. This matters: Sequentia block production can stall (a documented condition), and anchoring couples reorgs, not block rate, so a `T_resv` keyed to raw Sequentia height would drift against Bitcoin wall-clock. During a stall a buyer could still be under `T_resv` in Sequentia height while `T_btc_refund` (a Bitcoin height) has already elapsed, claim the asset, and then also reclaim the BTC, taking both. Keying `T_resv` to anchored Bitcoin height keeps the two deadlines on one clock.

**Ordering.** Both deadlines are expressed in Bitcoin height so they move together. The buyer reveals `t` by claiming the asset before `T_resv`; the seller then claims BTC before `T_btc_refund`. Set `T_btc_refund` comfortably after `T_resv` so that, in the worst case where the buyer claims just before `T_resv`, the seller still has ample time to extract `t`, wait for adequate anchor depth on the reveal (section 7), and confirm TX_pay. The margin must cover Bitcoin confirmation time plus the anchor-depth buffer of section 7.

**Residual risks, disclosed not hidden.** Two genuine loss cases exist; neither is a pure "each side refunds" case, and the venue must surface both:

1. **Seller offline past the window.** The buyer holds a timing option (they choose when to reveal within `[setup, T_resv)`). If the buyer reveals `t` near `T_resv` and the seller is offline or slow, the buyer can wait past `T_btc_refund`, reclaim the BTC via the CLTV path, AND keep the already-claimed asset. The seller loses the asset. So the seller has a hard liveness duty (section 8): watch Sequentia for the reveal and get TX_pay confirmed before `T_btc_refund`. A mis-set margin or an offline seller loses the seller principal, not merely a race.
2. **Reveal-window reorg** (section 7): a low-probability but nonzero principal-loss case.

The margin between `T_resv` and `T_btc_refund` is a safety parameter, not a default, and must also dominate the maximum plausible Sequentia stall.

---

## 6. Required openampd feature: the swap reservation (OA-SWAP)

A new, optional openampd capability. Without it the swap still works via the degraded setup-time-cosign protocol, but with the Problem A and Problem B risks of section 3; with it the swap is clean. Fold it into the SeqPal overhaul's openampd change list as OA-SWAP (owner: whoever owns openampd; the SeqDEX agent depends on it but does not build it).

- `POST /v1/swap/reserve` (public; the seller proves control by signing a challenge with the enclave user key, as at order placement, 2.3): `{asset, seller_aid, outpoint, tx_asset_hex, deadline_anchor_height}`. openampd validates that `tx_asset_hex` spends exactly `outpoint` (the seller's enclave UTXO), that `outpoint` is confirmed-unspent and has NO other active reservation (reject overlapping reservations on one outpoint, which would otherwise let a seller oversell the same UTXO to two buyers), runs `checkTransfer` on it (so an ineligible or rule-violating swap is rejected at reservation, before any BTC is locked), records a reservation binding `outpoint` to `sha256(tx_asset_hex)` until `deadline_anchor_height` (a Bitcoin anchor height, section 5), and returns a reservation id. Idempotent per `(outpoint, tx_hash)`, but a DIFFERENT tx_hash on an already-reserved outpoint is rejected, not accepted as a second reservation.
- **While reserved and before the deadline**, openampd refuses to cosign any spend of `outpoint` other than the exact reserved transaction (`handleCosign` gains a reservation check alongside its existing claimed-input validation, the loop over `req.Inputs` at `transfer.go:676-686`).
- **On cosigning the reserved TX_asset**, openampd marks `outpoint` CONSUMED and will never cosign a reclaim of it, even after the deadline (the latch of section 3, which closes the boundary race).
- **At the deadline with no claim cosign issued**, the reservation expires and the seller may cosign a reclaim of `outpoint`. Because a reservation is not a signature, letting it expire is safe; openampd never issued a signature it must revoke.
- Reservations are visible in the transparency log (reserve, claim/consume, expire) so both parties and auditors can follow the swap, consistent with the log-anchoring model.
- No held funds, no swap secret, no custody: openampd only decides which of two mutually exclusive spends of an already-restricted UTXO it will cosign, by deadline and latch. This is strictly less power than it already has over every enclave spend.
- **Precondition:** this rides `POST /v1/cosign`, so the OA-7 unclaimed-enclave-input containment fix (companion spec 2.5, confirmed unimplemented: the promise at `transfer.go:671-673` is only a comment, the code loops over claimed inputs at `transfer.go:676-686` with no rejection of unclaimed enclave inputs) is a precondition here too. Do not deploy swap settlement before OA-7.

**Interaction with velocity (fixes Problem A precisely).** With claim-time cosign, the velocity-counted `TransferRecord` is written only on the real claim (`transfer.go:729`), so an abandoned or expired reservation never touches velocity. Do not write a velocity record at reservation time.

---

## 7. Reorg interaction (a low-probability principal-loss window)

Sequentia anchoring couples DEEP reorgs: every Sequentia block references a Bitcoin header, and an anchor-final Sequentia block does not reorg unless Bitcoin reorgs below its anchor. This partly helps a cross-chain swap, because a deep Bitcoin reorg tends to unwind both legs together rather than one in isolation. But it is not a full guarantee, and the naive "mostly a friend" reading is wrong in one specific window.

The danger: `t` is revealed at TX_asset's 0-conf, exactly when the asset claim is maximally reversible, yet `t` is public the instant the claim is seen. Two Sequentia blocks can share the same Bitcoin anchor and be resolved by Sequentia's own finality (compare the finality-split condition), so a SHALLOW, same-anchor Sequentia reorg is possible and is not prevented by anchoring. A seller who claims BTC immediately after seeing `t` at 0-conf, before TX_asset is anchor-final, benefits if a shallow reorg then restores the asset to the seller: the seller keeps the asset and has taken the BTC, and the buyer loses both. The buyer cannot prevent this by construction, because their claim (and thus the reveal) has already happened; they can only choose not to rely on the asset until it is anchor-final.

So the residual is a low-probability principal-loss case, not zero. Mitigations, all of which reduce probability rather than eliminate it: gate "settled" on Bitcoin ANCHOR depth on BOTH legs (never on Sequentia confirmations alone, and never label anything final at 0-conf, a standing first principle); set `T_btc_refund` beyond that anchor depth with margin; and have the honest seller wait for anchor depth on the reveal before claiming BTC (a discipline the buyer cannot enforce, so the venue should encode it in the reference settler rather than leave it to seller goodwill). The venue surfaces anchor depth for both legs, as it does for every restricted market (2.6), and states this residual plainly.

---

## 8. What SWK and the wallet must provide

Beyond the Part 1 wallet conformance in the main spec:

- **BIP340 Schnorr adaptor-signature primitives** in SWK: `adaptorSign(privkey, sighash, T) -> â`, `adaptorComplete(â, t) -> sig`, `adaptorExtract(sig, â) -> t`, and `adaptorVerify(pubkey, sighash, T, â)`. This is a NEW, un-vendored, security-critical primitive (section 1): the vendored `secp256k1-zkp` 0.11.0 exposes an ECDSA adaptor only, and the BIP340 enclave leg cannot use it, so this must be built in-house on the vendored `schnorrsig` and point/scalar operations, with correct BIP340 nonce parity and negation (the parity handling is what makes `adaptorExtract` actually recover `t`), and independently audited, OR obtained by upgrading to a `secp256k1-zkp` release shipping a `schnorr_adaptor` module. Expose it through lwk_wasm and (later) lwk_bindings, deterministic where the base signer is (0.4(4)). Conformance vectors: adaptor sign/complete/extract round-trip; `adaptorVerify` accepts a valid `â` and rejects a tampered one; and a completed adaptor signature verifies byte-identically to a normal BIP340 signature under the same key and message (so consensus cannot tell them apart).
- **`adaptorVerify` as the release gate (normative).** Per section 2.3, the seller MUST NOT create or release `b̂` until it has run `adaptorVerify(K_buyer, tx_pay_sighash, T, â)` to success AND confirmed TX_pay pays the agreed amount AND confirmed the buyer's BTC funding output is on-chain. Holding the TX_pay template is not sufficient; the seller must hold a verified `â` over a confirmed output.
- **Swap-aware effect display.** The enclave-spend signing rule (0.4(3)) still binds: the SELLER, when creating `b̂`, must recompute TX_asset's sighash from the transaction and prevouts and display what it spends (their asset out); the BUYER, before broadcasting, verifies TX_asset delivers to their own enclave. Neither party ever blind-signs a bare digest, and an adaptor signature is not an exception: it commits to a specific transaction just as a normal signature does.
- **Seller claim liveness (loses principal if neglected).** After the buyer reveals `t` (TX_asset seen on Sequentia), the seller's wallet MUST watch for the reveal, extract `t`, and get TX_pay confirmed before `T_btc_refund` (and, per section 7, ideally wait for anchor depth on the reveal first). This is the one counterparty-liveness duty the design does not remove: a seller that fails it can lose the asset while the buyer refunds the BTC (section 5).
- **Refund-path management**: the buyer's wallet must track `T_btc_refund` and reclaim on timeout; the seller's wallet must track `T_resv` and reclaim the enclave UTXO after expiry if the buyer never claimed.

The venue (SeqDEX settler) orchestrates the message flow (reservation, funding-output creation, adaptor-signature exchange, deadlines) but never holds either party's key and never learns `t`.

---

## 9. Acceptance criteria

1. A regtest end-to-end swap: buyer with testnet4 BTC and an eligible SeqPal ID acquires a restricted asset from a seller; a single secret couples the two legs; the buyer's asset claim reveals `t`; the seller claims BTC with the extracted `t`; both explorer transactions resolve, and eligibility was enforced at the claim cosign.
2. Abort paths, each proven: buyer never claims (buyer refunds BTC at `T_btc_refund`, seller reclaims the enclave UTXO after `T_resv`, no velocity consumed); ineligible buyer (claim cosign returns 403, BTC refunds).
3. OA-SWAP reservation proven: while reserved, a conflicting cosign of the reserved UTXO is refused; after the deadline, the reserved TX_asset is refused and the seller's reclaim is cosigned.
4. Adaptor-signature conformance vectors pass, and a completed adaptor signature is byte-indistinguishable from a normal BIP340 signature to consensus.
5. Reorg behavior documented and, on regtest, a Bitcoin reorg that unwinds the BTC leg is shown to correlate with the Sequentia leg per anchoring; "settled" is gated on Bitcoin anchor depth.
6. Lightning hold-invoice rail (section 11) proven on regtest with SeqLN: the seller's secret doubles as the Schnorr scalar and the Lightning preimage; the seller settling the invoice reveals the secret and the buyer claims the asset before the reservation deadline; the abort path (seller never settles) times out the held Lightning payment and expires the reservation. The buyer-eligibility-lapse case (11.2) is exercised and its chosen mitigation is proven.

## 11. Lightning BTC as the payment rail

A SeqDEX normally lets Lightning BTC buy unrestricted Sequentia assets through a submarine swap: the unrestricted asset sits in an on-chain HTLC that shares one hash with the Lightning payment, so paying the invoice reveals the preimage that unlocks the asset. That exact trick is unavailable for a restricted asset, for the same reason section 1 gives: the asset can never sit in a hash-locked output. The hold-invoice bridge below carries Lightning BTC instead, reusing the asset-leg primitive unchanged: the seller adaptor-signs their enclave user-half under point `T`, and the buyer completes it with the secret `t` (where `T = t*G`) and claims the asset before the reservation deadline (section 6). What differs from the on-chain case is only how the secret is generated and revealed.

### 11.1 The hold-invoice bridge

Lightning today locks payments to a hash preimage, not to a curve point, so the discrete-log adaptor secret and the Lightning secret must be the same 32 bytes. Generate `t` as a valid secp256k1 scalar (`t < n`, overwhelmingly the default) and use it twice: as the Schnorr adaptor scalar (`T = t*G`) and as the Lightning preimage (`H = sha256(t)`). Lightning's payee reveals the secret, so here the SELLER generates `t` and reveals it by settling the payment. This flips the on-chain role assignment (there the buyer generates `t`), which changes the risk profile, so read 11.2 before building.

Flow:

1. Seller reserves the enclave UTXO (OA-SWAP, section 6) for the exact TX_asset that delivers to the buyer, and gives the buyer the adaptor signature `b̂` for the seller's user-half under `T = t*G`. Handing `b̂` over early is safe in this direction, unlike the on-chain case, because the buyer does NOT hold `t` and cannot complete `b̂` until the seller settles (2.3's ordering hazard is a buyer-holds-`t` hazard, absent here).
2. Seller issues a Lightning HOLD invoice locked to `H = sha256(t)`.
3. Buyer pays the invoice; the payment is held in-flight along the route, not yet captured.
4. Seller settles the invoice by releasing `t`, capturing the BTC. The preimage `t` propagates back along the route to the buyer.
5. Buyer now knows `t`, completes `b̂`, requests the claim-time policy cosign for the reserved TX_asset (before the reservation deadline), assembles the witness, broadcasts, and receives the asset.

Timelock coordination mirrors section 5 with the roles flipped: the SELLER now holds the timing option (they choose when to settle within the hold window), so `T_resv` must sit safely after the latest the seller can settle the Lightning HTLC, with margin for the buyer to then claim on-chain: `T_resv > (Lightning HTLC timeout) + (buyer on-chain claim margin)`, expressed in Bitcoin anchor height (section 5). A hold invoice ties up channel liquidity and, if held near the HTLC timeout, risks a force-close, so bound the hold duration well inside the channel timeouts. SeqLN supports hold invoices (they already back the instant-swap buy path), so no new Lightning capability is required, only this coupling.

### 11.2 The Lightning-specific principal-loss risk (buyer eligibility lapse), and how to bound it

The seller-reveals direction has an exposure the on-chain buyer-reveals direction does not, and it must not be glossed. The seller captures the buyer's BTC by settling the invoice, and only AFTER that does the buyer claim the asset. If the buyer's eligibility lapses between paying the invoice and claiming (most plausibly a freeze, or a category expiry), the claim-time cosign 403s, and the buyer has lost the BTC (a settled Lightning payment cannot be clawed back) without receiving the asset. On-chain this cannot happen, because there the buyer claims first, so an ineligible buyer's claim simply fails before any BTC moves.

This is a real principal-loss case, not a timing race. Two ways to bound it, and the venue must choose and disclose one:

1. **Short window plus disclosure (no new openampd work).** Keep the interval between invoice payment and claim small, re-check the buyer's eligibility (`GET /v1/users/{aid}`, and the advisory preflight) immediately before the buyer pays, and disclose on the market page that a Lightning purchase carries a small residual risk if the buyer is frozen in the window. Freezes are issuer or platform actions taken for cause and are rare, so the residual is low, but it is nonzero and the buyer bears it.
2. **Reservation pins recipient eligibility (an openampd choice).** Extend OA-SWAP so the reservation locks in the recipient's eligibility as validated at reserve time, and the claim-time cosign of the exact reserved TX_asset honors that validation rather than re-checking the recipient. This removes the buyer's exposure but weakens the "freeze is immediate and global" property for a reserved swap in flight, which is a genuine policy tradeoff for whoever owns openampd to decide. Flag it as an open question (section 12), do not assume it.

Until one is chosen, the honest default is option 1 with the risk stated plainly.

### 11.3 What is shared, and what still needs verifying

Eligibility is enforced at the claim-time cosign regardless of rail (section 4): a Lightning-paying buyer must still be a registered, eligible SeqPal ID holder. Reorg exposure: the Lightning BTC leg settles off-chain, so it is not directly subject to a Bitcoin reorg, but the Sequentia asset claim is still anchored to Bitcoin, so the buyer must still gate "asset received" on Bitcoin anchor depth (section 7). The OA-SWAP reservation (with its consumed-latch) and the SWK adaptor-signature primitives (sections 6 and 8, including that the BIP340 Schnorr adaptor is a new in-house primitive, NOT vendored) are shared with the on-chain case; the only Lightning-specific additions are the hold-invoice coupling and the eligibility-lapse handling of 11.2. Because the on-chain construction was adversarially verified but this Lightning direction was specified afterward, it warrants its own adversarial verification pass (with attention to the settle-timing and eligibility-lapse cases) before it is built.

## 12. Open questions for the implementing agent

1. OA-SWAP ownership and timing: it is an openampd change outside the SeqDEX/SWK repos. Build the degraded setup-time-cosign version first (documenting its Problem A and B exposure on the market page) and depend on OA-SWAP for the clean version, or wait for OA-SWAP?
2. Fee funding for TX_asset: the buyer supplies a small ordinary-Sequentia-asset fee input (they need a little of a Sequentia fee asset even when paying in BTC), or the seller funds the Sequentia fee out of proceeds, or fee-conversion is offered. Pick one and state it in the market UI.
3. Multi-input seller enclaves: if a swap spends more than one seller enclave UTXO, the reservation and adaptor signatures cover each; confirm the batching and the per-input adaptor exchange.
4. Deadline margin: both deadlines are pinned to Bitcoin anchor height (section 5, resolving the earlier open question). What remains is to set the concrete safety margin between `T_resv` and `T_btc_refund`: it must dominate the maximum plausible Sequentia stall AND the anchor-depth buffer of section 7. Pin a conservative default with a rationale.
5. Whether the venue offers this only between two live wallets, or also supports a resting-order form where the seller pre-authorizes a reservation for a quoted price (note that a reservation ties up the seller's UTXO for its duration, so resting swap-orders have an inventory cost).
6. Lightning eligibility-lapse mitigation (11.2): ship option 1 (short window plus disclosure, no openampd change, buyer bears a small residual freeze risk) or option 2 (extend OA-SWAP to pin recipient eligibility at reserve time, removing the buyer's exposure but weakening immediate-global-freeze for an in-flight reserved swap)? This is a policy call for whoever owns openampd; state the choice and disclose the residual honestly per 2.4b.
