// Package frostsigner is the threshold (FROST) backend for the PolicySigner
// seam in package server: a working 2-of-3 (t-of-n configurable) threshold
// Schnorr signer whose aggregate signatures are ordinary BIP340 signatures
// under the group x-only key.
//
// # Design
//
//   - The FROST GROUP public key IS the on-chain policy key. Enclave scripts
//     stay `<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG` with a single x-only
//     key, so nothing about enclaves, contracts or issued assets changes when
//     the backend swaps in — exactly the property the PolicySigner seam exists
//     to protect.
//
//   - Keygen is TRUSTED-DEALER Shamir (the testnet posture): the dealer
//     samples the group secret, splits it into n shares at x = 1..n over the
//     secp256k1 order, and discards the polynomial. A DKG replaces the dealer
//     later — no party ever holds the whole secret — without changing the
//     seam, the key-storage shape, or the group-key concept.
//
//   - Signing follows FROST's two-round structure (run in-process here): each
//     participant commits to a hiding and a binding nonce (D_i, E_i), the
//     binding factor rho_i ties the second nonce to the message and the full
//     commitment list, R = sum(D_i + rho_i*E_i), and Lagrange-weighted partial
//     signatures s_i = k_h + rho_i*k_b + e*lambda_i*d_i are individually
//     verified against public data before aggregation. The BIP340 parity
//     adjustments (even-Y R via nonce negation, even-Y P via share negation)
//     are documented at the top of frost.go — they are where threshold Schnorr
//     implementations silently break.
//
//   - Resharing rotates members WITHOUT changing the group key, which is why
//     the quorum lives off-chain behind this seam rather than as an on-chain
//     k-of-n multisig (that would bake the signer set into every enclave
//     address).
//
//   - The PolicyContext travels with every SignPolicy request so each member
//     can see (log, rate-limit, or veto) what it is signing — a clawback sweep
//     is not a routine transfer co-signature. It is advisory and never
//     contributes signature bytes.
//
// # Selection
//
// The backend registers itself as "frost" for the daemon's -signer flag
// (OPENAMPD_SIGNER); "local" (the single-key LocalKeySigner) stays the
// default. Assets provisioned under local keep working when frost is selected:
// the backend falls back per asset when no FROST share set exists.
package frostsigner
