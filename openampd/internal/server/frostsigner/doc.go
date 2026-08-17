// Package frostsigner is the threshold (FROST) backend skeleton for the
// PolicySigner seam in package server. It is scaffolding: the types compile,
// implement the interface, and refuse honestly until a real implementation and
// its transport land. Nothing wires it into server.New yet.
//
// # Design
//
// The committed production shape is 2-of-3 FROST over secp256k1:
//
//   - The FROST GROUP public key IS the on-chain policy key. Enclave scripts
//     stay `<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG` with a single x-only
//     key, so nothing about enclaves, contracts or issued assets changes when
//     the backend swaps in — exactly the property the PolicySigner seam exists
//     to protect.
//
//   - GeneratePolicyKey runs the DKG (distributed key generation) across the
//     three members at provision time and returns the group public key. No
//     member ever holds the full private key; the ref identifies the DKG
//     session until Adopt binds it to the derived asset id.
//
//   - Resharing rotates members WITHOUT changing the group key: a new share set
//     for a (possibly different) member set is derived such that the same group
//     public key verifies. That is why the quorum lives off-chain behind this
//     seam rather than as an on-chain k-of-n multisig — the signer set and
//     threshold can change over an asset's life with no chain migration of
//     holders' funds.
//
//   - SignPolicy fans the sighash out to the quorum members over an internal
//     transport (mutually authenticated; members may be separate processes,
//     hosts, or HSMs), runs the two-round FROST signing protocol with any t=2
//     of the n=3 members, and aggregates into one 64-byte BIP340 signature
//     that verifies under the group key. The PolicyContext travels with the
//     request so each member can log, rate-limit, or veto what it is signing
//     (a clawback sweep is not a routine transfer co-signature); the context
//     is advisory and never contributes signature bytes.
//
// # Status
//
// Not configured, deliberately: every method returns ErrNotConfigured. The
// compile-time assertion in frostsigner.go keeps this package honest against
// interface drift in package server.
package frostsigner
