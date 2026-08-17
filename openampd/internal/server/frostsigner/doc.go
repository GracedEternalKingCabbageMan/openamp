// Package frostsigner is the threshold (FROST) backend for the PolicySigner
// seam in package server: a working 2-of-3 (t-of-n configurable) threshold
// Schnorr signer whose aggregate signatures are ordinary BIP340 signatures
// under the group x-only key, with distributed key generation and a transport
// seam a networked quorum plugs into.
//
// # Design
//
//   - The FROST GROUP public key IS the on-chain policy key. Enclave scripts
//     stay `<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG` with a single x-only
//     key, so nothing about enclaves, contracts, addresses or asset ids changes
//     — when the backend swaps in, and equally when keygen moves from a dealer
//     to a DKG. That invariance is why the quorum lives off-chain behind this
//     seam rather than as an on-chain k-of-n multisig, which would bake the
//     signer set into every enclave address.
//
//   - KEYGEN IS A DKG by default (dkg.go): every member samples its own
//     polynomial, publishes Feldman commitments plus a Schnorr proof of
//     knowledge of its constant term, deals shares directly to its peers, and
//     each recipient verifies the share it was handed against its sender's
//     commitments. The group secret is the sum of the members' constant terms,
//     so NO component ever holds it — not a dealer, not the coordinator, not any
//     member — and the group public key is derived from public commitments
//     rather than reported by anyone. Every check names the participant that
//     fails it. The trusted dealer stays available behind Config.Keygen =
//     KeygenDealer (or OPENAMPD_FROST_KEYGEN=dealer): it is the construction the
//     pinned test vectors were computed under, and it is the one mode a
//     networked transport cannot serve, because its members would have to accept
//     material they did not generate.
//
//   - SIGNING follows FROST's two-round structure: each member commits to a
//     hiding and a binding nonce (D_i, E_i), the binding factor rho_i ties the
//     second nonce to the message and the full commitment list, R = sum(D_i +
//     rho_i*E_i), and Lagrange-weighted partials s_i = k_h + rho_i*k_b +
//     e*lambda_i*d_i are each verified against public data before aggregation.
//     A member destroys its nonces the moment it produces a partial, so one
//     nonce pair can never sign two messages. The BIP340 parity adjustments
//     (even-Y R via nonce negation, even-Y P via share negation) are documented
//     at the top of frost.go — they are where threshold Schnorr implementations
//     silently break.
//
//   - Resharing — deriving a new share set, for a possibly different member set,
//     that keeps the SAME group public key — is what would let the signer set
//     and threshold change over an asset's life with no chain migration of
//     holders' funds. The construction permits it (the group key is a public
//     point, not a function of who holds shares); this package does not
//     implement it yet. Rotating members today means generating a new key,
//     which means a new asset.
//
//   - THE TRANSPORT SEAM (transport.go) is the only thing the coordinator talks
//     through. Member and Transport carry participant identity, the DKG rounds,
//     member-to-member share delivery, the signing rounds, key binding, and the
//     failure semantics (ErrUnreachable versus *MisbehaviorError, all-n for
//     keygen versus t-of-n for signing, per-call timeouts). LocalTransport
//     (local.go) implements it in process. An HTTP or gRPC transport is a client
//     stub implementing Member plus a handler hosting the same member logic; it
//     adds no protocol decisions.
//
//   - The SignRequest travels with every signing round so each member can log,
//     rate-limit or refuse what it is signing — a clawback sweep is not a
//     routine transfer co-signature. It is advisory and never contributes
//     signature bytes; a member that refuses is excluded and the round retries
//     without it while a quorum remains.
//
// # What the single-process posture proves, and what it does not
//
// LocalTransport runs the members as separate ROLES, not on separate machines.
//
// What that genuinely establishes: the protocol is correct and complete — a real
// DKG, per-member secrets that never leave their owner, verification at every
// step, named aborts; no single share can sign; the coordinator holds neither a
// share nor the group secret; and every message that would cross a wire already
// exists as a typed value passing through the Member interface.
//
// What it does NOT establish: independent compromise. All n members run in one
// process, draw from one random source, and — because the in-process member
// persists where the daemon does — write their shares into the SAME 0600 keys
// file. An attacker holding that file or that process holds every share, so
// today's threshold protects against a signing-path bug or a misused API, not
// against host compromise. No member state is shared in memory (each holds its
// own polynomial, share and nonces under its own mutex), which is what makes
// separating custody a deployment change rather than a rewrite: write a
// transport, point each member at its own storage and its own entropy. The seam
// is where that happens, and it is the only place that changes.
//
// # Selection
//
// The backend registers itself as "frost" for the daemon's -signer flag
// (OPENAMPD_SIGNER); "local" (the single-key LocalKeySigner) stays the default.
// Assets provisioned under local keep working when frost is selected: the
// backend falls back per asset when no FROST key material exists. Key material
// generated by the first release of this backend (x-only group record, no pinned
// public shares) also keeps working — see FrostSigner.verificationData.
package frostsigner
