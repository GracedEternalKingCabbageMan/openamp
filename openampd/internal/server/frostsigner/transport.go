package frostsigner

import (
	"context"
	"errors"
	"fmt"
)

// The quorum transport seam.
//
// Everything the coordinator (FrostSigner) does, it does through Member calls
// obtained from a Transport. No protocol math lives on this side of the
// interface and no transport detail lives on the other, so a networked
// transport (HTTP, gRPC, a queue) is written by implementing Member as a
// client stub and hosting localMember behind a handler — it adds no protocol
// decisions. LocalTransport (local.go) is the in-process implementation and is
// the default.
//
// # Message flow
//
// Keygen (DKG, three coordinator rounds plus one member-to-member round):
//
//	1. coordinator -> every member:  Commit         (returns the member's Feldman commitments + PoK)
//	2. coordinator -> every member:  Deal           (member sends its shares to its PEERS itself)
//	   member       -> every peer:   AcceptShare    (the member-to-member round)
//	3. coordinator -> every member:  Finalize       (member verifies, stores its share, returns the group key)
//	   on any failure:               AbortDKG       (member discards session state AND anything it stored)
//
// Signing (two coordinator rounds):
//
//	1. coordinator -> t members:     NonceCommit    (member samples two nonces, returns their commitments)
//	2. coordinator -> t members:     Partial        (member returns its partial signature and DESTROYS its nonces)
//	   on any failure:               AbortSign      (members that committed drop their unused nonces)
//
// # Invariants a transport must preserve
//
//   - ORDERING: the coordinator completes round 1 with every member before any
//     Deal, so a member always holds the session before shares arrive for it. A
//     member refuses AcceptShare for a session it has not been asked to Commit
//     for.
//   - CONFIDENTIALITY: a DKGShare is secret to its named recipient. The
//     coordinator never sees one — Deal returns only an error, because each
//     member pushes its own shares to its peers. A networked transport MUST
//     carry AcceptShare over a mutually authenticated, confidential channel
//     (mTLS or Noise); that is a channel-security requirement, not an
//     application-layer format to invent.
//   - AUTHENTICATION: a member must know which peer an AcceptShare came from.
//     DKGShare.From is a claim; the channel identity is the proof. An
//     unauthenticated transport lets a peer impersonate another and forge the
//     Feldman check's subject.
//   - IDEMPOTENCE: AbortDKG, AbortSign and Adopt may be retried. Commit, Deal,
//     Finalize, NonceCommit and Partial are once-per-session; a member rejects a
//     repeat (nonce reuse across two messages leaks the share).
//   - SESSION BINDING: a member pins the DKGSession it was given at Commit and
//     rejects a later round whose session differs, so a caller cannot start a
//     run under one member set or KeyID and finish it under another. It also
//     rejects a commitment set whose membership is not exactly the session's,
//     because the group key is the sum of those commitments: an extra
//     well-formed entry would shift the group key while every other check
//     still passed.
//   - EXPIRY: session state is not immortal. A member drops keygen sessions and
//     unused nonces that have gone stale (sessionTTL), so a coordinator that
//     dies mid-round cannot leave live nonces behind for good.
//
// # Failure semantics
//
//   - Unreachable is any error wrapping ErrUnreachable, or a context deadline.
//     The coordinator applies Config.RoundTimeout to every call, so a hung
//     member is indistinguishable from a dead one — deliberately.
//   - KEYGEN requires all n members: DKG has no threshold. Any failure aborts
//     the whole session (every reachable member is told to Abort, which rolls
//     back anything it stored) and NOTHING is persisted, so a half-generated
//     key can never exist.
//   - SIGNING requires t members: the coordinator collects nonce commitments in
//     ID order, skipping members that fail, and needs t. A member that answers
//     round 1 but fails round 2 is excluded and the round restarts under a FRESH
//     session (never with the surviving members' consumed nonces), while enough
//     members remain. Signing therefore survives n-t failures; the error names
//     every member that failed.
//   - MISBEHAVIOR is distinct from unreachability: a member that proves
//     something false (a bad PoK, a share that fails its commitment check, a
//     divergent group key, an invalid partial) is reported as *MisbehaviorError
//     naming it, and is never retried around.

// ErrUnreachable marks a member the transport could not reach. Wrap it
// (fmt.Errorf("...: %w", ErrUnreachable)) so callers can classify liveness
// failures apart from protocol failures.
var ErrUnreachable = errors.New("quorum member unreachable")

// MisbehaviorError names a member that produced provably invalid material. It
// is never a liveness problem: retrying cannot help, and the member must be
// investigated.
type MisbehaviorError struct {
	ID     int
	Reason string
}

func (e *MisbehaviorError) Error() string {
	return fmt.Sprintf("quorum member %d misbehaved: %s", e.ID, e.Reason)
}

// misbehaved is the constructor used everywhere a check fails, so every such
// failure names its participant.
func misbehaved(id int, format string, args ...any) error {
	return &MisbehaviorError{ID: id, Reason: fmt.Sprintf(format, args...)}
}

// Identity pins WHO a quorum member is, independently of where it runs. ID is
// the member's Shamir x-coordinate and is fixed for the life of a key: shares
// are indexed by it and the Lagrange weights are computed from it.
type Identity struct {
	ID   int    // 1..n
	Name string // operator-facing label ("custody-a"); informational
	Addr string // transport address; empty in process
}

// Transport hands the coordinator a handle per member.
type Transport interface {
	// Members lists every member of the quorum, ascending by ID. The length is
	// n and must not change over a key's life.
	Members() []Identity

	// Member returns a handle for one member. A transport that cannot reach it
	// may fail here or at the first call; either way the error must wrap
	// ErrUnreachable.
	Member(id int) (Member, error)

	// Close releases transport resources. Signing after Close must fail.
	Close() error
}

// Member is one quorum member as seen by whoever is calling it: the coordinator
// for every method, and a peer member for AcceptShare. Every method is one
// round trip and must honour ctx.
type Member interface {
	Identity() Identity

	// --- key generation (DKG) ---

	// Commit is DKG round 1: the member samples its own degree t-1 polynomial
	// for this session and returns the Feldman commitments to its coefficients
	// plus a proof of knowledge of its constant term. The polynomial never
	// leaves the member.
	Commit(ctx context.Context, s DKGSession) (*DKGCommitment, error)

	// Deal is DKG round 2: given every member's commitments, the member
	// verifies their proofs and sends each PEER the share it owes it, by
	// calling AcceptShare on that peer through its own transport. It returns no
	// share material — the coordinator must never see one.
	Deal(ctx context.Context, s DKGSession, comms map[int]*DKGCommitment) error

	// AcceptShare receives one share addressed to this member from a peer. The
	// caller is a peer member, not the coordinator.
	AcceptShare(ctx context.Context, sessionID string, sh *DKGShare) error

	// Finalize is DKG round 3: the member verifies every share it received
	// against its sender's commitments (Feldman VSS), sums them into its
	// long-term share, persists that share under the session's KeyID, and
	// returns the group public key it derived. A share that fails its check
	// makes this return *MisbehaviorError naming the SENDER.
	Finalize(ctx context.Context, s DKGSession) (*DKGResult, error)

	// AbortDKG discards all state for a keygen session AND anything Finalize
	// persisted for it. It is the rollback that makes a failed DKG leave no
	// partial key set. Idempotent, and safe for an unknown session.
	AbortDKG(ctx context.Context, sessionID string) error

	// --- key binding ---

	// Adopt renames the member's own key material from a provisional KeyID to
	// its final one (openampd learns an asset id only after issuance derives
	// it). Idempotent: already adopted is success.
	Adopt(ctx context.Context, fromKeyID, toKeyID string) error

	// PublicShare returns this member's public share Y_i = d_i*G (33-byte
	// compressed) for a key. It is public data; the coordinator uses it to
	// verify partial signatures for key sets generated before public shares
	// were pinned at keygen (see FrostSigner.verificationData).
	PublicShare(ctx context.Context, keyID string) ([]byte, error)

	// --- signing ---

	// NonceCommit is signing round 1: the member samples a hiding and a binding
	// nonce for this session, keeps them, and returns their commitments.
	NonceCommit(ctx context.Context, s SignSession) (*NonceCommitment, error)

	// Partial is signing round 2: the member re-derives the binding factors,
	// the aggregate nonce, both BIP340 parity adjustments and the challenge
	// from the package (all public), computes its partial signature, and
	// DESTROYS its nonces for the session. Calling it twice for one session
	// fails rather than reusing nonces.
	//
	// What a member can enforce here: that the package carries the exact nonce
	// commitments it published, and that the session is the one it committed
	// to. What it cannot: which group key the round is under — it holds a share,
	// not the group point, so a coordinator naming the wrong key gets a useless
	// signature rather than a leak (the share is protected by the fresh nonces
	// either way, and the coordinator verifies the aggregate before returning
	// it). A member that wants that check needs its own copy of the group key,
	// which is a storage decision for whoever hosts it.
	Partial(ctx context.Context, s SignSession, pkg *SigningPackage) ([32]byte, error)

	// AbortSign discards the nonces a member is holding for a signing session
	// that will never complete. Without it, a round abandoned between the two
	// rounds — because another member failed — would leave live nonces whose
	// commitments are already public, waiting to be consumed by whatever
	// message reaches the member next. The coordinator calls it on every member
	// that committed to a failed round; members must also expire nonces on
	// their own, since the coordinator may be the thing that died. Idempotent,
	// and safe for an unknown session.
	AbortSign(ctx context.Context, sessionID string) error
}

// DKGSession identifies one key-generation run. Members key their per-session
// state on ID and store the resulting share under KeyID.
type DKGSession struct {
	ID        string     // unique per run
	KeyID     string     // which key material this run produces
	Threshold int        // t
	Members   []Identity // all n, ascending by ID
}

// SignSession identifies one signing run.
type SignSession struct {
	ID      string      // unique per run
	KeyID   string      // which key material to sign with
	Signers []int       // the t member IDs taking part, ascending
	Request SignRequest // what the signature authorizes (advisory)
}

// SignRequest describes what a signature is FOR, so a member can log it,
// rate-limit it, or refuse it. It mirrors server.PolicyContext but is declared
// here so a member host need not import the policy server. It is advisory and
// never contributes signature bytes: the sighash already commits to the
// transaction.
type SignRequest struct {
	Action     string // "issue" | "transfer" | "burn" | "clawback" | "reissue"
	AID        string // acting account
	TxID       string // transaction the sighash belongs to
	Reason     string // human-readable reason (clawbacks)
	InputIndex int    // which input the sighash covers
}

// DKGCommitment is a member's round-1 broadcast: Feldman commitments to its
// polynomial coefficients, and a Schnorr proof of knowledge of the constant
// term. The proof is what stops a member choosing its contribution AFTER
// seeing the others' and biasing the group key (the rogue-key attack); it is
// verified by the coordinator and by every other member.
type DKGCommitment struct {
	From   int      // the member that produced it
	Coeffs [][]byte // t compressed points; Coeffs[0] commits to the constant term
	PoKR   []byte   // compressed R = k*G
	PoKMu  [32]byte // mu = k + a_0*c
}

// DKGShare is one member's secret share of another member's polynomial:
// Value = f_From(To). Secret to To; see the CONFIDENTIALITY invariant.
type DKGShare struct {
	From  int
	To    int
	Value [32]byte
}

// DKGResult is what a member reports at the end of a DKG run.
type DKGResult struct {
	GroupKey []byte // 33-byte compressed group public key the member derived
}

// NonceCommitment is a member's signing round-1 output.
type NonceCommitment struct {
	From int
	D    []byte // compressed hiding-nonce commitment
	E    []byte // compressed binding-nonce commitment
}

// SigningPackage is the public material of a signing round: everything a
// member needs to derive the binding factors, the aggregate nonce, the BIP340
// parity adjustments and the challenge, with nothing secret in it. The group
// key travels as a full 33-byte point (not x-only) precisely so the member can
// derive the P-parity adjustment itself instead of being told a bit to trust.
type SigningPackage struct {
	Message     [32]byte
	GroupKey    []byte // 33-byte compressed group public key
	Commitments []*NonceCommitment
}

// commitmentFor returns the commitment of one member in the package.
func (p *SigningPackage) commitmentFor(id int) (*NonceCommitment, bool) {
	for _, c := range p.Commitments {
		if c.From == id {
			return c, true
		}
	}
	return nil, false
}
