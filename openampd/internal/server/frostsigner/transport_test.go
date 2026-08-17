package frostsigner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// The transport seam's failure semantics: unreachable versus misbehaving,
// all-n for keygen versus t-of-n for signing, nonce single use, timeouts. Every
// fault is injected by implementing Member, so these tests are also the proof
// that a transport written outside this package can drive the protocol.

// newKeyedSigner runs a DKG and adopts the key, returning the signer, the group
// key, the asset id and the transport wrapper for later fault injection.
func newKeyedSigner(t *testing.T, wrap map[int]func(Member) Member) (*FrostSigner, [32]byte, string, *wrapTransport) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := &wrapTransport{inner: NewLocalTransport(st, 3, rand.Reader), wrap: map[int]func(Member) Member{}}
	f, err := NewWithTransport(st, Config{}, tr)
	if err != nil {
		t.Fatal(err)
	}
	pub, ref, err := f.GeneratePolicyKey() // honest quorum for keygen
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	for id, w := range wrap { // faults apply from here on
		tr.wrap[id] = w
	}
	return f, pub, "asset-1", tr
}

// countingMember records how many times each round was called on it.
type countingMember struct {
	Member
	nonceCalls, partialCalls *atomic.Int32
}

func (c countingMember) NonceCommit(ctx context.Context, s SignSession) (*NonceCommitment, error) {
	c.nonceCalls.Add(1)
	return c.Member.NonceCommit(ctx, s)
}

func (c countingMember) Partial(ctx context.Context, s SignSession, pkg *SigningPackage) ([32]byte, error) {
	c.partialCalls.Add(1)
	return c.Member.Partial(ctx, s, pkg)
}

// refusingMember vetoes at round 1, the way a member enforcing its own policy
// would refuse a clawback it does not like.
type refusingMember struct {
	Member
	reason string
}

func (r refusingMember) NonceCommit(context.Context, SignSession) (*NonceCommitment, error) {
	return nil, fmt.Errorf("member %d refuses: %s", r.Member.Identity().ID, r.reason)
}

// hangingMember never answers, so the coordinator's per-call timeout must treat
// it as unreachable.
type hangingMember struct{ Member }

func (h hangingMember) NonceCommit(ctx context.Context, _ SignSession) (*NonceCommitment, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// garbagePartial answers round 2 with a well-formed but wrong scalar.
type garbagePartial struct{ Member }

func (g garbagePartial) Partial(ctx context.Context, s SignSession, pkg *SigningPackage) ([32]byte, error) {
	if _, err := g.Member.Partial(ctx, s, pkg); err != nil { // consume nonces honestly
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte("not a partial signature")), nil
}

// TestTransport_UnreachableMemberStillSigns proves signing is t-of-n for real:
// one member down does not stop a 2-of-3 quorum, and the surviving pair's
// signature verifies under the same group key.
func TestTransport_UnreachableMemberStillSigns(t *testing.T) {
	f, pub, asset, _ := newKeyedSigner(t, map[int]func(Member) Member{
		2: func(m Member) Member { return unreachableMember{Member: m} },
	})
	m := sha256.Sum256([]byte("sign without member 2"))
	sig, err := f.SignPolicy(asset, m, server.PolicyContext{Action: "transfer"})
	if err != nil {
		t.Fatalf("a 2-of-3 quorum must sign with one member down: %v", err)
	}
	verifyBIP340(t, sig, m, pub)
}

// TestTransport_RefusingMemberIsRoutedAround proves the advisory SignRequest can
// be acted on: a member that vetoes is skipped and the round completes with the
// others.
func TestTransport_RefusingMemberIsRoutedAround(t *testing.T) {
	f, pub, asset, _ := newKeyedSigner(t, map[int]func(Member) Member{
		1: func(m Member) Member { return refusingMember{Member: m, reason: "clawbacks need a second operator"} },
	})
	m := sha256.Sum256([]byte("clawback sweep"))
	sig, err := f.SignPolicy(asset, m, server.PolicyContext{Action: "clawback", Reason: "court order"})
	if err != nil {
		t.Fatalf("a refusing member must be routed around: %v", err)
	}
	verifyBIP340(t, sig, m, pub)
}

// TestTransport_HangingMemberTimesOut proves a hung member is treated exactly
// like a dead one, bounded by Config.RoundTimeout rather than hanging the
// request path.
func TestTransport_HangingMemberTimesOut(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := &wrapTransport{inner: NewLocalTransport(st, 3, rand.Reader), wrap: map[int]func(Member) Member{}}
	f, err := NewWithTransport(st, Config{RoundTimeout: 150 * time.Millisecond}, tr)
	if err != nil {
		t.Fatal(err)
	}
	pub, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	tr.wrap[1] = func(m Member) Member { return hangingMember{m} }

	start := time.Now()
	m := sha256.Sum256([]byte("hung member"))
	sig, err := f.SignPolicy("asset-1", m, server.PolicyContext{Action: "transfer"})
	if err != nil {
		t.Fatalf("a hung member must be skipped, not fatal: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("signing took %v: the per-call timeout is not bounding the round", elapsed)
	}
	verifyBIP340(t, sig, m, pub)
}

// TestTransport_MemberDroppingBetweenRoundsIsExcludedAndRetried proves the
// conservative retry: a member that commits nonces and then dies is excluded and
// the round restarts under a FRESH session, never reusing the survivors'
// consumed nonces. The surviving members are asked for nonces twice, once per
// session.
func TestTransport_MemberDroppingBetweenRoundsIsExcludedAndRetried(t *testing.T) {
	var n1, p1, n3, p3 atomic.Int32
	f, pub, asset, _ := newKeyedSigner(t, map[int]func(Member) Member{
		1: func(m Member) Member { return countingMember{Member: m, nonceCalls: &n1, partialCalls: &p1} },
		2: func(m Member) Member { return unreachableMember{Member: m, at: "Partial"} },
		3: func(m Member) Member { return countingMember{Member: m, nonceCalls: &n3, partialCalls: &p3} },
	})
	m := sha256.Sum256([]byte("member 2 dies mid-round"))
	sig, err := f.SignPolicy(asset, m, server.PolicyContext{Action: "transfer"})
	if err != nil {
		t.Fatalf("the round must retry without the dropped member: %v", err)
	}
	verifyBIP340(t, sig, m, pub)
	if got := n1.Load(); got != 2 {
		t.Fatalf("member 1 should have committed nonces twice (one per session), got %d", got)
	}
	if got := n3.Load(); got != 1 {
		t.Fatalf("member 3 should have joined only the retry, got %d nonce commitments", got)
	}
	// Member 1 produced a partial in BOTH sessions: the first round's partial is
	// stranded when member 2 drops. That is harmless — a partial is public data
	// verifiable against public commitments, and the nonces behind it were
	// destroyed on use, so the retry's partial uses a fresh pair. What would be
	// unsafe is reusing those nonces, which is exactly why the retry starts a new
	// session instead of resuming the old one.
	if got := p1.Load(); got != 2 {
		t.Fatalf("member 1 should have produced one partial per session (2), got %d", got)
	}
}

// TestTransport_TooFewMembersFailsNamingThem proves the coordinator gives up
// when no quorum can be assembled, and says who failed.
func TestTransport_TooFewMembersFailsNamingThem(t *testing.T) {
	f, _, asset, _ := newKeyedSigner(t, map[int]func(Member) Member{
		2: func(m Member) Member { return unreachableMember{Member: m} },
		3: func(m Member) Member { return unreachableMember{Member: m} },
	})
	_, err := f.SignPolicy(asset, sha256.Sum256([]byte("no quorum")), server.PolicyContext{Action: "transfer"})
	if err == nil {
		t.Fatal("signing must fail when fewer than t members answer")
	}
	for _, want := range []string{"member 2", "member 3"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must name the failures (%s missing): %v", want, err)
		}
	}
}

// TestTransport_MisbehavingPartialIsNamedAndNotRetried proves misbehavior is
// handled differently from a dropout: a member that returns a well-formed but
// invalid partial is named, and the coordinator does NOT retry around it (a
// retry cannot fix a lie, and burning nonces on one would be the wrong answer).
func TestTransport_MisbehavingPartialIsNamedAndNotRetried(t *testing.T) {
	var n1, p1 atomic.Int32
	f, _, asset, _ := newKeyedSigner(t, map[int]func(Member) Member{
		1: func(m Member) Member { return countingMember{Member: m, nonceCalls: &n1, partialCalls: &p1} },
		2: func(m Member) Member { return garbagePartial{m} },
	})
	_, err := f.SignPolicy(asset, sha256.Sum256([]byte("bad partial")), server.PolicyContext{Action: "transfer"})
	if err == nil {
		t.Fatal("an invalid partial must fail the signature")
	}
	var mis *MisbehaviorError
	if !errors.As(err, &mis) || mis.ID != 2 {
		t.Fatalf("the failure must name member 2 as misbehaving, got: %v", err)
	}
	if got := n1.Load(); got != 1 {
		t.Fatalf("misbehavior must not be retried around: member 1 was asked for nonces %d times", got)
	}
}

// TestTransport_NoncesAreSingleUse proves a member destroys its nonces when it
// produces a partial: a second Partial for the same session fails instead of
// signing a different message with the same nonce pair (which would leak the
// share).
func TestTransport_NoncesAreSingleUse(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	f, err := NewWithTransport(st, Config{}, tr)
	if err != nil {
		t.Fatal(err)
	}
	_, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	sess := SignSession{ID: "session-1", KeyID: "asset-1", Signers: []int{1, 2}}
	pkg := &SigningPackage{Message: sha256.Sum256([]byte("first message"))}
	rec, _ := f.loadRecord("asset-1")
	pkg.GroupKey = compressPoint(rec.group)
	for _, id := range []int{1, 2} {
		m, err := tr.Member(id)
		if err != nil {
			t.Fatal(err)
		}
		nc, err := m.NonceCommit(ctx, sess)
		if err != nil {
			t.Fatal(err)
		}
		pkg.Commitments = append(pkg.Commitments, nc)
	}
	m1, _ := tr.Member(1)
	if _, err := m1.Partial(ctx, sess, pkg); err != nil {
		t.Fatal(err)
	}
	if _, err := m1.Partial(ctx, sess, pkg); err == nil {
		t.Fatal("a member must refuse to sign twice with one nonce pair")
	}
	// And a fresh session cannot borrow the old commitments either.
	other := SignSession{ID: "session-2", KeyID: "asset-1", Signers: []int{1, 2}}
	if _, err := m1.Partial(ctx, other, pkg); err == nil {
		t.Fatal("a member must not sign for a session it never committed nonces to")
	}
}

// TestTransport_PackageMustCarryTheMembersOwnCommitment proves a member refuses
// to sign a round whose binding factors were computed over commitments it never
// published — the check that stops a coordinator substituting nonce
// commitments.
func TestTransport_PackageMustCarryTheMembersOwnCommitment(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	f, err := NewWithTransport(st, Config{}, tr)
	if err != nil {
		t.Fatal(err)
	}
	_, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sess := SignSession{ID: "s", KeyID: "asset-1", Signers: []int{1, 2}}
	rec, _ := f.loadRecord("asset-1")
	pkg := &SigningPackage{Message: sha256.Sum256([]byte("m")), GroupKey: compressPoint(rec.group)}
	m1, _ := tr.Member(1)
	m2, _ := tr.Member(2)
	nc1, err := m1.NonceCommit(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	nc2, err := m2.NonceCommit(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	// Swap member 1's commitment for a different valid point.
	forged := &NonceCommitment{From: 1, D: nc2.D, E: nc2.E}
	pkg.Commitments = []*NonceCommitment{forged, nc2}
	if _, err := m1.Partial(ctx, sess, pkg); err == nil {
		t.Fatal("a member must refuse a package that misstates its own nonce commitment")
	}
	_ = nc1
}

// TestTransport_ConcurrentSigningIsSafe drives many signatures at once through
// one signer, which is how openampd uses it (concurrent HTTP handlers). Run
// under -race this is the guard on the members' per-member state.
func TestTransport_ConcurrentSigningIsSafe(t *testing.T) {
	f, pub, asset, _ := newKeyedSigner(t, nil)
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := sha256.Sum256([]byte(fmt.Sprintf("concurrent message %d", i)))
			sig, err := f.SignPolicy(asset, m, server.PolicyContext{Action: "transfer", InputIndex: i})
			if err != nil {
				errs <- err
				return
			}
			if err := verifySig(sig, m, pub); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent signing failed: %v", err)
	}
}

// TestTransport_AbandonedRoundLeavesNoLiveNonces proves the coordinator cleans
// up after itself: when a round is abandoned because one member dropped, the
// members that already committed are told to drop their nonces. Otherwise a
// nonce pair whose commitments are already public would sit there waiting for
// whatever message reached the member next.
func TestTransport_AbandonedRoundLeavesNoLiveNonces(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inner := NewLocalTransport(st, 3, rand.Reader)
	tr := &wrapTransport{inner: inner, wrap: map[int]func(Member) Member{}}
	f, err := NewWithTransport(st, Config{}, tr)
	if err != nil {
		t.Fatal(err)
	}
	pub, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	tr.wrap[2] = func(m Member) Member { return unreachableMember{Member: m, at: "Partial"} }

	m := sha256.Sum256([]byte("member 2 dies mid-round"))
	sig, err := f.SignPolicy("asset-1", m, server.PolicyContext{Action: "transfer"})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySig(sig, m, pub); err != nil {
		t.Fatal(err)
	}
	for id, member := range inner.members {
		member.mu.Lock()
		live := len(member.nonces)
		member.mu.Unlock()
		if live != 0 {
			t.Fatalf("member %d still holds %d nonce set(s) after the round finished", id, live)
		}
	}
}

// TestTransport_StaleNoncesExpire proves the member's own backstop for a
// coordinator that dies between the rounds: nonces older than sessionTTL are
// dropped, so they cannot be consumed later by a message of someone else's
// choosing.
func TestTransport_StaleNoncesExpire(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	f, err := NewWithTransport(st, Config{}, tr)
	if err != nil {
		t.Fatal(err)
	}
	_, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m1, _ := tr.Member(1)
	abandoned := SignSession{ID: "abandoned", KeyID: "asset-1"}
	if _, err := m1.NonceCommit(ctx, abandoned); err != nil {
		t.Fatal(err)
	}
	// Age it past the TTL, then drive any operation that sweeps.
	member := tr.members[1]
	member.mu.Lock()
	member.nonces["abandoned"].created = time.Now().Add(-2 * sessionTTL)
	member.mu.Unlock()
	if _, err := m1.NonceCommit(ctx, SignSession{ID: "fresh", KeyID: "asset-1"}); err != nil {
		t.Fatal(err)
	}
	member.mu.Lock()
	_, stillThere := member.nonces["abandoned"]
	member.mu.Unlock()
	if stillThere {
		t.Fatal("nonces older than the session TTL must be dropped")
	}
	// And the expired session can no longer produce a partial.
	if _, err := m1.Partial(ctx, abandoned, &SigningPackage{}); err == nil {
		t.Fatal("an expired session must not sign")
	}
}

// TestTransport_AbortSignIsIdempotent covers the explicit cancel, including for
// sessions the member never heard of (a transport may retry it).
func TestTransport_AbortSignIsIdempotent(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	m1, _ := tr.Member(1)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := m1.AbortSign(ctx, "never-existed"); err != nil {
			t.Fatalf("AbortSign on an unknown session must succeed: %v", err)
		}
		if err := m1.AbortDKG(ctx, "never-existed"); err != nil {
			t.Fatalf("AbortDKG on an unknown session must succeed: %v", err)
		}
	}
}

// TestTransport_NilPackageIsAnErrorNotAPanic keeps a decoded-request edge case
// honest: a transport handing a member an empty body must get an error back.
func TestTransport_NilPackageIsAnErrorNotAPanic(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	f, err := NewWithTransport(st, Config{}, tr)
	if err != nil {
		t.Fatal(err)
	}
	_, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m1, _ := tr.Member(1)
	sess := SignSession{ID: "s", KeyID: "asset-1"}
	if _, err := m1.NonceCommit(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := m1.Partial(ctx, sess, nil); err == nil {
		t.Fatal("a nil signing package must be an error")
	}
}

// TestTransport_ClosedTransportCannotSign proves Close is meaningful: after it,
// no member is reachable and signing fails instead of silently proceeding.
func TestTransport_ClosedTransportCannotSign(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := &closableTransport{inner: NewLocalTransport(st, 3, rand.Reader)}
	f, err := NewWithTransport(st, Config{}, tr)
	if err != nil {
		t.Fatal(err)
	}
	_, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.SignPolicy("asset-1", sha256.Sum256([]byte("m")), server.PolicyContext{Action: "transfer"}); err == nil {
		t.Fatal("signing over a closed transport must fail")
	} else if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("the failure must classify as unreachable, got: %v", err)
	}
}

// closableTransport reports every member unreachable once closed, which is how a
// networked transport behaves after its connections are torn down.
type closableTransport struct {
	inner  *LocalTransport
	closed bool
}

func (c *closableTransport) Members() []Identity { return c.inner.Members() }
func (c *closableTransport) Member(id int) (Member, error) {
	if c.closed {
		return nil, fmt.Errorf("transport closed: %w", ErrUnreachable)
	}
	return c.inner.Member(id)
}
func (c *closableTransport) Close() error { c.closed = true; return nil }

// verifySig is the error-returning form of verifyBIP340, for use off the main
// test goroutine (t.Fatalf is illegal there).
func verifySig(sig []byte, m [32]byte, groupX [32]byte) error {
	pub, err := schnorr.ParsePubKey(groupX[:])
	if err != nil {
		return err
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return err
	}
	if !parsed.Verify(m[:], pub) {
		return fmt.Errorf("signature does not verify under the group key")
	}
	return nil
}
