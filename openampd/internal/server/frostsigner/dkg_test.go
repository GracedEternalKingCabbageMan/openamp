package frostsigner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// --- fault injection through the seam ----------------------------------------
//
// Every fault below is injected by implementing the Transport/Member interfaces,
// never by reaching into the package's internals. That is the same thing a
// networked transport does, so these tests double as proof that the seam is
// implementable from outside.

// wrapTransport substitutes wrapped members for chosen IDs. Member-to-member
// delivery still goes through the underlying LocalTransport, so a wrapped
// member's peers behave honestly.
type wrapTransport struct {
	inner *LocalTransport
	wrap  map[int]func(Member) Member
}

func (w *wrapTransport) Members() []Identity { return w.inner.Members() }
func (w *wrapTransport) Member(id int) (Member, error) {
	m, err := w.inner.Member(id)
	if err != nil {
		return nil, err
	}
	if f, ok := w.wrap[id]; ok {
		return f(m), nil
	}
	return m, nil
}
func (w *wrapTransport) Close() error { return w.inner.Close() }

// newWrapped builds a signer whose quorum has some members wrapped.
func newWrapped(t *testing.T, cfg Config, wrap map[int]func(Member) Member) (*FrostSigner, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := &wrapTransport{inner: NewLocalTransport(st, 3, rand.Reader), wrap: wrap}
	f, err := NewWithTransport(st, cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	return f, st
}

// unreachableMember is a member whose every call fails as unreachable.
type unreachableMember struct {
	Member
	at string // which call fails; "" = all of them
}

func (u unreachableMember) fail(call string) error {
	if u.at == "" || u.at == call {
		return fmt.Errorf("dial member %d: %w", u.Member.Identity().ID, ErrUnreachable)
	}
	return nil
}

func (u unreachableMember) Commit(ctx context.Context, s DKGSession) (*DKGCommitment, error) {
	if err := u.fail("Commit"); err != nil {
		return nil, err
	}
	return u.Member.Commit(ctx, s)
}

func (u unreachableMember) NonceCommit(ctx context.Context, s SignSession) (*NonceCommitment, error) {
	if err := u.fail("NonceCommit"); err != nil {
		return nil, err
	}
	return u.Member.NonceCommit(ctx, s)
}

func (u unreachableMember) Partial(ctx context.Context, s SignSession, pkg *SigningPackage) ([32]byte, error) {
	if err := u.fail("Partial"); err != nil {
		return [32]byte{}, err
	}
	return u.Member.Partial(ctx, s, pkg)
}

// corruptingRelay alters a share in flight: it is the delivery hop between two
// members, and it changes the value of shares claiming to come from `from`. The
// recipient's Feldman check must reject it and name the SENDER — which is the
// right semantics precisely because the transport contract requires an
// authenticated channel, so "the share I hold from 2 does not match 2's
// commitments" is an accusation 2 is accountable for.
type corruptingRelay struct {
	Member
	from int
}

func (c corruptingRelay) AcceptShare(ctx context.Context, sessionID string, sh *DKGShare) error {
	if sh.From == c.from {
		spoiled := *sh
		spoiled.Value[31] ^= 0x01
		sh = &spoiled
	}
	return c.Member.AcceptShare(ctx, sessionID, sh)
}

// forgedCommitment returns a commitment whose proof of knowledge is invalid.
type forgedCommitment struct{ Member }

func (f forgedCommitment) Commit(ctx context.Context, s DKGSession) (*DKGCommitment, error) {
	c, err := f.Member.Commit(ctx, s)
	if err != nil {
		return nil, err
	}
	c.PoKMu[31] ^= 0x01 // break the proof
	return c, nil
}

// failingFinalizer takes part fully, then refuses at the last round — the case
// that must leave NO key material anywhere.
type failingFinalizer struct{ Member }

func (f failingFinalizer) Finalize(context.Context, DKGSession) (*DKGResult, error) {
	return nil, fmt.Errorf("member %d: storage is read-only", f.Member.Identity().ID)
}

// --- tests -------------------------------------------------------------------

// TestDKG_ManyRunsSignAndVerify is the primary gate: a DKG-generated group key
// signs through the ordinary path and the aggregate verifies under it, over many
// independent runs (fresh polynomials, fresh messages, all three signer pairs
// exercised by rotation).
func TestDKG_ManyRunsSignAndVerify(t *testing.T) {
	for run := 0; run < 16; run++ {
		f, _ := newTestSigner(t, KeygenDKG)
		pub, ref, err := f.GeneratePolicyKey()
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		assetID := fmt.Sprintf("asset-%d", run)
		if err := f.Adopt(ref, assetID); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		var m [32]byte
		if _, err := rand.Read(m[:]); err != nil {
			t.Fatal(err)
		}
		sig, err := f.SignPolicy(assetID, m, server.PolicyContext{Action: "transfer"})
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		verifyBIP340(t, sig, m, pub)
	}
}

// TestDKG_NoComponentHoldsTheGroupSecret is the structural claim behind the DKG:
// each member's stored share is only a point on the combined polynomial, no
// stored value equals the group secret, and any t of the shares reconstruct the
// same group key while a single share reconstructs nothing.
func TestDKG_NoComponentHoldsTheGroupSecret(t *testing.T) {
	f, st := newTestSigner(t, KeygenDKG)
	pub, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	shares := map[int][32]byte{}
	for i := 1; i <= 3; i++ {
		b := mustHexBytes(keys[fmt.Sprintf("frost:asset-1:share:%d", i)])
		if len(b) != 32 {
			t.Fatalf("member %d has no share", i)
		}
		var s [32]byte
		copy(s[:], b)
		shares[i] = s
		// No single stored share is the group secret: d_i*G is never P.
		sc := new(secp.ModNScalar)
		sc.SetBytes(&s)
		if xBytes(pointFromScalar(sc)) == pub {
			t.Fatalf("member %d's share IS the group secret — the split did not happen", i)
		}
	}
	for _, pair := range [][]int{{1, 2}, {1, 3}, {2, 3}} {
		subset := map[int][32]byte{pair[0]: shares[pair[0]], pair[1]: shares[pair[1]]}
		P, err := groupPointFromShares(subset)
		if err != nil {
			t.Fatal(err)
		}
		if xBytes(P) != pub {
			t.Fatalf("shares %v reconstruct %x, want the group key %x", pair, xBytes(P), pub)
		}
	}
}

// TestDKG_TamperedShareRejectedAndNamed covers the Feldman check twice: as a
// unit (a corrupted share against its sender's commitments) and end to end
// (a member that deals a bad share makes the whole DKG abort, naming it).
func TestDKG_TamperedShareRejectedAndNamed(t *testing.T) {
	// Unit: the check names the SENDER, not the recipient.
	poly, err := newPolynomial(2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	comm, err := poly.commit(2, "session-abc", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := &DKGShare{From: 2, To: 3, Value: poly.eval(3).Bytes()}
	if err := verifyShare(comm, good); err != nil {
		t.Fatalf("an honest share must verify: %v", err)
	}
	bad := *good
	bad.Value[31] ^= 0x01
	err = verifyShare(comm, &bad)
	if err == nil {
		t.Fatal("a tampered share must be rejected")
	}
	var mis *MisbehaviorError
	if !errors.As(err, &mis) || mis.ID != 2 {
		t.Fatalf("the rejection must name sender 2 as misbehaving, got %v", err)
	}

	// End to end: the share member 2 sends member 3 arrives altered. The DKG must
	// abort, name member 2, and leave nothing persisted.
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	tr.members[2].peer = func(id int) (Member, error) {
		m, err := tr.Member(id)
		if err != nil || id != 3 {
			return m, err
		}
		return corruptingRelay{Member: m, from: 2}, nil
	}
	f, err := NewWithTransport(st, Config{Keygen: KeygenDKG}, tr)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.GeneratePolicyKey()
	if err == nil {
		t.Fatal("a DKG with a bad dealt share must fail")
	}
	if !errors.As(err, &mis) || mis.ID != 2 {
		t.Fatalf("the abort must name member 2 (the sender), got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not match its published commitments") {
		t.Fatalf("the abort must cite the Feldman check, got: %v", err)
	}
	assertNoKeyMaterial(t, st)
}

// TestDKG_ForgedProofOfKnowledgeRejected proves the proof of knowledge is
// enforced: without it a member could choose its contribution after seeing the
// others' and steer the group key.
func TestDKG_ForgedProofOfKnowledgeRejected(t *testing.T) {
	// Unit.
	poly, err := newPolynomial(2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := poly.commit(1, "sess", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCommitment("sess", 2, c); err != nil {
		t.Fatalf("an honest commitment must verify: %v", err)
	}
	if err := verifyCommitment("another-session", 2, c); err == nil {
		t.Fatal("a proof must not verify in another session (it is session-bound)")
	}
	c.PoKMu[0] ^= 0x02
	if err := verifyCommitment("sess", 2, c); err == nil {
		t.Fatal("a forged proof must be rejected")
	}

	// End to end.
	f, st := newWrapped(t, Config{Keygen: KeygenDKG}, map[int]func(Member) Member{
		3: func(m Member) Member { return forgedCommitment{m} },
	})
	_, _, err = f.GeneratePolicyKey()
	if err == nil {
		t.Fatal("a DKG with a forged proof of knowledge must fail")
	}
	var mis *MisbehaviorError
	if !errors.As(err, &mis) || mis.ID != 3 {
		t.Fatalf("the abort must name member 3, got: %v", err)
	}
	assertNoKeyMaterial(t, st)
}

// TestDKG_MemberFailsMidRunLeavesNoPartialKeySet is the rollback gate: a member
// that fails at the LAST round, after its peers have already stored their
// shares, must leave the keys file with no frost material at all — there is no
// such thing as a partially generated key.
func TestDKG_MemberFailsMidRunLeavesNoPartialKeySet(t *testing.T) {
	f, st := newWrapped(t, Config{Keygen: KeygenDKG}, map[int]func(Member) Member{
		3: func(m Member) Member { return failingFinalizer{m} },
	})
	if _, _, err := f.GeneratePolicyKey(); err == nil {
		t.Fatal("a DKG whose member fails to finalize must fail")
	} else if !strings.Contains(err.Error(), "member 3") {
		t.Fatalf("the failure must name member 3, got: %v", err)
	}
	assertNoKeyMaterial(t, st)
}

// TestDKG_UnreachableMemberAbortsKeygen proves keygen has NO threshold: unlike
// signing, it needs every member, and a missing one leaves nothing behind.
func TestDKG_UnreachableMemberAbortsKeygen(t *testing.T) {
	f, st := newWrapped(t, Config{Keygen: KeygenDKG}, map[int]func(Member) Member{
		2: func(m Member) Member { return unreachableMember{Member: m} },
	})
	_, _, err := f.GeneratePolicyKey()
	if err == nil {
		t.Fatal("keygen must fail when a member is unreachable")
	}
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("the failure must classify as unreachable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "member 2") {
		t.Fatalf("the failure must name member 2, got: %v", err)
	}
	assertNoKeyMaterial(t, st)
}

// TestDKG_SessionStateIsDiscarded proves a member keeps no polynomial after a
// run: the share is all that survives a completed DKG, and nothing survives an
// aborted one.
func TestDKG_SessionStateIsDiscarded(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	f, err := NewWithTransport(st, Config{Keygen: KeygenDKG}, tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.GeneratePolicyKey(); err != nil {
		t.Fatal(err)
	}
	for id, m := range tr.members {
		m.mu.Lock()
		for sid, sess := range m.dkg {
			if sess.poly != nil {
				t.Fatalf("member %d kept its polynomial for session %s after finalizing", id, sid)
			}
		}
		if len(m.nonces) != 0 {
			t.Fatalf("member %d kept live nonces after keygen", id)
		}
		m.mu.Unlock()
	}
}

// TestDKG_PhantomCommitmentRejected proves a member will not deal into a
// commitment set that is not exactly its session's membership. The group key is
// the SUM of those commitments, so one extra well-formed entry (whose author
// knows its own constant term) would shift the group key while every other
// check still passed — and because all members would derive the same wrong key,
// the divergence check could not catch it either. The result would be a key
// that can never sign and whose failures name innocent members.
func TestDKG_PhantomCommitmentRejected(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	sess := DKGSession{ID: "phantom", KeyID: "pending:x", Threshold: 2, Members: tr.Members()}
	ctx := context.Background()
	comms := map[int]*DKGCommitment{}
	for _, ident := range tr.Members() {
		m, err := tr.Member(ident.ID)
		if err != nil {
			t.Fatal(err)
		}
		c, err := m.Commit(ctx, sess)
		if err != nil {
			t.Fatal(err)
		}
		comms[ident.ID] = c
	}
	// A fourth, perfectly valid commitment from outside the quorum.
	poly, err := newPolynomial(2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	phantom, err := poly.commit(4, sess.ID, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCommitment(sess.ID, 2, phantom); err != nil {
		t.Fatalf("the phantom commitment must itself be valid for this test to mean anything: %v", err)
	}
	comms[4] = phantom

	m1, _ := tr.Member(1)
	if err := m1.Deal(ctx, sess, comms); err == nil {
		t.Fatal("a member must refuse a commitment set that is not its session's membership")
	} else if !strings.Contains(err.Error(), "commitment set") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Misattribution is refused too: a commitment filed under the wrong member.
	delete(comms, 4)
	comms[3] = comms[2]
	if err := m1.Deal(ctx, sess, comms); err == nil {
		t.Fatal("a member must refuse a commitment filed under the wrong member")
	}
}

// TestDKG_SessionIsPinnedAtCommit proves a member finishes the run it started:
// a later round carrying a different KeyID, threshold or member set is refused,
// so a caller cannot commit under one session and finalize under another.
func TestDKG_SessionIsPinnedAtCommit(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewLocalTransport(st, 3, rand.Reader)
	sess := DKGSession{ID: "pinned", KeyID: "pending:a", Threshold: 2, Members: tr.Members()}
	ctx := context.Background()
	comms := map[int]*DKGCommitment{}
	for _, ident := range tr.Members() {
		m, _ := tr.Member(ident.ID)
		c, err := m.Commit(ctx, sess)
		if err != nil {
			t.Fatal(err)
		}
		comms[ident.ID] = c
	}
	m1, _ := tr.Member(1)

	swapped := sess
	swapped.KeyID = "pending:b" // the key the run would produce
	if err := m1.Deal(ctx, swapped, comms); err == nil {
		t.Fatal("a member must refuse a round that changes the key it is generating")
	}
	shrunk := sess
	shrunk.Members = sess.Members[:2] // drop a member between rounds
	if err := m1.Deal(ctx, shrunk, comms); err == nil {
		t.Fatal("a member must refuse a round that changes the member set")
	}
	retuned := sess
	retuned.Threshold = 3
	if err := m1.Deal(ctx, retuned, comms); err == nil {
		t.Fatal("a member must refuse a round that changes the threshold")
	}
	// The unchanged session is still accepted.
	if err := m1.Deal(ctx, sess, comms); err != nil {
		t.Fatalf("the pinned session must still work: %v", err)
	}
}

// TestDKG_AlteredCoefficientCaughtAtRoundOne proves the proof of knowledge
// commits to the WHOLE commitment vector: a higher coefficient altered in
// transit fails verification at round 1, instead of surfacing later as a
// Feldman share failure that would frame an honest dealer.
func TestDKG_AlteredCoefficientCaughtAtRoundOne(t *testing.T) {
	poly, err := newPolynomial(2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := poly.commit(2, "sess", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCommitment("sess", 2, c); err != nil {
		t.Fatal(err)
	}
	other, err := newPolynomial(2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.Coeffs[1] = compressPoint(pointFromScalar(other.coeffs[1])) // swap a NON-constant coefficient
	if err := verifyCommitment("sess", 2, c); err == nil {
		t.Fatal("altering any published coefficient must fail the proof of knowledge")
	}
}

// TestDKG_AdoptIsIdempotent proves a repeated adopt (a lost response, a retried
// issuance) reports success rather than a broken binding.
func TestDKG_AdoptIsIdempotent(t *testing.T) {
	f, st := newTestSigner(t, KeygenDKG)
	pub, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatalf("a repeated adopt must succeed: %v", err)
	}
	got, ok := f.PolicyPubKey("asset-1")
	if !ok || got != pub {
		t.Fatal("the binding must survive a repeated adopt")
	}
	keys, _ := st.LoadKeys()
	for name := range keys {
		if strings.HasPrefix(name, "frost-pending:") {
			t.Fatalf("a repeated adopt left staged material: %s", name)
		}
	}
	// Adopting a ref that was never generated is still an error.
	if err := f.Adopt("never-generated", "asset-2"); err == nil {
		t.Fatal("adopting unknown key material must fail")
	}
}

// TestDKG_UnreadableRecordDoesNotFallBack proves a FROST asset whose record is
// corrupt fails loudly instead of quietly routing to the single-key backend,
// which holds no key matching that asset's K_policy.
func TestDKG_UnreadableRecordDoesNotFallBack(t *testing.T) {
	f, st := newTestSigner(t, KeygenDKG)
	_, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveKey("frost:asset-1:group", "not-hex"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.PolicyPubKey("asset-1"); ok {
		t.Fatal("an unreadable group record must not report a usable policy key")
	}
	_, err = f.SignPolicy("asset-1", sha256.Sum256([]byte("m")), server.PolicyContext{Action: "transfer"})
	if err == nil {
		t.Fatal("signing with an unreadable record must fail")
	}
	if strings.Contains(err.Error(), "policy key unavailable") {
		t.Fatalf("the error must describe the real problem, not the single-key fallback's: %v", err)
	}
}

// assertNoKeyMaterial fails if any frost key material is present.
func assertNoKeyMaterial(t *testing.T, st *store.Store) {
	t.Helper()
	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	for name := range keys {
		if strings.HasPrefix(name, "frost:") || strings.HasPrefix(name, "frost-pending:") {
			t.Fatalf("an aborted DKG left key material behind: %s (all keys: %v)", name, keys)
		}
	}
}
