package frostsigner

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// detRand is a deterministic byte stream (SHA256 counter mode over a seed) so
// keygen and signing rounds are reproducible for the pinned vectors.
type detRand struct {
	seed [32]byte
	ctr  uint64
	buf  []byte
}

func newDetRand(seed string) *detRand {
	return &detRand{seed: sha256.Sum256([]byte(seed))}
}

func (d *detRand) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], d.ctr)
		d.ctr++
		block := sha256.Sum256(append(d.seed[:], c[:]...))
		d.buf = append(d.buf, block[:]...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func shareSubset(shares [][32]byte, ids ...int) map[int][32]byte {
	m := map[int][32]byte{}
	for _, id := range ids {
		m[id] = shares[id-1]
	}
	return m
}

func verifyBIP340(t *testing.T, sig []byte, m [32]byte, groupX [32]byte) {
	t.Helper()
	pub, err := schnorr.ParsePubKey(groupX[:])
	if err != nil {
		t.Fatalf("group key unparseable: %v", err)
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		t.Fatalf("signature unparseable: %v", err)
	}
	if !parsed.Verify(m[:], pub) {
		t.Fatalf("aggregate signature does not verify under the group key")
	}
}

// inProcessRound drives one signing round directly over the protocol
// primitives, holding every share itself. It is the reference path the pinned
// vectors were computed under: the real signer never does this — it runs the
// same primitives across the transport seam, one share per member.
type inProcessRound struct {
	ctx       *signingContext
	shares    map[int]*secp.ModNScalar
	pubShares map[int]*secp.JacobianPoint
	nonces    map[int][2]*secp.ModNScalar
}

func newInProcessRound(m [32]byte, shares map[int][32]byte, rnd io.Reader) (*inProcessRound, error) {
	P, err := groupPointFromShares(shares)
	if err != nil {
		return nil, err
	}
	r := &inProcessRound{
		shares: map[int]*secp.ModNScalar{}, pubShares: map[int]*secp.JacobianPoint{},
		nonces: map[int][2]*secp.ModNScalar{},
	}
	pkg := &SigningPackage{Message: m, GroupKey: compressPoint(P)}
	for _, id := range sortedIDs(shares) {
		b := shares[id]
		d := new(secp.ModNScalar)
		d.SetBytes(&b)
		r.shares[id] = d
		r.pubShares[id] = pointFromScalar(d)
		kh, err := randomScalar(rnd)
		if err != nil {
			return nil, err
		}
		kb, err := randomScalar(rnd)
		if err != nil {
			return nil, err
		}
		r.nonces[id] = [2]*secp.ModNScalar{kh, kb}
		pkg.Commitments = append(pkg.Commitments, &NonceCommitment{
			From: id, D: compressPoint(pointFromScalar(kh)), E: compressPoint(pointFromScalar(kb)),
		})
	}
	r.ctx, err = newSigningContext(pkg)
	return r, err
}

func (r *inProcessRound) partial(t *testing.T, id int) [32]byte {
	t.Helper()
	p, err := r.ctx.partial(id, r.shares[id], r.nonces[id][0], r.nonces[id][1])
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (r *inProcessRound) allPartials(t *testing.T) map[int][32]byte {
	t.Helper()
	out := map[int][32]byte{}
	for _, id := range r.ctx.ids {
		out[id] = r.partial(t, id)
	}
	return out
}

// signInProcess is the reference single-process signing path.
func signInProcess(t *testing.T, m [32]byte, shares map[int][32]byte, rnd io.Reader) ([]byte, [32]byte) {
	t.Helper()
	r, err := newInProcessRound(m, shares, rnd)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := r.ctx.aggregate(r.allPartials(t), r.pubShares)
	if err != nil {
		t.Fatal(err)
	}
	return sig, r.ctx.groupX
}

// TestFrost_RandomKeysAndMessages is the base correctness gate: over many
// random keys and messages, the aggregate of a 2-of-3 round is a valid BIP340
// signature under the group x-only key (checked by the independent btcec
// verifier, not by this package's own math).
func TestFrost_RandomKeysAndMessages(t *testing.T) {
	for i := 0; i < 48; i++ {
		groupX, shares, err := dealerKeygen(2, 3, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var m [32]byte
		if _, err := rand.Read(m[:]); err != nil {
			t.Fatal(err)
		}
		sig, gotX := signInProcess(t, m, shareSubset(shares, 1, 2), rand.Reader)
		if gotX != groupX {
			t.Fatalf("subset reconstructs %x, dealer says %x", gotX, groupX)
		}
		verifyBIP340(t, sig, m, groupX)
	}
}

// TestFrost_ParityBranches forces all four (P parity, R parity) combinations —
// the exact places threshold Schnorr silently breaks under BIP340 — and
// requires a valid signature in each. Rounds run until every combination has
// been exercised.
func TestFrost_ParityBranches(t *testing.T) {
	seen := map[[2]bool]int{}
	rnd := newDetRand("parity-branches")
	var m [32]byte
	copy(m[:], bytes.Repeat([]byte{0x42}, 32))
	for i := 0; i < 400 && len(seen) < 4; i++ {
		groupX, shares, err := dealerKeygen(2, 3, rnd)
		if err != nil {
			t.Fatal(err)
		}
		r, err := newInProcessRound(m, shareSubset(shares, 1, 3), rnd)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := r.ctx.aggregate(r.allPartials(t), r.pubShares)
		if err != nil {
			t.Fatalf("aggregate (pNegated=%v rNegated=%v): %v", r.ctx.pNegated, r.ctx.rNegated, err)
		}
		verifyBIP340(t, sig, m, groupX)
		seen[[2]bool{r.ctx.pNegated, r.ctx.rNegated}]++
	}
	if len(seen) < 4 {
		t.Fatalf("not all parity combinations exercised: %v", seen)
	}
}

// TestFrost_AllSignerPairs proves 2-of-3 works with each of the three signer
// pairs, and that every pair reconstructs the SAME group key.
func TestFrost_AllSignerPairs(t *testing.T) {
	groupX, shares, err := dealerKeygen(2, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var m [32]byte
	if _, err := rand.Read(m[:]); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][]int{{1, 2}, {1, 3}, {2, 3}} {
		sig, gotX := signInProcess(t, m, shareSubset(shares, pair...), rand.Reader)
		if gotX != groupX {
			t.Fatalf("pair %v reconstructs %x, want %x", pair, gotX, groupX)
		}
		verifyBIP340(t, sig, m, groupX)
	}
}

// TestFrost_TamperedPartialDetectedAndNamed proves a single corrupted partial
// is caught by partial verification BEFORE aggregation, with the offending
// participant named in the error.
func TestFrost_TamperedPartialDetectedAndNamed(t *testing.T) {
	_, shares, err := dealerKeygen(2, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var m [32]byte
	m[0] = 7
	r, err := newInProcessRound(m, shareSubset(shares, 2, 3), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	partials := r.allPartials(t)
	bad := partials[3]
	bad[31] ^= 0x01
	partials[3] = bad
	if _, err := r.ctx.aggregate(partials, r.pubShares); err == nil {
		t.Fatal("tampered partial must fail aggregation")
	} else if !strings.Contains(err.Error(), "member 3") {
		t.Fatalf("the error must name member 3, got: %v", err)
	}
	// The honest partial still verifies: detection is per participant.
	if err := r.ctx.verifyPartial(2, r.pubShares[2], partials[2]); err != nil {
		t.Fatalf("honest partial rejected: %v", err)
	}
}

// TestFrost_PartialReplayAcrossMessagesFails proves a partial produced for one
// message cannot be replayed into a round for another message: the binding
// factor and challenge commit to the round, so verification fails.
func TestFrost_PartialReplayAcrossMessagesFails(t *testing.T) {
	_, shares, err := dealerKeygen(2, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var m1, m2 [32]byte
	m1[0], m2[0] = 1, 2
	subset := shareSubset(shares, 1, 2)
	r1, err := newInProcessRound(m1, subset, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replayed := r1.partial(t, 1)
	r2, err := newInProcessRound(m2, subset, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.ctx.verifyPartial(1, r2.pubShares[1], replayed); err == nil {
		t.Fatal("a partial from another message's round must not verify")
	}
	partials := map[int][32]byte{1: replayed, 2: r2.partial(t, 2)}
	if _, err := r2.ctx.aggregate(partials, r2.pubShares); err == nil {
		t.Fatal("aggregation over a replayed partial must fail")
	}
}

// Pinned deterministic vectors: for a fixed rand stream and message, the
// TRUSTED-DEALER keygen and the signing round must reproduce these exact bytes.
// A change here means the derivation or the protocol serialization changed —
// which invalidates nothing on-chain (signatures are per-round) but must be a
// deliberate, reviewed decision, not drift. Keeping the dealer path is partly
// what keeps this gate meaningful now that DKG is the default.
const (
	frostVectorGroupX = "817e243dd6b8b869c09b3ca4646f2eaf9b6d9b626d6a00acc8cf5588d74b5dbe"
	frostVectorSig    = "78142032461f4be50066b5058403d08580eddda5ef2d2cb9b22c8229f4934881ae5e80390957f9ce20ad9eba26c4a49d2737a04934e88b641c2844d8d2862491"
)

func TestFrost_DeterministicVectorsPinned(t *testing.T) {
	rnd := newDetRand("openamp-frost-vector-1")
	groupX, shares, err := dealerKeygen(2, 3, rnd)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(groupX[:]); got != frostVectorGroupX {
		t.Fatalf("group key drifted:\n got %s\nwant %s", got, frostVectorGroupX)
	}
	m := sha256.Sum256([]byte("openamp frost vector message"))
	sig, _ := signInProcess(t, m, shareSubset(shares, 1, 2), rnd)
	if got := hex.EncodeToString(sig); got != frostVectorSig {
		t.Fatalf("signature drifted:\n got %s\nwant %s", got, frostVectorSig)
	}
	verifyBIP340(t, sig, m, groupX)
}

// --- the PolicySigner backend -------------------------------------------------

// newTestSigner builds a signer over a fresh store, with the given keygen mode.
func newTestSigner(t *testing.T, mode KeygenMode) (*FrostSigner, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := New(st, Config{Keygen: mode})
	if err != nil {
		t.Fatal(err)
	}
	return f, st
}

// TestFrostSigner_KeyLifecycle drives GeneratePolicyKey -> Adopt -> SignPolicy
// under BOTH keygen modes: each member's share lands in the keys file under the
// asset id, the coordinator's record carries the group point and the pinned
// public shares, and the signature verifies under the group key. DKG is the
// default, so the zero-value mode must behave like KeygenDKG.
func TestFrostSigner_KeyLifecycle(t *testing.T) {
	for _, mode := range []KeygenMode{"", KeygenDKG, KeygenDealer} {
		t.Run("mode-"+string(mode), func(t *testing.T) {
			f, st := newTestSigner(t, mode)
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
			for _, want := range []string{
				"frost:asset-1:group",
				"frost:asset-1:share:1", "frost:asset-1:share:2", "frost:asset-1:share:3",
				"frost:asset-1:pubshare:1", "frost:asset-1:pubshare:2", "frost:asset-1:pubshare:3",
			} {
				if _, ok := keys[want]; !ok {
					t.Fatalf("missing key %s after adopt (have %v)", want, keys)
				}
			}
			for name := range keys {
				if strings.HasPrefix(name, "frost-pending:") {
					t.Fatalf("staged key %s survived adopt", name)
				}
			}
			// The group record is the FULL point, so the parity the signing round
			// needs is part of the record rather than recovered at signing time.
			if g := keys["frost:asset-1:group"]; len(g) != 66 {
				t.Fatalf("group record must be a 33-byte compressed point, got %q", g)
			}
			got, ok := f.PolicyPubKey("asset-1")
			if !ok || got != pub {
				t.Fatalf("PolicyPubKey = %x ok=%v, want %x", got, ok, pub)
			}
			sighash := sha256.Sum256([]byte("a real spend"))
			sig, err := f.SignPolicy("asset-1", sighash, server.PolicyContext{Action: "transfer"})
			if err != nil {
				t.Fatal(err)
			}
			verifyBIP340(t, sig, sighash, pub)
		})
	}
}

// TestFrostSigner_LegacyLocalFallback proves an asset provisioned by the
// LocalKeySigner keeps signing when the frost backend is selected.
func TestFrostSigner_LegacyLocalFallback(t *testing.T) {
	f, st := newTestSigner(t, KeygenDKG)
	local := server.NewLocalKeySigner(st)
	pub, ref, err := local.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Adopt(ref, "legacy-asset"); err != nil {
		t.Fatal(err)
	}
	got, ok := f.PolicyPubKey("legacy-asset")
	if !ok || got != pub {
		t.Fatalf("legacy asset key not served through the frost backend")
	}
	sighash := sha256.Sum256([]byte("legacy spend"))
	sig, err := f.SignPolicy("legacy-asset", sighash, server.PolicyContext{Action: "transfer"})
	if err != nil {
		t.Fatal(err)
	}
	verifyBIP340(t, sig, sighash, pub)
}

// TestFrostSigner_FirstReleaseKeyLayoutStillSigns pins backward compatibility
// with the layout this backend shipped with — an x-only group record and NO
// pinned public shares, which is what the live testnet asset carries. The
// coordinator must recover the group point's parity and the public shares from
// the members and still produce a valid signature.
func TestFrostSigner_FirstReleaseKeyLayoutStillSigns(t *testing.T) {
	f, st := newTestSigner(t, KeygenDealer)
	pub, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "old-asset"); err != nil {
		t.Fatal(err)
	}
	// Rewrite the record in the first release's shape: x-only group key, no
	// pubshare entries.
	if err := st.SaveKey("frost:old-asset:group", hex.EncodeToString(pub[:])); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := st.DeleteKey(fmt.Sprintf("frost:old-asset:pubshare:%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := f.PolicyPubKey("old-asset")
	if !ok || got != pub {
		t.Fatalf("PolicyPubKey over the first-release layout = %x ok=%v, want %x", got, ok, pub)
	}
	sighash := sha256.Sum256([]byte("spend under the old layout"))
	sig, err := f.SignPolicy("old-asset", sighash, server.PolicyContext{Action: "clawback", Reason: "court order"})
	if err != nil {
		t.Fatalf("first-release key layout must still sign: %v", err)
	}
	verifyBIP340(t, sig, sighash, pub)
}

// TestFrostSigner_CorruptedPublicShareRecordRefuses proves the group-key
// cross-check catches a public-share record that does not belong to the key,
// instead of emitting a signature that cannot verify.
func TestFrostSigner_CorruptedPublicShareRecordRefuses(t *testing.T) {
	f, st := newTestSigner(t, KeygenDKG)
	_, ref, err := f.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Adopt(ref, "asset-x"); err != nil {
		t.Fatal(err)
	}
	// A valid point, but not member 1's public share.
	other := pointFromScalar(scalarFromHash(sha256.Sum256([]byte("not the right share"))))
	if err := st.SaveKey("frost:asset-x:pubshare:1", hex.EncodeToString(compressPoint(other))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.SignPolicy("asset-x", sha256.Sum256([]byte("m")), server.PolicyContext{Action: "transfer"}); err == nil {
		t.Fatal("a public-share record inconsistent with the group key must refuse to sign")
	} else if !strings.Contains(err.Error(), "reconstruct") {
		t.Fatalf("expected a reconstruction mismatch, got: %v", err)
	}
}

// TestFrostSigner_DealerModeNeedsALocalQuorum proves the trusted-dealer mode is
// refused on a transport whose members will not accept externally generated
// shares — the property that makes DKG the only option once members are
// separate hosts — while DKG works over that same transport.
func TestFrostSigner_DealerModeNeedsALocalQuorum(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewWithTransport(st, Config{Keygen: KeygenDealer}, &remoteish{NewLocalTransport(st, 3, rand.Reader)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.GeneratePolicyKey(); err == nil {
		t.Fatal("dealer keygen must be refused when members cannot be handed shares")
	} else if !strings.Contains(err.Error(), "install dealt shares") {
		t.Fatalf("unexpected error: %v", err)
	}
	f2, err := NewWithTransport(st, Config{Keygen: KeygenDKG}, &remoteish{NewLocalTransport(st, 3, rand.Reader)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f2.GeneratePolicyKey(); err != nil {
		t.Fatalf("DKG must work over a transport that cannot install shares: %v", err)
	}
}

// remoteish exposes ONLY the Transport interface, hiding InstallDealtShares —
// exactly how a networked transport must look.
type remoteish struct{ inner *LocalTransport }

func (r *remoteish) Members() []Identity           { return r.inner.Members() }
func (r *remoteish) Member(id int) (Member, error) { return r.inner.Member(id) }
func (r *remoteish) Close() error                  { return r.inner.Close() }

var _ Transport = (*remoteish)(nil)
