package frostsigner

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

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
		sig, gotX, err := signFROST(m, shareSubset(shares, 1, 2), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
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
		r, err := newRound(m, shareSubset(shares, 1, 3), rnd)
		if err != nil {
			t.Fatal(err)
		}
		partials := map[int][32]byte{}
		for _, id := range r.ids {
			partials[id] = r.partial(id)
		}
		sig, err := r.aggregate(partials)
		if err != nil {
			t.Fatalf("aggregate (pNegated=%v rNegated=%v): %v", r.pNegated, r.rNegated, err)
		}
		verifyBIP340(t, sig, m, groupX)
		seen[[2]bool{r.pNegated, r.rNegated}]++
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
		sig, gotX, err := signFROST(m, shareSubset(shares, pair...), rand.Reader)
		if err != nil {
			t.Fatalf("pair %v: %v", pair, err)
		}
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
	r, err := newRound(m, shareSubset(shares, 2, 3), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	partials := map[int][32]byte{}
	for _, id := range r.ids {
		partials[id] = r.partial(id)
	}
	bad := partials[3]
	bad[31] ^= 0x01
	partials[3] = bad
	if _, err := r.aggregate(partials); err == nil {
		t.Fatal("tampered partial must fail aggregation")
	} else if !strings.Contains(err.Error(), "participant 3") {
		t.Fatalf("the error must name participant 3, got: %v", err)
	}
	// The honest partial still verifies: detection is per participant.
	if err := r.verifyPartial(2, partials[2]); err != nil {
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
	r1, err := newRound(m1, shareSubset(shares, 1, 2), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replayed := r1.partial(1)
	r2, err := newRound(m2, shareSubset(shares, 1, 2), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.verifyPartial(1, replayed); err == nil {
		t.Fatal("a partial from another message's round must not verify")
	}
	partials := map[int][32]byte{1: replayed, 2: r2.partial(2)}
	if _, err := r2.aggregate(partials); err == nil {
		t.Fatal("aggregation over a replayed partial must fail")
	}
}

// Pinned deterministic vectors: for a fixed rand stream and message, keygen
// and the signing round must reproduce these exact bytes. A change here means
// the derivation or the protocol serialization changed — which invalidates
// nothing on-chain (signatures are per-round) but must be a deliberate,
// reviewed decision, not drift.
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
	sig, _, err := signFROST(m, shareSubset(shares, 1, 2), rnd)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sig); got != frostVectorSig {
		t.Fatalf("signature drifted:\n got %s\nwant %s", got, frostVectorSig)
	}
	verifyBIP340(t, sig, m, groupX)
}

// --- the PolicySigner backend -------------------------------------------------

// TestFrostSigner_KeyLifecycle drives GeneratePolicyKey -> Adopt -> SignPolicy
// against a real store: shares land in the keys file under the asset id, the
// group key is the policy pubkey, and the signature verifies under it.
func TestFrostSigner_KeyLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := New(st, Config{})
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
	keys, err := st.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"frost:asset-1:group", "frost:asset-1:share:1", "frost:asset-1:share:2", "frost:asset-1:share:3"} {
		if _, ok := keys[want]; !ok {
			t.Fatalf("missing key %s after adopt (have %v)", want, keys)
		}
	}
	for name := range keys {
		if strings.HasPrefix(name, "frost-pending:") {
			t.Fatalf("staged key %s survived adopt", name)
		}
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
}

// TestFrostSigner_LegacyLocalFallback proves an asset provisioned by the
// LocalKeySigner keeps signing when the frost backend is selected.
func TestFrostSigner_LegacyLocalFallback(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	local := server.NewLocalKeySigner(st)
	pub, ref, err := local.GeneratePolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Adopt(ref, "legacy-asset"); err != nil {
		t.Fatal(err)
	}
	f, err := New(st, Config{})
	if err != nil {
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
