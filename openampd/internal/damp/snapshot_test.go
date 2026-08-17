package damp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// goldenSnapshot builds the fixed, fully populated snapshot the goldens pin:
// one blacklisted outpoint, one whitelisted owner key, a limit and a window.
func goldenSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	bl := NewSMT()
	k1 := OutpointKey(rep(0x44), 0)
	bl.Insert(k1)
	blRoot := bl.Root()
	wl := NewSMT()
	owner := rep(0x55)
	wl.Insert(owner)
	wlRoot := wl.Root()
	limit := uint64(500000)
	s := &Snapshot{
		V:             1,
		Asset:         strings.Repeat("11", 32),
		VerifierAsset: strings.Repeat("99", 32),
		Q:             1000,
		Seq:           0,
		PrevPi:        nil,
		Tree:          TreeSMTv1,
		Predicates: Predicates{
			Blacklist: PredicateList{Root: hex.EncodeToString(blRoot[:]), Entries: []string{hex.EncodeToString(k1[:])}},
			Whitelist: PredicateList{Root: hex.EncodeToString(wlRoot[:]), Entries: []string{hex.EncodeToString(owner[:])}},
			Limit:     &limit,
			Windows:   []Window{{Class: "regS", From: 100, Until: 5000}},
		},
	}
	pi, err := s.ComputePi()
	if err != nil {
		t.Fatal(err)
	}
	s.Pi = hex.EncodeToString(pi[:])
	return s
}

// The pinned golden canonical bytes and content hash of goldenSnapshot.
// Regenerate only for a deliberate, versioned format break: deployed
// snapshots are content-addressed by this exact serialization.
const (
	goldenSnapCanonical = `{"asset":"1111111111111111111111111111111111111111111111111111111111111111","pi":"37071e69e8a360ec9dea456788a74a627228d1a83495073ca5d7fb6eaa2d23a7","predicates":{"blacklist":{"entries":["dead7603eb8f756e0eb3afc21be8c6595b9be48c0f362de122dbb649f2005aad"],"root":"465343f213d06c8bab3b4d2cc711433472db9633df15e6e6ec7ea3a58282afd1"},"limit":500000,"whitelist":{"entries":["5555555555555555555555555555555555555555555555555555555555555555"],"root":"1d0a8871fd268940bcd59ae3a46265d43d3a6f1a4c06826ea0fff13f9caa1cab"},"windows":[{"class":"regS","from":100,"until":5000}]},"prev_pi":null,"q":1000,"seq":0,"tree":"smt-v1","v":1,"verifier_asset":"9999999999999999999999999999999999999999999999999999999999999999"}`
	goldenSnapHash      = "915539b157f3bbc82fa8a5303fc2f02745dd3d76ae867aad18738897d06283d1"
)

// TestSnapshotCanonicalGolden pins the canonical bytes, the hash, and the pi
// of the golden snapshot, and confirms Validate accepts it.
func TestSnapshotCanonicalGolden(t *testing.T) {
	s := goldenSnapshot(t)
	if err := s.Validate(); err != nil {
		t.Fatalf("golden snapshot must validate: %v", err)
	}
	c, err := s.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != goldenSnapCanonical {
		t.Fatalf("canonical bytes changed:\n got  %s\n want %s", c, goldenSnapCanonical)
	}
	h, err := s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(h[:]) != goldenSnapHash {
		t.Fatalf("snapshot hash changed:\n got  %x\n want %s", h, goldenSnapHash)
	}
	if s.Pi != "37071e69e8a360ec9dea456788a74a627228d1a83495073ca5d7fb6eaa2d23a7" {
		t.Fatalf("golden pi changed: %s", s.Pi)
	}
}

// TestSnapshotCanonicalizationStability: the same document arriving with two
// different JSON field orders (and an issuer_sig in one of them) must yield
// one identical canonical byte stream.
func TestSnapshotCanonicalizationStability(t *testing.T) {
	// Field order A: the golden order. Field order B: reversed top-level and
	// nested orders, plus a bogus issuer_sig that canonicalization must drop.
	orderB := `{"verifier_asset":"9999999999999999999999999999999999999999999999999999999999999999","v":1,"tree":"smt-v1","seq":0,"q":1000,"prev_pi":null,"predicates":{"windows":[{"until":5000,"from":100,"class":"regS"}],"whitelist":{"root":"1d0a8871fd268940bcd59ae3a46265d43d3a6f1a4c06826ea0fff13f9caa1cab","entries":["5555555555555555555555555555555555555555555555555555555555555555"]},"limit":500000,"blacklist":{"root":"465343f213d06c8bab3b4d2cc711433472db9633df15e6e6ec7ea3a58282afd1","entries":["dead7603eb8f756e0eb3afc21be8c6595b9be48c0f362de122dbb649f2005aad"]}},"pi":"37071e69e8a360ec9dea456788a74a627228d1a83495073ca5d7fb6eaa2d23a7","issuer_sig":"` + strings.Repeat("ab", 64) + `","asset":"1111111111111111111111111111111111111111111111111111111111111111"}`
	for i, in := range []string{goldenSnapCanonical, orderB} {
		var s Snapshot
		if err := json.Unmarshal([]byte(in), &s); err != nil {
			t.Fatalf("input %d: %v", i, err)
		}
		c, err := s.CanonicalJSON()
		if err != nil {
			t.Fatalf("input %d: %v", i, err)
		}
		if string(c) != goldenSnapCanonical {
			t.Fatalf("input %d not canonicalized to the golden bytes:\n got  %s\n want %s", i, c, goldenSnapCanonical)
		}
	}
}

// TestSnapshotSignVerify: sign/verify round trip, and rejection of a wrong
// key, a tampered document, and a tampered signature.
func TestSnapshotSignVerify(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))

	s := goldenSnapshot(t)
	if err := s.Sign(priv.Serialize()); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(pubHex); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Signing must not change the canonical bytes (issuer_sig excluded).
	c, _ := s.CanonicalJSON()
	if string(c) != goldenSnapCanonical {
		t.Fatal("issuer_sig leaked into the canonical bytes")
	}

	other, _ := btcec.NewPrivateKey()
	if err := s.Verify(hex.EncodeToString(schnorr.SerializePubKey(other.PubKey()))); err == nil {
		t.Fatal("verify must fail under a different key")
	}
	tampered := *s
	tampered.Q = 1001
	if err := tampered.Verify(pubHex); err == nil {
		t.Fatal("verify must fail after tampering with the document")
	}
	badSig := *s
	sb, _ := hex.DecodeString(badSig.IssuerSig)
	sb[10] ^= 0x01
	badSig.IssuerSig = hex.EncodeToString(sb)
	if err := badSig.Verify(pubHex); err == nil {
		t.Fatal("verify must fail on a tampered signature")
	}
}

// TestSnapshotValidateRefusals is the table of Validate() refusals, including
// the two required cases: a wrong predicate root and a wrong pi.
func TestSnapshotValidateRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(s *Snapshot)
		wantErr string
	}{
		{"wrong blacklist root", func(s *Snapshot) {
			s.Predicates.Blacklist.Root = strings.Repeat("ee", 32)
		}, "blacklist.root mismatch"},
		{"wrong pi", func(s *Snapshot) {
			s.Pi = strings.Repeat("ee", 32)
		}, "pi mismatch"},
		{"tampered entry changes root", func(s *Snapshot) {
			s.Predicates.Whitelist.Entries[0] = strings.Repeat("56", 32)
		}, "whitelist.root mismatch"},
		{"bad version", func(s *Snapshot) { s.V = 2 }, "v must be 1"},
		{"unsupported tree", func(s *Snapshot) { s.Tree = "cmt-v1" }, "not supported"},
		{"seq 0 with prev_pi", func(s *Snapshot) {
			p := strings.Repeat("aa", 32)
			s.PrevPi = &p
		}, "seq 0 must have prev_pi null"},
		{"seq 1 without prev_pi", func(s *Snapshot) {
			s.Seq = 1 // pi would also mismatch, but prev_pi is checked first
		}, "requires prev_pi"},
		{"explicit zero limit", func(s *Snapshot) {
			z := uint64(0)
			s.Predicates.Limit = &z
		}, "limit must be positive or null"},
		{"zero q", func(s *Snapshot) { s.Q = 0 }, "q (verifier amount) must be positive"},
		{"verifier asset equals asset", func(s *Snapshot) { s.VerifierAsset = s.Asset }, "must differ"},
		{"url-only list", func(s *Snapshot) {
			s.Predicates.Blacklist.Entries = nil
			s.Predicates.Blacklist.URL = "https://example.com/bl.json"
		}, "inline entries are required"},
		{"absent predicate with entries", func(s *Snapshot) {
			s.Predicates.Blacklist.Root = ""
		}, "must be fully absent"},
		{"duplicate entry", func(s *Snapshot) {
			s.Predicates.Blacklist.Entries = append(s.Predicates.Blacklist.Entries, s.Predicates.Blacklist.Entries[0])
		}, "duplicate entry"},
		{"malformed entry hex", func(s *Snapshot) {
			s.Predicates.Blacklist.Entries[0] = "zz"
		}, "must be 32-byte hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := goldenSnapshot(t)
			tc.mutate(s)
			err := s.Validate()
			if err == nil {
				t.Fatal("Validate accepted an invalid snapshot")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestSnapshotMinimal: a snapshot with every predicate absent validates, its
// rules_root is the all-absent commitment, and enabled-but-empty stays
// distinct from absent.
func TestSnapshotMinimal(t *testing.T) {
	s := &Snapshot{
		V:             1,
		Asset:         strings.Repeat("11", 32),
		VerifierAsset: strings.Repeat("99", 32),
		Q:             1,
		Seq:           0,
		Tree:          TreeSMTv1,
	}
	pi, err := s.ComputePi()
	if err != nil {
		t.Fatal(err)
	}
	s.Pi = hex.EncodeToString(pi[:])
	if err := s.Validate(); err != nil {
		t.Fatalf("minimal snapshot must validate: %v", err)
	}

	// Enabled-but-empty blacklist (root = EmptyRoot) commits differently from
	// an absent one.
	s2 := *s
	er := EmptyRoot()
	s2.Predicates.Blacklist = PredicateList{Root: hex.EncodeToString(er[:])}
	pi2, err := s2.ComputePi()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(pi2[:]) == s.Pi {
		t.Fatal("enabled-but-empty predicate must commit differently from absent")
	}
}

// --- dmt-v1: the consensus-bearing snapshot format ---------------------------

// TestSnapshotDMTv1MatchesVectors is the important one: a dmt-v1 snapshot's pi
// must be the pi the DEPLOYED covenant is instantiated with, so this builds one
// from opendamp/vectors/addresses.json (asset, verifier asset, q, whitelist) and
// requires Validate to accept the vectors' own pi. If the two constructions ever
// diverge, this server would publish a policy no covenant answers to and every
// transfer would fail at consensus.
func TestSnapshotDMTv1MatchesVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "opendamp", "vectors", "addresses.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("opendamp vectors unavailable (%v)", err)
	}
	var v struct {
		Asset          string `json:"asset"`
		VerifierAsset  string `json:"verifier_asset"`
		VerifierAmount uint64 `json:"verifier_amount"`
		Policy         struct {
			Pi               string   `json:"pi"`
			Seq              uint64   `json:"seq"`
			WhitelistRoot    string   `json:"whitelist_root"`
			WhitelistEntries []string `json:"whitelist_entries"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	s := &Snapshot{
		V: 1, Asset: v.Asset, VerifierAsset: v.VerifierAsset, Q: v.VerifierAmount,
		Pi: v.Policy.Pi, Seq: v.Policy.Seq, PrevPi: nil, Tree: TreeDMTv1,
		Predicates: Predicates{
			Whitelist: PredicateList{Root: v.Policy.WhitelistRoot, Entries: v.Policy.WhitelistEntries},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("a dmt-v1 snapshot built from the vectors must validate: %v", err)
	}
	got, err := s.ComputePi()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != v.Policy.Pi {
		t.Fatalf("dmt-v1 pi = %x, the covenant is instantiated with %s", got, v.Policy.Pi)
	}
	// The whitelist root must be recomputed from the entries, so a declared root
	// that does not match its own list is refused rather than published.
	bad := *s
	bad.Predicates.Whitelist.Root = strings.Repeat("22", 32)
	if err := bad.Validate(); err == nil {
		t.Fatal("a dmt-v1 whitelist root that does not match its entries must be refused")
	}
}

// TestSnapshotDMTv1RefusesUnenforcedPredicates: the covenant reads no blacklist
// and no height windows, so a dmt-v1 snapshot carrying either is refused rather
// than published with the slot silently committed empty. An issuer who publishes
// a blacklist and believes it binds has a false sense of a freeze.
func TestSnapshotDMTv1RefusesUnenforcedPredicates(t *testing.T) {
	base := func() *Snapshot {
		wl := rep(0x55)
		root, err := WhitelistRoot([][32]byte{wl})
		if err != nil {
			t.Fatal(err)
		}
		s := &Snapshot{
			V: 1, Asset: strings.Repeat("11", 32), VerifierAsset: strings.Repeat("99", 32),
			Q: 1, Seq: 0, Tree: TreeDMTv1,
			Predicates: Predicates{
				Whitelist: PredicateList{Root: hex.EncodeToString(root[:]), Entries: []string{hex.EncodeToString(wl[:])}},
			},
		}
		pi, err := s.ComputePi()
		if err != nil {
			t.Fatal(err)
		}
		s.Pi = hex.EncodeToString(pi[:])
		return s
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("the plain dmt-v1 shape must validate: %v", err)
	}

	withBl := base()
	blRoot, blEntry := rep(0x77), rep(0x88)
	withBl.Predicates.Blacklist = PredicateList{Root: hex.EncodeToString(blRoot[:]), Entries: []string{hex.EncodeToString(blEntry[:])}}
	if err := withBl.Validate(); err == nil || !strings.Contains(err.Error(), "must not carry a blacklist") {
		t.Fatalf("a dmt-v1 blacklist must be refused, got %v", err)
	}

	withWin := base()
	withWin.Predicates.Windows = []Window{{Class: "regS", From: 1, Until: 2}}
	if err := withWin.Validate(); err == nil || !strings.Contains(err.Error(), "must not carry height windows") {
		t.Fatalf("dmt-v1 height windows must be refused, got %v", err)
	}
}

// TestSnapshotSMTv1StillWorks: adding dmt-v1 changed nothing about the M2
// document format. The golden snapshot is the pinned smt-v1 shape.
func TestSnapshotSMTv1StillWorks(t *testing.T) {
	s := goldenSnapshot(t)
	if s.Tree != TreeSMTv1 {
		t.Fatal("the golden snapshot is the smt-v1 shape")
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("smt-v1 validation regressed: %v", err)
	}
	c, err := s.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != goldenSnapCanonical {
		t.Fatalf("smt-v1 canonical bytes drifted:\n got: %s\nwant: %s", c, goldenSnapCanonical)
	}
	// And an unknown tree is still refused, now naming both supported values.
	s.Tree = "cmt-v1"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "dmt-v1") || !strings.Contains(err.Error(), "smt-v1") {
		t.Fatalf("an unknown tree must be refused naming both supported values, got %v", err)
	}
}
