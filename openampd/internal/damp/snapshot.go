package damp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// PredicateEntry is one entry of a list predicate. Key is the 32-byte policy
// key in hex: an outpoint key for the blacklist, a raw x-only owner key for the
// whitelist. SendAfter and RecvAfter are the whitelist's height bounds, and they
// are part of the LEAF the covenant hashes, not commentary beside it: SendAfter
// is the lockup binding the owner of a regulated input, RecvAfter the receive
// window binding the recipient of a regulated output, and zero means unbounded.
//
// # WHY THE JSON FORM IS TWO SHAPES
//
// An unbounded entry serializes as a BARE HEX STRING and a bounded one as an
// object. That is not decoration: the snapshot hash and the issuer signature
// commit to the canonical bytes, so every document written before bounds existed
// has to keep hashing and verifying exactly as it did. A bare key round-trips
// byte-identically, and only an entry that actually carries a bound spends the
// extra bytes. A bounded entry always writes BOTH bound fields, so there is one
// encoding of a bound rather than one per zero-valued combination.
type PredicateEntry struct {
	Key       string `json:"key"`
	SendAfter uint32 `json:"send_after"`
	RecvAfter uint32 `json:"recv_after"`
}

// Unbounded reports whether the entry carries no height bound at all, which is
// the case for every holder until an issuer sets a lockup or a receive window.
func (e PredicateEntry) Unbounded() bool { return e.SendAfter == 0 && e.RecvAfter == 0 }

func (e PredicateEntry) MarshalJSON() ([]byte, error) {
	if e.Unbounded() {
		return json.Marshal(e.Key)
	}
	type bounded PredicateEntry
	return json.Marshal(bounded(e))
}

func (e *PredicateEntry) UnmarshalJSON(b []byte) error {
	var key string
	if err := json.Unmarshal(b, &key); err == nil {
		*e = PredicateEntry{Key: key}
		return nil
	}
	type bounded PredicateEntry
	var out bounded
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("a predicate entry is either a 32-byte hex key or an object {key, send_after, recv_after}: %w", err)
	}
	*e = PredicateEntry(out)
	return nil
}

// KeyEntries lifts bare hex keys into entries with no height bounds, for the
// callers (issuance, the blacklist, every pre-bounds document) that have keys and
// nothing else.
func KeyEntries(keys []string) []PredicateEntry {
	out := make([]PredicateEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, PredicateEntry{Key: k})
	}
	return out
}

// Keys returns just the hex keys of a list, for the reads that do not care about
// bounds (an ownership scan wants addresses, not windows).
func (p PredicateList) Keys() []string {
	out := make([]string, 0, len(p.Entries))
	for _, e := range p.Entries {
		out = append(out, e.Key)
	}
	return out
}

// PredicateList is one list predicate (blacklist or whitelist) in a snapshot.
// An ABSENT predicate has Root == "" and no entries, and commits to 32 zero
// bytes in RulesRoot. An enabled predicate carries the root over its entries
// (EmptyRoot() when the list is enabled but empty). The design doc allows "url"
// as an alternative to inline entries; this library validates inline entries
// only, and Validate refuses a url-only list (M2 snapshot service requires
// inline entries so the roots are recomputable).
type PredicateList struct {
	Root    string           `json:"root"`
	Entries []PredicateEntry `json:"entries"`
	URL     string           `json:"url,omitempty"`
}

// Window is one height-window rule (design doc 3.5): holders of owner class
// Class may not move funds outside [From, Until). Committed into rules_root
// via the windows hash (taggedHash over the canonical JSON of the array).
type Window struct {
	Class string `json:"class"`
	From  uint64 `json:"from"`
	Until uint64 `json:"until"`
}

// Predicates is the snapshot "predicates" block. Limit is null (nil) when no
// transfer limit is enabled; an explicit 0 is refused by Validate so "no
// limit" has exactly one encoding.
type Predicates struct {
	Blacklist PredicateList `json:"blacklist"`
	Whitelist PredicateList `json:"whitelist"`
	Limit     *uint64       `json:"limit"`
	Windows   []Window      `json:"windows"`
}

// Snapshot is the snapshot/v1 publication document (design doc section 4).
// Asset ids and pi are display hex; the policy commitment covers the
// hex-decoded bytes verbatim (see PolicyHeader). IssuerSig is a BIP340
// signature over H_"OpenDAMP/snapshot/v1"(Hash()) and is excluded from the
// canonical bytes it signs.
type Snapshot struct {
	V             int        `json:"v"`
	Asset         string     `json:"asset"`
	VerifierAsset string     `json:"verifier_asset"`
	Q             uint64     `json:"q"`
	Pi            string     `json:"pi"`
	Seq           uint64     `json:"seq"`
	PrevPi        *string    `json:"prev_pi"`
	Tree          string     `json:"tree"`
	Predicates    Predicates `json:"predicates"`
	IssuerSig     string     `json:"issuer_sig,omitempty"`
}

// canonicalize renders v as canonical JSON: object keys sorted at every
// level, compact separators, numbers verbatim (json.Number round-trip, so a
// full-range uint64 survives). This is the byte form every snapshot hash and
// signature commits to.
func canonicalize(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return json.Marshal(m) // Go sorts map keys; compact output
}

// CanonicalJSON returns the snapshot's canonical bytes: sorted keys, compact
// separators, issuer_sig omitted.
func (s *Snapshot) CanonicalJSON() ([]byte, error) {
	cp := *s
	cp.IssuerSig = "" // omitempty drops it
	return canonicalize(&cp)
}

// Hash is SHA256 of the canonical bytes; snapshots are content-addressed by it.
func (s *Snapshot) Hash() ([32]byte, error) {
	c, err := s.CanonicalJSON()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(c), nil
}

// sigMsg is the 32-byte message the issuer signs:
// H_"OpenDAMP/snapshot/v1"(Hash()).
func (s *Snapshot) sigMsg() ([32]byte, error) {
	h, err := s.Hash()
	if err != nil {
		return [32]byte{}, err
	}
	return taggedHash(TagSnapshot, h[:]), nil
}

// SigMessage is the 32-byte message an issuer signs to authenticate this
// snapshot. Exported so a server can hand it to an offline (or browser-held)
// issuer key without shipping the private key anywhere near the snapshot code.
func (s *Snapshot) SigMessage() ([32]byte, error) { return s.sigMsg() }

// Sign sets IssuerSig to the BIP340 signature of the snapshot under privKey
// (32 bytes).
func (s *Snapshot) Sign(privKey []byte) error {
	msg, err := s.sigMsg()
	if err != nil {
		return err
	}
	priv, _ := btcec.PrivKeyFromBytes(privKey)
	sig, err := schnorr.Sign(priv, msg[:])
	if err != nil {
		return err
	}
	s.IssuerSig = hex.EncodeToString(sig.Serialize())
	return nil
}

// Verify checks IssuerSig against the x-only issuer public key (hex).
func (s *Snapshot) Verify(issuerPubHex string) error {
	pkb, err := hex.DecodeString(issuerPubHex)
	if err != nil || len(pkb) != 32 {
		return fmt.Errorf("issuer pubkey must be 32-byte x-only hex")
	}
	pk, err := schnorr.ParsePubKey(pkb)
	if err != nil {
		return fmt.Errorf("issuer pubkey invalid: %w", err)
	}
	sigb, err := hex.DecodeString(s.IssuerSig)
	if err != nil || len(sigb) != 64 {
		return fmt.Errorf("issuer_sig must be 64-byte hex")
	}
	sig, err := schnorr.ParseSignature(sigb)
	if err != nil {
		return fmt.Errorf("issuer_sig invalid: %w", err)
	}
	msg, err := s.sigMsg()
	if err != nil {
		return err
	}
	if !sig.Verify(msg[:], pk) {
		return fmt.Errorf("issuer_sig does not verify")
	}
	return nil
}

func parseHex32(field, s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%s must be 32-byte hex", field)
	}
	copy(out[:], b)
	return out, nil
}

// predicateRoot recomputes a list predicate's commitment from its inline
// entries and checks it against the declared root. It returns the 32-byte
// commitment RulesRoot consumes: zeros for an absent predicate, the smt-v1
// root otherwise.
func predicateRoot(name string, p PredicateList) ([32]byte, error) {
	if p.Root == "" {
		if len(p.Entries) != 0 || p.URL != "" {
			return [32]byte{}, fmt.Errorf("%s: entries/url present but root empty (absent predicate must be fully absent)", name)
		}
		return [32]byte{}, nil
	}
	declared, err := parseHex32(name+".root", p.Root)
	if err != nil {
		return [32]byte{}, err
	}
	if p.URL != "" && len(p.Entries) == 0 {
		return [32]byte{}, fmt.Errorf("%s: url-only lists are not accepted; inline entries are required so the root is recomputable", name)
	}
	tree := NewSMT()
	for i, e := range p.Entries {
		// smt-v1 leaves are bare keys: there is no leaf shape for a height bound, so
		// accepting one would commit a root that omits it and imply a window nothing
		// enforces.
		if !e.Unbounded() {
			return [32]byte{}, fmt.Errorf("%s.entries[%d]: height bounds are a dmt-v1 leaf field; an smt-v1 document has nowhere to commit them", name, i)
		}
		k, err := parseHex32(fmt.Sprintf("%s.entries[%d]", name, i), e.Key)
		if err != nil {
			return [32]byte{}, err
		}
		if tree.Has(k) {
			return [32]byte{}, fmt.Errorf("%s.entries[%d]: duplicate entry %s", name, i, e.Key)
		}
		tree.Insert(k)
	}
	if got := tree.Root(); got != declared {
		return [32]byte{}, fmt.Errorf("%s.root mismatch: declared %s, entries hash to %x", name, p.Root, got)
	}
	return declared, nil
}

// WindowsHash commits a non-empty windows array:
// H_"OpenDAMP/windows/v1"(canonical JSON of the array). An empty or nil
// array commits to 32 zero bytes (predicate absent).
func WindowsHash(windows []Window) ([32]byte, error) {
	if len(windows) == 0 {
		return [32]byte{}, nil
	}
	c, err := canonicalize(windows)
	if err != nil {
		return [32]byte{}, err
	}
	return taggedHash(TagWindows, c), nil
}

// dmtDeclaredRoot is the shared preamble of both dmt-v1 predicate roots: an
// absent predicate is fully absent, a present one declares a root and carries
// inline entries so that root is recomputable.
func dmtDeclaredRoot(name string, p PredicateList) (*[32]byte, error) {
	if p.Root == "" {
		if len(p.Entries) != 0 || p.URL != "" {
			return nil, fmt.Errorf("%s: entries/url present but root empty (absent predicate must be fully absent)", name)
		}
		return nil, nil
	}
	declared, err := parseHex32(name+".root", p.Root)
	if err != nil {
		return nil, err
	}
	if p.URL != "" && len(p.Entries) == 0 {
		return nil, fmt.Errorf("%s: url-only lists are not accepted; inline entries are required so the root is recomputable", name)
	}
	return &declared, nil
}

// dmtWhitelistRoot recomputes the whitelist's dmt-v1 root from its inline entries
// AND THEIR HEIGHT BOUNDS, and checks it against the declared root.
//
// The bounds are load-bearing here. The covenant's whitelist leaf is
// SHA256(0x00 || key || BE32(send_after) || BE32(recv_after)), so computing the
// root from keys alone would publish a root that silently omits every lockup and
// receive window: a pi no deployed program answers to, which would make every
// transfer of the asset unspendable rather than merely unrestricted. That failure
// mode is why this is a separate function from the blacklist's rather than one
// generic helper over a build callback.
func dmtWhitelistRoot(name string, p PredicateList) (*[32]byte, error) {
	declared, err := dmtDeclaredRoot(name, p)
	if err != nil || declared == nil {
		return declared, err
	}
	entries := make([]WhitelistEntry, 0, len(p.Entries))
	for i, e := range p.Entries {
		k, err := parseHex32(fmt.Sprintf("%s.entries[%d]", name, i), e.Key)
		if err != nil {
			return nil, err
		}
		entries = append(entries, WhitelistEntry{Key: k, SendAfter: e.SendAfter, RecvAfter: e.RecvAfter})
	}
	got, err := WhitelistRootWithWindows(entries)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if got != *declared {
		return nil, fmt.Errorf("%s.root mismatch: declared %s, entries hash to %x", name, p.Root, got)
	}
	return declared, nil
}

// dmtBlacklistRoot recomputes the blacklist's dmt-v1 INTERVAL root from its
// inline outpoint keys.
//
// The two trees are DIFFERENT SHAPES and are not interchangeable: the whitelist
// is a sorted dense tree of holder leaves (membership, bounds included), the
// blacklist an interval tree of outpoint keys (non-membership by bracketing
// interval). Building one with the other's constructor yields a root no covenant
// answers to. A blacklist entry therefore has no height bounds to carry, and one
// that claims to is refused rather than dropped.
func dmtBlacklistRoot(name string, p PredicateList) (*[32]byte, error) {
	declared, err := dmtDeclaredRoot(name, p)
	if err != nil || declared == nil {
		return declared, err
	}
	keys := make([][32]byte, 0, len(p.Entries))
	for i, e := range p.Entries {
		if !e.Unbounded() {
			return nil, fmt.Errorf("%s.entries[%d]: a frozen outpoint has no height bounds; the interval leaf commits the outpoint key alone", name, i)
		}
		k, err := parseHex32(fmt.Sprintf("%s.entries[%d]", name, i), e.Key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	got, err := BlacklistRoot(keys)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if got != *declared {
		return nil, fmt.Errorf("%s.root mismatch: declared %s, entries hash to %x", name, p.Root, got)
	}
	return declared, nil
}

// computePiDMT is the pi a dmt-v1 snapshot commits to: the one the deployed
// verifier covenant is instantiated with. It mirrors `pi_of` in
// opendamp/src/bin/opendamp.rs exactly — a dmt-v1 whitelist root, a dmt-v1
// interval blacklist root, the covenant rules_root, and the asset id in
// INTERNAL byte order.
//
// Both list roots are commitments the covenant reads. An empty blacklist is NOT
// an absent one: the empty interval tree still has a root (the guard interval),
// so a policy that freezes nothing commits to that root rather than to zeros.
// Validate therefore refuses a dmt-v1 snapshot with no blacklist root at all,
// instead of quietly committing zeros the covenant would never accept.
//
// Blacklist entries are outpoint keys, SHA256(txid || BE32(vout)) with the txid
// in INTERNAL (consensus) byte order — the bytes the covenant's outpoint jet
// returns, not the reversed display form. Getting that backwards produces a root
// that looks right and freezes nothing.
//
// Height bounds ARE committed, per holder, inside the whitelist leaf, so a lockup
// or a receive window travels with the key it binds. The separate class-keyed
// "windows" array of the design document is a different construction that no
// shipped program reads, and Validate refuses it rather than committing to it.
func (s *Snapshot) computePiDMT() ([32]byte, error) {
	wl, err := dmtWhitelistRoot("predicates.whitelist", s.Predicates.Whitelist)
	if err != nil {
		return [32]byte{}, err
	}
	bl, err := dmtBlacklistRoot("predicates.blacklist", s.Predicates.Blacklist)
	if err != nil {
		return [32]byte{}, err
	}
	var limit uint64
	if s.Predicates.Limit != nil {
		limit = *s.Predicates.Limit
	}
	display, err := parseHex32("asset", s.Asset)
	if err != nil {
		return [32]byte{}, err
	}
	var internal [32]byte
	for i := 0; i < 32; i++ {
		internal[i] = display[31-i]
	}
	return PiCovenant(internal, s.Seq, RulesRootCovenant(bl, wl, limit, nil)), nil
}

// ComputePi derives the policy commitment the snapshot's contents imply. Which
// construction applies is selected by the tree field: dmt-v1 is the covenant's
// own commitment (computePiDMT), smt-v1 is the M2 document commitment below.
func (s *Snapshot) ComputePi() ([32]byte, error) {
	if s.Tree == TreeDMTv1 {
		return s.computePiDMT()
	}
	blRoot, err := predicateRoot("predicates.blacklist", s.Predicates.Blacklist)
	if err != nil {
		return [32]byte{}, err
	}
	wlRoot, err := predicateRoot("predicates.whitelist", s.Predicates.Whitelist)
	if err != nil {
		return [32]byte{}, err
	}
	var limit uint64
	if s.Predicates.Limit != nil {
		limit = *s.Predicates.Limit
	}
	wh, err := WindowsHash(s.Predicates.Windows)
	if err != nil {
		return [32]byte{}, err
	}
	asset, err := parseHex32("asset", s.Asset)
	if err != nil {
		return [32]byte{}, err
	}
	header := PolicyHeader{
		Version:   uint8(s.V),
		Asset:     asset,
		Seq:       s.Seq,
		RulesRoot: RulesRoot(blRoot, wlRoot, limit, wh),
	}
	return header.Commitment(), nil
}

// Validate checks the snapshot's internal consistency: version and tree, hex
// shapes, seq/prev_pi coherence, predicate roots recomputed from the inline
// entries, and pi recomputed from the header. It does NOT check issuer_sig
// (Verify) or chain linkage against previously published snapshots (the
// snapshot service does that against its store).
func (s *Snapshot) Validate() error {
	if s.V != 1 {
		return fmt.Errorf("v must be 1, got %d", s.V)
	}
	switch s.Tree {
	case TreeSMTv1:
	case TreeDMTv1:
		// The consensus-bearing format. Both list predicates are real: the covenant
		// reads a whitelist root AND a blacklist root, so both must be present and
		// recomputable. An empty blacklist still commits to the empty interval
		// tree's root, never to zeros, so "freeze nothing" is a root like any other
		// and its absence is a malformed policy rather than a permissive one.
		if s.Predicates.Whitelist.Root == "" {
			return fmt.Errorf("a dmt-v1 snapshot must carry a whitelist root: the covenant checks the recipient of every regulated output against it")
		}
		if s.Predicates.Blacklist.Root == "" {
			return fmt.Errorf("a dmt-v1 snapshot must carry a blacklist root: the covenant proves non-membership against it on every regulated input, and an empty blacklist still commits to the empty interval tree's root rather than to zeros")
		}
		// Refuse what nothing reads, rather than committing to it and implying
		// enforcement that does not exist. Height bounds themselves ARE enforced:
		// they belong to the holder they bind, inside the whitelist leaf, and this
		// refusal is about the separate class-keyed "windows" array, which no shipped
		// program reads.
		if len(s.Predicates.Windows) != 0 {
			return fmt.Errorf("a dmt-v1 snapshot must not carry a class-keyed windows array: no shipped covenant reads one. A height bound belongs to the holder it binds, as send_after/recv_after on that whitelist entry")
		}
		// A frozen outpoint has no window; refusing it here means the message names
		// the field rather than surfacing as a root mismatch.
		for i, e := range s.Predicates.Blacklist.Entries {
			if !e.Unbounded() {
				return fmt.Errorf("predicates.blacklist.entries[%d]: a frozen outpoint carries no height bounds", i)
			}
		}
	default:
		return fmt.Errorf("tree %q not supported (this library implements %q and %q)", s.Tree, TreeDMTv1, TreeSMTv1)
	}
	if _, err := parseHex32("verifier_asset", s.VerifierAsset); err != nil {
		return err
	}
	if s.VerifierAsset == s.Asset {
		return fmt.Errorf("verifier_asset must differ from asset")
	}
	if s.Q == 0 {
		return fmt.Errorf("q (verifier amount) must be positive")
	}
	if s.Seq == 0 {
		if s.PrevPi != nil {
			return fmt.Errorf("seq 0 must have prev_pi null")
		}
	} else {
		if s.PrevPi == nil {
			return fmt.Errorf("seq %d requires prev_pi", s.Seq)
		}
		if _, err := parseHex32("prev_pi", *s.PrevPi); err != nil {
			return err
		}
	}
	if s.Predicates.Limit != nil && *s.Predicates.Limit == 0 {
		return fmt.Errorf("limit must be positive or null (null means no limit)")
	}
	declared, err := parseHex32("pi", s.Pi)
	if err != nil {
		return err
	}
	computed, err := s.ComputePi()
	if err != nil {
		return err
	}
	if computed != declared {
		return fmt.Errorf("pi mismatch: declared %s, contents commit to %x", s.Pi, computed)
	}
	return nil
}
