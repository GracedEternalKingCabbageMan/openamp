package frostsigner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// KeygenMode selects how a new policy key is generated.
type KeygenMode string

const (
	// KeygenDKG is the default: a distributed key generation in which every
	// member samples its own polynomial, so no component ever holds the group
	// secret.
	KeygenDKG KeygenMode = "dkg"
	// KeygenDealer is the trusted-dealer Shamir split. One component samples
	// the group secret and splits it, so that component transiently knows it.
	// Kept because it is the construction the pinned test vectors were computed
	// under, and because it needs no member-to-member round; it must be asked
	// for explicitly, and only an in-process transport can install its shares.
	KeygenDealer KeygenMode = "dealer"
)

// Config is the quorum shape and policy. Zero values take the production
// defaults: 2-of-3, DKG keygen, a 10s per-round-trip timeout, crypto/rand.
type Config struct {
	Threshold    int           // t: members required to sign
	Participants int           // n: members holding shares
	Keygen       KeygenMode    // "dkg" (default) or "dealer"
	RoundTimeout time.Duration // per Member call; a hung member counts as unreachable
	Rand         io.Reader     // secret source for the built-in in-process transport
}

func (c Config) withDefaults() Config {
	if c.Threshold == 0 {
		c.Threshold = 2
	}
	if c.Participants == 0 {
		c.Participants = 3
	}
	if c.Keygen == "" {
		c.Keygen = KeygenDKG
	}
	if c.RoundTimeout == 0 {
		c.RoundTimeout = 10 * time.Second
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	return c
}

// FrostSigner implements server.PolicySigner as a t-of-n FROST quorum whose
// group public key IS the on-chain policy key, and is the COORDINATOR of that
// quorum: it holds no share and talks to the members only through the Transport
// seam (transport.go), so the protocol is unchanged whether the members are
// goroutines or hosts.
//
// What the coordinator persists (public data only):
//
//	frost:<assetID>:group        group public key (33-byte compressed; 32-byte
//	                             x-only for keys generated before the point was
//	                             recorded in full)
//	frost:<assetID>:pubshare:<i> member i's public share Y_i, pinned at keygen
//
// Each member persists its own share (the in-process member writes
// frost:<assetID>:share:<i> into the same 0600 keys file — see doc.go on what
// that does and does not prove).
//
// Assets provisioned by the LocalKeySigner (policy:<assetID>) keep working:
// PolicyPubKey and SignPolicy fall back to the local backend when an asset has
// no FROST key material, so switching -signer to frost strands nothing.
type FrostSigner struct {
	st    *store.Store
	cfg   Config
	tr    Transport
	local *server.LocalKeySigner // legacy single-key assets
}

// Compile-time proof that the backend tracks the PolicySigner seam.
var _ server.PolicySigner = (*FrostSigner)(nil)

// New returns a FROST backend running its quorum in this process.
func New(st *store.Store, cfg Config) (*FrostSigner, error) {
	cfg = cfg.withDefaults()
	return NewWithTransport(st, cfg, NewLocalTransport(st, cfg.Participants, cfg.Rand))
}

// NewWithTransport returns a FROST backend over an explicit transport — the
// entry point a networked quorum uses. The transport must expose exactly
// cfg.Participants members.
func NewWithTransport(st *store.Store, cfg Config, tr Transport) (*FrostSigner, error) {
	cfg = cfg.withDefaults()
	if cfg.Threshold < 2 || cfg.Participants < cfg.Threshold {
		return nil, fmt.Errorf("frostsigner: invalid quorum shape %d-of-%d", cfg.Threshold, cfg.Participants)
	}
	if cfg.Keygen != KeygenDKG && cfg.Keygen != KeygenDealer {
		return nil, fmt.Errorf("frostsigner: unknown keygen mode %q (want %q or %q)", cfg.Keygen, KeygenDKG, KeygenDealer)
	}
	if got := len(tr.Members()); got != cfg.Participants {
		return nil, fmt.Errorf("frostsigner: transport exposes %d members, quorum is %d-of-%d", got, cfg.Threshold, cfg.Participants)
	}
	return &FrostSigner{st: st, cfg: cfg, tr: tr, local: server.NewLocalKeySigner(st)}, nil
}

// The frost backend registers itself for -signer selection; server cannot
// import this package back (it would cycle through the PolicySigner seam).
// OPENAMPD_FROST_KEYGEN=dealer selects the trusted dealer for a run that must
// reproduce dealer-generated material; anything else (including unset) is DKG.
func init() {
	server.RegisterSigner("frost", func(st *store.Store) (server.PolicySigner, error) {
		cfg := Config{}
		if mode := os.Getenv("OPENAMPD_FROST_KEYGEN"); mode != "" {
			cfg.Keygen = KeygenMode(mode)
		}
		return New(st, cfg)
	})
}

// --- provisioning ------------------------------------------------------------

// GeneratePolicyKey provisions a new group key and returns its x-only form plus
// an opaque ref. The key material is staged under a provisional KeyID until
// Adopt binds it to the asset id issuance derives.
func (f *FrostSigner) GeneratePolicyKey() ([32]byte, string, error) {
	ref, err := randomHex()
	if err != nil {
		return [32]byte{}, "", err
	}
	keyID := pendingKeyPrefix + ref
	var P *secp.JacobianPoint
	switch f.cfg.Keygen {
	case KeygenDealer:
		P, err = f.runDealerKeygen(keyID)
	default:
		P, err = f.runDKG(keyID)
	}
	if err != nil {
		return [32]byte{}, "", err
	}
	return xBytes(P), ref, nil
}

// runDKG drives the distributed key generation across every member and persists
// only public material. Every member must take part: DKG has no threshold, so
// any failure aborts the session, every member rolls back, and nothing is
// persisted — there is no such thing as a partially generated key.
func (f *FrostSigner) runDKG(keyID string) (*secp.JacobianPoint, error) {
	idents := f.tr.Members()
	sessionID, err := randomHex()
	if err != nil {
		return nil, err
	}
	sess := DKGSession{ID: sessionID, KeyID: keyID, Threshold: f.cfg.Threshold, Members: idents}

	handles := make(map[int]Member, len(idents))
	for _, ident := range idents {
		m, err := f.tr.Member(ident.ID)
		if err != nil {
			f.abortDKG(handles, sessionID)
			return nil, fmt.Errorf("dkg: member %d: %w", ident.ID, err)
		}
		handles[ident.ID] = m
	}
	fail := func(err error) (*secp.JacobianPoint, error) {
		f.abortDKG(handles, sessionID)
		return nil, err
	}

	// Round 1: every member commits to its own polynomial.
	comms := make(map[int]*DKGCommitment, len(idents))
	for _, ident := range idents {
		ctx, cancel := f.roundCtx()
		c, err := handles[ident.ID].Commit(ctx, sess)
		cancel()
		if err != nil {
			return fail(fmt.Errorf("dkg round 1: member %d: %w", ident.ID, err))
		}
		if c.From != ident.ID {
			return fail(misbehaved(ident.ID, "returned a commitment attributed to member %d", c.From))
		}
		// The coordinator verifies the proof of knowledge itself, so it never
		// takes a member's word for its contribution.
		if err := verifyCommitment(sessionID, f.cfg.Threshold, c); err != nil {
			return fail(err)
		}
		comms[ident.ID] = c
	}

	// The group key and every public share come from the commitments — public
	// data, derived by the coordinator, never reported by a member.
	P, err := groupPoint(comms)
	if err != nil {
		return fail(fmt.Errorf("dkg: %w", err))
	}
	pubShares := make(map[int][]byte, len(idents))
	for _, ident := range idents {
		Y, err := publicShareFrom(comms, ident.ID)
		if err != nil {
			return fail(fmt.Errorf("dkg: %w", err))
		}
		pubShares[ident.ID] = compressPoint(Y)
	}

	// Round 2: every member deals its shares to its peers directly.
	for _, ident := range idents {
		ctx, cancel := f.roundCtx()
		err := handles[ident.ID].Deal(ctx, sess, comms)
		cancel()
		if err != nil {
			return fail(fmt.Errorf("dkg round 2: member %d: %w", ident.ID, err))
		}
	}

	// Round 3: every member verifies what it received against the commitments
	// and reports the group key it derived. Divergence names the member.
	want := compressPoint(P)
	for _, ident := range idents {
		ctx, cancel := f.roundCtx()
		res, err := handles[ident.ID].Finalize(ctx, sess)
		cancel()
		if err != nil {
			return fail(fmt.Errorf("dkg round 3: member %d: %w", ident.ID, err))
		}
		if !bytesEqual(res.GroupKey, want) {
			return fail(misbehaved(ident.ID, "derived group key %x, the commitments give %x", res.GroupKey, want))
		}
	}

	if err := f.saveRecord(keyID, want, pubShares); err != nil {
		// saveRecord writes several entries; purge whatever landed so a failed
		// keygen really does leave nothing behind, on either side.
		f.purgeRecord(keyID)
		return fail(fmt.Errorf("dkg: persist group record: %w", err))
	}
	log.Printf("frost: DKG complete for key %s — %d-of-%d, group key %x (no component holds the group secret)",
		keyID, f.cfg.Threshold, f.cfg.Participants, xBytes(P))
	return P, nil
}

// dealerInstaller is implemented by a transport whose members can be handed
// externally generated shares. Only the in-process transport does: a networked
// member must never accept a share it did not help generate, which is exactly
// the guarantee the DKG exists to provide.
type dealerInstaller interface {
	InstallDealtShares(keyID string, shares map[int][32]byte) error
}

// runDealerKeygen splits a freshly sampled group secret and installs the
// shares. Explicitly requested only (Config.Keygen = KeygenDealer).
func (f *FrostSigner) runDealerKeygen(keyID string) (*secp.JacobianPoint, error) {
	installer, ok := f.tr.(dealerInstaller)
	if !ok {
		return nil, fmt.Errorf("frostsigner: keygen mode %q needs a transport that can install dealt shares; "+
			"this transport's members only accept material they generated themselves (use %q)", KeygenDealer, KeygenDKG)
	}
	_, shareList, err := dealerKeygen(f.cfg.Threshold, f.cfg.Participants, f.cfg.Rand)
	if err != nil {
		return nil, err
	}
	shares := make(map[int][32]byte, len(shareList))
	for i, sh := range shareList {
		shares[i+1] = sh
	}
	P, err := groupPointFromShares(shares)
	if err != nil {
		return nil, err
	}
	pubShares := make(map[int][]byte, len(shares))
	for id, sh := range shares {
		s := new(secp.ModNScalar)
		v := sh
		s.SetBytes(&v)
		pubShares[id] = compressPoint(pointFromScalar(s))
	}
	if err := installer.InstallDealtShares(keyID, shares); err != nil {
		return nil, err
	}
	if err := f.saveRecord(keyID, compressPoint(P), pubShares); err != nil {
		return nil, err
	}
	log.Printf("frost: dealer keygen complete for key %s — %d-of-%d, group key %x (the dealer transiently held the group secret)",
		keyID, f.cfg.Threshold, f.cfg.Participants, xBytes(P))
	return P, nil
}

// abortDKG rolls every member back, best effort: a member that cannot be
// reached to abort keeps nothing usable (its share alone cannot sign, and the
// coordinator persisted no group record), but the leftover is logged.
func (f *FrostSigner) abortDKG(handles map[int]Member, sessionID string) {
	for _, id := range sortedIDs(handles) {
		ctx, cancel := f.roundCtx()
		err := handles[id].AbortDKG(ctx, sessionID)
		cancel()
		if err != nil {
			log.Printf("frost: member %d did not roll back DKG session %s: %v", id, sessionID, err)
		}
	}
}

// abortSign tells the members of an abandoned signing round to drop the nonces
// they committed. Best effort: a member that cannot be reached expires them on
// its own (see sessionTTL), and a stranded nonce pair is a liveness nuisance,
// never a correctness one — it can still only ever produce one partial.
func (f *FrostSigner) abortSign(handles map[int]Member, sessionID string) {
	for _, id := range sortedIDs(handles) {
		ctx, cancel := f.roundCtx()
		err := handles[id].AbortSign(ctx, sessionID)
		cancel()
		if err != nil {
			log.Printf("frost: member %d did not drop its nonces for abandoned session %s: %v", id, sessionID, err)
		}
	}
}

// purgeRecord deletes the coordinator's public record for a key.
func (f *FrostSigner) purgeRecord(keyID string) {
	prefix := storagePrefix(keyID)
	names := []string{prefix + "group"}
	for _, ident := range f.tr.Members() {
		names = append(names, fmt.Sprintf("%spubshare:%d", prefix, ident.ID))
	}
	for _, name := range names {
		if err := f.st.DeleteKey(name); err != nil {
			log.Printf("frost: could not purge %s: %v", name, err)
		}
	}
}

// Adopt binds staged key material to its final asset id: every member renames
// its own share, then the coordinator renames its own public record. Idempotent
// end to end — per member, and here — so a retry after a partial failure (or
// after a completed adopt whose response was lost) completes the binding
// instead of reporting a broken one.
func (f *FrostSigner) Adopt(ref, assetID string) error {
	from := pendingKeyPrefix + ref
	for _, ident := range f.tr.Members() {
		m, err := f.tr.Member(ident.ID)
		if err != nil {
			return fmt.Errorf("adopt: member %d: %w", ident.ID, err)
		}
		ctx, cancel := f.roundCtx()
		err = m.Adopt(ctx, from, assetID)
		cancel()
		if err != nil {
			return fmt.Errorf("adopt: member %d: %w", ident.ID, err)
		}
	}
	err := f.st.RenameKeyPrefix(storagePrefix(from), storagePrefix(assetID))
	if err != nil {
		// Nothing staged left to move: already adopted is success, anything else
		// is a real failure.
		if _, bound := f.loadRecord(assetID); bound {
			return nil
		}
		return fmt.Errorf("adopt: %w", err)
	}
	return nil
}

// --- stored public record ----------------------------------------------------

// quorumRecord is the coordinator's public view of a key.
type quorumRecord struct {
	group     *secp.JacobianPoint // full group point, when recorded in full
	groupX    [32]byte
	pubShares map[int][]byte // pinned public shares; empty for pre-pinning keys
}

func (f *FrostSigner) saveRecord(keyID string, group33 []byte, pubShares map[int][]byte) error {
	prefix := storagePrefix(keyID)
	if err := f.st.SaveKey(prefix+"group", hex.EncodeToString(group33)); err != nil {
		return err
	}
	for _, id := range sortedIDs(pubShares) {
		if err := f.st.SaveKey(fmt.Sprintf("%spubshare:%d", prefix, id), hex.EncodeToString(pubShares[id])); err != nil {
			return err
		}
	}
	return nil
}

// errNoFrostKey means this key has no FROST material at all, which is the one
// condition that legitimately falls back to the single-key backend. A record
// that exists but cannot be read is a different thing entirely and must be
// reported, never silently routed around.
var errNoFrostKey = errors.New("no frost key material")

// readRecord reads the coordinator's record for a key. A 33-byte group value is
// the current form (the parity of the group point is part of the record); a
// 32-byte value is the x-only form written by the first release of this backend
// and is still honoured — the missing parity and public shares are recovered
// from the members at signing time.
func (f *FrostSigner) readRecord(keyID string) (*quorumRecord, error) {
	keys, err := f.st.LoadKeys()
	if err != nil {
		return nil, fmt.Errorf("read key store: %w", err)
	}
	prefix := storagePrefix(keyID)
	g, has := keys[prefix+"group"]
	if !has {
		return nil, errNoFrostKey
	}
	gb, err := hex.DecodeString(g)
	if err != nil {
		return nil, fmt.Errorf("group record for %s is not hex: %w", keyID, err)
	}
	rec := &quorumRecord{pubShares: map[int][]byte{}}
	switch len(gb) {
	case 33:
		P, err := parsePoint(gb)
		if err != nil {
			return nil, fmt.Errorf("group record for %s: %w", keyID, err)
		}
		rec.group = P
		rec.groupX = xBytes(P)
	case 32:
		copy(rec.groupX[:], gb)
	default:
		return nil, fmt.Errorf("group record for %s is %d bytes, want 32 or 33", keyID, len(gb))
	}
	pubPrefix := prefix + "pubshare:"
	for name, v := range keys {
		suffix, isPub := strings.CutPrefix(name, pubPrefix)
		if !isPub {
			continue
		}
		id, err := strconv.Atoi(suffix)
		if err != nil || id < 1 {
			continue
		}
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != 33 {
			return nil, fmt.Errorf("public share record %s is malformed", name)
		}
		rec.pubShares[id] = b
	}
	return rec, nil
}

// loadRecord is readRecord for callers that only care whether a usable record
// exists.
func (f *FrostSigner) loadRecord(keyID string) (*quorumRecord, bool) {
	rec, err := f.readRecord(keyID)
	return rec, err == nil
}

func (f *FrostSigner) PolicyPubKey(assetID string) ([32]byte, bool) {
	rec, err := f.readRecord(assetID)
	switch {
	case err == nil:
		return rec.groupX, true
	case errors.Is(err, errNoFrostKey):
		return f.local.PolicyPubKey(assetID) // legacy single-key asset
	default:
		log.Printf("frost: policy key for asset %s is unreadable: %v", assetID, err)
		return [32]byte{}, false
	}
}

// --- signing -----------------------------------------------------------------

// SignPolicy runs the two-round FROST protocol with a threshold subset of the
// quorum and returns one 64-byte BIP340 signature verifying under the group
// key. Every partial is verified before aggregation and the aggregate is
// verified against the group key before it leaves the backend.
//
// Liveness: members that cannot be reached are skipped while t remain, and a
// member that answers round 1 but fails round 2 is excluded and the round
// restarts under a FRESH session — never with consumed nonces. Misbehavior
// (provably invalid material) is never retried around: it names the member and
// fails.
func (f *FrostSigner) SignPolicy(assetID string, sighash [32]byte, ctx server.PolicyContext) ([]byte, error) {
	rec, err := f.readRecord(assetID)
	if errors.Is(err, errNoFrostKey) {
		return f.local.SignPolicy(assetID, sighash, ctx) // legacy single-key asset
	}
	if err != nil {
		// A FROST asset whose record is unreadable must fail loudly here: the
		// single-key backend holds no key that matches this asset's K_policy, so
		// falling back would only turn a clear error into a confusing one.
		return nil, fmt.Errorf("frost sign (asset %s): %w", assetID, err)
	}
	req := SignRequest{
		Action: ctx.Action, AID: ctx.AID, TxID: ctx.TxID,
		Reason: ctx.Reason, InputIndex: ctx.InputIndex,
	}
	excluded := map[int]bool{}
	var failures []error
	for attempt := 0; attempt <= f.cfg.Participants-f.cfg.Threshold; attempt++ {
		sig, signers, badMember, err := f.signOnce(assetID, rec, sighash, req, excluded)
		if err == nil {
			log.Printf("frost: %d-of-%d quorum %v co-signed action=%s asset=%s aid=%s txid=%s input=%d",
				f.cfg.Threshold, f.cfg.Participants, signers,
				ctx.Action, assetID, ctx.AID, ctx.TxID, ctx.InputIndex)
			return sig, nil
		}
		var mis *MisbehaviorError
		if errors.As(err, &mis) {
			return nil, fmt.Errorf("frost sign (asset %s): %w", assetID, err)
		}
		if badMember == 0 {
			return nil, fmt.Errorf("frost sign (asset %s): %w", assetID, err)
		}
		// A member dropped out mid-round: exclude it and retry with a fresh
		// session, so its consumed nonces are never reused.
		excluded[badMember] = true
		failures = append(failures, err)
		log.Printf("frost: excluding member %d for this signature and retrying: %v", badMember, err)
	}
	return nil, fmt.Errorf("frost sign (asset %s): no %d-member quorum could be assembled: %w",
		assetID, f.cfg.Threshold, errors.Join(failures...))
}

// signOnce runs one complete signing attempt. badMember names a member that
// failed in a way a retry without it could survive (unreachable, refused,
// dropped between rounds); it is 0 for failures that are not attributable.
func (f *FrostSigner) signOnce(keyID string, rec *quorumRecord, sighash [32]byte,
	req SignRequest, excluded map[int]bool) (sig []byte, signers []int, badMember int, err error) {

	sessionID, err := randomHex()
	if err != nil {
		return nil, nil, 0, err
	}

	// Round 1: collect nonce commitments in member order until t answer.
	handles := map[int]Member{}
	commitments := []*NonceCommitment{}
	var skipped []error
	for _, ident := range f.tr.Members() {
		if len(commitments) == f.cfg.Threshold {
			break
		}
		if excluded[ident.ID] {
			continue
		}
		m, err := f.tr.Member(ident.ID)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("member %d: %w", ident.ID, err))
			continue
		}
		sess := SignSession{ID: sessionID, KeyID: keyID, Request: req}
		ctx, cancel := f.roundCtx()
		nc, err := m.NonceCommit(ctx, sess)
		cancel()
		if err != nil {
			skipped = append(skipped, fmt.Errorf("member %d: %w", ident.ID, err))
			continue
		}
		if nc.From != ident.ID {
			return nil, nil, 0, misbehaved(ident.ID, "returned a nonce commitment attributed to member %d", nc.From)
		}
		handles[ident.ID] = m
		commitments = append(commitments, nc)
	}
	if len(commitments) < f.cfg.Threshold {
		return nil, nil, 0, fmt.Errorf("only %d of %d required members committed nonces: %w",
			len(commitments), f.cfg.Threshold, errors.Join(skipped...))
	}
	signers = sortedIDs(handles)
	// Anything that abandons the round from here on leaves committed nonces
	// behind, so every exit path tells those members to drop them.
	abandoned := true
	defer func() {
		if abandoned {
			f.abortSign(handles, sessionID)
		}
	}()

	// The group point and the public shares of THIS subset: pinned at keygen
	// where available, recovered from the members otherwise.
	P, pubShares, err := f.verificationData(keyID, rec, signers, handles)
	if err != nil {
		return nil, nil, 0, err
	}
	pkg := &SigningPackage{Message: sighash, GroupKey: compressPoint(P), Commitments: commitments}
	sctx, err := newSigningContext(pkg)
	if err != nil {
		return nil, nil, 0, err
	}
	if sctx.groupX != rec.groupX {
		return nil, nil, 0, fmt.Errorf("group key mismatch: signing under %x, record says %x", sctx.groupX, rec.groupX)
	}

	// Round 2: collect partials. A member failing here has burned its nonces,
	// so the caller retries with a fresh session and without it.
	partials := map[int][32]byte{}
	for _, id := range signers {
		sess := SignSession{ID: sessionID, KeyID: keyID, Signers: signers, Request: req}
		ctx, cancel := f.roundCtx()
		p, err := handles[id].Partial(ctx, sess, pkg)
		cancel()
		if err != nil {
			var mis *MisbehaviorError
			if errors.As(err, &mis) {
				return nil, nil, 0, err
			}
			return nil, nil, id, err
		}
		partials[id] = p
	}

	sig, err = sctx.aggregate(partials, pubShares)
	if err != nil {
		return nil, nil, 0, err
	}
	// Self-check against the library verifier before the signature leaves the
	// backend: a parity or aggregation bug fails loudly here, never on-chain.
	pub, err := schnorr.ParsePubKey(rec.groupX[:])
	if err != nil {
		return nil, nil, 0, err
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return nil, nil, 0, err
	}
	if !parsed.Verify(sighash[:], pub) {
		return nil, nil, 0, fmt.Errorf("aggregate does not verify under the group key")
	}
	abandoned = false // every member consumed its nonces producing a partial
	return sig, signers, 0, nil
}

// verificationData resolves the full group point and the signing subset's
// public shares.
//
// For a key generated by this version both are pinned in the coordinator's
// record, straight from the DKG commitments, so a member cannot misreport its
// public share and a bad partial is always attributable to it. For a key
// generated by the first release (x-only group value, no pinned public shares)
// they are recovered from the members and cross-checked: sum(lambda_i*Y_i) must
// equal the recorded group key, which detects a misreported public share but
// cannot attribute it — the documented cost of that older layout.
func (f *FrostSigner) verificationData(keyID string, rec *quorumRecord, signers []int,
	handles map[int]Member) (*secp.JacobianPoint, map[int]*secp.JacobianPoint, error) {

	pubShares := make(map[int]*secp.JacobianPoint, len(signers))
	pinned := true
	for _, id := range signers {
		b, has := rec.pubShares[id]
		if !has {
			pinned = false
			break
		}
		Y, err := parsePoint(b)
		if err != nil {
			return nil, nil, fmt.Errorf("stored public share of member %d: %w", id, err)
		}
		pubShares[id] = Y
	}
	if !pinned {
		pubShares = make(map[int]*secp.JacobianPoint, len(signers))
		for _, id := range signers {
			ctx, cancel := f.roundCtx()
			b, err := handles[id].PublicShare(ctx, keyID)
			cancel()
			if err != nil {
				return nil, nil, fmt.Errorf("public share of member %d: %w", id, err)
			}
			Y, err := parsePoint(b)
			if err != nil {
				return nil, nil, misbehaved(id, "reported an invalid public share: %v", err)
			}
			pubShares[id] = Y
		}
	}

	// sum(lambda_i * Y_i) must be the group point, whichever source the shares
	// came from: it validates the pinned record against corruption and the
	// recovered shares against misreporting.
	var P secp.JacobianPoint
	for _, id := range signers {
		var term, sum secp.JacobianPoint
		secp.ScalarMultNonConst(lagrange(signers, id), pubShares[id], &term)
		secp.AddNonConst(&P, &term, &sum)
		P.Set(&sum)
	}
	P.ToAffine()
	if isInfinity(&P) {
		return nil, nil, fmt.Errorf("public shares of %v reconstruct no group key", signers)
	}
	if xBytes(&P) != rec.groupX {
		return nil, nil, fmt.Errorf("public shares of members %v reconstruct key %x, the record says %x",
			signers, xBytes(&P), rec.groupX)
	}
	if rec.group != nil && (!P.X.Equals(&rec.group.X) || !P.Y.Equals(&rec.group.Y)) {
		return nil, nil, fmt.Errorf("public shares of members %v disagree with the recorded group point's parity", signers)
	}
	return &P, pubShares, nil
}

// --- helpers -----------------------------------------------------------------

// roundCtx bounds one Member call. A member that does not answer within
// Config.RoundTimeout is treated exactly like an unreachable one.
func (f *FrostSigner) roundCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), f.cfg.RoundTimeout)
}

func randomHex() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
