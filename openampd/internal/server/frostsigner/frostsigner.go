package frostsigner

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Config is the quorum shape. Zero values take the production default (2-of-3).
type Config struct {
	Threshold    int // t: participants required to sign
	Participants int // n: participants holding shares
}

func (c Config) withDefaults() Config {
	if c.Threshold == 0 {
		c.Threshold = 2
	}
	if c.Participants == 0 {
		c.Participants = 3
	}
	return c
}

// FrostSigner implements server.PolicySigner as a t-of-n FROST quorum whose
// group public key is the on-chain policy key. Key material lives in the
// store's 0600 keys file:
//
//	frost:<assetID>:group     x-only group public key (hex)
//	frost:<assetID>:share:<i> participant i's share scalar (hex), i = 1..n
//
// (staged under frost-pending:<ref>:* between GeneratePolicyKey and Adopt).
//
// Assets provisioned by the LocalKeySigner (policy:<assetID>) keep working:
// PolicyPubKey and SignPolicy fall back to the local backend when an asset has
// no FROST keys, so switching -signer to frost strands nothing.
type FrostSigner struct {
	st    *store.Store
	cfg   Config
	local *server.LocalKeySigner // legacy single-key assets
}

// Compile-time proof that the backend tracks the PolicySigner seam.
var _ server.PolicySigner = (*FrostSigner)(nil)

// New returns a FROST backend over the given key store.
func New(st *store.Store, cfg Config) (*FrostSigner, error) {
	cfg = cfg.withDefaults()
	if cfg.Threshold < 2 || cfg.Participants < cfg.Threshold {
		return nil, fmt.Errorf("frostsigner: invalid quorum shape %d-of-%d", cfg.Threshold, cfg.Participants)
	}
	return &FrostSigner{st: st, cfg: cfg, local: server.NewLocalKeySigner(st)}, nil
}

// The frost backend registers itself for -signer selection; server cannot
// import this package back (it would cycle through the PolicySigner seam).
func init() {
	server.RegisterSigner("frost", func(st *store.Store) (server.PolicySigner, error) {
		return New(st, Config{})
	})
}

func pendingPrefix(ref string) string { return "frost-pending:" + ref + ":" }
func assetPrefix(assetID string) string {
	return "frost:" + assetID + ":"
}

// GeneratePolicyKey runs the dealer keygen and stages the share set under the
// ref (the hex group key, mirroring LocalKeySigner's ref convention).
//
// Dealer keygen is the testnet posture: one process samples the group secret
// and splits it, so that process transiently knows d. A DKG replaces the
// dealer later — the participants derive shares such that no one ever holds d
// — without changing this seam, the storage shape, or the meaning of the group
// key: the on-chain policy key is the group public key either way.
func (f *FrostSigner) GeneratePolicyKey() ([32]byte, string, error) {
	groupX, shares, err := dealerKeygen(f.cfg.Threshold, f.cfg.Participants, rand.Reader)
	if err != nil {
		return [32]byte{}, "", err
	}
	ref := hex.EncodeToString(groupX[:])
	if err := f.st.SaveKey(pendingPrefix(ref)+"group", ref); err != nil {
		return [32]byte{}, "", err
	}
	for i, sh := range shares {
		if err := f.st.SaveKey(fmt.Sprintf("%sshare:%d", pendingPrefix(ref), i+1), hex.EncodeToString(sh[:])); err != nil {
			return [32]byte{}, "", err
		}
	}
	return groupX, ref, nil
}

// Adopt binds a staged share set to its final asset id in one atomic keys-file
// write (no crash can leave a half-bound quorum).
func (f *FrostSigner) Adopt(ref, assetID string) error {
	return f.st.RenameKeyPrefix(pendingPrefix(ref), assetPrefix(assetID))
}

// loadQuorum reads an asset's group key and shares from the keys file.
func (f *FrostSigner) loadQuorum(assetID string) (groupX [32]byte, shares map[int][32]byte, ok bool) {
	keys, err := f.st.LoadKeys()
	if err != nil {
		return groupX, nil, false
	}
	g, has := keys[assetPrefix(assetID)+"group"]
	gb, err := hex.DecodeString(g)
	if !has || err != nil || len(gb) != 32 {
		return groupX, nil, false
	}
	copy(groupX[:], gb)
	shares = map[int][32]byte{}
	sharePrefix := assetPrefix(assetID) + "share:"
	for name, v := range keys {
		suffix, isShare := strings.CutPrefix(name, sharePrefix)
		if !isShare {
			continue
		}
		id, err := strconv.Atoi(suffix)
		if err != nil || id < 1 {
			continue
		}
		sb, err := hex.DecodeString(v)
		if err != nil || len(sb) != 32 {
			return groupX, nil, false
		}
		var s [32]byte
		copy(s[:], sb)
		shares[id] = s
	}
	if len(shares) < f.cfg.Threshold {
		return groupX, nil, false
	}
	return groupX, shares, true
}

func (f *FrostSigner) PolicyPubKey(assetID string) ([32]byte, bool) {
	if groupX, _, ok := f.loadQuorum(assetID); ok {
		return groupX, true
	}
	return f.local.PolicyPubKey(assetID) // legacy single-key asset
}

// SignPolicy runs the two-round protocol with a threshold subset of the
// asset's shares and returns one BIP340 signature verifying under the group
// key. The PolicyContext is logged — the in-process stand-in for each quorum
// member seeing what it is asked to authorize — and never contributes
// signature bytes.
func (f *FrostSigner) SignPolicy(assetID string, sighash [32]byte, ctx server.PolicyContext) ([]byte, error) {
	groupX, shares, ok := f.loadQuorum(assetID)
	if !ok {
		return f.local.SignPolicy(assetID, sighash, ctx) // legacy single-key asset
	}
	ids := make([]int, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	subset := map[int][32]byte{}
	for _, id := range ids[:f.cfg.Threshold] {
		subset[id] = shares[id]
	}
	sig, gotX, err := signFROST(sighash, subset, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("frost sign (asset %s): %w", assetID, err)
	}
	if gotX != groupX {
		return nil, fmt.Errorf("frost sign (asset %s): shares reconstruct key %x, stored group key is %x",
			assetID, gotX, groupX)
	}
	// Self-check against the library verifier before the signature leaves the
	// backend: a parity or aggregation bug fails loudly here, never on-chain.
	pub, err := schnorr.ParsePubKey(groupX[:])
	if err != nil {
		return nil, err
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return nil, err
	}
	if !parsed.Verify(sighash[:], pub) {
		return nil, fmt.Errorf("frost sign (asset %s): aggregate does not verify under the group key", assetID)
	}
	log.Printf("frost: %d-of-%d quorum %v co-signed action=%s asset=%s aid=%s txid=%s input=%d",
		f.cfg.Threshold, f.cfg.Participants, ids[:f.cfg.Threshold],
		ctx.Action, assetID, ctx.AID, ctx.TxID, ctx.InputIndex)
	return sig, nil
}
