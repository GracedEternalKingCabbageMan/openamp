package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// PolicySigner produces BIP340 signatures under an asset's policy key.
//
// The enclave script is always `<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG`
// with a SINGLE x-only policy key on-chain, so the quorum is entirely a
// backend concern: nothing about enclaves, contracts, wallets, or any
// already-issued asset changes when the backend changes.
//
//   - Testnet / PoC: LocalKeySigner holds one key per asset (this file).
//   - Mainnet: a FROST (or threshold-Schnorr MPC / threshold-custody HSM)
//     backend implements this same interface. The on-chain K_policy is the
//     FROST group public key; signing runs a t-of-n quorum off-chain and
//     returns one 64-byte signature that verifies under K_policy. Because the
//     group key is invariant under share resharing, the quorum's signer set
//     and threshold can be rotated over the asset's life with NO chain
//     migration of holders' funds. That rotation property is the reason the
//     quorum lives off-chain behind this seam rather than on-chain as a
//     k-of-n script multisig (which would bake the signer set into every
//     enclave address).
type PolicySigner interface {
	// GeneratePolicyKey provisions a new policy key and returns its x-only
	// public key plus an opaque ref. The pubkey is needed to build the
	// issuance contract; the asset id is only known afterwards (it commits to
	// this pubkey), so the material is bound to its asset id later via Adopt.
	// In production this runs the DKG and returns the group public key.
	GeneratePolicyKey() (pub [32]byte, ref string, err error)

	// Adopt binds a provisioned key (from GeneratePolicyKey) to its final
	// asset id, once issuance has derived it.
	Adopt(ref, assetID string) error

	// PolicyPubKey returns the asset's x-only policy public key.
	PolicyPubKey(assetID string) (pub [32]byte, ok bool)

	// SignPolicy returns a 64-byte BIP340 signature over sighash under the
	// asset's policy key. Production fans this out to the quorum and
	// aggregates; the caller neither knows nor cares.
	SignPolicy(assetID string, sighash [32]byte) (sig []byte, err error)
}

// LocalKeySigner is the single-key backend: it stores one policy private key
// per asset in the store's 0600 keys file. Appropriate for testnet and demos
// only; production replaces it with a threshold backend behind the same
// interface (see PolicySigner).
type LocalKeySigner struct {
	st *store.Store
}

func NewLocalKeySigner(st *store.Store) *LocalKeySigner { return &LocalKeySigner{st: st} }

func (l *LocalKeySigner) key(assetID string) string { return "policy:" + assetID }

func (l *LocalKeySigner) GeneratePolicyKey() ([32]byte, string, error) {
	var pub [32]byte
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return pub, "", err
	}
	pub = elements.XOnlyFromPriv(priv)
	ref := hex.EncodeToString(pub[:])
	if err := l.st.SaveKey("policy-pending:"+ref, hex.EncodeToString(priv)); err != nil {
		return pub, "", err
	}
	return pub, ref, nil
}

func (l *LocalKeySigner) Adopt(ref, assetID string) error {
	return l.st.RenameKey("policy-pending:"+ref, l.key(assetID))
}

func (l *LocalKeySigner) priv(assetID string) ([]byte, bool) {
	keys, err := l.st.LoadKeys()
	if err != nil {
		return nil, false
	}
	h, ok := keys[l.key(assetID)]
	if !ok {
		return nil, false
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, false
	}
	return b, true
}

func (l *LocalKeySigner) PolicyPubKey(assetID string) ([32]byte, bool) {
	var pub [32]byte
	priv, ok := l.priv(assetID)
	if !ok {
		return pub, false
	}
	return elements.XOnlyFromPriv(priv), true
}

func (l *LocalKeySigner) SignPolicy(assetID string, sighash [32]byte) ([]byte, error) {
	priv, ok := l.priv(assetID)
	if !ok {
		return nil, fmt.Errorf("policy key unavailable for asset %s", assetID)
	}
	return elements.SignSchnorr(priv, sighash)
}
