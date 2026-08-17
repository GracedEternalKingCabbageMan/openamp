package frostsigner

import (
	"errors"
	"fmt"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
)

// ErrNotConfigured is returned by every FrostSigner method until a real FROST
// implementation (DKG, member transport, signing rounds) is configured. It is a
// sentinel so callers and tests can distinguish "backend absent" from a signing
// failure.
var ErrNotConfigured = errors.New("frostsigner: not configured (FROST backend is scaffolding; use LocalKeySigner)")

// Config describes the quorum a FrostSigner will run. Held for shape only; no
// field is consumed yet.
type Config struct {
	Threshold int      // t: members required to sign (production: 2)
	Members   []string // transport addresses of the n members (production: 3)
}

// FrostSigner implements server.PolicySigner as a 2-of-3 FROST quorum. All
// methods currently refuse with ErrNotConfigured; see doc.go for the design
// they will implement.
type FrostSigner struct {
	cfg Config
}

// Compile-time proof that the skeleton tracks the PolicySigner seam.
var _ server.PolicySigner = (*FrostSigner)(nil)

// New returns a FrostSigner skeleton for the given quorum shape.
func New(cfg Config) *FrostSigner { return &FrostSigner{cfg: cfg} }

// GeneratePolicyKey will run the DKG across the members and return the group
// public key (the on-chain policy key) plus a ref naming the DKG session.
func (f *FrostSigner) GeneratePolicyKey() ([32]byte, string, error) {
	return [32]byte{}, "", fmt.Errorf("GeneratePolicyKey (DKG): %w", ErrNotConfigured)
}

// Adopt will bind a completed DKG session's group key to its final asset id.
func (f *FrostSigner) Adopt(ref, assetID string) error {
	return fmt.Errorf("Adopt %q -> asset %s: %w", ref, assetID, ErrNotConfigured)
}

// PolicyPubKey will return the asset's group public key. ok=false until the
// backend is configured (there is no key material to report).
func (f *FrostSigner) PolicyPubKey(assetID string) ([32]byte, bool) {
	return [32]byte{}, false
}

// SignPolicy will fan the sighash (with its advisory PolicyContext) out to the
// quorum, run the FROST signing rounds with any t members, and aggregate one
// 64-byte BIP340 signature verifying under the group key.
func (f *FrostSigner) SignPolicy(assetID string, sighash [32]byte, ctx server.PolicyContext) ([]byte, error) {
	return nil, fmt.Errorf("SignPolicy %s for asset %s: %w", ctx.Action, assetID, ErrNotConfigured)
}
