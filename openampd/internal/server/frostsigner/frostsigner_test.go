package frostsigner

import (
	"errors"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
)

// TestFrostSigner_NotConfigured proves the skeleton is honest: every method
// refuses with ErrNotConfigured (never a silent zero-value success), and
// PolicyPubKey reports no key. If any method started "working" without a real
// FROST implementation behind it, this test is the tripwire.
func TestFrostSigner_NotConfigured(t *testing.T) {
	f := New(Config{Threshold: 2, Members: []string{"a", "b", "c"}})

	if _, _, err := f.GeneratePolicyKey(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("GeneratePolicyKey: want ErrNotConfigured, got %v", err)
	}
	if err := f.Adopt("ref", "asset"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Adopt: want ErrNotConfigured, got %v", err)
	}
	if _, ok := f.PolicyPubKey("asset"); ok {
		t.Fatal("PolicyPubKey must report no key while unconfigured")
	}
	sig, err := f.SignPolicy("asset", [32]byte{1}, server.PolicyContext{Action: "clawback"})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("SignPolicy: want ErrNotConfigured, got %v", err)
	}
	if sig != nil {
		t.Fatal("SignPolicy must return no signature bytes while unconfigured")
	}
}

// TestFrostSigner_ImplementsPolicySigner is the runtime twin of the
// compile-time assertion: the skeleton satisfies the seam.
func TestFrostSigner_ImplementsPolicySigner(t *testing.T) {
	var s server.PolicySigner = New(Config{})
	if s == nil {
		t.Fatal("nil PolicySigner")
	}
}
