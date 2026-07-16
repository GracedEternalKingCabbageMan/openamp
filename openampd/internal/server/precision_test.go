package server

import (
	"encoding/json"
	"testing"
)

// TestNormalizePrecision covers the unset-vs-explicit-0 distinction: an omitted
// precision (the pre-decode sentinel) defaults to 8, while an explicit 0 is
// honoured so integer-only restricted assets are issuable. Out-of-range values
// are rejected.
func TestNormalizePrecision(t *testing.T) {
	cases := []struct {
		name    string
		in      int
		want    int
		wantErr bool
	}{
		{"unset defaults to 8", precisionUnset, 8, false},
		{"explicit 0 honoured", 0, 0, false},
		{"explicit 8 honoured", 8, 8, false},
		{"max 18 honoured", 18, 18, false},
		{"above range rejected", 19, 0, true},
		{"negative (non-sentinel) rejected", -2, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizePrecision(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizePrecision(%d): want error, got nil (val %d)", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePrecision(%d): unexpected error %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("normalizePrecision(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestIssueRequestPrecisionDecode proves the sentinel survives JSON decoding, so
// the handler can tell an omitted precision from an explicit 0.
func TestIssueRequestPrecisionDecode(t *testing.T) {
	// Omitted precision: the sentinel must survive decode, then default to 8.
	omitted := issueRequest{Precision: precisionUnset}
	if err := json.Unmarshal([]byte(`{"name":"X","ticker":"X"}`), &omitted); err != nil {
		t.Fatal(err)
	}
	if omitted.Precision != precisionUnset {
		t.Fatalf("omitted precision overwrote sentinel: got %d", omitted.Precision)
	}
	if got, err := normalizePrecision(omitted.Precision); err != nil || got != 8 {
		t.Fatalf("omitted precision: got %d err %v, want 8 nil", got, err)
	}

	// Explicit 0: must decode to 0 (not the sentinel) and normalize to 0.
	zero := issueRequest{Precision: precisionUnset}
	if err := json.Unmarshal([]byte(`{"name":"X","ticker":"X","precision":0}`), &zero); err != nil {
		t.Fatal(err)
	}
	if zero.Precision != 0 {
		t.Fatalf("explicit precision 0 decoded as %d, want 0", zero.Precision)
	}
	if got, err := normalizePrecision(zero.Precision); err != nil || got != 0 {
		t.Fatalf("explicit precision 0: got %d err %v, want 0 nil", got, err)
	}
}
