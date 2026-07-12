package server

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// OA-1: issueRequest.buildContract must add an entity/operator block when
// entity_domain is present (registry-required), keep the JSON canonical and the
// contract_hash stable, and remain byte-identical to the pre-OA-1 shape when the
// new fields are absent (so BONDX and every existing asset are unaffected).

var (
	oa1IssuerPub = strings.Repeat("aa", 32) // 32-byte x-only, fixed for goldens
	oa1PolicyPub = strings.Repeat("bb", 32)
)

// baseReq is the minimal transparent, clawback-enabled request with NO OA-1
// fields; its contract is the pre-OA-1 shape.
func baseReq() *issueRequest {
	return &issueRequest{Name: "BONDX", Ticker: "BONDX", Precision: 8}
}

// TestOA1_WithoutEntity_UnchangedShape pins the pre-OA-1 canonical bytes: a
// request without entity_domain must serialize exactly as before OA-1.
func TestOA1_WithoutEntity_UnchangedShape(t *testing.T) {
	got, err := canonicalJSON(baseReq().buildContract(oa1IssuerPub, oa1PolicyPub, true))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"issuer_pubkey":"` + oa1IssuerPub + `","name":"BONDX","openamp":{"burn_allowed":false,"clawback":true,"confidential":false,"policy_pubkey":"` + oa1PolicyPub + `","type":"restricted","version":1},"precision":8,"ticker":"BONDX","version":0}`
	if string(got) != want {
		t.Fatalf("pre-OA-1 shape changed.\n got: %s\nwant: %s", got, want)
	}
	// No entity/operator keys leaked in.
	if strings.Contains(string(got), "entity") || strings.Contains(string(got), "operator") {
		t.Fatalf("entity/operator must not appear without entity_domain: %s", got)
	}
}

// TestOA1_WithEntity_Canonical pins the canonical bytes and hash of a fully
// populated OA-1 contract and proves determinism + round-trip.
func TestOA1_WithEntity_Canonical(t *testing.T) {
	req := baseReq()
	req.EntityDomain = "sequentiatestnet.com"
	req.EntityName = "Concatena Labs"
	req.OperatorName = "Concatena Labs"
	req.OperatorRegistration = "HN-PROSPERA-001"

	want := `{"entity":{"domain":"sequentiatestnet.com","issuer":"Concatena Labs"},` +
		`"issuer_pubkey":"` + oa1IssuerPub + `","name":"BONDX",` +
		`"openamp":{"burn_allowed":false,"clawback":true,"confidential":false,"policy_pubkey":"` + oa1PolicyPub + `","type":"restricted","version":1},` +
		`"operator":{"name":"Concatena Labs","registration":"HN-PROSPERA-001"},` +
		`"precision":8,"ticker":"BONDX","version":0}`

	// Determinism: build twice from scratch, canonical bytes and hash must match.
	var firstHash [32]byte
	for i := 0; i < 2; i++ {
		got, err := canonicalJSON(req.buildContract(oa1IssuerPub, oa1PolicyPub, true))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("canonical bytes not stable/expected on pass %d.\n got: %s\nwant: %s", i, got, want)
		}
		h := sha256.Sum256(got)
		if i == 0 {
			firstHash = h
		} else if h != firstHash {
			t.Fatalf("contract_hash not deterministic: %x != %x", h, firstHash)
		}
	}

	// Round-trip: decode the canonical bytes and re-marshal; the entity/operator
	// blocks must survive and the bytes must be a fixed point.
	var back map[string]any
	if err := json.Unmarshal([]byte(want), &back); err != nil {
		t.Fatal(err)
	}
	re, err := canonicalJSON(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(re) != want {
		t.Fatalf("canonical JSON is not a fixed point after round-trip.\n got: %s\nwant: %s", re, want)
	}
	ent, _ := back["entity"].(map[string]any)
	if ent["domain"] != "sequentiatestnet.com" || ent["issuer"] != "Concatena Labs" {
		t.Fatalf("entity block lost in round-trip: %#v", back["entity"])
	}
	op, _ := back["operator"].(map[string]any)
	if op["name"] != "Concatena Labs" || op["registration"] != "HN-PROSPERA-001" {
		t.Fatalf("operator block lost in round-trip: %#v", back["operator"])
	}
}

// TestOA1_EntityDomainOnly proves the optional sub-fields are omitted (not
// emitted empty): entity carries domain only and the operator block is absent
// when no operator fields are supplied.
func TestOA1_EntityDomainOnly(t *testing.T) {
	req := baseReq()
	req.EntityDomain = "sequentiatestnet.com"

	got, err := canonicalJSON(req.buildContract(oa1IssuerPub, oa1PolicyPub, true))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"entity":{"domain":"sequentiatestnet.com"},` +
		`"issuer_pubkey":"` + oa1IssuerPub + `","name":"BONDX",` +
		`"openamp":{"burn_allowed":false,"clawback":true,"confidential":false,"policy_pubkey":"` + oa1PolicyPub + `","type":"restricted","version":1},` +
		`"precision":8,"ticker":"BONDX","version":0}`
	if string(got) != want {
		t.Fatalf("entity-domain-only shape wrong.\n got: %s\nwant: %s", got, want)
	}

	// The commitment must actually cover the domain: changing it changes the hash.
	req2 := baseReq()
	req2.EntityDomain = "example.com"
	other, _ := canonicalJSON(req2.buildContract(oa1IssuerPub, oa1PolicyPub, true))
	if reflect.DeepEqual(sha256.Sum256(got), sha256.Sum256(other)) {
		t.Fatal("contract_hash must change when entity.domain changes")
	}
}

// TestOA1_TermsHashUnaffected guards that OA-1 did not disturb the existing
// terms_hash / endpoint placement inside the openamp block.
func TestOA1_TermsHashUnaffected(t *testing.T) {
	req := baseReq()
	req.TermsHash = "deadbeef"
	req.Endpoint = "https://sequentiatestnet.com/openamp"
	got, err := canonicalJSON(req.buildContract(oa1IssuerPub, oa1PolicyPub, true))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"issuer_pubkey":"` + oa1IssuerPub + `","name":"BONDX",` +
		`"openamp":{"burn_allowed":false,"clawback":true,"confidential":false,"policy_endpoints":["https://sequentiatestnet.com/openamp"],"policy_pubkey":"` + oa1PolicyPub + `","terms_hash":"deadbeef","type":"restricted","version":1},` +
		`"precision":8,"ticker":"BONDX","version":0}`
	if string(got) != want {
		t.Fatalf("terms_hash/endpoint placement changed.\n got: %s\nwant: %s", got, want)
	}
}
