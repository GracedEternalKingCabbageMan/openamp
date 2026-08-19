package server

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Pledges (Pignus Tier C). Two things are proven here, and they are the two
// things a borrower and a lender each have to be able to rely on:
//
//	the LOCK   pledged atoms cannot leave the holder, and unpledged ones can
//	the KEYS   nobody can release or seize a pledge on their own say-so
//
// The seizure sweep itself is an L_claw spend and is exercised against a real
// chain by the clawback tests it shares its signing path with; what is proven
// here is every refusal that stands in front of it.

// keyedUser registers a user whose private key the test keeps, so the test can
// produce real signatures rather than asserting about a stub.
func keyedUser(t *testing.T, st *store.Store) (*store.User, []byte) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	x := elements.XOnlyFromPriv(priv)
	xh := hex.EncodeToString(x[:])
	aid := store.AID([]string{xh})
	u := &store.User{AID: aid, Pubkeys: []string{xh}}
	if err := st.Update(func(s *store.State) error {
		s.Users[aid] = u
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return u, priv
}

func signPledge(t *testing.T, priv []byte, action, id, extra string) string {
	t.Helper()
	msg := pledgeMessage(action, id, extra)
	sig, err := elements.SignSchnorr(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sig)
}

// newPledgeServer is newOA3Server plus a getblockcount the pledge handlers
// need: a pledge has a maturity height, so every path through them asks the
// chain what time it is.
func newPledgeServer(t *testing.T) (*Server, *store.Store, *[]map[string]any, *int64) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var scanUnspents []map[string]any
	var tip int64 = 500
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "scantxoutset":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{"success": true, "unspents": scanUnspents},
				"error":  nil,
			})
		case "getblockcount":
			_ = json.NewEncoder(w).Encode(map[string]any{"result": tip, "error": nil})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"result": nil, "error": nil})
		}
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	node, err := rpc.New(ts.URL, "u:p")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{}, st: st, node: node, pending: map[string]*pendingTransfer{}}
	return s, st, &scanUnspents, &tip
}

// unit is one whole coin in atoms. The fixture UTXOs the scan mock returns are
// one coin each (balanceUTXO's amount is 1.0), and every balance the pledge
// code compares against comes from that scan, so the test's own numbers have to
// be in the same units the chain speaks in.
const unit = uint64(100_000_000)

func clawbackAsset(t *testing.T, issuerAID string) *store.Asset {
	t.Helper()
	a := oa3Asset(t, issuerAID, store.Rules{})
	a.Clawback = true
	a.IssuerPub = oa3Xonly(t) // the L_claw leaf needs a real issuer key
	return a
}

func postPledge(t *testing.T, h http.HandlerFunc, path string, pathID string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	if pathID != "" {
		req.SetPathValue("id", pathID)
	}
	w := httptest.NewRecorder()
	h(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// openPledge writes an open pledge straight into the store. Used by the tests
// that are about what happens NEXT, so they do not re-prove creation.
func openPledge(t *testing.T, st *store.Store, asset *store.Asset, holder, lender *store.User, atoms uint64, maturity int64) *store.Pledge {
	t.Helper()
	p := &store.Pledge{
		ID: fmt.Sprintf("pl-%d-%d-%s", atoms, maturity, lender.AID[:8]),
		AssetID: asset.ID, Holder: holder.AID, Lender: lender.AID,
		Atoms: atoms, State: store.PledgeOpen, Maturity: maturity,
	}
	if err := st.Update(func(s *store.State) error {
		if s.Pledges == nil {
			s.Pledges = map[string]*store.Pledge{}
		}
		s.Pledges[p.ID] = p
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- the lock ----------------------------------------------------------------

// A pledged holder may move what is free and not what is pledged, and the line
// between the two is exact rather than approximate.
func TestPledge_LocksExactlyThePledgedAtoms(t *testing.T) {
	s, st, scan, _ := newPledgeServer(t)
	holder, _ := keyedUser(t, st)
	lender, _ := keyedUser(t, st)
	other, _ := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	setHeight(t, st, 500)
	asset := clawbackAsset(t, issuer.AID)

	// Ten coins of one atom each: holderBalances reads the chain, so the
	// holder's balance has to be on the (mock) chain.
	spk := enclaveSpk(t, s, holder, asset)
	for i := 0; i < 10; i++ {
		*scan = append(*scan, balanceUTXO(spk, asset.ID))
	}

	// Unpledged: a transfer of everything is fine.
	if err := s.checkTransfer(txTo(t, s, asset, 10*unit, other), asset, holder, map[string]uint64{}); err != nil {
		t.Fatalf("an unpledged holder should move their whole balance: %v", err)
	}

	openPledge(t, st, asset, holder, lender, 6*unit, 1000)

	// 4 free: exactly 4 out is fine, 5 is not.
	if err := s.checkTransfer(txTo(t, s, asset, 4*unit, other), asset, holder, map[string]uint64{}); err != nil {
		t.Fatalf("the 4 free atoms should still move: %v", err)
	}
	err := s.checkTransfer(txTo(t, s, asset, 5*unit, other), asset, holder, map[string]uint64{})
	if err == nil {
		t.Fatal("moving into the pledged 6 must be refused")
	}
	if _, ok := err.(*PolicyRefusal); !ok {
		t.Fatalf("expected PolicyRefusal, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "pledged") {
		t.Fatalf("the refusal should say why: %v", err)
	}

	// A released pledge stops locking anything at all.
	if err := st.Update(func(x *store.State) error {
		for _, p := range x.Pledges {
			p.State = store.PledgeReleased
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.checkTransfer(txTo(t, s, asset, 10*unit, other), asset, holder, map[string]uint64{}); err != nil {
		t.Fatalf("a released pledge must not still lock: %v", err)
	}
}

// Two pledges against one holder add up. A second lender must not be sold a
// claim on atoms the first lender already holds.
func TestPledge_PledgesAccumulate(t *testing.T) {
	s, st, scan, _ := newPledgeServer(t)
	holder, _ := keyedUser(t, st)
	l1, _ := keyedUser(t, st)
	l2, _ := keyedUser(t, st)
	other, _ := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	setHeight(t, st, 500)
	asset := clawbackAsset(t, issuer.AID)
	spk := enclaveSpk(t, s, holder, asset)
	for i := 0; i < 10; i++ {
		*scan = append(*scan, balanceUTXO(spk, asset.ID))
	}
	openPledge(t, st, asset, holder, l1, 4*unit, 1000)
	openPledge(t, st, asset, holder, l2, 5*unit, 1001)

	if err := s.checkTransfer(txTo(t, s, asset, 1*unit, other), asset, holder, map[string]uint64{}); err != nil {
		t.Fatalf("the single free atom should move: %v", err)
	}
	if err := s.checkTransfer(txTo(t, s, asset, 2*unit, other), asset, holder, map[string]uint64{}); err == nil {
		t.Fatal("9 of 10 atoms are pledged; 2 must not move")
	}
}

// --- creation refusals -------------------------------------------------------

func TestPledge_RefusesAssetWithoutClawback(t *testing.T) {
	s, st, scan, _ := newPledgeServer(t)
	holder, _ := keyedUser(t, st)
	lender, _ := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	setHeight(t, st, 500)
	asset := oa3Asset(t, issuer.AID, store.Rules{}) // no clawback leaf
	if err := st.Update(func(x *store.State) error {
		x.Assets[asset.ID] = asset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	spk := enclaveSpk(t, s, holder, asset)
	*scan = append(*scan, balanceUTXO(spk, asset.ID))

	code, body := postPledge(t, s.handlePledgeCreate, "/v1/issuer/pledges", "", map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "lender_aid": lender.AID,
		"atoms": 1, "maturity_height": 900,
	})
	if code != 409 {
		t.Fatalf("want 409 for a non-clawback asset, got %d: %v", code, body)
	}
	if !strings.Contains(body["error"].(string), "lock permanently") {
		t.Fatalf("the refusal should explain the trap: %v", body["error"])
	}
}

func TestPledge_RefusesOverPledging(t *testing.T) {
	s, st, scan, _ := newPledgeServer(t)
	holder, _ := keyedUser(t, st)
	lender, _ := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	setHeight(t, st, 500)
	asset := clawbackAsset(t, issuer.AID)
	if err := st.Update(func(x *store.State) error {
		x.Assets[asset.ID] = asset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	spk := enclaveSpk(t, s, holder, asset)
	for i := 0; i < 3; i++ {
		*scan = append(*scan, balanceUTXO(spk, asset.ID))
	}
	openPledge(t, st, asset, holder, lender, 2*unit, 1000)

	code, body := postPledge(t, s.handlePledgeCreate, "/v1/issuer/pledges", "", map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "lender_aid": lender.AID,
		"atoms": 2 * unit, "maturity_height": 900,
	})
	if code != 409 {
		t.Fatalf("want 409 pledging beyond the free balance, got %d: %v", code, body)
	}
	if !strings.Contains(body["error"].(string), "already pledged") {
		t.Fatalf("the refusal should name the earlier pledge: %v", body["error"])
	}
}

func TestPledge_RefusesMaturityInThePast(t *testing.T) {
	s, st, scan, tip := newPledgeServer(t)
	*tip = 900
	holder, _ := keyedUser(t, st)
	lender, _ := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	setHeight(t, st, 900)
	asset := clawbackAsset(t, issuer.AID)
	if err := st.Update(func(x *store.State) error {
		x.Assets[asset.ID] = asset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	spk := enclaveSpk(t, s, holder, asset)
	*scan = append(*scan, balanceUTXO(spk, asset.ID))
	code, body := postPledge(t, s.handlePledgeCreate, "/v1/issuer/pledges", "", map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "lender_aid": lender.AID,
		"atoms": 1, "maturity_height": 800,
	})
	if code != 400 {
		t.Fatalf("want 400 for a maturity already past, got %d: %v", code, body)
	}
}

// --- the keys ----------------------------------------------------------------

// The issuer token alone does not release a pledge. Only the lender's
// signature does, or an explicitly forced release with a written reason.
func TestPledge_ReleaseNeedsTheLender(t *testing.T) {
	s, st, _, _ := newPledgeServer(t)
	holder, holderPriv := keyedUser(t, st)
	lender, lenderPriv := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	asset := clawbackAsset(t, issuer.AID)
	p := openPledge(t, st, asset, holder, lender, 5, 1000)

	// No signature at all.
	code, _ := postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{"repaid_txid": "ab"})
	if code != 403 {
		t.Fatalf("an unsigned release must be refused, got %d", code)
	}
	// The HOLDER's signature is not the lender's.
	code, _ = postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{
		"repaid_txid": "ab", "lender_sig": signPledge(t, holderPriv, "release", p.ID, "ab")})
	if code != 403 {
		t.Fatalf("the borrower must not release their own pledge, got %d", code)
	}
	// The lender's signature over a DIFFERENT txid does not authorise this one.
	code, _ = postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{
		"repaid_txid": "ab", "lender_sig": signPledge(t, lenderPriv, "release", p.ID, "cd")})
	if code != 403 {
		t.Fatalf("a signature over another txid must not carry over, got %d", code)
	}
	// A release signature is not a seizure signature.
	code, _ = postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{
		"repaid_txid": "ab", "lender_sig": signPledge(t, lenderPriv, "seize", p.ID, "ab")})
	if code != 403 {
		t.Fatalf("a seize signature must not release, got %d", code)
	}
	// The real thing.
	code, body := postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{
		"repaid_txid": "ab", "lender_sig": signPledge(t, lenderPriv, "release", p.ID, "ab")})
	if code != 200 {
		t.Fatalf("the lender's own signature should release, got %d: %v", code, body)
	}
	var state store.PledgeState
	st.View(func(x *store.State) { state = x.Pledges[p.ID].State })
	if state != store.PledgeReleased {
		t.Fatalf("pledge is %s, want released", state)
	}
	// And releasing twice is a no-op rather than a second event.
	code, body = postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{
		"repaid_txid": "ab", "lender_sig": signPledge(t, lenderPriv, "release", p.ID, "ab")})
	if code != 200 || body["idempotent"] != true {
		t.Fatalf("a repeated release should be idempotent, got %d: %v", code, body)
	}
}

func TestPledge_ForcedReleaseNeedsAReason(t *testing.T) {
	s, st, _, _ := newPledgeServer(t)
	holder, _ := keyedUser(t, st)
	lender, _ := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	asset := clawbackAsset(t, issuer.AID)
	p := openPledge(t, st, asset, holder, lender, 5, 1000)

	code, _ := postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{"force": true})
	if code != 400 {
		t.Fatalf("a forced release without a reason must be refused, got %d", code)
	}
	code, _ = postPledge(t, s.handlePledgeRelease, "/x", p.ID, map[string]any{
		"force": true, "reason": "lender lost their key; collateral returned to its owner"})
	if code != 200 {
		t.Fatalf("a reasoned forced release should succeed, got %d", code)
	}
	var note string
	st.View(func(x *store.State) { note = x.Pledges[p.ID].Note })
	if !strings.Contains(note, "without a lender signature") {
		t.Fatalf("a forced release should be recorded as one: %q", note)
	}
}

// Nobody takes collateral early on their own word.
func TestPledge_SeizeIsRefusedWithoutTheRightSignatures(t *testing.T) {
	s, st, _, tip := newPledgeServer(t)
	*tip = 500
	holder, holderPriv := keyedUser(t, st)
	lender, lenderPriv := keyedUser(t, st)
	issuer, _ := keyedUser(t, st)
	asset := clawbackAsset(t, issuer.AID)
	if err := st.Update(func(x *store.State) error {
		x.Assets[asset.ID] = asset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := openPledge(t, st, asset, holder, lender, 5, 1000) // matures at 1000, tip 500

	// A reason is mandatory before anything else is even looked at.
	code, _ := postPledge(t, s.handlePledgeSeize, "/x", p.ID, map[string]any{})
	if code != 400 {
		t.Fatalf("a seizure without a reason must be refused, got %d", code)
	}
	// The issuer token alone is not a seizure.
	code, _ = postPledge(t, s.handlePledgeSeize, "/x", p.ID, map[string]any{"reason": "because"})
	if code != 403 {
		t.Fatalf("an unsigned seizure must be refused, got %d", code)
	}
	// The lender alone, before maturity, is not a seizure either.
	code, body := postPledge(t, s.handlePledgeSeize, "/x", p.ID, map[string]any{
		"reason": "because", "lender_sig": signPledge(t, lenderPriv, "seize", p.ID, "because")})
	if code != 409 {
		t.Fatalf("a pre-maturity seizure needs the holder too, got %d: %v", code, body)
	}
	if !strings.Contains(body["error"].(string), "countersignature") {
		t.Fatalf("the refusal should say what is missing: %v", body["error"])
	}
	// The holder's countersignature over a DIFFERENT reason does not count.
	code, _ = postPledge(t, s.handlePledgeSeize, "/x", p.ID, map[string]any{
		"reason":     "because",
		"lender_sig": signPledge(t, lenderPriv, "seize", p.ID, "because"),
		"holder_sig": signPledge(t, holderPriv, "seize", p.ID, "some other reason")})
	if code != 409 {
		t.Fatalf("a countersignature over another reason must not count, got %d", code)
	}
	// A released pledge cannot be seized afterwards.
	if err := st.Update(func(x *store.State) error {
		x.Pledges[p.ID].State = store.PledgeReleased
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	code, _ = postPledge(t, s.handlePledgeSeize, "/x", p.ID, map[string]any{
		"reason": "because", "lender_sig": signPledge(t, lenderPriv, "seize", p.ID, "because")})
	if code != 409 {
		t.Fatalf("a released pledge must not be seizable, got %d", code)
	}
}

// The store's own accounting, checked directly: only OPEN pledges of the right
// asset and the right holder count toward the lock.
func TestPledge_PledgedAtomsCountsOnlyWhatItShould(t *testing.T) {
	st := &store.State{Pledges: map[string]*store.Pledge{
		"a": {ID: "a", AssetID: "A", Holder: "h", Atoms: 3, State: store.PledgeOpen},
		"b": {ID: "b", AssetID: "A", Holder: "h", Atoms: 4, State: store.PledgeOpen},
		"c": {ID: "c", AssetID: "A", Holder: "h", Atoms: 5, State: store.PledgeReleased},
		"d": {ID: "d", AssetID: "A", Holder: "h", Atoms: 6, State: store.PledgeSeized},
		"e": {ID: "e", AssetID: "B", Holder: "h", Atoms: 7, State: store.PledgeOpen},
		"f": {ID: "f", AssetID: "A", Holder: "x", Atoms: 8, State: store.PledgeOpen},
	}}
	if got := store.PledgedAtoms(st, "A", "h"); got != 7 {
		t.Fatalf("PledgedAtoms = %d, want 7 (the two open A/h pledges)", got)
	}
	if got := store.PledgedAtoms(st, "Z", "h"); got != 0 {
		t.Fatalf("an asset with no pledges should total 0, got %d", got)
	}
	if got := len(store.PledgesFor(st, "A", "h")); got != 4 {
		t.Fatalf("PledgesFor should list closed ones too, got %d", got)
	}
}

func TestPledge_SaturatingSubDoesNotUnderflow(t *testing.T) {
	if got := saturatingSub(3, 10); got != 0 {
		t.Fatalf("saturatingSub(3,10) = %d, want 0", got)
	}
	if got := saturatingSub(10, 3); got != 7 {
		t.Fatalf("saturatingSub(10,3) = %d, want 7", got)
	}
}
