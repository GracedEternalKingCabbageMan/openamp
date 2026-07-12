package server

import (
	"crypto/rand"
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

// oa3TestAsset is a transparent, non-clawback restricted asset. Its ID is a
// fixed 32-byte hex; PolicyPub is a real x-only key so treeFor succeeds.
func oa3Asset(t *testing.T, issuerAID string, rules store.Rules) *store.Asset {
	t.Helper()
	return &store.Asset{
		ID:        strings.Repeat("11", 32),
		Ticker:    "OA3T",
		Name:      "OA3 Test Asset",
		Precision: 0,
		PolicyPub: oa3Xonly(t),
		IssuerAID: issuerAID,
		Rules:     rules,
	}
}

// oa3Xonly returns a fresh valid x-only pubkey hex.
func oa3Xonly(t *testing.T) string {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	x := elements.XOnlyFromPriv(priv[:])
	return hex.EncodeToString(x[:])
}

// regUser registers a user with the given categories and returns it.
func regUser(t *testing.T, st *store.Store, cats []string) *store.User {
	t.Helper()
	xh := oa3Xonly(t)
	aid := store.AID([]string{xh})
	u := &store.User{AID: aid, Pubkeys: []string{xh}, Categories: cats}
	if err := st.Update(func(s *store.State) error {
		s.Users[aid] = u
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return u
}

func setHeight(t *testing.T, st *store.Store, h int64) {
	t.Helper()
	if err := st.Update(func(s *store.State) error {
		s.Height = h
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// enclaveSpk returns the hex enclave scriptPubKey for a user under an asset.
func enclaveSpk(t *testing.T, s *Server, u *store.User, asset *store.Asset) string {
	t.Helper()
	tree, err := s.treeFor(u, asset)
	if err != nil {
		t.Fatalf("treeFor: %v", err)
	}
	return hex.EncodeToString(tree.ScriptPubKey())
}

// txTo builds a transfer tx delivering amt atoms of asset to each recipient.
func txTo(t *testing.T, s *Server, asset *store.Asset, amt uint64, recips ...*store.User) *elements.Tx {
	t.Helper()
	assetID := elements.MustHex32(asset.ID)
	tx := &elements.Tx{Version: 2}
	for _, u := range recips {
		tree, err := s.treeFor(u, asset)
		if err != nil {
			t.Fatalf("treeFor: %v", err)
		}
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset:        elements.ExplicitAsset(assetID),
			Value:        elements.ExplicitValue(amt),
			Nonce:        elements.NullNonce(),
			ScriptPubKey: tree.ScriptPubKey(),
		})
	}
	return tx
}

// newOA3Server builds a Server backed by an in-memory store and a node RPC
// pointed at a mock that answers scantxoutset from *scanUnspents. checkTransfer
// uses neither the genesis nor the signer, so both are left zero/default.
func newOA3Server(t *testing.T) (*Server, *store.Store, *[]map[string]any) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var scanUnspents []map[string]any
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
	return s, st, &scanUnspents
}

func balanceUTXO(spk, assetID string) map[string]any {
	return map[string]any{
		"txid":         strings.Repeat("22", 32),
		"vout":         0,
		"scriptPubKey": spk,
		"amount":       1.0,
		"asset":        assetID,
		"height":       1,
	}
}

// (a) Primary sender delivers to a non-issuer recipient during a lockup, while
// a non-primary sender's transfer to the same recipient in the same window is
// refused.
func TestOA3_PrimarySenderBypassesLockin(t *testing.T) {
	s, st, _ := newOA3Server(t)
	escrow := regUser(t, st, nil)      // per-offering escrow (primary)
	investor := regUser(t, st, nil)    // non-issuer recipient
	investor2 := regUser(t, st, nil)   // another non-primary sender
	issuer := regUser(t, st, nil)      // issuer counterparty
	setHeight(t, st, 500)

	asset := oa3Asset(t, issuer.AID, store.Rules{
		LockinUntilHeight: 1000,
		PrimaryAIDs:       []string{escrow.AID},
	})

	// Primary escrow -> investor during the lockup: permitted.
	if err := s.checkTransfer(txTo(t, s, asset, 10, investor), asset, escrow, map[string]uint64{}); err != nil {
		t.Fatalf("primary sender should deliver during lockup, got: %v", err)
	}
	// Non-primary investor2 -> investor in the same window: refused.
	err := s.checkTransfer(txTo(t, s, asset, 10, investor), asset, investor2, map[string]uint64{})
	if err == nil {
		t.Fatal("non-primary transfer during lockup should be refused")
	}
	if _, ok := err.(*PolicyRefusal); !ok {
		t.Fatalf("expected PolicyRefusal, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "locked in") {
		t.Fatalf("expected lock-in refusal, got: %v", err)
	}
}

// (b) A CategoryDeny{Prefix:"j:US", UntilHeight:H} refuses a recipient holding
// "j:US:acc" while height<H and permits at height>=H.
func TestOA3_CategoryDenyWindow(t *testing.T) {
	s, st, _ := newOA3Server(t)
	sender := regUser(t, st, nil)
	usRecipient := regUser(t, st, []string{"j:US:acc"})
	issuer := regUser(t, st, nil)

	const H = 1000
	asset := oa3Asset(t, issuer.AID, store.Rules{
		CategoryDenies: []store.CategoryDeny{{Prefix: "j:US", UntilHeight: H}},
	})

	// Before the window closes: refused.
	setHeight(t, st, 500)
	err := s.checkTransfer(txTo(t, s, asset, 10, usRecipient), asset, sender, map[string]uint64{})
	if err == nil {
		t.Fatal("US recipient should be refused before the deny height")
	}
	if !strings.Contains(err.Error(), "denied until height") {
		t.Fatalf("expected category-deny refusal, got: %v", err)
	}

	// At/after the window: permitted.
	setHeight(t, st, H)
	if err := s.checkTransfer(txTo(t, s, asset, 10, usRecipient), asset, sender, map[string]uint64{}); err != nil {
		t.Fatalf("US recipient should be permitted at/after the deny height, got: %v", err)
	}
}

// (c) HolderCapsByCategory{"j:DE:ret":2} refuses a 3rd distinct DE:ret holder,
// and permits a transfer that does not create a new distinct holder.
func TestOA3_HolderCapsByCategory(t *testing.T) {
	s, st, scan := newOA3Server(t)
	sender := regUser(t, st, nil) // no DE:ret category, no balance
	h1 := regUser(t, st, []string{"j:DE:ret"})
	h2 := regUser(t, st, []string{"j:DE:ret"})
	h3 := regUser(t, st, []string{"j:DE:ret"})
	issuer := regUser(t, st, nil)
	setHeight(t, st, 10)

	asset := oa3Asset(t, issuer.AID, store.Rules{
		HolderCapsByCategory: map[string]int{"j:DE:ret": 2},
	})

	// Two existing DE:ret holders with nonzero balances.
	*scan = []map[string]any{
		balanceUTXO(enclaveSpk(t, s, h1, asset), asset.ID),
		balanceUTXO(enclaveSpk(t, s, h2, asset), asset.ID),
	}

	// Delivery to a 3rd distinct DE:ret holder exceeds the cap: refused.
	err := s.checkTransfer(txTo(t, s, asset, 10, h3), asset, sender, map[string]uint64{})
	if err == nil {
		t.Fatal("3rd distinct DE:ret holder should be refused")
	}
	if !strings.Contains(err.Error(), "holder cap for category j:DE:ret") {
		t.Fatalf("expected per-category cap refusal, got: %v", err)
	}

	// Delivery to an existing holder (h1) creates no new distinct holder: ok.
	if err := s.checkTransfer(txTo(t, s, asset, 10, h1), asset, sender, map[string]uint64{}); err != nil {
		t.Fatalf("delivery to an existing DE:ret holder should be permitted, got: %v", err)
	}
}
