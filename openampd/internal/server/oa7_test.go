package server

import (
	"bytes"
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

// OA-7: handleCosign must refuse a cosign whose transaction hides an enclave
// output of the SAME asset among the inputs NOT listed in req.Inputs (someone
// else's coins riding in the same tx), while a legitimate cosign whose every
// enclave input is claimed still passes.

// newOA7Server builds a Server whose mock node answers getrawtransaction from a
// txid->rawhex map (so spentOutputs resolves prevouts) and carries a real
// LocalKeySigner so the passing path can co-sign.
func newOA7Server(t *testing.T) (*Server, *store.Store, map[string]string) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rawTxs := map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "getrawtransaction":
			var txid string
			if len(req.Params) > 0 {
				_ = json.Unmarshal(req.Params[0], &txid)
			}
			if raw, ok := rawTxs[txid]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"result": raw, "error": nil})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": nil, "error": map[string]any{"code": -5, "message": "No such mempool or blockchain transaction"},
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
	s := &Server{cfg: Config{}, st: st, node: node, pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(st)}
	return s, st, rawTxs
}

// oa7Asset registers a transparent, non-clawback restricted asset whose policy
// key material is stored so the LocalKeySigner can produce a co-signature.
func oa7Asset(t *testing.T, st *store.Store, issuerAID string) *store.Asset {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub := elements.XOnlyFromPriv(priv[:])
	asset := &store.Asset{
		ID:        strings.Repeat("ab", 32),
		Ticker:    "OA7T",
		Name:      "OA7 Test Asset",
		Precision: 0,
		PolicyPub: hex.EncodeToString(pub[:]),
		IssuerAID: issuerAID,
	}
	if err := st.Update(func(s *store.State) error {
		s.Assets[asset.ID] = asset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveKey("policy:"+asset.ID, hex.EncodeToString(priv[:])); err != nil {
		t.Fatal(err)
	}
	return asset
}

// enclaveOut builds an explicit output of asset for the user's enclave.
func enclaveOut(t *testing.T, s *Server, u *store.User, asset *store.Asset, amt uint64) *elements.TxOut {
	t.Helper()
	tree, err := s.treeFor(u, asset)
	if err != nil {
		t.Fatalf("treeFor: %v", err)
	}
	return &elements.TxOut{
		Asset:        elements.ExplicitAsset(elements.MustHex32(asset.ID)),
		Value:        elements.ExplicitValue(amt),
		Nonce:        elements.NullNonce(),
		ScriptPubKey: tree.ScriptPubKey(),
	}
}

// callCosign invokes handleCosign directly and returns the status code and body.
func callCosign(t *testing.T, s *Server, tx *elements.Tx, asset *store.Asset, senderAID string, inputs []int) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"tx":         hex.EncodeToString(tx.Serialize()),
		"asset":      asset.ID,
		"sender_aid": senderAID,
		"inputs":     inputs,
	})
	req := httptest.NewRequest("POST", "/v1/cosign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleCosign(rec, req)
	return rec.Code, rec.Body.String()
}

func TestOA7_RejectsUnclaimedEnclaveInput(t *testing.T) {
	s, st, rawTxs := newOA7Server(t)
	escrow := regUser(t, st, nil)    // primary sender (the claimer)
	other := regUser(t, st, nil)     // a DIFFERENT user with enclave coins of the asset
	recipient := regUser(t, st, nil) // delivery destination
	issuer := regUser(t, st, nil)
	asset := oa7Asset(t, st, issuer.AID)

	// A funding tx: vout0 escrow's enclave coin, vout1 escrow's enclave coin,
	// vout2 the OTHER user's enclave coin, all of the same asset.
	prev := &elements.Tx{Version: 2}
	prev.Out = append(prev.Out,
		enclaveOut(t, s, escrow, asset, 100),
		enclaveOut(t, s, escrow, asset, 100),
		enclaveOut(t, s, other, asset, 50),
	)
	prev.NormalizeWitness()
	prevID := prev.TxID()
	rawTxs[prevID] = hex.EncodeToString(prev.Serialize())

	// Malicious cosign: input 0 = escrow's coin (claimed), input 1 = the OTHER
	// user's enclave coin of the same asset (NOT claimed).
	tx := &elements.Tx{Version: 2}
	tx.In = append(tx.In,
		&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 0}},
		&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 2}},
	)
	tx.Out = append(tx.Out, enclaveOut(t, s, recipient, asset, 150))
	tx.NormalizeWitness()

	code, body := callCosign(t, s, tx, asset, escrow.AID, []int{0})
	if code != 403 {
		t.Fatalf("expected 403 for a hidden enclave input, got %d: %s", code, body)
	}
	if !strings.Contains(body, "unclaimed enclave output") {
		t.Fatalf("expected an unclaimed-enclave-input refusal, got: %s", body)
	}
}

func TestOA7_AllowsFullyClaimedCosign(t *testing.T) {
	s, st, rawTxs := newOA7Server(t)
	escrow := regUser(t, st, nil)
	regUser(t, st, nil) // an unrelated user with NO coins in this tx
	recipient := regUser(t, st, nil)
	issuer := regUser(t, st, nil)
	asset := oa7Asset(t, st, issuer.AID)

	// Funding tx with two escrow enclave coins.
	prev := &elements.Tx{Version: 2}
	prev.Out = append(prev.Out,
		enclaveOut(t, s, escrow, asset, 100),
		enclaveOut(t, s, escrow, asset, 100),
	)
	prev.NormalizeWitness()
	prevID := prev.TxID()
	rawTxs[prevID] = hex.EncodeToString(prev.Serialize())

	// A legitimate cosign: BOTH enclave inputs of the asset are escrow's and
	// BOTH are claimed. The containment loop must not reject it.
	tx := &elements.Tx{Version: 2}
	tx.In = append(tx.In,
		&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 0}},
		&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prevID), N: 1}},
	)
	tx.Out = append(tx.Out, enclaveOut(t, s, recipient, asset, 200))
	tx.NormalizeWitness()

	code, body := callCosign(t, s, tx, asset, escrow.AID, []int{0, 1})
	if code != 200 {
		t.Fatalf("a fully-claimed cosign should pass, got %d: %s", code, body)
	}
	var resp struct {
		Sigs []map[string]any `json:"sigs"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if len(resp.Sigs) != 2 {
		t.Fatalf("expected 2 policy signatures, got %d: %s", len(resp.Sigs), body)
	}
}
