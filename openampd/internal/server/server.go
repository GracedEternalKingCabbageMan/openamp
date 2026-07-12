// Package server implements openampd's HTTP API and policy engine.
//
// Wallet surface (no auth, testnet):
//
//	POST /v1/users                      register pubkeys -> AID
//	GET  /v1/users/{aid}                registration status
//	GET  /v1/users/{aid}/address        enclave address for an asset
//	GET  /v1/users/{aid}/balance        confirmed enclave balance
//	POST /v1/transfers                  hosted transfer build (fee convert/sponsor)
//	POST /v1/transfers/{id}/complete    submit user signatures -> broadcast
//	POST /v1/cosign                     raw co-sign for self-built transactions
//	GET  /v1/assets, /v1/assets/{id}    contracts and terms
//	GET  /v1/supply                     chain-derived circulating supply
//	GET  /v1/log                        transparency log
//
// Issuer surface (Bearer token):
//
//	POST /v1/issuer/assets              issue a restricted asset
//	POST /v1/issuer/freeze              freeze/unfreeze a user
//	POST /v1/issuer/categories          set a user's categories
//	POST /v1/issuer/rules               update an asset's policy rules
//	POST /v1/issuer/clawback            claw back a holder's UTXOs (legacy: signs+broadcasts; external issuer: builds the L_claw sweep)
//	POST /v1/issuer/clawback/{id}/complete  submit the external issuer's signatures -> broadcast
//	POST /v1/issuer/burn                build a redeem burn (OA-5), holder-signed
//	POST /v1/issuer/reissue             reissue more into a target enclave (OA-6)
//	GET  /v1/issuer/holders             ownership report
//	POST /v1/issuer/anchor              anchor the transparency log on-chain
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

type Config struct {
	Listen      string
	IssuerToken string
	FeeAsset    string // display hex of the ordinary fee asset the server pays fees in
	FeeSats     uint64
	DemoIssuer  bool   // hold issuer keys server-side (testnet demo); production keeps them offline
	ElectrsURL  string // explorer (electrs) base; prevout fallback when the node lacks -txindex
}

type Server struct {
	cfg    Config
	st     *store.Store
	node   *rpc.Client  // chain queries
	wallet *rpc.Client  // wallet operations (fee funding, issuance, broadcast)
	signer PolicySigner // policy-key backend (local key for testnet; FROST/MPC for mainnet)

	mu      sync.Mutex
	pending map[string]*pendingTransfer

	genesis [32]byte // internal order
}

// pendingTTL bounds how long a hosted-transfer build waits for the caller's
// signatures. M5's single-party pending used 15 minutes in memory; an atomic
// (OA-4) settlement can involve several parties, so the persisted build lives
// for 72h and survives a restart.
const pendingTTL = 72 * time.Hour

type pendingTransfer struct {
	tx            *elements.Tx // the (possibly blinded) tx that gets signed and broadcast
	explicitTx    *elements.Tx // pre-blind tx with readable amounts/assets for the policy check
	asset         *store.Asset
	senderAID     string
	atoms         uint64
	enclave       []int // restricted input indices the enclave key co-signs
	sighashes     [][32]byte
	userPub       [32]byte
	created       time.Time
	feeMode       string
	paymentInputs []int  // ordinary payment input indices the caller's own wallet signs (OA-4)
	burnAtoms     uint64 // >0 marks a burn build (OA-5): the atoms sent to the unspendable output
}

func New(cfg Config, st *store.Store, node, wallet *rpc.Client) (*Server, error) {
	s := &Server{cfg: cfg, st: st, node: node, wallet: wallet, pending: map[string]*pendingTransfer{},
		signer: NewLocalKeySigner(st)}
	gh, err := node.GetBlockHash(0)
	if err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	g, err := hex.DecodeString(gh)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 32; i++ {
		s.genesis[i] = g[31-i]
	}
	return s, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/users", s.handleRegister)
	mux.HandleFunc("GET /v1/users/{aid}", s.handleUser)
	mux.HandleFunc("GET /v1/users/{aid}/address", s.handleAddress)
	mux.HandleFunc("GET /v1/users/{aid}/balance", s.handleBalance)
	mux.HandleFunc("POST /v1/transfers", s.handleTransferBuild)
	mux.HandleFunc("POST /v1/transfers/{id}/complete", s.handleTransferComplete)
	mux.HandleFunc("POST /v1/cosign", s.handleCosign)
	mux.HandleFunc("GET /v1/assets", s.handleAssets)
	mux.HandleFunc("GET /v1/assets/{id}", s.handleAsset)
	mux.HandleFunc("GET /v1/supply", s.handleSupply)
	mux.HandleFunc("GET /v1/log", s.handleLog)

	mux.HandleFunc("POST /v1/issuer/assets", s.issuerAuth(s.handleIssue))
	mux.HandleFunc("POST /v1/issuer/freeze", s.issuerAuth(s.handleFreeze))
	mux.HandleFunc("POST /v1/issuer/categories", s.issuerAuth(s.handleCategories))
	mux.HandleFunc("POST /v1/issuer/rules", s.issuerAuth(s.handleRules))
	mux.HandleFunc("POST /v1/issuer/clawback", s.issuerAuth(s.handleClawback))
	mux.HandleFunc("POST /v1/issuer/clawback/{id}/complete", s.issuerAuth(s.handleClawbackComplete))
	mux.HandleFunc("POST /v1/issuer/burn", s.issuerAuth(s.handleBurnBuild))
	mux.HandleFunc("POST /v1/issuer/reissue", s.issuerAuth(s.handleReissue))
	mux.HandleFunc("GET /v1/issuer/holders", s.issuerAuth(s.handleHolders))
	mux.HandleFunc("POST /v1/issuer/anchor", s.issuerAuth(s.handleAnchor))
	return mux
}

func (s *Server) issuerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.cfg.IssuerToken == "" || tok != s.cfg.IssuerToken {
			httpErr(w, http.StatusUnauthorized, "issuer token required")
			return
		}
		next(w, r)
	}
}

func httpErr(w http.ResponseWriter, code int, msg string, args ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf(msg, args...)})
}

func httpJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// PolicyRefusal is surfaced to clients with HTTP 403 and logged.
type PolicyRefusal struct{ Reason string }

func (e *PolicyRefusal) Error() string { return e.Reason }

func refuse(format string, args ...any) error {
	return &PolicyRefusal{Reason: fmt.Sprintf(format, args...)}
}

// --- simple handlers ---------------------------------------------------------

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pubkeys []string `json:"pubkeys"`
	}
	if err := decodeBody(r, &req); err != nil || len(req.Pubkeys) == 0 {
		httpErr(w, 400, "pubkeys (x-only hex) required")
		return
	}
	for _, pk := range req.Pubkeys {
		if b, err := hex.DecodeString(pk); err != nil || len(b) != 32 {
			httpErr(w, 400, "bad pubkey %s", pk)
			return
		}
	}
	aid := store.AID(req.Pubkeys)
	err := s.st.Update(func(st *store.State) error {
		if _, exists := st.Users[aid]; !exists {
			st.Users[aid] = &store.User{AID: aid, Pubkeys: req.Pubkeys}
		}
		return nil
	})
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	s.st.AppendLog("register", map[string]any{"aid": aid})
	httpJSON(w, map[string]string{"aid": aid})
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	var user *store.User
	s.st.View(func(st *store.State) {
		if u, ok := st.Users[r.PathValue("aid")]; ok {
			cp := *u
			user = &cp
		}
	})
	if user == nil {
		httpErr(w, 404, "unknown aid")
		return
	}
	httpJSON(w, user)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	var assets []*store.Asset
	s.st.View(func(st *store.State) {
		for _, a := range st.Assets {
			cp := *a
			assets = append(assets, &cp)
		}
	})
	httpJSON(w, map[string]any{"assets": assets})
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[r.PathValue("id")]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset")
		return
	}
	httpJSON(w, asset)
}

func (s *Server) handleAddress(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	assetID := r.URL.Query().Get("asset")
	tree, user, asset, err := s.enclaveFor(aid, assetID)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	spk := tree.ScriptPubKey()
	var addr struct {
		Address string `json:"address"`
	}
	s.node.Call(&addr, "decodescript", hex.EncodeToString(spk))
	address := addr.Address
	// For a confidential asset, hand back the blinding (blech32) enclave
	// address, and make sure the watch wallet tracks it so the server can
	// unblind receipts. Same one-step ease as any confidential Sequentia asset.
	if asset.Confidential {
		priv, pub, err := s.blindingKey(asset.ID, elements.MustHex32(user.Pubkeys[0]))
		if err == nil {
			if ca, cerr := s.confidentialEnclaveAddress(hex.EncodeToString(spk), hex.EncodeToString(pub)); cerr == nil {
				address = ca
				_ = s.importConfidentialEnclave(hex.EncodeToString(spk), priv, hex.EncodeToString(pub))
			}
		}
	}
	transferCtl, _ := tree.ControlBlock("transfer")
	resp := map[string]any{
		"aid":              aid,
		"asset":            asset.ID,
		"script_pubkey":    hex.EncodeToString(spk),
		"address":          address,
		"confidential":     asset.Confidential,
		"user_pubkey":      user.Pubkeys[0],
		"transfer_leaf":    hex.EncodeToString(tree.Leaves["transfer"].Script),
		"transfer_control": hex.EncodeToString(transferCtl),
	}
	if asset.Clawback {
		clawCtl, _ := tree.ControlBlock("claw")
		resp["claw_leaf"] = hex.EncodeToString(tree.Leaves["claw"].Script)
		resp["claw_control"] = hex.EncodeToString(clawCtl)
	}
	httpJSON(w, resp)
}

func (s *Server) handleBalance(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	assetID := r.URL.Query().Get("asset")
	tree, _, asset, err := s.enclaveFor(aid, assetID)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	utxos, err := s.enclaveUTXOs(tree, asset.ID)
	if err != nil {
		httpErr(w, 502, "scan: %v", err)
		return
	}
	var atoms uint64
	for _, u := range utxos {
		atoms += u.atoms
	}
	httpJSON(w, map[string]any{"aid": aid, "asset": asset.ID, "atoms": atoms, "utxos": len(utxos)})
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, s.st.LogPath())
}

func (s *Server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AID    string `json:"aid"`
		Frozen bool   `json:"frozen"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	err := s.st.Update(func(st *store.State) error {
		u, ok := st.Users[req.AID]
		if !ok {
			return fmt.Errorf("unknown aid")
		}
		u.Frozen = req.Frozen
		return nil
	})
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	s.st.AppendLog("freeze", req)
	httpJSON(w, map[string]any{"aid": req.AID, "frozen": req.Frozen})
}

func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AID        string   `json:"aid"`
		Categories []string `json:"categories"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	err := s.st.Update(func(st *store.State) error {
		u, ok := st.Users[req.AID]
		if !ok {
			return fmt.Errorf("unknown aid")
		}
		u.Categories = req.Categories
		return nil
	})
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	// OA-LM: the public transparency log records a commitment to the category
	// set, not the raw vector, so it stops leaking each holder's exact
	// categories. The private state above keeps the raw set for policy checks.
	// Format-versioned ("v":1): older entries carry a raw "categories" list and
	// stay readable; new entries carry "categories_hash" and no raw list.
	s.st.AppendLog("categories", map[string]any{
		"v":               1,
		"aid":             req.AID,
		"categories_hash": store.CategorySetHash(req.Categories),
	})
	httpJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset string      `json:"asset"`
		Rules store.Rules `json:"rules"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	err := s.st.Update(func(st *store.State) error {
		a, ok := st.Assets[req.Asset]
		if !ok {
			return fmt.Errorf("unknown asset")
		}
		a.Rules = req.Rules
		return nil
	})
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	s.st.AppendLog("rules", req)
	httpJSON(w, map[string]any{"ok": true})
}

// --- shared helpers ----------------------------------------------------------

func (s *Server) enclaveFor(aid, assetID string) (*elements.TapTree, *store.User, *store.Asset, error) {
	var user *store.User
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if u, ok := st.Users[aid]; ok {
			cp := *u
			user = &cp
		}
		if a, ok := st.Assets[assetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if user == nil {
		return nil, nil, nil, fmt.Errorf("unknown aid %s", aid)
	}
	if asset == nil {
		return nil, nil, nil, fmt.Errorf("unknown asset %s", assetID)
	}
	tree, err := s.treeFor(user, asset)
	return tree, user, asset, err
}

func (s *Server) treeFor(user *store.User, asset *store.Asset) (*elements.TapTree, error) {
	userX := elements.MustHex32(user.Pubkeys[0])
	policyX := elements.MustHex32(asset.PolicyPub)
	var issuerX *[32]byte
	if asset.Clawback {
		x := elements.MustHex32(asset.IssuerPub)
		issuerX = &x
	}
	return elements.EnclaveTree(userX, policyX, issuerX)
}

type enclaveUTXO struct {
	txid  string
	vout  uint32
	atoms uint64
	spk   string
}

func (s *Server) enclaveUTXOs(tree *elements.TapTree, assetID string) ([]enclaveUTXO, error) {
	spk := hex.EncodeToString(tree.ScriptPubKey())
	// Confidential assets are scanned through the watch wallet, which holds the
	// blinding keys and reports unblinded amounts; scantxoutset would only see
	// commitments. Transparent assets scan the UTXO set directly.
	if s.assetConfidential(assetID) {
		cus, err := s.confidentialUTXOs(spk, assetID)
		if err != nil {
			return nil, err
		}
		var out []enclaveUTXO
		for _, u := range cus {
			out = append(out, enclaveUTXO{txid: u.TxID, vout: u.Vout, atoms: sats(u.Amount), spk: u.ScriptPubKey})
		}
		return out, nil
	}
	unspents, err := s.node.ScanTxOutSet([]string{spk})
	if err != nil {
		return nil, err
	}
	var out []enclaveUTXO
	for _, u := range unspents {
		if u.Asset != assetID {
			continue
		}
		out = append(out, enclaveUTXO{txid: u.TxID, vout: u.Vout, atoms: sats(u.Amount), spk: u.ScriptPubKey})
	}
	return out, nil
}

func (s *Server) assetConfidential(assetID string) bool {
	var conf bool
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[assetID]; ok {
			conf = a.Confidential
		}
	})
	return conf
}

func sats(v float64) uint64 {
	return uint64(v*1e8 + 0.5)
}

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func logRefusal(action string, st *store.Store, details map[string]any) {
	details["refused"] = true
	st.AppendLog(action, details)
}

var _ = log.Printf
