// seqpald is the SeqPal platform gateway: a thin, box-only service that sits
// between the SeqPal single-page app (a static front-end) and the OpenAMP
// policy server (openampd).
//
// It exists for one security reason: minting an OpenAMP restricted asset goes
// through openampd's issuer endpoint, which is bearer-token gated. That token
// is a server-side secret and must never reach a browser. seqpald holds the
// token and is the only party that calls the issuer endpoint.
//
// It is deliberately NOT a custodian. The SeqPal front-end generates a real
// Sequentia enclave keypair per SeqPal ID and keeps the private key in the
// browser; only the x-only public key reaches seqpald, which registers it and
// mints the initial supply into that holder's own enclave. seqpald never sees a
// private key. Everything the browser needs to read (assets, balances, enclave
// addresses, the transparency log) it fetches from openampd's public endpoints
// directly, same-origin under /openamp/.
//
// seqpald additionally serves the built SPA with history-API fallback, so a
// single Caddy route (handle_path /seqpal/*) covers both the app and its /api.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type config struct {
	listen      string
	openampURL  string // base, e.g. http://127.0.0.1:8722 (no /v1)
	issuerToken string
	feeConvert  uint64
	webroot     string
	datadir     string
	endpoint    string // public policy endpoint advertised in the asset contract
}

// deployment is the persisted record of one issued asset. It holds no private
// key: the holder key lives in the SeqPal front-end. The file records which
// browser-supplied enclave key received the supply so a re-deploy is idempotent.
type deployment struct {
	IssuanceID   string `json:"issuance_id"`
	Name         string `json:"name"`
	Ticker       string `json:"ticker"`
	Precision    int    `json:"precision"`
	Atoms        uint64 `json:"atoms"`
	Confidential bool   `json:"confidential"`
	Clawback     bool   `json:"clawback"`
	HolderPub    string `json:"holder_pub"` // x-only hex (browser-held key)
	AID          string `json:"aid"`
	Asset        string `json:"asset"`
	Txid         string `json:"txid"`
	ContractHash string `json:"contract_hash"`
	Address      string `json:"address"`
	CreatedAt    string `json:"created_at"`
}

type server struct {
	cfg  config
	http *http.Client
	mu   sync.Mutex // guards the store file + per-issuance serialization
	inFlight map[string]*sync.Mutex
	store    map[string]*deployment
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:8724", "HTTP listen address")
	flag.StringVar(&cfg.openampURL, "openamp", envOr("OPENAMP_URL", "http://127.0.0.1:8722"), "openampd base URL (no /v1)")
	flag.StringVar(&cfg.issuerToken, "issuertoken", os.Getenv("OPENAMPD_ISSUER_TOKEN"), "openampd issuer bearer token")
	flag.Uint64Var(&cfg.feeConvert, "feeconvert", 100, "default fee-conversion charge in asset atoms baked into issued assets")
	flag.StringVar(&cfg.webroot, "webroot", "", "directory of the built SPA to serve (empty = API only)")
	flag.StringVar(&cfg.datadir, "datadir", defaultDatadir(), "state directory for the treasury keystore")
	flag.StringVar(&cfg.endpoint, "endpoint", envOr("SEQPAL_POLICY_ENDPOINT", ""), "public policy endpoint advertised in the contract (e.g. https://host/openamp)")
	flag.Parse()

	if cfg.issuerToken == "" {
		log.Fatal("seqpald: issuer token required (-issuertoken or OPENAMPD_ISSUER_TOKEN)")
	}
	if err := os.MkdirAll(cfg.datadir, 0o700); err != nil {
		log.Fatalf("seqpald: datadir: %v", err)
	}

	s := &server{
		cfg:      cfg,
		http:     &http.Client{Timeout: 150 * time.Second},
		inFlight: map[string]*sync.Mutex{},
		store:    map[string]*deployment{},
	}
	s.load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("POST /api/deploy", s.handleDeploy)
	mux.HandleFunc("GET /api/deploy/{id}", s.handleGetDeploy)
	if cfg.webroot != "" {
		mux.Handle("/", s.spa())
	}

	log.Printf("seqpald on %s -> openampd %s (webroot=%q, %d deployments)", cfg.listen, cfg.openampURL, cfg.webroot, len(s.store))
	log.Fatal(http.ListenAndServe(cfg.listen, mux))
}

// ── deploy ──────────────────────────────────────────────────────────────

func (s *server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IssuanceID   string          `json:"issuance_id"`
		Name         string          `json:"name"`
		Ticker       string          `json:"ticker"`
		Precision    int             `json:"precision"`
		Atoms        uint64          `json:"atoms"`
		Confidential bool            `json:"confidential"`
		Clawback     *bool           `json:"clawback"`
		BurnAllowed  bool            `json:"burn_allowed"`
		TermsHash    string          `json:"terms_hash"`
		HolderPub    string          `json:"holder_pubkey"` // x-only hex, browser-held
		Rules        json.RawMessage `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "bad json: %v", err)
		return
	}
	if req.IssuanceID == "" || req.Name == "" || req.Ticker == "" || req.Atoms == 0 {
		httpErr(w, 400, "issuance_id, name, ticker and a nonzero atoms are required")
		return
	}
	if b, err := hex.DecodeString(req.HolderPub); err != nil || len(b) != 32 {
		httpErr(w, 400, "holder_pubkey must be 32-byte x-only hex")
		return
	}
	if req.Precision <= 0 {
		req.Precision = 2
	}
	clawback := true
	if req.Clawback != nil {
		clawback = *req.Clawback
	}

	// Idempotent by issuance_id, and serialized so a double-submit never
	// double-mints.
	lock := s.lockFor(req.IssuanceID)
	lock.Lock()
	defer lock.Unlock()
	if d := s.get(req.IssuanceID); d != nil {
		writeJSON(w, 200, deployResp(d))
		return
	}

	// The issuer of record also holds the freshly minted supply (holder ==
	// issuer), so the one browser-held enclave key covers both roles.
	aid, err := s.registerUser(req.HolderPub)
	if err != nil {
		httpErr(w, 502, "register: %v", err)
		return
	}

	// Rules: forward the caller's rules, but guarantee a fee-conversion charge
	// so holders can pay fees in the restricted asset itself.
	rules := map[string]any{}
	if len(req.Rules) > 0 {
		_ = json.Unmarshal(req.Rules, &rules)
	}
	if _, ok := rules["fee_convert_atoms"]; !ok {
		rules["fee_convert_atoms"] = s.cfg.feeConvert
	}

	issueReq := map[string]any{
		"name":         req.Name,
		"ticker":       req.Ticker,
		"precision":    req.Precision,
		"atoms":        req.Atoms,
		"holder_aid":   aid,
		"issuer_aid":   aid,
		"clawback":     clawback,
		"burn_allowed": req.BurnAllowed,
		"confidential": req.Confidential,
		"rules":        rules,
	}
	if req.TermsHash != "" {
		issueReq["terms_hash"] = req.TermsHash
	}
	if s.cfg.endpoint != "" {
		issueReq["endpoint"] = s.cfg.endpoint
	}

	var issued struct {
		Asset        string `json:"asset"`
		Txid         string `json:"txid"`
		ContractHash string `json:"contract_hash"`
		Error        string `json:"error"`
	}
	if err := s.callOpenAMP("POST", "/v1/issuer/assets", s.cfg.issuerToken, issueReq, &issued); err != nil {
		httpErr(w, 502, "issue: %v", err)
		return
	}
	if issued.Asset == "" {
		httpErr(w, 502, "issue returned no asset: %s", issued.Error)
		return
	}

	// Enclave receive address for the treasury (blech32 if confidential).
	var addr struct {
		Address string `json:"address"`
	}
	_ = s.callOpenAMP("GET", "/v1/users/"+aid+"/address?asset="+issued.Asset, "", nil, &addr)

	d := &deployment{
		IssuanceID:   req.IssuanceID,
		Name:         req.Name,
		Ticker:       req.Ticker,
		Precision:    req.Precision,
		Atoms:        req.Atoms,
		Confidential: req.Confidential,
		Clawback:     clawback,
		HolderPub:    req.HolderPub,
		AID:          aid,
		Asset:        issued.Asset,
		Txid:         issued.Txid,
		ContractHash: issued.ContractHash,
		Address:      addr.Address,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.put(d); err != nil {
		log.Printf("seqpald: persist %s: %v", req.IssuanceID, err)
	}
	log.Printf("seqpald: issued %s (%s) asset=%s txid=%s", req.Ticker, req.IssuanceID, d.Asset, d.Txid)
	writeJSON(w, 200, deployResp(d))
}

func (s *server) handleGetDeploy(w http.ResponseWriter, r *http.Request) {
	if d := s.get(r.PathValue("id")); d != nil {
		writeJSON(w, 200, deployResp(d))
		return
	}
	httpErr(w, 404, "no deployment for that issuance")
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var probe json.RawMessage
	err := s.callOpenAMP("GET", "/v1/assets", "", nil, &probe)
	writeJSON(w, 200, map[string]any{"ok": true, "openamp_reachable": err == nil})
}

func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	// The browser reads openampd's public endpoints directly; tell it where.
	writeJSON(w, 200, map[string]any{"openamp_base": "/openamp"})
}

// deployResp is the browser-safe projection (no private key).
func deployResp(d *deployment) map[string]any {
	return map[string]any{
		"issuance_id":   d.IssuanceID,
		"asset":         d.Asset,
		"txid":          d.Txid,
		"contract_hash": d.ContractHash,
		"aid":           d.AID,
		"address":       d.Address,
		"confidential":  d.Confidential,
		"atoms":         d.Atoms,
		"precision":     d.Precision,
	}
}

// ── openampd client ───────────────────────────────────────────────────────

func (s *server) registerUser(xonlyHex string) (string, error) {
	var resp struct {
		AID string `json:"aid"`
	}
	err := s.callOpenAMP("POST", "/v1/users", "", map[string]any{"pubkeys": []string{xonlyHex}}, &resp)
	if err != nil {
		return "", err
	}
	if resp.AID == "" {
		return "", fmt.Errorf("no aid returned")
	}
	return resp.AID, nil
}

func (s *server) callOpenAMP(method, path, token string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(s.cfg.openampURL, "/")+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("openampd %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// ── static SPA with history-API fallback ─────────────────────────────────

func (s *server) spa() http.Handler {
	fs := http.FileServer(http.Dir(s.cfg.webroot))
	index := filepath.Join(s.cfg.webroot, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never let the file server shadow the API namespace.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		clean := filepath.Clean(r.URL.Path)
		p := filepath.Join(s.cfg.webroot, clean)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, index) // client-routed path
	})
}

// ── keystore ──────────────────────────────────────────────────────────────

func (s *server) storePath() string { return filepath.Join(s.cfg.datadir, "deployments.json") }

func (s *server) load() {
	data, err := os.ReadFile(s.storePath())
	if err != nil {
		return
	}
	var list []*deployment
	if json.Unmarshal(data, &list) == nil {
		for _, d := range list {
			s.store[d.IssuanceID] = d
		}
	}
}

func (s *server) get(id string) *deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store[id]
}

func (s *server) put(d *deployment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[d.IssuanceID] = d
	list := make([]*deployment, 0, len(s.store))
	for _, v := range s.store {
		list = append(list, v)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.storePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.storePath())
}

func (s *server) lockFor(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.inFlight[id]; ok {
		return m
	}
	m := &sync.Mutex{}
	s.inFlight[id] = m
	return m
}

// ── helpers ───────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, format string, a ...any) {
	writeJSON(w, code, map[string]string{"error": fmt.Sprintf(format, a...)})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultDatadir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".seqpald")
	}
	return "./seqpald-data"
}
