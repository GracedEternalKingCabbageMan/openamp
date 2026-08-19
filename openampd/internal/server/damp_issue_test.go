package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Network-enforced (OpenDAMP) issuance, end to end against a mock node.
//
// The strongest assertions here are pinned to opendamp/vectors/addresses.json,
// the file the Rust implementation generates and spends against on regtest: with
// the vectors' CMRs and the vectors' owner key, the outputs this server builds
// must pay the EXACT scriptPubKeys the vectors record. A drift in the taproot
// derivation therefore fails a test rather than burning an asset into an
// unspendable (or worse, anyone-can-spend) address.

type dampVec struct {
	Programs struct {
		UCMR   string `json:"u_cmr"`
		PCMR   string `json:"p_cmr_canonical"`
		GCMR   string `json:"g_cmr"`
		Shapes []struct {
			Shape string `json:"shape"`
			CMR   string `json:"cmr"`
		} `json:"verifier_shapes"`
	} `json:"programs"`
	Policy struct {
		WhitelistRoot string `json:"whitelist_root"`
		// The vectors' holder entries carry the height bounds the covenant's
		// whitelist leaf commits, so they deserialize as entries rather than keys.
		// Issuance itself only ever produces UNBOUNDED entries (a lockup binds a
		// height, and at issuance there is no height yet), so the root an issuance
		// commits is recomputed from these keys without their bounds; the
		// cross-language pin for the tree WITH bounds lives in internal/damp's
		// TestSnapshotDMTv1PredicateShape.
		WhitelistEntries []damp.PredicateEntry `json:"whitelist_entries"`
		TransferLimit    uint64                `json:"transfer_limit"`
	} `json:"policy"`
	UserCovenants []struct {
		OwnerXOnly   string `json:"owner_xonly"`
		ScriptPubKey string `json:"script_pubkey"`
	} `json:"user_covenants"`
	VerifierCovenant struct {
		ScriptPubKey string `json:"script_pubkey"`
	} `json:"verifier_covenant"`
	path string
}

// whitelistKeys is the vectors' holder keys without their height bounds, which is
// what an issuance's holder list is.
func (v dampVec) whitelistKeys() []string {
	out := make([]string, 0, len(v.Policy.WhitelistEntries))
	for _, e := range v.Policy.WhitelistEntries {
		out = append(out, e.Key)
	}
	return out
}

func loadDampVectors(t *testing.T) dampVec {
	t.Helper()
	p := filepath.Join("..", "..", "..", "opendamp", "vectors", "addresses.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("opendamp vectors unavailable (%v)", err)
	}
	var v dampVec
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	v.path = p
	return v
}

// --- mock node ---------------------------------------------------------------

// dampNode is the issuance mock with two additions the damp path needs: it keeps
// EVERY broadcast (a damp issuance is two transactions) and it answers
// scantxoutset, so a covenant balance read has something to find.
type dampNode struct {
	addr    string
	spk     string
	fundTx  string
	sends   []string
	rejects string

	// scanUnspents is what scantxoutset reports, keyed by scriptPubKey hex.
	scanUnspents map[string]map[string]any
}

func newDampNode() *dampNode {
	return &dampNode{
		addr: "sq1walletaddr", spk: "0014" + strings.Repeat("aa", 20),
		fundTx:       strings.Repeat("f0", 32),
		scanUnspents: map[string]map[string]any{},
	}
}

func (n *dampNode) handler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"result": v, "error": nil}) }
	str := func(i int) string {
		if i >= len(req.Params) {
			return ""
		}
		var s string
		_ = json.Unmarshal(req.Params[i], &s)
		return s
	}

	switch req.Method {
	case "getblockhash":
		reply(strings.Repeat("01", 32))
	case "gettxout":
		reply(map[string]any{"confirmations": 1, "value": 1.0})
	case "listunspent":
		reply([]any{map[string]any{
			"txid": n.fundTx, "vout": 0, "amount": 100000.0 / 1e8,
			"asset": oa4FeeID, "scriptPubKey": n.spk, "spendable": true,
			"confidential": false, "amountblinder": "", "assetblinder": "",
		}})
	case "scantxoutset":
		var descs []string
		if len(req.Params) > 1 {
			_ = json.Unmarshal(req.Params[1], &descs)
		}
		var found []any
		for _, d := range descs {
			spk := strings.TrimSuffix(strings.TrimPrefix(d, "raw("), ")")
			if u, ok := n.scanUnspents[spk]; ok {
				found = append(found, u)
			}
		}
		reply(map[string]any{"success": true, "unspents": found})
	case "getnewaddress":
		reply(n.addr)
	case "getaddressinfo":
		reply(map[string]any{"scriptPubKey": n.spk, "unconfidential": "", "confidential_key": ""})
	case "decodescript":
		reply(map[string]any{"address": "sq1decoded-" + str(0)[:8]})
	case "signrawtransactionwithwallet":
		reply(map[string]any{"hex": str(0), "complete": true})
	case "testmempoolaccept":
		if n.rejects != "" {
			reply([]any{map[string]any{"allowed": false, "reject-reason": n.rejects}})
			return
		}
		reply([]any{map[string]any{"allowed": true}})
	case "sendrawtransaction":
		hexTx := str(0)
		n.sends = append(n.sends, hexTx)
		tx, err := elements.DeserializeTx(mustHexBytes(hexTx))
		if err != nil {
			reply(strings.Repeat("ee", 32))
			return
		}
		reply(tx.TxID())
	default:
		reply(nil)
	}
}

// newDampServer wires a server with network enforcement CONFIGURED from the
// vectors file, which is a valid CMR pinning input by construction.
func newDampServer(t *testing.T, v dampVec) (*Server, *store.Store, *dampNode) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node := newDampNode()
	ts := httptest.NewServer(http.HandlerFunc(node.handler))
	t.Cleanup(ts.Close)
	cl, err := rpc.New(ts.URL, "u:p")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := damp.LoadProgramRegistry(v.path)
	if err != nil {
		t.Fatalf("LoadProgramRegistry(%s): %v", v.path, err)
	}
	s := &Server{
		cfg: Config{FeeAsset: oa4FeeID, FeeSats: 100, DampRegistry: v.path},
		st:  st, node: cl, wallet: cl,
		pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(st),
		dampReg: reg,
	}
	for i := range s.genesis {
		s.genesis[i] = byte(i + 1)
	}
	return s, st, node
}

func postJSON(t *testing.T, h http.HandlerFunc, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	h(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// dampPrepareBody is a valid phase-1 body: the vectors' whitelist, with the
// vectors' first owner as the initial holder.
func dampPrepareBody(v dampVec) map[string]any {
	return map[string]any{
		"name": "Damp Bond", "ticker": "DBND", "precision": 2, "atoms": 500000,
		"holder_pubkey":     v.UserCovenants[0].OwnerXOnly,
		"whitelist":         v.whitelistKeys(),
		"verifier_amount":   1,
		"issuer_update_key": v.UserCovenants[1].OwnerXOnly,
		"burn_allowed":      false,
	}
}

func dampPrepare(t *testing.T, s *Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	return postJSON(t, s.handleDampIssuePrepare, "/v1/issuer/damp-assets", body)
}

func dampComplete(t *testing.T, s *Server, id string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/damp-assets/"+id+"/complete", bytes.NewReader(b))
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.handleDampIssueComplete(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// --- the headline test -------------------------------------------------------

// TestDamp_FullIssuance walks the whole two-phase issuance and pins the outputs
// against the Rust vectors: A is minted into C_U(holder), q of V is locked into
// C_V(pi_0) in the SAME transaction, and both scriptPubKeys are the exact bytes
// opendamp derives.
func TestDamp_FullIssuance(t *testing.T) {
	v := loadDampVectors(t)
	s, st, node := newDampServer(t, v)

	code, prep := dampPrepare(t, s, dampPrepareBody(v))
	if code != 200 {
		t.Fatalf("prepare: want 200, got %d: %v", code, prep)
	}
	// The whitelist root is the dmt-v1 root over the same entries the Rust side
	// hashes, so it must match the vectors byte for byte.
	// The whitelist root is the dmt-v1 root over the same holder LEAVES the Rust
	// side hashes. An issuance's leaves are unbounded, so the expected root is
	// recomputed here from the vectors' keys; the vectors' own root covers a holder
	// with a receive window, and internal/damp pins that one across languages.
	wantWLRoot, wlErr := damp.WhitelistRoot(func() [][32]byte {
		keys := make([][32]byte, 0, len(v.Policy.WhitelistEntries))
		for _, e := range v.Policy.WhitelistEntries {
			keys = append(keys, elements.MustHex32(e.Key))
		}
		return keys
	}())
	if wlErr != nil {
		t.Fatal(wlErr)
	}
	if prep["whitelist_root"] != hex.EncodeToString(wantWLRoot[:]) {
		t.Fatalf("whitelist_root = %v, the unbounded holder leaves hash to %x", prep["whitelist_root"], wantWLRoot)
	}
	if prep["tree"] != damp.TreeDMTv1 {
		t.Fatalf("tree = %v, want %s", prep["tree"], damp.TreeDMTv1)
	}
	if len(node.sends) != 1 {
		t.Fatalf("prepare must broadcast exactly the verifier issuance, got %d transactions", len(node.sends))
	}
	assetID, _ := prep["asset"].(string)
	vAssetID, _ := prep["verifier_asset"].(string)
	pi, _ := prep["pi"].(string)
	prepareID, _ := prep["prepare_id"].(string)
	if assetID == "" || vAssetID == "" || pi == "" || prepareID == "" {
		t.Fatalf("prepare response is missing a required field: %v", prep)
	}
	if assetID == vAssetID {
		t.Fatal("the verifier asset must differ from the asset")
	}
	// The derive-ready document carries the two fields the snapshot format does
	// not, and the canonical snapshot must NOT carry them (they are outside the
	// bytes the hash and signature commit to).
	derive, _ := prep["derive_snapshot"].(map[string]any)
	if derive["issuer_update_key"] != v.UserCovenants[1].OwnerXOnly || derive["network"] != "testnet" {
		t.Fatalf("derive_snapshot is not derive-ready: %v", derive)
	}
	snapRaw, _ := json.Marshal(prep["snapshot"])
	if strings.Contains(string(snapRaw), "issuer_update_key") || strings.Contains(string(snapRaw), "network") {
		t.Fatalf("the canonical snapshot must not carry derive-only fields: %s", snapRaw)
	}
	// Nothing of A exists yet.
	var count int
	st.View(func(state *store.State) { count = len(state.Assets) })
	if count != 0 {
		t.Fatal("prepare must not persist an asset")
	}

	code, out := dampComplete(t, s, prepareID, map[string]any{
		"user_cmr": v.Programs.UCMR, "verifier_cmrs": v.shapeCMRs(), "issuer_cmr": v.Programs.GCMR,
		"pi": pi, "verifier_spk": v.VerifierCovenant.ScriptPubKey,
	})
	if code != 200 {
		t.Fatalf("complete: want 200, got %d: %v", code, out)
	}
	if len(node.sends) != 2 {
		t.Fatalf("complete must broadcast exactly one transaction, total %d", len(node.sends))
	}
	txids, _ := out["txids"].(map[string]any)
	if txids["asset_issue"] == "" || txids["asset_issue"] != txids["verifier_lock"] {
		t.Fatalf("the asset issuance and the verifier lock are one transaction: %v", txids)
	}
	if txids["verifier_issue"] == txids["asset_issue"] {
		t.Fatalf("the verifier issuance is a separate transaction: %v", txids)
	}

	// The transaction itself: A into C_U(alice), q of V into C_V(pi_0).
	tx, err := elements.DeserializeTx(mustHexBytes(node.sends[1]))
	if err != nil {
		t.Fatalf("decode issuance: %v", err)
	}
	if len(tx.Out) != 5 {
		t.Fatalf("want 5 outputs (A, token, V lock, fee change, fee), got %d", len(tx.Out))
	}
	wantUserSpk := v.UserCovenants[0].ScriptPubKey
	if got := hex.EncodeToString(tx.Out[0].ScriptPubKey); got != wantUserSpk {
		t.Fatalf("A output pays %s, the vectors' C_U(alice) is %s", got, wantUserSpk)
	}
	if got := hex.EncodeToString(tx.Out[0].Asset); got != hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(assetID))) {
		t.Fatalf("A output carries the wrong asset: %s", got)
	}
	if got, ok := elements.ExplicitValueAmount(tx.Out[0].Value); !ok || got != 500000 {
		t.Fatalf("A output value = %d (explicit=%v), want 500000", got, ok)
	}
	wantVSpk := v.VerifierCovenant.ScriptPubKey
	if got := hex.EncodeToString(tx.Out[2].ScriptPubKey); got != wantVSpk {
		t.Fatalf("verifier lock pays %s, the derived C_V is %s", got, wantVSpk)
	}
	if got := hex.EncodeToString(tx.Out[2].Asset); got != hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(vAssetID))) {
		t.Fatalf("verifier lock carries the wrong asset: %s", got)
	}
	if got, ok := elements.ExplicitValueAmount(tx.Out[2].Value); !ok || got != 1 {
		t.Fatalf("verifier lock value = %d (explicit=%v), want q=1", got, ok)
	}
	// Fee output must not carry A. The covenant enforces this at consensus; this
	// asserts the builder never even tries.
	fee := tx.Out[len(tx.Out)-1]
	if len(fee.ScriptPubKey) != 0 {
		t.Fatal("last output must be the fee output (empty scriptPubKey)")
	}
	if hex.EncodeToString(fee.Asset) == hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(assetID))) {
		t.Fatal("the fee output carries the restricted asset")
	}
	// Input 1 spends the verifier issuance's V output.
	if len(tx.In) != 2 {
		t.Fatalf("want 2 inputs (funding+issuance, V), got %d", len(tx.In))
	}

	// Persistence: enforcement and the full binding.
	var asset *store.Asset
	st.View(func(state *store.State) { asset = state.Assets[assetID] })
	if asset == nil {
		t.Fatal("complete did not persist the asset")
	}
	if asset.Enforcement != "damp" || asset.Damp == nil {
		t.Fatalf("stored asset is not marked network-enforced: %+v", asset)
	}
	if asset.Clawback {
		t.Fatal("a network-enforced asset must have no clawback leaf")
	}
	if asset.Damp.Pi != pi || asset.Damp.WhitelistRoot != prep["whitelist_root"] ||
		asset.Damp.VerifierAsset != vAssetID || asset.Damp.VerifierAmount != 1 ||
		asset.Damp.UserCovenantSPK != wantUserSpk || asset.Damp.VerifierSPK != wantVSpk ||
		asset.Damp.Tree != damp.TreeDMTv1 {
		t.Fatalf("binding is wrong: %+v", asset.Damp)
	}
	if asset.IssuerPub != v.UserCovenants[1].OwnerXOnly || !asset.IssuerExternal {
		t.Fatal("the issuer key of a network-enforced asset is the external update key")
	}

	// The contract commits the section 5 fields and NOT a genesis policy.
	var contract map[string]any
	if err := json.Unmarshal(asset.Contract, &contract); err != nil {
		t.Fatal(err)
	}
	oa, _ := contract["openamp"].(map[string]any)
	if oa["enforcement"] != "damp" || oa["verifier_asset"] != vAssetID || oa["issuer_update_key"] != v.UserCovenants[1].OwnerXOnly {
		t.Fatalf("contract openamp block is wrong: %v", oa)
	}
	if oa["clawback"] != false {
		t.Fatalf("contract must record clawback:false, got %v", oa["clawback"])
	}
	if _, has := oa["policy_pubkey"]; !has {
		t.Fatal("policy_pubkey is kept so the asset stays registerable; it disappeared")
	}
	for _, forbidden := range []string{"genesis_policy", "genesis_snapshot_hash"} {
		if _, has := oa[forbidden]; has {
			t.Fatalf("%s must NOT be in the contract: pi commits to the asset id, which commits to the contract", forbidden)
		}
	}

	// The genesis snapshot is retrievable through the ordinary endpoint.
	req := httptest.NewRequest("GET", "/v1/snapshots?asset="+assetID, nil)
	rec := httptest.NewRecorder()
	s.handleSnapshotGet(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /v1/snapshots: %d %s", rec.Code, rec.Body.String())
	}
	var snapResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &snapResp)
	if snapResp["pi"] != pi || fmt.Sprint(snapResp["seq"]) != "0" {
		t.Fatalf("published snapshot is wrong: %v", snapResp)
	}
	published, _ := snapResp["snapshot"].(map[string]any)
	if published["tree"] != damp.TreeDMTv1 {
		t.Fatalf("published snapshot tree = %v", published["tree"])
	}
	// The genesis blacklist is EMPTY but not ABSENT: the covenant proves
	// non-membership against a real root on every regulated input, and an absent
	// root would commit zeros no covenant answers to.
	preds, _ := published["predicates"].(map[string]any)
	bl, _ := preds["blacklist"].(map[string]any)
	emptyBl, err := damp.BlacklistRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bl["root"] != hex.EncodeToString(emptyBl[:]) {
		t.Fatalf("genesis blacklist root = %v, want the empty interval tree root %x", bl["root"], emptyBl)
	}
	if entries, _ := bl["entries"].([]any); len(entries) != 0 {
		t.Fatalf("the genesis blacklist must be empty, got %v", entries)
	}

	// GET /v1/assets/{id} exposes the binding.
	areq := httptest.NewRequest("GET", "/v1/assets/"+assetID, nil)
	areq.SetPathValue("id", assetID)
	arec := httptest.NewRecorder()
	s.handleAsset(arec, areq)
	var assetResp map[string]any
	_ = json.Unmarshal(arec.Body.Bytes(), &assetResp)
	if assetResp["enforcement"] != "damp" {
		t.Fatalf("GET /v1/assets/{id} does not report enforcement: %s", arec.Body.String())
	}
	bind, _ := assetResp["damp"].(map[string]any)
	if bind["pi"] != pi || bind["verifier_covenant_spk"] != wantVSpk || bind["user_cmr"] != v.Programs.UCMR {
		t.Fatalf("GET /v1/assets/{id} does not expose the binding: %s", arec.Body.String())
	}

	// The prepare is consumed: a replay cannot mint a second time.
	code, out = dampComplete(t, s, prepareID, map[string]any{
		"user_cmr": v.Programs.UCMR, "verifier_cmrs": v.shapeCMRs(), "pi": pi,
	})
	if code != 404 {
		t.Fatalf("replayed complete: want 404, got %d %v", code, out)
	}
	if len(node.sends) != 2 {
		t.Fatalf("a replay broadcast again: %d transactions", len(node.sends))
	}
}

// TestDamp_PiMismatchRefused: the authority split. A CMR this server cannot
// compile is only accepted alongside a pi it can check, so a derive run against
// the wrong snapshot is refused before anything is broadcast.
func TestDamp_PiMismatchRefused(t *testing.T) {
	v := loadDampVectors(t)
	s, st, node := newDampServer(t, v)
	code, prep := dampPrepare(t, s, dampPrepareBody(v))
	if code != 200 {
		t.Fatalf("prepare: %d %v", code, prep)
	}
	before := len(node.sends)

	code, out := dampComplete(t, s, prep["prepare_id"].(string), map[string]any{
		"user_cmr": v.Programs.UCMR, "verifier_cmrs": v.shapeCMRs(),
		"pi": strings.Repeat("11", 32),
	})
	if code != 409 {
		t.Fatalf("pi mismatch: want 409, got %d %v", code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "pi mismatch") || !strings.Contains(msg, "nothing was broadcast") {
		t.Fatalf("refusal must name the cause and say nothing moved: %v", out["error"])
	}
	if len(node.sends) != before {
		t.Fatalf("a refused completion broadcast: %d -> %d", before, len(node.sends))
	}
	st.View(func(state *store.State) {
		if len(state.Assets) != 0 {
			t.Fatal("a refused completion persisted an asset")
		}
	})
	// And the refusal is in the public log.
	raw, err := os.ReadFile(st.LogPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "pi mismatch") {
		t.Fatal("the pi mismatch is not in the transparency log")
	}
}

// TestDamp_VerifierSPKMismatchRefused: the cross-check that catches a CMR from
// the wrong policy even when the operator pasted a matching pi.
func TestDamp_VerifierSPKMismatchRefused(t *testing.T) {
	v := loadDampVectors(t)
	s, _, node := newDampServer(t, v)
	_, prep := dampPrepare(t, s, dampPrepareBody(v))
	before := len(node.sends)
	code, out := dampComplete(t, s, prep["prepare_id"].(string), map[string]any{
		"user_cmr": v.Programs.UCMR, "verifier_cmrs": v.shapeCMRs(),
		"pi": prep["pi"], "verifier_spk": "5120" + strings.Repeat("cd", 32),
	})
	if code != 409 || !strings.Contains(out["error"].(string), "verifier_spk mismatch") {
		t.Fatalf("want a 409 spk mismatch, got %d %v", code, out)
	}
	if len(node.sends) != before {
		t.Fatal("a refused completion broadcast")
	}
}

// TestDamp_WhitelistMustContainHolder: a whitelist without the holder makes a
// dead asset, so it is refused before the verifier asset is even minted.
func TestDamp_WhitelistMustContainHolder(t *testing.T) {
	v := loadDampVectors(t)
	s, st, node := newDampServer(t, v)
	body := dampPrepareBody(v)
	body["whitelist"] = []string{v.UserCovenants[1].OwnerXOnly}
	code, out := dampPrepare(t, s, body)
	if code != 400 {
		t.Fatalf("want 400, got %d %v", code, out)
	}
	if !strings.Contains(out["error"].(string), "whitelist must contain holder_pubkey") {
		t.Fatalf("wrong refusal: %v", out["error"])
	}
	if len(node.sends) != 0 {
		t.Fatal("a refused prepare broadcast a verifier issuance")
	}
	st.View(func(state *store.State) {
		if len(state.PendingDampIssuances) != 0 {
			t.Fatal("a refused prepare persisted state")
		}
	})

	// An empty whitelist is the same refusal class.
	body["whitelist"] = []string{}
	if code, _ := dampPrepare(t, s, body); code != 400 {
		t.Fatalf("empty whitelist: want 400, got %d", code)
	}
}

// TestDamp_UnconfiguredGives501 pins the capability refusal on every damp
// endpoint when no CMR pinning file is configured.
func TestDamp_UnconfiguredGives501(t *testing.T) {
	s, _ := newM2Server(t, Config{DemoIssuer: true})
	if s.dampConfigured() {
		t.Fatal("a server with no -dampregistry must not report network enforcement")
	}
	code, out := dampPrepare(t, s, map[string]any{"name": "X", "ticker": "X"})
	if code != 501 || out["error"] != dampNotConfigured {
		t.Fatalf("prepare: want 501 %q, got %d %v", dampNotConfigured, code, out)
	}
	code, out = dampComplete(t, s, "whatever", map[string]any{})
	if code != 501 || out["error"] != dampNotConfigured {
		t.Fatalf("complete: want 501 %q, got %d %v", dampNotConfigured, code, out)
	}
}

// TestDamp_HostedIssueRoutesToDampEndpoint: with network enforcement configured,
// the co-signed endpoint stops answering 501 for enforcement "damp" and names
// the endpoint that can actually do it.
func TestDamp_HostedIssueRoutesToDampEndpoint(t *testing.T) {
	v := loadDampVectors(t)
	s, _, node := newDampServer(t, v)
	s.cfg.DemoIssuer = true
	code, out := postJSON(t, s.handleIssue, "/v1/issuer/assets", map[string]any{
		"name": "X", "ticker": "XXX", "atoms": 1, "enforcement": "damp",
		"holder_aid": "h", "issuer_aid": "i",
	})
	if code != 400 {
		t.Fatalf("want 400, got %d %v", code, out)
	}
	if !strings.Contains(out["error"].(string), "/v1/issuer/damp-assets") {
		t.Fatalf("the refusal must name the endpoint: %v", out["error"])
	}
	if len(node.sends) != 0 {
		t.Fatal("the routing refusal broadcast something")
	}
}

// --- refusals and non-interference -------------------------------------------

// seedDampAsset stores a network-enforced asset and a registered holder without
// touching the chain, for the paths that must refuse one.
func seedDampAsset(t *testing.T, s *Server, st *store.Store, v dampVec) (*store.Asset, *store.User) {
	t.Helper()
	// The holder must be registered under the vectors' OWNER key, so C_U(X) is the
	// address the vectors pin (regUser's second argument is categories, not keys).
	xh := v.UserCovenants[0].OwnerXOnly
	user := &store.User{AID: store.AID([]string{xh}), Pubkeys: []string{xh}}
	if err := st.Update(func(state *store.State) error {
		state.Users[user.AID] = user
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	asset := &store.Asset{
		ID: strings.Repeat("a1", 32), Ticker: "DBND", Name: "Damp Bond", Precision: 2,
		Contract: json.RawMessage(`{}`), ContractHash: strings.Repeat("c1", 32),
		PolicyPub: v.UserCovenants[1].OwnerXOnly, IssuerPub: v.UserCovenants[1].OwnerXOnly,
		IssuerExternal: true, IssuerAID: user.AID, Clawback: false, BurnAllowed: true,
		Entropy: strings.Repeat("e1", 32), Token: strings.Repeat("70", 32),
		Enforcement: "damp",
		Damp: &store.DampBinding{
			VerifierAsset: strings.Repeat("b2", 32), VerifierAmount: 1,
			IssuerUpdateKey: v.UserCovenants[1].OwnerXOnly, HolderPubkey: v.UserCovenants[0].OwnerXOnly,
			Pi: strings.Repeat("d1", 32), WhitelistRoot: v.Policy.WhitelistRoot, Tree: damp.TreeDMTv1,
			UserCMR: v.Programs.UCMR, VerifierCMR: v.Programs.PCMR, VerifierCMRs: v.shapeCMRs(), IssuerCMR: v.Programs.GCMR,
			UserCovenantSPK: v.UserCovenants[0].ScriptPubKey,
			VerifierSPK:     v.VerifierCovenant.ScriptPubKey,
		},
	}
	if err := st.Update(func(state *store.State) error {
		state.Assets[asset.ID] = asset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return asset, user
}

// TestDamp_CosignPathsRefuse409: every path that would co-sign, sweep, burn or
// reissue a damp asset refuses with the one documented message, so a caller is
// never left guessing why a hosted transfer produced nothing.
func TestDamp_CosignPathsRefuse409(t *testing.T) {
	v := loadDampVectors(t)
	s, st, _ := newDampServer(t, v)
	asset, user := seedDampAsset(t, s, st, v)

	cases := []struct {
		name string
		h    http.HandlerFunc
		path string
		body map[string]any
	}{
		{"hosted transfer", s.handleTransferBuild, "/v1/transfers", map[string]any{
			"asset": asset.ID, "sender_aid": user.AID, "recipient_aid": user.AID,
			"atoms": 1, "fee_mode": "sponsor"}},
		{"cosign", s.handleCosign, "/v1/cosign", map[string]any{
			"asset": asset.ID, "sender_aid": user.AID, "tx": "00", "inputs": []int{0}}},
		{"burn", s.handleBurnBuild, "/v1/issuer/burn", map[string]any{
			"asset": asset.ID, "holder_aid": user.AID, "atoms": 1}},
		{"reissue", s.handleReissue, "/v1/issuer/reissue", map[string]any{
			"asset": asset.ID, "target_aid": user.AID, "atoms": 1, "request_id": "r1"}},
		{"clawback", s.handleClawback, "/v1/issuer/clawback", map[string]any{
			"asset": asset.ID, "holder_aid": user.AID, "reason": "court order"}},
	}
	for _, c := range cases {
		code, out := postJSON(t, c.h, c.path, c.body)
		if code != 409 {
			t.Fatalf("%s: want 409, got %d %v", c.name, code, out)
		}
		if out["error"] != dampNotCosigned {
			t.Fatalf("%s: wrong message %q", c.name, out["error"])
		}
	}
}

// TestDamp_ReadPathsUseTheCovenant: address and balance must answer about the
// covenant, never about a meaningless enclave. Reporting an enclave balance of 0
// for a holder who owns coins would read as "empty" rather than "wrong place".
func TestDamp_ReadPathsUseTheCovenant(t *testing.T) {
	v := loadDampVectors(t)
	s, st, node := newDampServer(t, v)
	asset, user := seedDampAsset(t, s, st, v)
	wantSpk := v.UserCovenants[0].ScriptPubKey

	req := httptest.NewRequest("GET", "/v1/users/"+user.AID+"/address?asset="+asset.ID, nil)
	req.SetPathValue("aid", user.AID)
	rec := httptest.NewRecorder()
	s.handleAddress(rec, req)
	if rec.Code != 200 {
		t.Fatalf("address: %d %s", rec.Code, rec.Body.String())
	}
	var addr map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &addr)
	if addr["script_pubkey"] != wantSpk {
		t.Fatalf("address must be C_U(holder) = %s, got %v", wantSpk, addr["script_pubkey"])
	}
	if addr["covenant"] != true || addr["note"] != dampNotCosigned {
		t.Fatalf("address must say who enforces: %s", rec.Body.String())
	}
	if _, has := addr["transfer_leaf"]; has {
		t.Fatal("a covenant address has no enclave leaves to hand out")
	}

	// A confidential form is refused, with the reason: the covenant must read an
	// explicit asset id on every output it scans.
	creq := httptest.NewRequest("GET", "/v1/users/"+user.AID+"/address?asset="+asset.ID+"&confidential=1", nil)
	creq.SetPathValue("aid", user.AID)
	crec := httptest.NewRecorder()
	s.handleAddress(crec, creq)
	if crec.Code != 409 {
		t.Fatalf("confidential covenant address: want 409, got %d %s", crec.Code, crec.Body.String())
	}

	// Balance is scanned at the covenant script.
	node.scanUnspents[wantSpk] = map[string]any{
		"txid": strings.Repeat("11", 32), "vout": 0, "amount": 1234.0 / 1e8,
		"asset": asset.ID, "scriptPubKey": wantSpk,
	}
	breq := httptest.NewRequest("GET", "/v1/users/"+user.AID+"/balance?asset="+asset.ID, nil)
	breq.SetPathValue("aid", user.AID)
	brec := httptest.NewRecorder()
	s.handleBalance(brec, breq)
	if brec.Code != 200 {
		t.Fatalf("balance: %d %s", brec.Code, brec.Body.String())
	}
	var bal map[string]any
	_ = json.Unmarshal(brec.Body.Bytes(), &bal)
	if fmt.Sprint(bal["atoms"]) != "1234" || bal["covenant"] != true {
		t.Fatalf("balance must come from the covenant script: %s", brec.Body.String())
	}

	// Ownership reporting follows the same script, so supply is not silently 0.
	hreq := httptest.NewRequest("GET", "/v1/issuer/holders?asset="+asset.ID, nil)
	hrec := httptest.NewRecorder()
	s.handleHolders(hrec, hreq)
	var holders map[string]any
	_ = json.Unmarshal(hrec.Body.Bytes(), &holders)
	if fmt.Sprint(holders["total_atoms"]) != "1234" {
		t.Fatalf("holders report must scan covenants: %s", hrec.Body.String())
	}
}

// TestDamp_CosignAssetUnaffected: the co-signed tier is byte-untouched by all of
// this. A cosign issuance run through a damp-CONFIGURED server still produces the
// pinned contract bytes, and a stored cosign asset record still carries neither
// an enforcement nor a damp key.
func TestDamp_CosignAssetUnaffected(t *testing.T) {
	v := loadDampVectors(t)
	s, st, _ := newDampServer(t, v)
	s.cfg.DemoIssuer = true
	holder := regUser(t, st, nil)
	issuer := regUser(t, st, nil)

	code, out := postJSON(t, s.handleIssue, "/v1/issuer/assets", map[string]any{
		"name": "BONDX", "ticker": "BONDX", "precision": 8, "atoms": 1000000,
		"holder_aid": holder.AID, "issuer_aid": issuer.AID,
	})
	if code != 200 {
		t.Fatalf("cosign issuance through a damp-configured server failed: %d %v", code, out)
	}
	assetID := out["asset"].(string)
	var asset *store.Asset
	st.View(func(state *store.State) { asset = state.Assets[assetID] })
	if asset == nil {
		t.Fatal("cosign issuance did not persist")
	}
	if asset.Enforcement != "" || asset.Damp != nil {
		t.Fatalf("a cosign asset gained enforcement state: %+v", asset)
	}
	// Byte identity of the contract against the pinned pre-M2 shape.
	want := `{"issuer_pubkey":"` + asset.IssuerPub + `","name":"BONDX","openamp":{"burn_allowed":false,"clawback":true,"policy_pubkey":"` + asset.PolicyPub + `","type":"restricted","version":1},"precision":8,"ticker":"BONDX","version":0}`
	if string(asset.Contract) != want {
		t.Fatalf("cosign contract bytes drifted.\n got: %s\nwant: %s", asset.Contract, want)
	}
	// And the record serializes without either new key.
	raw, err := json.Marshal(asset)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"damp"`) || strings.Contains(string(raw), `"enforcement"`) {
		t.Fatalf("a cosign asset record must omit both keys: %s", raw)
	}
}

// shapeCMRs is the ordered menu of primary-program CMRs: one per transaction
// shape, canonical first. The verifier taptree is built from all of them, so a
// caller that sends one is sending a different address.
func (v *dampVec) shapeCMRs() []string {
	out := make([]string, 0, len(v.Programs.Shapes))
	for _, sh := range v.Programs.Shapes {
		out = append(out, sh.CMR)
	}
	return out
}

func (v *dampVec) shapeCMRBytes() [][32]byte {
	out := make([][32]byte, 0, len(v.Programs.Shapes))
	for _, sh := range v.Programs.Shapes {
		var c [32]byte
		copy(c[:], mustHexBytes(sh.CMR))
		out = append(out, c)
	}
	return out
}
