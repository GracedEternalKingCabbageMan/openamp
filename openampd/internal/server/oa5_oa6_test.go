package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// OA-5 (redeem = real burn) and OA-6 (DR mint = real reissuance). Both are
// additive: a burn only touches assets with BurnAllowed and reuses the M5/M6
// hosted transfer completion path unchanged; a reissue is reachable only via a
// new issuer endpoint and never affects an existing asset. The chain-derived
// supply read is proven to be exactly the holders sum.

// --- helpers ----------------------------------------------------------------

func makeBurnable(t *testing.T, st *store.Store, assetID string) {
	t.Helper()
	if err := st.Update(func(s *store.State) error {
		s.Assets[assetID].BurnAllowed = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func callBurn(t *testing.T, s *Server, body map[string]any) (int, buildResp, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/burn", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleBurnBuild(rec, req)
	var out buildResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func callSupply(t *testing.T, s *Server, assetID string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/v1/supply?asset="+assetID, nil)
	rec := httptest.NewRecorder()
	s.handleSupply(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func burnScriptOut(tx *elements.Tx, assetID string) (uint64, bool) {
	want := hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(assetID)))
	for _, o := range tx.Out {
		if len(o.ScriptPubKey) == 1 && o.ScriptPubKey[0] == 0x6a && hex.EncodeToString(o.Asset) == want {
			amt, _ := elements.ExplicitValueAmount(o.Value)
			return amt, true
		}
	}
	return 0, false
}

// --- OA-5: burn --------------------------------------------------------------

// TestOA5_BurnSpendsHolderIntoUnspendableAndCompletes proves a burn build sends
// the holder's units to the `0x6a` unspendable output (reducing the holder's
// balance) and completes through the unchanged M5/M6 co-sign path, once only.
func TestOA5_BurnSpendsHolderIntoUnspendableAndCompletes(t *testing.T) {
	f := newOA4Fixture(t)
	makeBurnable(t, f.st, f.asset.ID)

	code, resp, body := callBurn(t, f.s, map[string]any{
		"asset": f.asset.ID, "holder_aid": f.escrow.AID, "atoms": 400,
	})
	if code != 200 {
		t.Fatalf("burn build failed: %d %s", code, body)
	}
	if len(resp.ToSign) != 1 {
		t.Fatalf("expected 1 enclave input to sign, got %d", len(resp.ToSign))
	}
	tx, err := elements.DeserializeTx(mustHexBytes(resp.Tx))
	if err != nil {
		t.Fatal(err)
	}
	// The holder's 1000-atom enclave coin funds the burn; 400 goes to 0x6a and
	// 600 returns to the holder enclave. None of the 400 lands anywhere spendable.
	burned, ok := burnScriptOut(tx, f.asset.ID)
	if !ok || burned != 400 {
		t.Fatalf("expected a 400-atom 0x6a burn output, got %d ok=%v", burned, ok)
	}
	escrowTree, _ := f.s.treeFor(f.escrow, f.asset)
	escrowSpk := hex.EncodeToString(escrowTree.ScriptPubKey())
	var backToHolder uint64
	for _, o := range tx.Out {
		if hex.EncodeToString(o.ScriptPubKey) == escrowSpk {
			amt, _ := elements.ExplicitValueAmount(o.Value)
			backToHolder += amt
		}
	}
	if backToHolder != 600 {
		t.Fatalf("expected 600 atoms of change back to the holder, got %d", backToHolder)
	}

	// Holder signs the enclave input; the unchanged completion path co-signs.
	sh := mustHexBytes(resp.ToSign[0].Sighash)
	var sh32 [32]byte
	copy(sh32[:], sh)
	sig, err := elements.SignSchnorr(f.escrowKy, sh32)
	if err != nil {
		t.Fatal(err)
	}
	code, body = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 200 {
		t.Fatalf("burn complete failed: %d %s", code, body)
	}
	if !strings.Contains(body, f.node.broadcast) {
		t.Fatalf("expected broadcast txid, got %s", body)
	}
	// Consume-once: a replay is refused, so a burn can never double-spend.
	code, _ = callComplete(t, f.s, resp.ID, map[string]any{"sigs": map[string]string{"0": hex.EncodeToString(sig)}})
	if code != 404 {
		t.Fatalf("replay of a consumed burn should 404, got %d", code)
	}
	// The transparency log records it as a burn of 400 atoms.
	if !logHasBurn(t, f.st, 400) {
		t.Fatal("expected a burn log entry of 400 atoms")
	}
}

// TestOA5_NonBurnableRefused proves a burn of an asset without BurnAllowed is
// refused both at the endpoint and by the re-derived policy check.
func TestOA5_NonBurnableRefused(t *testing.T) {
	f := newOA4Fixture(t) // f.asset has BurnAllowed=false

	code, _, body := callBurn(t, f.s, map[string]any{
		"asset": f.asset.ID, "holder_aid": f.escrow.AID, "atoms": 100,
	})
	if code != 403 {
		t.Fatalf("expected 403 for a non-burnable asset, got %d: %s", code, body)
	}
	if !strings.Contains(body, "burns are not permitted") {
		t.Fatalf("expected a burn-not-permitted refusal, got %s", body)
	}

	// checkTransfer independently refuses a 0x6a output for a non-burnable asset.
	tx := &elements.Tx{Version: 2}
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(100),
		Nonce: elements.NullNonce(), ScriptPubKey: []byte{0x6a},
	})
	if err := f.s.checkTransfer(tx, f.asset, f.escrow, map[string]uint64{}); err == nil {
		t.Fatal("checkTransfer must refuse a burn output for a non-burnable asset")
	}
}

// TestOA5_SupplyIsChainDerived proves circulating supply is exactly the holders
// sum read from the chain, so a spent (burned) coin lowers it with no counter.
func TestOA5_SupplyIsChainDerived(t *testing.T) {
	f := newOA4Fixture(t)
	escrowTree, _ := f.s.treeFor(f.escrow, f.asset)
	escrowSpk := hex.EncodeToString(escrowTree.ScriptPubKey())

	// Before: the holder's 1000-atom coin is the entire supply.
	code, out := callSupply(t, f.s, f.asset.ID)
	if code != 200 {
		t.Fatalf("supply read failed: %d", code)
	}
	if got := uint64(out["circulating_atoms"].(float64)); got != 1000 {
		t.Fatalf("expected circulating 1000, got %d", got)
	}

	// After a burn spends that coin (600 change survives), the scan reflects 600
	// and supply drops accordingly, purely chain-derived.
	f.node.scan[escrowSpk] = []rpc.ScanUnspent{{
		TxID: strings.Repeat("99", 32), Vout: 0, Asset: f.asset.ID,
		Amount: 600.0 / 1e8, ScriptPubKey: escrowSpk, Height: 2,
	}}
	code, out = callSupply(t, f.s, f.asset.ID)
	if got := uint64(out["circulating_atoms"].(float64)); got != 600 {
		t.Fatalf("expected circulating 600 after the burn, got %d", got)
	}
}

func logHasBurn(t *testing.T, st *store.Store, atoms uint64) bool {
	t.Helper()
	data, err := readLog(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range data {
		if e.Action == "burn" {
			var d struct {
				Atoms uint64 `json:"atoms"`
			}
			_ = json.Unmarshal(e.Data, &d)
			if d.Atoms == atoms {
				return true
			}
		}
	}
	return false
}

func readLog(st *store.Store) ([]store.LogEntry, error) {
	f, err := os.ReadFile(st.LogPath())
	if err != nil {
		return nil, err
	}
	var out []store.LogEntry
	for _, line := range strings.Split(strings.TrimSpace(string(f)), "\n") {
		if line == "" {
			continue
		}
		var e store.LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// --- OA-6: reissuance --------------------------------------------------------

// TestOA6_BuildReissuanceTx_Structure proves the hand-built reissuance is a
// reissuance (not a new issuance) that lands new units in the target enclave
// while keeping the reissuance token blinded.
func TestOA6_BuildReissuanceTx_Structure(t *testing.T) {
	var abf [32]byte
	for i := range abf {
		abf[i] = byte(i + 1) // non-zero: a blinded token
	}
	var entropy [32]byte
	for i := range entropy {
		entropy[i] = byte(0x40 + i)
	}
	enclaveSpk := mustHexBytes("5120" + strings.Repeat("ab", 32))
	tokenNonce := mustHexBytes("02" + strings.Repeat("cd", 32)) // a blinding pubkey
	p := reissueParams{
		assetDisplay:    elements.MustHex32(oa4USDX),
		entropyInternal: entropy,
		precision:       8,
		tokenTxid:       strings.Repeat("11", 32), tokenVout: 1,
		tokenAbf: abf, tokenAtoms: 1_0000_0000,
		tokenChangeNonce: tokenNonce, tokenChangeSpk: mustHexBytes("0014" + strings.Repeat("cc", 20)),
		reissueAtoms: 500000, enclaveSpk: enclaveSpk,
		feeTxid: strings.Repeat("22", 32), feeVout: 0,
		feeChangeSats: 90000, feeChangeNonce: mustHexBytes("02" + strings.Repeat("ee", 32)),
		feeChangeSpk:    mustHexBytes("0014" + strings.Repeat("ff", 20)),
		feeAssetDisplay: elements.MustHex32(oa4FeeID), feeSats: 100,
	}
	tx := buildReissuanceTx(p)

	// The token input carries the reissuance issuance: a non-zero nonce marks it
	// as a reissuance, not a phantom new issuance.
	iss := tx.In[0].Issuance
	if iss == nil {
		t.Fatal("token input has no issuance")
	}
	if iss.Nonce == [32]byte{} {
		t.Fatal("reissuance nonce is zero: this would be read as a NEW issuance (phantom tx)")
	}
	if iss.Nonce != abf {
		t.Fatalf("reissuance nonce != token asset blinder")
	}
	if iss.Entropy != entropy {
		t.Fatalf("reissuance entropy mismatch")
	}
	if amt, ok := elements.ExplicitValueAmount(iss.Amount); !ok || amt != 500000 {
		t.Fatalf("reissuance amount = %d ok=%v, want 500000", amt, ok)
	}
	if len(iss.InflationKeys) != 1 || iss.InflationKeys[0] != 0 {
		t.Fatalf("reissuance must mint no new tokens (null inflation keys), got %x", iss.InflationKeys)
	}

	// The minted units land in the target enclave, explicit.
	mint := tx.Out[0]
	if hex.EncodeToString(mint.ScriptPubKey) != hex.EncodeToString(enclaveSpk) {
		t.Fatal("minted output does not pay the target enclave")
	}
	if amt, _ := elements.ExplicitValueAmount(mint.Value); amt != 500000 {
		t.Fatalf("minted amount = %d, want 500000", amt)
	}
	if hex.EncodeToString(mint.Asset) != hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(oa4USDX))) {
		t.Fatal("minted output is not the reissued asset")
	}

	// The reissuance token is re-output to a blinded destination (nonce present),
	// so it stays blinded across the operation.
	tokenOut := tx.Out[1]
	if len(tokenOut.Nonce) < 2 || tokenOut.Nonce[0] == 0 {
		t.Fatalf("reissuance token output must carry a blinding nonce (stay blinded), got %x", tokenOut.Nonce)
	}
	if amt, _ := elements.ExplicitValueAmount(tokenOut.Value); amt != 1_0000_0000 {
		t.Fatalf("token output amount = %d, want the full token", amt)
	}

	// The reissuance serializes and round-trips through the codec.
	back, err := elements.DeserializeTx(tx.Serialize())
	if err != nil {
		t.Fatalf("reissuance does not round-trip: %v", err)
	}
	if back.In[0].Issuance == nil || back.In[0].Issuance.Nonce != abf {
		t.Fatal("issuance lost across serialize round-trip")
	}
}

// TestOA6_LegacyAssetRefused proves an asset issued before OA-6 (no recorded
// entropy/token) cannot be reissued, so existing assets are unaffected.
func TestOA6_LegacyAssetRefused(t *testing.T) {
	f := newOA4Fixture(t) // oa7Asset records no Entropy/Token
	code, body := callReissue(t, f.s, map[string]any{
		"asset": f.asset.ID, "target_aid": f.investor.AID, "atoms": 1000, "request_id": "r1",
	})
	if code != 501 {
		t.Fatalf("expected 501 for a legacy asset, got %d: %s", code, body)
	}
}

// TestOA6_Idempotent proves a retry with the same request_id returns the same
// txid without minting again.
func TestOA6_Idempotent(t *testing.T) {
	f := newOA4Fixture(t)
	if err := f.st.Update(func(s *store.State) error {
		s.Assets[f.asset.ID].Entropy = strings.Repeat("33", 32)
		s.Assets[f.asset.ID].Token = strings.Repeat("44", 32)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Pre-record a completed reissue for this key: the handler must short-circuit
	// to it before touching the wallet.
	if err := f.st.MarkReissue("req-xyz", "deadbeeftxid"); err != nil {
		t.Fatal(err)
	}
	code, body := callReissue(t, f.s, map[string]any{
		"asset": f.asset.ID, "target_aid": f.investor.AID, "atoms": 1000, "request_id": "req-xyz",
	})
	if code != 200 {
		t.Fatalf("idempotent reissue failed: %d %s", code, body)
	}
	if !strings.Contains(body, "deadbeeftxid") || !strings.Contains(body, "idempotent") {
		t.Fatalf("expected the recorded txid returned idempotently, got %s", body)
	}
}

// TestOA6_CrashWindowRetryDoesNotDoubleMint is the supply-safety regression for
// the broadcast-then-crash window. A DR mint regenerates its own token input, so
// unlike a burn or transfer it has no UTXO-exhaustion backstop: if a prior attempt
// reserved + broadcast the reissuance but died before MarkReissue, a naive retry
// (GetReissue misses, the re-blinded token is found) would build and broadcast a
// SECOND distinct mint, inflating supply. The pre-broadcast reservation must make
// the retry rebroadcast the IDENTICAL reserved tx and return the reserved txid,
// never a freshly built one.
func TestOA6_CrashWindowRetryDoesNotDoubleMint(t *testing.T) {
	f := newOA4Fixture(t)
	if err := f.st.Update(func(s *store.State) error {
		s.Assets[f.asset.ID].Entropy = strings.Repeat("33", 32)
		s.Assets[f.asset.ID].Token = strings.Repeat("44", 32)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate a crashed prior attempt: the request_id was RESERVED with a signed tx
	// and its fixed txid (broadcast happened), but MarkReissue was lost. The reserved
	// txid is deliberately distinct from f.node.broadcast (what a fresh build would
	// return), so if the handler built a new mint the assertion below would catch it.
	const reservedTxid = "aa11bb22cc33reservedreissuetxid"
	if err := f.st.ReserveReissue("req-crash", "00", reservedTxid); err != nil {
		t.Fatal(err)
	}

	code, body := callReissue(t, f.s, map[string]any{
		"asset": f.asset.ID, "target_aid": f.investor.AID, "atoms": 1000, "request_id": "req-crash",
	})
	if code != 200 {
		t.Fatalf("crash-window retry failed: %d %s", code, body)
	}
	if !strings.Contains(body, reservedTxid) || !strings.Contains(body, "idempotent") {
		t.Fatalf("retry must return the RESERVED txid idempotently (no second mint), got %s", body)
	}
	if strings.Contains(body, f.node.broadcast) && f.node.broadcast != reservedTxid {
		t.Fatalf("retry returned a freshly built mint txid %q, not the reserved one: %s", f.node.broadcast, body)
	}
	// The mint is now durably recorded and the reservation cleared.
	if txid, ok := f.st.GetReissue("req-crash"); !ok || txid != reservedTxid {
		t.Fatalf("MarkReissue not completed from the reservation: got %q ok=%v", txid, ok)
	}
	if _, ok := f.st.GetPendingReissue("req-crash"); ok {
		t.Fatal("pending reservation should be cleared after the mint is recorded")
	}
}

// TestOA6_ReissueRaisesSupplyInEnclave proves chain-derived supply reflects new
// units landed in the target enclave (the observable effect of a DR mint).
func TestOA6_ReissueRaisesSupplyInEnclave(t *testing.T) {
	f := newOA4Fixture(t)
	investorTree, _ := f.s.treeFor(f.investor, f.asset)
	investorSpk := hex.EncodeToString(investorTree.ScriptPubKey())

	code, out := callSupply(t, f.s, f.asset.ID)
	if code != 200 {
		t.Fatalf("supply read failed: %d", code)
	}
	before := uint64(out["circulating_atoms"].(float64)) // 1000 (escrow only)

	// A DR mint lands 500000 units in the investor enclave; the scan now reports
	// them and the chain-derived supply rises by exactly that.
	f.node.scan[investorSpk] = []rpc.ScanUnspent{{
		TxID: strings.Repeat("77", 32), Vout: 0, Asset: f.asset.ID,
		Amount: 500000.0 / 1e8, ScriptPubKey: investorSpk, Height: 3,
	}}
	_, out = callSupply(t, f.s, f.asset.ID)
	after := uint64(out["circulating_atoms"].(float64))
	if after != before+500000 {
		t.Fatalf("expected supply to rise by 500000 (from %d), got %d", before, after)
	}
}

func callReissue(t *testing.T, s *Server, body map[string]any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/issuer/reissue", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	s.handleReissue(rec, req)
	return rec.Code, rec.Body.String()
}
