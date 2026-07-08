package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/fastmerkle"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// handleIssue mints a new restricted asset directly into the initial
// holder's enclave, exactly like the M0 proof: the transaction is built
// around the locally derived asset ids, so consensus acceptance re-validates
// the derivation every time.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string      `json:"name"`
		Ticker      string      `json:"ticker"`
		Precision   int         `json:"precision"`
		Atoms       uint64      `json:"atoms"`
		HolderAID   string      `json:"holder_aid"`
		IssuerAID   string      `json:"issuer_aid"`
		Clawback     *bool       `json:"clawback,omitempty"`
		BurnAllowed  bool        `json:"burn_allowed"`
		Confidential bool        `json:"confidential"`
		Rules        store.Rules `json:"rules"`
		TermsHash    string      `json:"terms_hash,omitempty"`
		Endpoint     string      `json:"endpoint,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Precision == 0 {
		req.Precision = 8
	}
	clawback := true
	if req.Clawback != nil {
		clawback = *req.Clawback
	}
	if !s.cfg.DemoIssuer {
		httpErr(w, 501, "hosted issuance requires -demoissuer; production issuance tooling keeps issuer keys offline")
		return
	}

	var holder, issuer *store.User
	s.st.View(func(st *store.State) {
		if u, ok := st.Users[req.HolderAID]; ok {
			cp := *u
			holder = &cp
		}
		if u, ok := st.Users[req.IssuerAID]; ok {
			cp := *u
			issuer = &cp
		}
	})
	if holder == nil || issuer == nil {
		httpErr(w, 404, "holder_aid and issuer_aid must be registered users")
		return
	}

	// Policy key via the signer backend (single key on testnet, FROST group
	// key in production). The pubkey is needed now to build the contract; the
	// key is bound to its asset id below once derived.
	policyX, policyRef, err := s.signer.GeneratePolicyKey()
	if err != nil {
		httpErr(w, 500, "policy key: %v", err)
		return
	}
	// Issuer key stays a local key (the issuer's own; production keeps it
	// offline). Used for the clawback leaf and to authorize issuance.
	issuerPriv := make([]byte, 32)
	rand.Read(issuerPriv)
	issuerX := elements.XOnlyFromPriv(issuerPriv)

	// Contract (canonical: sorted keys, no whitespace; see spec/contract-v1.md).
	contract := map[string]any{
		"name":          req.Name,
		"ticker":        req.Ticker,
		"precision":     req.Precision,
		"version":       0,
		"issuer_pubkey": hex.EncodeToString(issuerX[:]),
		"openamp": map[string]any{
			"version":       1,
			"type":          "restricted",
			"policy_pubkey": hex.EncodeToString(policyX[:]),
			"clawback":      clawback,
			"burn_allowed":  req.BurnAllowed,
			"confidential":  req.Confidential,
		},
	}
	if req.TermsHash != "" {
		contract["openamp"].(map[string]any)["terms_hash"] = req.TermsHash
	}
	if req.Endpoint != "" {
		contract["openamp"].(map[string]any)["policy_endpoints"] = []string{req.Endpoint}
	}
	canonical, err := canonicalJSON(contract)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	digest := sha256.Sum256(canonical)

	// Funding input for the issuance.
	feeUtxos, err := s.wallet.ListUnspent(1, s.cfg.FeeAsset)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	var funding *rpcUnspentLite
	for _, u := range feeUtxos {
		if u.Spendable && sats(u.Amount) > s.cfg.FeeSats*3 && s.utxoUnspent(u.TxID, u.Vout) {
			funding = &rpcUnspentLite{u.TxID, u.Vout, sats(u.Amount)}
			break
		}
	}
	if funding == nil {
		httpErr(w, 503, "no funding utxo")
		return
	}
	entropy, assetID, tokenID := fastmerkle.DeriveIssuanceIDs(internalHash(funding.txid), funding.vout, digest)
	assetDisplay := displayHash(assetID)

	// Provisional asset record so enclave trees can be derived.
	asset := &store.Asset{
		ID: assetDisplay, Ticker: req.Ticker, Name: req.Name, Precision: req.Precision,
		Contract: canonical, ContractHash: displayHash(digest),
		PolicyPub: hex.EncodeToString(policyX[:]), IssuerPub: hex.EncodeToString(issuerX[:]),
		IssuerAID: req.IssuerAID, Clawback: clawback, BurnAllowed: req.BurnAllowed,
		Confidential: req.Confidential, Rules: req.Rules,
	}
	holderTree, err := s.treeFor(holder, asset)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}

	// Token output destination: the server wallet (kept for reissuance; must
	// be re-blinded before any reissue, see the node repo's issuance notes).
	tokenAddr, err := s.wallet.GetNewAddress()
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	tokenInfo, err := s.wallet.GetAddressInfo(tokenAddr)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	changeAddr, err := s.wallet.GetNewAddress()
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	changeInfo, err := s.wallet.GetAddressInfo(changeAddr)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}

	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	// Output nonces: null for transparent assets; blinding public keys for a
	// confidential asset (the enclave output blinds to the holder's key, the
	// wallet token/change outputs blind to the wallet's own keys, giving the
	// >=2 confidential outputs a blinded transaction needs).
	holderNonce := elements.NullNonce()
	tokenNonce := elements.NullNonce()
	changeNonce := elements.NullNonce()
	if req.Confidential {
		holderX := elements.MustHex32(holder.Pubkeys[0])
		hn, err := s.enclaveConfNonce(assetDisplay, holderX, hex.EncodeToString(holderTree.ScriptPubKey()))
		if err != nil {
			httpErr(w, 500, "confidential enclave: %v", err)
			return
		}
		holderNonce = hn
		if tokenInfo.ConfidentialKey == "" || changeInfo.ConfidentialKey == "" {
			httpErr(w, 500, "wallet is not confidential (need -blindedaddresses=1 for confidential issuance)")
			return
		}
		tokenNonce = mustHexBytes(tokenInfo.ConfidentialKey)
		changeNonce = mustHexBytes(changeInfo.ConfidentialKey)
	}
	tx := &elements.Tx{Version: 2}
	tx.In = append(tx.In, &elements.TxIn{
		Prevout: elements.OutPoint{Hash: internalHash(funding.txid), N: funding.vout},
		Issuance: &elements.AssetIssuance{
			Entropy:       digest, // contract hash, in the issuance's entropy field
			Amount:        elements.ExplicitValue(req.Atoms),
			InflationKeys: elements.ExplicitValue(1_0000_0000),
			Denomination:  uint64(req.Precision),
		},
	})
	tx.Out = append(tx.Out,
		&elements.TxOut{Asset: elements.ExplicitAssetInternal(assetID), Value: elements.ExplicitValue(req.Atoms),
			Nonce: holderNonce, ScriptPubKey: holderTree.ScriptPubKey()},
		&elements.TxOut{Asset: elements.ExplicitAssetInternal(tokenID), Value: elements.ExplicitValue(1_0000_0000),
			Nonce: tokenNonce, ScriptPubKey: mustHexBytes(tokenInfo.ScriptPubKey)},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(funding.sats - s.cfg.FeeSats),
			Nonce: changeNonce, ScriptPubKey: mustHexBytes(changeInfo.ScriptPubKey)},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	if req.Confidential {
		blinded, err := s.blindTx(tx)
		if err != nil {
			httpErr(w, 500, "blind issuance: %v", err)
			return
		}
		tx = blinded
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(tx.Serialize()))
	if err != nil {
		httpErr(w, 502, "sign: %v", err)
		return
	}
	if !signed.Complete {
		log.Printf("issuance signing incomplete: errors=%+v", signed.Errors)
		httpErr(w, 502, "issuance signing incomplete: %+v", signed.Errors)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		log.Printf("issuance broadcast failed: %v\nraw: %s", err, signed.Hex)
		httpErr(w, 502, "broadcast: %v", err)
		return
	}
	asset.IssueTxid = txid

	if err := s.signer.Adopt(policyRef, assetDisplay); err != nil {
		httpErr(w, 500, "bind policy key: %v", err)
		return
	}
	if err := s.st.SaveKey("issuer:"+assetDisplay, hex.EncodeToString(issuerPriv)); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if err := s.st.Update(func(st *store.State) error {
		st.Assets[assetDisplay] = asset
		return nil
	}); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	s.st.AppendLog("issue", map[string]any{
		"asset": assetDisplay, "txid": txid, "atoms": req.Atoms,
		"holder": req.HolderAID, "contract_hash": asset.ContractHash,
	})
	httpJSON(w, map[string]any{
		"asset": assetDisplay, "token": displayHash(tokenID), "entropy": displayHash(entropy),
		"txid": txid, "contract": json.RawMessage(canonical), "contract_hash": asset.ContractHash,
	})
}

type rpcUnspentLite struct {
	txid string
	vout uint32
	sats uint64
}

// canonicalJSON: sorted keys, no insignificant whitespace (Go's Marshal
// sorts map keys and emits compact JSON already).
func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// handleClawback seizes a holder's enclave UTXOs into the issuer's enclave
// through the disclosed L_claw leaf. The transparency-log entry is written
// BEFORE the transaction is signed.
func (s *Server) handleClawback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset     string `json:"asset"`
		HolderAID string `json:"holder_aid"`
		Reason    string `json:"reason"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Reason == "" {
		httpErr(w, 400, "a reason is required; it becomes part of the public transparency log")
		return
	}
	holderTree, _, asset, err := s.enclaveFor(req.HolderAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	if !asset.Clawback {
		httpErr(w, 403, "this asset was issued without a clawback leaf; its terms cannot be retrofitted")
		return
	}
	issuerTree, _, _, err := s.enclaveFor(asset.IssuerAID, req.Asset)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	keys, err := s.st.LoadKeys()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	issuerPriv, ok2 := keys["issuer:"+asset.ID]
	if _, hasPolicy := s.signer.PolicyPubKey(asset.ID); !hasPolicy || !ok2 {
		httpErr(w, 501, "clawback requires both the policy and issuer keys on this server (demo mode)")
		return
	}

	utxos, err := s.enclaveUTXOs(holderTree, asset.ID)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	if len(utxos) == 0 {
		httpErr(w, 409, "holder has no confirmed enclave balance")
		return
	}
	var total uint64
	for _, u := range utxos {
		total += u.atoms
	}

	// Fee funding.
	feeUtxos, err := s.wallet.ListUnspent(1, s.cfg.FeeAsset)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	var feeIn *rpcUnspentLite
	for _, u := range feeUtxos {
		if u.Spendable && sats(u.Amount) > s.cfg.FeeSats*2 {
			feeIn = &rpcUnspentLite{u.TxID, u.Vout, sats(u.Amount)}
			break
		}
	}
	if feeIn == nil {
		httpErr(w, 503, "no fee funds")
		return
	}
	changeAddr, _ := s.wallet.GetNewAddress()
	changeInfo, err := s.wallet.GetAddressInfo(changeAddr)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}

	assetID := elements.MustHex32(asset.ID)
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	tx := &elements.Tx{Version: 2}
	for _, u := range utxos {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(u.txid), N: u.vout}})
	}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feeIn.txid), N: feeIn.vout}})
	tx.Out = append(tx.Out,
		&elements.TxOut{Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(total),
			Nonce: elements.NullNonce(), ScriptPubKey: issuerTree.ScriptPubKey()},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.sats - s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(changeInfo.ScriptPubKey)},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	tx.NormalizeWitness()

	// Public notice precedes the signature.
	s.st.AppendLog("clawback", map[string]any{
		"asset": asset.ID, "holder": req.HolderAID, "atoms": total, "reason": req.Reason, "txid": tx.TxID(),
	})

	spent, err := s.spentOutputs(tx)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	leaf := holderTree.Leaves["claw"].Script
	control, _ := holderTree.ControlBlock("claw")
	for i := range utxos {
		sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, i, leaf)
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		policySig, err := s.signer.SignPolicy(asset.ID, sh)
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		issuerSig, err := elements.SignSchnorr(mustHexBytes(issuerPriv), sh)
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		tx.InWit[i].ScriptWitness = [][]byte{policySig, issuerSig, leaf, control}
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(tx.Serialize()))
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		httpErr(w, 502, "broadcast: %v", err)
		return
	}
	httpJSON(w, map[string]any{"txid": txid, "atoms": total})
}

// handleHolders is the ownership report: confirmed enclave balances per AID.
func (s *Server) handleHolders(w http.ResponseWriter, r *http.Request) {
	assetID := r.URL.Query().Get("asset")
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[assetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset")
		return
	}
	balances, err := s.holderBalances(asset)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	var total uint64
	for _, a := range balances {
		total += a
	}
	var height int64
	s.st.View(func(st *store.State) { height = st.Height })
	httpJSON(w, map[string]any{"asset": asset.ID, "height": height, "holders": balances, "total_atoms": total})
}

// handleAnchor commits the transparency-log head on-chain in an OP_RETURN.
func (s *Server) handleAnchor(w http.ResponseWriter, r *http.Request) {
	var head string
	var seq uint64
	s.st.View(func(st *store.State) { head, seq = st.LogHead, st.LogSeq })
	if head == "" {
		httpErr(w, 409, "empty log")
		return
	}
	payload := fmt.Sprintf("OPENAMP:%d:%s", seq, head)
	var rawHex string
	if err := s.wallet.Call(&rawHex, "createrawtransaction",
		[]any{}, []any{map[string]any{"data": hex.EncodeToString([]byte(payload))}}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	var funded struct {
		Hex string `json:"hex"`
	}
	if err := s.wallet.Call(&funded, "fundrawtransaction", rawHex); err != nil {
		httpErr(w, 502, "fund: %v", err)
		return
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(funded.Hex)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	s.st.AppendLog("anchor", map[string]any{"txid": txid, "anchored_seq": seq, "anchored_head": head})
	httpJSON(w, map[string]any{"txid": txid, "seq": seq, "head": head})
}
