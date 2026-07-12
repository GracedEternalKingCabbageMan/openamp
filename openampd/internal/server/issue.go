package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/fastmerkle"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// handleIssue mints a new restricted asset directly into the initial
// holder's enclave, exactly like the M0 proof: the transaction is built
// around the locally derived asset ids, so consensus acceptance re-validates
// the derivation every time.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
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
	// Issuer key: by default a server-generated local key (the legacy path,
	// production keeps it offline). M9: when the request carries an external
	// issuer_pubkey (the entity's own x-only browser key) the server does NOT
	// generate a key; the external key becomes the enclave issuer half so the
	// L_claw leaf is (policy, EXTERNAL issuer) and the server never holds the
	// issuer private key for this asset. A malformed external key is refused.
	var issuerPriv []byte
	var issuerX [32]byte
	issuerExternal := req.IssuerPubkey != ""
	if issuerExternal {
		xb, err := hex.DecodeString(req.IssuerPubkey)
		if err != nil || len(xb) != 32 {
			httpErr(w, 400, "issuer_pubkey must be 32-byte x-only hex")
			return
		}
		if _, err := schnorr.ParsePubKey(xb); err != nil {
			httpErr(w, 400, "issuer_pubkey is not a valid x-only public key: %v", err)
			return
		}
		copy(issuerX[:], xb)
	} else {
		issuerPriv = make([]byte, 32)
		rand.Read(issuerPriv)
		issuerX = elements.XOnlyFromPriv(issuerPriv)
	}

	// Contract (canonical: sorted keys, no whitespace; see spec/contract-v1.md).
	contract := req.buildContract(hex.EncodeToString(issuerX[:]), hex.EncodeToString(policyX[:]), clawback)
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
		IssuerExternal: issuerExternal,
		IssuerAID: req.IssuerAID, Clawback: clawback, BurnAllowed: req.BurnAllowed,
		Confidential: req.Confidential, Rules: req.Rules,
		// Recorded for a later DR reissuance (OA-6): the final entropy re-derives
		// the asset and the token id locates the reissuance token in the wallet.
		Entropy: displayHash(entropy), Token: displayHash(tokenID),
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
	// Output nonces + destinations. For a transparent asset (the default) the
	// token and fee-change outputs go to ordinary wallet addresses with null
	// nonces, byte-identically to before OA-8. For a confidential asset the
	// enclave output blinds to the holder's key and the token/fee-change outputs
	// go to per-call blinded (blech32) wallet addresses, which forces blinding
	// for THIS transaction even on a wallet running -blindedaddresses=0 (node000's
	// flag is never touched) and gives the >=2 confidential outputs a blinded
	// transaction needs.
	holderNonce := elements.NullNonce()
	tokenNonce := elements.NullNonce()
	changeNonce := elements.NullNonce()
	tokenSpk := mustHexBytes(tokenInfo.ScriptPubKey)
	changeSpk := mustHexBytes(changeInfo.ScriptPubKey)
	if req.Confidential {
		holderX := elements.MustHex32(holder.Pubkeys[0])
		hn, err := s.enclaveConfNonce(assetDisplay, holderX, hex.EncodeToString(holderTree.ScriptPubKey()))
		if err != nil {
			httpErr(w, 500, "confidential enclave: %v", err)
			return
		}
		holderNonce = hn
		// OA-8: opt-in confidential per call, no node flag. Request a fresh
		// blech32 address for each of the token and fee-change outputs; the
		// wallet returns a blinding key for it even under -blindedaddresses=0.
		tn, tspk, err := s.blindedWalletOutput()
		if err != nil {
			httpErr(w, 500, "confidential token output: %v", err)
			return
		}
		cn, cspk, err := s.blindedWalletOutput()
		if err != nil {
			httpErr(w, 500, "confidential fee-change output: %v", err)
			return
		}
		tokenNonce, tokenSpk = tn, tspk
		changeNonce, changeSpk = cn, cspk
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
			Nonce: tokenNonce, ScriptPubKey: tokenSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(funding.sats - s.cfg.FeeSats),
			Nonce: changeNonce, ScriptPubKey: changeSpk},
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
	// Only a server-generated issuer key is stored. For an external issuer key the
	// server holds nothing (the entity signs clawbacks in its browser), so there is
	// no issuer key to persist and clawback runs two-phase.
	if !issuerExternal {
		if err := s.st.SaveKey("issuer:"+assetDisplay, hex.EncodeToString(issuerPriv)); err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
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
	resp := map[string]any{
		"asset": assetDisplay, "token": displayHash(tokenID), "entropy": displayHash(entropy),
		"txid": txid, "contract": json.RawMessage(canonical), "contract_hash": asset.ContractHash,
	}
	// Only surface issuer_external when true, so a legacy (server-generated key)
	// issuance response stays byte-identical to pre-M9.
	if issuerExternal {
		resp["issuer_external"] = true
	}
	httpJSON(w, resp)
}

// issueRequest is the POST /v1/issuer/assets body. The entity_* / operator_*
// fields (OA-1) are optional: when entity_domain is absent the contract is
// byte-identical to the pre-OA-1 shape (so existing assets like BONDX are
// unaffected); when present they add the registry-required entity block and an
// operator-identity block, both committed by contract_hash.
type issueRequest struct {
	Name         string      `json:"name"`
	Ticker       string      `json:"ticker"`
	Precision    int         `json:"precision"`
	Atoms        uint64      `json:"atoms"`
	HolderAID    string      `json:"holder_aid"`
	IssuerAID    string      `json:"issuer_aid"`
	Clawback     *bool       `json:"clawback,omitempty"`
	BurnAllowed  bool        `json:"burn_allowed"`
	Confidential bool        `json:"confidential"`
	Rules        store.Rules `json:"rules"`
	TermsHash    string      `json:"terms_hash,omitempty"`
	Endpoint     string      `json:"endpoint,omitempty"`

	// IssuerPubkey (M9) is an OPTIONAL external issuer key (x-only hex = the
	// entity's own browser key). When present the server does NOT generate the
	// issuer key: the external key becomes the enclave issuer half, so the 2-of-2
	// and the L_claw leaf are (policy, EXTERNAL issuer) and clawback runs
	// two-phase (the issuer signs the sweep externally). When absent the server
	// generates the issuer key exactly as before M9 (the legacy single-call
	// clawback), keeping a no-key issuance byte-identical.
	IssuerPubkey string      `json:"issuer_pubkey,omitempty"`

	// OA-1: optional issuer/operator identity for asset-registry publication.
	EntityDomain         string `json:"entity_domain,omitempty"`
	EntityName           string `json:"entity_name,omitempty"`
	OperatorName         string `json:"operator_name,omitempty"`
	OperatorRegistration string `json:"operator_registration,omitempty"`
}

// buildContract assembles the canonical issuance contract map. Go's json.Marshal
// sorts map keys at every level, so the result serializes deterministically and
// contract_hash commits to the whole document. When EntityDomain is empty no
// entity/operator keys are added, keeping the output byte-identical to pre-OA-1.
func (req *issueRequest) buildContract(issuerPubkey, policyPubkey string, clawback bool) map[string]any {
	contract := map[string]any{
		"name":          req.Name,
		"ticker":        req.Ticker,
		"precision":     req.Precision,
		"version":       0,
		"issuer_pubkey": issuerPubkey,
		"openamp": map[string]any{
			"version":       1,
			"type":          "restricted",
			"policy_pubkey": policyPubkey,
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
	if req.EntityDomain != "" {
		entity := map[string]any{"domain": req.EntityDomain}
		if req.EntityName != "" {
			entity["issuer"] = req.EntityName
		}
		contract["entity"] = entity
		operator := map[string]any{}
		if req.OperatorName != "" {
			operator["name"] = req.OperatorName
		}
		if req.OperatorRegistration != "" {
			operator["registration"] = req.OperatorRegistration
		}
		if len(operator) > 0 {
			contract["operator"] = operator
		}
	}
	return contract
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
//
// Two paths (M9), selected from the asset:
//   - LEGACY (server-held issuer key, Asset.IssuerExternal false): a single call
//     signs both the policy and issuer parts and broadcasts, exactly as before M9.
//   - EXTERNAL (Asset.IssuerExternal true): the server holds only the policy key,
//     so this call BUILDS the L_claw sweep, logs the reason and returns the leaf
//     sighashes for the issuer to sign in its browser; POST
//     /v1/issuer/clawback/{id}/complete then adds the issuer signatures and
//     broadcasts. The issuer private key never touches the server.
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
	// Key check per path. Legacy needs BOTH keys server-side; external needs only
	// the policy key (the issuer signs externally at /complete).
	var issuerPriv string
	if asset.IssuerExternal {
		if _, hasPolicy := s.signer.PolicyPubKey(asset.ID); !hasPolicy {
			httpErr(w, 501, "clawback requires the policy key on this server")
			return
		}
	} else {
		keys, err := s.st.LoadKeys()
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		var ok2 bool
		issuerPriv, ok2 = keys["issuer:"+asset.ID]
		if _, hasPolicy := s.signer.PolicyPubKey(asset.ID); !hasPolicy || !ok2 {
			httpErr(w, 501, "clawback requires both the policy and issuer keys on this server (demo mode)")
			return
		}
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

	// L_claw sighashes for every enclave input (one per holder UTXO).
	sighashes := make([][32]byte, len(utxos))
	for i := range utxos {
		sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, i, leaf)
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		sighashes[i] = sh
	}

	if asset.IssuerExternal {
		// BUILD phase: persist the pending sweep and return the sighashes for the
		// issuer to sign externally. Nothing is signed or broadcast here; the reason
		// is already in the public log above.
		id := newID()
		shHex := make([]string, len(sighashes))
		enclave := make([]int, len(sighashes))
		type toSign struct {
			Input   int    `json:"input"`
			Sighash string `json:"sighash"`
			Pubkey  string `json:"pubkey"`
		}
		signing := make([]toSign, len(sighashes))
		for i := range sighashes {
			shHex[i] = hex.EncodeToString(sighashes[i][:])
			enclave[i] = i
			// A REAL taproot script-path spend sighash the issuer signs with its
			// entity key; not a tagged challenge (that oracle guard is unaffected).
			signing[i] = toSign{Input: i, Sighash: shHex[i], Pubkey: asset.IssuerPub}
		}
		s.st.GCPendingClawbacks(pendingTTL)
		txHex := hex.EncodeToString(tx.Serialize())
		if err := s.st.PutPendingClawback(&store.PendingClawback{
			ID: id, TxHex: txHex, AssetID: asset.ID, HolderAID: req.HolderAID,
			Atoms: total, Enclave: enclave, Sighashes: shHex, IssuerPub: asset.IssuerPub,
			Reason: req.Reason, Created: time.Now(),
		}); err != nil {
			httpErr(w, 500, "persist pending: %v", err)
			return
		}
		httpJSON(w, map[string]any{"id": id, "tx": txHex, "to_sign": signing, "atoms": total})
		return
	}

	// LEGACY: the server holds the issuer key, so it signs both parts and
	// broadcasts in this one call, exactly as before M9.
	for i := range utxos {
		policySig, err := s.signer.SignPolicy(asset.ID, sighashes[i])
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		issuerSig, err := elements.SignSchnorr(mustHexBytes(issuerPriv), sighashes[i])
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

// handleClawbackComplete finishes a two-phase (external-issuer) clawback: it
// accepts the issuer's schnorr signatures over the L_claw leaf sighashes returned
// by the build, adds the policy signature, and broadcasts. Idempotent and
// consume-once: a completed id returns the same txid and never re-drives a fresh
// sweep, so a replay can never double-sweep (the reconciled M7/M8 invariant).
func (s *Server) handleClawbackComplete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		// Sigs maps an L_claw input index (decimal string) to the issuer's 64-byte
		// schnorr signature (hex) over that input's real taproot script-path spend
		// sighash. A genuine spend the issuer authorizes with its entity key,
		// distinct from the tagged challenge/document signers.
		Sigs map[string]string `json:"sigs"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}

	// Idempotent replay: a completed clawback returns its txid, never re-broadcasts.
	if txid, ok := s.st.GetClawback(id); ok {
		httpJSON(w, map[string]any{"txid": txid, "idempotent": true})
		return
	}
	pc, ok := s.st.GetPendingClawback(id)
	if !ok {
		httpErr(w, 404, "unknown or expired clawback")
		return
	}
	holderTree, _, _, err := s.enclaveFor(pc.HolderAID, pc.AssetID)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}

	// Verify the issuer's signatures over the stored L_claw sighashes before doing
	// anything else (the same order as the transfer completion path).
	pk, err := schnorr.ParsePubKey(mustHexBytes(pc.IssuerPub))
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	issuerSigs := make(map[int][]byte, len(pc.Enclave))
	for i, idx := range pc.Enclave {
		sigHex, has := req.Sigs[fmt.Sprintf("%d", idx)]
		if !has {
			httpErr(w, 400, "missing issuer signature for input %d", idx)
			return
		}
		var sh [32]byte
		copy(sh[:], mustHexBytes(pc.Sighashes[i]))
		sigBytes := mustHexBytes(sigHex)
		sig, err := schnorr.ParseSignature(sigBytes)
		if err != nil || !sig.Verify(sh[:], pk) {
			httpErr(w, 400, "invalid issuer signature for input %d", idx)
			return
		}
		issuerSigs[idx] = sigBytes
	}

	tx, err := elements.DeserializeTx(mustHexBytes(pc.TxHex))
	if err != nil {
		httpErr(w, 500, "decode pending clawback: %v", err)
		return
	}
	tx.NormalizeWitness()
	leaf := holderTree.Leaves["claw"].Script
	control, err := holderTree.ControlBlock("claw")
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	for i, idx := range pc.Enclave {
		var sh [32]byte
		copy(sh[:], mustHexBytes(pc.Sighashes[i]))
		policySig, err := s.signer.SignPolicy(pc.AssetID, sh)
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		tx.InWit[idx].ScriptWitness = [][]byte{policySig, issuerSigs[idx], leaf, control}
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
	// Record the txid and consume the pending build (a replay now short-circuits to
	// this txid). A crash between broadcast and this write leaves the pending build,
	// so a retry rebroadcasts the identical tx (same txid, the node dedupes) and
	// records it; reconcile a fully lost write by the log/chain like the M7 clawback.
	if err := s.st.MarkClawback(id, txid); err != nil {
		httpErr(w, 500, "persist clawback: %v", err)
		return
	}
	httpJSON(w, map[string]any{"txid": txid, "atoms": pc.Atoms})
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

// handleSupply reports an asset's circulating supply as a purely chain-derived
// figure: the sum of every registered holder's confirmed enclave balance. It is
// never a stored counter, so a burn (OA-5) that spends enclave units into an
// unspendable output lowers it and a reissuance (OA-6) that lands new units in
// an enclave raises it, both as soon as the change confirms. The reissuance
// token (held in the server wallet, not an enclave) is deliberately excluded.
func (s *Server) handleSupply(w http.ResponseWriter, r *http.Request) {
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
	httpJSON(w, map[string]any{"asset": asset.ID, "circulating_atoms": total, "height": height})
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
