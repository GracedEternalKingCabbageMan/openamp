package server

// Pledges: restricted-asset collateral for a Pignus loan (Tier C).
//
// store/pledge.go says why a restricted asset cannot go into a covenant vault
// and what a pledge costs the lender in exchange. This file is the mechanism:
//
//	POST /v1/issuer/pledges                 lock collateral in place
//	GET  /v1/issuer/pledges                 list them
//	POST /v1/issuer/pledges/{id}/release    debt settled, holder free again
//	POST /v1/issuer/pledges/{id}/seize      default, collateral to the lender
//
// The endpoints are issuer-token gated because every OpenAMP issuer endpoint
// is, but the token is deliberately NOT sufficient on its own for the two that
// move value. A release needs the LENDER's signature -- the lender is the only
// party who can say the debt was settled -- and a seizure needs the lender's
// signature AND either a matured loan or the HOLDER's countersignature. So an
// issuer alone cannot hand a holder's collateral to a friend, and a lender
// alone cannot take collateral from a borrower who is still within their term.
//
// The issuer can still FORCE a release with a written reason, because the
// alternative is collateral locked forever when a lender loses their key, and a
// forced release only ever gives the collateral back to the holder who owns it.
// It is logged loudly. There is deliberately no forced seizure: the direction
// that takes value away from its owner is the direction that must not have a
// unilateral override.
//
// A seizure is an L_claw spend, the same leaf and the same key pair as an
// ordinary clawback, but with two asset outputs instead of one: the pledged
// atoms to the LENDER's enclave and the rest straight back to the holder's.
// Seizing a pledge must not touch the holder's unpledged balance.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// pledgeMessage is what a lender or holder signs to authorise a pledge action.
//
// A plain domain-separated sha256, deliberately not a taproot sighash: nothing
// signed here can ever be replayed as authorisation to spend a coin, and
// nothing signed to spend a coin can ever be replayed as a pledge action.
func pledgeMessage(action, id, extra string) [32]byte {
	return sha256.Sum256([]byte("openamp-pledge|" + action + "|" + id + "|" + extra))
}

// checkPledgeSig verifies one party's authorisation over pledgeMessage.
func (s *Server) checkPledgeSig(aid, sigHex, action, id, extra string) error {
	if sigHex == "" {
		return fmt.Errorf("no signature from %s", aid)
	}
	var pubHex string
	s.st.View(func(st *store.State) {
		if u, ok := st.Users[aid]; ok && len(u.Pubkeys) > 0 {
			pubHex = u.Pubkeys[0]
		}
	})
	if pubHex == "" {
		return fmt.Errorf("%s has no registered pubkey to check a signature against", aid)
	}
	pk, err := schnorr.ParsePubKey(mustHexBytes(pubHex))
	if err != nil {
		return fmt.Errorf("%s has an unparseable pubkey: %w", aid, err)
	}
	raw, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("signature from %s is not hex: %w", aid, err)
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil {
		return fmt.Errorf("signature from %s is malformed: %w", aid, err)
	}
	msg := pledgeMessage(action, id, extra)
	if !sig.Verify(msg[:], pk) {
		return fmt.Errorf("signature from %s does not authorise %q on pledge %s", aid, action, id)
	}
	return nil
}

// --- create ------------------------------------------------------------------

func (s *Server) handlePledgeCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset     string `json:"asset"`
		HolderAID string `json:"holder_aid"`
		LenderAID string `json:"lender_aid"`
		Atoms     uint64 `json:"atoms"`
		DebtAsset string `json:"debt_asset"`
		DebtAtoms uint64 `json:"debt_atoms"`
		Maturity  int64  `json:"maturity_height"`
		Note      string `json:"note"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Atoms == 0 {
		httpErr(w, 400, "a pledge of zero atoms locks nothing")
		return
	}
	if req.HolderAID == req.LenderAID {
		httpErr(w, 400, "holder and lender cannot be the same party")
		return
	}
	if req.Maturity <= 0 {
		httpErr(w, 400, "maturity_height is required; without it a seizure has no date it becomes due")
		return
	}

	// Both parties must have an enclave for this asset -- the holder's is where
	// the collateral already sits, the lender's is the only place a seizure is
	// allowed to deliver it. Refusing here rather than at seizure time means a
	// lender cannot discover on default that they were never able to be paid.
	holderTree, _, asset, err := s.enclaveFor(req.HolderAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	if refuseDampCosign(w, asset) {
		return
	}
	if _, _, _, err := s.enclaveFor(req.LenderAID, req.Asset); err != nil {
		httpErr(w, 404, "lender: %v", err)
		return
	}

	// Without a clawback leaf a pledge would be a trap rather than collateral.
	// The lock would hold -- the transfer check refuses to move pledged atoms --
	// but on default nobody could ever deliver them to the lender, because a
	// transfer out of the holder's enclave needs the holder's own signature and
	// a defaulting borrower has no reason to give it. The collateral would sit
	// frozen forever, useless to both parties. Refuse at the only moment the
	// refusal is cheap.
	if !asset.Clawback {
		httpErr(w, 409, "this asset was issued without a clawback leaf, so a "+
			"defaulted pledge could never be delivered to the lender: the "+
			"collateral would lock permanently instead. Use an asset issued "+
			"with clawback, or a covenant vault on an unrestricted asset")
		return
	}

	var holderFrozen bool
	s.st.View(func(st *store.State) {
		if u, ok := st.Users[req.HolderAID]; ok {
			holderFrozen = u.Frozen
		}
	})
	if holderFrozen {
		httpErr(w, 409, "the holder is frozen; their collateral cannot be delivered on default")
		return
	}

	// Free balance: what the holder actually has on chain, minus what earlier
	// pledges already spoke for. Two lenders must not be told they hold a claim
	// on the same atoms.
	balances, err := s.holderBalances(asset)
	if err != nil {
		httpErr(w, 502, "holder scan: %v", err)
		return
	}
	have := balances[req.HolderAID]
	var already uint64
	s.st.View(func(st *store.State) {
		already = store.PledgedAtoms(st, asset.ID, req.HolderAID)
	})
	free := saturatingSub(have, already)
	if free < req.Atoms {
		httpErr(w, 409, "holder has %d atoms confirmed and %d already pledged, "+
			"so only %d are free; cannot pledge %d",
			have, already, free, req.Atoms)
		return
	}
	_ = holderTree

	height, err := s.node.GetBlockCount()
	if err != nil {
		httpErr(w, 502, "chain height: %v", err)
		return
	}
	if req.Maturity <= height {
		httpErr(w, 400, "maturity_height %d is not in the future (tip is %d)", req.Maturity, height)
		return
	}

	p := &store.Pledge{
		ID: newID(), AssetID: asset.ID, Holder: req.HolderAID, Lender: req.LenderAID,
		Atoms: req.Atoms, State: store.PledgeOpen, Created: height,
		Maturity: req.Maturity, DebtAsset: req.DebtAsset, DebtAtoms: req.DebtAtoms,
		Note: req.Note,
	}
	if err := s.st.Update(func(st *store.State) error {
		if st.Pledges == nil {
			st.Pledges = map[string]*store.Pledge{}
		}
		st.Pledges[p.ID] = p
		return nil
	}); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	s.st.AppendLog("pledge", map[string]any{
		"id": p.ID, "asset": p.AssetID, "holder": p.Holder, "lender": p.Lender,
		"atoms": p.Atoms, "maturity": p.Maturity, "note": p.Note,
	})
	httpJSON(w, map[string]any{
		"pledge": p,
		"release_message": hex.EncodeToString(func() []byte {
			m := pledgeMessage("release", p.ID, "")
			return m[:]
		}()),
		"note": "the lender signs release|<id>|<repaid_txid> to release, and " +
			"seize|<id>|<reason> to seize; both are sha256 over that exact string",
	})
}

// --- list --------------------------------------------------------------------

func (s *Server) handlePledgeList(w http.ResponseWriter, r *http.Request) {
	asset := r.URL.Query().Get("asset")
	holder := r.URL.Query().Get("holder")
	lender := r.URL.Query().Get("lender")
	state := r.URL.Query().Get("state")
	out := []*store.Pledge{}
	s.st.View(func(st *store.State) {
		for _, p := range st.Pledges {
			if asset != "" && p.AssetID != asset {
				continue
			}
			if holder != "" && p.Holder != holder {
				continue
			}
			if lender != "" && p.Lender != lender {
				continue
			}
			if state != "" && string(p.State) != state {
				continue
			}
			cp := *p
			out = append(out, &cp)
		}
	})
	httpJSON(w, map[string]any{"pledges": out})
}

// --- release -----------------------------------------------------------------

func (s *Server) handlePledgeRelease(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		RepaidTxid string `json:"repaid_txid"`
		LenderSig  string `json:"lender_sig"`
		Force      bool   `json:"force"`
		Reason     string `json:"reason"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	var p store.Pledge
	var found bool
	s.st.View(func(st *store.State) {
		if q, ok := st.Pledges[id]; ok {
			p, found = *q, true
		}
	})
	if !found {
		httpErr(w, 404, "unknown pledge")
		return
	}
	if !p.Open() {
		// Idempotent: releasing a released pledge is a no-op, not an error, so a
		// retried request cannot look like a second release.
		if p.State == store.PledgeReleased {
			httpJSON(w, map[string]any{"pledge": &p, "idempotent": true})
			return
		}
		httpErr(w, 409, "pledge is %s", p.State)
		return
	}

	if req.Force {
		if req.Reason == "" {
			httpErr(w, 400, "a forced release needs a reason; it becomes part of the public transparency log")
			return
		}
	} else if err := s.checkPledgeSig(p.Lender, req.LenderSig, "release", id, req.RepaidTxid); err != nil {
		httpErr(w, 403, "%v; or set force with a reason if the lender cannot sign", err)
		return
	}

	if err := s.st.Update(func(st *store.State) error {
		q, ok := st.Pledges[id]
		if !ok {
			return fmt.Errorf("unknown pledge")
		}
		if !q.Open() {
			return fmt.Errorf("pledge is %s", q.State)
		}
		q.State = store.PledgeReleased
		q.RepaidTx = req.RepaidTxid
		if req.Force {
			q.Note = "released by the issuer without a lender signature: " + req.Reason
		}
		return nil
	}); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	s.st.AppendLog("pledge-release", map[string]any{
		"id": id, "asset": p.AssetID, "holder": p.Holder, "lender": p.Lender,
		"atoms": p.Atoms, "repaid_txid": req.RepaidTxid,
		"forced": req.Force, "reason": req.Reason,
	})
	s.st.View(func(st *store.State) {
		if q, ok := st.Pledges[id]; ok {
			p = *q
		}
	})
	httpJSON(w, map[string]any{"pledge": &p})
}

// --- seize -------------------------------------------------------------------

func (s *Server) handlePledgeSeize(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Reason    string `json:"reason"`
		LenderSig string `json:"lender_sig"`
		HolderSig string `json:"holder_sig"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Reason == "" {
		httpErr(w, 400, "a reason is required; it becomes part of the public transparency log")
		return
	}
	var p store.Pledge
	var found bool
	s.st.View(func(st *store.State) {
		if q, ok := st.Pledges[id]; ok {
			p, found = *q, true
		}
	})
	if !found {
		httpErr(w, 404, "unknown pledge")
		return
	}
	if !p.Open() {
		httpErr(w, 409, "pledge is %s", p.State)
		return
	}
	if err := s.checkPledgeSig(p.Lender, req.LenderSig, "seize", id, req.Reason); err != nil {
		httpErr(w, 403, "%v", err)
		return
	}
	height, err := s.node.GetBlockCount()
	if err != nil {
		httpErr(w, 502, "chain height: %v", err)
		return
	}
	if height < p.Maturity {
		// Before maturity the borrower is not in default, so the lender's word
		// alone is not enough. The holder may still hand the collateral over --
		// a negotiated surrender, or a liquidation they agree to -- and that is
		// what their signature means here.
		if err := s.checkPledgeSig(p.Holder, req.HolderSig, "seize", id, req.Reason); err != nil {
			httpErr(w, 409, "the loan matures at height %d and the tip is %d, so a "+
				"seizure needs the holder's countersignature too: %v", p.Maturity, height, err)
			return
		}
	}

	holderTree, holderUser, asset, err := s.enclaveFor(p.Holder, p.AssetID)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	if refuseDampCosign(w, asset) {
		return
	}
	if !asset.Clawback {
		httpErr(w, 409, "this asset has no clawback leaf; the pledge cannot be delivered")
		return
	}
	lenderTree, lenderUser, _, err := s.enclaveFor(p.Lender, p.AssetID)
	if err != nil {
		httpErr(w, 404, "lender: %v", err)
		return
	}
	issuerTree, _, _, err := s.enclaveFor(asset.IssuerAID, p.AssetID)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	_ = issuerTree

	var issuerPriv string
	if asset.IssuerExternal {
		if _, hasPolicy := s.signer.PolicyPubKey(asset.ID); !hasPolicy {
			httpErr(w, 501, "seizure requires the policy key on this server")
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
			httpErr(w, 501, "seizure requires both the policy and issuer keys on this server (demo mode)")
			return
		}
	}

	utxos, err := s.enclaveUTXOs(holderTree, asset.ID)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	var total uint64
	anyBlindedIn := false
	for _, u := range utxos {
		total += u.atoms
		anyBlindedIn = anyBlindedIn || u.blinded
	}
	if total < p.Atoms {
		httpErr(w, 409, "holder holds %d confirmed atoms but the pledge is %d; "+
			"nothing has been swept", total, p.Atoms)
		return
	}
	// Anything the holder holds beyond THIS pledge stays theirs, including
	// atoms locked by a different pledge. Seizing one loan must not disturb
	// another lender's collateral or the holder's free balance.
	change := total - p.Atoms

	feeIn, err := s.feeUTXO(s.cfg.FeeSats * 2)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	if feeIn == nil {
		httpErr(w, 503, "no fee funds")
		return
	}
	assetID := elements.MustHex32(asset.ID)
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	tx := &elements.Tx{Version: 2}
	for _, u := range utxos {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(u.txid), N: u.vout}})
	}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feeIn.txid), N: feeIn.vout}})

	// Confidentiality follows the ACTUAL inputs, never a per-asset flag: if any
	// swept input was blinded, both asset outputs blind to their destination
	// enclaves and the fee change goes to a per-call blinded wallet output. The
	// same discipline as clawback and transfer.
	seizedNonce := elements.NullNonce()
	changeNonce := elements.NullNonce()
	feeChangeOut := &elements.TxOut{
		Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.sats - s.cfg.FeeSats),
		Nonce: elements.NullNonce(),
	}
	if anyBlindedIn {
		seizedNonce, err = s.enclaveConfNonce(asset.ID, elements.MustHex32(lenderUser.Pubkeys[0]),
			hex.EncodeToString(lenderTree.ScriptPubKey()))
		if err != nil {
			httpErr(w, 500, "confidential seized output: %v", err)
			return
		}
		if change > 0 {
			changeNonce, err = s.enclaveConfNonce(asset.ID, elements.MustHex32(holderUser.Pubkeys[0]),
				hex.EncodeToString(holderTree.ScriptPubKey()))
			if err != nil {
				httpErr(w, 500, "confidential holder change: %v", err)
				return
			}
		}
		feeChangeOut, err = s.confWalletOutput(feeIn.sats - s.cfg.FeeSats)
		if err != nil {
			httpErr(w, 502, "confidential fee change: %v", err)
			return
		}
	} else {
		changeAddr, _ := s.wallet.GetNewAddress()
		changeInfo, err := s.wallet.GetAddressInfo(changeAddr)
		if err != nil {
			httpErr(w, 502, "%v", err)
			return
		}
		feeChangeOut.ScriptPubKey = mustHexBytes(changeInfo.ScriptPubKey)
	}

	tx.Out = append(tx.Out,
		&elements.TxOut{Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(p.Atoms),
			Nonce: seizedNonce, ScriptPubKey: lenderTree.ScriptPubKey()})
	if change > 0 {
		tx.Out = append(tx.Out,
			&elements.TxOut{Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(change),
				Nonce: changeNonce, ScriptPubKey: holderTree.ScriptPubKey()})
	}
	tx.Out = append(tx.Out, feeChangeOut,
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: nil})
	tx.NormalizeWitness()

	if anyBlindedIn {
		blinded, err := s.blindTx(tx)
		if err != nil {
			httpErr(w, 500, "blind seizure: %v", err)
			return
		}
		tx = blinded
	}

	// Public notice precedes the signature, as it does for a clawback.
	s.st.AppendLog("pledge-seize", map[string]any{
		"id": id, "asset": asset.ID, "holder": p.Holder, "lender": p.Lender,
		"atoms": p.Atoms, "returned_to_holder": change, "reason": req.Reason,
		"txid": tx.TxID(), "matured": height >= p.Maturity,
	})

	spent, err := s.spentOutputs(tx)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	leaf := holderTree.Leaves["claw"].Script
	control, _ := holderTree.ControlBlock("claw")
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
		// Two-phase, exactly as clawback: the sweep waits for the external
		// issuer's signatures. It completes through the SAME endpoint, which
		// marks the pledge seized once the transaction is broadcast.
		pid := newID()
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
			signing[i] = toSign{Input: i, Sighash: shHex[i], Pubkey: asset.IssuerPub}
		}
		s.st.GCPendingClawbacks(pendingTTL)
		txHex := hex.EncodeToString(tx.Serialize())
		if err := s.st.PutPendingClawback(&store.PendingClawback{
			ID: pid, TxHex: txHex, AssetID: asset.ID, HolderAID: p.Holder,
			Atoms: p.Atoms, Enclave: enclave, Sighashes: shHex, IssuerPub: asset.IssuerPub,
			Reason: "pledge seizure: " + req.Reason, PledgeID: id, Created: time.Now(),
		}); err != nil {
			httpErr(w, 500, "persist pending: %v", err)
			return
		}
		httpJSON(w, map[string]any{
			"id": pid, "tx": txHex, "to_sign": signing, "atoms": p.Atoms,
			"complete_at": "/v1/issuer/clawback/" + pid + "/complete",
		})
		return
	}

	seizeTxid := tx.TxID()
	for i := range utxos {
		policySig, err := s.signer.SignPolicy(asset.ID, sighashes[i], PolicyContext{
			Action: "pledge-seize", AID: p.Holder, TxID: seizeTxid,
			Reason: req.Reason, InputIndex: i,
		})
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
	if err := s.mempoolGate("pledge-seize", signed.Hex, map[string]any{
		"asset": asset.ID, "holder": p.Holder, "lender": p.Lender, "pledge": id,
	}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	// The pledge is marked seized only after the sweep is actually on the
	// network. A failed broadcast must leave the collateral locked, not lost.
	if err := s.markPledgeSeized(id, txid, req.Reason); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	httpJSON(w, map[string]any{
		"txid": txid, "atoms": p.Atoms, "returned_to_holder": change,
	})
}

// markPledgeSeized closes a pledge once its sweep is on the network. Shared
// with the external-issuer completion path in issue.go.
func (s *Server) markPledgeSeized(id, txid, reason string) error {
	return s.st.Update(func(st *store.State) error {
		q, ok := st.Pledges[id]
		if !ok {
			return fmt.Errorf("unknown pledge %s", id)
		}
		q.State = store.PledgeSeized
		q.RepaidTx = txid
		q.Note = reason
		return nil
	})
}
