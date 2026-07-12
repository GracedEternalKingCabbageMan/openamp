package server

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
)

// handleBurnBuild builds a redeem burn (OA-5): a holder's enclave units are sent
// to the provably-unspendable output (a single-byte OP_RETURN scriptPubKey),
// reducing the chain-derived circulating supply for real once it confirms. The
// tx is only assembled here and returned with the enclave sighashes to sign; the
// holder signs the transfer leaf and the completion path (POST
// /v1/transfers/{id}/complete) policy-co-signs and broadcasts, exactly like an
// M5/M6 hosted transfer. Reusing that path inherits its once-only, restart-
// durable idempotency (a completed id can never be settled twice), so a retry
// after a broadcast never double-burns.
//
// Additive: the burn output is the `0x6a` destination checkTransfer already
// permits for asset.BurnAllowed; assets without BurnAllowed are refused here and
// again at co-sign. No existing transfer or cosign path changes.
func (s *Server) handleBurnBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset     string `json:"asset"`
		HolderAID string `json:"holder_aid"`
		Atoms     uint64 `json:"atoms"`
		FeeMode   string `json:"fee_mode"` // "sponsor" (default) | "convert"
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Atoms == 0 {
		httpErr(w, 400, "atoms must be greater than zero")
		return
	}
	if req.FeeMode == "" {
		req.FeeMode = "sponsor"
	}
	if req.FeeMode != "sponsor" && req.FeeMode != "convert" {
		httpErr(w, 400, "fee_mode must be sponsor or convert")
		return
	}
	holderTree, holder, asset, err := s.enclaveFor(req.HolderAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	if !asset.BurnAllowed {
		logRefusal("burn", s.st, map[string]any{"holder": holder.AID, "asset": asset.ID, "reason": "burns are not permitted for this asset"})
		httpErr(w, 403, "burns are not permitted for this asset")
		return
	}
	issuerTree, issuerUser, _, err := s.enclaveFor(asset.IssuerAID, req.Asset)
	if err != nil {
		httpErr(w, 500, "issuer enclave: %v", err)
		return
	}

	convertAtoms := uint64(0)
	if req.FeeMode == "convert" {
		convertAtoms = asset.Rules.FeeConvertAtoms
		if convertAtoms == 0 {
			convertAtoms = 1
		}
	}

	// Holder coin selection.
	utxos, err := s.enclaveUTXOs(holderTree, asset.ID)
	if err != nil {
		httpErr(w, 502, "scan: %v", err)
		return
	}
	need := req.Atoms + convertAtoms
	var chosen []enclaveUTXO
	var total uint64
	for _, u := range utxos {
		chosen = append(chosen, u)
		total += u.atoms
		if total >= need {
			break
		}
	}
	if total < need {
		httpErr(w, 409, "insufficient balance: have %d atoms, need %d", total, need)
		return
	}

	// Server fee funding.
	feeUtxos, err := s.wallet.ListUnspent(1, s.cfg.FeeAsset)
	if err != nil {
		httpErr(w, 502, "fee funding: %v", err)
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
		httpErr(w, 503, "policy server has no fee funds")
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
	changeSpk := changeInfo.ScriptPubKey
	if changeInfo.Unconfidential != "" && changeInfo.Unconfidential != changeAddr {
		if info2, err := s.wallet.GetAddressInfo(changeInfo.Unconfidential); err == nil {
			changeSpk = info2.ScriptPubKey
		}
	}

	// Assemble.
	tx := &elements.Tx{Version: 2}
	assetID := elements.MustHex32(asset.ID)
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	var enclaveIdx []int
	for i := range chosen {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(chosen[i].txid), N: chosen[i].vout}})
		enclaveIdx = append(enclaveIdx, i)
	}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feeIn.txid), N: feeIn.vout}})

	// The burn output is always explicit: an OP_RETURN carries no blinding nonce
	// and the amount being retired is public by design. The change back to the
	// holder and the fee-conversion output blind to the enclave keys when the
	// asset is confidential (giving the >=2 blinded outputs a blinded tx needs).
	changeNonce, convNonce := elements.NullNonce(), elements.NullNonce()
	if asset.Confidential {
		if changeNonce, err = s.enclaveConfNonce(asset.ID, elements.MustHex32(holder.Pubkeys[0]), hex.EncodeToString(holderTree.ScriptPubKey())); err != nil {
			httpErr(w, 500, "confidential change: %v", err)
			return
		}
		if convNonce, err = s.enclaveConfNonce(asset.ID, elements.MustHex32(issuerUser.Pubkeys[0]), hex.EncodeToString(issuerTree.ScriptPubKey())); err != nil {
			httpErr(w, 500, "confidential conversion: %v", err)
			return
		}
	}

	// Burn output: the whole requested amount to the unspendable `0x6a` script.
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(req.Atoms),
		Nonce: elements.NullNonce(), ScriptPubKey: []byte{0x6a},
	})
	if change := total - need; change > 0 {
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(change),
			Nonce: changeNonce, ScriptPubKey: holderTree.ScriptPubKey(),
		})
	}
	if convertAtoms > 0 {
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(convertAtoms),
			Nonce: convNonce, ScriptPubKey: issuerTree.ScriptPubKey(),
		})
	}
	if asset.Confidential {
		feeChange, err := s.confWalletOutput(feeIn.sats - s.cfg.FeeSats)
		if err != nil {
			httpErr(w, 502, "%v", err)
			return
		}
		tx.Out = append(tx.Out, feeChange)
	} else {
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.sats - s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(changeSpk),
		})
	}
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
		Nonce: elements.NullNonce(), ScriptPubKey: nil,
	})
	tx.NormalizeWitness()

	// Keep the pre-blind (explicit) tx for the policy check; blind the copy that
	// gets signed and broadcast when the asset is confidential.
	explicitTx := tx
	if asset.Confidential {
		blinded, err := s.blindTx(tx)
		if err != nil {
			httpErr(w, 500, "blind burn: %v", err)
			return
		}
		tx = blinded
	}

	// Sighashes for the holder's enclave inputs (transfer leaf).
	spent, err := s.spentOutputs(tx)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	leaf := holderTree.Leaves["transfer"].Script
	var sighashes [][32]byte
	type toSign struct {
		Input   int    `json:"input"`
		Sighash string `json:"sighash"`
		Pubkey  string `json:"pubkey"`
	}
	var signing []toSign
	for _, idx := range enclaveIdx {
		sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, idx, leaf)
		if err != nil {
			httpErr(w, 500, "sighash: %v", err)
			return
		}
		sighashes = append(sighashes, sh)
		signing = append(signing, toSign{Input: idx, Sighash: hex.EncodeToString(sh[:]), Pubkey: holder.Pubkeys[0]})
	}

	id := newID()
	pt := &pendingTransfer{
		tx: tx, explicitTx: explicitTx, asset: asset, senderAID: holder.AID, atoms: need,
		enclave: enclaveIdx, sighashes: sighashes, burnAtoms: req.Atoms,
		userPub: elements.MustHex32(holder.Pubkeys[0]), created: time.Now(), feeMode: req.FeeMode,
	}
	s.mu.Lock()
	for k, p := range s.pending {
		if time.Since(p.created) > pendingTTL {
			delete(s.pending, k)
		}
	}
	s.pending[id] = pt
	s.mu.Unlock()
	s.st.GCPendingTransfers(pendingTTL)
	if err := s.st.PutPendingTransfer(pendingRecord(id, pt)); err != nil {
		httpErr(w, 500, "persist pending: %v", err)
		return
	}

	httpJSON(w, map[string]any{
		"id": id, "tx": hex.EncodeToString(tx.Serialize()),
		"to_sign": signing, "burn_atoms": req.Atoms, "convert_atoms": convertAtoms, "fee_sats": s.cfg.FeeSats,
	})
}
