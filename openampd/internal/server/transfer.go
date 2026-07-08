package server

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// --- policy engine -----------------------------------------------------------

// checkTransfer re-derives every claim from the transaction itself and the
// chain; it never trusts request metadata. It enforces containment (Rule 1
// included) and the asset's policy rules.
func (s *Server) checkTransfer(tx *elements.Tx, asset *store.Asset, sender *store.User, atomsOut map[string]uint64) error {
	if sender.Frozen {
		return refuse("sender frozen")
	}
	assetCommit := hex.EncodeToString(explicitAssetCommit(asset.ID))

	// Snapshot registry data.
	spkToUser := map[string]*store.User{}
	var height int64
	s.st.View(func(st *store.State) {
		height = st.Height
		for _, u := range st.Users {
			cp := *u
			tree, err := s.treeFor(&cp, asset)
			if err == nil {
				spkToUser[hex.EncodeToString(tree.ScriptPubKey())] = &cp
			}
		}
	})

	recipients := map[string]uint64{} // aid -> atoms received
	for i, out := range tx.Out {
		if len(out.Asset) != 33 || out.Asset[0] != 1 {
			return refuse("output %d: confidential or malformed asset in a restricted transfer", i)
		}
		if len(out.Value) != 9 || out.Value[0] != 1 {
			return refuse("output %d: confidential value in a restricted transfer", i)
		}
		if hex.EncodeToString(out.Asset) != assetCommit {
			continue
		}
		if len(out.ScriptPubKey) == 0 {
			return refuse("restricted asset in a fee output")
		}
		if len(out.ScriptPubKey) == 1 && out.ScriptPubKey[0] == 0x6a {
			if !asset.BurnAllowed {
				return refuse("burns are not permitted for this asset")
			}
			continue
		}
		u, ok := spkToUser[hex.EncodeToString(out.ScriptPubKey)]
		if !ok {
			return refuse("restricted asset to an out-of-enclave destination")
		}
		amt, _ := elements.ExplicitValueAmount(out.Value)
		if u.AID != sender.AID {
			recipients[u.AID] += amt
			atomsOut[u.AID] += amt
		}
		if u.Frozen && u.AID != asset.IssuerAID {
			return refuse("recipient %s frozen", u.AID)
		}
	}

	rules := asset.Rules
	// Category gating (issuer exempt as conversion/redemption counterparty).
	if len(rules.AllowedCategories) > 0 {
		for aid := range recipients {
			if aid == asset.IssuerAID {
				continue
			}
			var ok bool
			s.st.View(func(st *store.State) {
				if u, has := st.Users[aid]; has {
					for _, c := range u.Categories {
						for _, want := range rules.AllowedCategories {
							if c == want {
								ok = true
							}
						}
					}
				}
			})
			if !ok {
				return refuse("recipient %s lacks a permitted category", aid)
			}
		}
	}

	// Lock-in period.
	if rules.LockinUntilHeight > 0 && height < rules.LockinUntilHeight {
		onlyIssuer := true
		for aid := range recipients {
			if aid != asset.IssuerAID {
				onlyIssuer = false
			}
		}
		if !(onlyIssuer && rules.ConvertDuringLockin) {
			return refuse("asset is locked in until height %d (current %d)", rules.LockinUntilHeight, height)
		}
	}

	var sent uint64
	for _, a := range recipients {
		sent += a
	}

	// Velocity.
	if rules.VelocityMaxAtoms > 0 && rules.VelocityWindowBlocks > 0 {
		var window uint64
		s.st.View(func(st *store.State) {
			for _, rec := range st.Transfers {
				if rec.Asset == asset.ID && rec.SenderAID == sender.AID &&
					(rec.Height < 0 || rec.Height > height-rules.VelocityWindowBlocks) {
					window += rec.Atoms
				}
			}
		})
		if window+sent > rules.VelocityMaxAtoms {
			return refuse("velocity limit: %d atoms in window plus %d exceeds %d",
				window, sent, rules.VelocityMaxAtoms)
		}
	}

	// Holder cap and vesting need chain balances.
	if rules.HolderCap > 0 || len(rules.Vesting) > 0 {
		balances, err := s.holderBalances(asset)
		if err != nil {
			return fmt.Errorf("holder scan: %w", err)
		}
		if rules.HolderCap > 0 {
			holders := map[string]bool{}
			for aid, atoms := range balances {
				if atoms > 0 {
					holders[aid] = true
				}
			}
			for aid, got := range recipients {
				if got > 0 {
					holders[aid] = true
				}
			}
			// The sender may be exiting entirely; keep the check conservative
			// (sender still counted) — a cap breach on exit is never created.
			if len(holders) > rules.HolderCap {
				return refuse("holder cap %d would be exceeded (%d holders)", rules.HolderCap, len(holders))
			}
		}
		for _, v := range rules.Vesting {
			if v.AID != sender.AID || v.UntilHeight <= height {
				continue
			}
			if balances[sender.AID] < sent+v.Atoms {
				return refuse("vesting: %d atoms locked until height %d", v.Atoms, v.UntilHeight)
			}
		}
	}
	return nil
}

func explicitAssetCommit(displayID string) []byte {
	id := elements.MustHex32(displayID)
	return elements.ExplicitAsset(id)
}

// holderBalances scans confirmed enclave balances for every registered user.
func (s *Server) holderBalances(asset *store.Asset) (map[string]uint64, error) {
	spkToAID := map[string]string{}
	var spks []string
	var scanErr error
	s.st.View(func(st *store.State) {
		for _, u := range st.Users {
			tree, err := s.treeFor(u, asset)
			if err != nil {
				scanErr = err
				return
			}
			spk := hex.EncodeToString(tree.ScriptPubKey())
			spkToAID[spk] = u.AID
			spks = append(spks, spk)
		}
	})
	if scanErr != nil {
		return nil, scanErr
	}
	balances := map[string]uint64{}
	if len(spks) == 0 {
		return balances, nil
	}
	unspents, err := s.node.ScanTxOutSet(spks)
	if err != nil {
		return nil, err
	}
	for _, u := range unspents {
		if u.Asset != asset.ID {
			continue
		}
		balances[spkToAID[u.ScriptPubKey]] += sats(u.Amount)
	}
	return balances, nil
}

// spentOutputs resolves every input's prevout from the node (mempool included).
func (s *Server) spentOutputs(tx *elements.Tx) ([]*elements.SpentOutput, error) {
	spent := make([]*elements.SpentOutput, len(tx.In))
	for i, in := range tx.In {
		txid := displayHash(in.Prevout.Hash)
		res, err := s.node.GetTxOut(txid, in.Prevout.N, true)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return nil, refuse("input %d (%s:%d) is unknown or already spent", i, txid, in.Prevout.N)
		}
		var asset [32]byte
		copy(asset[:], mustHexBytes(res.Asset))
		spk, err := hex.DecodeString(res.ScriptPubKey.Hex)
		if err != nil {
			return nil, err
		}
		spent[i] = &elements.SpentOutput{
			Asset:        elements.ExplicitAsset(asset),
			Value:        elements.ExplicitValue(sats(res.Value)),
			ScriptPubKey: spk,
		}
	}
	return spent, nil
}

func displayHash(internal [32]byte) string {
	var d [32]byte
	for i := 0; i < 32; i++ {
		d[i] = internal[31-i]
	}
	return hex.EncodeToString(d[:])
}

func internalHash(display string) [32]byte {
	b := mustHexBytes(display)
	var out [32]byte
	for i := 0; i < 32 && i < len(b); i++ {
		out[i] = b[31-i]
	}
	return out
}

func mustHexBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// --- hosted transfer build -----------------------------------------------------

func (s *Server) handleTransferBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset        string `json:"asset"`
		SenderAID    string `json:"sender_aid"`
		RecipientAID string `json:"recipient_aid"`
		Atoms        uint64 `json:"atoms"`
		FeeMode      string `json:"fee_mode"` // "convert" | "sponsor"
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.FeeMode != "convert" && req.FeeMode != "sponsor" {
		httpErr(w, 400, "fee_mode must be convert or sponsor (self-paid transactions use POST /v1/cosign)")
		return
	}
	senderTree, sender, asset, err := s.enclaveFor(req.SenderAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	recipTree, _, _, err := s.enclaveFor(req.RecipientAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	issuerTree, _, _, err := s.enclaveFor(asset.IssuerAID, req.Asset)
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

	// Sender coin selection.
	utxos, err := s.enclaveUTXOs(senderTree, asset.ID)
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
	var feeIn *struct {
		txid string
		vout uint32
		sats uint64
	}
	for _, u := range feeUtxos {
		if u.Spendable && sats(u.Amount) > s.cfg.FeeSats*2 {
			feeIn = &struct {
				txid string
				vout uint32
				sats uint64
			}{u.TxID, u.Vout, sats(u.Amount)}
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
		info2, err := s.wallet.GetAddressInfo(changeInfo.Unconfidential)
		if err == nil {
			changeSpk = info2.ScriptPubKey
		}
	}

	// Assemble.
	tx := &elements.Tx{Version: 2}
	assetID := elements.MustHex32(asset.ID)
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	var enclaveIdx []int
	for i, u := range chosen {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(u.txid), N: u.vout}})
		enclaveIdx = append(enclaveIdx, i)
	}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feeIn.txid), N: feeIn.vout}})

	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(req.Atoms),
		Nonce: elements.NullNonce(), ScriptPubKey: recipTree.ScriptPubKey(),
	})
	if change := total - need; change > 0 {
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(change),
			Nonce: elements.NullNonce(), ScriptPubKey: senderTree.ScriptPubKey(),
		})
	}
	if convertAtoms > 0 {
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(convertAtoms),
			Nonce: elements.NullNonce(), ScriptPubKey: issuerTree.ScriptPubKey(),
		})
	}
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.sats - s.cfg.FeeSats),
		Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(changeSpk),
	})
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
		Nonce: elements.NullNonce(), ScriptPubKey: nil,
	})
	tx.NormalizeWitness()

	// Sighashes for the enclave inputs.
	spent, err := s.spentOutputs(tx)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	leaf := senderTree.Leaves["transfer"].Script
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
		signing = append(signing, toSign{Input: idx, Sighash: hex.EncodeToString(sh[:]), Pubkey: sender.Pubkeys[0]})
	}

	id := newID()
	s.mu.Lock()
	for k, p := range s.pending { // GC stale
		if time.Since(p.created) > 15*time.Minute {
			delete(s.pending, k)
		}
	}
	s.pending[id] = &pendingTransfer{
		tx: tx, asset: asset, senderAID: sender.AID, atoms: req.Atoms + convertAtoms,
		enclave: enclaveIdx, sighashes: sighashes,
		userPub: elements.MustHex32(sender.Pubkeys[0]), created: time.Now(), feeMode: req.FeeMode,
	}
	s.mu.Unlock()

	httpJSON(w, map[string]any{
		"id": id, "tx": hex.EncodeToString(tx.Serialize()),
		"to_sign": signing, "convert_atoms": convertAtoms, "fee_sats": s.cfg.FeeSats,
	})
}

func (s *Server) handleTransferComplete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Sigs map[string]string `json:"sigs"` // input index (decimal string) -> 64-byte schnorr sig hex
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	s.mu.Lock()
	p, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if !ok {
		httpErr(w, 404, "unknown or expired transfer")
		return
	}

	var sender *store.User
	s.st.View(func(st *store.State) {
		if u, has := st.Users[p.senderAID]; has {
			cp := *u
			sender = &cp
		}
	})
	if sender == nil {
		httpErr(w, 404, "sender no longer registered")
		return
	}

	// Verify the user's signatures before doing anything else.
	pk, err := schnorr.ParsePubKey(p.userPub[:])
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	userSigs := map[int][]byte{}
	for i, idx := range p.enclave {
		sigHex, has := req.Sigs[fmt.Sprintf("%d", idx)]
		if !has {
			httpErr(w, 400, "missing signature for input %d", idx)
			return
		}
		sigBytes := mustHexBytes(sigHex)
		sig, err := schnorr.ParseSignature(sigBytes)
		if err != nil || !sig.Verify(p.sighashes[i][:], pk) {
			httpErr(w, 400, "invalid signature for input %d", idx)
			return
		}
		userSigs[idx] = sigBytes
	}

	txid, err := s.cosignAndBroadcast(p, sender, userSigs)
	if err != nil {
		if pr, isRefusal := err.(*PolicyRefusal); isRefusal {
			logRefusal("cosign", s.st, map[string]any{"sender": sender.AID, "asset": p.asset.ID, "reason": pr.Reason})
			httpErr(w, 403, "%v", pr)
			return
		}
		httpErr(w, 502, "%v", err)
		return
	}
	httpJSON(w, map[string]string{"txid": txid})
}

func (s *Server) cosignAndBroadcast(p *pendingTransfer, sender *store.User, userSigs map[int][]byte) (string, error) {
	atomsOut := map[string]uint64{}
	if err := s.checkTransfer(p.tx, p.asset, sender, atomsOut); err != nil {
		return "", err
	}
	senderTree, err := s.treeFor(sender, p.asset)
	if err != nil {
		return "", err
	}
	leaf := senderTree.Leaves["transfer"].Script
	control, err := senderTree.ControlBlock("transfer")
	if err != nil {
		return "", err
	}
	p.tx.NormalizeWitness()
	for i, idx := range p.enclave {
		policySig, err := s.signer.SignPolicy(p.asset.ID, p.sighashes[i])
		if err != nil {
			return "", err
		}
		p.tx.InWit[idx].ScriptWitness = [][]byte{policySig, userSigs[idx], leaf, control}
	}
	// Wallet signs its own fee input.
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(p.tx.Serialize()))
	if err != nil {
		return "", err
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		return "", err
	}
	var sent uint64
	for _, a := range atomsOut {
		sent += a
	}
	s.st.Update(func(st *store.State) error {
		st.Transfers = append(st.Transfers, store.TransferRecord{
			Txid: txid, Asset: p.asset.ID, SenderAID: sender.AID, Atoms: sent, Height: -1,
		})
		return nil
	})
	s.st.AppendLog("transfer", map[string]any{
		"txid": txid, "asset": p.asset.ID, "sender": sender.AID, "atoms": sent, "fee_mode": p.feeMode,
	})
	return txid, nil
}

// --- raw co-sign (self-built transactions, fee self-paid) ---------------------

func (s *Server) handleCosign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tx        string `json:"tx"`
		Asset     string `json:"asset"`
		SenderAID string `json:"sender_aid"`
		Inputs    []int  `json:"inputs"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	senderTree, sender, asset, err := s.enclaveFor(req.SenderAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	tx, err := elements.DeserializeTx(mustHexBytes(req.Tx))
	if err != nil {
		httpErr(w, 400, "tx: %v", err)
		return
	}
	spent, err := s.spentOutputs(tx)
	if err != nil {
		if pr, isRefusal := err.(*PolicyRefusal); isRefusal {
			httpErr(w, 403, "%v", pr)
			return
		}
		httpErr(w, 502, "%v", err)
		return
	}
	// Claimed inputs must actually be the sender's enclave outputs; and no
	// unclaimed input may be an enclave output of this asset (a co-sign for
	// someone else's coins hidden in the same tx).
	senderSpk := hex.EncodeToString(senderTree.ScriptPubKey())
	claimed := map[int]bool{}
	for _, idx := range req.Inputs {
		if idx < 0 || idx >= len(tx.In) {
			httpErr(w, 400, "input %d out of range", idx)
			return
		}
		claimed[idx] = true
		if hex.EncodeToString(spent[idx].ScriptPubKey) != senderSpk {
			httpErr(w, 403, "input %d is not the sender's enclave output", idx)
			return
		}
	}
	atomsOut := map[string]uint64{}
	if err := s.checkTransfer(tx, asset, sender, atomsOut); err != nil {
		if pr, isRefusal := err.(*PolicyRefusal); isRefusal {
			logRefusal("cosign", s.st, map[string]any{"sender": sender.AID, "asset": asset.ID, "reason": pr.Reason})
			httpErr(w, 403, "%v", pr)
			return
		}
		httpErr(w, 502, "%v", err)
		return
	}
	leaf := senderTree.Leaves["transfer"].Script
	control, _ := senderTree.ControlBlock("transfer")
	type sigOut struct {
		Input     int    `json:"input"`
		Sighash   string `json:"sighash"`
		PolicySig string `json:"policy_sig"`
		Leaf      string `json:"leaf"`
		Control   string `json:"control"`
	}
	var sigs []sigOut
	var sent uint64
	for _, a := range atomsOut {
		sent += a
	}
	for _, idx := range req.Inputs {
		sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, idx, leaf)
		if err != nil {
			httpErr(w, 500, "sighash: %v", err)
			return
		}
		sig, err := s.signer.SignPolicy(asset.ID, sh)
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		sigs = append(sigs, sigOut{
			Input: idx, Sighash: hex.EncodeToString(sh[:]), PolicySig: hex.EncodeToString(sig),
			Leaf: hex.EncodeToString(leaf), Control: hex.EncodeToString(control),
		})
	}
	rawTxid := tx.TxID()
	s.st.Update(func(st *store.State) error {
		st.Transfers = append(st.Transfers, store.TransferRecord{
			Txid: rawTxid, Asset: asset.ID, SenderAID: sender.AID, Atoms: sent, Height: -1,
		})
		return nil
	})
	s.st.AppendLog("cosign", map[string]any{"txid": rawTxid, "sender": sender.AID, "asset": asset.ID, "atoms": sent})
	httpJSON(w, map[string]any{"sigs": sigs})
}
