package server

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	// Sender scoping (OA-3): a primary sender (per-offering escrow / entity
	// treasury) is exempt from the lock-in and the Reg S category-deny windows,
	// so it can deliver to investors during a lockup. Every other rule still
	// applies to it.
	senderIsPrimary := false
	for _, a := range rules.PrimaryAIDs {
		if a == sender.AID {
			senderIsPrimary = true
			break
		}
	}

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

	// Reg S category-deny windows (OA-3): only bind non-primary senders.
	if !senderIsPrimary && len(rules.CategoryDenies) > 0 {
		recipCats := map[string][]string{}
		s.st.View(func(st *store.State) {
			for aid := range recipients {
				if aid == asset.IssuerAID {
					continue
				}
				if u, has := st.Users[aid]; has {
					recipCats[aid] = append([]string(nil), u.Categories...)
				}
			}
		})
		for aid, cats := range recipCats {
			for _, d := range rules.CategoryDenies {
				if height >= d.UntilHeight {
					continue
				}
				for _, c := range cats {
					if strings.HasPrefix(c, d.Prefix) {
						return refuse("recipient %s holds category %s denied until height %d (current %d)",
							aid, c, d.UntilHeight, height)
					}
				}
			}
		}
	}

	// Lock-in period: only binds non-primary senders (OA-3 scoping).
	if !senderIsPrimary && rules.LockinUntilHeight > 0 && height < rules.LockinUntilHeight {
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

	// Holder cap, per-category caps and vesting need chain balances.
	if rules.HolderCap > 0 || len(rules.Vesting) > 0 || len(rules.HolderCapsByCategory) > 0 {
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
		// Per-category holder caps (OA-3): each holder's categories come from the
		// registry; a distinct nonzero holder (existing or incoming) carrying the
		// exact category token counts once against that category's cap.
		if len(rules.HolderCapsByCategory) > 0 {
			aidCats := map[string][]string{}
			s.st.View(func(st *store.State) {
				for aid := range balances {
					if u, has := st.Users[aid]; has {
						aidCats[aid] = append([]string(nil), u.Categories...)
					}
				}
				for aid := range recipients {
					if u, has := st.Users[aid]; has {
						aidCats[aid] = append([]string(nil), u.Categories...)
					}
				}
			})
			for cat, limit := range rules.HolderCapsByCategory {
				if limit <= 0 {
					continue
				}
				holders := map[string]bool{}
				for aid, atoms := range balances {
					if atoms > 0 && hasCategory(aidCats[aid], cat) {
						holders[aid] = true
					}
				}
				for aid, got := range recipients {
					if got > 0 && hasCategory(aidCats[aid], cat) {
						holders[aid] = true
					}
				}
				if len(holders) > limit {
					return refuse("holder cap for category %s: %d holders would exceed %d", cat, len(holders), limit)
				}
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

// hasCategory reports whether cats contains the exact category token want.
func hasCategory(cats []string, want string) bool {
	for _, c := range cats {
		if c == want {
			return true
		}
	}
	return false
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
	// Confidential assets are unblinded through the watch wallet, which reports
	// the amount per enclave scriptPubKey; scantxoutset would only see
	// commitments (whose asset never matches the plaintext asset id).
	if asset.Confidential {
		w, err := s.watchClient()
		if err != nil {
			return nil, err
		}
		all, err := w.ListUnspentAll()
		if err != nil {
			return nil, err
		}
		for _, u := range all {
			if aid, ok := spkToAID[u.ScriptPubKey]; ok && u.Asset == asset.ID {
				balances[aid] += sats(u.Amount)
			}
		}
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
// spentOutputs resolves each input's prevout to the EXACT on-chain nAsset,
// nValue and scriptPubKey bytes (commitments for confidential outputs), read
// from the raw prevout transaction. This is what the taproot sighash commits
// to, uniformly for explicit and confidential inputs.
// rawTxViaElectrs fetches a transaction's raw hex from the explorer (electrs),
// which indexes every transaction, so a confirmed prevout resolves even though
// the node runs without -txindex.
func (s *Server) rawTxViaElectrs(txid string) (string, error) {
	if s.cfg.ElectrsURL == "" {
		return "", fmt.Errorf("getrawtransaction failed and no electrs URL is configured (node needs -txindex)")
	}
	url := strings.TrimRight(s.cfg.ElectrsURL, "/") + "/tx/" + txid + "/hex"
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("electrs fetch %s: %w", txid, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("electrs %s -> HTTP %d", txid, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *Server) spentOutputs(tx *elements.Tx) ([]*elements.SpentOutput, error) {
	spent := make([]*elements.SpentOutput, len(tx.In))
	cache := map[string]*elements.Tx{}
	for i, in := range tx.In {
		txid := displayHash(in.Prevout.Hash)
		prev, ok := cache[txid]
		if !ok {
			// getrawtransaction resolves a mempool prevout without -txindex, but a
			// CONFIRMED prevout needs -txindex, which the shared producer node does
			// not run. Fall back to electrs (which indexes every tx) so a transfer
			// from a confirmed enclave UTXO still resolves.
			raw, err := s.node.GetRawTransactionHex(txid)
			if err != nil {
				raw, err = s.rawTxViaElectrs(txid)
				if err != nil {
					return nil, refuse("input %d (%s:%d): %v", i, txid, in.Prevout.N, err)
				}
			}
			prev, err = elements.DeserializeTx(mustHexBytes(raw))
			if err != nil {
				return nil, fmt.Errorf("decode prevout %s: %w", txid, err)
			}
			cache[txid] = prev
		}
		if int(in.Prevout.N) >= len(prev.Out) {
			return nil, refuse("input %d: prevout %s:%d out of range", i, txid, in.Prevout.N)
		}
		o := prev.Out[in.Prevout.N]
		spent[i] = &elements.SpentOutput{Asset: o.Asset, Value: o.Value, ScriptPubKey: o.ScriptPubKey}
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

// addressScriptPubKey resolves an ordinary address to its (unconfidential)
// scriptPubKey hex. A confidential address is reduced to its unconfidential
// form first, mirroring the change-address handling in the build path.
func (s *Server) addressScriptPubKey(addr string) (string, error) {
	info, err := s.wallet.GetAddressInfo(addr)
	if err != nil {
		return "", err
	}
	spk := info.ScriptPubKey
	if info.Unconfidential != "" && info.Unconfidential != addr {
		if info2, err := s.wallet.GetAddressInfo(info.Unconfidential); err == nil {
			spk = info2.ScriptPubKey
		}
	}
	if spk == "" {
		return "", fmt.Errorf("no scriptPubKey for %s", addr)
	}
	return spk, nil
}

// --- hosted transfer build -----------------------------------------------------

func (s *Server) handleTransferBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset        string `json:"asset"`
		SenderAID    string `json:"sender_aid"`
		RecipientAID string `json:"recipient_aid"`
		Atoms        uint64 `json:"atoms"`
		FeeMode      string `json:"fee_mode"` // "convert" | "sponsor"
		// Payment (OA-4): an optional ordinary-asset (e.g. USDX) leg carried in the
		// SAME transaction as the restricted transfer, turning delivery-versus-
		// payment into one atomic tx. from_address is an ordinary address the
		// caller controls (the escrow's payment coins); to_address is the payee
		// (the issuer's registered payout address). The caller signs the payment
		// inputs with its own wallet at /complete. Absent = exactly the M5 flow.
		Payment *struct {
			Asset       string `json:"asset"`
			Atoms       uint64 `json:"atoms"`
			FromAddress string `json:"from_address"`
			ToAddress   string `json:"to_address"`
		} `json:"payment,omitempty"`
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
	recipTree, recipUser, _, err := s.enclaveFor(req.RecipientAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	issuerTree, issuerUser, _, err := s.enclaveFor(asset.IssuerAID, req.Asset)
	if err != nil {
		httpErr(w, 500, "issuer enclave: %v", err)
		return
	}

	// OA-4 payment leg: only for a transparent restricted asset (the atomic DvP
	// path keeps the WHOLE tx transparent; a blinded restricted leg cannot carry
	// an explicit foreign payment output under the transparency rule).
	if req.Payment != nil {
		if asset.Confidential {
			httpErr(w, 400, "an atomic payment leg is only supported for a transparent restricted asset")
			return
		}
		p := req.Payment
		if p.Asset == "" || p.Atoms == 0 || p.FromAddress == "" || p.ToAddress == "" {
			httpErr(w, 400, "payment requires asset, atoms, from_address and to_address")
			return
		}
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

	// Output nonces: null for transparent assets; per-enclave blinding pubkeys
	// for a confidential asset (each also registers the recipient's enclave in
	// the watch wallet so the server can unblind it later).
	recipNonce, changeNonce, convNonce := elements.NullNonce(), elements.NullNonce(), elements.NullNonce()
	if asset.Confidential {
		if recipNonce, err = s.enclaveConfNonce(asset.ID, elements.MustHex32(recipUser.Pubkeys[0]), hex.EncodeToString(recipTree.ScriptPubKey())); err != nil {
			httpErr(w, 500, "confidential recipient: %v", err)
			return
		}
		if changeNonce, err = s.enclaveConfNonce(asset.ID, elements.MustHex32(sender.Pubkeys[0]), hex.EncodeToString(senderTree.ScriptPubKey())); err != nil {
			httpErr(w, 500, "confidential change: %v", err)
			return
		}
		if convNonce, err = s.enclaveConfNonce(asset.ID, elements.MustHex32(issuerUser.Pubkeys[0]), hex.EncodeToString(issuerTree.ScriptPubKey())); err != nil {
			httpErr(w, 500, "confidential conversion: %v", err)
			return
		}
	}

	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(req.Atoms),
		Nonce: recipNonce, ScriptPubKey: recipTree.ScriptPubKey(),
	})
	if change := total - need; change > 0 {
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(change),
			Nonce: changeNonce, ScriptPubKey: senderTree.ScriptPubKey(),
		})
	}
	if convertAtoms > 0 {
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(assetID), Value: elements.ExplicitValue(convertAtoms),
			Nonce: convNonce, ScriptPubKey: issuerTree.ScriptPubKey(),
		})
	}

	// OA-4 payment leg: the escrow's ordinary payment coins (from_address) in and
	// the payee's payment output (to_address) out, both explicit, in this same
	// transaction. The inputs are ordinary (not enclave) coins; the caller signs
	// them with its own wallet at /complete. Added before the fee output so the
	// fee output stays last, and after the restricted outputs so the enclave
	// input indices are unchanged (fully additive for a no-payment request).
	var paymentIdx []int
	if req.Payment != nil {
		p := req.Payment
		fromSpk, err := s.addressScriptPubKey(p.FromAddress)
		if err != nil {
			httpErr(w, 400, "payment from_address: %v", err)
			return
		}
		toSpk, err := s.addressScriptPubKey(p.ToAddress)
		if err != nil {
			httpErr(w, 400, "payment to_address: %v", err)
			return
		}
		unspents, err := s.node.ScanTxOutSet([]string{fromSpk})
		if err != nil {
			httpErr(w, 502, "payment scan: %v", err)
			return
		}
		var payTotal uint64
		for _, u := range unspents {
			if u.Asset != p.Asset {
				continue
			}
			idx := len(tx.In)
			tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(u.TxID), N: u.Vout}})
			paymentIdx = append(paymentIdx, idx)
			payTotal += sats(u.Amount)
			if payTotal >= p.Atoms {
				break
			}
		}
		if payTotal < p.Atoms {
			httpErr(w, 409, "insufficient payment balance at from_address: have %d atoms, need %d", payTotal, p.Atoms)
			return
		}
		payAssetID := elements.MustHex32(p.Asset)
		tx.Out = append(tx.Out, &elements.TxOut{
			Asset: elements.ExplicitAsset(payAssetID), Value: elements.ExplicitValue(p.Atoms),
			Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(toSpk),
		})
		if change := payTotal - p.Atoms; change > 0 {
			tx.Out = append(tx.Out, &elements.TxOut{
				Asset: elements.ExplicitAsset(payAssetID), Value: elements.ExplicitValue(change),
				Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(fromSpk),
			})
		}
	}
	// Fee change: a confidential wallet output for a confidential asset (so the
	// transaction has >=2 confidential outputs and the amount is hidden too),
	// otherwise a plain wallet output.
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

	// Keep the pre-blind (explicit) tx for the policy check, which reads
	// amounts, assets and destinations; blind the copy that gets signed and
	// broadcast (the sighash commits to the blinded outputs).
	explicitTx := tx
	if asset.Confidential {
		blinded, err := s.blindTx(tx)
		if err != nil {
			httpErr(w, 500, "blind transfer: %v", err)
			return
		}
		tx = blinded
	}

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
	pt := &pendingTransfer{
		tx: tx, explicitTx: explicitTx, asset: asset, senderAID: sender.AID, atoms: req.Atoms + convertAtoms,
		enclave: enclaveIdx, sighashes: sighashes, paymentInputs: paymentIdx,
		userPub: elements.MustHex32(sender.Pubkeys[0]), created: time.Now(), feeMode: req.FeeMode,
	}
	s.mu.Lock()
	for k, p := range s.pending { // GC the in-memory fast-path cache
		if time.Since(p.created) > pendingTTL {
			delete(s.pending, k)
		}
	}
	s.pending[id] = pt
	s.mu.Unlock()
	// Persist the build so the caller's signatures can complete it after a
	// restart (the multi-party OA-4 case); the store is the durable authority.
	s.st.GCPendingTransfers(pendingTTL)
	if err := s.st.PutPendingTransfer(pendingRecord(id, pt)); err != nil {
		httpErr(w, 500, "persist pending: %v", err)
		return
	}

	resp := map[string]any{
		"id": id, "tx": hex.EncodeToString(tx.Serialize()),
		"to_sign": signing, "convert_atoms": convertAtoms, "fee_sats": s.cfg.FeeSats,
	}
	// Only surface payment_inputs when there is a payment leg, so a no-payment
	// build's response is identical to M5's.
	if len(paymentIdx) > 0 {
		resp["payment_inputs"] = paymentIdx
	}
	httpJSON(w, resp)
}

// pendingRecord serialises an in-memory build into its persisted form.
func pendingRecord(id string, p *pendingTransfer) *store.PendingTransfer {
	sh := make([]string, len(p.sighashes))
	for i := range p.sighashes {
		sh[i] = hex.EncodeToString(p.sighashes[i][:])
	}
	explicitHex := ""
	if p.explicitTx != nil && p.explicitTx != p.tx {
		explicitHex = hex.EncodeToString(p.explicitTx.Serialize())
	}
	return &store.PendingTransfer{
		ID: id, TxHex: hex.EncodeToString(p.tx.Serialize()), ExplicitTxHex: explicitHex,
		AssetID: p.asset.ID, SenderAID: p.senderAID, Atoms: p.atoms,
		Enclave: p.enclave, Sighashes: sh, UserPub: hex.EncodeToString(p.userPub[:]),
		FeeMode: p.feeMode, PaymentInputs: p.paymentInputs, Created: p.created,
	}
}

// loadPendingRecord rebuilds an in-memory build from its persisted form,
// re-fetching the asset from the registry. It is the restart-survival path.
func (s *Server) loadPendingRecord(rec *store.PendingTransfer) (*pendingTransfer, error) {
	tx, err := elements.DeserializeTx(mustHexBytes(rec.TxHex))
	if err != nil {
		return nil, fmt.Errorf("decode pending tx: %w", err)
	}
	explicitTx := tx
	if rec.ExplicitTxHex != "" {
		explicitTx, err = elements.DeserializeTx(mustHexBytes(rec.ExplicitTxHex))
		if err != nil {
			return nil, fmt.Errorf("decode pending explicit tx: %w", err)
		}
	}
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[rec.AssetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		return nil, fmt.Errorf("asset %s no longer registered", rec.AssetID)
	}
	sighashes := make([][32]byte, len(rec.Sighashes))
	for i, h := range rec.Sighashes {
		b := mustHexBytes(h)
		if len(b) != 32 {
			return nil, fmt.Errorf("bad stored sighash")
		}
		copy(sighashes[i][:], b)
	}
	return &pendingTransfer{
		tx: tx, explicitTx: explicitTx, asset: asset, senderAID: rec.SenderAID, atoms: rec.Atoms,
		enclave: rec.Enclave, sighashes: sighashes, paymentInputs: rec.PaymentInputs,
		userPub: elements.MustHex32(rec.UserPub), created: rec.Created, feeMode: rec.FeeMode,
	}, nil
}

// takePending consumes a pending build once: it removes the id from both the
// in-memory cache and the persisted store, returning the reconstructed build.
// The delete-before-use guarantees a completed or replayed id can never be
// settled twice (the M5 idempotency invariant, now restart-durable).
func (s *Server) takePending(id string) (*pendingTransfer, bool) {
	s.mu.Lock()
	p, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if ok {
		_ = s.st.DeletePendingTransfer(id)
		return p, true
	}
	rec, has := s.st.GetPendingTransfer(id)
	if !has {
		return nil, false
	}
	_ = s.st.DeletePendingTransfer(id)
	p, err := s.loadPendingRecord(rec)
	if err != nil {
		return nil, false
	}
	return p, true
}

func (s *Server) handleTransferComplete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Sigs map[string]string `json:"sigs"` // enclave input index (decimal string) -> 64-byte schnorr sig hex
		// PaymentTx (OA-4) is the caller's own tx, identical in body to the built
		// tx, whose payment-input witnesses the caller filled with its wallet. The
		// server lifts only those witnesses; the tx body is pinned by txid so the
		// caller cannot alter amounts or destinations. Absent for a no-payment
		// transfer (the M5 flow).
		PaymentTx string `json:"payment_tx,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	p, ok := s.takePending(id)
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

	// OA-4: merge the caller's payment-input witnesses. The caller signed those
	// ordinary inputs with its own wallet and returns a tx identical in body to
	// the build. Pin the body by txid (which excludes witnesses) so a tampered
	// amount or destination is rejected, then lift only the payment inputs'
	// witness stacks into the build the server will co-sign and broadcast.
	if len(p.paymentInputs) > 0 {
		if req.PaymentTx == "" {
			httpErr(w, 400, "payment_tx required: this transfer carries a payment leg")
			return
		}
		payTx, err := elements.DeserializeTx(mustHexBytes(req.PaymentTx))
		if err != nil {
			httpErr(w, 400, "payment_tx: %v", err)
			return
		}
		if payTx.TxID() != p.tx.TxID() {
			httpErr(w, 400, "payment_tx body does not match the built transaction")
			return
		}
		payTx.NormalizeWitness()
		p.tx.NormalizeWitness()
		for _, idx := range p.paymentInputs {
			if idx >= len(payTx.InWit) || len(payTx.InWit[idx].ScriptWitness) == 0 {
				httpErr(w, 400, "payment_tx is missing a signature for payment input %d", idx)
				return
			}
			p.tx.InWit[idx].ScriptWitness = payTx.InWit[idx].ScriptWitness
		}
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
	// Policy runs on the pre-blind (explicit) tx, which has readable amounts,
	// assets and destinations; for a transparent asset it is the same tx.
	policyTx := p.explicitTx
	if policyTx == nil {
		policyTx = p.tx
	}
	if err := s.checkTransfer(policyTx, p.asset, sender, atomsOut); err != nil {
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
	if asset.Confidential {
		httpErr(w, 400, "confidential assets must use the hosted transfer flow (POST /v1/transfers); the server blinds the transaction")
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
	// Containment: every enclave input of this asset must be claimed. Resolve the
	// enclave scriptPubKey of every registered user for this asset, then refuse
	// any UNCLAIMED input landing on one (a co-sign hiding someone else's enclave
	// coins of the same asset in the same tx). Additive: a legitimate cosign, in
	// which all such inputs are claimed, resolves no unclaimed enclave input.
	enclaveSpks := map[string]bool{}
	s.st.View(func(st *store.State) {
		for _, u := range st.Users {
			cp := *u
			tree, err := s.treeFor(&cp, asset)
			if err == nil {
				enclaveSpks[hex.EncodeToString(tree.ScriptPubKey())] = true
			}
		}
	})
	for idx := range tx.In {
		if claimed[idx] {
			continue
		}
		if enclaveSpks[hex.EncodeToString(spent[idx].ScriptPubKey)] {
			logRefusal("cosign", s.st, map[string]any{"sender": sender.AID, "asset": asset.ID, "reason": "unclaimed enclave input"})
			httpErr(w, 403, "input %d is an unclaimed enclave output of this asset", idx)
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
