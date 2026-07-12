package server

import (
	"encoding/hex"
	"net/http"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
)

// OA-6: reissue MORE of an existing restricted asset into a target enclave, for
// a Depository-Receipt programme whose circulating supply must change for real.
//
// The critical node hazard (see the reissuance memory): a reissuance spent from
// an UNBLINDED reissuance token is a phantom, invalid transaction, because the
// issuance's asset-blinding-nonce field would be zero and consensus then reads
// the input as a NEW issuance rather than a reissuance. So the token MUST be
// blinded first; its non-zero asset blinding factor becomes the reissuance
// nonce. This file re-blinds the token when needed (a per-call blech32 address,
// never the node's -blindedaddresses flag), then hand-builds the reissuance and
// only broadcasts it after testmempoolaccept accepts it, so a malformed
// reissuance can never spend funds. A caller request_id makes the mint
// idempotent: a retry returns the same txid and never double-mints.

// reissueParams are the fully resolved pieces of a reissuance, kept explicit so
// the transaction assembly is a pure function the tests can drive without a node.
type reissueParams struct {
	assetDisplay    [32]byte // display-order asset id
	entropyInternal [32]byte // final asset entropy (internal order)
	precision       uint64

	tokenTxid        string
	tokenVout        uint32
	tokenAbf         [32]byte // asset blinding factor of the spent token (non-zero)
	tokenAtoms       uint64   // token amount to re-output (keeps the token alive)
	tokenChangeNonce []byte   // blinding pubkey so the re-output token stays blinded
	tokenChangeSpk   []byte

	reissueAtoms uint64 // newly minted units
	enclaveSpk   []byte // target enclave scriptPubKey

	feeTxid        string
	feeVout        uint32
	feeChangeSats  uint64
	feeChangeNonce []byte // blinding pubkey (>=2 blinded outputs for a blindable tx)
	feeChangeSpk   []byte

	feeAssetDisplay [32]byte
	feeSats         uint64
}

// buildReissuanceTx assembles the pre-blind (explicit) reissuance transaction.
// The token input carries the Elements reissuance issuance: a non-zero nonce
// (the token's asset blinding factor) marks it as a reissuance rather than a new
// issuance, the entropy re-derives the asset id, the amount is the explicit
// newly minted quantity, and the inflation-keys field is null (a reissuance
// mints no new tokens). The newly minted units go to the target enclave; the
// token is re-output to a blinded address so it survives for the next mint.
func buildReissuanceTx(p reissueParams) *elements.Tx {
	tx := &elements.Tx{Version: 2}

	// Token input, bearing the reissuance issuance.
	tx.In = append(tx.In, &elements.TxIn{
		Prevout: elements.OutPoint{Hash: internalHash(p.tokenTxid), N: p.tokenVout},
		Issuance: &elements.AssetIssuance{
			Nonce:         p.tokenAbf,                             // non-zero ⇒ reissuance
			Entropy:       p.entropyInternal,                      // final asset entropy
			Amount:        elements.ExplicitValue(p.reissueAtoms), // explicit minted amount
			InflationKeys: []byte{0},                              // null: no new tokens
			Denomination:  p.precision,
		},
	})
	// Fee funding input (a wallet coin).
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(p.feeTxid), N: p.feeVout}})

	// Minted units to the target enclave (explicit; a transparent asset).
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(p.assetDisplay), Value: elements.ExplicitValue(p.reissueAtoms),
		Nonce: elements.NullNonce(), ScriptPubKey: p.enclaveSpk,
	})
	// Re-output the reissuance token to a blinded address so it stays blinded and
	// reusable for the next reissuance.
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(p.assetDisplay), Value: elements.ExplicitValue(p.tokenAtoms),
		Nonce: p.tokenChangeNonce, ScriptPubKey: p.tokenChangeSpk,
	})
	// Blinded fee change (gives the >=2 blinded outputs a blindable tx needs).
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(p.feeAssetDisplay), Value: elements.ExplicitValue(p.feeChangeSats),
		Nonce: p.feeChangeNonce, ScriptPubKey: p.feeChangeSpk,
	})
	// Fee output.
	tx.Out = append(tx.Out, &elements.TxOut{
		Asset: elements.ExplicitAsset(p.feeAssetDisplay), Value: elements.ExplicitValue(p.feeSats),
		Nonce: elements.NullNonce(), ScriptPubKey: nil,
	})
	tx.NormalizeWitness()
	return tx
}

// blindedWalletOutput resolves a fresh per-call blinded (blech32) wallet
// destination: its blinding pubkey (used as an output nonce) and its
// unconfidential scriptPubKey. It forces blinding for this output without
// touching the node's -blindedaddresses flag.
func (s *Server) blindedWalletOutput() (nonce []byte, spk []byte, err error) {
	addr, err := s.wallet.GetNewBlindedAddress()
	if err != nil {
		return nil, nil, err
	}
	info, err := s.wallet.GetAddressInfo(addr)
	if err != nil {
		return nil, nil, err
	}
	if info.ConfidentialKey == "" {
		return nil, nil, errNoBlinding
	}
	spkHex := info.ScriptPubKey
	if info.Unconfidential != "" && info.Unconfidential != addr {
		if info2, err := s.wallet.GetAddressInfo(info.Unconfidential); err == nil && info2.ScriptPubKey != "" {
			spkHex = info2.ScriptPubKey
		}
	}
	return mustHexBytes(info.ConfidentialKey), mustHexBytes(spkHex), nil
}

var errNoBlinding = &PolicyRefusal{Reason: "wallet returned no blinding key for a per-call blinded address"}

// pickFeeUTXO selects one spendable fee-asset coin large enough to fund a fee.
func (s *Server) pickFeeUTXO() (*rpcUnspentLite, error) {
	feeUtxos, err := s.wallet.ListUnspent(1, s.cfg.FeeAsset)
	if err != nil {
		return nil, err
	}
	for _, u := range feeUtxos {
		if u.Spendable && sats(u.Amount) > s.cfg.FeeSats*2 {
			return &rpcUnspentLite{u.TxID, u.Vout, sats(u.Amount)}, nil
		}
	}
	return nil, nil
}

// tokenUTXO locates the reissuance token in the server wallet. The token is a
// spendable coin of the demo wallet (issuance paid it there, and a re-blind
// re-outputs it to a demo-wallet blinded address), so the demo wallet lists it
// with its blinders when confidential.
func (s *Server) tokenUTXO(tokenID string) (*rpc.ConfUnspent, error) {
	us, err := s.wallet.ListUnspentAll()
	if err != nil {
		return nil, err
	}
	for i := range us {
		if us[i].Asset == tokenID {
			cp := us[i]
			return &cp, nil
		}
	}
	return nil, nil
}

// handleReissue mints more of an existing restricted asset into a target enclave.
func (s *Server) handleReissue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset     string `json:"asset"`
		TargetAID string `json:"target_aid"`
		Atoms     uint64 `json:"atoms"`
		RequestID string `json:"request_id"` // idempotency key; a retry returns the same txid
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Atoms == 0 {
		httpErr(w, 400, "atoms must be greater than zero")
		return
	}
	if req.RequestID == "" {
		httpErr(w, 400, "request_id is required (idempotency key; a retry returns the same reissue txid)")
		return
	}
	targetTree, _, asset, err := s.enclaveFor(req.TargetAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	if asset.Entropy == "" || asset.Token == "" {
		httpErr(w, 501, "reissuance needs an asset issued with OA-6 (its entropy and token id were not recorded)")
		return
	}

	// Idempotency: a completed reissue for this request_id returns its txid.
	if txid, ok := s.st.GetReissue(req.RequestID); ok {
		httpJSON(w, map[string]any{"reissue_txid": txid, "status": "done", "idempotent": true})
		return
	}
	// Crash-window recovery: a reservation exists (the tx was built + signed and its
	// txid fixed) but MarkReissue was lost. Rebroadcast the IDENTICAL stored tx: the
	// node dedupes (same txid), and if the first reissuance already confirmed the
	// rebroadcast is a harmless no-op. Either way the mint is the same single tx, so
	// this can never mint a second time. Then complete the idempotency record.
	if pr, ok := s.st.GetPendingReissue(req.RequestID); ok {
		if _, err := s.wallet.SendRawTransaction(pr.SignedHex); err != nil {
			// Already-in-mempool / already-in-chain / spent-inputs all mean the
			// reserved tx is (or was) live; the reserved txid is authoritative.
			s.st.AppendLog("reissue-rebroadcast", map[string]any{"request_id": req.RequestID, "txid": pr.Txid, "note": err.Error()})
		}
		if err := s.st.MarkReissue(req.RequestID, pr.Txid); err != nil {
			httpErr(w, 500, "persist reissue: %v", err)
			return
		}
		httpJSON(w, map[string]any{"reissue_txid": pr.Txid, "status": "done", "idempotent": true})
		return
	}

	// Locate the reissuance token and ensure it is blinded before spending.
	tok, err := s.tokenUTXO(asset.Token)
	if err != nil {
		httpErr(w, 502, "token scan: %v", err)
		return
	}
	if tok == nil {
		httpErr(w, 409, "reissuance token not found in the server wallet")
		return
	}
	if !tok.Confidential || tok.AssetBlinder == "" || tok.AssetBlinder == zeroBlinder {
		// Re-blind first (the phantom-tx hazard). Broadcasts a token -> blinded
		// address move; the caller retries the same request_id once it is in the
		// wallet (0-conf is fine to chain from, nothing is final yet).
		reblindTxid, err := s.reblindToken(tok)
		if err != nil {
			httpErr(w, 502, "re-blind token: %v", err)
			return
		}
		s.st.AppendLog("reissue-reblind", map[string]any{"asset": asset.ID, "token": asset.Token, "txid": reblindTxid})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		httpJSON(w, map[string]any{
			"status": "reblinding", "reblind_txid": reblindTxid,
			"detail": "reissuance token is being blinded; retry with the same request_id once it confirms",
		})
		return
	}

	// Blinded token: assemble the reissuance.
	feeIn, err := s.pickFeeUTXO()
	if err != nil {
		httpErr(w, 502, "fee funding: %v", err)
		return
	}
	if feeIn == nil {
		httpErr(w, 503, "policy server has no fee funds")
		return
	}
	tokenNonce, tokenSpk, err := s.blindedWalletOutput()
	if err != nil {
		httpErr(w, 502, "token blinded output: %v", err)
		return
	}
	feeNonce, feeSpk, err := s.blindedWalletOutput()
	if err != nil {
		httpErr(w, 502, "fee blinded output: %v", err)
		return
	}

	p := reissueParams{
		assetDisplay:    elements.MustHex32(asset.ID),
		entropyInternal: internalHash(asset.Entropy),
		precision:       uint64(asset.Precision),
		tokenTxid:       tok.TxID, tokenVout: tok.Vout,
		tokenAbf: mustHex32Bytes(tok.AssetBlinder), tokenAtoms: sats(tok.Amount),
		tokenChangeNonce: tokenNonce, tokenChangeSpk: tokenSpk,
		reissueAtoms: req.Atoms, enclaveSpk: targetTree.ScriptPubKey(),
		feeTxid: feeIn.txid, feeVout: feeIn.vout,
		feeChangeSats: feeIn.sats - s.cfg.FeeSats, feeChangeNonce: feeNonce, feeChangeSpk: feeSpk,
		feeAssetDisplay: elements.MustHex32(s.cfg.FeeAsset), feeSats: s.cfg.FeeSats,
	}
	tx := buildReissuanceTx(p)

	// Blind the token-change and fee-change outputs via the node's tested CT
	// machinery; the minted enclave output stays explicit.
	blinded, err := s.blindTx(tx)
	if err != nil {
		httpErr(w, 500, "blind reissuance: %v", err)
		return
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(blinded.Serialize()))
	if err != nil {
		httpErr(w, 502, "sign: %v", err)
		return
	}
	if !signed.Complete {
		httpErr(w, 502, "reissuance signing incomplete: %+v", signed.Errors)
		return
	}
	// Safety gate: never broadcast a reissuance the node would reject. A malformed
	// reissuance (e.g. a mis-derived nonce) is refused here, spending nothing.
	ok, reason, err := s.wallet.TestMempoolAccept(signed.Hex)
	if err != nil {
		httpErr(w, 502, "testmempoolaccept: %v", err)
		return
	}
	if !ok {
		httpErr(w, 502, "reissuance rejected by the node (not broadcast): %s", reason)
		return
	}
	// Compute the txid deterministically from the signed tx and RESERVE the
	// request_id (the exact signed tx + txid) BEFORE broadcast. A DR mint regenerates
	// its own token input, so it has no UTXO-exhaustion backstop; this reservation is
	// the sole guard against a double-mint if we crash between broadcast and the
	// idempotency write. A retry rebroadcasts this identical tx (same txid).
	rawSigned, err := hex.DecodeString(signed.Hex)
	if err != nil {
		httpErr(w, 500, "decode signed reissuance: %v", err)
		return
	}
	signedTx, err := elements.DeserializeTx(rawSigned)
	if err != nil {
		httpErr(w, 500, "parse signed reissuance: %v", err)
		return
	}
	reissueTxid := signedTx.TxID()
	if err := s.st.ReserveReissue(req.RequestID, signed.Hex, reissueTxid); err != nil {
		httpErr(w, 500, "reserve reissue: %v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		httpErr(w, 502, "broadcast: %v", err)
		return
	}
	// Record so a retry short-circuits to the completed record (also clears the
	// pending reservation).
	if err := s.st.MarkReissue(req.RequestID, txid); err != nil {
		httpErr(w, 500, "persist reissue: %v", err)
		return
	}
	s.st.AppendLog("reissue", map[string]any{
		"asset": asset.ID, "target": req.TargetAID, "atoms": req.Atoms, "txid": txid,
	})
	httpJSON(w, map[string]any{
		"reissue_txid": txid, "status": "broadcast", "target_aid": req.TargetAID, "atoms": req.Atoms,
	})
}

// reblindToken moves the (unblinded) reissuance token to a fresh blinded wallet
// address, so its next spend carries a non-zero asset blinding factor. The token
// output and a fee-change output are blinded (the two blinded outputs a blindable
// tx needs); the wallet signs both its own inputs.
func (s *Server) reblindToken(tok *rpc.ConfUnspent) (string, error) {
	feeIn, err := s.pickFeeUTXO()
	if err != nil {
		return "", err
	}
	if feeIn == nil {
		return "", &PolicyRefusal{Reason: "policy server has no fee funds"}
	}
	tokenNonce, tokenSpk, err := s.blindedWalletOutput()
	if err != nil {
		return "", err
	}
	feeNonce, feeSpk, err := s.blindedWalletOutput()
	if err != nil {
		return "", err
	}
	tokenAssetID := elements.MustHex32(tok.Asset)
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	tx := &elements.Tx{Version: 2}
	tx.In = append(tx.In,
		&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(tok.TxID), N: tok.Vout}},
		&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feeIn.txid), N: feeIn.vout}},
	)
	tx.Out = append(tx.Out,
		&elements.TxOut{Asset: elements.ExplicitAsset(tokenAssetID), Value: elements.ExplicitValue(sats(tok.Amount)),
			Nonce: tokenNonce, ScriptPubKey: tokenSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.sats - s.cfg.FeeSats),
			Nonce: feeNonce, ScriptPubKey: feeSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	tx.NormalizeWitness()
	blinded, err := s.blindTx(tx)
	if err != nil {
		return "", err
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(blinded.Serialize()))
	if err != nil {
		return "", err
	}
	if !signed.Complete {
		return "", &PolicyRefusal{Reason: "re-blind signing incomplete"}
	}
	return s.wallet.SendRawTransaction(signed.Hex)
}

// mustHex32Bytes parses a 32-byte hex blinder; a short/empty value yields zeros
// (which the caller has already excluded before spending).
func mustHex32Bytes(h string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(h)
	if err == nil && len(b) == 32 {
		copy(out[:], b)
	}
	return out
}
