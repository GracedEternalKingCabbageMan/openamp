package server

import (
	"encoding/hex"
	"net/http"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
)

// Blinded-change consolidation. Confidential builds pay the server's fee
// change to per-call blinded (blech32) addresses, and the fee pickers refuse
// blinded coins (a blinded fee input would unbalance a fully explicit
// transaction), so a busy server slowly converts its whole fee float into
// coins it cannot spend as fees. Consolidation sweeps that blinded change back
// into one EXPLICIT coin: manually via POST /v1/issuer/consolidate, and
// automatically when a fee picker comes up empty while blinded fee-asset coins
// exist.

// consolidateMaxInputs bounds one consolidation's input count; a larger backlog
// drains over successive consolidations.
const consolidateMaxInputs = 20

// dustReserve is the amount kept on the one blinded output a consolidation
// must carry (blinded inputs can never balance into all-explicit outputs; see
// blindTx). 2*FeeSats keeps it above any plausible dust floor while leaving
// the overwhelming majority of the swept value explicit.
func (s *Server) dustReserve() uint64 { return 2 * s.cfg.FeeSats }

// pickFeeUTXOMin selects one spendable EXPLICIT fee-asset coin worth more than
// minSats, verified unspent in the global UTXO set (a wallet can list coins
// another wallet spent).
func (s *Server) pickFeeUTXOMin(minSats uint64) (*rpcUnspentLite, error) {
	feeUtxos, err := s.wallet.ListUnspent(1, s.cfg.FeeAsset)
	if err != nil {
		return nil, err
	}
	for _, u := range feeUtxos {
		if u.Spendable && u.Explicit() && u.Asset == s.cfg.FeeAsset &&
			sats(u.Amount) > minSats && s.utxoUnspent(u.TxID, u.Vout) {
			return &rpcUnspentLite{u.TxID, u.Vout, sats(u.Amount)}, nil
		}
	}
	return nil, nil
}

// feeUTXO is THE fee picker for every build path. When no explicit fee coin
// covers minSats but blinded fee-asset coins exist, it consolidates them once
// and funds the caller directly from the consolidation's explicit output
// (0-conf chaining from the server's own change), so the original operation
// simply proceeds. A wallet with no blinded fee coins never consolidates; the
// nil,nil result is the caller's usual "no fee funds" refusal.
func (s *Server) feeUTXO(minSats uint64) (*rpcUnspentLite, error) {
	coin, err := s.pickFeeUTXOMin(minSats)
	if err != nil || coin != nil {
		return coin, err
	}
	return s.consolidateBlindedFees(minSats)
}

// blindedFeeCoins lists the demo wallet's blinded fee-asset coins.
func (s *Server) blindedFeeCoins() ([]rpc.ConfUnspent, error) {
	all, err := s.wallet.ListUnspentAll()
	if err != nil {
		return nil, err
	}
	var coins []rpc.ConfUnspent
	for _, u := range all {
		if u.Asset == s.cfg.FeeAsset && u.Blinded() && u.Spendable {
			coins = append(coins, u)
			if len(coins) == consolidateMaxInputs {
				break
			}
		}
	}
	return coins, nil
}

// consolidateBlindedFees builds, gates and broadcasts one consolidation:
// inputs are up to 20 blinded fee-asset wallet coins; outputs are one EXPLICIT
// output of (sum - fee - dustReserve) to a fresh wallet address, one blinded
// per-call blech32 output carrying dustReserve (the balancing output the
// blinded inputs require), and the fee. Returns the explicit output (vout 0)
// as a spendable coin, or nil,nil when there is nothing to consolidate or the
// blinded balance cannot yield an explicit coin above minSats. Serialized so
// concurrent fee-picker failures consolidate once, not once each.
func (s *Server) consolidateBlindedFees(minSats uint64) (*rpcUnspentLite, error) {
	s.consolidateMu.Lock()
	defer s.consolidateMu.Unlock()

	coins, err := s.blindedFeeCoins()
	if err != nil {
		return nil, err
	}
	if len(coins) == 0 {
		return nil, nil
	}
	var sum uint64
	for _, u := range coins {
		sum += sats(u.Amount)
	}
	reserve := s.cfg.FeeSats + s.dustReserve()
	if sum <= reserve || sum-reserve <= minSats {
		return nil, nil // too small to yield a usable explicit coin
	}
	explicitSats := sum - reserve

	addr, err := s.wallet.GetNewAddress()
	if err != nil {
		return nil, err
	}
	spkHex, err := s.addressScriptPubKey(addr)
	if err != nil {
		return nil, err
	}
	dustNonce, dustSpk, err := s.blindedWalletOutput()
	if err != nil {
		return nil, err
	}

	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	tx := &elements.Tx{Version: 2}
	for _, u := range coins {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(u.TxID), N: u.Vout}})
	}
	tx.Out = append(tx.Out,
		// vout 0: the majority-explicit sweep destination.
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(explicitSats),
			Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(spkHex)},
		// vout 1: the one blinded output the blinded inputs balance into.
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.dustReserve()),
			Nonce: dustNonce, ScriptPubKey: dustSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	tx.NormalizeWitness()

	blinded, err := s.blindTx(tx)
	if err != nil {
		return nil, err
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(blinded.Serialize()))
	if err != nil {
		return nil, err
	}
	if !signed.Complete {
		return nil, &PolicyRefusal{Reason: "consolidation signing incomplete"}
	}
	// Safety gate (W-1): a consolidation the node would reject spends nothing.
	if err := s.mempoolGate("consolidate", signed.Hex, map[string]any{"inputs": len(coins)}); err != nil {
		return nil, err
	}
	// The txid comes from the signed bytes, not the node's reply, so the
	// returned outpoint is correct even if the broadcast response is lost.
	signedTx, err := elements.DeserializeTx(mustHexBytes(signed.Hex))
	if err != nil {
		return nil, err
	}
	txid := signedTx.TxID()
	if _, err := s.wallet.SendRawTransaction(signed.Hex); err != nil {
		return nil, err
	}
	s.st.AppendLog("consolidate", map[string]any{
		"txid": txid, "inputs": len(coins), "explicit_atoms": explicitSats, "dust_reserve": s.dustReserve(),
	})
	return &rpcUnspentLite{txid, 0, explicitSats}, nil
}

// handleConsolidate is the manual trigger: sweep blinded fee-asset change now.
func (s *Server) handleConsolidate(w http.ResponseWriter, r *http.Request) {
	coin, err := s.consolidateBlindedFees(0)
	if err != nil {
		httpErr(w, 502, "consolidate: %v", err)
		return
	}
	if coin == nil {
		httpErr(w, 409, "nothing to consolidate: no blinded fee-asset coins (or their total cannot yield an explicit coin)")
		return
	}
	httpJSON(w, map[string]any{"txid": coin.txid, "explicit_atoms": coin.sats})
}
