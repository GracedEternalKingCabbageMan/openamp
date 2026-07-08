package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
)

// Confidential-asset support. Sequentia is transparent by default and
// confidentiality is opt-in per asset; for a governed asset the policy server
// holds the blinding keys (so the issuer always sees who owns what) while
// outside observers see nothing. No confidential-transaction crypto is
// reimplemented here: the node's tested CT machinery does the blinding and a
// node watch wallet (holding the blinding keys) does the unblinding.

const watchWalletName = "openampd-watch"

var watchOnce sync.Once

// watchClient returns the (lazily created) client for the node watch wallet
// that holds the enclave blinding keys.
func (s *Server) watchClient() (*rpc.Client, error) {
	var initErr error
	watchOnce.Do(func() {
		// Create as a blank, private-key-disabled wallet, then keep it loaded.
		if err := s.node.CreateWallet(watchWalletName, true, true); err != nil {
			// createwallet fails if it already exists on disk; try to load.
			if lerr := s.node.LoadWallet(watchWalletName); lerr != nil && !rpc.IsRPCError(lerr, "already loaded") {
				initErr = fmt.Errorf("watch wallet: create=%v load=%v", err, lerr)
				return
			}
		}
	})
	if initErr != nil {
		return nil, initErr
	}
	c, err := rpc.New(s.node.WalletURL(watchWalletName), s.node.Auth())
	if err != nil {
		return nil, err
	}
	return c, nil
}

// blindMaster returns the server's master blinding secret (per install),
// generating and persisting it on first use.
func (s *Server) blindMaster() ([]byte, error) {
	keys, err := s.st.LoadKeys()
	if err != nil {
		return nil, err
	}
	if h, ok := keys["blind-master"]; ok {
		return hex.DecodeString(h)
	}
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		return nil, err
	}
	if err := s.st.SaveKey("blind-master", hex.EncodeToString(m)); err != nil {
		return nil, err
	}
	return m, nil
}

// blindingKey derives the deterministic blinding keypair for a (holder, asset)
// enclave: priv = SHA256(master || assetID || holderXonly), pub = priv*G
// (compressed). Deterministic so the server can always re-derive and re-import.
func (s *Server) blindingKey(assetID string, holderXonly [32]byte) (priv []byte, pubCompressed []byte, err error) {
	master, err := s.blindMaster()
	if err != nil {
		return nil, nil, err
	}
	h := sha256.New()
	h.Write(master)
	h.Write([]byte("openamp-blind-v1"))
	h.Write([]byte(assetID))
	h.Write(holderXonly[:])
	sum := h.Sum(nil)
	sk, pk := btcec.PrivKeyFromBytes(sum)
	return sk.Serialize(), pk.SerializeCompressed(), nil
}

// confidentialEnclaveAddress builds the blech32 confidential address for an
// enclave scriptPubKey and a blinding public key.
func (s *Server) confidentialEnclaveAddress(enclaveSpkHex, blindingPubHex string) (string, error) {
	unconf, err := s.node.AddressForScript(enclaveSpkHex)
	if err != nil {
		return "", fmt.Errorf("enclave address: %w", err)
	}
	return s.node.CreateBlindedAddress(unconf, blindingPubHex)
}

// importConfidentialEnclave makes the watch wallet track a confidential enclave
// address and unblind its UTXOs. Idempotent.
func (s *Server) importConfidentialEnclave(enclaveSpkHex string, blindingPriv []byte, blindingPubHex string) error {
	w, err := s.watchClient()
	if err != nil {
		return err
	}
	confAddr, err := s.confidentialEnclaveAddress(enclaveSpkHex, blindingPubHex)
	if err != nil {
		return err
	}
	// Track the script (watch-only) and associate the blinding key so the
	// wallet can unblind UTXOs paid to it.
	if err := w.ImportAddress(enclaveSpkHex, "openamp-enclave", false); err != nil &&
		!rpc.IsRPCError(err, "already") {
		return fmt.Errorf("importaddress: %w", err)
	}
	if err := w.ImportBlindingKey(confAddr, hex.EncodeToString(blindingPriv)); err != nil &&
		!rpc.IsRPCError(err, "already") {
		return fmt.Errorf("importblindingkey: %w", err)
	}
	return nil
}

// confidentialUTXOs returns the watch wallet's unblinded UTXOs for a given
// enclave scriptPubKey and asset.
func (s *Server) confidentialUTXOs(enclaveSpkHex, assetID string) ([]rpc.ConfUnspent, error) {
	w, err := s.watchClient()
	if err != nil {
		return nil, err
	}
	all, err := w.ListUnspentAll()
	if err != nil {
		return nil, err
	}
	var out []rpc.ConfUnspent
	for _, u := range all {
		if u.ScriptPubKey == enclaveSpkHex && u.Asset == assetID {
			out = append(out, u)
		}
	}
	return out, nil
}

const zeroBlinder = "0000000000000000000000000000000000000000000000000000000000000000"

// blindTx blinds a raw transaction: it gathers each input's amount, asset and
// blinders from the demo wallet (fee/funding inputs) and the watch wallet
// (enclave inputs), then runs the node's rawblindrawtransaction. Outputs that
// carry a blinding pubkey (nonce) are blinded; the transaction must have at
// least two such outputs. Returns the blinded transaction, deserialized.
func (s *Server) blindTx(tx *elements.Tx) (*elements.Tx, error) {
	idx := map[string]rpc.ConfUnspent{}
	sources := []*rpc.Client{s.wallet}
	if wc, err := s.watchClient(); err == nil {
		sources = append(sources, wc)
	}
	for _, c := range sources {
		us, err := c.ListUnspentAll()
		if err != nil {
			return nil, fmt.Errorf("list utxos for blinding: %w", err)
		}
		for _, u := range us {
			idx[fmt.Sprintf("%s:%d", u.TxID, u.Vout)] = u
		}
	}
	var amountBlinders, assets, assetBlinders []string
	var amounts []float64
	for i, in := range tx.In {
		key := fmt.Sprintf("%s:%d", displayHash(in.Prevout.Hash), in.Prevout.N)
		u, ok := idx[key]
		if !ok {
			return nil, fmt.Errorf("input %d (%s) not found in demo/watch wallets for blinding", i, key)
		}
		ab := u.AmountBlinder
		if ab == "" {
			ab = zeroBlinder
		}
		sb := u.AssetBlinder
		if sb == "" {
			sb = zeroBlinder
		}
		amountBlinders = append(amountBlinders, ab)
		amounts = append(amounts, u.Amount)
		assets = append(assets, u.Asset)
		assetBlinders = append(assetBlinders, sb)
	}
	blindedHex, err := s.wallet.RawBlindRawTransaction(hex.EncodeToString(tx.Serialize()),
		amountBlinders, amounts, assets, assetBlinders, false)
	if err != nil {
		return nil, fmt.Errorf("rawblindrawtransaction: %w", err)
	}
	bt, err := elements.DeserializeTx(mustHexBytes(blindedHex))
	if err != nil {
		return nil, fmt.Errorf("decode blinded tx: %w", err)
	}
	// The codec must round-trip the blinded tx (rangeproofs + surjection proofs
	// in the output witnesses) exactly, since we re-serialize it to add input
	// witnesses before broadcast.
	if got := hex.EncodeToString(bt.Serialize()); got != blindedHex {
		return nil, fmt.Errorf("blinded tx codec round-trip mismatch (len got=%d want=%d)", len(got), len(blindedHex))
	}
	return bt, nil
}

// confWalletOutput builds an output paying `sats` of the fee asset to a fresh
// CONFIDENTIAL wallet address (so it blinds and counts toward the >=2 blinded
// outputs a blinded transaction needs).
func (s *Server) confWalletOutput(sats uint64) (*elements.TxOut, error) {
	addr, err := s.wallet.GetNewAddress()
	if err != nil {
		return nil, err
	}
	info, err := s.wallet.GetAddressInfo(addr)
	if err != nil {
		return nil, err
	}
	if info.ConfidentialKey == "" {
		return nil, fmt.Errorf("wallet address is not confidential (need -blindedaddresses=1)")
	}
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	return &elements.TxOut{
		Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(sats),
		Nonce: mustHexBytes(info.ConfidentialKey), ScriptPubKey: mustHexBytes(info.ScriptPubKey),
	}, nil
}

// enclaveConfNonce returns the blinding public key (as an output nonce) for a
// holder's confidential enclave, and ensures the watch wallet tracks it.
func (s *Server) enclaveConfNonce(assetID string, holderXonly [32]byte, enclaveSpkHex string) ([]byte, error) {
	priv, pub, err := s.blindingKey(assetID, holderXonly)
	if err != nil {
		return nil, err
	}
	if err := s.importConfidentialEnclave(enclaveSpkHex, priv, hex.EncodeToString(pub)); err != nil {
		return nil, err
	}
	return pub, nil
}

// utxoUnspent verifies a wallet-listed utxo is actually unspent in the global
// UTXO set. Guards against stale entries a wallet may still list for outputs
// another wallet spent (e.g. anyonecanspend outputs on regtest).
func (s *Server) utxoUnspent(txid string, vout uint32) bool {
	res, err := s.node.GetTxOut(txid, vout, true)
	return err == nil && res != nil
}
