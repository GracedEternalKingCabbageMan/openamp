package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Per-transfer confidentiality support. Sequentia is transparent by default
// and confidentiality is opt-in PER CALL: an asset is never "a confidential
// asset" — any holder may receive or move ANY restricted asset confidentially
// in a given transaction (issue/transfer/reissue take "confidential": true;
// GET /address takes ?confidential=1). The policy server derives and holds the
// per-(holder, asset) blinding keys, so the issuer always sees every holding
// through the watch wallet; confidentiality is privacy from outsiders only.
// No confidential-transaction crypto is reimplemented here: the node's tested
// CT machinery does the blinding and a node watch wallet (holding the blinding
// keys) does the unblinding.

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

const zeroBlinder = "0000000000000000000000000000000000000000000000000000000000000000"

// blindTx blinds a raw transaction: it gathers each input's amount, asset and
// blinders from the demo wallet (fee/funding inputs) and the watch wallet
// (enclave inputs), then runs the node's rawblindrawtransaction. Outputs that
// carry a blinding pubkey (nonce) are blinded. Returns the blinded transaction,
// deserialized.
//
// Blinded inputs and explicit outputs — what the node actually requires: a
// transaction spending a blinded input can NEVER have all-explicit outputs.
// Consensus checks the value balance homomorphically on the Pedersen
// commitments themselves (explicit values enter as zero-blinder commitments),
// so the input's non-zero blinding factors must be absorbed by at least one
// blinded OUTPUT whose blinder rawblindrawtransaction computes to balance;
// "supplying the input blinders to the node" is not a mechanism that exists at
// validation time — the blinders are only inputs to rawblindrawtransaction,
// which is why every build touching a blinded input must route through here
// (with a blinded output to balance into), while a build over purely explicit
// inputs with no blinded outputs skips blinding entirely. With no blinded
// inputs the transaction needs >=2 blinded outputs (a single one would get a
// forced, trivially-unwindable blinder and the node refuses); with a blinded
// input present, one blinded output suffices.
//
// Every input's amount/asset/blinders must be known: blinded inputs come from
// the demo or watch wallet (which unblinds imported enclave scripts); an
// explicit input unknown to either wallet (e.g. a never-imported enclave UTXO)
// is resolved from its prevout bytes, since an explicit prevout needs no
// secret knowledge (zero blinders).
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
	var spent []*elements.SpentOutput // lazily resolved prevouts (explicit-input fallback)
	var amountBlinders, assets, assetBlinders []string
	var amounts []float64
	for i, in := range tx.In {
		key := fmt.Sprintf("%s:%d", displayHash(in.Prevout.Hash), in.Prevout.N)
		u, ok := idx[key]
		if !ok {
			// Fallback: resolve the prevout. Only an EXPLICIT prevout can be used
			// this way; a blinded prevout without wallet knowledge has no
			// recoverable blinders.
			if spent == nil {
				var err error
				if spent, err = s.spentOutputs(tx); err != nil {
					return nil, fmt.Errorf("resolve prevouts for blinding: %w", err)
				}
			}
			o := spent[i]
			amt, okv := elements.ExplicitValueAmount(o.Value)
			if !okv || len(o.Asset) != 33 || o.Asset[0] != 1 {
				return nil, fmt.Errorf("input %d (%s): blinded prevout not found in demo/watch wallets (no blinders available)", i, key)
			}
			var assetInternal [32]byte
			copy(assetInternal[:], o.Asset[1:]) // commitment bytes are internal order
			u = rpc.ConfUnspent{Amount: float64(amt) / 1e8, Asset: displayHash(assetInternal)}
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
// per-call blinded (blech32) wallet address, so it blinds and counts toward the
// >=2 blinded outputs a blinded transaction needs. OA-8: the per-call blinded
// address forces blinding for this output even on a wallet running
// -blindedaddresses=0, so confidential transfers and burns never depend on
// node000's default-blinding flag.
func (s *Server) confWalletOutput(sats uint64) (*elements.TxOut, error) {
	nonce, spk, err := s.blindedWalletOutput()
	if err != nil {
		return nil, err
	}
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	return &elements.TxOut{
		Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(sats),
		Nonce: nonce, ScriptPubKey: spk,
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

// startWatchReconcile launches the watch-wallet rescan reconcile (W-5c) in a
// goroutine, at most once per process start. It never blocks request handling:
// every import it performs is the same idempotent import the request paths do
// on demand, so a request racing the reconcile just does the work first.
func (s *Server) startWatchReconcile() {
	s.watchReconcile.Do(func() { go s.reconcileWatchWallet() })
}

// reconcileWatchWallet re-imports the enclave script + blinding key of EVERY
// registered (holder, asset) pair into the watch wallet, then runs ONE
// rescanblockchain pass. Confidentiality is per transfer, so any enclave of
// any asset may hold blinded UTXOs — the legacy per-asset Confidential flag is
// deliberately not consulted. The request paths import with rescan=false (to
// keep them fast), so an enclave whose key arrived after its funds — a
// restored data directory, a receipt while the daemon was down — holds UTXOs
// the wallet has never seen; the rescan surfaces them. We cannot tell which
// imports were "first" imports, so the pass runs whenever any pair exists at
// all: it is read-only against the chain and bounded to once per process start
// by startWatchReconcile.
func (s *Server) reconcileWatchWallet() {
	type pair struct {
		assetID string
		spkHex  string
		holderX [32]byte
	}
	var pairs []pair
	s.st.View(func(st *store.State) {
		for _, a := range st.Assets {
			for _, u := range st.Users {
				tree, err := s.treeFor(u, a)
				if err != nil {
					continue
				}
				pairs = append(pairs, pair{a.ID, hex.EncodeToString(tree.ScriptPubKey()), elements.MustHex32(u.Pubkeys[0])})
			}
		}
	})
	if len(pairs) == 0 {
		return // no enclaves registered: nothing to import or rescan
	}
	imported := 0
	for _, p := range pairs {
		priv, pub, err := s.blindingKey(p.assetID, p.holderX)
		if err != nil {
			log.Printf("watch reconcile: blinding key for asset %s: %v", p.assetID, err)
			continue
		}
		if err := s.importConfidentialEnclave(p.spkHex, priv, hex.EncodeToString(pub)); err != nil {
			log.Printf("watch reconcile: import enclave %s (asset %s): %v", p.spkHex, p.assetID, err)
			continue
		}
		imported++
	}
	w, err := s.watchClient()
	if err != nil {
		log.Printf("watch reconcile: watch wallet unavailable, rescan skipped: %v", err)
		return
	}
	if err := w.RescanBlockchain(); err != nil {
		log.Printf("watch reconcile: rescanblockchain: %v", err)
		return
	}
	log.Printf("watch reconcile: re-imported %d/%d enclaves, rescan complete", imported, len(pairs))
}

// utxoUnspent verifies a wallet-listed utxo is actually unspent in the global
// UTXO set. Guards against stale entries a wallet may still list for outputs
// another wallet spent (e.g. anyonecanspend outputs on regtest).
func (s *Server) utxoUnspent(txid string, vout uint32) bool {
	res, err := s.node.GetTxOut(txid, vout, true)
	return err == nil && res != nil
}
