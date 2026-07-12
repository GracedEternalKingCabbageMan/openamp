// Package store is openampd's persistent state: a JSON document written
// atomically, suitable for testnet scale (a SQL backend can replace it
// behind the same interface later). Signing keys live in a separate
// 0600 file so the state document is safe to inspect and back up.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type User struct {
	AID        string   `json:"aid"`
	Pubkeys    []string `json:"pubkeys"` // x-only hex; [0] is the active enclave key (v0)
	Categories []string `json:"categories,omitempty"`
	Frozen     bool     `json:"frozen,omitempty"`
}

type VestingEntry struct {
	AID         string `json:"aid"`
	Atoms       uint64 `json:"atoms"`
	UntilHeight int64  `json:"until_height"`
}

// CategoryDeny refuses delivery to a recipient carrying a category whose token
// has Prefix as a prefix, until the chain reaches UntilHeight. It models a
// Reg S distribution-compliance window keyed by a jurisdiction prefix (e.g.
// Prefix "j:US" until height H). Only non-primary senders are bound by it.
type CategoryDeny struct {
	Prefix      string `json:"prefix"`
	UntilHeight int64  `json:"until_height"`
}

type Rules struct {
	// Recipient must hold one of these categories (empty = any registered user).
	AllowedCategories []string `json:"allowed_categories,omitempty"`
	// Max atoms a sender may move within the window (0 = no limit).
	VelocityWindowBlocks int64  `json:"velocity_window_blocks,omitempty"`
	VelocityMaxAtoms     uint64 `json:"velocity_max_atoms,omitempty"`
	// Max distinct holders with a nonzero balance (0 = no cap).
	HolderCap int `json:"holder_cap,omitempty"`
	// No transfers before this height (0 = none). Fee conversion during
	// lock-in follows ConvertDuringLockin.
	LockinUntilHeight   int64          `json:"lockin_until_height,omitempty"`
	ConvertDuringLockin bool           `json:"convert_during_lockin,omitempty"`
	Vesting             []VestingEntry `json:"vesting,omitempty"`
	// Flat conversion charge for issuer-bridged fees, in asset atoms.
	// Placeholder pricing until price-server integration.
	FeeConvertAtoms uint64 `json:"fee_convert_atoms,omitempty"`
	// Sender scoping (OA-3). When the transfer's sender AID is one of these,
	// LockinUntilHeight and CategoryDenies do NOT bind (so escrow/treasury
	// delivery to an investor works during a lockup). AllowedCategories, the
	// holder caps (global and per-category) and velocity still apply.
	PrimaryAIDs []string `json:"primary_aids,omitempty"`
	// Reg S style windows (OA-3). For a non-primary sender, refuse if any
	// recipient holds a category whose token has one of these prefixes while
	// height < UntilHeight.
	CategoryDenies []CategoryDeny `json:"category_denies,omitempty"`
	// Per exact category token holder caps (OA-3), e.g. EU per-member-state
	// caps. Like HolderCap but counts only distinct nonzero holders carrying
	// that category, including incoming recipients. Empty = no per-category cap.
	HolderCapsByCategory map[string]int `json:"holder_caps_by_category,omitempty"`
}

type Asset struct {
	ID           string          `json:"id"` // display hex
	Ticker       string          `json:"ticker"`
	Name         string          `json:"name"`
	Precision    int             `json:"precision"`
	Contract     json.RawMessage `json:"contract"`
	ContractHash string          `json:"contract_hash"` // display hex
	PolicyPub    string          `json:"policy_pub"`
	IssuerPub    string          `json:"issuer_pub"`
	// IssuerExternal marks an asset whose issuer key is the entity's own external
	// (browser) key rather than a server-held key (M9). Clawback then runs
	// two-phase: the server builds the L_claw sweep and the issuer signs it
	// externally, so the server never holds the issuer key for this asset. Absent
	// or false = the legacy server-held issuer key and the single-call clawback,
	// so records issued before M9 stay byte-compatible.
	IssuerExternal bool          `json:"issuer_external,omitempty"`
	IssuerAID    string          `json:"issuer_aid"`
	Clawback     bool            `json:"clawback"`
	BurnAllowed  bool            `json:"burn_allowed"`
	Confidential bool            `json:"confidential"`
	IssueTxid    string          `json:"issue_txid"`
	Rules        Rules           `json:"rules"`
	// Reissuance material (OA-6), recorded at issuance so a later DR mint can
	// re-derive the asset entropy and locate the reissuance token. Both are
	// display-hex. Absent on assets issued before OA-6 (reissue is refused for
	// them), so existing records are byte-compatible.
	Entropy string `json:"entropy,omitempty"` // final asset entropy
	Token   string `json:"token,omitempty"`   // reissuance token id
}

// TransferRecord supports velocity accounting; entries above a reorged-out
// height are re-marked unconfirmed by the follower.
type TransferRecord struct {
	Txid      string `json:"txid"`
	Asset     string `json:"asset"`
	SenderAID string `json:"sender_aid"`
	Atoms     uint64 `json:"atoms"`
	Height    int64  `json:"height"` // -1 while unconfirmed
}

type LogEntry struct {
	Seq    uint64          `json:"seq"`
	Prev   string          `json:"prev"`
	Time   string          `json:"time"`
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data"`
	Hash   string          `json:"hash"`
}

// PendingTransfer is a hosted-transfer build awaiting the caller's signatures
// (M6/OA-4). It persists so a multi-party settlement survives a restart between
// build and complete; M5's single-party pending was in-memory only. The tx and
// its policy-check (pre-blind) copy are stored as raw hex so the exact bytes the
// caller signed are reconstructed verbatim; the sighashes are stored so the
// enclave signatures are verified without re-resolving prevouts.
type PendingTransfer struct {
	ID            string    `json:"id"`
	TxHex         string    `json:"tx_hex"`                    // (possibly blinded) tx that gets signed and broadcast
	ExplicitTxHex string    `json:"explicit_tx_hex,omitempty"` // pre-blind tx for the policy check (== TxHex when transparent)
	AssetID       string    `json:"asset_id"`
	SenderAID     string    `json:"sender_aid"`
	Atoms         uint64    `json:"atoms"`
	Enclave       []int     `json:"enclave"`   // restricted input indices the enclave key signs
	Sighashes     []string  `json:"sighashes"` // hex 32-byte sighashes, aligned with Enclave
	UserPub       string    `json:"user_pub"`  // x-only hex of the enclave key
	FeeMode       string    `json:"fee_mode"`
	PaymentInputs []int     `json:"payment_inputs,omitempty"` // ordinary payment input indices the caller's wallet signs
	BurnAtoms     uint64    `json:"burn_atoms,omitempty"`     // >0 marks a burn build (OA-5); the atoms sent to the unspendable output
	Created       time.Time `json:"created"`
}

type State struct {
	Users            map[string]*User            `json:"users"`
	Assets           map[string]*Asset           `json:"assets"`
	Transfers        []TransferRecord            `json:"transfers"`
	PendingTransfers map[string]*PendingTransfer `json:"pending_transfers,omitempty"`
	// Reissues maps a caller idempotency key (request_id) to the reissuance txid
	// it produced (OA-6), so a retried DR mint returns the same txid instead of
	// minting again. Absent on pre-OA-6 documents; initialised on load.
	Reissues map[string]string `json:"reissues,omitempty"`
	// PendingReissues reserves a request_id with the EXACT signed reissuance tx and
	// its txid BEFORE broadcast. A DR mint regenerates its own input (the token is
	// re-output for the next mint), so unlike a burn/transfer it has no
	// UTXO-exhaustion backstop; this reservation is the sole double-mint guard. A
	// retry rebroadcasts the identical stored tx (same txid, the node dedupes) and
	// returns the reserved txid, so a crash between broadcast and MarkReissue can
	// never mint a second distinct transaction. Initialised on load.
	PendingReissues map[string]*PendingReissue `json:"pending_reissues,omitempty"`
	// Clawbacks maps a two-phase clawback build id to the sweep txid it produced
	// (M9), so replaying complete returns the same txid instead of driving a fresh
	// broadcast. Absent on pre-M9 documents; initialised on load.
	Clawbacks map[string]string `json:"clawbacks,omitempty"`
	// PendingClawbacks holds a two-phase clawback build (the assembled L_claw sweep
	// and its leaf sighashes) awaiting the external issuer's signatures (M9). It
	// persists so the build survives a restart between build and complete, exactly
	// like a pending transfer. Initialised on load.
	PendingClawbacks map[string]*PendingClawback `json:"pending_clawbacks,omitempty"`
	RecentBlocks []string          `json:"recent_blocks"` // newest last
	Height       int64             `json:"height"`
	LogHead      string            `json:"log_head"`
	LogSeq       uint64            `json:"log_seq"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	keys  string
	log   string
	state *State
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{
		path: filepath.Join(dir, "state.json"),
		keys: filepath.Join(dir, "keys.json"),
		log:  filepath.Join(dir, "transparency.log"),
		state: &State{
			Users:            map[string]*User{},
			Assets:           map[string]*Asset{},
			PendingTransfers: map[string]*PendingTransfer{},
		},
	}
	data, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(data, s.state); err != nil {
			return nil, fmt.Errorf("state corrupt: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// A state document written before OA-4 has no pending_transfers field;
	// initialise it so callers never touch a nil map.
	if s.state.PendingTransfers == nil {
		s.state.PendingTransfers = map[string]*PendingTransfer{}
	}
	if s.state.Reissues == nil {
		s.state.Reissues = map[string]string{}
	}
	if s.state.PendingReissues == nil {
		s.state.PendingReissues = map[string]*PendingReissue{}
	}
	if s.state.Clawbacks == nil {
		s.state.Clawbacks = map[string]string{}
	}
	if s.state.PendingClawbacks == nil {
		s.state.PendingClawbacks = map[string]*PendingClawback{}
	}
	return s, nil
}

// --- reissuance idempotency (OA-6) -------------------------------------------

// GetReissue returns the txid a prior reissue with this request_id produced.
func (s *Store) GetReissue(requestID string) (string, bool) {
	var txid string
	var ok bool
	s.View(func(st *State) { txid, ok = st.Reissues[requestID] })
	return txid, ok
}

// MarkReissue records the txid produced for a request_id (idempotency key), so a
// retry with the same key never mints again. It also clears any pending
// reservation for the key: the mint is now durably recorded, so the reserved tx
// is no longer needed.
func (s *Store) MarkReissue(requestID, txid string) error {
	return s.Update(func(st *State) error {
		if st.Reissues == nil {
			st.Reissues = map[string]string{}
		}
		st.Reissues[requestID] = txid
		delete(st.PendingReissues, requestID)
		return nil
	})
}

// PendingReissue is the pre-broadcast reservation for a reissuance request_id: the
// exact signed transaction hex and its deterministically computed txid.
type PendingReissue struct {
	SignedHex string `json:"signed_hex"`
	Txid      string `json:"txid"`
}

// GetPendingReissue returns the reservation for a request_id, if any.
func (s *Store) GetPendingReissue(requestID string) (*PendingReissue, bool) {
	var pr *PendingReissue
	var ok bool
	s.View(func(st *State) {
		if p, has := st.PendingReissues[requestID]; has {
			cp := *p
			pr, ok = &cp, true
		}
	})
	return pr, ok
}

// ReserveReissue persists the signed reissuance tx and its txid under a request_id
// BEFORE the tx is broadcast, so a crash in the broadcast window is recoverable by
// rebroadcasting the identical tx rather than minting a second one.
func (s *Store) ReserveReissue(requestID, signedHex, txid string) error {
	return s.Update(func(st *State) error {
		if st.PendingReissues == nil {
			st.PendingReissues = map[string]*PendingReissue{}
		}
		st.PendingReissues[requestID] = &PendingReissue{SignedHex: signedHex, Txid: txid}
		return nil
	})
}

// --- pending transfers (OA-4) ------------------------------------------------

// PutPendingTransfer persists a build awaiting the caller's signatures.
func (s *Store) PutPendingTransfer(pt *PendingTransfer) error {
	return s.Update(func(st *State) error {
		if st.PendingTransfers == nil {
			st.PendingTransfers = map[string]*PendingTransfer{}
		}
		cp := *pt
		st.PendingTransfers[pt.ID] = &cp
		return nil
	})
}

// GetPendingTransfer returns a copy of the pending transfer, if present.
func (s *Store) GetPendingTransfer(id string) (*PendingTransfer, bool) {
	var out *PendingTransfer
	s.View(func(st *State) {
		if pt, ok := st.PendingTransfers[id]; ok {
			cp := *pt
			out = &cp
		}
	})
	return out, out != nil
}

// DeletePendingTransfer consumes a pending transfer (idempotent). This is the
// once-only guard: a completed or expired id can never be settled twice.
func (s *Store) DeletePendingTransfer(id string) error {
	return s.Update(func(st *State) error {
		delete(st.PendingTransfers, id)
		return nil
	})
}

// GCPendingTransfers drops pending transfers older than ttl.
func (s *Store) GCPendingTransfers(ttl time.Duration) {
	_ = s.Update(func(st *State) error {
		for id, pt := range st.PendingTransfers {
			if time.Since(pt.Created) > ttl {
				delete(st.PendingTransfers, id)
			}
		}
		return nil
	})
}

// --- two-phase clawback (M9) -------------------------------------------------

// PendingClawback is a two-phase clawback build awaiting the external issuer's
// signatures. The assembled sweep tx (empty enclave witnesses) is stored as raw
// hex so the exact bytes are reconstructed verbatim on complete; the leaf
// sighashes are stored so the issuer's signatures are verified without
// re-resolving prevouts, aligned with Enclave (the L_claw input indices). Only
// external-issuer assets (Asset.IssuerExternal) ever create one; the legacy
// server-held-key clawback still signs and broadcasts in a single call.
type PendingClawback struct {
	ID        string    `json:"id"`
	TxHex     string    `json:"tx_hex"` // assembled L_claw sweep, enclave witnesses empty
	AssetID   string    `json:"asset_id"`
	HolderAID string    `json:"holder_aid"`
	Atoms     uint64    `json:"atoms"`
	Enclave   []int     `json:"enclave"`   // L_claw input indices the issuer signs
	Sighashes []string  `json:"sighashes"` // hex 32-byte sighashes, aligned with Enclave
	IssuerPub string    `json:"issuer_pub"` // x-only hex of the external issuer key
	Reason    string    `json:"reason"`
	Created   time.Time `json:"created"`
}

// PutPendingClawback persists a two-phase clawback build awaiting issuer sigs.
func (s *Store) PutPendingClawback(pc *PendingClawback) error {
	return s.Update(func(st *State) error {
		if st.PendingClawbacks == nil {
			st.PendingClawbacks = map[string]*PendingClawback{}
		}
		cp := *pc
		st.PendingClawbacks[pc.ID] = &cp
		return nil
	})
}

// GetPendingClawback returns a copy of the pending clawback, if present.
func (s *Store) GetPendingClawback(id string) (*PendingClawback, bool) {
	var out *PendingClawback
	s.View(func(st *State) {
		if pc, ok := st.PendingClawbacks[id]; ok {
			cp := *pc
			out = &cp
		}
	})
	return out, out != nil
}

// GCPendingClawbacks drops pending clawbacks older than ttl.
func (s *Store) GCPendingClawbacks(ttl time.Duration) {
	_ = s.Update(func(st *State) error {
		for id, pc := range st.PendingClawbacks {
			if time.Since(pc.Created) > ttl {
				delete(st.PendingClawbacks, id)
			}
		}
		return nil
	})
}

// GetClawback returns the sweep txid a completed two-phase clawback produced.
func (s *Store) GetClawback(id string) (string, bool) {
	var txid string
	var ok bool
	s.View(func(st *State) { txid, ok = st.Clawbacks[id] })
	return txid, ok
}

// MarkClawback records the txid a two-phase clawback produced (so a replay of
// complete returns the same txid, never a second broadcast) and clears the
// consumed pending build. Mirrors MarkReissue's consume-once semantics.
func (s *Store) MarkClawback(id, txid string) error {
	return s.Update(func(st *State) error {
		if st.Clawbacks == nil {
			st.Clawbacks = map[string]string{}
		}
		st.Clawbacks[id] = txid
		delete(st.PendingClawbacks, id)
		return nil
	})
}

// Update runs fn under the lock and persists the state afterwards.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.state); err != nil {
		return err
	}
	return s.persistLocked()
}

// View runs fn under the lock without persisting.
func (s *Store) View(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.state)
}

func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// --- keys -------------------------------------------------------------------

func (s *Store) LoadKeys() (map[string]string, error) {
	data, err := os.ReadFile(s.keys)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var keys map[string]string
	return keys, json.Unmarshal(data, &keys)
}

func (s *Store) SaveKey(name, privHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateKeysLocked(func(keys map[string]string) error {
		keys[name] = privHex
		return nil
	})
}

// RenameKey moves a stored key from one name to another (used to bind a
// provisioned policy key to its asset id once issuance derives it).
func (s *Store) RenameKey(from, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateKeysLocked(func(keys map[string]string) error {
		v, ok := keys[from]
		if !ok {
			return fmt.Errorf("key %q not found", from)
		}
		keys[to] = v
		delete(keys, from)
		return nil
	})
}

func (s *Store) mutateKeysLocked(fn func(map[string]string) error) error {
	keys, err := s.LoadKeys()
	if err != nil {
		return err
	}
	if err := fn(keys); err != nil {
		return err
	}
	data, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		return err
	}
	tmp := s.keys + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.keys)
}

// --- transparency log --------------------------------------------------------

// AppendLog writes a hash-chained decision record and returns the new head.
func (s *Store) AppendLog(action string, data any) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	entry := LogEntry{
		Seq:    s.state.LogSeq + 1,
		Prev:   s.state.LogHead,
		Time:   time.Now().UTC().Format(time.RFC3339),
		Action: action,
		Data:   raw,
	}
	// Canonical pre-image so any client can re-verify the chain:
	// sha256("<seq>|<prev>|<time>|<action>|<data-json>").
	pre := fmt.Sprintf("%d|%s|%s|%s|%s", entry.Seq, entry.Prev, entry.Time, entry.Action, string(raw))
	h := sha256.Sum256([]byte(pre))
	entry.Hash = hex.EncodeToString(h[:])
	line, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(s.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return "", err
	}
	s.state.LogSeq = entry.Seq
	s.state.LogHead = entry.Hash
	return entry.Hash, s.persistLocked()
}

func (s *Store) LogPath() string { return s.log }

// CategorySetHash is the transparency-log commitment to a holder's category
// set (OA-LM log minimization). The public log records this hash in place of
// the raw category vector, so an observer can no longer read a holder's exact
// categories, while a holder or auditor who knows the set recomputes the hash
// and verifies it. The commitment is SHA-256 over the sorted, de-duplicated
// labels under a versioned domain tag, so it is order- and duplicate-stable and
// the "v1" format tag lets a later scheme coexist. The private server state
// keeps the raw set for policy enforcement; only the public log is minimized.
func CategorySetHash(categories []string) string {
	seen := map[string]bool{}
	uniq := make([]string, 0, len(categories))
	for _, c := range categories {
		if !seen[c] {
			seen[c] = true
			uniq = append(uniq, c)
		}
	}
	sort.Strings(uniq)
	h := sha256.New()
	h.Write([]byte("openamp-catset-v1"))
	for _, c := range uniq {
		h.Write([]byte{0}) // unambiguous separator between labels
		h.Write([]byte(c))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AID derives the account id from a registered pubkey set: 20-byte
// hash160-style id over the sorted x-only keys (hex).
func AID(pubkeys []string) string {
	sorted := append([]string(nil), pubkeys...)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte("openamp-aid-v1"))
	for _, pk := range sorted {
		h.Write([]byte(pk))
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:20])
}
