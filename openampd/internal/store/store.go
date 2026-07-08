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
	IssuerAID    string          `json:"issuer_aid"`
	Tier         string          `json:"tier"`
	Clawback     bool            `json:"clawback"`
	BurnAllowed  bool            `json:"burn_allowed"`
	IssueTxid    string          `json:"issue_txid"`
	Rules        Rules           `json:"rules"`
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

type State struct {
	Users        map[string]*User  `json:"users"`
	Assets       map[string]*Asset `json:"assets"`
	Transfers    []TransferRecord  `json:"transfers"`
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
			Users:  map[string]*User{},
			Assets: map[string]*Asset{},
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
	return s, nil
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
	keys, err := s.LoadKeys()
	if err != nil {
		return err
	}
	keys[name] = privHex
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
