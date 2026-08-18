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
	"strings"
	"sync"
	"time"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp"
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
	IssuerExternal bool   `json:"issuer_external,omitempty"`
	IssuerAID      string `json:"issuer_aid"`
	Clawback       bool   `json:"clawback"`
	BurnAllowed    bool   `json:"burn_allowed"`
	Confidential   bool   `json:"confidential"`
	IssueTxid      string `json:"issue_txid"`
	Rules          Rules  `json:"rules"`
	// Reissuance material (OA-6), recorded at issuance so a later DR mint can
	// re-derive the asset entropy and locate the reissuance token. Both are
	// display-hex. Absent on assets issued before OA-6 (reissue is refused for
	// them), so existing records are byte-compatible.
	Entropy string `json:"entropy,omitempty"` // final asset entropy
	Token   string `json:"token,omitempty"`   // reissuance token id
	// Enforcement records the issuance-time enforcement election (OpenDAMP).
	// Absent (or "") = cosign, so nothing ever writes "cosign" explicitly and
	// every stored record stays byte-compatible. A network-enforced (damp) asset
	// persists "damp" here and carries Damp below.
	Enforcement string `json:"enforcement,omitempty"`
	// Damp is the verifier binding of a network-enforced asset: present exactly
	// when Enforcement == "damp", absent (and omitted) for every cosign asset, so
	// existing records are byte-compatible.
	Damp *DampBinding `json:"damp,omitempty"`
	// BlindEpoch is the asset's current blinding-key derivation epoch:
	// server-side rotation bookkeeping, never an asset property and never part
	// of the contract. Epoch 0 is the original (v1) derivation and is omitted,
	// so every record written before rotation existed stays byte-compatible.
	BlindEpoch uint32 `json:"blind_epoch,omitempty"`
}

// DampBinding is everything a holder or auditor needs to act on a
// network-enforced (OpenDAMP) asset without asking this server for permission:
// the verifier asset and its fixed amount q, the issuer key that may update the
// policy, the genesis policy commitment pi_0 and the whitelist it commits to,
// the three program CMRs the covenant addresses derive from, and the derived
// addresses themselves.
//
// The first four are committed into the asset id through the contract's openamp
// block (opendamp-design.md section 5), so they are chain-provable. The CMRs are
// NOT in the contract: they are the compiled-program identities the operator
// supplied from `opendamp derive`, recorded here so the addresses this server
// reports are reproducible. A holder verifies them the same way anyone does — by
// recompiling the programs and comparing, or against a template registry.
type DampBinding struct {
	VerifierAsset     string `json:"verifier_asset"`      // display hex of V
	VerifierAmount    uint64 `json:"verifier_amount"`     // q
	VerifierIssueTxid string `json:"verifier_issue_txid"` // the tx that minted q of V
	IssuerUpdateKey   string `json:"issuer_update_key"`   // x-only hex; may spend C_V through G(I)
	HolderPubkey      string `json:"holder_pubkey"`       // x-only hex of the initial holder
	Pi                string `json:"pi"`                  // pi_0, hex
	WhitelistRoot     string `json:"whitelist_root"`      // dmt-v1 root, hex
	// Whitelist is the owner keys the CURRENT policy admits, kept in step with
	// WhitelistRoot by every published seq. It is not decoration: a network-
	// enforced asset's holders are raw x-only keys that need never register with
	// this server, so the whitelist is the only enumeration of who can hold the
	// asset, and therefore the only way an ownership report or a supply figure can
	// know which covenant scripts to scan. Dropping it made both answer zero for a
	// live asset, which reads as a truthful empty register rather than as a
	// missing input. Absent on records written before that was fixed, so those
	// fall back to the registered-user scan alone.
	//
	// Each entry carries the height bounds that bind that holder, and serializes as
	// a bare key when it has none, so a record written before bounds existed stays
	// byte-identical to what it was.
	Whitelist        []damp.PredicateEntry `json:"whitelist,omitempty"`
	Tree             string                `json:"tree"` // "dmt-v1"
	UserCMR          string                `json:"user_cmr"`
	VerifierCMR      string                `json:"verifier_cmr"`
	IssuerCMR        string                `json:"issuer_cmr"`
	UserCovenantSPK  string                `json:"user_covenant_spk"`     // C_U(initial holder), hex
	UserCovenantAddr string                `json:"user_covenant_address"` // best-effort, node-decoded
	VerifierSPK      string                `json:"verifier_covenant_spk"`
	VerifierAddr     string                `json:"verifier_covenant_address"`
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
	// PendingDampIssuances holds a network-enforced issuance between its two
	// phases: prepare (which fixes the asset id and pi_0 and mints the verifier
	// asset) and complete (which needs the covenant CMRs only the Rust toolchain
	// can compile). Absent on documents written before damp issuance existed;
	// initialised on load.
	PendingDampIssuances map[string]*PendingDampIssuance `json:"pending_damp_issuances,omitempty"`
	// PendingDampPolicies holds a network-enforced POLICY UPDATE between its two
	// phases: prepare (which fixes the next whitelist/blacklist, pi_{n+1} and the
	// snapshot the issuer signs) and complete (which needs the recompiled verifier
	// CMR and the finished C_V respend, neither of which a Go server can produce).
	// Absent on documents written before policy updates existed; initialised on
	// load.
	PendingDampPolicies map[string]*PendingDampPolicy `json:"pending_damp_policies,omitempty"`
	// DampPolicies maps a completed policy-update id to the respend txid it
	// broadcast, so a replayed complete returns that txid instead of driving a
	// second broadcast. Absent on older documents; initialised on load.
	DampPolicies map[string]string `json:"damp_policies,omitempty"`
	// Snapshots maps an asset id to its published OpenDAMP policy snapshots in
	// seq order (index == seq; the snapshot service enforces gapless append).
	// Absent on documents written before M2; initialised on load.
	Snapshots    map[string][]*StoredSnapshot `json:"snapshots,omitempty"`
	RecentBlocks []string                     `json:"recent_blocks"` // newest last
	Height       int64                        `json:"height"`
	LogHead      string                       `json:"log_head"`
	LogSeq       uint64                       `json:"log_seq"`
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
	if s.state.Snapshots == nil {
		s.state.Snapshots = map[string][]*StoredSnapshot{}
	}
	if s.state.PendingDampIssuances == nil {
		s.state.PendingDampIssuances = map[string]*PendingDampIssuance{}
	}
	if s.state.PendingDampPolicies == nil {
		s.state.PendingDampPolicies = map[string]*PendingDampPolicy{}
	}
	if s.state.DampPolicies == nil {
		s.state.DampPolicies = map[string]string{}
	}
	return s, nil
}

// --- network-enforced (OpenDAMP) issuance, phase 1 ----------------------------

// PendingDampIssuance is a network-enforced issuance waiting for its covenant
// parameters. Phase 1 mints the verifier asset, pins the funding outpoint, and
// therefore FIXES the asset id and pi_0; phase 2 supplies the program CMRs and
// broadcasts the asset issuance straight into the user covenant. Everything
// phase 2 needs is recorded here, so the contract bytes phase 2 commits to are
// the exact bytes phase 1 hashed into the asset id.
type PendingDampIssuance struct {
	ID string `json:"id"`

	Name      string `json:"name"`
	Ticker    string `json:"ticker"`
	Precision int    `json:"precision"`
	Atoms     uint64 `json:"atoms"`

	HolderPubkey  string   `json:"holder_pubkey"`
	Whitelist     []string `json:"whitelist"`
	WhitelistRoot string   `json:"whitelist_root"`

	VerifierAsset     string `json:"verifier_asset"`
	VerifierAmount    uint64 `json:"verifier_amount"`
	VerifierIssueTxid string `json:"verifier_issue_txid"`
	VerifierToken     string `json:"verifier_token"`
	VerifierVout      uint32 `json:"verifier_vout"`

	IssuerUpdateKey string `json:"issuer_update_key"`
	IssuerAID       string `json:"issuer_aid,omitempty"`
	BurnAllowed     bool   `json:"burn_allowed"`

	// Policy key material: PolicyPub is committed in the contract (and therefore
	// in the asset id); PolicyRef is the signer-backend handle phase 2 adopts.
	PolicyPub string `json:"policy_pub"`
	PolicyRef string `json:"policy_ref"`

	Contract     json.RawMessage `json:"contract"`
	ContractHash string          `json:"contract_hash"`
	AssetID      string          `json:"asset_id"`
	Entropy      string          `json:"entropy"`
	Token        string          `json:"token"`

	FundingTxid string `json:"funding_txid"`
	FundingVout uint32 `json:"funding_vout"`
	FundingSats uint64 `json:"funding_sats"`

	Pi             string          `json:"pi"`
	Snapshot       json.RawMessage `json:"snapshot"`         // canonical seq-0 snapshot/v1 bytes
	SnapshotHash   string          `json:"snapshot_hash"`    // SHA256 of those bytes
	SnapshotSigMsg string          `json:"snapshot_sig_msg"` // the 32 bytes the issuer signs

	Created time.Time `json:"created"`
}

// PutPendingDampIssuance persists a prepared issuance awaiting covenant params.
func (s *Store) PutPendingDampIssuance(p *PendingDampIssuance) error {
	return s.Update(func(st *State) error {
		if st.PendingDampIssuances == nil {
			st.PendingDampIssuances = map[string]*PendingDampIssuance{}
		}
		cp := *p
		st.PendingDampIssuances[p.ID] = &cp
		return nil
	})
}

// GetPendingDampIssuance returns a copy of the prepared issuance, if present.
func (s *Store) GetPendingDampIssuance(id string) (*PendingDampIssuance, bool) {
	var out *PendingDampIssuance
	s.View(func(st *State) {
		if p, ok := st.PendingDampIssuances[id]; ok {
			cp := *p
			out = &cp
		}
	})
	return out, out != nil
}

// DeletePendingDampIssuance consumes a prepared issuance (idempotent). This is
// the once-only guard: a completed prepare can never mint its asset twice.
func (s *Store) DeletePendingDampIssuance(id string) error {
	return s.Update(func(st *State) error {
		delete(st.PendingDampIssuances, id)
		return nil
	})
}

// GCPendingDampIssuances drops prepared issuances older than ttl. An expired
// prepare has cost the operator only the verifier asset it minted, which is
// internal plumbing and can be reused by preparing again.
func (s *Store) GCPendingDampIssuances(ttl time.Duration) {
	_ = s.Update(func(st *State) error {
		for id, p := range st.PendingDampIssuances {
			if time.Since(p.Created) > ttl {
				delete(st.PendingDampIssuances, id)
			}
		}
		return nil
	})
}

// --- network-enforced (OpenDAMP) policy updates -------------------------------

// PendingDampPolicy is a policy update waiting for the two things this server
// cannot produce: the CMR of the RECOMPILED verifier program P(pi_{n+1}), and
// the finished spend of the current verifier output through the issuer path
// G(I). Everything the completion needs to be checked against is recorded here
// at prepare, so the policy that gets published is the policy whose reason was
// logged before anything was signed.
//
// Whitelist/Blacklist are the NEXT policy's inline entries (owner keys and
// outpoint keys, both 32-byte hex), kept so the completion can recompute pi from
// stored state rather than trusting the supplied one. VerifierTxid/VerifierVout
// pin the outpoint the respend must consume, so a transaction spending some
// other coin is refused rather than broadcast.
type PendingDampPolicy struct {
	ID      string `json:"id"`
	AssetID string `json:"asset_id"`
	Reason  string `json:"reason"`

	Seq    uint64 `json:"seq"`     // the seq this update publishes (current + 1)
	PrevPi string `json:"prev_pi"` // the pi it chains from
	Pi     string `json:"pi"`      // pi_{n+1}

	// Whitelist carries the next policy's holders WITH their height bounds;
	// Blacklist the frozen outpoints' 32-byte policy keys, which have no bounds.
	Whitelist     []damp.PredicateEntry `json:"whitelist"`
	Blacklist     []string              `json:"blacklist"`
	WhitelistRoot string                `json:"whitelist_root"`
	BlacklistRoot string                `json:"blacklist_root"`
	// Added/Removed record the human-legible shape of the change for the
	// transparency log and for the console that renders it. Blacklist entries are
	// hashes, so the outpoints they came from are recorded here or lost.
	AddedHolders     []string `json:"added_holders,omitempty"`
	RemovedHolders   []string `json:"removed_holders,omitempty"`
	AddedOutpoints   []string `json:"added_outpoints,omitempty"`   // "txid:vout"
	RemovedOutpoints []string `json:"removed_outpoints,omitempty"` // "txid:vout"

	VerifierAsset   string `json:"verifier_asset"`
	VerifierAmount  uint64 `json:"verifier_amount"`
	VerifierTxid    string `json:"verifier_txid"`
	VerifierVout    uint32 `json:"verifier_vout"`
	VerifierSPKPrev string `json:"verifier_spk_prev"`
	VerifierCMRPrev string `json:"verifier_cmr_prev"`
	IssuerUpdateKey string `json:"issuer_update_key"`

	Snapshot       json.RawMessage `json:"snapshot"`         // canonical seq n+1 bytes
	SnapshotHash   string          `json:"snapshot_hash"`    // SHA256 of those bytes
	SnapshotSigMsg string          `json:"snapshot_sig_msg"` // the 32 bytes the issuer signs

	Created time.Time `json:"created"`
}

// PutPendingDampPolicy persists a prepared policy update.
func (s *Store) PutPendingDampPolicy(p *PendingDampPolicy) error {
	return s.Update(func(st *State) error {
		if st.PendingDampPolicies == nil {
			st.PendingDampPolicies = map[string]*PendingDampPolicy{}
		}
		cp := *p
		st.PendingDampPolicies[p.ID] = &cp
		return nil
	})
}

// GetPendingDampPolicy returns a copy of the prepared policy update, if present.
func (s *Store) GetPendingDampPolicy(id string) (*PendingDampPolicy, bool) {
	var out *PendingDampPolicy
	s.View(func(st *State) {
		if p, ok := st.PendingDampPolicies[id]; ok {
			cp := *p
			out = &cp
		}
	})
	return out, out != nil
}

// GCPendingDampPolicies drops prepared policy updates older than ttl. An expired
// prepare has cost nothing: no coin moved and no snapshot was published.
func (s *Store) GCPendingDampPolicies(ttl time.Duration) {
	_ = s.Update(func(st *State) error {
		for id, p := range st.PendingDampPolicies {
			if time.Since(p.Created) > ttl {
				delete(st.PendingDampPolicies, id)
			}
		}
		return nil
	})
}

// GetDampPolicy returns the respend txid a completed policy update produced.
func (s *Store) GetDampPolicy(id string) (string, bool) {
	var txid string
	var ok bool
	s.View(func(st *State) { txid, ok = st.DampPolicies[id] })
	return txid, ok
}

// MarkDampPolicy records the txid a policy update broadcast and consumes the
// pending build, so a replay short-circuits to that txid and can never build or
// broadcast a second respend. Mirrors MarkClawback's consume-once semantics.
func (s *Store) MarkDampPolicy(id, txid string) error {
	return s.Update(func(st *State) error {
		if st.DampPolicies == nil {
			st.DampPolicies = map[string]string{}
		}
		st.DampPolicies[id] = txid
		delete(st.PendingDampPolicies, id)
		return nil
	})
}

// --- OpenDAMP policy snapshots (M2) -------------------------------------------

// StoredSnapshot is one published policy snapshot for an asset. Canonical is
// the snapshot's canonical JSON (sorted keys, compact, issuer_sig excluded);
// Hash is SHA256 of those bytes (the content address); IssuerSig is the BIP340
// signature over the tagged snapshot hash; IssuerPub is the x-only key the
// signature was verified against, pinned so later seqs of the same asset must
// chain under the same key.
type StoredSnapshot struct {
	Seq       uint64          `json:"seq"`
	Pi        string          `json:"pi"`
	Hash      string          `json:"hash"`
	IssuerPub string          `json:"issuer_pub"`
	Canonical json.RawMessage `json:"canonical"`
	IssuerSig string          `json:"issuer_sig"`
}

// AppendSnapshot appends a snapshot for an asset, enforcing gapless sequence
// numbers atomically (seq must equal the current count, so the first is 0).
// The prev_pi linkage check runs in the handler; this seq check is what makes
// concurrent posts race-safe.
func (s *Store) AppendSnapshot(assetID string, ss *StoredSnapshot) error {
	return s.Update(func(st *State) error {
		if st.Snapshots == nil {
			st.Snapshots = map[string][]*StoredSnapshot{}
		}
		if want := uint64(len(st.Snapshots[assetID])); ss.Seq != want {
			return fmt.Errorf("snapshot seq must be %d (gapless), got %d", want, ss.Seq)
		}
		cp := *ss
		st.Snapshots[assetID] = append(st.Snapshots[assetID], &cp)
		return nil
	})
}

// LatestSnapshot returns a copy of the asset's newest snapshot, if any.
func (s *Store) LatestSnapshot(assetID string) (*StoredSnapshot, bool) {
	var out *StoredSnapshot
	s.View(func(st *State) {
		if list := st.Snapshots[assetID]; len(list) > 0 {
			cp := *list[len(list)-1]
			out = &cp
		}
	})
	return out, out != nil
}

// SnapshotAt returns a copy of the asset's snapshot with the exact seq, if any.
func (s *Store) SnapshotAt(assetID string, seq uint64) (*StoredSnapshot, bool) {
	var out *StoredSnapshot
	s.View(func(st *State) {
		if list := st.Snapshots[assetID]; seq < uint64(len(list)) {
			cp := *list[seq]
			out = &cp
		}
	})
	return out, out != nil
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
	Enclave   []int     `json:"enclave"`    // L_claw input indices the issuer signs
	Sighashes []string  `json:"sighashes"`  // hex 32-byte sighashes, aligned with Enclave
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

// DeleteKey removes a stored key. Idempotent — a missing key is not an error —
// so it is safe as the rollback step of a multi-key provisioning run that
// failed partway (a quorum member discarding the share of an aborted DKG).
func (s *Store) DeleteKey(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateKeysLocked(func(keys map[string]string) error {
		delete(keys, name)
		return nil
	})
}

// RenameKeyPrefix moves every stored key beginning with fromPrefix to the same
// suffix under toPrefix, in ONE keys-file write — so binding a multi-key set
// (a FROST share set) to its asset id is atomic and a crash cannot leave a
// half-bound quorum. Errors when nothing matches.
func (s *Store) RenameKeyPrefix(fromPrefix, toPrefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateKeysLocked(func(keys map[string]string) error {
		var matched []string
		for name := range keys {
			if strings.HasPrefix(name, fromPrefix) {
				matched = append(matched, name)
			}
		}
		if len(matched) == 0 {
			return fmt.Errorf("no keys under %q", fromPrefix)
		}
		for _, name := range matched {
			keys[toPrefix+name[len(fromPrefix):]] = keys[name]
			delete(keys, name)
		}
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
