package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/fastmerkle"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Network-enforced (OpenDAMP) issuance: enforcement "damp".
//
// A damp asset has NO enclave and NO co-signer. Units live in user covenants
// C_U(X) — taproot outputs with a Simplicity leaf — and every transfer is
// policed on chain by a verifier covenant C_V(pi) the holder spends alongside
// their own coins. This server issues such an asset, publishes its policy
// snapshots, and then has nothing further to authorize: transfers work with the
// policy service switched off, which is the whole point of the tier.
//
// # THE SEAM: a Go server cannot compile Simplicity
//
// Both covenant programs are parameterized at COMPILE time:
//
//   - U takes (asset A, verifier asset V, amount q), so its CMR is per-asset
//     (opendamp/STATUS.md section 5);
//   - P takes pi, so its CMR — and therefore the C_V address — is per-policy.
//
// openampd derives covenant ADDRESSES byte-exactly (internal/elements/
// simplicity.go, vector-pinned) but cannot produce a CMR: that needs the
// SimplicityHL compiler, which lives in the Rust `opendamp` crate. And the
// dependency is circular in the awkward direction: A's id commits to its
// contract and to the funding outpoint this server chooses, so NEITHER the CMRs
// NOR pi_0 can be computed by anyone — operator or server — before this server
// has picked that outpoint.
//
// The resolution is a two-phase issuance, and it keeps each side authoritative
// over what it actually knows:
//
//	  phase 1  POST /v1/issuer/damp-assets
//	           This server mints the verifier asset V, fixes the funding
//	           outpoint, and therefore FIXES A's id, its contract bytes and
//	           pi_0. It broadcasts only the V issuance. It returns a
//	           derive-ready snapshot document.
//	  (operator) opendamp derive --snapshot <that document>
//	           The Rust toolchain compiles U, P(pi_0) and G and prints their
//	           CMRs, C_V(pi_0)'s scriptPubKey, and its own pi.
//	  phase 2  POST /v1/issuer/damp-assets/{id}/complete
//	           The operator posts the CMRs and the pi derive printed. This
//	           server REFUSES unless that pi equals the pi it computes itself
//	           from the whitelist and the asset id, so the server stays
//	           authoritative about POLICY while the Rust toolchain stays
//	           authoritative about PROGRAM COMPILATION. It then mints A
//	           straight into C_U(holder) and locks q of V into C_V(pi_0) in ONE
//	           transaction, so A never exists without its verifier output.
//
// A supplied verifier_spk is checked against the address this server derives
// from the supplied CMR, which is the cross-check that catches a CMR pasted
// from the wrong policy before any coin moves.

// dampPrepareTTL bounds how long a prepared issuance waits for its covenant
// parameters. Generous: an operator runs `opendamp derive` by hand, possibly on
// another machine, and may want the issuer to sign the genesis snapshot offline
// in the same window.
const dampPrepareTTL = 72 * time.Hour

// dampNotConfigured is the exact capability refusal every damp endpoint gives
// when no CMR pinning file is configured. Shape is deliberately stable: clients
// (SeqPal) match on the status, and operators match on the string.
const dampNotConfigured = "network enforcement is not configured on this policy server"

// dampNotCosigned is the exact refusal a co-signing path gives for a damp
// asset. It is a 409 (the request is well-formed and the asset exists; this
// server is simply not in the transfer path) rather than a 403, which would
// read as a policy denial the holder could appeal.
const dampNotCosigned = "this asset is network-enforced: transfers are built by the holder from the published snapshot, not co-signed here"

// dampConfigured reports whether the CMR pinning file was loaded.
func (s *Server) dampConfigured() bool { return s.dampReg != nil }

// requireDamp writes the capability refusal and returns false when network
// enforcement is not configured.
func (s *Server) requireDamp(w http.ResponseWriter) bool {
	if s.dampConfigured() {
		return true
	}
	httpErr(w, 501, dampNotConfigured)
	return false
}

// refuseDampCosign writes the 409 for a co-signing/hosted path invoked on a
// network-enforced asset and returns true when it did. Every path that would
// otherwise try to derive an enclave for such an asset calls this first: the
// enclave tree it would build is meaningless (no coin ever pays it), so without
// the guard the caller would get a confusing empty balance instead of the real
// answer, which is that this server is not in the loop.
func refuseDampCosign(w http.ResponseWriter, asset *store.Asset) bool {
	if asset == nil || asset.Enforcement != "damp" {
		return false
	}
	httpErr(w, 409, dampNotCosigned)
	return true
}

// --- request/response shapes --------------------------------------------------

// dampIssueRequest is the POST /v1/issuer/damp-assets (phase 1) body. The
// identity fields mirror issueRequest's OA-1 block exactly, so a damp asset
// registers through the same path as a cosign one.
//
// Unlike hosted issuance this endpoint does NOT require -demoissuer: it needs no
// issuer private key. issuer_update_key is the issuer's own x-only key, supplied
// by the caller and never generated here, and the only signature this server
// makes is the ordinary wallet signature over its own funding inputs.
type dampIssueRequest struct {
	Name      string `json:"name"`
	Ticker    string `json:"ticker"`
	Precision int    `json:"precision"`
	Atoms     uint64 `json:"atoms"`

	// HolderPubkey is the initial holder's x-only key; A is minted straight into
	// C_U(holder_pubkey).
	HolderPubkey string `json:"holder_pubkey"`
	// Whitelist is the set of x-only owner keys permitted to RECEIVE the asset
	// under pi_0. It must contain holder_pubkey — a whitelist that does not is a
	// dead asset, because the covenant checks recipients and the very first
	// transfer back to the holder would fail at consensus. Note the honest scope:
	// the shipped covenant checks recipients only, so removing a key stops it
	// receiving, not spending (opendamp/STATUS.md).
	Whitelist []string `json:"whitelist"`
	// VerifierAmount is q, the fixed amount of V a valid verifier output carries.
	// Defaults to 1: q's only job is to be a recognisable constant, and a smaller
	// q leaves more of V's supply for the parallel verifier outputs of design
	// section 6.
	VerifierAmount uint64 `json:"verifier_amount,omitempty"`
	// IssuerUpdateKey (x-only hex) may spend C_V through the issuer path G(I) to
	// update the policy or halt the asset. It is committed into the contract and
	// therefore into the asset id.
	IssuerUpdateKey string `json:"issuer_update_key"`
	// Network selects the address encoding `opendamp derive` should use. It is
	// passed through into the derive-ready document ONLY; nothing in the
	// commitment depends on it.
	Network string `json:"network,omitempty"`

	BurnAllowed bool   `json:"burn_allowed"`
	IssuerAID   string `json:"issuer_aid,omitempty"`

	// OA-1 identity, byte-for-byte the same block a cosign issuance builds.
	TermsHash            string `json:"terms_hash,omitempty"`
	Endpoint             string `json:"endpoint,omitempty"`
	EntityDomain         string `json:"entity_domain,omitempty"`
	EntityName           string `json:"entity_name,omitempty"`
	OperatorName         string `json:"operator_name,omitempty"`
	OperatorRegistration string `json:"operator_registration,omitempty"`
}

// dampCompleteRequest is the POST /v1/issuer/damp-assets/{id}/complete body:
// the compiled-program identities from `opendamp derive`, plus the pi that run
// printed as the cross-check.
type dampCompleteRequest struct {
	UserCMR string `json:"user_cmr"`
	// VerifierCMRs is one CMR per transaction shape, in the order `opendamp
	// derive` prints them (canonical first). They all commit to the same policy
	// and all sit in the one C_V(pi) taptree, so the ORDER is part of the
	// address. VerifierCMR is the pre-menu field and is refused with an
	// explanation rather than misread as a one-leaf menu.
	VerifierCMRs []string `json:"verifier_cmrs"`
	VerifierCMR  string   `json:"verifier_cmr,omitempty"`
	// IssuerCMR is optional: G takes only the issuer key as a parameter, so its
	// CMR is stable across policies and the pinning file's g_cmr is right almost
	// always. Supply it to override.
	IssuerCMR string `json:"issuer_cmr,omitempty"`
	// Pi must equal the pi this server computes from the stored whitelist and
	// asset id. A mismatch means the operator derived against a different
	// snapshot, and every transfer would fail at consensus, so it is refused.
	Pi string `json:"pi"`
	// VerifierSPK is optional: when present it must equal the scriptPubKey this
	// server derives from VerifierCMR, which catches a CMR from the wrong policy
	// before any coin moves.
	VerifierSPK string `json:"verifier_spk,omitempty"`
	// SnapshotSig is an OPTIONAL BIP340 signature by issuer_update_key over the
	// snapshot_sig_message phase 1 returned. When present the genesis snapshot is
	// published signed and attributable. When absent it is published with an empty
	// issuer_sig: pi_0 is recomputable by anyone from the asset id and the
	// whitelist, and the binding fact a holder checks is the on-chain C_V(pi_0)
	// output, so an unsigned genesis snapshot is still verifiable — just not
	// attributable. Every LATER seq goes through POST /v1/issuer/snapshots, which
	// requires the signature as it always has.
	SnapshotSig string `json:"snapshot_sig,omitempty"`
}

// --- helpers -----------------------------------------------------------------

func parseXOnly(field, s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%s must be 32-byte x-only hex", field)
	}
	if _, err := schnorr.ParsePubKey(b); err != nil {
		return out, fmt.Errorf("%s is not a valid x-only public key: %v", field, err)
	}
	copy(out[:], b)
	return out, nil
}

// parseCMRMenu turns the registrar's list of primary-program CMRs into the menu
// the verifier taptree is built from. Order matters: it is the crate's SHAPES
// order, canonical first, and a different order is a different address.
//
// A caller that sends only the old single `verifier_cmr` is refused rather than
// silently treated as a one-leaf menu, because that derives a real but WRONG
// address and the mistake would only surface when a holder could not spend.
func parseCMRMenu(list []string, legacy string) ([][32]byte, error) {
	if len(list) == 0 {
		if strings.TrimSpace(legacy) != "" {
			return nil, fmt.Errorf(
				"verifier_cmr is the pre-menu field: OpenDAMP now compiles one primary " +
					"program per transaction shape and puts them all in one C_V(pi) taptree. " +
					"Send verifier_cmrs, in the order `opendamp derive` prints them")
		}
		return nil, fmt.Errorf("verifier_cmrs must list one CMR per verifier shape")
	}
	out := make([][32]byte, 0, len(list))
	for i, h := range list {
		c, err := parseCMR(fmt.Sprintf("verifier_cmrs[%d]", i), h)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// cmrHexList renders a menu for storage and comparison.
func cmrHexList(menu [][32]byte) []string {
	out := make([]string, 0, len(menu))
	for _, c := range menu {
		out = append(out, hex.EncodeToString(c[:]))
	}
	return out
}

// sameCMRMenu reports whether two menus are the same set of programs in the
// same order, which is what "the policy did not change" means on chain.
func sameCMRMenu(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

func parseCMR(field, s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%s must be a 32-byte CMR in hex (from `opendamp derive`)", field)
	}
	copy(out[:], b)
	return out, nil
}

// addressOfSPK asks the node to render a scriptPubKey as an address. Purely
// cosmetic: it is best-effort and an empty result never blocks an issuance,
// because the scriptPubKey is the authoritative form and is always returned.
func (s *Server) addressOfSPK(spk []byte) string {
	var out struct {
		Address string `json:"address"`
	}
	if err := s.node.Call(&out, "decodescript", hex.EncodeToString(spk)); err != nil {
		return ""
	}
	return out.Address
}

// dampWhitelistRoot parses the whitelist and returns its dmt-v1 root along with
// the normalized (validated) key list.
func dampWhitelistRoot(list []string, holder string) ([32]byte, error) {
	var root [32]byte
	if len(list) == 0 {
		return root, fmt.Errorf("whitelist must contain at least the initial holder")
	}
	keys := make([][32]byte, 0, len(list))
	found := false
	for i, e := range list {
		k, err := parseXOnly(fmt.Sprintf("whitelist[%d]", i), e)
		if err != nil {
			return root, err
		}
		if e == holder {
			found = true
		}
		keys = append(keys, k)
	}
	if !found {
		return root, fmt.Errorf("whitelist must contain holder_pubkey: the covenant checks the RECIPIENT of every regulated output, so a holder outside the whitelist could never be paid, including by their own change")
	}
	return damp.WhitelistRoot(keys)
}

// dampContract assembles A's issuance contract. The openamp block carries the
// section 5 binding: enforcement, the verifier asset and its amount, and the
// issuer update key. Three choices worth stating:
//
//   - policy_pubkey is STILL issued. A damp asset never uses it — there is no
//     co-signature and no L_claw leaf — but the registry's validateOpenAmp
//     requires the field unconditionally, so omitting it would make a
//     network-enforced asset unregisterable, and keeping it leaves the asset-id
//     shape uniform across both tiers and a later migration possible.
//   - clawback is always false. A damp asset has no enclave and therefore no
//     L_claw leaf; the covenant IS the enforcement, and the issuer's powers are
//     policy update and halt through G(I).
//   - There is NO genesis_policy and NO genesis_snapshot_hash. pi_0 commits to
//     A's id, and A's id commits to this contract, so a contract carrying pi_0
//     would have to contain a hash of itself (opendamp-design.md section 5).
func (req *dampIssueRequest) dampContract(policyPubkey, verifierAsset string, q uint64) map[string]any {
	openamp := map[string]any{
		"version":           1,
		"type":              "restricted",
		"policy_pubkey":     policyPubkey,
		"clawback":          false,
		"burn_allowed":      req.BurnAllowed,
		"enforcement":       "damp",
		"verifier_asset":    verifierAsset,
		"verifier_amount":   q,
		"issuer_update_key": req.IssuerUpdateKey,
	}
	if req.TermsHash != "" {
		openamp["terms_hash"] = req.TermsHash
	}
	if req.Endpoint != "" {
		openamp["policy_endpoints"] = []string{req.Endpoint}
	}
	contract := map[string]any{
		"name":      req.Name,
		"ticker":    req.Ticker,
		"precision": req.Precision,
		"version":   0,
		// The issuer's own key. For a damp asset this IS the update key: there is
		// no separate enclave issuer half, so naming a second key would invent a
		// role no program reads.
		"issuer_pubkey": req.IssuerUpdateKey,
		"openamp":       openamp,
	}
	if req.EntityDomain != "" {
		entity := map[string]any{"domain": req.EntityDomain}
		if req.EntityName != "" {
			entity["issuer"] = req.EntityName
		}
		contract["entity"] = entity
		operator := map[string]any{}
		if req.OperatorName != "" {
			operator["name"] = req.OperatorName
		}
		if req.OperatorRegistration != "" {
			operator["registration"] = req.OperatorRegistration
		}
		if len(operator) > 0 {
			contract["operator"] = operator
		}
	}
	return contract
}

// verifierContract is V's issuance contract. V is INTERNAL PLUMBING, not an
// offered instrument: its only job is to exist in a recognisable fixed amount
// inside C_V so that every regulated transfer must spend the verifier output and
// therefore run the policy program. It is precision 0 (q is a count, not a
// quantity), it carries no openamp block (nothing polices V itself), and it must
// never be presented to an investor as part of the offering.
func verifierContract(name, ticker string) map[string]any {
	return map[string]any{
		"name":      name + " verifier",
		"ticker":    ticker + "V",
		"precision": 0,
		"version":   0,
	}
}

// --- phase 1: prepare --------------------------------------------------------

// handleDampIssuePrepare is POST /v1/issuer/damp-assets.
func (s *Server) handleDampIssuePrepare(w http.ResponseWriter, r *http.Request) {
	if !s.requireDamp(w) {
		return
	}
	req := dampIssueRequest{Precision: precisionUnset}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	precision, err := normalizePrecision(req.Precision)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	req.Precision = precision
	if req.Name == "" || req.Ticker == "" {
		httpErr(w, 400, "name and ticker are required")
		return
	}
	if req.Atoms == 0 {
		httpErr(w, 400, "atoms must be positive")
		return
	}
	if _, err := parseXOnly("holder_pubkey", req.HolderPubkey); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if _, err := parseXOnly("issuer_update_key", req.IssuerUpdateKey); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	wlRoot, err := dampWhitelistRoot(req.Whitelist, req.HolderPubkey)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	q := req.VerifierAmount
	if q == 0 {
		q = 1
	}
	if req.IssuerAID != "" {
		known := false
		s.st.View(func(st *store.State) { _, known = st.Users[req.IssuerAID] })
		if !known {
			httpErr(w, 404, "issuer_aid must be a registered user when supplied")
			return
		}
	}
	network := req.Network
	if network == "" {
		network = "testnet"
	}

	// Policy key. Generated but never used to authorize a transfer of this asset;
	// see dampContract for why it is still committed.
	policyX, policyRef, err := s.signer.GeneratePolicyKey()
	if err != nil {
		httpErr(w, 500, "policy key: %v", err)
		return
	}

	// Step 1 of opendamp-design.md section 5: issue V. Its id depends on nothing
	// about A, which is what breaks the circularity. Funding must cover this
	// transaction's fee and the NEXT one's, because phase 2 spends this
	// transaction's fee change as A's issuance input.
	funding, err := s.feeUTXO(s.cfg.FeeSats * 4)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	if funding == nil {
		httpErr(w, 503, "no funding utxo")
		return
	}
	if funding.sats < s.cfg.FeeSats*3 {
		httpErr(w, 503, "funding coin of %d atoms is too small for a two-transaction issuance (needs > %d)", funding.sats, s.cfg.FeeSats*3)
		return
	}
	vContract, err := canonicalJSON(verifierContract(req.Name, req.Ticker))
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	vDigest := sha256.Sum256(vContract)
	_, vAssetID, vTokenID := fastmerkle.DeriveIssuanceIDs(internalHash(funding.txid), funding.vout, vDigest)
	vAssetDisplay := displayHash(vAssetID)

	walletAddr, err := s.wallet.GetNewAddress()
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	walletInfo, err := s.wallet.GetAddressInfo(walletAddr)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	walletSpk := mustHexBytes(walletInfo.ScriptPubKey)
	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)

	// V's issuance is fully transparent. There is no confidential option here on
	// purpose: the covenant must read explicit asset ids on the outputs it scans,
	// so a blinded verifier output could not satisfy input zero at all.
	vTx := &elements.Tx{Version: 2}
	vTx.In = append(vTx.In, &elements.TxIn{
		Prevout: elements.OutPoint{Hash: internalHash(funding.txid), N: funding.vout},
		Issuance: &elements.AssetIssuance{
			Entropy:       vDigest,
			Amount:        elements.ExplicitValue(q),
			InflationKeys: elements.ExplicitValue(1_0000_0000),
			Denomination:  0,
		},
	})
	// Output order is load-bearing: phase 2 spends vout 0 (the q units of V) into
	// C_V and vout 2 (the fee change) as A's issuance input, both by outpoint.
	vTx.Out = append(vTx.Out,
		&elements.TxOut{Asset: elements.ExplicitAssetInternal(vAssetID), Value: elements.ExplicitValue(q),
			Nonce: elements.NullNonce(), ScriptPubKey: walletSpk},
		&elements.TxOut{Asset: elements.ExplicitAssetInternal(vTokenID), Value: elements.ExplicitValue(1_0000_0000),
			Nonce: elements.NullNonce(), ScriptPubKey: walletSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(funding.sats - s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: walletSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	vSigned, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(vTx.Serialize()))
	if err != nil {
		httpErr(w, 502, "sign verifier issuance: %v", err)
		return
	}
	if !vSigned.Complete {
		httpErr(w, 502, "verifier issuance signing incomplete: %+v", vSigned.Errors)
		return
	}
	if err := s.mempoolGate("damp-issue", vSigned.Hex, map[string]any{
		"phase": "verifier-issue", "ticker": req.Ticker,
	}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}

	// A's contract and id. Its funding outpoint is the V transaction's fee change,
	// which is deterministic before broadcast, so the asset id is fixed here and
	// no second confirmed coin is needed.
	contract, err := canonicalJSON(req.dampContract(hex.EncodeToString(policyX[:]), vAssetDisplay, q))
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	digest := sha256.Sum256(contract)
	// The txid of a fully signed transaction is determined by its bytes, so this
	// local computation is authoritative and sendrawtransaction's return value is
	// only a broadcast acknowledgement. Both of phase 2's outpoints (A's funding
	// input and the V input) are taken from here, never from the RPC reply, so the
	// asset id phase 1 commits to is the asset id phase 2 produces.
	vTxid := vTx.TxID()
	const aFundingVout = uint32(2)
	aFundingSats := funding.sats - s.cfg.FeeSats
	entropy, assetID, tokenID := fastmerkle.DeriveIssuanceIDs(internalHash(vTxid), aFundingVout, digest)
	assetDisplay := displayHash(assetID)

	// pi_0 over the now-known asset id. The genesis blacklist is EMPTY, which is
	// not the same as absent: the empty interval tree has a root (the guard
	// interval) and the covenant proves non-membership against it on every
	// regulated input, so a fresh asset with nothing frozen still commits to that
	// root. A later freeze is a policy update that publishes a new root, exactly
	// like a whitelist change. Windows are omitted: no shipped program reads them.
	blRoot, err := damp.BlacklistRoot(nil)
	if err != nil {
		httpErr(w, 500, "genesis blacklist root: %v", err)
		return
	}
	pi := damp.PiCovenant(assetID, 0, damp.RulesRootCovenant(&blRoot, &wlRoot, 0, nil))
	piHex := hex.EncodeToString(pi[:])

	snap := &damp.Snapshot{
		V: 1, Asset: assetDisplay, VerifierAsset: vAssetDisplay, Q: q,
		Pi: piHex, Seq: 0, PrevPi: nil, Tree: damp.TreeDMTv1,
		Predicates: damp.Predicates{
			Blacklist: damp.PredicateList{Root: hex.EncodeToString(blRoot[:]), Entries: []damp.PredicateEntry{}},
			// The genesis holder list carries no height bounds. A lockup or a receive
			// window is set by a later policy update, which is the only place bounds can
			// come from anyway: they bind heights, and at issuance there is no height to
			// bind them to yet.
			Whitelist: damp.PredicateList{Root: hex.EncodeToString(wlRoot[:]), Entries: damp.KeyEntries(req.Whitelist)},
		},
	}
	if err := snap.Validate(); err != nil {
		httpErr(w, 500, "genesis snapshot is not self-consistent: %v", err)
		return
	}
	snapCanonical, err := snap.CanonicalJSON()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	snapHash, err := snap.Hash()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	sigMsg, err := snap.SigMessage()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}

	// Persist the prepare BEFORE broadcasting V. A crash after this write and
	// before the broadcast leaves a prepare whose V transaction never confirmed;
	// completing it then fails at the mempool gate with the node's own reason,
	// which is recoverable by preparing again. The opposite order could broadcast
	// a V issuance no record points at.
	pending := &store.PendingDampIssuance{
		ID: newID(), Name: req.Name, Ticker: req.Ticker, Precision: req.Precision, Atoms: req.Atoms,
		HolderPubkey: req.HolderPubkey, Whitelist: req.Whitelist, WhitelistRoot: hex.EncodeToString(wlRoot[:]),
		VerifierAsset: vAssetDisplay, VerifierAmount: q, VerifierToken: displayHash(vTokenID), VerifierVout: 0,
		VerifierIssueTxid: vTxid,
		IssuerUpdateKey:   req.IssuerUpdateKey, IssuerAID: req.IssuerAID, BurnAllowed: req.BurnAllowed,
		PolicyPub: hex.EncodeToString(policyX[:]), PolicyRef: policyRef,
		Contract: contract, ContractHash: displayHash(digest),
		AssetID: assetDisplay, Entropy: displayHash(entropy), Token: displayHash(tokenID),
		FundingTxid: vTxid, FundingVout: aFundingVout, FundingSats: aFundingSats,
		Pi: piHex, Snapshot: snapCanonical,
		SnapshotHash: hex.EncodeToString(snapHash[:]), SnapshotSigMsg: hex.EncodeToString(sigMsg[:]),
		Created: time.Now(),
	}
	s.st.GCPendingDampIssuances(dampPrepareTTL)
	if err := s.st.PutPendingDampIssuance(pending); err != nil {
		httpErr(w, 500, "persist prepared issuance: %v", err)
		return
	}
	if _, err := s.wallet.SendRawTransaction(vSigned.Hex); err != nil {
		httpErr(w, 502, "broadcast verifier issuance: %v", err)
		return
	}
	s.st.AppendLog("damp-issue", map[string]any{
		"phase": "prepare", "prepare_id": pending.ID, "asset": assetDisplay,
		"verifier_asset": vAssetDisplay, "verifier_issue_txid": vTxid,
		"pi": piHex, "whitelist_root": pending.WhitelistRoot, "contract_hash": pending.ContractHash,
	})

	// The derive-ready document is the canonical snapshot plus the two fields
	// `opendamp derive` needs and the snapshot format does not carry: the issuer
	// update key (a compile-time parameter of G) and the chain (address encoding
	// only). Extra keys are ignored by the CLI's deserializer, and they are NOT
	// part of the canonical bytes the hash and signature commit to.
	var deriveDoc map[string]any
	_ = json.Unmarshal(snapCanonical, &deriveDoc)
	deriveDoc["issuer_update_key"] = req.IssuerUpdateKey
	deriveDoc["network"] = network

	httpJSON(w, map[string]any{
		"prepare_id":           pending.ID,
		"asset":                assetDisplay,
		"contract":             json.RawMessage(contract),
		"contract_hash":        pending.ContractHash,
		"verifier_asset":       vAssetDisplay,
		"verifier_amount":      q,
		"verifier_issue_txid":  vTxid,
		"pi":                   piHex,
		"whitelist_root":       pending.WhitelistRoot,
		"tree":                 damp.TreeDMTv1,
		"snapshot":             json.RawMessage(snapCanonical),
		"snapshot_hash":        pending.SnapshotHash,
		"snapshot_sig_message": pending.SnapshotSigMsg,
		"derive_snapshot":      deriveDoc,
		"next": "run `opendamp derive --snapshot <derive_snapshot>` and POST its u_cmr, p_cmr (as verifier_cmr), " +
			"g_cmr, pi and C_V(pi) spk to /v1/issuer/damp-assets/" + pending.ID + "/complete. " +
			"Nothing of asset " + assetDisplay + " exists on chain until you do.",
	})
}

// --- phase 2: complete -------------------------------------------------------

// handleDampIssueComplete is POST /v1/issuer/damp-assets/{id}/complete: it mints
// A straight into C_U(holder) and locks q of V into C_V(pi_0) in ONE
// transaction, so there is no window in which A exists without its verifier
// output and therefore none in which A can move unpoliced.
func (s *Server) handleDampIssueComplete(w http.ResponseWriter, r *http.Request) {
	if !s.requireDamp(w) {
		return
	}
	id := r.PathValue("id")
	var req dampCompleteRequest
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	p, ok := s.st.GetPendingDampIssuance(id)
	if !ok {
		httpErr(w, 404, "unknown or expired prepared issuance; POST /v1/issuer/damp-assets again")
		return
	}
	// A completed prepare is consumed, so this is also the once-only guard.
	var already *store.Asset
	s.st.View(func(st *store.State) {
		if a, has := st.Assets[p.AssetID]; has {
			cp := *a
			already = &cp
		}
	})
	if already != nil {
		httpErr(w, 409, "asset %s is already issued", p.AssetID)
		return
	}

	userCMR, err := parseCMR("user_cmr", req.UserCMR)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	verifierCMRs, err := parseCMRMenu(req.VerifierCMRs, req.VerifierCMR)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	issuerCMR := s.dampReg.IssuerCMR
	if req.IssuerCMR != "" {
		issuerCMR, err = parseCMR("issuer_cmr", req.IssuerCMR)
		if err != nil {
			httpErr(w, 400, "%v", err)
			return
		}
	}

	// THE AUTHORITY SPLIT. The server recomputes pi from the policy it stored at
	// prepare and refuses unless the operator's derive run agrees. That is what
	// keeps this server authoritative about policy: a CMR it cannot compile is
	// accepted only alongside a pi it can, and does, check.
	var keys [][32]byte
	for i, e := range p.Whitelist {
		k, err := parseXOnly(fmt.Sprintf("whitelist[%d]", i), e)
		if err != nil {
			httpErr(w, 500, "stored whitelist is corrupt: %v", err)
			return
		}
		keys = append(keys, k)
	}
	wlRoot, err := damp.WhitelistRoot(keys)
	if err != nil {
		httpErr(w, 500, "stored whitelist is corrupt: %v", err)
		return
	}
	blRoot, err := damp.BlacklistRoot(nil)
	if err != nil {
		httpErr(w, 500, "genesis blacklist root: %v", err)
		return
	}
	assetInternal := internalHash(p.AssetID)
	want := damp.PiCovenant(assetInternal, 0, damp.RulesRootCovenant(&blRoot, &wlRoot, 0, nil))
	wantHex := hex.EncodeToString(want[:])
	if wantHex != p.Pi {
		httpErr(w, 500, "stored pi %s no longer matches the stored policy (%s)", p.Pi, wantHex)
		return
	}
	if req.Pi != wantHex {
		logRefusal("damp-issue", s.st, map[string]any{
			"reason": "pi mismatch", "phase": "complete", "prepare_id": id,
			"asset": p.AssetID, "supplied_pi": req.Pi, "expected_pi": wantHex,
		})
		httpErr(w, 409, "pi mismatch: this policy commits to %s but the covenant parameters were derived against %s. Re-run `opendamp derive` against the snapshot this server returned; nothing was broadcast.", wantHex, req.Pi)
		return
	}

	userCov, err := elements.UserCovenant(userCMR, elements.MustHex32(p.HolderPubkey))
	if err != nil {
		httpErr(w, 500, "derive user covenant: %v", err)
		return
	}
	verifierCov, err := elements.VerifierCovenant(verifierCMRs, issuerCMR)
	if err != nil {
		httpErr(w, 500, "derive verifier covenant: %v", err)
		return
	}
	verifierSpkHex := hex.EncodeToString(verifierCov.ScriptPubKey())
	if req.VerifierSPK != "" && req.VerifierSPK != verifierSpkHex {
		httpErr(w, 409, "verifier_spk mismatch: verifier_cmr derives %s, not %s", verifierSpkHex, req.VerifierSPK)
		return
	}

	// The genesis snapshot, from the exact canonical bytes phase 1 returned (and
	// the operator may have signed).
	var snap damp.Snapshot
	if err := json.Unmarshal(p.Snapshot, &snap); err != nil {
		httpErr(w, 500, "stored genesis snapshot is corrupt: %v", err)
		return
	}
	if err := snap.Validate(); err != nil {
		httpErr(w, 500, "stored genesis snapshot is not self-consistent: %v", err)
		return
	}
	if req.SnapshotSig != "" {
		snap.IssuerSig = req.SnapshotSig
		if err := snap.Verify(p.IssuerUpdateKey); err != nil {
			httpErr(w, 400, "snapshot_sig: %v", err)
			return
		}
	}

	// The funding outpoint must still be spendable. It is phase 1's fee change,
	// so the usual way to lose it is another server-funded transaction picking it
	// up between the phases.
	if !s.utxoUnspent(p.FundingTxid, p.FundingVout) {
		httpErr(w, 409, "the prepared funding output %s:%d is gone, so asset id %s can no longer be produced; POST /v1/issuer/damp-assets again", p.FundingTxid, p.FundingVout, p.AssetID)
		return
	}

	feeAssetID := elements.MustHex32(s.cfg.FeeAsset)
	assetID := internalHash(p.AssetID)
	tokenID := internalHash(p.Token)
	vAssetID := elements.MustHex32(p.VerifierAsset)
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
	changeSpk := mustHexBytes(changeInfo.ScriptPubKey)

	// The contract hash is stored display-hex; the issuance entropy field takes
	// the same bytes phase 1 hashed into the asset id, i.e. the internal order.
	digest := internalHash(p.ContractHash)

	tx := &elements.Tx{Version: 2}
	// Input 0 carries the issuance of A and pays the fee; input 1 is the q units
	// of V phase 1 minted, which this transaction moves into C_V(pi_0).
	tx.In = append(tx.In,
		&elements.TxIn{
			Prevout: elements.OutPoint{Hash: internalHash(p.FundingTxid), N: p.FundingVout},
			Issuance: &elements.AssetIssuance{
				Entropy:       digest,
				Amount:        elements.ExplicitValue(p.Atoms),
				InflationKeys: elements.ExplicitValue(1_0000_0000),
				Denomination:  uint64(p.Precision),
			},
		},
		&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(p.VerifierIssueTxid), N: p.VerifierVout}},
	)
	tx.Out = append(tx.Out,
		&elements.TxOut{Asset: elements.ExplicitAssetInternal(assetID), Value: elements.ExplicitValue(p.Atoms),
			Nonce: elements.NullNonce(), ScriptPubKey: userCov.ScriptPubKey()},
		&elements.TxOut{Asset: elements.ExplicitAssetInternal(tokenID), Value: elements.ExplicitValue(1_0000_0000),
			Nonce: elements.NullNonce(), ScriptPubKey: changeSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(vAssetID), Value: elements.ExplicitValue(p.VerifierAmount),
			Nonce: elements.NullNonce(), ScriptPubKey: verifierCov.ScriptPubKey()},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(p.FundingSats - s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: changeSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(s.cfg.FeeSats),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(tx.Serialize()))
	if err != nil {
		httpErr(w, 502, "sign: %v", err)
		return
	}
	if !signed.Complete {
		httpErr(w, 502, "issuance signing incomplete: %+v", signed.Errors)
		return
	}
	if err := s.mempoolGate("damp-issue", signed.Hex, map[string]any{
		"phase": "complete", "prepare_id": id, "asset": p.AssetID, "ticker": p.Ticker,
	}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	// Bind the policy key before broadcast, for the same reason handleIssue does:
	// a bound key for an asset that never reached the chain is harmless, the
	// reverse is not.
	if err := s.signer.Adopt(p.PolicyRef, p.AssetID); err != nil {
		httpErr(w, 500, "bind policy key: %v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		httpErr(w, 502, "broadcast: %v", err)
		return
	}

	userAddr := s.addressOfSPK(userCov.ScriptPubKey())
	verifierAddr := s.addressOfSPK(verifierCov.ScriptPubKey())
	asset := &store.Asset{
		ID: p.AssetID, Ticker: p.Ticker, Name: p.Name, Precision: p.Precision,
		Contract: p.Contract, ContractHash: p.ContractHash,
		PolicyPub: p.PolicyPub,
		// For a damp asset the issuer key IS the update key, and it is external by
		// construction: this server never holds it, so a later snapshot posted for
		// this asset verifies against exactly the key the contract commits to.
		IssuerPub: p.IssuerUpdateKey, IssuerExternal: true,
		IssuerAID: p.IssuerAID, Clawback: false, BurnAllowed: p.BurnAllowed,
		Entropy: p.Entropy, Token: p.Token,
		IssueTxid:   txid,
		Enforcement: "damp",
		Damp: &store.DampBinding{
			VerifierAsset: p.VerifierAsset, VerifierAmount: p.VerifierAmount,
			VerifierIssueTxid: p.VerifierIssueTxid, IssuerUpdateKey: p.IssuerUpdateKey,
			HolderPubkey: p.HolderPubkey, Pi: p.Pi, WhitelistRoot: p.WhitelistRoot,
			// The whitelist is retained, not just its root: these keys are the only
			// enumeration of this asset's possible holders (a damp holder never has to
			// register with this server), so the ownership report and the supply figure
			// derive their scan set from here. Later seqs keep it current through the
			// policy-update path.
			Whitelist: damp.KeyEntries(p.Whitelist),
			Tree:      damp.TreeDMTv1,
			UserCMR: req.UserCMR,
			VerifierCMR:  cmrHexList(verifierCMRs)[0],
			VerifierCMRs: cmrHexList(verifierCMRs),
			IssuerCMR:    hex.EncodeToString(issuerCMR[:]),
			UserCovenantSPK: hex.EncodeToString(userCov.ScriptPubKey()), UserCovenantAddr: userAddr,
			VerifierSPK: verifierSpkHex, VerifierAddr: verifierAddr,
		},
	}
	if err := s.st.Update(func(st *store.State) error {
		st.Assets[p.AssetID] = asset
		return nil
	}); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	// Publish seq 0 through the existing snapshot store, so GET /v1/snapshots
	// serves it exactly like any other and the sequencing invariant (gapless,
	// first is 0) is the same code path.
	snapCanonical, err := snap.CanonicalJSON()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	snapHash, err := snap.Hash()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if err := s.st.AppendSnapshot(p.AssetID, &store.StoredSnapshot{
		Seq: 0, Pi: p.Pi, Hash: hex.EncodeToString(snapHash[:]), IssuerPub: p.IssuerUpdateKey,
		Canonical: snapCanonical, IssuerSig: snap.IssuerSig,
	}); err != nil {
		httpErr(w, 500, "publish genesis snapshot: %v", err)
		return
	}
	if err := s.st.DeletePendingDampIssuance(id); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	s.st.AppendLog("damp-issue", map[string]any{
		"phase": "complete", "prepare_id": id, "asset": p.AssetID, "txid": txid,
		"atoms": p.Atoms, "pi": p.Pi, "snapshot_signed": snap.IssuerSig != "",
		"user_covenant_spk": asset.Damp.UserCovenantSPK, "verifier_covenant_spk": verifierSpkHex,
	})
	s.st.AppendLog("snapshot", map[string]any{
		"asset": p.AssetID, "seq": 0, "pi": p.Pi, "hash": hex.EncodeToString(snapHash[:]),
	})

	httpJSON(w, map[string]any{
		"asset":          p.AssetID,
		"verifier_asset": p.VerifierAsset,
		"txids": map[string]string{
			// asset_issue and verifier_lock are the SAME transaction on purpose: A is
			// minted into C_U and q of V is locked into C_V(pi_0) atomically.
			"verifier_issue": p.VerifierIssueTxid,
			"asset_issue":    txid,
			"verifier_lock":  txid,
		},
		"pi":                        p.Pi,
		"whitelist_root":            p.WhitelistRoot,
		"user_covenant_address":     userAddr,
		"user_covenant_spk":         asset.Damp.UserCovenantSPK,
		"verifier_covenant_address": verifierAddr,
		"verifier_covenant_spk":     verifierSpkHex,
		"contract":                  json.RawMessage(p.Contract),
		"contract_hash":             p.ContractHash,
		"snapshot_seq":              0,
		"snapshot_signed":           snap.IssuerSig != "",
	})
}

// --- damp-aware reads --------------------------------------------------------

// dampHolderSPK is the covenant scriptPubKey a given owner key holds a damp
// asset at: C_U(X) under the asset's recorded user program. There is no enclave
// and no policy half, so this is the whole of the address derivation.
func dampHolderSPK(asset *store.Asset, ownerXOnly string) ([]byte, error) {
	if asset.Damp == nil {
		return nil, fmt.Errorf("asset %s carries no network-enforcement binding", asset.ID)
	}
	cmr, err := parseCMR("user_cmr", asset.Damp.UserCMR)
	if err != nil {
		return nil, err
	}
	owner, err := parseXOnly("owner", ownerXOnly)
	if err != nil {
		return nil, err
	}
	cov, err := elements.UserCovenant(cmr, owner)
	if err != nil {
		return nil, err
	}
	return cov.ScriptPubKey(), nil
}
