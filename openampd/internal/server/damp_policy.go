package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp/dmt"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// Policy updates for a network-enforced (OpenDAMP) asset: the freeze path.
//
// For a co-signed asset a freeze is a flag this server checks before it signs.
// For a network-enforced one there is no signature to withhold, so a freeze is a
// PUBLICATION plus a SPEND:
//
//  1. publish snapshot seq n+1 whose whitelist drops the holder (the covenant
//     checks the owner key of every regulated input, so a dropped key can no
//     longer spend) and/or whose blacklist lists an outpoint (that UTXO alone
//     stops moving); and
//  2. respend the verifier output through the issuer path G(I) so the on-chain
//     C_V commits to the NEW pi. Until step 2 confirms, holders still transfer
//     under the old policy, because the old C_V is what their transfers spend.
//
// Both are reversible by a further update: restoring the key, or dropping the
// listing, is one more seq (opendamp/STATUS.md proofs 7g/7h and 8e/8f).
//
// # THE SEAM, AGAIN
//
// This runs into the same wall issuance does, and resolves it the same way.
// P is parameterized by pi at COMPILE time, so the new C_V address needs the
// SimplicityHL compiler; and the G(I) spend needs an encoded Simplicity program
// plus its witness, which no Go code here can produce. What this server IS
// authoritative about is POLICY: it recomputes the whitelist and blacklist roots
// and pi_{n+1} from the snapshot chain it publishes, and it refuses a completion
// whose parameters disagree with them.
//
//	  prepare   POST /v1/issuer/damp-policy
//	            Applies the requested change to the CURRENT published policy,
//	            recomputes pi_{n+1}, builds and validates snapshot n+1, logs the
//	            REASON publicly, and returns the derive-ready document plus the
//	            32 bytes the issuer must sign. Nothing is signed, published or
//	            broadcast.
//	  (issuer)  opendamp derive --snapshot <derive_snapshot>
//	            gives the new p_cmr and C_V(pi_{n+1}) scriptPubKey;
//	            opendamp issuer-update --snapshot <current> --next-snapshot <next>
//	            gives the finished, signed respend.
//	  complete  POST /v1/issuer/damp-policy/{id}/complete
//	            Verifies the issuer's snapshot signature against the asset's
//	            issuer_update_key, checks the supplied CMR/scriptPubKey against
//	            the pi this server computed, checks the transaction actually
//	            consumes the recorded verifier outpoint and recreates C_V under
//	            the new policy, then broadcasts it and publishes seq n+1.
//
// # WHY THE ISSUER SIGNATURE IS THE SNAPSHOT SIGNATURE
//
// The issuer update key is EXTERNAL by construction (damp_issue.go): this server
// never holds it, and every published seq after 0 has always had to carry that
// key's BIP340 signature over the snapshot (snapshots.go). That signature is the
// one this server can and does verify, and it is what makes the published policy
// attributable. The signature INSIDE the G(I) witness authorises the coin
// movement and is checked by consensus, not here; this server checks the spend
// structurally instead (right outpoint in, right C_V out, right asset and q) and
// lets the node reject anything else at the mempool gate.

// dampPolicyPrepareTTL bounds how long a prepared policy update waits for its
// recompiled parameters. Same generosity as issuance: the issuer may run the
// derivation on another machine and sign the snapshot offline.
const dampPolicyPrepareTTL = 72 * time.Hour

// dampPolicyParamsMissing is the exact refusal a completion gets when the
// recompiled verifier CMR or the finished respend is absent.
const dampPolicyParamsMissing = "a policy update needs the recompiled verifier program and the finished verifier respend: run `opendamp derive` against derive_snapshot for verifier_cmr, then `opendamp issuer-update` for signed_tx. Nothing has been published or broadcast."

// --- request shapes ----------------------------------------------------------

// dampOutpointRef names one UTXO to freeze or unfreeze, in the DISPLAY txid form
// every explorer and RPC uses. The policy key the covenant reads is derived from
// the internal byte order, which is this server's job to get right; getting it
// backwards produces a root that looks correct and freezes nothing.
type dampOutpointRef struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

func (o dampOutpointRef) String() string { return fmt.Sprintf("%s:%d", o.Txid, o.Vout) }

// key is the blacklist policy key: SHA256(txid_internal || BE32(vout)).
func (o dampOutpointRef) key() ([32]byte, error) {
	b, err := hex.DecodeString(o.Txid)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("txid %q must be 32-byte hex", o.Txid)
	}
	return dmt.OutpointKey(internalHash(o.Txid), o.Vout), nil
}

// dampPolicyRequest is the POST /v1/issuer/damp-policy body. Every field is a
// DELTA against the currently published policy, never a replacement set: an
// issuer who names one holder cannot accidentally drop every other one.
type dampPolicyRequest struct {
	Asset string `json:"asset"`

	// AddWhitelist admits holders. Each element is either a bare 32-byte key or an
	// object {key, send_after, recv_after}, so a holder can be admitted WITH a
	// lockup or a receive window in one step rather than admitted first and bounded
	// afterwards (which would leave a window in which they were unbounded).
	AddWhitelist    []damp.PredicateEntry `json:"add_whitelist,omitempty"`
	RemoveWhitelist []string              `json:"remove_whitelist,omitempty"`
	// SetWindows changes the height bounds of holders who are ALREADY admitted.
	// Setting both bounds to zero lifts them. It is a separate field from
	// AddWhitelist because "admit someone" and "change what binds someone" are
	// different intentions, and confusing them is how a holder silently loses a
	// lockup.
	SetWindows []damp.PredicateEntry `json:"set_windows,omitempty"`

	AddBlacklist    []dampOutpointRef `json:"add_blacklist,omitempty"`
	RemoveBlacklist []dampOutpointRef `json:"remove_blacklist,omitempty"`

	// Reason is REQUIRED and goes into the public transparency log BEFORE
	// anything is signed, exactly like a clawback. A freeze without a stated
	// reason is not a freeze this server will help build.
	Reason string `json:"reason"`
}

// dampPolicyCompleteRequest is the POST /v1/issuer/damp-policy/{id}/complete
// body.
type dampPolicyCompleteRequest struct {
	// Sig is the issuer update key's BIP340 signature over the to_sign prepare
	// returned (the tagged snapshot hash). It is what makes seq n+1 attributable.
	Sig string `json:"sig"`
	// VerifierCMR is the CMR of P(pi_{n+1}) from `opendamp derive`. It must differ
	// from the current one: an unchanged CMR means the derivation ran against the
	// old policy, and the respend would recreate the OLD C_V.
	VerifierCMR string `json:"verifier_cmr"`
	// VerifierSPK is optional; when present it must equal the scriptPubKey this
	// server derives from VerifierCMR.
	VerifierSPK string `json:"verifier_spk,omitempty"`
	// SignedTx is the finished issuer-path respend, ready to broadcast.
	SignedTx string `json:"signed_tx"`
}

// --- prepare -----------------------------------------------------------------

// handleDampPolicyPrepare is POST /v1/issuer/damp-policy.
func (s *Server) handleDampPolicyPrepare(w http.ResponseWriter, r *http.Request) {
	if !s.requireDamp(w) {
		return
	}
	var req dampPolicyRequest
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		httpErr(w, 400, "a reason is required; it becomes part of the public transparency log before anything is signed")
		return
	}
	asset := s.dampAsset(w, req.Asset)
	if asset == nil {
		return
	}

	latest, ok := s.st.LatestSnapshot(asset.ID)
	if !ok {
		httpErr(w, 409, "asset %s has no published policy to update", asset.ID)
		return
	}
	var cur damp.Snapshot
	if err := json.Unmarshal(latest.Canonical, &cur); err != nil {
		httpErr(w, 500, "the published policy for %s is corrupt: %v", asset.ID, err)
		return
	}
	if cur.Tree != damp.TreeDMTv1 {
		httpErr(w, 409, "asset %s publishes %q policies, which no covenant reads; only %q can be updated here", asset.ID, cur.Tree, damp.TreeDMTv1)
		return
	}

	next, change, err := applyPolicyDelta(&cur, &req)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}

	// pi_{n+1} over the new roots at the new seq, chained to the published pi.
	prev := cur.Pi
	next.Seq = cur.Seq + 1
	next.PrevPi = &prev
	wlRoot, blRoot, pi, err := dampRoots(asset.ID, next)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	next.Pi = hex.EncodeToString(pi[:])
	if err := next.Validate(); err != nil {
		httpErr(w, 500, "the updated policy is not self-consistent: %v", err)
		return
	}
	canonical, err := next.CanonicalJSON()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	snapHash, err := next.Hash()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	sigMsg, err := next.SigMessage()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}

	// Where the verifier output lives right now. It is what the respend must
	// consume, and its absence is itself an answer: a halted asset (V spent out of
	// the covenant) can never be updated again, and saying so is better than
	// building a transaction against a coin that is gone.
	outTxid, outVout, err := s.dampVerifierOutpoint(asset)
	if err != nil {
		httpErr(w, 409, "%v", err)
		return
	}

	// The public notice precedes the signature, exactly as a clawback's does. It
	// is written before the pending record so that even a crashed prepare leaves
	// the intent on the record.
	s.st.AppendLog("damp-policy", map[string]any{
		"phase": "prepare", "asset": asset.ID, "seq": next.Seq, "pi": next.Pi, "prev_pi": prev,
		"reason": strings.TrimSpace(req.Reason), "whitelist_root": hex.EncodeToString(wlRoot[:]),
		"blacklist_root":    hex.EncodeToString(blRoot[:]),
		"added_holders":     change.addedHolders,
		"removed_holders":   change.removedHolders,
		"added_outpoints":   change.addedOutpoints,
		"removed_outpoints": change.removedOutpoints,
	})

	pending := &store.PendingDampPolicy{
		ID: newID(), AssetID: asset.ID, Reason: strings.TrimSpace(req.Reason),
		Seq: next.Seq, PrevPi: prev, Pi: next.Pi,
		Whitelist: next.Predicates.Whitelist.Entries, Blacklist: next.Predicates.Blacklist.Keys(),
		WhitelistRoot: hex.EncodeToString(wlRoot[:]), BlacklistRoot: hex.EncodeToString(blRoot[:]),
		AddedHolders: change.addedHolders, RemovedHolders: change.removedHolders,
		AddedOutpoints: change.addedOutpoints, RemovedOutpoints: change.removedOutpoints,
		VerifierAsset: asset.Damp.VerifierAsset, VerifierAmount: asset.Damp.VerifierAmount,
		VerifierTxid: outTxid, VerifierVout: outVout,
		VerifierSPKPrev: asset.Damp.VerifierSPK, VerifierCMRPrev: asset.Damp.VerifierCMR,
		IssuerUpdateKey: asset.Damp.IssuerUpdateKey,
		Snapshot:        canonical, SnapshotHash: hex.EncodeToString(snapHash[:]),
		SnapshotSigMsg: hex.EncodeToString(sigMsg[:]), Created: time.Now(),
	}
	s.st.GCPendingDampPolicies(dampPolicyPrepareTTL)
	if err := s.st.PutPendingDampPolicy(pending); err != nil {
		httpErr(w, 500, "persist prepared policy update: %v", err)
		return
	}

	// The derive-ready document is the canonical NEXT snapshot plus the issuer
	// update key, which is a compile-time parameter of G and is not part of the
	// snapshot format. It is outside the bytes the hash and signature cover.
	var deriveDoc map[string]any
	_ = json.Unmarshal(canonical, &deriveDoc)
	deriveDoc["issuer_update_key"] = asset.Damp.IssuerUpdateKey

	httpJSON(w, map[string]any{
		"policy_id":      pending.ID,
		"asset":          asset.ID,
		"seq":            next.Seq,
		"prev_pi":        prev,
		"pi_next":        next.Pi,
		"whitelist":      next.Predicates.Whitelist.Entries,
		"whitelist_root": pending.WhitelistRoot,
		"blacklist":      next.Predicates.Blacklist.Entries,
		"blacklist_root": pending.BlacklistRoot,
		"change": map[string]any{
			"added_holders":     change.addedHolders,
			"removed_holders":   change.removedHolders,
			"added_outpoints":   change.addedOutpoints,
			"removed_outpoints": change.removedOutpoints,
		},
		"snapshot":             json.RawMessage(canonical),
		"snapshot_hash":        pending.SnapshotHash,
		"to_sign":              pending.SnapshotSigMsg,
		"sign_with":            "issuer_update_key",
		"issuer_update_key":    asset.Damp.IssuerUpdateKey,
		"verifier_outpoint":    map[string]any{"txid": outTxid, "vout": outVout},
		"verifier_asset":       asset.Damp.VerifierAsset,
		"verifier_amount":      asset.Damp.VerifierAmount,
		"verifier_cmr_current": asset.Damp.VerifierCMR,
		"verifier_spk_current": asset.Damp.VerifierSPK,
		"verifier_cmr_next_hint": "the verifier program is parameterized by the policy commitment, so pi_next needs a NEW verifier_cmr. " +
			"Run `opendamp derive` against derive_snapshot and post its p_cmr; a verifier_cmr equal to verifier_cmr_current is refused, " +
			"because it would recreate the old policy.",
		"derive_snapshot": deriveDoc,
		"next": "run `opendamp derive --snapshot <derive_snapshot>` for the new verifier CMR and address, then " +
			"`opendamp issuer-update --snapshot <current> --next-snapshot <derive_snapshot> --request <fee utxo> --issuer-privkey <key>` " +
			"for the signed respend, and POST both to /v1/issuer/damp-policy/" + pending.ID + "/complete with your signature over to_sign. " +
			"Nothing is published or broadcast until you do, and holders keep transferring under the current policy until it confirms.",
	})
}

// --- complete ----------------------------------------------------------------

// handleDampPolicyComplete is POST /v1/issuer/damp-policy/{id}/complete.
func (s *Server) handleDampPolicyComplete(w http.ResponseWriter, r *http.Request) {
	if !s.requireDamp(w) {
		return
	}
	id := r.PathValue("id")
	var req dampPolicyCompleteRequest
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	// Idempotent replay: a completed update returns its txid and never
	// re-broadcasts or re-publishes.
	if txid, done := s.st.GetDampPolicy(id); done {
		httpJSON(w, map[string]any{"policy_id": id, "txid": txid, "idempotent": true})
		return
	}
	p, ok := s.st.GetPendingDampPolicy(id)
	if !ok {
		httpErr(w, 404, "unknown or expired policy update; POST /v1/issuer/damp-policy again")
		return
	}
	asset := s.dampAsset(w, p.AssetID)
	if asset == nil {
		return
	}
	if strings.TrimSpace(req.VerifierCMR) == "" || strings.TrimSpace(req.SignedTx) == "" {
		httpErr(w, 409, "%s", dampPolicyParamsMissing)
		return
	}

	// 1. The issuer's signature over the snapshot. Checked FIRST, so an
	// unauthorized caller never gets as far as a structural opinion about a
	// transaction it supplied.
	var snap damp.Snapshot
	if err := json.Unmarshal(p.Snapshot, &snap); err != nil {
		httpErr(w, 500, "the prepared policy is corrupt: %v", err)
		return
	}
	snap.IssuerSig = strings.TrimSpace(req.Sig)
	if snap.IssuerSig == "" {
		httpErr(w, 400, "sig is required: every published policy after the first carries the issuer update key's signature")
		return
	}
	if err := snap.Verify(p.IssuerUpdateKey); err != nil {
		logRefusal("damp-policy", s.st, map[string]any{
			"reason": "issuer signature", "phase": "complete", "policy_id": id,
			"asset": p.AssetID, "seq": p.Seq, "detail": err.Error(),
		})
		httpErr(w, 400, "sig: %v (nothing was published or broadcast)", err)
		return
	}

	// 2. This server recomputes pi from the policy IT stored, and refuses if its
	// own record no longer implies the pi it prepared. Same discipline as
	// issuance: the authority split only works if the policy half is re-derived
	// rather than trusted.
	if _, _, pi, err := dampRootsFrom(p.AssetID, p.Seq, p.Whitelist, p.Blacklist, snap.Predicates.Limit); err != nil {
		httpErr(w, 500, "%v", err)
		return
	} else if got := hex.EncodeToString(pi[:]); got != p.Pi {
		httpErr(w, 500, "stored pi %s no longer matches the stored policy (%s)", p.Pi, got)
		return
	}
	if err := snap.Validate(); err != nil {
		httpErr(w, 500, "the prepared policy is not self-consistent: %v", err)
		return
	}

	// 3. The recompiled verifier program. A CMR this server cannot compile is
	// accepted only alongside checks it can make: that it is not the CURRENT one
	// (which would recreate the old policy), and that the scriptPubKey the issuer
	// says it derives is the one this server derives from it.
	verifierCMR, err := parseCMR("verifier_cmr", req.VerifierCMR)
	if err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if strings.EqualFold(req.VerifierCMR, p.VerifierCMRPrev) {
		logRefusal("damp-policy", s.st, map[string]any{
			"reason": "verifier cmr unchanged", "phase": "complete", "policy_id": id,
			"asset": p.AssetID, "seq": p.Seq,
		})
		httpErr(w, 409, "verifier_cmr is the program the CURRENT policy runs, so it was derived against pi %s rather than %s. Re-run `opendamp derive` against the snapshot this update returned; nothing was published or broadcast.", p.PrevPi, p.Pi)
		return
	}
	issuerCMR, err := parseCMR("issuer_cmr", asset.Damp.IssuerCMR)
	if err != nil {
		httpErr(w, 500, "the asset's recorded issuer program is corrupt: %v", err)
		return
	}
	verifierCov, err := elements.VerifierCovenant(verifierCMR, issuerCMR)
	if err != nil {
		httpErr(w, 500, "derive verifier covenant: %v", err)
		return
	}
	verifierSpkHex := hex.EncodeToString(verifierCov.ScriptPubKey())
	if req.VerifierSPK != "" && !strings.EqualFold(req.VerifierSPK, verifierSpkHex) {
		logRefusal("damp-policy", s.st, map[string]any{
			"reason": "verifier spk mismatch", "phase": "complete", "policy_id": id,
			"asset": p.AssetID, "seq": p.Seq, "derived": verifierSpkHex, "supplied": req.VerifierSPK,
		})
		httpErr(w, 409, "verifier_spk mismatch: verifier_cmr derives %s, not %s. Nothing was published or broadcast.", verifierSpkHex, req.VerifierSPK)
		return
	}
	if verifierSpkHex == p.VerifierSPKPrev {
		httpErr(w, 409, "the supplied program derives the CURRENT verifier address, so this update would leave the policy exactly where it is")
		return
	}

	// 4. The respend itself. This server cannot produce a Simplicity witness, so
	// it checks the SHAPE of what it is handed: the recorded verifier outpoint is
	// consumed, and the new C_V is recreated carrying exactly q of V. A
	// transaction failing either is refused unbroadcast rather than sent and
	// regretted.
	tx, err := elements.DeserializeTx(mustHexBytes(req.SignedTx))
	if err != nil {
		httpErr(w, 400, "signed_tx could not be decoded: %v", err)
		return
	}
	if err := checkVerifierRespend(tx, p, verifierCov.ScriptPubKey()); err != nil {
		logRefusal("damp-policy", s.st, map[string]any{
			"reason": "respend shape", "phase": "complete", "policy_id": id,
			"asset": p.AssetID, "seq": p.Seq, "detail": err.Error(),
		})
		httpErr(w, 409, "%v (nothing was published or broadcast)", err)
		return
	}

	// 5. Broadcast, then publish. A snapshot published for a policy that never
	// reached the chain would tell holders to build transfers the current C_V
	// cannot accept, so the order is deliberate and matches issuance.
	if err := s.mempoolGate("damp-policy", req.SignedTx, map[string]any{
		"asset": p.AssetID, "seq": p.Seq, "policy_id": id,
	}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(req.SignedTx)
	if err != nil {
		httpErr(w, 502, "broadcast: %v", err)
		return
	}

	// Publish seq n+1. AppendSnapshot re-checks the gapless sequence under the
	// store lock; a seq already holding exactly this pi means a previous attempt
	// published it and the write of the txid was lost, which is a resume, not a
	// conflict.
	published := true
	if err := s.st.AppendSnapshot(p.AssetID, &store.StoredSnapshot{
		Seq: p.Seq, Pi: p.Pi, Hash: p.SnapshotHash, IssuerPub: p.IssuerUpdateKey,
		Canonical: p.Snapshot, IssuerSig: snap.IssuerSig,
	}); err != nil {
		if prior, ok := s.st.SnapshotAt(p.AssetID, p.Seq); ok && prior.Pi == p.Pi {
			published = false // already published by an attempt whose txid write was lost
		} else {
			httpErr(w, 409, "publish policy snapshot: %v", err)
			return
		}
	}

	// The asset's binding now points at the new policy and the new covenant, so
	// every read (addresses, holders, the derive documents of later updates)
	// answers about the policy that is actually deployed.
	if err := s.st.Update(func(st *store.State) error {
		a, ok := st.Assets[p.AssetID]
		if !ok || a.Damp == nil {
			return fmt.Errorf("asset %s is no longer network-enforced", p.AssetID)
		}
		a.Damp.Pi = p.Pi
		a.Damp.WhitelistRoot = p.WhitelistRoot
		// The stored whitelist moves with its root. It is what the ownership report
		// and the supply figure scan, so a stale copy would report a removed holder's
		// coins forever and miss a newly admitted one entirely.
		a.Damp.Whitelist = p.Whitelist
		a.Damp.VerifierCMR = strings.ToLower(req.VerifierCMR)
		a.Damp.VerifierSPK = verifierSpkHex
		a.Damp.VerifierAddr = s.addressOfSPK(verifierCov.ScriptPubKey())
		return nil
	}); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if err := s.st.MarkDampPolicy(id, txid); err != nil {
		httpErr(w, 500, "persist policy update: %v", err)
		return
	}
	s.st.AppendLog("damp-policy", map[string]any{
		"phase": "complete", "policy_id": id, "asset": p.AssetID, "seq": p.Seq,
		"pi": p.Pi, "prev_pi": p.PrevPi, "txid": txid, "reason": p.Reason,
		"verifier_covenant_spk": verifierSpkHex,
	})
	s.st.AppendLog("snapshot", map[string]any{
		"asset": p.AssetID, "seq": p.Seq, "pi": p.Pi, "hash": p.SnapshotHash,
	})

	httpJSON(w, map[string]any{
		"policy_id": id, "asset": p.AssetID, "txid": txid,
		"seq": p.Seq, "pi": p.Pi, "prev_pi": p.PrevPi,
		"whitelist": p.Whitelist, "whitelist_root": p.WhitelistRoot,
		"blacklist": p.Blacklist, "blacklist_root": p.BlacklistRoot,
		"verifier_covenant_spk":     verifierSpkHex,
		"verifier_covenant_address": s.addressOfSPK(verifierCov.ScriptPubKey()),
		"snapshot_published":        published,
		"note": "the policy is published and the update is broadcast; it binds transfers once the respend confirms, " +
			"and until then holders transfer under the previous policy",
	})
}

// --- helpers -----------------------------------------------------------------

// dampAsset loads an asset and requires it to be network-enforced with a
// complete binding, writing the refusal itself when it is not.
func (s *Server) dampAsset(w http.ResponseWriter, assetID string) *store.Asset {
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[assetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset %s", assetID)
		return nil
	}
	if asset.Enforcement != "damp" || asset.Damp == nil {
		httpErr(w, 409, "asset %s is co-signed, not network-enforced: its holder controls run through /v1/issuer/freeze and /v1/issuer/clawback, not through a published policy", assetID)
		return nil
	}
	return asset
}

// policyChange is the human-legible shape of one update, for the transparency
// log and for the console that renders it.
type policyChange struct {
	addedHolders     []string
	removedHolders   []string
	reboundHolders   []string
	addedOutpoints   []string
	removedOutpoints []string
}

func (c *policyChange) empty() bool {
	return len(c.addedHolders) == 0 && len(c.removedHolders) == 0 && len(c.reboundHolders) == 0 &&
		len(c.addedOutpoints) == 0 && len(c.removedOutpoints) == 0
}

// applyPolicyDelta returns the NEXT snapshot with the requested change applied to
// the current one. Seq, prev_pi and pi are left for the caller. Every refusal
// here is a request that would have produced a policy the issuer did not mean:
// an empty whitelist (which strands the asset), a duplicate addition, or a
// removal of something that is not listed (almost always a typo, and silently
// succeeding would tell the issuer a coin is unfrozen when it never was).
func applyPolicyDelta(cur *damp.Snapshot, req *dampPolicyRequest) (*damp.Snapshot, *policyChange, error) {
	change := &policyChange{}

	// The holder list is a map keyed by the lowercase key, so an entry's HEIGHT
	// BOUNDS travel with it: they are part of the leaf the covenant hashes, and
	// rebuilding the list from keys alone would silently drop every lockup and
	// receive window the current policy binds.
	byKey := map[string]damp.PredicateEntry{}
	for _, e := range cur.Predicates.Whitelist.Entries {
		byKey[strings.ToLower(e.Key)] = damp.PredicateEntry{
			Key: strings.ToLower(e.Key), SendAfter: e.SendAfter, RecvAfter: e.RecvAfter,
		}
	}
	for _, raw := range req.AddWhitelist {
		k := strings.ToLower(strings.TrimSpace(raw.Key))
		if _, err := parseXOnly("add_whitelist", k); err != nil {
			return nil, nil, err
		}
		if _, has := byKey[k]; has {
			return nil, nil, fmt.Errorf("%s can already hold this asset; adding it again would publish a duplicate entry", k)
		}
		byKey[k] = damp.PredicateEntry{Key: k, SendAfter: raw.SendAfter, RecvAfter: raw.RecvAfter}
		change.addedHolders = append(change.addedHolders, k)
	}
	for _, raw := range req.SetWindows {
		k := strings.ToLower(strings.TrimSpace(raw.Key))
		if _, err := parseXOnly("set_windows", k); err != nil {
			return nil, nil, err
		}
		e, has := byKey[k]
		if !has {
			return nil, nil, fmt.Errorf("%s is not on this asset's holder list, so there are no height bounds to set for it; admit it with add_whitelist instead", k)
		}
		if e.SendAfter == raw.SendAfter && e.RecvAfter == raw.RecvAfter {
			return nil, nil, fmt.Errorf("%s already has exactly those height bounds", k)
		}
		byKey[k] = damp.PredicateEntry{Key: k, SendAfter: raw.SendAfter, RecvAfter: raw.RecvAfter}
		change.reboundHolders = append(change.reboundHolders, k)
	}
	for _, rawKey := range req.RemoveWhitelist {
		k := strings.ToLower(strings.TrimSpace(rawKey))
		if _, err := parseXOnly("remove_whitelist", k); err != nil {
			return nil, nil, err
		}
		if _, has := byKey[k]; !has {
			return nil, nil, fmt.Errorf("%s is not on this asset's holder list, so there is nothing to remove", k)
		}
		delete(byKey, k)
		change.removedHolders = append(change.removedHolders, k)
	}
	if len(byKey) == 0 {
		return nil, nil, fmt.Errorf("the holder list cannot be emptied: the network checks the recipient of every regulated output, so an empty list freezes the asset permanently with no way back except a further update nobody could ever satisfy")
	}
	kept := make([]damp.PredicateEntry, 0, len(byKey))
	for _, e := range byKey {
		kept = append(kept, e)
	}

	bl := append([]string(nil), cur.Predicates.Blacklist.Keys()...)
	inBL := map[string]bool{}
	for _, e := range bl {
		inBL[strings.ToLower(e)] = true
	}
	for _, o := range req.AddBlacklist {
		k, err := o.key()
		if err != nil {
			return nil, nil, fmt.Errorf("add_blacklist: %v", err)
		}
		kh := hex.EncodeToString(k[:])
		if inBL[kh] {
			return nil, nil, fmt.Errorf("%s is already frozen", o)
		}
		inBL[kh] = true
		bl = append(bl, kh)
		change.addedOutpoints = append(change.addedOutpoints, o.String())
	}
	unlist := map[string]bool{}
	for _, o := range req.RemoveBlacklist {
		k, err := o.key()
		if err != nil {
			return nil, nil, fmt.Errorf("remove_blacklist: %v", err)
		}
		kh := hex.EncodeToString(k[:])
		if !inBL[kh] {
			return nil, nil, fmt.Errorf("%s is not frozen, so there is nothing to lift", o)
		}
		unlist[kh] = true
		change.removedOutpoints = append(change.removedOutpoints, o.String())
	}
	keptBL := make([]string, 0, len(bl))
	for _, e := range bl {
		if unlist[strings.ToLower(e)] {
			continue
		}
		keptBL = append(keptBL, e)
	}

	if change.empty() {
		return nil, nil, fmt.Errorf("this request changes nothing; a policy update that publishes the same policy would still cost a transaction and a sequence number")
	}

	// Deterministic order, so the same change always produces the same document
	// bytes regardless of how the request happened to be written (and regardless of
	// Go's map iteration order above).
	sort.Slice(kept, func(i, j int) bool { return kept[i].Key < kept[j].Key })
	sort.Strings(keptBL)
	sort.Strings(change.addedHolders)
	sort.Strings(change.removedHolders)
	sort.Strings(change.reboundHolders)

	next := *cur
	next.IssuerSig = ""
	next.Predicates = damp.Predicates{
		Blacklist: damp.PredicateList{Entries: damp.KeyEntries(keptBL)},
		Whitelist: damp.PredicateList{Entries: kept},
		Limit:     cur.Predicates.Limit,
	}
	return &next, change, nil
}

// dampRoots recomputes the roots and pi a snapshot's contents imply and writes
// the roots back into the document, so the returned snapshot is self-consistent.
func dampRoots(assetID string, snap *damp.Snapshot) (wl, bl, pi [32]byte, err error) {
	wl, bl, pi, err = dampRootsFrom(assetID, snap.Seq, snap.Predicates.Whitelist.Entries, snap.Predicates.Blacklist.Keys(), snap.Predicates.Limit)
	if err != nil {
		return
	}
	snap.Predicates.Whitelist.Root = hex.EncodeToString(wl[:])
	snap.Predicates.Blacklist.Root = hex.EncodeToString(bl[:])
	return
}

// dampRootsFrom is the pi construction over inline entries: a dmt-v1 whitelist
// root over holder LEAVES (key plus the height bounds that bind it), a dmt-v1
// INTERVAL root over outpoint keys, and the covenant rules root, committed with
// the asset id in internal byte order.
//
// The two trees are different shapes and are not interchangeable, which is why
// the entries are kept apart all the way down. And the whitelist root is computed
// from the leaves, never from the keys: a lockup or a receive window lives INSIDE
// the leaf, so a keys-only root would publish a commitment that omits it, and
// every transfer of the asset would then fail against the deployed program rather
// than merely lose a restriction.
func dampRootsFrom(assetID string, seq uint64, whitelist []damp.PredicateEntry, blacklist []string, limit *uint64) (wl, bl, pi [32]byte, err error) {
	wlEntries := make([]damp.WhitelistEntry, 0, len(whitelist))
	for i, e := range whitelist {
		k, kerr := parseXOnly(fmt.Sprintf("whitelist[%d]", i), e.Key)
		if kerr != nil {
			return wl, bl, pi, fmt.Errorf("stored holder list is corrupt: %v", kerr)
		}
		wlEntries = append(wlEntries, damp.WhitelistEntry{Key: k, SendAfter: e.SendAfter, RecvAfter: e.RecvAfter})
	}
	if wl, err = damp.WhitelistRootWithWindows(wlEntries); err != nil {
		return
	}
	blKeys := make([][32]byte, 0, len(blacklist))
	for i, e := range blacklist {
		b, derr := hex.DecodeString(e)
		if derr != nil || len(b) != 32 {
			return wl, bl, pi, fmt.Errorf("stored frozen-coin list is corrupt at entry %d", i)
		}
		blKeys = append(blKeys, [32]byte(b))
	}
	if bl, err = damp.BlacklistRoot(blKeys); err != nil {
		return
	}
	var lim uint64
	if limit != nil {
		lim = *limit
	}
	pi = damp.PiCovenant(internalHash(assetID), seq, damp.RulesRootCovenant(&bl, &wl, lim, nil))
	return
}

// dampVerifierOutpoint locates the asset's current verifier output: the single
// coin of V, in amount q, sitting at the recorded C_V address. Anything other
// than exactly one is a refusal with the real reason rather than a guess, because
// picking the wrong one would build a respend that cannot confirm.
func (s *Server) dampVerifierOutpoint(asset *store.Asset) (string, uint32, error) {
	utxos, err := s.unifiedUTXOs([]string{asset.Damp.VerifierSPK}, asset.Damp.VerifierAsset)
	if err != nil {
		return "", 0, fmt.Errorf("scan the rules address: %v", err)
	}
	var found []enclaveUTXO
	for _, u := range utxos {
		if u.atoms == asset.Damp.VerifierAmount {
			found = append(found, u)
		}
	}
	switch {
	case len(found) == 0:
		return "", 0, fmt.Errorf("asset %s has no rules output at %s: either the update transaction has not confirmed yet, or the asset was halted, and a halted asset has no policy left to update", asset.ID, asset.Damp.VerifierAddr)
	case len(found) > 1:
		return "", 0, fmt.Errorf("asset %s has %d rules outputs at %s; refusing to guess which one an update should consume", asset.ID, len(found), asset.Damp.VerifierAddr)
	}
	return found[0].txid, found[0].vout, nil
}

// checkVerifierRespend is the structural check on a supplied issuer-path spend:
// it consumes the recorded verifier outpoint, and it recreates the verifier
// output at the NEW policy address carrying exactly q of V. Those two facts are
// what make it a policy update rather than a halt or a payment, and they are
// checkable without compiling anything.
func checkVerifierRespend(tx *elements.Tx, p *store.PendingDampPolicy, nextSPK []byte) error {
	wantHash := internalHash(p.VerifierTxid)
	spends := false
	for _, in := range tx.In {
		if in.Prevout.Hash == wantHash && in.Prevout.N == p.VerifierVout {
			spends = true
			break
		}
	}
	if !spends {
		return fmt.Errorf("signed_tx does not spend this asset's rules output %s:%d, so it is not the update this policy prepared", p.VerifierTxid, p.VerifierVout)
	}
	wantAsset := hex.EncodeToString(elements.ExplicitAsset(elements.MustHex32(p.VerifierAsset)))
	wantSPK := hex.EncodeToString(nextSPK)
	for _, out := range tx.Out {
		if hex.EncodeToString(out.ScriptPubKey) != wantSPK {
			continue
		}
		if hex.EncodeToString(out.Asset) != wantAsset {
			continue
		}
		amt, explicit := elements.ExplicitValueAmount(out.Value)
		if !explicit {
			return fmt.Errorf("the recreated rules output must carry an explicit amount: the on-chain program reads it")
		}
		if amt != p.VerifierAmount {
			return fmt.Errorf("the recreated rules output carries %d of the rules asset, not the %d this asset is defined with", amt, p.VerifierAmount)
		}
		return nil
	}
	return fmt.Errorf("signed_tx does not recreate the rules output under the new policy; it must pay %s with exactly %d of %s", wantSPK, p.VerifierAmount, p.VerifierAsset)
}
