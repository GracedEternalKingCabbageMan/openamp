package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// OpenDAMP snapshot service (M2, opendamp-design.md section 4). Pure data
// plane: it validates, sequences, stores and serves signed policy snapshots.
// It is live before the covenants (M1/M3) exist because holders and mirrors
// need the publication channel and its transparency-log discipline either way;
// nothing here touches the chain or the wallet.
//
// Trust model for the issuer signature:
//   - Asset known to this daemon (it issued it): issuer_sig must verify
//     against the asset's stored IssuerPub — for an external-issuer asset that
//     is the entity's own key, for a legacy asset the server-generated one. A
//     request-supplied issuer_pubkey must match it exactly.
//   - Asset unknown (issued elsewhere; this daemon is acting as a snapshot
//     mirror/registrar): the FIRST snapshot (seq 0) must carry issuer_pubkey
//     and is verified against it — trust-on-first-use, the same trust note as
//     any registrar accepting an external publisher. The key is pinned in the
//     stored record; every later seq must verify under the SAME key, so an
//     attacker cannot splice a chain by swapping keys mid-history. Consumers
//     who need more than TOFU verify the key against the asset's on-chain
//     contract ("issuer_update_key", section 5) once damp issuance exists.
type snapshotPostRequest struct {
	damp.Snapshot
	// IssuerPubkey (x-only hex) is required for the seq-0 snapshot of an asset
	// this daemon did not issue; for a known asset it is optional and must
	// match the stored IssuerPub.
	IssuerPubkey string `json:"issuer_pubkey,omitempty"`
}

// handleSnapshotPost is POST /v1/issuer/snapshots (bearer-gated): body = a
// full snapshot/v1 JSON document (plus optional issuer_pubkey, above).
func (s *Server) handleSnapshotPost(w http.ResponseWriter, r *http.Request) {
	var req snapshotPostRequest
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	snap := req.Snapshot

	// 1. Internal consistency: predicate roots recomputed from the inline
	// entries, pi recomputed from the header, shape checks.
	if err := snap.Validate(); err != nil {
		httpErr(w, 400, "invalid snapshot: %v", err)
		return
	}
	if snap.IssuerSig == "" {
		httpErr(w, 400, "issuer_sig is required")
		return
	}

	// 2. Resolve the issuer key to verify against (trust model above).
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[snap.Asset]; ok {
			cp := *a
			asset = &cp
		}
	})
	latest, haveLatest := s.st.LatestSnapshot(snap.Asset)
	var issuerPub string
	switch {
	case asset != nil:
		issuerPub = asset.IssuerPub
		if req.IssuerPubkey != "" && req.IssuerPubkey != issuerPub {
			httpErr(w, 400, "issuer_pubkey does not match the asset's registered issuer key")
			return
		}
	case haveLatest:
		// Unknown asset with history: the chain pins the key (TOFU at seq 0).
		issuerPub = latest.IssuerPub
		if req.IssuerPubkey != "" && req.IssuerPubkey != issuerPub {
			httpErr(w, 400, "issuer_pubkey does not match the key this asset's snapshot chain is pinned to")
			return
		}
	default:
		if req.IssuerPubkey == "" {
			httpErr(w, 400, "issuer_pubkey is required for the first snapshot of an asset not issued by this server")
			return
		}
		issuerPub = req.IssuerPubkey
	}

	// 3. Sequencing: gapless seq (first must be 0) and prev_pi linkage.
	if haveLatest {
		if snap.Seq != latest.Seq+1 {
			httpErr(w, 409, "snapshot seq must be %d (last published is %d)", latest.Seq+1, latest.Seq)
			return
		}
		// Validate() guarantees PrevPi != nil for seq > 0.
		if *snap.PrevPi != latest.Pi {
			httpErr(w, 409, "prev_pi %s does not match the latest published pi %s", *snap.PrevPi, latest.Pi)
			return
		}
	} else if snap.Seq != 0 {
		httpErr(w, 409, "first snapshot for an asset must have seq 0, got %d", snap.Seq)
		return
	}

	// 4. Issuer signature over the tagged snapshot hash.
	if err := snap.Verify(issuerPub); err != nil {
		httpErr(w, 400, "issuer_sig: %v", err)
		return
	}

	// 5. Persist (AppendSnapshot re-checks seq under the store lock, so a
	// concurrent duplicate post loses there) and log. The transparency log is
	// the hash-chained public record wallets poll alongside GET /v1/snapshots.
	canonical, err := snap.CanonicalJSON()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	hash, err := snap.Hash()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	hashHex := hex.EncodeToString(hash[:])
	if err := s.st.AppendSnapshot(snap.Asset, &store.StoredSnapshot{
		Seq: snap.Seq, Pi: snap.Pi, Hash: hashHex, IssuerPub: issuerPub,
		Canonical: canonical, IssuerSig: snap.IssuerSig,
	}); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	s.st.AppendLog("snapshot", map[string]any{
		"asset": snap.Asset, "seq": snap.Seq, "pi": snap.Pi, "hash": hashHex,
	})
	httpJSON(w, map[string]any{
		"asset": snap.Asset, "seq": snap.Seq, "pi": snap.Pi, "hash": hashHex,
	})
}

// handleSnapshotGet is GET /v1/snapshots?asset=<id>[&seq=n] (public): the
// latest snapshot by default, the exact seq when given, 404 when unknown.
// The response carries the stored canonical document verbatim plus the
// issuer_sig, so any client can recompute hash and pi and verify the
// signature offline.
func (s *Server) handleSnapshotGet(w http.ResponseWriter, r *http.Request) {
	assetID := r.URL.Query().Get("asset")
	if assetID == "" {
		httpErr(w, 400, "asset query parameter required")
		return
	}
	var ss *store.StoredSnapshot
	var ok bool
	if seqStr := r.URL.Query().Get("seq"); seqStr != "" {
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			httpErr(w, 400, "seq must be an unsigned integer")
			return
		}
		ss, ok = s.st.SnapshotAt(assetID, seq)
	} else {
		ss, ok = s.st.LatestSnapshot(assetID)
	}
	if !ok {
		httpErr(w, 404, "no such snapshot")
		return
	}
	httpJSON(w, map[string]any{
		"asset":      assetID,
		"seq":        ss.Seq,
		"pi":         ss.Pi,
		"hash":       ss.Hash,
		"issuer_pub": ss.IssuerPub,
		"issuer_sig": ss.IssuerSig,
		"snapshot":   json.RawMessage(ss.Canonical),
	})
}
