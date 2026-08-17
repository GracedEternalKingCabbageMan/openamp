package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

// handleRotateBlinding cuts a new blinding-key epoch for one asset (the
// docs/blinding-key-rotation.md design): it provisions the next versioned
// master secret if this install has never reached that epoch, bumps the
// asset's BlindEpoch, and re-imports every registered holder's enclave script
// with its NEW blinding key into the watch wallet, so addresses served and
// outputs blinded from now on use the new epoch immediately.
//
// What rotation deliberately does NOT do: touch old epochs (their masters are
// retained forever and their imported keys keep historical UTXOs readable, so
// balances over mixed-epoch coins stay exact), sweep funds (migration is
// re-blind-on-touch: the next transaction that touches an enclave blinds its
// outputs to the new key), or write anything into the contract (the epoch is
// server-side bookkeeping, never an asset property).
func (s *Server) handleRotateBlinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset string `json:"asset"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[req.Asset]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset")
		return
	}
	newEpoch := asset.BlindEpoch + 1

	// Provision the epoch's master if no rotation has reached it yet. Masters
	// are global (epoch N is the same secret for every asset), created once,
	// never deleted.
	keys, err := s.st.LoadKeys()
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	if _, ok := keys[blindMasterName(newEpoch)]; !ok {
		m := make([]byte, 32)
		if _, err := rand.Read(m); err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		if err := s.st.SaveKey(blindMasterName(newEpoch), hex.EncodeToString(m)); err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
	}

	// Bump the epoch BEFORE the imports so a crash mid-import fails safe: the
	// startup reconcile re-imports every epoch of every pair anyway.
	if err := s.st.Update(func(st *store.State) error {
		st.Assets[req.Asset].BlindEpoch = newEpoch
		return nil
	}); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}

	// Re-import every registered holder's enclave with the new epoch's key.
	// The old epochs' keys stay imported, so mixed-epoch UTXOs keep reading.
	var users []*store.User
	s.st.View(func(st *store.State) {
		for _, u := range st.Users {
			cp := *u
			users = append(users, &cp)
		}
	})
	reimported := 0
	var spks []string
	for _, u := range users {
		tree, err := s.treeFor(u, asset)
		if err != nil {
			continue
		}
		spkHex := hex.EncodeToString(tree.ScriptPubKey())
		priv, pub, err := s.blindingKeyAt(asset.ID, elements.MustHex32(u.Pubkeys[0]), newEpoch)
		if err != nil {
			httpErr(w, 500, "derive epoch-%d key: %v", newEpoch, err)
			return
		}
		if err := s.importConfidentialEnclave(spkHex, priv, hex.EncodeToString(pub)); err != nil {
			httpErr(w, 502, "re-import enclave: %v", err)
			return
		}
		spks = append(spks, spkHex)
		reimported++
	}

	// The public record commits to the re-imported script SET, never to key
	// material (the same minimization discipline as the category set-hash).
	sort.Strings(spks)
	h := sha256.New()
	h.Write([]byte("openamp-rotation-v1"))
	for _, spk := range spks {
		h.Write([]byte{0})
		h.Write([]byte(spk))
	}
	s.st.AppendLog("rotate-blinding", map[string]any{
		"asset":        asset.ID,
		"epoch":        newEpoch,
		"holders":      reimported,
		"scripts_hash": hex.EncodeToString(h.Sum(nil)),
	})
	httpJSON(w, map[string]any{"asset": asset.ID, "epoch": newEpoch, "holders_reimported": reimported})
}
