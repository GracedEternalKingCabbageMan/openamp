package server

import (
	"context"
	"log"
	"time"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

const recentBlockWindow = 100

// RunFollower tracks the chain: it confirms transfer records, and on a reorg
// (which on Sequentia is a designed-for event whenever Bitcoin reorgs) it
// re-marks records above the fork point as unconfirmed so velocity and
// reporting reflect only the surviving chain.
func (s *Server) RunFollower(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.followTick(); err != nil {
				log.Printf("follower: %v", err)
			}
		}
	}
}

func (s *Server) followTick() error {
	tip, err := s.node.GetBlockCount()
	if err != nil {
		return err
	}
	var prevHeight int64
	var prevBlocks []string
	s.st.View(func(st *store.State) {
		prevHeight = st.Height
		prevBlocks = append([]string(nil), st.RecentBlocks...)
	})

	// Detect a fork: compare stored recent hashes against the current chain.
	forkAt := int64(-1) // height of the first mismatching stored block
	base := prevHeight - int64(len(prevBlocks)) + 1
	for i, stored := range prevBlocks {
		h := base + int64(i)
		if h < 0 || h > tip {
			continue
		}
		cur, err := s.node.GetBlockHash(h)
		if err != nil {
			return err
		}
		if cur != stored {
			forkAt = h
			break
		}
	}

	// Collect txids of blocks from the fork (or the previous tip) up to now.
	scanFrom := prevHeight + 1
	if forkAt >= 0 {
		scanFrom = forkAt
	}
	confirmed := map[string]int64{}
	for h := scanFrom; h <= tip; h++ {
		hash, err := s.node.GetBlockHash(h)
		if err != nil {
			return err
		}
		var blk struct {
			Tx []string `json:"tx"`
		}
		if err := s.node.Call(&blk, "getblock", hash, 1); err != nil {
			return err
		}
		for _, txid := range blk.Tx {
			confirmed[txid] = h
		}
	}

	// New recent-hash window.
	start := tip - recentBlockWindow + 1
	if start < 0 {
		start = 0
	}
	var recent []string
	for h := start; h <= tip; h++ {
		hash, err := s.node.GetBlockHash(h)
		if err != nil {
			return err
		}
		recent = append(recent, hash)
	}

	return s.st.Update(func(st *store.State) error {
		st.Height = tip
		st.RecentBlocks = recent
		for i := range st.Transfers {
			rec := &st.Transfers[i]
			if forkAt >= 0 && rec.Height >= forkAt {
				rec.Height = -1
			}
			if h, ok := confirmed[rec.Txid]; ok {
				rec.Height = h
			}
		}
		return nil
	})
}
