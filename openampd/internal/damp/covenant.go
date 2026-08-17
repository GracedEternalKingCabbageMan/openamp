package damp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/damp/dmt"
)

// Covenant-facing policy construction, mirroring opendamp/src/policy.rs so the
// commitment this server publishes is the one the on-chain covenant verifies.
// The M2 half of this package speaks the snapshot document format; this half
// speaks the covenant's own dmt-v1 whitelist tree and the pi it is instantiated
// with. Both must stay pinned to opendamp/vectors/addresses.json.

// PolicyVersion is the version byte inside pi.
const PolicyVersion = 0x01

// ProgramRegistry pins program_id -> CMR. A CMR change is a different covenant
// and therefore a different address, so these are loaded from a file the
// operator controls rather than guessed, and the loader refuses partial sets.
type ProgramRegistry struct {
	UserCMR     [32]byte
	VerifierCMR [32]byte
	IssuerCMR   [32]byte
}

// LoadProgramRegistry reads the CMR pinning file produced by `opendamp
// registry` (or the vectors file, which carries the same fields under
// "programs"). Both shapes are accepted so an operator can point at either.
func LoadProgramRegistry(path string) (*ProgramRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("program registry: %w", err)
	}
	var doc struct {
		Programs struct {
			UCMR string `json:"u_cmr"`
			PCMR string `json:"p_cmr"`
			GCMR string `json:"g_cmr"`
		} `json:"programs"`
		UCMR string `json:"u_cmr"`
		PCMR string `json:"p_cmr"`
		GCMR string `json:"g_cmr"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("program registry: %w", err)
	}
	u, p, g := doc.Programs.UCMR, doc.Programs.PCMR, doc.Programs.GCMR
	if u == "" && p == "" && g == "" {
		u, p, g = doc.UCMR, doc.PCMR, doc.GCMR
	}
	if u == "" || p == "" || g == "" {
		return nil, fmt.Errorf("program registry %s: needs u_cmr, p_cmr and g_cmr", path)
	}
	reg := &ProgramRegistry{}
	for _, f := range []struct {
		hex string
		dst *[32]byte
	}{{u, &reg.UserCMR}, {p, &reg.VerifierCMR}, {g, &reg.IssuerCMR}} {
		b, err := hex.DecodeString(f.hex)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("program registry: %q is not a 32-byte CMR", f.hex)
		}
		copy(f.dst[:], b)
	}
	return reg, nil
}

// WhitelistRoot is the dmt-v1 root over the holder keys permitted to RECEIVE
// the asset. Note the scope honestly: the covenant checks recipients, so
// removing a key stops it receiving, not spending (opendamp/STATUS.md).
func WhitelistRoot(ownerKeys [][32]byte) ([32]byte, error) {
	keys := make([]dmt.Key, 0, len(ownerKeys))
	for _, k := range ownerKeys {
		keys = append(keys, dmt.Key(k))
	}
	tree, err := dmt.New(keys)
	if err != nil {
		return [32]byte{}, err
	}
	return tree.Root(), nil
}

// RulesRootCovenant is the fixed-order two-level Merkle root over the four
// predicate commitments [blacklist, whitelist, limit, windows]; an absent
// predicate commits to 32 zero bytes. This is opendamp/src/policy.rs
// rules_root, NOT the M2 snapshot RulesRoot (which serves the document format);
// they are separate constructions on purpose and both are vector-pinned.
func RulesRootCovenant(blacklist, whitelist *[32]byte, limit uint64, windows *[32]byte) [32]byte {
	var zero [32]byte
	pick := func(p *[32]byte) [32]byte {
		if p == nil {
			return zero
		}
		return *p
	}
	cBl, cWl, cWin := pick(blacklist), pick(whitelist), pick(windows)
	var cLim [32]byte
	if limit != 0 {
		binary.BigEndian.PutUint64(cLim[24:], limit)
	}
	left := sha256.Sum256(append(append([]byte{}, cBl[:]...), cWl[:]...))
	right := sha256.Sum256(append(append([]byte{}, cLim[:]...), cWin[:]...))
	return sha256.Sum256(append(append([]byte{}, left[:]...), right[:]...))
}

// PiCovenant is the policy commitment the verifier covenant is instantiated
// with: H_"OpenDAMP/policy/v1"(version || asset_internal || seq_be64 ||
// rules_root). assetInternal is the asset id in internal (hash) byte order,
// which is the display id reversed.
func PiCovenant(assetInternal [32]byte, seq uint64, rulesRoot [32]byte) [32]byte {
	msg := make([]byte, 0, 1+32+8+32)
	msg = append(msg, PolicyVersion)
	msg = append(msg, assetInternal[:]...)
	var seqBE [8]byte
	binary.BigEndian.PutUint64(seqBE[:], seq)
	msg = append(msg, seqBE[:]...)
	msg = append(msg, rulesRoot[:]...)
	return taggedHash("OpenDAMP/policy/v1", msg)
}
