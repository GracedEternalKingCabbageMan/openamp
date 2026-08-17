package frostsigner

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// FROST threshold Schnorr over secp256k1, adapted to BIP340. All scalar and
// point arithmetic is the decred secp256k1 library's (constant-time where it
// provides it); nothing here rolls its own field math.
//
// The BIP340 adaptation is the part that silently breaks threshold Schnorr
// implementations, so the two parity adjustments are centralized and explicit:
//
//   - R parity: BIP340 signatures commit to an even-Y R. After aggregating
//     R = sum(D_i + rho_i*E_i), if R.y is odd EVERY participant negates BOTH
//     its nonce scalars (k -> n-k), which negates R without changing R.x.
//     Partial verification correspondingly negates the public commitments
//     D_i, E_i.
//   - P parity: an x-only public key names the even-Y point. If the dealer's
//     P = d*G has odd Y, the effective secret is n-d; each participant negates
//     its share's contribution (d_i -> n-d_i in the partial), since
//     sum(lambda_i * -d_i) = -(d) = n-d. Partial verification negates the
//     public share Y_i.
//
// Both adjustments are per-round, derived from public data, and applied by
// every participant identically; nothing about the stored shares changes.

// rhoTag is the domain-separation tag for the binding factor, which ties each
// participant's second nonce to the message and the full commitment list so a
// commitment cannot be replayed into a different signing round (the Drijvers/
// ROS-style attack FROST's two-nonce design exists to stop).
const rhoTag = "FROST/rho"

// taggedHash is BIP340-style tagged hashing: sha256(sha256(tag) || sha256(tag)
// || chunks...).
func taggedHash(tag string, chunks ...[]byte) [32]byte {
	th := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(th[:])
	h.Write(th[:])
	for _, c := range chunks {
		h.Write(c)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func scalarFromHash(h [32]byte) *secp.ModNScalar {
	s := new(secp.ModNScalar)
	s.SetBytes(&h) // reduces mod n
	return s
}

func randomScalar(rnd io.Reader) (*secp.ModNScalar, error) {
	pk, err := secp.GeneratePrivateKeyFromRand(rnd)
	if err != nil {
		return nil, err
	}
	return &pk.Key, nil
}

// pointFromScalar returns k*G, affine.
func pointFromScalar(k *secp.ModNScalar) *secp.JacobianPoint {
	var p secp.JacobianPoint
	secp.ScalarBaseMultNonConst(k, &p)
	p.ToAffine()
	return &p
}

// negatePoint returns -p for an affine p.
func negatePoint(p *secp.JacobianPoint) *secp.JacobianPoint {
	var q secp.JacobianPoint
	q.Set(p)
	q.Y.Negate(1)
	q.Y.Normalize()
	return &q
}

// compressPoint serializes an affine point in 33-byte compressed form.
func compressPoint(p *secp.JacobianPoint) []byte {
	return secp.NewPublicKey(&p.X, &p.Y).SerializeCompressed()
}

// xBytes returns the 32-byte X coordinate of an affine point.
func xBytes(p *secp.JacobianPoint) [32]byte {
	var b [32]byte
	p.X.PutBytesUnchecked(b[:])
	return b
}

func isInfinity(p *secp.JacobianPoint) bool {
	return p.X.IsZero() && p.Y.IsZero()
}

func idBytes(id int) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(id))
	return b[:]
}

// lagrange computes the Lagrange coefficient at x=0 for participant i within
// the signing subset ids: prod_{j != i} j * (j - i)^-1 mod n.
func lagrange(ids []int, i int) *secp.ModNScalar {
	num := new(secp.ModNScalar).SetInt(1)
	den := new(secp.ModNScalar).SetInt(1)
	var xi secp.ModNScalar
	xi.SetInt(uint32(i))
	for _, j := range ids {
		if j == i {
			continue
		}
		var xj secp.ModNScalar
		xj.SetInt(uint32(j))
		num.Mul(&xj)
		diff := new(secp.ModNScalar).NegateVal(&xi)
		diff.Add(&xj) // j - i
		den.Mul(diff)
	}
	den.InverseNonConst()
	return num.Mul(den)
}

// dealerKeygen runs a trusted-dealer Shamir split of a fresh group secret d
// over the secp256k1 order: degree t-1 polynomial with constant term d, shares
// d_i = f(i) at x = 1..n. Returns the x-only group public key (P = d*G) and
// the n share scalars; shares[k] belongs to participant id k+1. The dealer's
// coefficients are discarded on return — only the shares persist.
func dealerKeygen(t, n int, rnd io.Reader) (groupX [32]byte, shares [][32]byte, err error) {
	if t < 2 || n < t {
		return groupX, nil, fmt.Errorf("invalid quorum shape %d-of-%d", t, n)
	}
	coeffs := make([]*secp.ModNScalar, t) // coeffs[0] is the group secret d
	for k := range coeffs {
		if coeffs[k], err = randomScalar(rnd); err != nil {
			return groupX, nil, err
		}
	}
	groupX = xBytes(pointFromScalar(coeffs[0]))
	shares = make([][32]byte, n)
	for i := 1; i <= n; i++ {
		var x secp.ModNScalar
		x.SetInt(uint32(i))
		acc := new(secp.ModNScalar).Set(coeffs[t-1])
		for k := t - 2; k >= 0; k-- { // Horner
			acc.Mul(&x).Add(coeffs[k])
		}
		shares[i-1] = acc.Bytes()
	}
	return groupX, shares, nil
}

// round is one FROST signing round over a threshold subset of shares. Both
// protocol rounds run in-process here (the participants share an address
// space), but the structure is the wire protocol's: independent per-participant
// nonces and commitments, binding factors over the full commitment list, and
// partial signatures that are individually verifiable against public data
// before aggregation.
type round struct {
	m       [32]byte
	ids     []int // signing subset, ascending
	lambdas map[int]*secp.ModNScalar

	secrets   map[int]*secp.ModNScalar    // each participant's share d_i
	pubShares map[int]*secp.JacobianPoint // Y_i = d_i*G (public)

	hiding, binding map[int]*secp.ModNScalar    // nonce scalars, R-parity applied
	commD, commE    map[int]*secp.JacobianPoint // original commitments D_i, E_i
	rhos            map[int]*secp.ModNScalar

	rx     [32]byte
	e      *secp.ModNScalar
	groupX [32]byte

	rNegated bool // R.y was odd: all nonces negated, verify against -D_i, -E_i
	pNegated bool // P.y was odd: shares negated in partials, verify against -Y_i
}

// newRound derives everything both protocol messages would carry: nonce
// commitments, binding factors, the aggregate nonce R (with the BIP340 R-parity
// adjustment), the group key parity, and the challenge e. shares maps
// participant id -> share scalar; the subset IS the signing quorum.
func newRound(m [32]byte, shares map[int][32]byte, rnd io.Reader) (*round, error) {
	r := &round{
		m:       m,
		lambdas: map[int]*secp.ModNScalar{}, secrets: map[int]*secp.ModNScalar{},
		pubShares: map[int]*secp.JacobianPoint{},
		hiding:    map[int]*secp.ModNScalar{}, binding: map[int]*secp.ModNScalar{},
		commD: map[int]*secp.JacobianPoint{}, commE: map[int]*secp.JacobianPoint{},
		rhos: map[int]*secp.ModNScalar{},
	}
	for id := range shares {
		if id < 1 || id > 0xffff {
			return nil, fmt.Errorf("participant id %d out of range", id)
		}
		r.ids = append(r.ids, id)
	}
	sort.Ints(r.ids)
	if len(r.ids) < 2 {
		return nil, fmt.Errorf("need at least 2 signers, have %d", len(r.ids))
	}

	// Shares, public shares, Lagrange weights, and the group point
	// P = sum(lambda_i * Y_i).
	var P secp.JacobianPoint
	for _, id := range r.ids {
		b := shares[id]
		d := new(secp.ModNScalar)
		if d.SetBytes(&b) != 0 || d.IsZero() {
			return nil, fmt.Errorf("participant %d: invalid share scalar", id)
		}
		r.secrets[id] = d
		r.pubShares[id] = pointFromScalar(d)
		r.lambdas[id] = lagrange(r.ids, id)

		var term, sum secp.JacobianPoint
		secp.ScalarMultNonConst(r.lambdas[id], r.pubShares[id], &term)
		secp.AddNonConst(&P, &term, &sum)
		P.Set(&sum)
	}
	P.ToAffine()
	if isInfinity(&P) {
		return nil, fmt.Errorf("degenerate group key")
	}
	r.groupX = xBytes(&P)
	r.pNegated = P.Y.IsOdd()

	// Round 1: two nonces per participant, commitments D_i = k_h*G, E_i = k_b*G.
	for _, id := range r.ids {
		kh, err := randomScalar(rnd)
		if err != nil {
			return nil, err
		}
		kb, err := randomScalar(rnd)
		if err != nil {
			return nil, err
		}
		r.hiding[id], r.binding[id] = kh, kb
		r.commD[id], r.commE[id] = pointFromScalar(kh), pointFromScalar(kb)
	}

	// Binding factors over the full commitment list, then
	// R = sum(D_i + rho_i*E_i).
	var commitList []byte
	for _, id := range r.ids {
		commitList = append(commitList, idBytes(id)...)
		commitList = append(commitList, compressPoint(r.commD[id])...)
		commitList = append(commitList, compressPoint(r.commE[id])...)
	}
	var R secp.JacobianPoint
	for _, id := range r.ids {
		rho := scalarFromHash(taggedHash(rhoTag, idBytes(id), m[:], commitList))
		if rho.IsZero() {
			return nil, fmt.Errorf("participant %d: zero binding factor", id)
		}
		r.rhos[id] = rho
		var rhoE, bound, sum secp.JacobianPoint
		secp.ScalarMultNonConst(rho, r.commE[id], &rhoE)
		secp.AddNonConst(&rhoE, r.commD[id], &bound)
		secp.AddNonConst(&R, &bound, &sum)
		R.Set(&sum)
	}
	R.ToAffine()
	if isInfinity(&R) {
		return nil, fmt.Errorf("aggregate nonce is the point at infinity; retry with fresh nonces")
	}
	// BIP340 R parity: an odd-Y R is negated by negating every nonce scalar
	// (R.x is unchanged, so the signature bytes commit to the same rx).
	if R.Y.IsOdd() {
		r.rNegated = true
		for _, id := range r.ids {
			r.hiding[id].Negate()
			r.binding[id].Negate()
		}
	}
	r.rx = xBytes(&R)

	// e = tagged_hash("BIP0340/challenge", R.x || P.x || m), exactly the single
	// signer's challenge, so the aggregate verifies as an ordinary signature.
	r.e = scalarFromHash(taggedHash("BIP0340/challenge", r.rx[:], r.groupX[:], m[:]))
	return r, nil
}

// partial computes participant id's signature share
// s_i = k_h + rho_i*k_b + e*lambda_i*d_i, with d_i negated when the group key
// has odd Y (the nonces already carry the R-parity sign from newRound).
func (r *round) partial(id int) [32]byte {
	d := new(secp.ModNScalar).Set(r.secrets[id])
	if r.pNegated {
		d.Negate()
	}
	term := new(secp.ModNScalar).Set(r.e)
	term.Mul(r.lambdas[id]).Mul(d)
	s := new(secp.ModNScalar).Set(r.rhos[id])
	s.Mul(r.binding[id]).Add(r.hiding[id]).Add(term)
	return s.Bytes()
}

// verifyPartial checks a partial signature against PUBLIC data only:
// s_i*G == ~D_i + rho_i*~E_i + e*lambda_i*~Y_i, where ~X negates the point
// exactly when the corresponding parity adjustment applied. Because rho_i and e
// commit to this round's message and commitment list, a partial from any other
// round (or any other message) fails here — replay is not a special case.
func (r *round) verifyPartial(id int, partial [32]byte) error {
	if _, ok := r.rhos[id]; !ok {
		return fmt.Errorf("participant %d: not in this signing round", id)
	}
	var si secp.ModNScalar
	if si.SetBytes(&partial) != 0 {
		return fmt.Errorf("participant %d: partial overflows the group order", id)
	}
	lhs := pointFromScalar(&si)

	D, E := r.commD[id], r.commE[id]
	if r.rNegated {
		D, E = negatePoint(D), negatePoint(E)
	}
	Y := r.pubShares[id]
	if r.pNegated {
		Y = negatePoint(Y)
	}
	el := new(secp.ModNScalar).Set(r.e)
	el.Mul(r.lambdas[id])

	var t1, t2, dt1, rhs secp.JacobianPoint
	secp.ScalarMultNonConst(r.rhos[id], E, &t1)
	secp.ScalarMultNonConst(el, Y, &t2)
	secp.AddNonConst(D, &t1, &dt1)
	secp.AddNonConst(&dt1, &t2, &rhs)
	rhs.ToAffine()
	if !lhs.X.Equals(&rhs.X) || !lhs.Y.Equals(&rhs.Y) {
		return fmt.Errorf("participant %d: invalid partial signature", id)
	}
	return nil
}

// aggregate verifies every partial and sums them into the final 64-byte BIP340
// signature (R.x || s). A bad partial fails here with its participant named,
// before it can poison the aggregate.
func (r *round) aggregate(partials map[int][32]byte) ([]byte, error) {
	s := new(secp.ModNScalar)
	for _, id := range r.ids {
		p, ok := partials[id]
		if !ok {
			return nil, fmt.Errorf("participant %d: missing partial signature", id)
		}
		if err := r.verifyPartial(id, p); err != nil {
			return nil, err
		}
		var si secp.ModNScalar
		si.SetBytes(&p)
		s.Add(&si)
	}
	sig := make([]byte, 64)
	copy(sig[:32], r.rx[:])
	sb := s.Bytes()
	copy(sig[32:], sb[:])
	return sig, nil
}

// signFROST runs a complete in-process signing round over the given share
// subset and returns the BIP340 signature plus the group X the subset
// reconstructs (for the caller to check against the stored group key).
func signFROST(m [32]byte, shares map[int][32]byte, rnd io.Reader) (sig []byte, groupX [32]byte, err error) {
	r, err := newRound(m, shares, rnd)
	if err != nil {
		return nil, groupX, err
	}
	partials := map[int][32]byte{}
	for _, id := range r.ids {
		partials[id] = r.partial(id)
	}
	sig, err = r.aggregate(partials)
	if err != nil {
		return nil, groupX, err
	}
	return sig, r.groupX, nil
}
