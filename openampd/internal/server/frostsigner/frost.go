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

// parsePoint decodes a 33-byte compressed point to affine form.
func parsePoint(b []byte) (*secp.JacobianPoint, error) {
	if len(b) != 33 {
		return nil, fmt.Errorf("want a 33-byte compressed point, got %d bytes", len(b))
	}
	pub, err := secp.ParsePubKey(b)
	if err != nil {
		return nil, err
	}
	var p secp.JacobianPoint
	pub.AsJacobian(&p)
	p.ToAffine()
	if isInfinity(&p) {
		return nil, fmt.Errorf("point at infinity")
	}
	return &p, nil
}

func idBytes(id int) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(id))
	return b[:]
}

// sortedIDs returns a map's integer keys in ascending order, so every
// participant serializes the same list in the same order.
func sortedIDs[V any](m map[int]V) []int {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
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

// signingContext is one FROST signing round derived from PUBLIC data only: the
// message, the group public key and the members' nonce commitments. Coordinator
// and member each build it from the same SigningPackage and therefore agree on
// the binding factors, the aggregate nonce, both BIP340 parity adjustments and
// the challenge without exchanging any of them. Nothing secret enters here, so
// the same type serves the member (which then adds its share and nonces) and
// the coordinator (which then verifies and aggregates).
type signingContext struct {
	m       [32]byte
	ids     []int // signing subset, ascending
	lambdas map[int]*secp.ModNScalar

	commD, commE map[int]*secp.JacobianPoint // as published by the members
	rhos         map[int]*secp.ModNScalar

	rx     [32]byte
	e      *secp.ModNScalar
	groupX [32]byte

	rNegated bool // R.y was odd: nonces negated, verify against -D_i, -E_i
	pNegated bool // P.y was odd: shares negated in partials, verify against -Y_i
}

// newSigningContext derives the round from a signing package.
func newSigningContext(pkg *SigningPackage) (*signingContext, error) {
	if pkg == nil || len(pkg.Commitments) < 2 {
		return nil, fmt.Errorf("signing package needs at least 2 nonce commitments")
	}
	c := &signingContext{
		m:       pkg.Message,
		lambdas: map[int]*secp.ModNScalar{},
		commD:   map[int]*secp.JacobianPoint{}, commE: map[int]*secp.JacobianPoint{},
		rhos: map[int]*secp.ModNScalar{},
	}
	for _, nc := range pkg.Commitments {
		if nc.From < 1 || nc.From > 0xffff {
			return nil, fmt.Errorf("participant id %d out of range", nc.From)
		}
		if _, dup := c.commD[nc.From]; dup {
			return nil, fmt.Errorf("participant %d appears twice in the signing package", nc.From)
		}
		D, err := parsePoint(nc.D)
		if err != nil {
			return nil, misbehaved(nc.From, "hiding-nonce commitment is not a valid point: %v", err)
		}
		E, err := parsePoint(nc.E)
		if err != nil {
			return nil, misbehaved(nc.From, "binding-nonce commitment is not a valid point: %v", err)
		}
		c.commD[nc.From], c.commE[nc.From] = D, E
	}
	c.ids = sortedIDs(c.commD)
	for _, id := range c.ids {
		c.lambdas[id] = lagrange(c.ids, id)
	}

	// The group key travels as a full point so its parity is derived, not
	// trusted: an x-only key names the even-Y point, so an odd-Y group point
	// means the effective secret is n-d and every share's contribution is
	// negated.
	P, err := parsePoint(pkg.GroupKey)
	if err != nil {
		return nil, fmt.Errorf("group public key: %w", err)
	}
	c.groupX = xBytes(P)
	c.pNegated = P.Y.IsOdd()

	// Binding factors over the FULL commitment list (so a commitment cannot be
	// replayed into another round), then R = sum(D_i + rho_i*E_i).
	var commitList []byte
	for _, id := range c.ids {
		commitList = append(commitList, idBytes(id)...)
		commitList = append(commitList, compressPoint(c.commD[id])...)
		commitList = append(commitList, compressPoint(c.commE[id])...)
	}
	var R secp.JacobianPoint
	for _, id := range c.ids {
		rho := scalarFromHash(taggedHash(rhoTag, idBytes(id), c.m[:], commitList))
		if rho.IsZero() {
			return nil, fmt.Errorf("participant %d: zero binding factor", id)
		}
		c.rhos[id] = rho
		var rhoE, bound, sum secp.JacobianPoint
		secp.ScalarMultNonConst(rho, c.commE[id], &rhoE)
		secp.AddNonConst(&rhoE, c.commD[id], &bound)
		secp.AddNonConst(&R, &bound, &sum)
		R.Set(&sum)
	}
	R.ToAffine()
	if isInfinity(&R) {
		return nil, fmt.Errorf("aggregate nonce is the point at infinity; retry with fresh nonces")
	}
	// BIP340 R parity: an odd-Y R is negated by negating every nonce scalar
	// (R.x is unchanged, so the signature bytes commit to the same rx).
	c.rNegated = R.Y.IsOdd()
	c.rx = xBytes(&R)

	// e = tagged_hash("BIP0340/challenge", R.x || P.x || m), exactly the single
	// signer's challenge, so the aggregate verifies as an ordinary signature.
	c.e = scalarFromHash(taggedHash("BIP0340/challenge", c.rx[:], c.groupX[:], c.m[:]))
	return c, nil
}

// partial computes one member's signature share
// s_i = k_h + rho_i*k_b + e*lambda_i*d_i, applying both parity adjustments: the
// nonces are negated when R had odd Y, the share when the group point had odd
// Y. Only the member itself ever calls this — share and nonces are its secrets.
func (c *signingContext) partial(id int, share, kh, kb *secp.ModNScalar) ([32]byte, error) {
	lambda, ok := c.lambdas[id]
	if !ok {
		return [32]byte{}, fmt.Errorf("participant %d is not in this signing round", id)
	}
	h := new(secp.ModNScalar).Set(kh)
	b := new(secp.ModNScalar).Set(kb)
	if c.rNegated {
		h.Negate()
		b.Negate()
	}
	d := new(secp.ModNScalar).Set(share)
	if c.pNegated {
		d.Negate()
	}
	term := new(secp.ModNScalar).Set(c.e)
	term.Mul(lambda).Mul(d)
	s := new(secp.ModNScalar).Set(c.rhos[id])
	s.Mul(b).Add(h).Add(term)
	return s.Bytes(), nil
}

// verifyPartial checks a partial signature against PUBLIC data only:
// s_i*G == ~D_i + rho_i*~E_i + e*lambda_i*~Y_i, where ~X negates the point
// exactly when the corresponding parity adjustment applied. Because rho_i and e
// commit to this round's message and commitment list, a partial from any other
// round (or any other message) fails here — replay is not a special case.
func (c *signingContext) verifyPartial(id int, Y *secp.JacobianPoint, partial [32]byte) error {
	if _, ok := c.rhos[id]; !ok {
		return fmt.Errorf("participant %d: not in this signing round", id)
	}
	var si secp.ModNScalar
	if si.SetBytes(&partial) != 0 {
		return misbehaved(id, "partial signature overflows the group order")
	}
	lhs := pointFromScalar(&si)

	D, E := c.commD[id], c.commE[id]
	if c.rNegated {
		D, E = negatePoint(D), negatePoint(E)
	}
	if c.pNegated {
		Y = negatePoint(Y)
	}
	el := new(secp.ModNScalar).Set(c.e)
	el.Mul(c.lambdas[id])

	var t1, t2, dt1, rhs secp.JacobianPoint
	secp.ScalarMultNonConst(c.rhos[id], E, &t1)
	secp.ScalarMultNonConst(el, Y, &t2)
	secp.AddNonConst(D, &t1, &dt1)
	secp.AddNonConst(&dt1, &t2, &rhs)
	rhs.ToAffine()
	if !lhs.X.Equals(&rhs.X) || !lhs.Y.Equals(&rhs.Y) {
		return misbehaved(id, "invalid partial signature")
	}
	return nil
}

// aggregate verifies every partial against its member's public share and sums
// them into the final 64-byte BIP340 signature (R.x || s). A bad partial fails
// here with its member named, before it can poison the aggregate.
func (c *signingContext) aggregate(partials map[int][32]byte, pubShares map[int]*secp.JacobianPoint) ([]byte, error) {
	s := new(secp.ModNScalar)
	for _, id := range c.ids {
		p, ok := partials[id]
		if !ok {
			return nil, fmt.Errorf("participant %d: missing partial signature", id)
		}
		Y, ok := pubShares[id]
		if !ok {
			return nil, fmt.Errorf("participant %d: no public share to verify its partial against", id)
		}
		if err := c.verifyPartial(id, Y, p); err != nil {
			return nil, err
		}
		var si secp.ModNScalar
		si.SetBytes(&p)
		s.Add(&si)
	}
	sig := make([]byte, 64)
	copy(sig[:32], c.rx[:])
	sb := s.Bytes()
	copy(sig[32:], sb[:])
	return sig, nil
}

// groupPointFromShares reconstructs the group point from a threshold subset of
// shares: sum(lambda_i * d_i * G) = f(0)*G = P. Used for key material generated
// before the group point was persisted in full (see
// FrostSigner.verificationData) and by the dealer keygen.
func groupPointFromShares(shares map[int][32]byte) (*secp.JacobianPoint, error) {
	ids := sortedIDs(shares)
	if len(ids) < 2 {
		return nil, fmt.Errorf("need at least 2 shares, have %d", len(ids))
	}
	var P secp.JacobianPoint
	for _, id := range ids {
		b := shares[id]
		d := new(secp.ModNScalar)
		if d.SetBytes(&b) != 0 || d.IsZero() {
			return nil, fmt.Errorf("participant %d: invalid share scalar", id)
		}
		var term, sum secp.JacobianPoint
		secp.ScalarMultNonConst(lagrange(ids, id), pointFromScalar(d), &term)
		secp.AddNonConst(&P, &term, &sum)
		P.Set(&sum)
	}
	P.ToAffine()
	if isInfinity(&P) {
		return nil, fmt.Errorf("degenerate group key")
	}
	return &P, nil
}
