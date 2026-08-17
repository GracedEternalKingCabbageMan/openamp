package frostsigner

import (
	"fmt"
	"io"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Distributed key generation: Feldman VSS with a Schnorr proof of knowledge on
// each member's constant term.
//
// Each member i samples its OWN degree t-1 polynomial f_i and publishes
// commitments C_{i,k} = a_{i,k}*G. The group secret is d = sum_i a_{i,0} and
// the group public key is P = sum_i C_{i,0}, so no component ever holds d — not
// a dealer, not the coordinator, not any member. Member j's long-term share is
// d_j = sum_i f_i(j), which is f(j) for the combined polynomial
// f = sum_i f_i: degree t-1 with f(0) = d. That is exactly the object the
// signing round already expects, so the group key is usable by the existing
// path unchanged and K_policy remains one x-only point (no address or asset id
// moves).
//
// Two checks make it a real DKG rather than a share-shuffling exercise, and
// each names the participant that fails it:
//
//   - PROOF OF KNOWLEDGE (verified by the coordinator and by every member
//     before it deals): mu_i*G == R_i + c_i*C_{i,0}. Without it a member could
//     wait for everyone else's commitments and choose its own contribution as a
//     function of them, steering the group key (rogue-key attack).
//   - FELDMAN SHARE CHECK (verified by the RECIPIENT, the only party that can):
//     f_i(j)*G == sum_k C_{i,k} * j^k. This is what binds the secret share a
//     member receives to the commitment its sender published, so a sender
//     cannot hand out a share inconsistent with the public group key. A member
//     that deals inconsistently is caught by whichever recipient's check fails,
//     and equivocation (different commitments to different peers) additionally
//     shows up as members deriving different group keys.

// dkgPoKTag domain-separates the proof-of-knowledge challenge from every other
// hash in the protocol, and binds the proof to its session so a proof cannot be
// replayed into another DKG run.
const dkgPoKTag = "FROST/dkg-pok"

// polynomial is a member's secret polynomial: coeffs[0] is its contribution to
// the group secret.
type polynomial struct {
	coeffs []*secp.ModNScalar
}

// newPolynomial samples a degree t-1 polynomial.
func newPolynomial(t int, rnd io.Reader) (*polynomial, error) {
	if t < 2 {
		return nil, fmt.Errorf("threshold must be at least 2, got %d", t)
	}
	p := &polynomial{coeffs: make([]*secp.ModNScalar, t)}
	for k := range p.coeffs {
		c, err := randomScalar(rnd)
		if err != nil {
			return nil, err
		}
		p.coeffs[k] = c
	}
	return p, nil
}

// eval returns f(x) for a participant index x >= 1.
func (p *polynomial) eval(x int) *secp.ModNScalar {
	var xs secp.ModNScalar
	xs.SetInt(uint32(x))
	acc := new(secp.ModNScalar).Set(p.coeffs[len(p.coeffs)-1])
	for k := len(p.coeffs) - 2; k >= 0; k-- { // Horner
		acc.Mul(&xs).Add(p.coeffs[k])
	}
	return acc
}

// commit produces the member's round-1 broadcast: the Feldman commitments and
// the proof of knowledge of coeffs[0].
func (p *polynomial) commit(id int, sessionID string, rnd io.Reader) (*DKGCommitment, error) {
	c := &DKGCommitment{From: id, Coeffs: make([][]byte, len(p.coeffs))}
	for k, a := range p.coeffs {
		c.Coeffs[k] = compressPoint(pointFromScalar(a))
	}
	k, err := randomScalar(rnd)
	if err != nil {
		return nil, err
	}
	R := pointFromScalar(k)
	c.PoKR = compressPoint(R)
	chal := pokChallenge(sessionID, id, c.Coeffs, c.PoKR)
	mu := new(secp.ModNScalar).Set(chal)
	mu.Mul(p.coeffs[0]).Add(k) // mu = k + a_0*c
	c.PoKMu = mu.Bytes()
	return c, nil
}

// pokChallenge is the proof-of-knowledge challenge scalar. It commits to the
// WHOLE commitment vector, not just the constant term: only a_0 is proven
// known, but binding the higher coefficients means a broadcast altered in
// transit fails this check at round 1 — where the failure is attributable to
// the relayed commitment — instead of surfacing later as a Feldman share
// failure that would frame an honest dealer.
func pokChallenge(sessionID string, id int, coeffs [][]byte, r []byte) *secp.ModNScalar {
	chunks := make([][]byte, 0, len(coeffs)+4)
	chunks = append(chunks, []byte(sessionID), idBytes(id), idBytes(len(coeffs)))
	chunks = append(chunks, coeffs...)
	chunks = append(chunks, r)
	return scalarFromHash(taggedHash(dkgPoKTag, chunks...))
}

// verifyCommitment checks a member's round-1 broadcast: well-formed commitments
// of the right degree, no identity points, and a valid proof of knowledge of
// the constant term. Every failure names the member.
func verifyCommitment(sessionID string, threshold int, c *DKGCommitment) error {
	if c == nil {
		return fmt.Errorf("missing commitment")
	}
	if len(c.Coeffs) != threshold {
		return misbehaved(c.From, "published %d coefficient commitments, want %d (threshold)", len(c.Coeffs), threshold)
	}
	pts := make([]*secp.JacobianPoint, len(c.Coeffs))
	for k, b := range c.Coeffs {
		p, err := parsePoint(b)
		if err != nil {
			return misbehaved(c.From, "coefficient commitment %d is not a valid point: %v", k, err)
		}
		pts[k] = p
	}
	R, err := parsePoint(c.PoKR)
	if err != nil {
		return misbehaved(c.From, "proof-of-knowledge nonce is not a valid point: %v", err)
	}
	var mu secp.ModNScalar
	if mu.SetBytes(&c.PoKMu) != 0 {
		return misbehaved(c.From, "proof-of-knowledge scalar overflows the group order")
	}
	// mu*G == R + c*C_0
	chal := pokChallenge(sessionID, c.From, c.Coeffs, c.PoKR)
	var scaled, rhs secp.JacobianPoint
	secp.ScalarMultNonConst(chal, pts[0], &scaled)
	secp.AddNonConst(R, &scaled, &rhs)
	rhs.ToAffine()
	lhs := pointFromScalar(&mu)
	if !lhs.X.Equals(&rhs.X) || !lhs.Y.Equals(&rhs.Y) {
		return misbehaved(c.From, "invalid proof of knowledge for its constant-term commitment")
	}
	return nil
}

// commitmentEval evaluates a member's commitment polynomial in the group:
// sum_k C_k * x^k. This is the public image of f_i(x), which is what makes the
// share check possible without knowing f_i.
func commitmentEval(c *DKGCommitment, x int) (*secp.JacobianPoint, error) {
	if len(c.Coeffs) == 0 {
		return nil, misbehaved(c.From, "published no coefficient commitments")
	}
	var xs, pow secp.ModNScalar
	xs.SetInt(uint32(x))
	pow.SetInt(1)
	var acc secp.JacobianPoint
	for k, b := range c.Coeffs {
		p, err := parsePoint(b)
		if err != nil {
			return nil, misbehaved(c.From, "coefficient commitment %d is not a valid point: %v", k, err)
		}
		var term, sum secp.JacobianPoint
		secp.ScalarMultNonConst(&pow, p, &term)
		secp.AddNonConst(&acc, &term, &sum)
		acc.Set(&sum)
		pow.Mul(&xs)
	}
	acc.ToAffine()
	return &acc, nil
}

// verifyShare is the Feldman check, run by the RECIPIENT: the secret share it
// was handed must be the pre-image of its sender's public commitment
// polynomial at the recipient's index. Names the SENDER on failure.
func verifyShare(c *DKGCommitment, sh *DKGShare) error {
	var s secp.ModNScalar
	v := sh.Value
	if s.SetBytes(&v) != 0 {
		return misbehaved(sh.From, "share for participant %d overflows the group order", sh.To)
	}
	if s.IsZero() {
		return misbehaved(sh.From, "share for participant %d is zero", sh.To)
	}
	want, err := commitmentEval(c, sh.To)
	if err != nil {
		return err
	}
	got := pointFromScalar(&s)
	if !got.X.Equals(&want.X) || !got.Y.Equals(&want.Y) {
		return misbehaved(sh.From, "share for participant %d does not match its published commitments", sh.To)
	}
	return nil
}

// groupPoint derives the group public key from the constant-term commitments:
// P = sum_i C_{i,0}. Public data only, so the coordinator never takes a
// member's word for the group key.
func groupPoint(comms map[int]*DKGCommitment) (*secp.JacobianPoint, error) {
	var acc secp.JacobianPoint
	for _, id := range sortedIDs(comms) {
		if len(comms[id].Coeffs) == 0 {
			return nil, misbehaved(id, "published no coefficient commitments")
		}
		p, err := parsePoint(comms[id].Coeffs[0])
		if err != nil {
			return nil, misbehaved(id, "constant-term commitment is not a valid point: %v", err)
		}
		var sum secp.JacobianPoint
		secp.AddNonConst(&acc, p, &sum)
		acc.Set(&sum)
	}
	acc.ToAffine()
	if isInfinity(&acc) {
		return nil, fmt.Errorf("group public key is the point at infinity")
	}
	return &acc, nil
}

// publicShareFrom derives member j's public share from the commitments:
// Y_j = sum_i (sum_k C_{i,k} * j^k) = d_j*G. Public data, so pinning these at
// keygen lets the coordinator later verify each partial signature and NAME the
// member that produced a bad one, without trusting any member's self-report.
func publicShareFrom(comms map[int]*DKGCommitment, j int) (*secp.JacobianPoint, error) {
	var acc secp.JacobianPoint
	for _, id := range sortedIDs(comms) {
		p, err := commitmentEval(comms[id], j)
		if err != nil {
			return nil, err
		}
		var sum secp.JacobianPoint
		secp.AddNonConst(&acc, p, &sum)
		acc.Set(&sum)
	}
	acc.ToAffine()
	if isInfinity(&acc) {
		return nil, fmt.Errorf("public share of participant %d is the point at infinity", j)
	}
	return &acc, nil
}
