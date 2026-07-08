// Package fastmerkle implements Elements' fast merkle root for the two-leaf
// case used by asset issuance (SHA256 midstate: one compression, no padding),
// and the asset/token id derivation chain.
package fastmerkle

import (
	"crypto/sha256"
	"encoding/binary"
)

var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

var iv = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

func ror(x uint32, n uint) uint32 { return x>>n | x<<(32-n) }

// Midstate: SHA256 state after compressing one 64-byte block from the IV.
func Midstate(block [64]byte) [32]byte {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}
	for i := 16; i < 64; i++ {
		s0 := ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ w[i-15]>>3
		s1 := ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ w[i-2]>>10
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d, e, f, g, h := iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]
	for i := 0; i < 64; i++ {
		s1 := ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
		ch := (e & f) ^ (^e & g)
		t1 := h + s1 + ch + k[i] + w[i]
		s0 := ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := s0 + maj
		h, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	var out [32]byte
	for i, v := range [8]uint32{iv[0] + a, iv[1] + b, iv[2] + c, iv[3] + d, iv[4] + e, iv[5] + f, iv[6] + g, iv[7] + h} {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return out
}

// Root2 is the fast merkle root of exactly two 32-byte leaves.
func Root2(l, r [32]byte) [32]byte {
	var block [64]byte
	copy(block[:32], l[:])
	copy(block[32:], r[:])
	return Midstate(block)
}

// DeriveIssuanceIDs computes (entropy, asset, token) in internal byte order
// from the issuance prevout (txid internal order, vout) and the raw sha256
// digest of the canonical contract JSON.
func DeriveIssuanceIDs(prevoutHash [32]byte, vout uint32, contractDigest [32]byte) (entropy, asset, token [32]byte) {
	var ser [36]byte
	copy(ser[:32], prevoutHash[:])
	binary.LittleEndian.PutUint32(ser[32:], vout)
	first := sha256.Sum256(ser[:])
	hi := sha256.Sum256(first[:])
	entropy = Root2(hi, contractDigest)
	asset = Root2(entropy, [32]byte{})
	var one [32]byte
	one[0] = 1
	token = Root2(entropy, one)
	return
}
