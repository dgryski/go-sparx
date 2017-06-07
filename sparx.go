// Package sparx implements the SPARX lightweight cipher
/*

   https://www.cryptolux.org/index.php/SPARX
   https://github.com/cryptolu/SPARX/blob/master/ref-c/sparx.c

*/
package sparx

import (
	"encoding/binary"
)

func rotl(x uint16, n uint) uint16 {
	return (((x) << n) | ((x) >> (16 - (n))))
}

const (
	nSteps         = 8
	roundsPerSteps = 3
	nBranches      = 2
)

const BlockSize = 8

type Cipher struct {
	k [nBranches*nSteps + 1][2 * roundsPerSteps]uint16
}

func (c *Cipher) BlockSize() int { return BlockSize }

func a(l, r uint16) (uint16, uint16) {
	l = rotl(l, 9)
	l += r
	r = rotl(r, 2)
	r ^= l
	return l, r
}

func aInv(l, r uint16) (uint16, uint16) {
	r ^= l
	r = rotl(r, 14)
	l -= r
	l = rotl(l, 7)
	return l, r
}

func l2(x []uint16) {
	tmp := rotl((x[0] ^ x[1]), 8)
	x[2] ^= x[0] ^ tmp
	x[3] ^= x[1] ^ tmp
	x[0], x[2] = x[2], x[0]
	x[1], x[3] = x[3], x[1]
}

func l2Inv(x []uint16) {
	x[0], x[2] = x[2], x[0]
	x[1], x[3] = x[3], x[1]
	tmp := rotl(x[0]^x[1], 8)
	x[2] ^= x[0] ^ tmp
	x[3] ^= x[1] ^ tmp
}

func perm64x128(k []uint16, c uint16) {
	/* Misty-like transformation */
	k[0], k[1] = a(k[0], k[1])
	k[2] += k[0]
	k[3] += k[1]
	k[7] += c
	/* Branch rotation */
	tmp0 := k[6]
	tmp1 := k[7]
	for i := 7; i >= 2; i-- {
		k[i] = k[i-2]
	}
	k[0] = tmp0
	k[1] = tmp1
}

func New(masterKey []uint16) *Cipher {
	var cipher Cipher
	for c := 0; c < (nBranches*nSteps + 1); c++ {
		for i := 0; i < 2*roundsPerSteps; i++ {
			cipher.k[c][i] = masterKey[i]
		}
		perm64x128(masterKey, uint16(c+1))
	}

	return &cipher
}

func (c *Cipher) Encrypt(dst, src []uint8) {
	var x [4]uint16
	x[0] = binary.BigEndian.Uint16(src)
	x[1] = binary.BigEndian.Uint16(src[2:])
	x[2] = binary.BigEndian.Uint16(src[4:])
	x[3] = binary.BigEndian.Uint16(src[6:])

	for s := 0; s < nSteps; s++ {
		for b := 0; b < nBranches; b++ {
			for r := 0; r < roundsPerSteps; r++ {
				x[2*b] ^= c.k[nBranches*s+b][2*r]
				x[2*b+1] ^= c.k[nBranches*s+b][2*r+1]
				x[2*b], x[2*b+1] = a(x[2*b], x[2*b+1])
			}
		}
		l2(x[:])
	}

	for b := 0; b < nBranches; b++ {
		x[2*b] ^= c.k[nBranches*nSteps][2*b]
		x[2*b+1] ^= c.k[nBranches*nSteps][2*b+1]
	}

	binary.BigEndian.PutUint16(dst, x[0])
	binary.BigEndian.PutUint16(dst[2:], x[1])
	binary.BigEndian.PutUint16(dst[4:], x[2])
	binary.BigEndian.PutUint16(dst[6:], x[3])
}

func (c *Cipher) Decrypt(dst, src []uint8) {
	var x [4]uint16
	x[0] = binary.BigEndian.Uint16(src)
	x[1] = binary.BigEndian.Uint16(src[2:])
	x[2] = binary.BigEndian.Uint16(src[4:])
	x[3] = binary.BigEndian.Uint16(src[6:])

	for b := 0; b < nBranches; b++ {
		x[2*b] ^= c.k[nBranches*nSteps][2*b]
		x[2*b+1] ^= c.k[nBranches*nSteps][2*b+1]
	}

	for s := nSteps - 1; s >= 0; s-- {
		l2Inv(x[:])
		for b := 0; b < nBranches; b++ {
			for r := roundsPerSteps - 1; r >= 0; r-- {
				x[2*b], x[2*b+1] = aInv(x[2*b], x[2*b+1])
				x[2*b] ^= c.k[nBranches*s+b][2*r]
				x[2*b+1] ^= c.k[nBranches*s+b][2*r+1]
			}
		}
	}

	binary.BigEndian.PutUint16(dst, x[0])
	binary.BigEndian.PutUint16(dst[2:], x[1])
	binary.BigEndian.PutUint16(dst[4:], x[2])
	binary.BigEndian.PutUint16(dst[6:], x[3])
}
