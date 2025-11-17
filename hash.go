package crpt

import (
	"crypto"
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

// Hash identifies a cryptographic hash function that is implemented in another
// package. Hash extends crypto.Hash and add extra hash functions.
type Hash crypto.Hash

const (

	// Passing NotHashed as hashFunc to Crpt.Sign indicates that message is not hashed
	NotHashed Hash = 0
	minHash   Hash = 1024 + iota
	SM3            // import sm3
	maxHash
)

var digestSizes = []uint8{
	NotHashed: 0,
	SM3:       sm3.Size,
}

// HashFunc simply returns the value of h so that [Hash] implements [SignerOpts].
func (h Hash) HashFunc() Hash {
	return h
}

func (h Hash) String() string {
	switch h {
	case SM3:
		return "SM3"
	default:
		return crypto.Hash(h).String()
	}
}

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
	if h > minHash && h < maxHash {
		return int(digestSizes[h])
	}
	return crypto.Hash(h).Size()
}

var hashes = make([]func() hash.Hash, maxHash)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > minHash && h < maxHash {
		f := hashes[h]
		if f != nil {
			return f()
		}
	}
	return crypto.Hash(h).New()
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
	if minHash < h && h < maxHash && hashes[h] != nil {
		return true
	}
	return crypto.Hash(h).Available()
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, f func() hash.Hash) {
	if h <= minHash || h >= maxHash {
		panic("crypto: RegisterHash of unknown hash function")
	}
	hashes[h] = f
}

// HashValue represents a hash value.
type HashValue []byte

// TypedHashValue is a hash value representation that replace the first byte with uint8 representation of the
// crpt.Hash used.
type TypedHashValue []byte
