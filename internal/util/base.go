package util

import (
	"crypto"
	"errors"
	"github.com/nexzhu/go-crpt"
	"io"
)

// BaseCrpt is a helper struct meant to be anonymously embedded by pointer in all
// Crpt implementations.
type BaseCrpt struct {
	// HashFunc holds the hash function to be used for Crpt.Hash.
	HashFunc crypto.Hash

	// CanSignPreHashedMessages specify whether a Crpt implementation can sign the
	// pre-hashed messages. See Crpt.SignMessage for details.
	CanSignPreHashedMessages bool

	// Crpt is the crpt.Crpt instance which is embedding this BaseCrpt instance.
	Crpt crpt.Crpt
}

// Hash implements Crpt.Hash using BaseCrpt.HashFunc.
func (crpt *BaseCrpt) Hash(b []byte) []byte {
	h := crpt.HashFunc.New()
	h.Write(b)
	return h.Sum(nil)
}

var ErrMessageAndDigestAreBothEmpty = errors.New("message and digest are both empty")

// Sign implements Crpt.Sign, see Crpt.Sign for details.
func (crpt *BaseCrpt) Sign(privateKey crpt.PrivateKey, message, digest []byte,
	hashFunc crypto.Hash, rand io.Reader) (crpt.Signature, error) {
	if len(digest) > 0 && crpt.CanSignPreHashedMessages {
		return crpt.Crpt.SignDigest(privateKey, digest, hashFunc, rand)
	} else if len(message) > 0 {
		return crpt.Crpt.SignMessage(privateKey, message, rand)
	} else {
		return nil, ErrMessageAndDigestAreBothEmpty
	}
}
