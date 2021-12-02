// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package util provides common utils for Crpt implementations.
package util

import (
	"crypto"
	"hash"
	"io"
	"strconv"

	"github.com/crpt/go-merkle"

	"github.com/crpt/go-crpt"
)

// BaseCrpt is a helper struct meant to be anonymously embedded by pointer in all
// Crpt implementations.
type BaseCrpt struct {
	// KeyType used for embedding crpt.Crpt instance
	keyType crpt.KeyType

	// hashFunc holds the hash function to be used for Crpt.Hash.
	hashFunc crypto.Hash

	// hashFuncByte := byte(hashFunc)
	hashFuncByte byte

	// canSignPreHashedMessages specify whether a Crpt implementation can sign the
	// pre-hashed messages. See Crpt.SignMessage for details.
	canSignPreHashedMessages bool

	// parentCrpt is the crpt.Crpt instance which is embedding this BaseCrpt instance.
	parentCrpt crpt.Crpt
}

func NewBaseCrpt(t crpt.KeyType, hashFunc crypto.Hash, canSignPreHashedMessages bool,
	parentCrpt crpt.Crpt) (*BaseCrpt, error) {
	if hashFunc != 0 && !hashFunc.Available() {
		panic("crypto: requested hash function #" + strconv.Itoa(int(hashFunc)) + " is unavailable")
	}
	if parentCrpt == nil {
		panic("implementations should always pass parentCrpt")
	}
	return &BaseCrpt{
		keyType:                  t,
		hashFunc:                 hashFunc,
		hashFuncByte:             byte(hashFunc),
		canSignPreHashedMessages: canSignPreHashedMessages,
		parentCrpt:               parentCrpt,
	}, nil
}

func (c *BaseCrpt) checkHashFunc() crypto.Hash {
	if !c.hashFunc.Available() {
		panic("crpt: hash function is not set")
	}
	return c.hashFunc
}

// KeyType implements crpt.KeyType.
func (c *BaseCrpt) KeyType() crpt.KeyType {
	return c.keyType
}

// HashFunc implements crpt.HashFunc.
func (c *BaseCrpt) HashFunc() crypto.Hash {
	return c.hashFunc
}

// Hash implements Crpt.Hash using BaseCrpt.hashFunc.
func (c *BaseCrpt) Hash(b []byte) []byte {
	h := c.checkHashFunc().New()
	h.Write(b)
	return h.Sum(nil)
}

// Hash implements Crpt.Hash using BaseCrpt.hashFunc.
func (c *BaseCrpt) HashTyped(b []byte) crpt.TypedHash {
	h := c.checkHashFunc().New()
	h.Write(b)
	s := h.Sum(nil)
	s[0] = c.hashFuncByte
	return s
}

// SumHashTyped implements crpt.SumHashTyped.
func (c *BaseCrpt) SumHashTyped(h hash.Hash, b []byte) []byte {
	s := h.Sum(b)
	s[len(b)] = c.hashFuncByte
	return s
}

// Sign implements Crpt.Sign, see Crpt.Sign for details.
func (c *BaseCrpt) Sign(priv crpt.PrivateKey, message, digest []byte, hashFunc crypto.Hash, rand io.Reader,
) (crpt.Signature, error) {
	if len(digest) > 0 && c.canSignPreHashedMessages {
		return c.parentCrpt.SignDigest(priv, digest, hashFunc, rand)
	} else if len(message) > 0 {
		return c.parentCrpt.SignMessage(priv, message, rand)
	} else {
		return nil, crpt.ErrMessageAndDigestAreBothEmpty
	}
}

// Sign implements Crpt.MerkleHashFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleHashFromByteSlices(items [][]byte) (rootHash []byte) {
	h := c.checkHashFunc()
	return merkle.HashFromByteSlicesIterative(h, items)
}

// Sign implements Crpt.MerkleHashTypedFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleHashTypedFromByteSlices(items [][]byte) (rootHash crpt.TypedHash) {
	h := c.checkHashFunc()
	rootHash = merkle.HashFromByteSlicesIterative(h, items)
	rootHash[0] = byte(h)
	return rootHash
}

// Sign implements Crpt.MerkleProofsFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleProofsFromByteSlices(items [][]byte,
) (rootHash []byte, proofs []*merkle.Proof) {
	h := c.checkHashFunc()
	return merkle.ProofsFromByteSlices(h, items)
}

// Sign implements Crpt.MerkleProofsTypedFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleProofsTypedFromByteSlices(items [][]byte,
) (rootHash crpt.TypedHash, proofs []*merkle.Proof) {
	h := c.checkHashFunc()
	rootHash, proofs = merkle.ProofsFromByteSlices(h, items)
	rootHash[0] = byte(h)
	return rootHash, proofs
}
