// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package util provides common utils for Crpt implementations.
package util

import (
	"crypto"
	"errors"
	"hash"
	"io"
	"strconv"

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

func NewBaseCrpt(ktype crpt.KeyType, hashFunc crypto.Hash, canSignPreHashedMessages bool,
	parentCrpt crpt.Crpt) (*BaseCrpt, error) {
	if !hashFunc.Available() {
		return nil, errors.New("crpt: requested hash function #" +
			strconv.Itoa(int(hashFunc)) + " is unavailable")
	}
	if parentCrpt == nil {
		panic("implementations should always pass parentCrpt")
	}
	return &BaseCrpt{
		keyType:                  ktype,
		hashFunc:                 hashFunc,
		hashFuncByte:             byte(hashFunc),
		canSignPreHashedMessages: canSignPreHashedMessages,
		parentCrpt:               parentCrpt,
	}, nil
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
	h := c.hashFunc.New()
	h.Write(b)
	return h.Sum(nil)
}

// Hash implements Crpt.Hash using BaseCrpt.hashFunc.
func (c *BaseCrpt) HashTyped(b []byte) crpt.TypedHash {
	h := c.hashFunc.New()
	h.Write(b)
	s := make([]byte, 1, h.Size()+1)
	s[0] = c.hashFuncByte
	return h.Sum(s)
}

// SumHashTyped implements crpt.SumHashTyped.
func (c *BaseCrpt) SumHashTyped(h hash.Hash, b []byte) []byte {
	s := make([]byte, len(b)+1, len(b)+h.Size()+1)
	if len(b) > 0 {
		copy(s, b)
	}
	s[len(b)] = c.hashFuncByte
	return h.Sum(s)
}

var ErrMessageAndDigestAreBothEmpty = errors.New("message and digest are both empty")

// Sign implements Crpt.Sign, see Crpt.Sign for details.
func (c *BaseCrpt) Sign(privateKey crpt.PrivateKey, message, digest []byte,
	hashFunc crypto.Hash, rand io.Reader) (crpt.Signature, error) {
	if len(digest) > 0 && c.canSignPreHashedMessages {
		return c.parentCrpt.SignDigest(privateKey, digest, hashFunc, rand)
	} else if len(message) > 0 {
		return c.parentCrpt.SignMessage(privateKey, message, rand)
	} else {
		return nil, ErrMessageAndDigestAreBothEmpty
	}
}
