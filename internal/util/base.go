// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package util provides common utils for Crpt implementations.
package util

import (
	"crypto"
	"errors"
	"github.com/nexzhu/go-crpt"
	"io"
	"strconv"
)

// BaseCrpt is a helper struct meant to be anonymously embedded by pointer in all
// Crpt implementations.
type BaseCrpt struct {
	// hashFunc holds the hash function to be used for Crpt.Hash.
	hashFunc crypto.Hash

	// canSignPreHashedMessages specify whether a Crpt implementation can sign the
	// pre-hashed messages. See Crpt.SignMessage for details.
	canSignPreHashedMessages bool

	// parentCrpt is the crpt.Crpt instance which is embedding this BaseCrpt instance.
	parentCrpt crpt.Crpt
}

func NewBaseCrpt(hashFunc crypto.Hash, canSignPreHashedMessages bool,
	parentCrpt crpt.Crpt) (*BaseCrpt, error) {
	if !hashFunc.Available() {
		return nil, errors.New("crpt: requested hash function #" +
			strconv.Itoa(int(hashFunc)) + " is unavailable")
	}
	if parentCrpt == nil {
		panic("implementations should always pass parentCrpt")
	}
	return &BaseCrpt{
		hashFunc:                 hashFunc,
		canSignPreHashedMessages: canSignPreHashedMessages,
		parentCrpt:               parentCrpt,
	}, nil
}

// Hash implements Crpt.Hash using BaseCrpt.hashFunc.
func (crpt *BaseCrpt) Hash(b []byte) []byte {
	h := crpt.hashFunc.New()
	h.Write(b)
	return h.Sum(nil)
}

var ErrMessageAndDigestAreBothEmpty = errors.New("message and digest are both empty")

// Sign implements Crpt.Sign, see Crpt.Sign for details.
func (crpt *BaseCrpt) Sign(privateKey crpt.PrivateKey, message, digest []byte,
	hashFunc crypto.Hash, rand io.Reader) (crpt.Signature, error) {
	if len(digest) > 0 && crpt.canSignPreHashedMessages {
		return crpt.parentCrpt.SignDigest(privateKey, digest, hashFunc, rand)
	} else if len(message) > 0 {
		return crpt.parentCrpt.SignMessage(privateKey, message, rand)
	} else {
		return nil, ErrMessageAndDigestAreBothEmpty
	}
}
