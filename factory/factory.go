// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package factory is used to create Crpt instances from options.
package factory

import (
	"crypto"

	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/ed25519"
)

// New creates a Crpt instance with the specified KeyType and hashFunc.
func New(keyType crpt.KeyType, hashFunc crypto.Hash) (crpt.Crpt, error) {
	switch keyType {
	case crpt.Ed25519:
		return ed25519.New(hashFunc)
	default:
		return nil, crpt.ErrKeyTypeNotSupported
	}
}

// MustNew creates a Crpt instance with the specified algorithm and hashFunc,
// it panics if an error occurs.
func MustNew(keyType crpt.KeyType, hashFunc crypto.Hash) crpt.Crpt {
	var crypt crpt.Crpt
	var err error
	switch keyType {
	case crpt.Ed25519:
		crypt, err = ed25519.New(hashFunc)
	default:
		panic(crpt.ErrKeyTypeNotSupported)
	}
	if err != nil {
		panic(err)
	}
	return crypt
}
