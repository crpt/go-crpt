// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package factory is used to create Crpt instances from options.
package factory

import (
	"crypto"

	"github.com/nexzhu/go-crpt"
	"github.com/nexzhu/go-crpt/ed25519"
)

// New creates a Crpt instance with the specified algorithm and hashFunc.
func New(algorithm crpt.Algorithm, hashFunc crypto.Hash) (crpt.Crpt, error) {
	switch algorithm {
	case crpt.Ed25519:
		return ed25519.New(false, hashFunc)
	case crpt.Ed25519_SHA3_512:
		return ed25519.New(true, hashFunc)
	default:
		return nil, crpt.ErrAlgorithmNotSupported
	}
}
