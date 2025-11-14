// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package factory is used to create Crpt instances from options.
package factory

import (
	"crypto"

	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/ed25519"
	"github.com/crpt/go-crpt/sm2"
)

// New creates a Crpt instance with the specified KeyType and default signer options.
func New(keyType crpt.KeyType, opts crypto.SignerOpts) (crpt.Crpt, error) {
	switch keyType {
	case crpt.Ed25519:
		return ed25519.NewWithCryptoSignerOpts(opts)
	case crpt.SM2:
		return sm2.NewWithCryptoSignerOpts(opts)
	default:
		return nil, crpt.ErrKeyTypeNotSupported
	}
}

// MustNew creates a Crpt instance with the specified KeyType and default signer options,
// it panics if an error occurs.
func MustNew(keyType crpt.KeyType, opts crypto.SignerOpts) crpt.Crpt {
	var crypt crpt.Crpt
	var err error
	switch keyType {
	case crpt.Ed25519:
		crypt, err = ed25519.NewWithCryptoSignerOpts(opts)
	case crpt.SM2:
		crypt, err = sm2.NewWithCryptoSignerOpts(opts)
	default:
		panic(crpt.ErrKeyTypeNotSupported)
	}
	if err != nil {
		panic(err)
	}
	return crypt
}

// NewWithKeyTypeStr creates a Crpt instance with the specified KeyType string and default signer options.
func NewWithKeyTypeStr(keyTypeStr string, opts crypto.SignerOpts) (crpt.Crpt, error) {
	return New(crpt.StrToKeyType[keyTypeStr], opts)
}

// MustNewWithKeyTypeStr creates a Crpt instance with the specified KeyType string and default signer options,
// it panics if an error occurs.
func MustNewWithKeyTypeStr(keyTypeStr string, opts crypto.SignerOpts) crpt.Crpt {
	return MustNew(crpt.StrToKeyType[keyTypeStr], opts)
}
