// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package auto provides an implementation that automatically detects the types of public/private
// keys or signatures and use corresponding Crpt implementations for crypto operations.
package auto

import (
	"crypto"
	"errors"
	"io"

	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/factory"
	"github.com/crpt/go-crpt/internal/util"
)

var ErrKeyTypesDoesNotMatch = errors.New("key types of the public key and the signature does not match")

// New creates an auto Crpt.
func New(hash crypto.Hash) (*autoCrpt, error) {
	crypt := &autoCrpt{crpts: make(map[crpt.KeyType]crpt.Crpt)}
	var err error
	for t := crpt.KeyType(1); t < crpt.NumberOfAvailableImpl; t++ {
		if crypt.crpts[t], err = factory.New(t, hash); err != nil {
			return nil, err
		}
	}

	base, err := util.NewBaseCrpt(crpt.Auto, hash, false, crypt)
	if err != nil {
		return nil, err
	}
	crypt.BaseCrpt = base
	return crypt, nil
}

type autoCrpt struct {
	*util.BaseCrpt

	crpts map[crpt.KeyType]crpt.Crpt
}

func (a autoCrpt) PublicKeyFromBytes(pub []byte) (crpt.PublicKey, error) {
	panic(crpt.ErrUnimplemented)
}

func (a autoCrpt) PublicKeyFromTypedBytes(pub crpt.TypedPublicKey) (crpt.PublicKey, error) {
	t := crpt.KeyType(pub[0])
	crypt, ok := a.crpts[t]
	if !ok {
		return nil, crpt.ErrKeyTypeNotSupported
	}
	return crypt.PublicKeyFromTypedBytes(pub)
}

func (a autoCrpt) PrivateKeyFromBytes(priv []byte) (crpt.PrivateKey, error) {
	panic(crpt.ErrUnimplemented)
}

func (a autoCrpt) PrivateKeyFromTypedBytes(priv crpt.TypedPrivateKey) (crpt.PrivateKey, error) {
	t := crpt.KeyType(priv[0])
	crypt, ok := a.crpts[t]
	if !ok {
		return nil, crpt.ErrKeyTypeNotSupported
	}
	return crypt.PrivateKeyFromTypedBytes(priv)
}

func (a autoCrpt) SignatureFromBytes(sig []byte) (crpt.Signature, error) {
	panic(crpt.ErrUnimplemented)
}

func (a autoCrpt) SignatureFromTypedBytes(sig crpt.TypedSignature) (crpt.Signature, error) {
	t := crpt.KeyType(sig[0])
	crypt, ok := a.crpts[t]
	if !ok {
		return nil, crpt.ErrKeyTypeNotSupported
	}
	return crypt.SignatureFromTypedBytes(sig)
}

func (a autoCrpt) GenerateKey(rand io.Reader) (crpt.PublicKey, crpt.PrivateKey, error) {
	panic(crpt.ErrUnimplemented)
}

func (a autoCrpt) SignMessage(priv crpt.PrivateKey, message []byte, rand io.Reader,
) (crpt.Signature, error) {
	crypt, ok := a.crpts[priv.KeyType()]
	if !ok {
		return nil, crpt.ErrKeyTypeNotSupported
	}
	return crypt.SignMessage(priv, message, rand)
}

func (a autoCrpt) SignDigest(priv crpt.PrivateKey, digest []byte, hashFunc crypto.Hash, rand io.Reader,
) (crpt.Signature, error) {
	crypt, ok := a.crpts[priv.KeyType()]
	if !ok {
		return nil, crpt.ErrKeyTypeNotSupported
	}
	return crypt.SignDigest(priv, digest, hashFunc, rand)
}

func (a autoCrpt) Verify(pub crpt.PublicKey, message []byte, sig crpt.Signature) (bool, error) {
	if pub.KeyType() != sig.KeyType() {
		return false, ErrKeyTypesDoesNotMatch
	}
	crypt, ok := a.crpts[pub.KeyType()]
	if !ok {
		return false, crpt.ErrKeyTypeNotSupported
	}
	return crypt.Verify(pub, message, sig)
}

var _ crpt.Crpt = (*autoCrpt)(nil)
