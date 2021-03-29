// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package ed25519 provides the Ed25519 Crpt implementation backed by
// [crypto/ed25519](https://pkg.go.dev/crypto/ed25519), and the Ed25519-SHA3-512 implementation backd by
// [github.com/crpt/go-ed25519-sha3-512](https://pkg.go.dev/github.com/crpt/go-ed25519-sha3-512).
package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"

	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/internal/util"
	ed25519sha3 "github.com/crpt/go-ed25519-sha3-512"
)

var (
	ErrWrongPublicKeySize       = errors.New("wrong Ed25519 public key size, should be 32 bytes")
	ErrWrongPrivateKeySize      = errors.New("wrong Ed25519 private key size, should be 64 bytes")
	ErrWrongSignatureSize       = errors.New("wrong Ed25519 signature size, should be 64 bytes")
	ErrNotEd25519PublicKey      = errors.New("not a Ed25519 public key")
	ErrNotEd25519SHA3PublicKey  = errors.New("not a Ed25519-SHA3-512 public key")
	ErrNotEd25519PrivateKey     = errors.New("not a Ed25519 private key")
	ErrNotEd25519SHA3PrivateKey = errors.New("not a Ed25519-SHA3-512 private key")
)

// Ed25519 32-byte public key
type publicKey ed25519.PublicKey
type sha3PublicKey ed25519sha3.PublicKey

// Ed25519 32-byte private key + 32-byte public key suffix = 64 bytes
// See: https://pkg.go.dev/crypto/ed25519
type privateKey ed25519.PrivateKey
type sha3PrivateKey ed25519sha3.PrivateKey

// Ed25519 64-byte signature
type Signature = crpt.Signature

// Ed25519 32-byte address
type Address = crpt.Address

func (pub publicKey) Bytes() []byte {
	return pub
}
func (pub sha3PublicKey) Bytes() []byte {
	return pub
}

// Address returns the public key as is instead of deriving address from the
// public key by hashing and returning the last certain bytes, to avoid adding
// extra space in transactions for public keys.
func (pub publicKey) Address() Address {
	return crpt.Address(pub)
}
func (pub sha3PublicKey) Address() Address {
	return crpt.Address(pub)
}

func (priv privateKey) Bytes() []byte {
	return priv
}
func (priv sha3PrivateKey) Bytes() []byte {
	return priv
}

func (priv privateKey) Public() crpt.PublicKey {
	return publicKey(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))
}
func (priv sha3PrivateKey) Public() crpt.PublicKey {
	return sha3PublicKey(ed25519sha3.PrivateKey(priv).Public().(ed25519sha3.PublicKey))
}

// New creates a Ed225519 Crpt, if sha3 is true, it uses SHA3-512 hash function
// instead of normal SHA-512.
func New(sha3 bool, hash crypto.Hash) (*ed25519Crpt, error) {
	crypt := &ed25519Crpt{sha3: sha3}
	algo := crpt.Ed25519
	if sha3 {
		algo = crpt.Ed25519_SHA3_512
	}
	base, err := util.NewBaseCrpt(algo, hash, false, crypt)
	if err != nil {
		return nil, err
	}
	crypt.BaseCrpt = base
	return crypt, nil
}

type ed25519Crpt struct {
	*util.BaseCrpt

	sha3 bool
}

func (crpt *ed25519Crpt) PublicKeyFromBytes(pub []byte) (crpt.PublicKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrWrongPublicKeySize
	}
	if crpt.sha3 {
		return sha3PublicKey(pub), nil
	} else {
		return publicKey(pub), nil
	}
}

func (crpt *ed25519Crpt) PrivateKeyFromBytes(priv []byte) (crpt.PrivateKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrWrongPrivateKeySize
	}
	if crpt.sha3 {
		return sha3PrivateKey(priv), nil
	} else {
		return privateKey(priv), nil
	}
}

func (crpt *ed25519Crpt) SignatureFromBytes(sig []byte) (crpt.Signature, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrWrongSignatureSize
	}
	return sig, nil
}

func (crpt *ed25519Crpt) GenerateKey(rand io.Reader) (crpt.PublicKey, crpt.PrivateKey, error) {
	if crpt.sha3 {
		pub, priv, err := ed25519sha3.GenerateKey(rand)
		return sha3PublicKey(pub), sha3PrivateKey(priv), err
	} else {
		pub, priv, err := ed25519.GenerateKey(rand)
		return publicKey(pub), privateKey(priv), err
	}
}

func (crpt *ed25519Crpt) SignMessage(priv crpt.PrivateKey, message []byte, rand io.Reader) (Signature, error) {
	if crpt.sha3 {
		if edpriv, ok := priv.(sha3PrivateKey); ok {
			return ed25519sha3.Sign(ed25519sha3.PrivateKey(edpriv), message), nil
		} else {
			return nil, ErrNotEd25519SHA3PrivateKey
		}
	} else {
		if edpriv, ok := priv.(privateKey); ok {
			return ed25519.Sign(ed25519.PrivateKey(edpriv), message), nil
		} else {
			return nil, ErrNotEd25519PrivateKey
		}
	}
}

func (crpt *ed25519Crpt) SignDigest(priv crpt.PrivateKey, digest []byte, hashFunc crypto.Hash,
	rand io.Reader) (Signature, error) {
	panic("not supported: Ed25519 cannot handle pre-hashed messages, " +
		"see: https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign")
}

func (crpt *ed25519Crpt) Verify(pub crpt.PublicKey, message []byte, sig Signature) (bool,
	error) {
	if crpt.sha3 {
		if edpub, ok := pub.(sha3PublicKey); ok {
			return ed25519sha3.Verify(ed25519sha3.PublicKey(edpub), message, sig), nil
		} else {
			return false, ErrNotEd25519SHA3PublicKey
		}
	} else {
		if edpub, ok := pub.(publicKey); ok {
			return ed25519.Verify(ed25519.PublicKey(edpub), message, sig), nil
		} else {
			return false, ErrNotEd25519PublicKey
		}
	}
}
