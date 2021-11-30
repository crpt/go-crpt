// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package ed25519 provides an Ed25519 implementation backed by [crypto/ed25519](https://pkg.go.dev/crypto/ed25519) std package,
// but using [ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) package for signature verification,
// which conforms to [ZIP 215](https://zips.z.cash/zip-0215) specification, making it suitable for consensus-critical contexts,
// see [README from ed25519consensus](https://github.com/hdevalence/ed25519consensus) for the explanation.
//
// It also provides an Ed25519-SHA3-512 implementation backed by [go-ed25519-sha3-512](https://pkg.go.dev/github.com/crpt/go-ed25519-sha3-512) package,
// which is a fork of [crypto/ed25519](https://pkg.go.dev/crypto/ed25519) std package, modified to use SHA3-512 instead of SHA-512.
// using [go-ed25519consensus-sha3-512](https://pkg.go.dev/github.com/crpt/go-ed25519consensus-sha3-512) package for signature verification,
// which is a fork of [ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) package, modified to use SHA3-512 instead of SHA-512.
// So it's also suitable for consensus-critical contexts.
package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	ed25519sha3 "github.com/crpt/go-ed25519-sha3-512"
	"github.com/crpt/go-ed25519consensus"
	ed25519consensus_sha3 "github.com/crpt/go-ed25519consensus-sha3-512"

	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/internal/util"
)

const (
	// 32
	PublicKeySize = ed25519.PublicKeySize
	// 64
	PrivateKeySize = ed25519.PrivateKeySize
	// 64
	SignatureSize = ed25519.SignatureSize
	// 65
	AddressSize = PublicKeySize + 1
)

var (
	KeyTypeByte          = byte(crpt.Ed25519)
	KeyTypeByte_SHA3_512 = byte(crpt.Ed25519_SHA3_512)

	ErrWrongPublicKeySize       = fmt.Errorf("%w, should be 32 bytes", crpt.ErrWrongPublicKeySize)
	ErrWrongPrivateKeySize      = fmt.Errorf("%w, should be 64 bytes", crpt.ErrWrongPrivateKeySize)
	ErrWrongSignatureSize       = fmt.Errorf("%w, should be 64 bytes", crpt.ErrWrongSignatureSize)
	ErrNotEd25519PublicKey      = errors.New("not a Ed25519 public key")
	ErrNotEd25519SHA3PublicKey  = errors.New("not a Ed25519-SHA3-512 public key")
	ErrNotEd25519PrivateKey     = errors.New("not a Ed25519 private key")
	ErrNotEd25519SHA3PrivateKey = errors.New("not a Ed25519-SHA3-512 private key")
	ErrNotEd25519Signature      = errors.New("not a Ed25519 signature")
	ErrNotEd25519SHA3Signature  = errors.New("not a Ed25519-SHA3-512 signature")
)

// Ed25519 32-byte public key
// + 1-byte key type prefix
type publicKey crpt.TypedPublicKey
type sha3PublicKey crpt.TypedPublicKey

// Ed25519 32-byte private key + 32-byte public key suffix = 64 bytes
// + 1-byte key type prefix
// See: https://pkg.go.dev/crypto/ed25519
type privateKey crpt.TypedPrivateKey
type sha3PrivateKey crpt.TypedPrivateKey

// Ed25519 64-byte signature
// + 1-byte key type prefix
type signature crpt.TypedSignature
type sha3Signature crpt.TypedSignature

// Ed25519 33-byte address (the same as TypedPublicKey)
type Address = crpt.Address

func (pub publicKey) KeyType() crpt.KeyType {
	return crpt.Ed25519
}
func (pub sha3PublicKey) KeyType() crpt.KeyType {
	return crpt.Ed25519_SHA3_512
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub publicKey) Bytes() []byte {
	return pub[1 : PublicKeySize+1]
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub sha3PublicKey) Bytes() []byte {
	return pub[1 : PublicKeySize+1]
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (pub publicKey) TypedBytes() crpt.TypedPublicKey {
	return crpt.TypedPublicKey(pub)
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (pub sha3PublicKey) TypedBytes() crpt.TypedPublicKey {
	return crpt.TypedPublicKey(pub)
}

// Address returns TypedPublicKey instead of deriving address from the public key by hashing and
// returning the last certain bytes, to avoid adding extra space in transactions for public keys.
//
// Address's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub publicKey) Address() Address {
	return Address(pub)
}

// Address returns TypedPublicKey instead of deriving address from the public key by hashing and
// returning the last certain bytes, to avoid adding extra space in transactions for public keys.
//
// The returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub sha3PublicKey) Address() Address {
	return Address(pub)
}

func (priv privateKey) KeyType() crpt.KeyType {
	return crpt.Ed25519
}
func (priv sha3PrivateKey) KeyType() crpt.KeyType {
	return crpt.Ed25519_SHA3_512
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (priv privateKey) Bytes() []byte {
	return priv[1 : PrivateKeySize+1]
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (priv sha3PrivateKey) Bytes() []byte {
	return priv[1 : PrivateKeySize+1]
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (priv privateKey) TypedBytes() crpt.TypedPrivateKey {
	return crpt.TypedPrivateKey(priv)
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (priv sha3PrivateKey) TypedBytes() crpt.TypedPrivateKey {
	return crpt.TypedPrivateKey(priv)
}

func (priv privateKey) Public() crpt.PublicKey {
	pub, _ := publicKeyFromBytes(false, ed25519.PrivateKey(priv[1:PrivateKeySize+1]).Public().(ed25519.PublicKey))
	return pub
}
func (priv sha3PrivateKey) Public() crpt.PublicKey {
	pub, _ := publicKeyFromBytes(true, ed25519sha3.PrivateKey(priv[1:PrivateKeySize+1]).Public().(ed25519sha3.PublicKey))
	return pub
}

func (s signature) KeyType() crpt.KeyType {
	return crpt.Ed25519
}
func (s sha3Signature) KeyType() crpt.KeyType {
	return crpt.Ed25519_SHA3_512
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (s signature) Bytes() []byte {
	return s[1 : SignatureSize+1]
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (s sha3Signature) Bytes() []byte {
	return s[1 : SignatureSize+1]
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (s signature) TypedBytes() crpt.TypedSignature {
	return crpt.TypedSignature(s)
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (s sha3Signature) TypedBytes() crpt.TypedSignature {
	return crpt.TypedSignature(s)
}

// New creates a Ed225519 Crpt, if sha3 is true, it uses SHA3-512 hash function
// instead of normal SHA-512.
func New(sha3 bool, hash crypto.Hash) (*ed25519Crpt, error) {
	crypt := &ed25519Crpt{sha3: sha3}
	ktype := crpt.Ed25519
	if sha3 {
		ktype = crpt.Ed25519_SHA3_512
	}
	base, err := util.NewBaseCrpt(ktype, hash, false, crypt)
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

var _ crpt.Crpt = (*ed25519Crpt)(nil)

func (c *ed25519Crpt) PublicKeyFromBytes(pub []byte) (crpt.PublicKey, error) {
	return publicKeyFromBytes(c.sha3, pub)
}

func publicKeyFromBytes(sha3 bool, pub []byte) (crpt.PublicKey, error) {
	if len(pub) != PublicKeySize {
		return nil, ErrWrongPublicKeySize
	}

	k := make([]byte, PublicKeySize+1)
	if sha3 {
		k[0] = KeyTypeByte_SHA3_512
	} else {
		k[0] = KeyTypeByte
	}
	copy(k[1:PublicKeySize+1], pub)

	if sha3 {
		return sha3PublicKey(k), nil
	} else {
		return publicKey(k), nil
	}
}

func (c *ed25519Crpt) PublicKeyFromTypedBytes(pub crpt.TypedPublicKey) (crpt.PublicKey, error) {
	if len(pub) != PublicKeySize+1 {
		return nil, ErrWrongPublicKeySize
	}

	if c.sha3 {
		return sha3PublicKey(pub), nil
	} else {
		return publicKey(pub), nil
	}
}

func (c *ed25519Crpt) PrivateKeyFromBytes(priv []byte) (crpt.PrivateKey, error) {
	if len(priv) != PrivateKeySize {
		return nil, ErrWrongPrivateKeySize
	}

	k := make([]byte, PrivateKeySize+1)
	if c.sha3 {
		k[0] = KeyTypeByte_SHA3_512
	} else {
		k[0] = KeyTypeByte
	}
	copy(k[1:PrivateKeySize+1], priv)

	return c.PrivateKeyFromTypedBytes(k)
}

func (c *ed25519Crpt) PrivateKeyFromTypedBytes(priv crpt.TypedPrivateKey) (crpt.PrivateKey, error) {
	if len(priv) != PrivateKeySize+1 {
		return nil, ErrWrongPrivateKeySize
	}

	if c.sha3 {
		return sha3PrivateKey(priv), nil
	} else {
		return privateKey(priv), nil
	}
}

func (c *ed25519Crpt) SignatureFromBytes(sig []byte) (crpt.Signature, error) {
	if len(sig) != SignatureSize {
		return nil, ErrWrongSignatureSize
	}

	s := make([]byte, SignatureSize+1)
	if c.sha3 {
		s[0] = KeyTypeByte_SHA3_512
	} else {
		s[0] = KeyTypeByte
	}
	copy(s[1:SignatureSize+1], sig)

	return c.SignatureFromTypedBytes(s)
}

func (c *ed25519Crpt) SignatureFromTypedBytes(sig crpt.TypedSignature) (crpt.Signature, error) {
	if len(sig) != SignatureSize+1 {
		return nil, ErrWrongSignatureSize
	}

	if c.sha3 {
		return sha3Signature(sig), nil
	} else {
		return signature(sig), nil
	}
}

func (c *ed25519Crpt) GenerateKey(rand io.Reader,
) (cpub crpt.PublicKey, cpriv crpt.PrivateKey, err error) {
	var pub, priv []byte
	if c.sha3 {
		pub, priv, err = ed25519sha3.GenerateKey(rand)
	} else {
		pub, priv, err = ed25519.GenerateKey(rand)
	}
	if err == nil {
		cpub, err = c.PublicKeyFromBytes(pub)
	}
	if err == nil {
		cpriv, err = c.PrivateKeyFromBytes(priv)
	}
	return cpub, cpriv, err
}

func (c *ed25519Crpt) SignMessage(priv crpt.PrivateKey, message []byte, rand io.Reader,
) (crpt.Signature, error) {
	if c.sha3 {
		if edpriv, ok := priv.(sha3PrivateKey); ok {
			return c.SignatureFromBytes(ed25519sha3.Sign(ed25519sha3.PrivateKey(edpriv.Bytes()), message))
		} else {
			return nil, ErrNotEd25519SHA3PrivateKey
		}
	} else {
		if edpriv, ok := priv.(privateKey); ok {
			return c.SignatureFromBytes(ed25519.Sign(ed25519.PrivateKey(edpriv.Bytes()), message))
		} else {
			return nil, ErrNotEd25519PrivateKey
		}
	}
}

func (c *ed25519Crpt) SignDigest(priv crpt.PrivateKey, digest []byte, hashFunc crypto.Hash, rand io.Reader,
) (crpt.Signature, error) {
	panic("not supported: Ed25519 cannot handle pre-hashed messages, " +
		"see: https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign")
}

func (c *ed25519Crpt) Verify(pub crpt.PublicKey, message []byte, sig crpt.Signature,
) (bool, error) {
	if c.sha3 {
		if edpub, ok := pub.(sha3PublicKey); !ok {
			return false, ErrNotEd25519SHA3PublicKey
		} else if edsig, ok := sig.(sha3Signature); !ok {
			return false, ErrNotEd25519SHA3Signature
		} else {
			// This implementation has defined criteria (ZIP 215 w/ SHA3-512) for signature validity
			return ed25519consensus_sha3.Verify(edpub.Bytes(), message, edsig.Bytes()), nil
			//return ed25519sha3.Verify(ed25519sha3.PublicKey(edpub), message, sig), nil
		}
	} else {
		if edpub, ok := pub.(publicKey); !ok {
			return false, ErrNotEd25519PublicKey
		} else if edsig, ok := sig.(signature); !ok {
			return false, ErrNotEd25519Signature
		} else {
			// This implementation has defined criteria (ZIP 215) for signature validity
			return ed25519consensus.Verify(edpub.Bytes(), message, edsig.Bytes()), nil
			//return ed25519.Verify(ed25519.PublicKey(edpub), message, sig), nil
		}
	}
}
