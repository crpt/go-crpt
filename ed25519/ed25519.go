// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package ed25519 provides an Ed25519 implementation backed by [crypto/ed25519](https://pkg.go.dev/crypto/ed25519) std package,
// but using [ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) package for signature verification,
// which conforms to [ZIP 215](https://zips.z.cash/zip-0215) specification, making it suitable for consensus-critical contexts,
// see [README from ed25519consensus](https://github.com/hdevalence/ed25519consensus) for the explanation.
package ed25519

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	gerr "github.com/daotl/guts/error"
	ved25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"

	"github.com/crpt/go-crpt"
)

func init() {
	c, _ := New(0)
	crpt.RegisterCrpt(crpt.Ed25519, c)
}

var (
	optContext         = ""
	optAddedRandomness = false
	optVerfiy          = ved25519.VerifyOptionsFIPS_186_5
	notHashedOpts      = &ved25519.Options{
		Hash:            crpt.NotHashed,
		Context:         optContext,
		AddedRandomness: optAddedRandomness,
		Verify:          optVerfiy,
	}
)

// SetEd25519Options sets the Ed25519 options used by this package.
//
// See `github.com/oasisprotocol/curve25519-voi/primitives/ed25519.Options` for parameter details.
func SetEd25519Options(context string, addedRandomness bool, verify *ved25519.VerifyOptions) {
	optContext = context
	optAddedRandomness = addedRandomness
	optVerfiy = verify
	notHashedOpts = &ved25519.Options{
		Hash:            crpt.NotHashed,
		Context:         optContext,
		AddedRandomness: optAddedRandomness,
		Verify:          optVerfiy,
	}
}

const (
	// 32
	PublicKeySize = ved25519.PublicKeySize
	// 64
	PrivateKeySize = ved25519.PrivateKeySize
	// 64
	SignatureSize = ved25519.SignatureSize
	// 64
	AddressSize = PublicKeySize
)

var (
	KeyTypeByte = byte(crpt.Ed25519)

	ErrWrongPublicKeySize   = fmt.Errorf("%w, should be 32 bytes", crpt.ErrWrongPublicKeySize)
	ErrWrongPrivateKeySize  = fmt.Errorf("%w, should be 64 bytes", crpt.ErrWrongPrivateKeySize)
	ErrWrongSignatureSize   = fmt.Errorf("%w, should be 64 bytes", crpt.ErrWrongSignatureSize)
	ErrNotEd25519PublicKey  = errors.New("not a Ed25519 public key")
	ErrNotEd25519PrivateKey = errors.New("not a Ed25519 private key")
)

// Ed25519 32-byte public key
type publicKey ved25519.PublicKey

// Ed25519 32-byte private key + 32-byte public key suffix = 64 bytes
// See: https://pkg.go.dev/crypto/ed25519
type privateKey ved25519.PrivateKey

// Ed25519 33-byte address (the same as TypedPublicKey)
type Address = crpt.Address

func (pub publicKey) KeyType() crpt.KeyType {
	return crpt.Ed25519
}

func (pub publicKey) Equal(o crpt.PublicKey) bool {
	return bytes.Compare(pub, o.Bytes()) == 0
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub publicKey) Bytes() []byte {
	return pub
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (pub publicKey) TypedBytes() crpt.TypedPublicKey {
	k := make([]byte, PublicKeySize+1)
	k[0] = KeyTypeByte
	copy(k[1:PublicKeySize+1], pub)
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

func (pub publicKey) Verify(message, digest []byte, hashFunc crypto.Hash, sig crpt.Signature,
) (bool, error) {
	if digest != nil && hashFunc.Available() {
		return pub.VerifyDigest(digest, hashFunc, sig)
	} else if message != nil {
		return pub.VerifyMessage(message, sig)
	} else {
		return false, crpt.ErrEmptyMessage
	}
}

func (pub publicKey) VerifyMessage(message []byte, sig crpt.Signature) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
			err = gerr.ToError(r)
		}
	}()
	return ved25519.VerifyWithOptions(ved25519.PublicKey(pub), message, sig, notHashedOpts), nil
}

func (pub publicKey) VerifyDigest(digest []byte, hashFunc crypto.Hash, sig crpt.Signature,
) (ok bool, err error) {
	if !hashFunc.Available() {
		return false, crpt.ErrInvalidHashFunc
	}

	defer func() {
		if r := recover(); r != nil {
			ok = false
			err = gerr.ToError(r)
		}
	}()
	return ved25519.VerifyWithOptions(ved25519.PublicKey(pub), digest, sig, &ved25519.Options{
		Hash:            hashFunc,
		Context:         optContext,
		AddedRandomness: optAddedRandomness,
		Verify:          optVerfiy,
	}), nil
}

func (priv privateKey) KeyType() crpt.KeyType {
	return crpt.Ed25519
}

func (priv privateKey) Equal(o crpt.PrivateKey) bool {
	return bytes.Compare(priv, o.Bytes()) == 0
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (priv privateKey) Bytes() []byte {
	return priv
}

// TypedBytes's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (priv privateKey) TypedBytes() crpt.TypedPrivateKey {
	k := make([]byte, PrivateKeySize+1)
	k[0] = KeyTypeByte
	copy(k[1:PrivateKeySize+1], priv)
	return crpt.TypedPrivateKey(priv)
}

func (priv privateKey) Public() crpt.PublicKey {
	pub, _ := publicKeyFromBytes(ved25519.PrivateKey(priv).Public().(ved25519.PublicKey))
	return pub
}

func (priv privateKey) Sign(message, digest []byte, hashFunc crypto.Hash, rand io.Reader,
) (crpt.Signature, error) {
	if digest != nil && hashFunc.Available() {
		return priv.SignDigest(digest, hashFunc, rand)
	} else if message != nil {
		return priv.SignMessage(message, rand)
	} else {
		return nil, crpt.ErrEmptyMessage
	}
}

func (priv privateKey) SignMessage(message []byte, rand io.Reader) (crpt.Signature, error) {
	return ved25519.PrivateKey(priv).Sign(rand, message, notHashedOpts)
}

func (priv privateKey) SignDigest(digest []byte, hashFunc crypto.Hash, rand io.Reader,
) (crpt.Signature, error) {
	if !hashFunc.Available() {
		return nil, crpt.ErrInvalidHashFunc
	}

	return ved25519.PrivateKey(priv).Sign(rand, digest, &ved25519.Options{
		Hash:            hashFunc,
		Context:         optContext,
		AddedRandomness: optAddedRandomness,
		Verify:          optVerfiy,
	})
}

// New creates an Ed225519 Crpt.
func New(hash crypto.Hash) (*ed25519Crpt, error) {
	crypt := &ed25519Crpt{}
	ktype := crpt.Ed25519
	base, err := crpt.NewBaseCrpt(ktype, hash, false, crypt)
	if err != nil {
		return nil, err
	}
	crypt.BaseCrpt = base
	return crypt, nil
}

type ed25519Crpt struct {
	*crpt.BaseCrpt
}

var _ crpt.Crpt = (*ed25519Crpt)(nil)

func (c *ed25519Crpt) PublicKeyFromBytes(pub []byte) (crpt.PublicKey, error) {
	return publicKeyFromBytes(pub)
}

func publicKeyFromBytes(pub []byte) (crpt.PublicKey, error) {
	if len(pub) != PublicKeySize {
		return nil, ErrWrongPublicKeySize
	}
	return publicKey(pub), nil
}

func (c *ed25519Crpt) PrivateKeyFromBytes(priv []byte) (crpt.PrivateKey, error) {
	if len(priv) != PrivateKeySize {
		return nil, ErrWrongPrivateKeySize
	}
	return privateKey(priv), nil
}

// SignatureToTyped's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (c *ed25519Crpt) SignatureToTyped(sig crpt.Signature) (crpt.TypedSignature, error) {
	if len(sig) != SignatureSize {
		return nil, ErrWrongSignatureSize
	}
	ts := make([]byte, SignatureSize+1)
	ts[0] = KeyTypeByte
	copy(ts[1:], ts)
	return ts, nil
}

func (c *ed25519Crpt) GenerateKey(rand io.Reader,
) (cpub crpt.PublicKey, cpriv crpt.PrivateKey, err error) {
	var pub, priv []byte
	pub, priv, err = ed25519.GenerateKey(rand)
	if err == nil {
		cpub, err = c.PublicKeyFromBytes(pub)
	}
	if err == nil {
		cpriv, err = c.PrivateKeyFromBytes(priv)
	}
	return cpub, cpriv, err
}

func (c *ed25519Crpt) Sign(
	priv crpt.PrivateKey, message, digest []byte, hashFunc crypto.Hash, rand io.Reader,
) (crpt.Signature, error) {
	if edpriv, ok := priv.(privateKey); !ok {
		return nil, ErrNotEd25519PrivateKey
	} else {
		return edpriv.Sign(message, digest, hashFunc, rand)
	}
}

func (c *ed25519Crpt) SignMessage(priv crpt.PrivateKey, message []byte, rand io.Reader,
) (crpt.Signature, error) {
	if edpriv, ok := priv.(privateKey); !ok {
		return nil, ErrNotEd25519PrivateKey
	} else {
		return edpriv.SignMessage(message, rand)
	}
}

func (c *ed25519Crpt) SignDigest(priv crpt.PrivateKey, digest []byte, hashFunc crypto.Hash, rand io.Reader,
) (crpt.Signature, error) {
	if edpriv, ok := priv.(privateKey); !ok {
		return nil, ErrNotEd25519PrivateKey
	} else {
		return edpriv.SignDigest(digest, hashFunc, rand)
	}
}

func (c *ed25519Crpt) Verify(
	pub crpt.PublicKey, message, digest []byte, hashFunc crypto.Hash, sig crpt.Signature,
) (bool, error) {
	if edpub, ok := pub.(publicKey); !ok {
		return false, ErrNotEd25519PublicKey
	} else {
		return edpub.Verify(message, digest, hashFunc, sig)
	}
}

func (c *ed25519Crpt) VerifyMessage(pub crpt.PublicKey, message []byte, sig crpt.Signature,
) (bool, error) {
	if edpub, ok := pub.(publicKey); !ok {
		return false, ErrNotEd25519PublicKey
	} else {
		return edpub.VerifyMessage(message, sig)
	}
}

func (c *ed25519Crpt) VerifyDigest(
	pub crpt.PublicKey, digest []byte, hashFunc crypto.Hash, sig crpt.Signature,
) (bool, error) {
	if edpub, ok := pub.(publicKey); !ok {
		return false, ErrNotEd25519PublicKey
	} else {
		return edpub.VerifyDigest(digest, hashFunc, sig)
	}
}
