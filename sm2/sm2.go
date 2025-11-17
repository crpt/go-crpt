// Copyright 2024 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package sm2 exposes an SM2 implementation backed by github.com/emmansun/gmsm.
package sm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	gsm2 "github.com/emmansun/gmsm/sm2"

	"github.com/crpt/go-crpt"
)

const (
	KeyType        = crpt.SM2
	PublicKeySize  = 65 // 0x04 || X || Y (32 bytes each)
	PrivateKeySize = 32
	AddressSize    = PublicKeySize

	minSignatureSize = 8
	maxSignatureSize = 72
)

// SignerOpts controls how SM2 operations are performed.
type SignerOpts struct {
	*gsm2.SM2SignerOption
	hash crpt.Hash
	uid  []byte
}

func NewSignerOpts(forceGMSign bool, uid []byte, hash crpt.Hash) *SignerOpts {
	return &SignerOpts{
		SM2SignerOption: gsm2.NewSM2SignerOption(forceGMSign, uid),
		hash:            hash,
		uid:             uid,
	}
}

// Type check
var _ crpt.SignerOptsExtended = (*SignerOpts)(nil)

// HashFunc implements crypto.SignerOpts.
func (o *SignerOpts) HashFunc() crpt.Hash {
	if o == nil {
		return crpt.NotHashed
	}
	return o.hash
}

// Clone creates a copy of the SignerOpts.
func (o *SignerOpts) Clone() crpt.SignerOptsExtended {
	if o == nil {
		return nil
	}
	// Only hash is modifyable, so shallow copy is enough
	copy := *o
	return &copy
}

// SetHash sets the hash function for the SignerOpts.
func (o *SignerOpts) SetHash(hash crpt.Hash) {
	if o != nil {
		o.hash = hash
	}
}

var (
	KeyTypeByte            = byte(KeyType)
	ErrWrongPublicKeySize  = fmt.Errorf("%w, should be %d bytes", crpt.ErrWrongPublicKeySize, PublicKeySize)
	ErrWrongPrivateKeySize = fmt.Errorf("%w, should be %d bytes", crpt.ErrWrongPrivateKeySize, PrivateKeySize)
	ErrInvalidSignature    = errors.New("sm2: invalid signature encoding")
	DefaultSignerOpts      = NewSignerOpts(true, nil, crpt.Hash(crypto.SHA256))
)

// Address matches the global crpt.Address alias for clarity.
type Address = crpt.Address

func init() {
	c, _ := New(nil)
	crpt.RegisterCrpt(KeyType, c)
}

// PublicKey wraps an uncompressed SM2 public key.
type PublicKey struct {
	*crpt.BasePublicKey
	raw      []byte
	ecdsaPub *ecdsa.PublicKey
}

// Type check
var _ crpt.PublicKey = (*PublicKey)(nil)

// NewPublicKey constructs a PublicKey from its uncompressed bytes.
func NewPublicKey(b []byte, opts crpt.SignerOpts) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, ErrWrongPublicKeySize
	}
	if opts == nil {
		return nil, errors.New("sm2: opts is nil")
	}
	so, ok := opts.(*SignerOpts)
	if !ok {
		return nil, errors.New("sm2: opts is not of type *SignerOpts")
	}
	ecdsaPub, err := gsm2.NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	raw := append([]byte(nil), b...)
	pub := &PublicKey{
		raw:      raw,
		ecdsaPub: ecdsaPub,
	}
	pub.BasePublicKey = &crpt.BasePublicKey{
		BaseKey: &crpt.BaseKey{
			Type:  KeyType,
			Sopts: so,
		},
		Parent: pub,
	}
	return pub, nil
}

// Equal runs in constant time over the compressed bytes.
func (pub PublicKey) Equal(o crpt.PublicKey) bool {
	other, ok := o.(*PublicKey)
	if !ok {
		return false
	}
	if len(pub.raw) != len(other.raw) {
		return false
	}
	return subtle.ConstantTimeCompare(pub.raw, other.raw) == 1
}

// Bytes returns the uncompressed public key bytes.
func (pub PublicKey) Bytes() []byte {
	return pub.raw
}

// Address returns the transaction address backing this key.
func (pub PublicKey) Address() Address {
	return pub.raw
}

func (pub PublicKey) VerifyMessage(message []byte, sig crpt.Signature, opts crpt.SignerOpts,
) (bool, error) {
	if err := validateSignature(sig); err != nil {
		if errors.Is(err, crpt.ErrWrongSignatureSize) || errors.Is(err, ErrInvalidSignature) {
			return false, nil
		}
		return false, err
	}

	if message == nil {
		message = []byte{}
	}
	baseSopts, _ := pub.SignerOpts().(*SignerOpts)
	so := crpt.ConvertSignerOpts(opts, baseSopts)
	digest, err := gsm2.CalculateSM2Hash(pub.ecdsaPub, message, so.uid)
	if err != nil {
		return false, err
	}
	return gsm2.VerifyASN1(pub.ecdsaPub, digest, sig), nil
}

func (pub PublicKey) VerifyDigest(digest []byte, sig crpt.Signature, opts crpt.SignerOpts,
) (bool, error) {
	if len(digest) == 0 {
		return false, crpt.ErrEmptyMessage
	}
	if err := validateSignature(sig); err != nil {
		if errors.Is(err, crpt.ErrWrongSignatureSize) || errors.Is(err, ErrInvalidSignature) {
			return false, nil
		}
		return false, err
	}

	baseSopts, _ := pub.SignerOpts().(*SignerOpts)
	so := crpt.ConvertSignerOpts(opts, baseSopts)
	if !so.hash.Available() {
		return false, crpt.ErrInvalidHashFunc
	}
	return gsm2.VerifyASN1(pub.ecdsaPub, digest, sig), nil
}

// PrivateKey wraps the gmsm private key implementation.
type PrivateKey struct {
	*crpt.BasePrivateKey
	priv *gsm2.PrivateKey
}

// Type check
var _ crpt.PrivateKey = (*PrivateKey)(nil)

// NewPrivateKey constructs a PrivateKey from raw scalar bytes.
func NewPrivateKey(b []byte, opts crpt.SignerOpts) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, ErrWrongPrivateKeySize
	}
	so := crpt.ConvertSignerOpts(opts, DefaultSignerOpts)
	priv, err := gsm2.NewPrivateKey(b)
	if err != nil {
		return nil, err
	}
	p := &PrivateKey{priv: priv}
	p.BasePrivateKey = &crpt.BasePrivateKey{
		BaseKey: &crpt.BaseKey{
			Type:  KeyType,
			Sopts: so,
		},
		Parent: p,
	}
	return p, nil
}

func (priv PrivateKey) Equal(o crpt.PrivateKey) bool {
	other, ok := o.(*PrivateKey)
	if !ok {
		return false
	}
	var selfBytes, otherBytes [PrivateKeySize]byte
	priv.priv.D.FillBytes(selfBytes[:])
	other.priv.D.FillBytes(otherBytes[:])
	return subtle.ConstantTimeCompare(selfBytes[:], otherBytes[:]) == 1
}

func (priv PrivateKey) Bytes() []byte {
	out := make([]byte, PrivateKeySize)
	priv.priv.D.FillBytes(out)
	return out
}

func (priv PrivateKey) Public() crpt.PublicKey {
	pubKey := priv.priv.PublicKey
	raw := elliptic.Marshal(pubKey.Curve, priv.priv.PublicKey.X, priv.priv.PublicKey.Y)
	pub := &PublicKey{
		raw:      raw,
		ecdsaPub: &pubKey,
	}
	pub.BasePublicKey = &crpt.BasePublicKey{
		BaseKey: &crpt.BaseKey{
			Type:  KeyType,
			Sopts: priv.SignerOpts(),
		},
		Parent: pub,
	}
	return pub
}

func (priv PrivateKey) SignMessage(message []byte, rand io.Reader, opts crpt.SignerOpts,
) (crpt.Signature, error) {
	if message == nil {
		message = []byte{}
	}
	if rand == nil {
		rand = crand.Reader
	}
	baseSopts, _ := priv.SignerOpts().(*SignerOpts)
	so := crpt.ConvertSignerOpts(opts, baseSopts)
	gmOpts := so.SM2SignerOption
	if gmOpts == nil {
		gmOpts = gsm2.NewSM2SignerOption(true, so.uid)
	}
	sig, err := priv.priv.Sign(rand, message, gmOpts)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (priv PrivateKey) SignDigest(digest []byte, rand io.Reader, opts crpt.SignerOpts,
) (crpt.Signature, error) {
	if len(digest) == 0 {
		return nil, crpt.ErrEmptyMessage
	}
	if rand == nil {
		rand = crand.Reader
	}
	baseSopts, _ := priv.SignerOpts().(*SignerOpts)
	so := crpt.ConvertSignerOpts(opts, baseSopts)
	// Alwasy set forceGMSign=false for SignDigest
	gmOpts := gsm2.NewSM2SignerOption(false, so.uid)
	sig, err := priv.priv.Sign(rand, digest, gmOpts)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// New creates an SM2 Crpt instance with optional signer options.
type sm2Crpt struct {
	*crpt.BaseCrpt
}

// Type check
var _ crpt.Crpt = (*sm2Crpt)(nil)

// New creates an SM2 Crpt with the provided default signer options.
func New(opts *SignerOpts) (*sm2Crpt, error) {
	if opts == nil {
		opts = DefaultSignerOpts
	}
	crypt := &sm2Crpt{}
	base, err := crpt.NewBaseCrpt(KeyType, opts, crypt)
	if err != nil {
		return nil, err
	}
	crypt.BaseCrpt = base
	return crypt, nil
}

// NewWithCryptoSignerOpts creates an SM2 Crpt from generic crypto.SignerOpts.
func NewWithCryptoSignerOpts(opts crpt.SignerOpts) (*sm2Crpt, error) {
	so := crpt.ConvertSignerOpts(opts, DefaultSignerOpts)
	return New(so)
}

func (c *sm2Crpt) PublicKeyFromBytes(pub []byte) (crpt.PublicKey, error) {
	return NewPublicKey(pub, c.SignerOpts())
}

func (c *sm2Crpt) PrivateKeyFromBytes(priv []byte) (crpt.PrivateKey, error) {
	return NewPrivateKey(priv, c.SignerOpts())
}

func (c *sm2Crpt) SignatureToASN1(sig crpt.Signature) ([]byte, error) {
	if err := validateSignature(sig); err != nil {
		return nil, err
	}
	out := make([]byte, len(sig))
	copy(out, sig)
	return out, nil
}

func (c *sm2Crpt) SignatureToTyped(sig crpt.Signature) (crpt.TypedSignature, error) {
	if err := validateSignature(sig); err != nil {
		return nil, err
	}
	ts := make([]byte, len(sig)+1)
	ts[0] = KeyTypeByte
	copy(ts[1:], sig)
	return ts, nil
}

func (c *sm2Crpt) GenerateKey(rand io.Reader,
) (crpt.PublicKey, crpt.PrivateKey, error) {
	if rand == nil {
		rand = crand.Reader
	}
	priv, err := gsm2.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	privBytes := make([]byte, PrivateKeySize)
	priv.D.FillBytes(privBytes)

	cpriv, err := c.PrivateKeyFromBytes(privBytes)
	if err != nil {
		return nil, nil, err
	}

	return cpriv.Public(), cpriv, nil
}

func (c *sm2Crpt) NewBatchVerifier(opts crpt.SignerOpts) (crpt.BatchVerifier, error) {
	return nil, crpt.ErrUnimplemented
}

// asn1Signature mirrors the DER structure for SM2 signatures.
type asn1Signature struct {
	R, S *big.Int
}

func validateSignature(sig []byte) error {
	if l := len(sig); l < minSignatureSize || l > maxSignatureSize {
		return crpt.ErrWrongSignatureSize
	}
	var asn asn1Signature
	if _, err := asn1.Unmarshal(sig, &asn); err != nil {
		return ErrInvalidSignature
	}
	if asn.R == nil || asn.S == nil || asn.R.Sign() <= 0 || asn.S.Sign() <= 0 {
		return ErrInvalidSignature
	}
	return nil
}
