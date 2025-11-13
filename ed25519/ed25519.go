// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package ed25519 provides an Ed25519 implementation backed by [crypto/ed25519](https://pkg.go.dev/crypto/ed25519) std package,
// but using [ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) package for signature verification,
// which conforms to [ZIP 215](https://zips.z.cash/zip-0215) specification, making it suitable for consensus-critical contexts,
// see [README from ed25519consensus](https://github.com/hdevalence/ed25519consensus) for the explanation.
package ed25519

import (
	"crypto"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	gerr "github.com/daotl/guts/error"
	ved25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519/extra/cache"

	"github.com/crpt/go-crpt"
)

type SignerOpts = ved25519.Options

// Type check
var _ crypto.SignerOpts = (*SignerOpts)(nil)

const (
	KeyType = crpt.Ed25519
	// 32 bytes
	PublicKeySize = ved25519.PublicKeySize
	// 64 bytes
	PrivateKeySize = ved25519.PrivateKeySize
	// 64 bytes (The size of a compressed, Edwards25519 point, and a field element. Both of which are 32 bytes.)
	SignatureSize = ved25519.SignatureSize
	// 32 bytes private key seeds. (These are the private key representations used by RFC 8032.)
	SeedSize = 32
	// 64 bytes
	AddressSize = PublicKeySize

	DefaultContext         = ""
	DefaultAddedRandomness = false

	// cacheSize is the number of public keys that will be cached in
	// an expanded format for repeated signature verification.
	//
	// TODO/perf: Either this should exclude single verification, or be
	// tuned to `> validatorSize + maxTxnsPerBlock` to avoid cache
	// thrashing.
	cacheSize = 4096
)

var (
	DefaultVerfiyOpts = ved25519.VerifyOptionsZIP_215
	DefaultSignerOpts = &SignerOpts{
		Hash:            crypto.SHA512,
		Context:         DefaultContext,
		AddedRandomness: DefaultAddedRandomness,
		Verify:          DefaultVerfiyOpts,
	}
)

func init() {
	c, _ := New(nil)
	crpt.RegisterCrpt(KeyType, c)
}

var cachingVerifier = cache.NewVerifier(cache.NewLRUCache(cacheSize))

var (
	KeyTypeByte = byte(KeyType)

	ErrWrongPublicKeySize   = fmt.Errorf("%w, should be 32 bytes", crpt.ErrWrongPublicKeySize)
	ErrWrongPrivateKeySize  = fmt.Errorf("%w, should be 64 bytes", crpt.ErrWrongPrivateKeySize)
	ErrWrongSignatureSize   = fmt.Errorf("%w, should be 64 bytes", crpt.ErrWrongSignatureSize)
	ErrNotEd25519PublicKey  = errors.New("not a Ed25519 public key")
	ErrNotEd25519PrivateKey = errors.New("not a Ed25519 private key")
)

// ConvertSignerOpts convert crypto.SignerOpts to SignerOpts, falling back to defaultOpts
func ConvertSignerOpts(opts crypto.SignerOpts, defaultOpts SignerOpts) *SignerOpts {
	if opts == nil {
		return &defaultOpts
	}

	// If opts is provided and is *SignerOpts, use it; otherwise only use opts.HashFunc()
	if o, ok := opts.(*SignerOpts); ok {
		// Copy to avoid modifying the original
		sops := *o
		return &sops
	} else {
		defaultOpts.Hash = opts.HashFunc()
		return &defaultOpts
	}
}

// Ed25519 32-byte public key
type PublicKey struct {
	*crpt.BasePublicKey
	vpub ved25519.PublicKey
}

// Type check
var _ crpt.PublicKey = (*PublicKey)(nil)

// NewPublicKey from bytes
func NewPublicKey(b []byte, opts crypto.SignerOpts) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, ErrWrongPublicKeySize
	}
	sops := ConvertSignerOpts(opts, *DefaultSignerOpts)
	pub := &PublicKey{
		vpub: b,
	}
	pub.BasePublicKey = &crpt.BasePublicKey{
		BaseKey: &crpt.BaseKey{
			Type: KeyType,
			Sops: sops,
		},
		Parent: pub,
	}
	return pub, nil
}

// Ed25519 32-byte private key + 32-byte public key suffix = 64 bytes
// See: https://pkg.go.dev/crypto/ed25519
type PrivateKey struct {
	*crpt.BasePrivateKey
	vpriv ved25519.PrivateKey
}

// Type check
var _ crpt.PrivateKey = (*PrivateKey)(nil)

// NewPrivateKey from bytes
func NewPrivateKey(b []byte, opts crypto.SignerOpts) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, ErrWrongPrivateKeySize
	}
	sops := ConvertSignerOpts(opts, *DefaultSignerOpts)
	priv := &PrivateKey{
		vpriv: b,
	}
	priv.BasePrivateKey = &crpt.BasePrivateKey{
		BaseKey: &crpt.BaseKey{
			Type: KeyType,
			Sops: sops,
		},
		Parent: priv,
	}
	return priv, nil
}

// Ed25519 33-byte address (the same as Typed[PublicKey])
type Address = crpt.Address

// Runs in constant time based on length of the keys to prevent time attacks.
func (pub PublicKey) Equal(o crpt.PublicKey) bool {
	if oed, ok := o.(*PublicKey); !ok {
		return false
	} else {
		return subtle.ConstantTimeCompare(pub.vpub, oed.vpub) == 1
	}
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub PublicKey) Bytes() []byte {
	return pub.vpub
}

// Address returns Typed[PublicKey] instead of deriving address from the public key by hashing and
// returning the last certain bytes, to avoid adding extra space in transactions for public keys.
//
// Address's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub PublicKey) Address() Address {
	return Address(pub.vpub)
}

func (pub PublicKey) VerifyMessage(message []byte, sig crpt.Signature, opts crypto.SignerOpts,
) (ok bool, err error) {
	if len(sig) != SignatureSize {
		return false, nil
	}

	sops := ConvertSignerOpts(opts, *pub.SignerOpts().(*SignerOpts))
	// Alwasy use crpt.NotHashed for SignMessage
	sops.Hash = crpt.NotHashed

	defer func() {
		if r := recover(); r != nil {
			ok = false
			err = gerr.ToError(r)
		}
	}()
	return cachingVerifier.VerifyWithOptions(pub.vpub, message, sig, sops), nil
}

func (pub PublicKey) VerifyDigest(digest []byte, sig crpt.Signature, opts crypto.SignerOpts,
) (ok bool, err error) {
	if len(sig) != SignatureSize {
		return false, nil
	}

	sops := ConvertSignerOpts(opts, *pub.SignerOpts().(*SignerOpts))

	defer func() {
		if r := recover(); r != nil {
			ok = false
			err = gerr.ToError(r)
		}
	}()
	return cachingVerifier.VerifyWithOptions(pub.vpub, digest, sig, sops), nil
}

func (priv PrivateKey) Equal(o crpt.PrivateKey) bool {
	if oed, ok := o.(*PrivateKey); !ok {
		return false
	} else {
		return subtle.ConstantTimeCompare(priv.vpriv, oed.vpriv) == 1
	}
}

// Bytes's returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (priv PrivateKey) Bytes() []byte {
	return priv.vpriv
}

// Panics if the private key is not initialized.
func (priv PrivateKey) Public() crpt.PublicKey {
	// If the latter 32 bytes of `priv` are all zero, `priv` is not initialized.
	initialized := false
	for _, v := range priv.vpriv[32:] {
		if v != 0 {
			initialized = true
			break
		}
	}

	if !initialized {
		panic("Expected ed25519 PrivateKey to include concatenated PublicKey bytes")
	}

	pub, err := NewPublicKey(priv.vpriv.Public().(ved25519.PublicKey), priv.SignerOpts())
	// Should never happens
	if err != nil {
		panic(err)
	}
	return pub
}

func (priv PrivateKey) SignMessage(message []byte, rand io.Reader, opts crypto.SignerOpts) (crpt.Signature, error) {
	// If opts is provided and is *SignerOpts, use it; otherwise use the default
	sops := ConvertSignerOpts(opts, *priv.SignerOpts().(*SignerOpts))
	// Alwasy use crpt.NotHashed for SignMessage
	sops.Hash = crpt.NotHashed
	return priv.vpriv.Sign(rand, message, sops)
}

func (priv PrivateKey) SignDigest(digest []byte, rand io.Reader, opts crypto.SignerOpts,
) (crpt.Signature, error) {
	sops := ConvertSignerOpts(opts, *priv.SignerOpts().(*SignerOpts))
	if !sops.Hash.Available() {
		return nil, crpt.ErrInvalidHashFunc
	}
	return priv.vpriv.Sign(rand, digest, sops)
}

// New creates an Ed225519 Crpt.
func New(opts *SignerOpts) (*ed25519Crpt, error) {
	sops := opts
	if opts == nil {
		sops = DefaultSignerOpts
	}
	crypt := &ed25519Crpt{}
	base, err := crpt.NewBaseCrpt(KeyType, sops, crypt)
	if err != nil {
		return nil, err
	}
	crypt.BaseCrpt = base
	return crypt, nil
}

// New creates an Ed225519 Crpt with crypto.SignerOpts.
func NewWithCryptoSignerOpts(opts crypto.SignerOpts) (*ed25519Crpt, error) {
	sops := ConvertSignerOpts(opts, *DefaultSignerOpts)
	return New(sops)
}

type ed25519Crpt struct {
	*crpt.BaseCrpt
}

var _ crpt.Crpt = (*ed25519Crpt)(nil)

func (c *ed25519Crpt) PublicKeyFromBytes(pub []byte) (crpt.PublicKey, error) {
	return NewPublicKey(pub, c.SignerOpts())
}

func (c *ed25519Crpt) PrivateKeyFromBytes(priv []byte) (crpt.PrivateKey, error) {
	return NewPrivateKey(priv, c.SignerOpts())
}

// SignatureToASN1 converts an Ed25519 signature to ASN.1 DER encoding.
// For Ed25519, this encodes the 64-byte signature as an OCTET STRING.
func (c *ed25519Crpt) SignatureToASN1(sig crpt.Signature) ([]byte, error) {
	if len(sig) != SignatureSize {
		return nil, ErrWrongSignatureSize
	}
	// Ed25519 signatures are encoded as OCTET STRING in ASN.1
	return asn1.Marshal(sig)
}

// SignatureToTyped's returned byte slice is not safe to modify because it returns the underlying
// byte slice directly for the performance reason. Copy it if you need to modify.
func (c *ed25519Crpt) SignatureToTyped(sig crpt.Signature) (crpt.TypedSignature, error) {
	if len(sig) != SignatureSize {
		return nil, ErrWrongSignatureSize
	}
	ts := make([]byte, SignatureSize+1)
	ts[0] = KeyTypeByte
	copy(ts[1:], sig)
	return ts, nil
}

func (c *ed25519Crpt) GenerateKey(rand io.Reader,
) (cpub crpt.PublicKey, cpriv crpt.PrivateKey, err error) {
	var pub, priv []byte
	pub, priv, err = ved25519.GenerateKey(rand)
	if err == nil {
		cpub, err = c.PublicKeyFromBytes(pub)
	}
	if err == nil {
		cpriv, err = c.PrivateKeyFromBytes(priv)
	}
	return cpub, cpriv, err
}

// NewBatchVerifier creates a new batch verifier for Ed25519 with the given options.
func (c *ed25519Crpt) NewBatchVerifier(opts crypto.SignerOpts) (crpt.BatchVerifier, error) {
	sops := ConvertSignerOpts(opts, *c.SignerOpts().(*SignerOpts))
	return NewBatchVerifier(sops), nil
}

/* Batch */

// BatchVerifier implements batch verification for ed25519.
type BatchVerifier struct {
	*ved25519.BatchVerifier

	// Default signer options
	sops *SignerOpts
}

// NewBatchVerifier create a crpt.BatchVerifier
func NewBatchVerifier(opts *SignerOpts) crpt.BatchVerifier {
	sops := opts
	if opts == nil {
		sops = DefaultSignerOpts
	}
	return &BatchVerifier{
		BatchVerifier: ved25519.NewBatchVerifier(),
		sops:          sops,
	}
}

// NewBatchVerifierWithCryptoSignerOpts create a crpt.BatchVerifier from cryptoo.SignerOpts
func NewBatchVerifierWithCryptoSignerOpts(opts crypto.SignerOpts) crpt.BatchVerifier {
	sops := ConvertSignerOpts(opts, *DefaultSignerOpts)
	return NewBatchVerifier(sops)
}

func (b *BatchVerifier) Add(pub crpt.PublicKey, message, digest []byte, sig crpt.Signature, opts crypto.SignerOpts) error {
	edpub, ok := pub.(*PublicKey)
	if !ok {
		return ErrNotEd25519PublicKey
	}

	if l := len(edpub.vpub); l != PublicKeySize {
		return fmt.Errorf("%v; expected: %d, got %d", crpt.ErrWrongPublicKeySize, PublicKeySize, l)
	}

	// check that the signature is the correct length
	if len(sig) != SignatureSize {
		return crpt.ErrWrongSignatureSize
	}

	// Fall back to b.sops
	sops := ConvertSignerOpts(opts, *b.sops)
	m := message
	if digest != nil && opts != nil && opts.HashFunc().Available() {
		m = digest
	} else if message != nil {
		sops.Hash = crpt.NotHashed
	} else {
		return crpt.ErrEmptyMessage
	}

	cachingVerifier.AddWithOptions(b.BatchVerifier, edpub.vpub, m, sig, sops)
	return nil
}

func (b *BatchVerifier) Verify(rand io.Reader) (bool, []bool) {
	return b.BatchVerifier.Verify(rand)
}
