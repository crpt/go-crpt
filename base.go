// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crpt

import (
	"crypto"
	"errors"
	"hash"
	"io"

	"github.com/crpt/go-merkle"
)

type BaseKey struct {
	Type  KeyType
	Sopts SignerOpts
}

// KeyType returns the key type.
func (k BaseKey) KeyType() KeyType {
	return k.Type
}

// SignerOpts reports the default SignerOpts use by this key.
func (k BaseKey) SignerOpts() SignerOpts {
	return k.Sopts
}

// BasePublicKey is a helper struct meant to be anonymously embedded by pointer in all
// PublicKey implementations.
type BasePublicKey struct {
	*BaseKey
	// Parent is the concrete PublicKey which is embedding this BasePublicKey instance.
	Parent PublicKey
}

// ToTyped returns the typed bytes representation of the public key.
func (pub BasePublicKey) ToTyped() Typed[PublicKey] {
	return ToTyped(pub.Parent, pub.KeyType())
}

// Verify reports whether `sig` is a valid signature of message or digest by the public key.
func (pub BasePublicKey) Verify(message, digest []byte, sig Signature, opts SignerOpts) (bool, error) {
	if digest != nil && opts != nil && opts.HashFunc() != NotHashed {
		return pub.Parent.VerifyDigest(digest, sig, opts)
	} else if message != nil {
		return pub.Parent.VerifyMessage(message, sig, opts)
	} else {
		return false, ErrEmptyMessage
	}
}

// BasePrivateKey is a helper struct meant to be anonymously embedded by pointer in all
// PrivateKey implementations.
type BasePrivateKey struct {
	*BaseKey
	// Parent is the concrete PublicKey which is embedding this BasePublicKey instance.
	Parent PrivateKey
}

// ToTyped returns the typed bytes representation of the private key.
func (priv BasePrivateKey) ToTyped() Typed[PrivateKey] {
	return ToTyped(priv.Parent, priv.KeyType())
}

// Sign produces a signature on the provided message.
func (priv BasePrivateKey) Sign(message, digest []byte, rand io.Reader, opts SignerOpts,
) (Signature, error) {
	if len(digest) > 0 {
		if !(opts != nil && opts.HashFunc().Available()) {
			return nil, ErrInvalidHashFunc
		} else {
			return priv.Parent.SignDigest(digest, rand, opts)
		}
	} else if len(message) > 0 {
		return priv.Parent.SignMessage(message, rand, opts)
	} else {
		return nil, ErrEmptyMessage
	}
}

// BaseCrpt is a helper struct meant to be anonymously embedded by pointer in all
// Crpt implementations.
type BaseCrpt struct {
	// KeyType used for embedding crpt.Crpt instance
	keyType KeyType

	// sopts holds the default signer options to be used for Crpt.Hash and other operations.
	sopts SignerOpts

	// hashFuncByte := byte(defaultSignerOpts.HashFunc())
	hashFuncByte byte

	// parent is the concrete crpt.Crpt instance which is embedding this BaseCrpt instance.
	parent Crpt
}

var ErrParentIsNil = errors.New("implementations should always pass parent Crpt")

// NewBaseCrpt returns a BaseCrpt.
//
// t: KeyType used for embedding crpt.Crpt instance
// opts: holds the default signer options to be used for Crpt.Hash and other operations.
// parent: the concrete crpt.Crpt instance which is embedding this BaseCrpt instance.
func NewBaseCrpt(t KeyType, opts SignerOpts, parent Crpt) (*BaseCrpt, error) {
	var hashFunc Hash
	if opts != nil {
		hashFunc = opts.HashFunc()
		if hashFunc != 0 && !hashFunc.Available() {
			return nil, ErrInvalidHashFunc
		}
	}
	if parent == nil {
		return nil, ErrParentIsNil
	}
	return &BaseCrpt{
		keyType:      t,
		sopts:        opts,
		hashFuncByte: byte(hashFunc),
		parent:       parent,
	}, nil
}

func (c *BaseCrpt) checkHashFunc() Hash {
	if c.sopts == nil || !c.sopts.HashFunc().Available() {
		panic("crpt: hash function is not set")
	}
	return c.sopts.HashFunc()
}

// KeyType implements crpt.KeyType.
func (c *BaseCrpt) KeyType() KeyType {
	return c.keyType
}

// HashFunc implements crpt.SignerOpts.
func (c *BaseCrpt) SignerOpts() SignerOpts {
	return c.sopts
}

// HashFunc implements crpt.HashFunc.
func (c *BaseCrpt) HashFunc() Hash {
	if c.sopts == nil {
		return 0
	}
	return c.sopts.HashFunc()
}

// Hash implements Crpt.Hash using BaseCrpt.defaultSignerOpts.
func (c *BaseCrpt) Hash(b []byte) HashValue {
	h := c.checkHashFunc().HashFunc().New()
	h.Write(b)
	return h.Sum(nil)
}

// HashTyped implements Crpt.HashTyped using BaseCrpt.defaultSignerOpts.
func (c *BaseCrpt) HashTyped(b []byte) TypedHashValue {
	h := c.checkHashFunc().New()
	h.Write(b)
	s := h.Sum(nil)
	s[0] = c.hashFuncByte
	return s
}

// SumHashTyped implements crpt.SumHashTyped.
func (c *BaseCrpt) SumHashTyped(h hash.Hash, b []byte) []byte {
	s := h.Sum(b)
	s[len(b)] = c.hashFuncByte
	return s
}

// HashValueToTyped decorates a hash into a TypedHash.
func (c *BaseCrpt) HashValueToTyped(h HashValue) TypedHashValue {
	ht := make([]byte, len(h))
	ht[0] = c.hashFuncByte
	copy(ht[1:], h[1:])
	return ht
}

// Sign implements Crpt.MerkleHashFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleHashFromByteSlices(items [][]byte) (rootHash []byte) {
	h := c.checkHashFunc()
	return merkle.HashFromByteSlicesIterative(crypto.Hash(h), items)
}

// Sign implements Crpt.MerkleHashTypedFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleHashTypedFromByteSlices(items [][]byte) (rootHash TypedHashValue) {
	h := c.checkHashFunc()
	rootHash = merkle.HashFromByteSlicesIterative(crypto.Hash(h), items)
	rootHash[0] = byte(h)
	return rootHash
}

// Sign implements Crpt.MerkleProofsFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleProofsFromByteSlices(items [][]byte,
) (rootHash []byte, proofs []*merkle.Proof) {
	h := c.checkHashFunc()
	return merkle.ProofsFromByteSlices(crypto.Hash(h), items)
}

// Sign implements Crpt.MerkleProofsTypedFromByteSlices using `crpt/go-merkle`.
func (c *BaseCrpt) MerkleProofsTypedFromByteSlices(items [][]byte,
) (rootHash TypedHashValue, proofs []*merkle.Proof) {
	h := c.checkHashFunc()
	rootHash, proofs = merkle.ProofsFromByteSlices(crypto.Hash(h), items)
	rootHash[0] = byte(h)
	return rootHash, proofs
}
