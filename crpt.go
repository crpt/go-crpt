// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package crpt provides interface for common crypto operations.
package crpt

import (
	"bytes"
	"crypto"
	"errors"
	"github.com/multiformats/go-multihash"
	"hash"
	"io"
)

type KeyType uint8

const (
	Auto KeyType = iota
	Ed25519
	Ed25519_SHA3_512
	// This may change as new implementations come out.
	NumberOfAvailableImpl
)

// Passing NotHashed as hashFunc to Crpt.Sign indicates that message is not hashed
const NotHashed crypto.Hash = 0

var (
	ErrKeyTypeNotSupported  = errors.New("key type not supported")
	ErrUnimplemented        = errors.New("unimplemented")
	ErrWrongPublicKeySize   = errors.New("wrong public key size")
	ErrWrongPrivateKeySize  = errors.New("wrong private key size")
	ErrWrongSignatureSize   = errors.New("wrong signature size")
	ErrNoMatchingCryptoHash = errors.New("no matching crypto.Hash exists")
	ErrNoMatchingMultihash  = errors.New("no matching multihash exists")
)

// PublicKey represents a public key with a specific key type.
type PublicKey interface {
	// KeyType returns the key type.
	KeyType() KeyType

	// Equal reports whether this key is equal to another key.
	Equal(PublicKey) bool

	// Bytes returns the bytes representation of the public key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Bytes() []byte

	// TypedBytes returns the TypedPublicKey bytes representation of the public key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	TypedBytes() TypedPublicKey

	// Address returns the address derived from the public key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Address() Address
}

// PrivateKey represents a private key with a specific key type.
type PrivateKey interface {
	// KeyType returns the key type.
	KeyType() KeyType

	// Equal reports whether this key is equal to another key.
	Equal(PrivateKey) bool

	// Bytes returns the bytes representation of the private key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Bytes() []byte

	// TypedBytes returns the TypedPrivateKey bytes representation of the private key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	TypedBytes() TypedPrivateKey

	// Public returns the public key corresponding to the private key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Public() PublicKey
}

// Signature represents a digital signature produced by signing a message.
type Signature interface {
	// KeyType returns the key type used to compute the signature.
	KeyType() KeyType

	// Equal reports whether this signature is equal to another signature.
	Equal(Signature) bool

	// Bytes returns the bytes representation of the signature.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Bytes() []byte

	// TypedBytes returns the TypedSignature bytes representation of the signature.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	TypedBytes() TypedSignature
}

// TypedPublicKey consists of 1-byte KeyType of a PublicKey concatenated with its bytes representation.
type TypedPublicKey []byte

// TypedPrivateKey consists of 1-byte KeyType of a PrivateKey concatenated with its bytes representation.
type TypedPrivateKey []byte

// TypedSignature consists of 1-byte representation of crypto.Hash used as uint8 concatenated with
// the signature's bytes representation.
type TypedSignature []byte

// Address represents an address derived from a PublicKey.
type Address []byte

// TypedHash is a hash representation that replace the first byte with uint8 representation of the
// crypto.Hash used.
type TypedHash []byte

// Crpt is the common crypto operations interface implemented by all crypto implementations.
type Crpt interface {
	// KeyType reports the key type used.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	KeyType() KeyType

	// HashFunc reports the hash function to be used for Crpt.Hash.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	HashFunc() crypto.Hash

	// Hash calculates the hash of msg using underlying BaseCrpt.hashFunc.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	Hash(msg []byte) []byte

	// HashTyped calculates the hash of msg using underlying BaseCrpt.hashFunc
	// and return its TypedHash bytes representation.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	HashTyped(msg []byte) TypedHash

	// SumHashTyped appends the current hash of `h` in TypeHash bytes
	// representation to`b` and returns the resulting/slice.
	// It does not change the underlying hash state.
	SumHashTyped(h hash.Hash, b []byte) []byte

	// PublicKeyFromBytes constructs a PublicKey from raw bytes.
	PublicKeyFromBytes(pub []byte) (PublicKey, error)

	// PublicKeyFromTypedBytes constructs a PublicKey from a TypedPublicKey.
	PublicKeyFromTypedBytes(pub TypedPublicKey) (PublicKey, error)

	// PrivateKeyFromBytes constructs a PrivateKey from raw bytes.
	PrivateKeyFromBytes(priv []byte) (PrivateKey, error)

	// PrivateKeyFromTypedBytes constructs a PrivateKey from TypedPrivateKey.
	PrivateKeyFromTypedBytes(priv TypedPrivateKey) (PrivateKey, error)

	// SignatureFromBytes constructs a Signature from raw bytes.
	SignatureFromBytes(sig []byte) (Signature, error)

	// SignatureFromTypedBytes constructs a Signature from TypedSignature.
	SignatureFromTypedBytes(sig TypedSignature) (Signature, error)

	// GenerateKey generates a public/private key pair using entropy from rand.
	GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)

	// Sign signs message or digest and returns a Signature, possibly using entropy
	// from rand.
	//
	// In most case, it is recommended to use Sign instead of SignMessage or SignDigest. If not
	// providing digest (nil or empty), the caller can pass NotHashed as the value for hashFunc.
	//
	// If digest is provided (not empty), and the Crpt implementation is appropriate
	// for signing the pre-hashed messages (see SignMessage for details), Sign should
	// just call SignDigest, otherwise it should just call SignMessage.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	Sign(priv PrivateKey, message, digest []byte, hashFunc crypto.Hash, rand io.Reader) (Signature, error)

	// SignMessage directly signs message with `priv`, or hashes message first
	// and signs the resulting digest and returns a Signature, possibly using entropy
	// from rand.
	//
	// Whether SignMessage signs message or its digest depends on the Crpt implementation.
	// In most case, it will hash the message first and signs the resulting digest.But in some
	// cases, the Crpt implementations are not appropriate for signing the pre-hashed messages.
	// For example, Ed25519 performs two passes over messages to be signed and therefore cannot
	// handle pre-hashed messages, so it will directly signs the message.
	SignMessage(priv PrivateKey, message []byte, rand io.Reader) (Signature, error)

	// SignDigest signs digest with `priv` and returns a Signature, possibly
	// using entropy from rand.
	//
	// The caller must hash the message and pass the hash (as digest) and the hash
	// function used (as hashFunc) to SignDigest.
	SignDigest(priv PrivateKey, digest []byte, hashFunc crypto.Hash, rand io.Reader) (Signature, error)

	// Verify reports whether sig is a valid signature of message by `pub`.
	Verify(pub PublicKey, message []byte, sig Signature) (bool, error)
}

// Equal reports whether this key is equal to another key.
func (pub TypedPublicKey) Equal(o TypedPublicKey) bool {
	return bytes.Compare(pub, o) == 0
}

// Raw return the raw bytes of the public key without the 1-byte key type prefix.
//
// The returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (pub TypedPublicKey) Raw() []byte {
	return pub[1:]
}

// Equal reports whether this key is equal to another key.
func (priv TypedPrivateKey) Equal(o TypedPrivateKey) bool {
	return bytes.Compare(priv, o) == 0
}

// Raw return the raw bytes of the private key without the 1-byte key type prefix.
//
// The returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (priv TypedPrivateKey) Raw() []byte {
	return priv[1:]
}

// Equal reports whether this hash is equal to another hash.
func (h TypedHash) Equal(o TypedHash) bool {
	return bytes.Compare(h, o) == 0
}

func TypedHashFromMultihash(mh multihash.Multihash) (TypedHash, error) {
	decoded, err := multihash.Decode(mh)
	if err != nil {
		return nil, err
	}
	if h, ok := MulticodecToCryptoHash[decoded.Code]; !ok {
		return nil, ErrNoMatchingCryptoHash
	} else {
		decoded.Digest[0] = byte(h)
		return decoded.Digest, nil
	}
}
