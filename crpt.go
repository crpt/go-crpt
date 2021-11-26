// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package crpt provides interface for common crypto operations.
package crpt

import (
	"crypto"
	"errors"
	"io"
)

type KeyType uint8

const (
	Ed25519 KeyType = iota
	Ed25519_SHA3_512
	// Only for test
	CurrentKeyTypeCount
)

// Passing NotHashed as hashFunc to Crpt.Sign indicates that message is not hashed
const NotHashed crypto.Hash = 0

var ErrKeyTypeNotSupported = errors.New("key type not supported")

// PublicKey represents a public key with an unspecified key type.
type PublicKey interface {
	// Bytes returns the bytes representation of the public key.
	Bytes() []byte

	// Address returns the address derived from the public key.
	Address() Address
}

// PrivateKey represents a private key with an unspecified key type.
type PrivateKey interface {
	// Bytes returns the bytes representation of the private key.
	Bytes() []byte

	// Public returns the public key corresponding to the private key.
	Public() PublicKey
}

// Address represents an address derived from a PublicKey.
type Address []byte

// Signature represents a digital signature produced by signing a message.
type Signature []byte

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

	// PublicKeyFromBytes constructs a PublicKey from bytes.
	PublicKeyFromBytes(publicKey []byte) (PublicKey, error)

	// PrivateKeyFromBytes constructs a PrivateKey from bytes.
	PrivateKeyFromBytes(privateKey []byte) (PrivateKey, error)

	// SignatureFromBytes constructs a Signature from bytes.
	SignatureFromBytes(sig []byte) (Signature, error)

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
	Sign(privateKey PrivateKey, message, digest []byte, hashFunc crypto.Hash, rand io.Reader) (Signature, error)

	// SignMessage directly signs message with privateKey, or hashes message first
	// and signs the resulting digest and returns a Signature, possibly using entropy
	// from rand.
	//
	// Whether SignMessage signs message or its digest depends on the Crpt implementation.
	// In most case, it will hash the message first and signs the resulting digest.But in some
	// cases, the Crpt implementations are not appropriate for signing the pre-hashed messages.
	// For example, Ed25519 performs two passes over messages to be signed and therefore cannot
	// handle pre-hashed messages, so it will directly signs the message.
	SignMessage(privateKey PrivateKey, message []byte, rand io.Reader) (Signature, error)

	// SignDigest signs digest with privateKey and returns a Signature, possibly
	// using entropy from rand.
	//
	// The caller must hash the message and pass the hash (as digest) and the hash
	// function used (as hashFunc) to SignDigest.
	SignDigest(privateKey PrivateKey, digest []byte, hashFunc crypto.Hash, rand io.Reader) (Signature, error)

	// Verify reports whether sig is a valid signature of message by publicKey.
	Verify(publicKey PublicKey, message []byte, sig Signature) (bool, error)
}
