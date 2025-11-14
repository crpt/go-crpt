// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Package crpt provides interface for common crypto operations.
package crpt

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"strconv"

	"github.com/crpt/go-merkle"
	gbytes "github.com/daotl/guts/bytes"
	"github.com/multiformats/go-multihash"
)

type KeyType uint8

const (
	Ed25519 KeyType = 1 + iota
	SM2
	// This may change as new implementations come out.
	MaxCrpt
)

var KeyTypeToStr = map[KeyType]string{
	Ed25519: "Ed25519",
	SM2:     "SM2",
}
var StrToKeyType map[string]KeyType

func init() {
	StrToKeyType = make(map[string]KeyType, len(KeyTypeToStr))
	for t, s := range KeyTypeToStr {
		StrToKeyType[s] = t
	}
}

func (h KeyType) String() string {
	switch h {
	case Ed25519:
		return "Ed25519"
	case SM2:
		return "SM2"
	default:
		return "unknown key type value " + strconv.Itoa(int(h))
	}
}

// Available reports whether the given KeyType implementation is available.
func (t KeyType) Available() bool {
	return t < MaxCrpt && crpts[t] != nil
}

// Passing NotHashed as hashFunc to Crpt.Sign indicates that message is not hashed
const NotHashed crypto.Hash = 0

var (
	ErrKeyTypeNotSupported  = errors.New("key type not supported")
	ErrUnimplemented        = errors.New("not implemented")
	ErrWrongPublicKeySize   = errors.New("wrong public key size")
	ErrWrongPrivateKeySize  = errors.New("wrong private key size")
	ErrWrongSignatureSize   = errors.New("wrong signature size")
	ErrEmptyMessage         = errors.New("message is empty")
	ErrInvalidHashFunc      = errors.New("invalid hash function")
	ErrNoMatchingCryptoHash = errors.New("no matching crypto.Hash exists")
	// ErrNoMatchingMultihash  = errors.New("no matching multihash exists")
)

// Untyped is the minimal common interface for the following crpt objects: PublicKey, PrivateKey, Signature
type Untyped[T any] interface {
	// Equal reports whether this key or signature is equal to another one.
	// Runs in constant time based on length of the keys to prevent time attacks.
	Equal(T) bool

	// Bytes returns the bytes representation of the key or the signature.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Bytes() []byte
}

// Typed representations of the following crpt objects: PublicKey, PrivateKey, Signature, consists of 1-byte KeyType concatenated with its bytes representation.
type Typed[T any] []byte

// KeyType returns the key type.
func (t Typed[T]) KeyType() KeyType {
	return KeyType(t[0])
}

// Equal reports whether this key or signature is equal to another one.
// Runs in constant time based on length of the keys to prevent time attacks.
func (t Typed[T]) Equal(t2 Typed[T]) bool {
	if len(t) != len(t2) {
		return false
	}
	return subtle.ConstantTimeCompare(t, t2) == 1
}

// Raw return the raw bytes of the the following typed crpt objects: PublicKey, PrivateKey, Signature
//
// The returned byte slice is not safe to modify because it returns the underlying byte slice
// directly for the performance reason. Copy it if you need to modify.
func (t Typed[T]) Raw() []byte {
	return t[1:]
}

// ToTyped returns the typed bytes representation of Untyped (PublicKey, PrivateKey, Signature).
func ToTyped[T any](u Untyped[T], t KeyType) []byte {
	ub := u.Bytes()
	b := make([]byte, len(ub)+1)
	b[0] = byte(t)
	copy(b[1:], ub)
	return b
}

// UntypedKey is the common interface for PublicKey and PrivateKey
type UntypedKey[T any] interface {
	Untyped[T]

	// KeyType returns the key type.
	//
	// PublicKey/PrivateKey implementations generally don't need to implement this method as it is
	// already implemented by embedded BasePublicKey/BasePrivateKey.
	KeyType() KeyType

	// SignerOpts reports the default SignerOpts use by this key.
	//
	// PublicKey/PrivateKey implementations generally don't need to implement this method as it is
	// already implemented by embedded BasePublicKey/BasePrivateKey.
	SignerOpts() crypto.SignerOpts

	// ToTyped returns the typed bytes representation of the key.
	//
	// PublicKey/PrivateKey implementations generally don't need to implement this method as it is
	// already implemented by embedded BasePublicKey/BasePrivateKey.
	ToTyped() Typed[T]
}

// PublicKey represents a public key with a specific key type.
type PublicKey interface {
	UntypedKey[PublicKey]

	// Address returns the address derived from the public key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Address() Address

	// Verify reports whether `sig` is a valid signature of message or digest by the public key.
	//
	// In most case, it is recommended to use Verify instead of VerifyMessage or VerifyDigest.
	//
	// If digest is provided (not empty), and the Crpt implementation is appropriate for signing the
	// pre-hashed messages (see SignMessage for details), Verify should try VerifyDigest first, then
	// it should try VerifyMessage, it should returns true if either returns true.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	Verify(message, digest []byte, sig Signature, opts crypto.SignerOpts) (bool, error)

	// VerifyMessage reports whether `sig` is a valid signature of message by the public key.
	VerifyMessage(message []byte, sig Signature, opts crypto.SignerOpts) (bool, error)

	// VerifyDigest reports whether `sig` is a valid signature of digest by the public key.
	//
	// The caller must hash the message and pass the hash (as digest) and the appropriate crypto.SignerOpts
	// so opts.HashFunc() returns the function used to SignDigest.
	//
	// Some Crpt implementations are not appropriate for signing the pre-hashed messages, which will
	// return ErrUnimplemented.
	VerifyDigest(digest []byte, sig Signature, opts crypto.SignerOpts) (bool, error)
}

// PrivateKey represents a private key with a specific key type.
type PrivateKey interface {
	UntypedKey[PrivateKey]

	// Public returns the public key corresponding to the private key.
	//
	// NOTE: It's not safe to modify the returned slice because the implementations most likely
	// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
	Public() PublicKey

	// Sign signs message or digest and returns a Signature, possibly using entropy from rand.
	//
	// In most case, it is recommended to use Sign instead of SignMessage or SignDigest. If not
	// providing digest (nil or empty), the caller can pass NotHashed as the value for hashFunc.
	//
	// If digest is provided (not empty), and the Crpt implementation is appropriate
	// for signing the pre-hashed messages (see SignMessage for details), Sign should
	// just call SignDigest, otherwise it should just call SignMessage.
	//
	// PrivateKey implementations generally don't need to implement this method as it is
	// already implemented by embedded BasePrivateKey.
	Sign(message, digest []byte, rand io.Reader, opts crypto.SignerOpts) (Signature, error)

	// SignMessage directly signs message with `priv`, possibly using entropy from rand.
	// Implementations should always use crpt.NotHashed and ignore opts.HashFunc().
	SignMessage(message []byte, rand io.Reader, opts crypto.SignerOpts) (Signature, error)

	// SignDigest signs digest with `priv` and returns a Signature, possibly using entropy from rand.
	//
	// The caller must hash the message and pass the hash (as digest) and the hash
	// function used (as hashFunc) to SignDigest.
	//
	// Some Crpt implementations are not appropriate for signing the pre-hashed messages, which will
	// return ErrUnimplemented.
	SignDigest(digest []byte, rand io.Reader, opts crypto.SignerOpts) (Signature, error)
}

// Signature represents a digital signature produced by signing a message.
type Signature []byte

// Type check
var _ Untyped[Signature] = Signature(nil)

// Equal reports whether this signature is equal to another one.
// Runs in constant time based on length of the keys to prevent time attacks.
func (sig Signature) Equal(o Signature) bool {
	if len(sig) != len(o) {
		return false
	}
	return subtle.ConstantTimeCompare(sig, o.Bytes()) == 1
}

// Bytes returns the bytes representation of the key or the signature.
//
// NOTE: It's not safe to modify the returned slice because the implementations most likely
// return the underlying byte slice directly for the performance reason. Copy it if you need to modify.
func (sig Signature) Bytes() []byte {
	return sig
}

// TypedSignature consists of 1-byte representation of crypto.Hash used as uint8 concatenated with
// the signature's bytes representation.
type TypedSignature []byte

// Address represents an address derived from a PublicKey.
// An address is a []byte, but hex-encoded even in JSON.
type Address = gbytes.HexBytes

// Hash represents a hash.
type Hash []byte

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

	// SignerOpts reports the default SignerOpts use by this Crpt instance.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	SignerOpts() crypto.SignerOpts

	// HashFunc reports the hash function to be used for Crpt.Hash.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	HashFunc() crypto.Hash

	// Hash calculates the hash of msg using underlying BaseCrpt.hashFunc.
	//
	// Crpt implementations generally don't need to implement this method as it is
	// already implemented by embedded BaseCrpt.
	Hash(msg []byte) Hash

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

	// HashToTyped decorates a hash into a TypedHash.
	HashToTyped(Hash) TypedHash

	// PublicKeyFromBytes constructs a PublicKey from raw bytes.
	PublicKeyFromBytes(pub []byte) (PublicKey, error)

	// PrivateKeyFromBytes constructs a PrivateKey from raw bytes.
	PrivateKeyFromBytes(priv []byte) (PrivateKey, error)

	// SignatureToASN1 converts a Signature to ASN.1 DER encoding.
	SignatureToASN1(sig Signature) ([]byte, error)

	// SignatureToTyped decorates a Signature into a TypedSignature.
	SignatureToTyped(sig Signature) (TypedSignature, error)

	// GenerateKey generates a public/private key pair using entropy from rand.
	GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)

	// NewBatchVerifier creates a new batch verifier for this key type with the given options.
	// Returns ErrUnimplemented if batch verification is not supported for this key type.
	NewBatchVerifier(opts crypto.SignerOpts) (BatchVerifier, error)

	// MerkleHashFromByteSlices computes a Merkle tree where the leaves are the byte slice,
	// in the provided order. It follows RFC-6962.
	MerkleHashFromByteSlices(items [][]byte) (rootHash []byte)

	// MerkleHashTypedFromByteSlices computes a Merkle tree where the leaves are the byte slice,
	// in the provided order. It follows RFC-6962.
	// This returns the TypedHash bytes representation.
	MerkleHashTypedFromByteSlices(items [][]byte) (rootHash TypedHash)

	// MerkleProofsFromByteSlices computes inclusion proof for given items.
	// proofs[0] is the proof for items[0].
	MerkleProofsFromByteSlices(items [][]byte) (rootHash []byte, proofs []*merkle.Proof)

	// MerkleProofsTypedFromByteSlices computes inclusion proof for given items.
	// proofs[0] is the proof for items[0].
	// This returns the TypedHash bytes representation.
	MerkleProofsTypedFromByteSlices(items [][]byte) (rootHash TypedHash, proofs []*merkle.Proof)
}

var crpts = make([]Crpt, MaxCrpt)

// RegisterCrpt registers a function that returns a new instance of the given
// Crpt instance. This is intended to be called from the init function in
// packages that implement Crpt interface.
func RegisterCrpt(t KeyType, c Crpt) {
	if t >= MaxCrpt {
		panic("crypto: RegisterCrpt of unknown Crpt implementation")
	}
	crpts[t] = c
}

// Equal reports whether this hash is equal to another hash.
// Runs in constant time based on length of the keys to prevent time attacks.
func (h TypedHash) Equal(o TypedHash) bool {
	if len(h) != len(o) {
		return false
	}
	return subtle.ConstantTimeCompare(h, o) == 1
}

// HashToTyped decorates a hash into a TypedHash with crypto.Hash.
func HashToTyped(hashFunc crypto.Hash, h Hash) TypedHash {
	ht := make([]byte, len(h))
	ht[0] = byte(hashFunc)
	return ht
}

// TypedHashFromMultihash turns a Multihash into a TypedHash.
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

// PublicKeyFromBytes constructs a PublicKey from raw bytes.
func PublicKeyFromBytes(t KeyType, pub []byte) (PublicKey, error) {
	if t >= MaxCrpt || crpts[t] == nil {
		return nil, ErrKeyTypeNotSupported
	}
	return crpts[t].PublicKeyFromBytes(pub)
}

// PublicKeyFromTyped constructs a PublicKey from its typed bytes representation.
func PublicKeyFromTyped(pub Typed[PublicKey]) (PublicKey, error) {
	if len(pub) == 0 {
		return nil, ErrWrongPublicKeySize
	}
	return PublicKeyFromBytes(KeyType(pub[0]), pub[1:])
}

// PrivateKeyFromBytes constructs a PrivateKey from raw bytes.
func PrivateKeyFromBytes(t KeyType, priv []byte) (PrivateKey, error) {
	if !t.Available() {
		return nil, ErrKeyTypeNotSupported
	}
	return crpts[t].PrivateKeyFromBytes(priv)
}

// PrivateKeyFromTyped constructs a PrivateKey from its typed bytes representation.
func PrivateKeyFromTyped(priv Typed[PrivateKey]) (PrivateKey, error) {
	if len(priv) == 0 {
		return nil, ErrWrongPublicKeySize
	}
	return PrivateKeyFromBytes(KeyType(priv[0]), priv[1:])
}

// SignatureToASN1 converts a Signature to ASN.1 DER encoding.
func SignatureToASN1(t KeyType, sig Signature) ([]byte, error) {
	if !t.Available() {
		return nil, ErrKeyTypeNotSupported
	}
	return crpts[t].SignatureToASN1(sig)
}

// SignatureToTyped decorates a Signature into a TypedSignature.
func SignatureToTyped(t KeyType, sig Signature) (TypedSignature, error) {
	if !t.Available() {
		return nil, ErrKeyTypeNotSupported
	}
	return crpts[t].SignatureToTyped(sig)
}

// GenerateKey generates a public/private key pair using entropy from rand.
func GenerateKey(t KeyType, rand io.Reader) (PublicKey, PrivateKey, error) {
	if !t.Available() {
		return nil, nil, ErrKeyTypeNotSupported
	}
	return crpts[t].GenerateKey(rand)
}

// NewBatchVerifier creates a new batch verifier for this key type with the given options.
// Returns ErrUnimplemented if batch verification is not supported for this key type.
func NewBatchVerifier(t KeyType, opts crypto.SignerOpts) (BatchVerifier, error) {
	if !t.Available() {
		return nil, ErrKeyTypeNotSupported
	}
	return crpts[t].NewBatchVerifier(opts)
}

// Sign signs message or digest and returns a Signature, possibly using entropy from rand.
//
// See PrivateKey.Sign for more details.
func Sign(priv PrivateKey, message, digest []byte, rand io.Reader, opts crypto.SignerOpts,
) (Signature, error) {
	return priv.Sign(message, digest, rand, opts)
}

// SignMessage directly signs message with `priv`, possibly using entropy from rand.
// Implementations should always use crpt.NotHashed and ignore opts.HashFunc().
//
// See PrivateKey.SignMessage for more details.
func SignMessage(priv PrivateKey, message []byte, rand io.Reader, opts crypto.SignerOpts,
) (Signature, error) {
	return priv.SignMessage(message, rand, opts)
}

// SignDigest signs digest with `priv` and returns a Signature, possibly using entropy from rand.
//
// See PrivateKey.SignDigest for more details.
func SignDigest(priv PrivateKey, digest []byte, rand io.Reader, opts crypto.SignerOpts,
) (Signature, error) {
	return priv.SignDigest(digest, rand, opts)
}

// Verify reports whether `sig` is a valid signature of message or digest by `pub`.
//
// See PublicKey.Verify for more details.
func Verify(pub PublicKey, message, digest []byte, sig Signature, opts crypto.SignerOpts) (bool, error) {
	return pub.Verify(message, digest, sig, opts)
}

// VerifyMessage reports whether `sig` is a valid signature of message by `pub`.
//
// See PublicKey.VerifyMessage for more details.
func VerifyMessage(pub PublicKey, message []byte, sig Signature, opts crypto.SignerOpts) (bool, error) {
	return pub.VerifyMessage(message, sig, opts)
}

// VerifyDigest reports whether `sig` is a valid signature of digest by `pub`.
//
// See PublicKey.VerifyDigest for more details.
func VerifyDigest(pub PublicKey, digest []byte, sig Signature, opts crypto.SignerOpts) (bool, error) {
	return pub.VerifyDigest(digest, sig, opts)
}

// SignerOptsWithHash is an interface that combines crypto.SignerOpts with SetHash and Clone methods
type SignerOptsWithHash interface {
	crypto.SignerOpts
	Clone() SignerOptsWithHash
	SetHash(crypto.Hash)
}

// ConvertSignerOpts converts crypto.SignerOpts to a specific SignerOpts type using generics.
//
// T must be a pointer type that implements SignerOptsWithHash.
// The behavior is:
// - If opts is nil, returns defaultOpts (as-is, even if nil)
// - If opts is of type T, returns opts (caller should not modify the returned value)
// - If opts is not of type T, creates a copy of defaultOpts, extracts HashFunc(), modifies the copy, and returns it
func ConvertSignerOpts[T SignerOptsWithHash](opts crypto.SignerOpts, defaultOpts T) T {
	// Create a dopt to avoid modifying the original defaultOpts
	dopt := defaultOpts.Clone().(T)

	if opts == nil {
		return dopt
	}

	// Try to convert to the target type
	if typed, ok := opts.(T); ok {
		return typed
	}

	// For type other than T, only use the hash function (including NotHashed which is 0)
	dopt.SetHash(opts.HashFunc())

	return dopt
}

/* Batch */

// BatchVerifier provides batch signature verification.
//
// If a new key type implements batch verification,
// the key type must be registered in `github.com/crpt/go-crpt/batch`
type BatchVerifier interface {
	// Add appends an entry into the BatchVerifier.
	//
	// If digest is provided (not empty), and the Crpt implementation is appropriate for signing the
	// pre-hashed messages (see SignMessage for details), Verify should try VerifyDigest first, then
	// it should try VerifyMessage, it should returns true if either returns true.
	Add(key PublicKey, message, digest []byte, sig Signature, opts crypto.SignerOpts) error

	// Verify verifies all the entries in the BatchVerifier, and returns
	// if every signature in the batch is valid, and a vector of bools
	// indicating the verification status of each signature (in the order
	// that signatures were added to the batch).
	Verify(rand io.Reader) (bool, []bool)
}
