// Copyright 2025 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crpt

import (
	"crypto"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockCrpt implements the Crpt interface for testing
type mockCrpt struct {
	BaseCrpt
}

func (m *mockCrpt) GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return nil, nil, nil
}

func (m *mockCrpt) Sign(priv PrivateKey, message, digest []byte, rand io.Reader, opts SignerOpts) (Signature, error) {
	return nil, nil
}

func (m *mockCrpt) SignMessage(priv PrivateKey, message []byte, rand io.Reader, opts SignerOpts) (Signature, error) {
	return nil, nil
}

func (m *mockCrpt) SignDigest(priv PrivateKey, digest []byte, rand io.Reader, opts SignerOpts) (Signature, error) {
	return nil, nil
}

func (m *mockCrpt) Verify(pub PublicKey, message, digest []byte, hashFunc Hash, sig Signature) (bool, error) {
	return false, nil
}

func (m *mockCrpt) VerifyMessage(pub PublicKey, message []byte, sig Signature) (bool, error) {
	return false, nil
}

func (m *mockCrpt) VerifyDigest(pub PublicKey, digest []byte, hashFunc Hash, sig Signature) (bool, error) {
	return false, nil
}

func (m *mockCrpt) PublicKeyFromBytes(b []byte) (PublicKey, error) {
	return nil, nil
}

func (m *mockCrpt) PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	return nil, nil
}

func (m *mockCrpt) SignatureToASN1(sig Signature) ([]byte, error) {
	return nil, nil
}

func (m *mockCrpt) SignatureToTyped(sig Signature) (TypedSignature, error) {
	return nil, nil
}

func (m *mockCrpt) NewBatchVerifier(opts SignerOpts) (BatchVerifier, error) {
	return nil, nil
}

func TestNewBaseCrpt(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		hashFunc Hash
		parent   Crpt
		wantErr  bool
		panicMsg string
	}{
		{
			name:     "Valid parameters should work",
			keyType:  Ed25519,
			hashFunc: Hash(crypto.SHA512),
			parent:   &mockCrpt{},
			wantErr:  false,
		},
		{
			name:     "Zero hash function should work",
			keyType:  Ed25519,
			hashFunc: 0,
			parent:   &mockCrpt{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panicMsg != "" {
				defer func() {
					if r := recover(); r != nil {
						require.Contains(t, r.(string), tt.panicMsg)
					} else {
						t.Errorf("Expected panic with message: %s", tt.panicMsg)
					}
				}()
			}

			got, err := NewBaseCrpt(tt.keyType, Hash(tt.hashFunc), tt.parent)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.keyType, got.KeyType())
				require.Equal(t, Hash(tt.hashFunc), got.HashFunc())
			}
		})
	}
}

func TestNewBaseCrpt_ErrorCases(t *testing.T) {
	t.Run("Nil parent should return error", func(t *testing.T) {
		_, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrParentIsNil)
	})

	t.Run("Unavailable hash function should return error", func(t *testing.T) {
		// Use a hash function that's likely not available
		unavailableHash := Hash(999) // Very unlikely to exist

		_, err := NewBaseCrpt(Ed25519, unavailableHash, &mockCrpt{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidHashFunc)
	})
}

func TestBaseCrpt_KeyType(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	require.Equal(t, Ed25519, base.KeyType())
}

func TestBaseCrpt_HashFunc(t *testing.T) {
	mock := &mockCrpt{}

	tests := []struct {
		name     string
		hashFunc Hash
	}{
		{"SHA256", Hash(crypto.SHA256)},
		{"SHA512", Hash(crypto.SHA512)},
		{"Zero", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, err := NewBaseCrpt(Ed25519, Hash(tt.hashFunc), mock)
			require.NoError(t, err)
			require.Equal(t, Hash(tt.hashFunc), base.HashFunc())
		})
	}
}

func TestBaseCrpt_Hash(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	message := []byte("test message")
	hash := base.Hash(message)
	require.NotEmpty(t, hash)
	require.Len(t, hash, 64) // SHA512 produces 64-byte hash

	// Test deterministic behavior
	hash2 := base.Hash(message)
	require.Equal(t, hash, hash2)

	// Test different messages produce different hashes
	otherMessage := []byte("other message")
	hash3 := base.Hash(otherMessage)
	require.NotEqual(t, hash, hash3)
}

func TestBaseCrpt_HashTyped(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	message := []byte("test message")
	typedHash := base.HashTyped(message)
	require.NotEmpty(t, typedHash)
	require.Len(t, typedHash, 64) // SHA512 hash length

	// Verify it contains the hashFuncByte at index 0 (overwriting the first byte of hash)
	require.Equal(t, byte(crypto.SHA512), typedHash[0])

	// Verify the hash has the correct length (same as raw hash, but with first byte overwritten)
	rawHash := base.Hash(message)
	require.Equal(t, len(rawHash), len(typedHash))

	// Test deterministic behavior
	typedHash2 := base.HashTyped(message)
	require.Equal(t, typedHash, typedHash2)
}

func TestBaseCrpt_SumHashTyped(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	data := []byte("test data for sum")

	// Create a hash instance manually
	hasher := crypto.SHA512.New()
	typedHash := base.SumHashTyped(hasher, data)
	require.NotEmpty(t, typedHash)

	// The result should be: data + hashFuncByte + remaining_31_bytes_of_hash
	expectedLen := len(data) + 64 // data + hash (with first byte overwritten)
	require.Len(t, typedHash, expectedLen)

	// Verify it contains the original data
	require.Equal(t, data, typedHash[:len(data)])

	// Verify it contains the hashFuncByte right after the data
	require.Equal(t, byte(crypto.SHA512), typedHash[len(data)])

	// Verify there are remaining hash bytes (should be 31 bytes)
	require.Len(t, typedHash[len(data)+1:], 63)
}

func TestBaseCrpt_HashToTyped(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	hash := make([]byte, 64)
	for i := range hash {
		hash[i] = byte(i)
	}

	typedHash := base.HashValueToTyped(hash)
	require.NotEmpty(t, typedHash)
	require.Len(t, typedHash, 64) // Same length as original hash (this is the implementation's behavior)
	require.Equal(t, byte(crypto.SHA512), typedHash[0])
	require.Equal(t, hash[1:], []byte(typedHash[1:]))
}

func TestBaseCrpt_MerkleHashFromByteSlices(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	tests := []struct {
		name  string
		items [][]byte
	}{
		{
			name:  "Single item",
			items: [][]byte{[]byte("item1")},
		},
		{
			name:  "Multiple items",
			items: [][]byte{[]byte("item1"), []byte("item2"), []byte("item3")},
		},
		{
			name:  "Empty items",
			items: [][]byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootHash := base.MerkleHashFromByteSlices(tt.items)
			// The merkle library returns a hash even for empty items
			require.NotEmpty(t, rootHash)

			// Test deterministic behavior
			rootHash2 := base.MerkleHashFromByteSlices(tt.items)
			require.Equal(t, rootHash, rootHash2)
		})
	}
}

func TestBaseCrpt_MerkleHashTypedFromByteSlices(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	items := [][]byte{[]byte("item1"), []byte("item2")}
	typedRootHash := base.MerkleHashTypedFromByteSlices(items)

	require.NotEmpty(t, typedRootHash)
	require.Len(t, typedRootHash, 64)
	require.Equal(t, byte(crypto.SHA512), typedRootHash[0])
}

func TestBaseCrpt_MerkleProofsFromByteSlices(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	items := [][]byte{[]byte("item1"), []byte("item2"), []byte("item3")}
	_, proofs := base.MerkleProofsFromByteSlices(items)

	require.Len(t, proofs, len(items))

	// Verify each proof is not nil for non-empty items
	for i, proof := range proofs {
		if len(items[i]) > 0 {
			require.NotNil(t, proof)
		}
	}
}

func TestBaseCrpt_MerkleProofsTypedFromByteSlices(t *testing.T) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	require.NoError(t, err)

	items := [][]byte{[]byte("item1"), []byte("item2")}
	_, proofs := base.MerkleProofsTypedFromByteSlices(items)

	require.Len(t, proofs, len(items))

	// Verify each typed proof is not nil for non-empty items
	for i, proof := range proofs {
		if len(items[i]) > 0 {
			require.NotNil(t, proof)
		}
	}
}

func TestBaseCrpt_Parent(t *testing.T) {
	parent := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), parent)
	require.NoError(t, err)

	// Verify parent reference is stored
	require.Equal(t, parent, base.parent)
}

// Benchmark tests for BaseCrpt methods
func BenchmarkBaseCrpt_Hash(b *testing.B) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for hashing")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = base.Hash(message)
	}
}

func BenchmarkBaseCrpt_HashTyped(b *testing.B) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for typed hashing")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = base.HashTyped(message)
	}
}

func BenchmarkBaseCrpt_MerkleHashFromByteSlices(b *testing.B) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	if err != nil {
		b.Fatal(err)
	}

	// Prepare test data
	const numItems = 100
	items := make([][]byte, numItems)
	for i := 0; i < numItems; i++ {
		items[i] = make([]byte, 32)
		for j := range items[i] {
			items[i][j] = byte(i + j)
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = base.MerkleHashFromByteSlices(items)
	}
}

func BenchmarkBaseCrpt_MerkleHashTypedFromByteSlices(b *testing.B) {
	mock := &mockCrpt{}
	base, err := NewBaseCrpt(Ed25519, Hash(crypto.SHA512), mock)
	if err != nil {
		b.Fatal(err)
	}

	// Prepare test data
	const numItems = 100
	items := make([][]byte, numItems)
	for i := 0; i < numItems; i++ {
		items[i] = make([]byte, 32)
		for j := range items[i] {
			items[i][j] = byte(i + j)
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = base.MerkleHashTypedFromByteSlices(items)
	}
}
