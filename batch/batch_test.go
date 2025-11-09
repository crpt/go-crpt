// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package batch

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/ed25519"
	"github.com/stretchr/testify/require"
)

func TestNewBatchVerifier(t *testing.T) {
	tests := []struct {
		name    string
		keyType crpt.KeyType
		want    bool
		wantErr bool
	}{
		{
			name:    "Ed25519 key type should return batch verifier",
			keyType: ed25519.KeyType,
			want:    true,
		},
		{
			name:    "Invalid key type should return false",
			keyType: crpt.KeyType(255),
			want:    false,
		},
		{
			name:    "Zero key type should return false",
			keyType: crpt.KeyType(0),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, exists := NewBatchVerifier(tt.keyType)
			if tt.want {
				require.True(t, exists, "Expected batch verifier to exist for key type %d", tt.keyType)
				require.NotNil(t, got, "Expected non-nil batch verifier for key type %d", tt.keyType)
			} else {
				require.False(t, exists, "Expected no batch verifier for key type %d", tt.keyType)
				require.Nil(t, got, "Expected nil batch verifier for key type %d", tt.keyType)
			}
		})
	}
}

func TestSupportsBatchVerifier(t *testing.T) {
	tests := []struct {
		name    string
		keyType crpt.KeyType
		want    bool
	}{
		{
			name:    "Ed25519 should support batch verification",
			keyType: ed25519.KeyType,
			want:    true,
		},
		{
			name:    "Invalid key type should not support batch verification",
			keyType: crpt.KeyType(255),
			want:    false,
		},
		{
			name:    "Zero key type should not support batch verification",
			keyType: crpt.KeyType(0),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SupportsBatchVerifier(tt.keyType)
			require.Equal(t, tt.want, got, "SupportsBatchVerifier(%d) = %v, want %v", tt.keyType, got, tt.want)
		})
	}
}

func TestBatchVerifierFunctionality(t *testing.T) {
	// Test that the returned batch verifier actually works
	bv, exists := NewBatchVerifier(ed25519.KeyType)
	require.True(t, exists, "Ed25519 should support batch verification")
	require.NotNil(t, bv, "Batch verifier should not be nil")

	// Test that we can add signatures and verify
	crypt, err := ed25519.New(crypto.SHA256)
	require.NoError(t, err)

	// Generate test keys and signatures
	pub1, priv1, err := crypt.GenerateKey(nil)
	require.NoError(t, err)

	pub2, priv2, err := crypt.GenerateKey(nil)
	require.NoError(t, err)

	message1 := []byte("test message 1")
	message2 := []byte("test message 2")

	sig1, err := priv1.SignMessage(message1, nil)
	require.NoError(t, err)

	sig2, err := priv2.SignMessage(message2, nil)
	require.NoError(t, err)

	// Add signatures to batch verifier
	err = bv.Add(pub1, message1, sig1)
	require.NoError(t, err)

	err = bv.Add(pub2, message2, sig2)
	require.NoError(t, err)

	// Verify batch
	ok, results := bv.Verify(rand.Reader)
	require.True(t, ok, "Batch verification should succeed")
	require.Len(t, results, 2, "Should return results for all signatures")
	require.True(t, results[0], "First signature should be valid")
	require.True(t, results[1], "Second signature should be valid")
}

func TestBatchVerifierInvalidSignature(t *testing.T) {
	bv, exists := NewBatchVerifier(ed25519.KeyType)
	require.True(t, exists)
	require.NotNil(t, bv)

	crypt, err := ed25519.New(crypto.SHA256)
	require.NoError(t, err)

	pub, priv, err := crypt.GenerateKey(nil)
	require.NoError(t, err)

	message := []byte("test message")
	sig, err := priv.SignMessage(message, nil)
	require.NoError(t, err)

	// Add valid signature
	err = bv.Add(pub, message, sig)
	require.NoError(t, err)

	// Add invalid signature (wrong message)
	wrongMessage := []byte("wrong message")
	err = bv.Add(pub, wrongMessage, sig)
	require.NoError(t, err)

	// Batch verification should fail
	ok, results := bv.Verify(rand.Reader)
	require.False(t, ok, "Batch verification should fail with invalid signature")
	require.Len(t, results, 2, "Should return results for all signatures")
	require.True(t, results[0], "First signature should be valid")
	require.False(t, results[1], "Second signature should be invalid")
}

// BenchmarkBatchVerifier benchmarks the batch verification performance
func BenchmarkBatchVerifier(b *testing.B) {
	crypt, _ := ed25519.New(crypto.SHA256)

	// Prepare test data
	const batchSize = 100
	pubs := make([]crpt.PublicKey, batchSize)
	privs := make([]crpt.PrivateKey, batchSize)
	messages := make([][]byte, batchSize)
	signatures := make([]crpt.Signature, batchSize)

	for i := 0; i < batchSize; i++ {
		pub, priv, err := crypt.GenerateKey(nil)
		if err != nil {
			b.Fatal(err)
		}
		pubs[i] = pub
		privs[i] = priv
		messages[i] = []byte("benchmark message")
		signatures[i], err = priv.SignMessage(messages[i], nil)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batchVerifier, _ := NewBatchVerifier(ed25519.KeyType)

		for j := 0; j < batchSize; j++ {
			err := batchVerifier.Add(pubs[j], messages[j], signatures[j])
			if err != nil {
				b.Fatal(err)
			}
		}

		ok, results := batchVerifier.Verify(rand.Reader)
		if !ok {
			b.Fatal("batch verification failed")
		}
		// Check that all results are true
		for _, result := range results {
			if !result {
				b.Fatal("individual verification failed")
			}
		}
	}
}
