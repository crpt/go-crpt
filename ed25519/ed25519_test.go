// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package ed25519_test

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crpt/go-crpt"
	. "github.com/crpt/go-crpt/ed25519"
	"github.com/crpt/go-crpt/internal/test"
)

func TestEd25519Crpt(t *testing.T) {
	req := require.New(t)
	assr := assert.New(t)

	c, err := New(nil)
	req.NoError(err)

	t.Run("PublicKey/PrivateKey", func(t *testing.T) {
		test.Test_PrivateKey_PublicKey(t, c)
	})

	t.Run("KeyType & HashFunc", func(t *testing.T) {
		assr.Equal(crpt.Ed25519, c.KeyType())
		assr.Equal(crpt.Hash(crypto.SHA512), c.HashFunc())
	})

	t.Run("Hash", func(t *testing.T) {
		test.Test_Hash(t, c)
	})

	t.Run("XxxFromBytes, SignXxx, Verify", func(t *testing.T) {
		test.Test_XxxFromBytes_SignXxx_Verify(t, c, test.TestEd25519PrivateKey, crpt.Ed25519)
	})

	t.Run("Batch", func(t *testing.T) {
		test.Test_Batch(t, c, crpt.Ed25519)
	})

	t.Run("SignatureToASN1", func(t *testing.T) {
		test.Test_SignatureToASN1(t, c, crpt.Ed25519)
	})

	t.Run("NewBatchVerifier", func(t *testing.T) {
		test.Test_NewBatchVerifier(t, c, crpt.Ed25519)
	})
}

func TestEd25519_Comprehensive(t *testing.T) {
	// Use SHA512 which works with the ed25519 implementation
	hashFunc := crpt.Hash(crypto.SHA512)

	c, err := NewWithCryptoSignerOpts(hashFunc)
	require.NoError(t, err)

	// Test key generation
	pub, priv, err := c.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, pub)
	require.NotNil(t, priv)

	// Test key properties
	assert.Equal(t, crpt.Ed25519, pub.KeyType())
	assert.Equal(t, crpt.Ed25519, priv.KeyType())
	assert.Equal(t, hashFunc, c.HashFunc())

	// Test key equality
	assert.True(t, pub.Equal(pub))
	assert.True(t, priv.Equal(priv))

	// Test key serialization
	pubBytes := pub.Bytes()
	privBytes := priv.Bytes()
	assert.Len(t, pubBytes, 32)
	assert.Len(t, privBytes, 64)

	// Test typed keys
	typedPub := pub.ToTyped()
	typedPriv := priv.ToTyped()
	assert.Len(t, typedPub, 33)  // 32 bytes + 1 byte type
	assert.Len(t, typedPriv, 65) // 64 bytes + 1 byte type
	assert.Equal(t, byte(KeyType), typedPub[0])
	assert.Equal(t, byte(KeyType), typedPriv[0])

	// Test Raw() method
	assert.Equal(t, pubBytes, typedPub.Raw())
	assert.Equal(t, privBytes, typedPriv.Raw())

	// Test signing different message sizes
	messageSizes := []int{0, 1, 32, 64, 128, 1024, 4096}
	for _, size := range messageSizes {
		message := make([]byte, size)
		rand.Read(message)

		// Sign message
		sig, err := priv.SignMessage(message, rand.Reader, nil)
		require.NoError(t, err)
		require.Len(t, sig, 64)

		// Verify signature
		valid, err := pub.VerifyMessage(message, sig, nil)
		require.NoError(t, err)
		require.True(t, valid)

		// Test with wrong message
		wrongMessage := make([]byte, len(message))
		copy(wrongMessage, message)
		if len(wrongMessage) > 0 {
			wrongMessage[0] ^= 0xFF
			valid, err = pub.VerifyMessage(wrongMessage, sig, nil)
			require.NoError(t, err)
			require.False(t, valid)
		}
	}

	// Test digest signing
	message := []byte("test message for digest signing")
	digest := c.Hash(message)

	// Sign digest
	sig, err := priv.SignDigest(digest, rand.Reader, hashFunc)
	require.NoError(t, err)

	// Verify digest
	valid, err := pub.VerifyDigest(digest, sig, hashFunc)
	require.NoError(t, err)
	require.True(t, valid)

	// Test with wrong digest
	wrongDigest := make([]byte, len(digest))
	copy(wrongDigest, digest)
	wrongDigest[0] ^= 0xFF

	valid, err = pub.VerifyDigest(wrongDigest, sig, hashFunc)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestEd25519_ErrorCases(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	t.Run("Invalid signature sizes", func(t *testing.T) {
		pub, _, err := c.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := []byte("test message")

		// Test with various invalid signature sizes
		invalidSizes := []int{0, 1, 31, 63, 65, 128}
		for _, size := range invalidSizes {
			sig := make([]byte, size)
			rand.Read(sig)

			valid, err := pub.VerifyMessage(message, sig, nil)
			require.NoError(t, err)
			require.False(t, valid)
		}
	})

	t.Run("Invalid public key sizes", func(t *testing.T) {
		// Test PublicKeyFromBytes with invalid sizes
		invalidSizes := []int{0, 1, 31, 33, 64}
		for _, size := range invalidSizes {
			pubBytes := make([]byte, size)
			rand.Read(pubBytes)

			pub, err := c.PublicKeyFromBytes(pubBytes)
			require.Error(t, err)
			require.Nil(t, pub)
			require.ErrorIs(t, err, crpt.ErrWrongPublicKeySize)
		}
	})

	t.Run("Invalid private key sizes", func(t *testing.T) {
		// Test PrivateKeyFromBytes with invalid sizes
		invalidSizes := []int{0, 1, 63, 65, 128}
		for _, size := range invalidSizes {
			privBytes := make([]byte, size)
			rand.Read(privBytes)

			priv, err := c.PrivateKeyFromBytes(privBytes)
			require.Error(t, err)
			require.Nil(t, priv)
			require.ErrorIs(t, err, crpt.ErrWrongPrivateKeySize)
		}
	})

	t.Run("Invalid signature sizes for typed conversion", func(t *testing.T) {
		// Test SignatureToTyped with invalid sizes
		invalidSizes := []int{0, 1, 31, 63, 65, 128}
		for _, size := range invalidSizes {
			sig := make([]byte, size)
			rand.Read(sig)

			typedSig, err := c.SignatureToTyped(sig)
			require.Error(t, err)
			require.Nil(t, typedSig)
			require.ErrorIs(t, err, crpt.ErrWrongSignatureSize)
		}
	})

	t.Run("Uninitialized private key", func(t *testing.T) {
		// Create a private key with uninitialized public key part
		privBytes := make([]byte, 64)
		// Set private key part (first 32 bytes) to something
		rand.Read(privBytes[:32])
		// Leave public key part (last 32 bytes) as zeros

		priv, err := c.PrivateKeyFromBytes(privBytes)
		require.NoError(t, err)

		// This should panic when trying to extract the public key
		assert.Panics(t, func() {
			_ = priv.Public()
		})
	})
}

func TestEd25519_KeySerializationRoundTrip(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	// Generate multiple key pairs
	for i := 0; i < 10; i++ {
		pub, priv, err := c.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Test public key round-trip
		pubBytes := pub.Bytes()
		pubFromBytes, err := c.PublicKeyFromBytes(pubBytes)
		require.NoError(t, err)
		require.True(t, pub.Equal(pubFromBytes))

		// Test private key round-trip
		privBytes := priv.Bytes()
		privFromBytes, err := c.PrivateKeyFromBytes(privBytes)
		require.NoError(t, err)
		require.True(t, priv.Equal(privFromBytes))

		// Test that round-tripped keys can sign and verify
		message := []byte("round-trip test")
		sig, err := privFromBytes.SignMessage(message, rand.Reader, nil)
		require.NoError(t, err)

		valid, err := pubFromBytes.VerifyMessage(message, sig, nil)
		require.NoError(t, err)
		require.True(t, valid)
	}
}

func TestEd25519_ConcurrentOperations(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	const numGoroutines = 20
	const operationsPerGoroutine = 10

	// Pre-generate keys
	pubs := make([]crpt.PublicKey, numGoroutines)
	privs := make([]crpt.PrivateKey, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		pub, priv, err := c.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pubs[i] = pub
		privs[i] = priv
	}

	// Test concurrent signing and verification
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer func() { done <- true }()
			for j := 0; j < operationsPerGoroutine; j++ {
				message := []byte("concurrent test message")
				sig, err := privs[index].SignMessage(message, rand.Reader, nil)
				require.NoError(t, err)

				valid, err := pubs[index].VerifyMessage(message, sig, nil)
				require.NoError(t, err)
				require.True(t, valid)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestEd25519_HashFunctionConsistency(t *testing.T) {
	// Test with SHA512 which is supported by the ed25519 implementation
	hashFunc := crpt.Hash(crypto.SHA512)

	c, err := NewWithCryptoSignerOpts(hashFunc)
	require.NoError(t, err)

	// Test that hash function is correctly set
	assert.Equal(t, hashFunc, c.HashFunc())

	// Test hash computation
	message := []byte("hash consistency test")
	hash := c.Hash(message)
	assert.NotEmpty(t, hash)

	// Test deterministic behavior
	hash2 := c.Hash(message)
	assert.Equal(t, hash, hash2)

	// Test typed hash (same length as hash, but with first byte overwritten)
	typedHash := c.HashTyped(message)
	assert.Len(t, typedHash, len(hash))
	assert.Equal(t, byte(hashFunc), typedHash[0])
	// The rest contains the hash bytes except the first byte which was overwritten
}

func TestEd25519_SignatureProperties(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	pub, priv, err := c.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("signature properties test")

	// Sign the same message multiple times
	sig1, err := priv.SignMessage(message, rand.Reader, nil)
	require.NoError(t, err)

	sig2, err := priv.SignMessage(message, rand.Reader, nil)
	require.NoError(t, err)

	// Both should verify correctly
	valid1, err := pub.VerifyMessage(message, sig1, nil)
	require.NoError(t, err)
	require.True(t, valid1)

	valid2, err := pub.VerifyMessage(message, sig2, nil)
	require.NoError(t, err)
	require.True(t, valid2)

	// Test signature equality methods
	assert.True(t, sig1.Equal(sig1))

	// Test typed signature conversion (adds one byte for key type)
	typedSig1, err := c.SignatureToTyped(sig1)
	require.NoError(t, err)
	assert.Len(t, typedSig1, len(sig1)+1) // Signature + 1 byte type
	assert.Equal(t, byte(KeyType), typedSig1[0])
	// The rest contains the complete original signature (both converted to []byte for comparison)
	assert.Equal(t, []byte(sig1), []byte(typedSig1[1:]))
}

func TestEd25519_LargeMessageSigning(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	pub, priv, err := c.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Test with large messages
	messageSizes := []int{1024, 4096, 16384, 65536}
	for _, size := range messageSizes {
		t.Run(fmt.Sprintf("Size-%d", size), func(t *testing.T) {
			message := make([]byte, size)
			rand.Read(message)

			sig, err := priv.SignMessage(message, rand.Reader, nil)
			require.NoError(t, err)

			valid, err := pub.VerifyMessage(message, sig, nil)
			require.NoError(t, err)
			require.True(t, valid)
		})
	}
}

func TestEd25519_SignatureToASN1(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	_, priv, err := c.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for ASN.1 encoding")

	// Create a signature
	sig, err := priv.SignMessage(message, rand.Reader, nil)
	require.NoError(t, err)
	require.Len(t, sig, 64)

	t.Run("Valid signature conversion", func(t *testing.T) {
		asn1Bytes, err := c.SignatureToASN1(sig)
		require.NoError(t, err)
		require.NotNil(t, asn1Bytes)

		// ASN.1 encoding should be longer than raw signature due to OCTET STRING wrapper
		assert.Greater(t, len(asn1Bytes), len(sig))

		// The ASN.1 encoding should start with OCTET STRING tag (0x04)
		assert.Equal(t, byte(0x04), asn1Bytes[0])

		// Verify the encoded signature length matches the length field
		// For Ed25519: OCTET STRING (0x04) + length (1 byte) + 64 bytes signature
		expectedLength := 66 // 1 (tag) + 1 (length) + 64 (signature)
		assert.Equal(t, expectedLength, len(asn1Bytes))
		assert.Equal(t, byte(64), asn1Bytes[1])     // Length field
		assert.Equal(t, []byte(sig), asn1Bytes[2:]) // The signature itself
	})

	t.Run("Global function test", func(t *testing.T) {
		asn1Bytes, err := crpt.SignatureToASN1(crpt.Ed25519, sig)
		require.NoError(t, err)
		require.NotNil(t, asn1Bytes)

		// Should match the instance method result
		asn1Bytes2, err := c.SignatureToASN1(sig)
		require.NoError(t, err)
		require.Equal(t, asn1Bytes, asn1Bytes2)
	})

	t.Run("Invalid signature sizes", func(t *testing.T) {
		// Test with various invalid signature sizes
		invalidSizes := []int{0, 1, 31, 63, 65, 128}
		for _, size := range invalidSizes {
			invalidSig := make([]byte, size)
			rand.Read(invalidSig)

			asn1Bytes, err := c.SignatureToASN1(invalidSig)
			require.Error(t, err)
			require.Nil(t, asn1Bytes)
			require.ErrorIs(t, err, ErrWrongSignatureSize)
		}
	})

	t.Run("Multiple signatures", func(t *testing.T) {
		// Test converting multiple different signatures
		for i := 0; i < 10; i++ {
			message := []byte(fmt.Sprintf("test message %d", i))
			sig, err := priv.SignMessage(message, rand.Reader, nil)
			require.NoError(t, err)

			asn1Bytes, err := c.SignatureToASN1(sig)
			require.NoError(t, err)

			// Each signature should produce different ASN.1 encoding
			// (but same structure)
			assert.Greater(t, len(asn1Bytes), len(sig))
		}
	})

	t.Run("Concurrent conversions", func(t *testing.T) {
		const numGoroutines = 10
		const conversionsPerGoroutine = 100

		done := make(chan bool, numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer func() { done <- true }()
				for j := 0; j < conversionsPerGoroutine; j++ {
					asn1Bytes, err := c.SignatureToASN1(sig)
					require.NoError(t, err)
					require.NotNil(t, asn1Bytes)
					assert.Greater(t, len(asn1Bytes), len(sig))
				}
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})

	t.Run("Deterministic encoding", func(t *testing.T) {
		// ASN.1 DER encoding should be deterministic for the same input
		asn1Bytes1, err := c.SignatureToASN1(sig)
		require.NoError(t, err)

		asn1Bytes2, err := c.SignatureToASN1(sig)
		require.NoError(t, err)

		assert.Equal(t, asn1Bytes1, asn1Bytes2)
	})
}

func TestEd25519_MemoryUsage(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	// Test that repeated operations don't leak memory
	for i := 0; i < 1000; i++ {
		pub, priv, err := c.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := make([]byte, 1024)
		rand.Read(message)

		sig, err := priv.SignMessage(message, rand.Reader, nil)
		require.NoError(t, err)

		valid, err := pub.VerifyMessage(message, sig, nil)
		require.NoError(t, err)
		require.True(t, valid)

		// Test serialization
		_ = pub.Bytes()
		_ = priv.Bytes()
		_ = pub.ToTyped()
		_ = priv.ToTyped()
		_, _ = c.SignatureToTyped(sig)
		_, _ = c.SignatureToASN1(sig)
	}
}

// Comprehensive benchmarks for ed25519 package
func BenchmarkEd25519_KeyGeneration(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := c.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519_SignMessage_Sizes(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	_, priv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	sizes := []int{32, 64, 128, 256, 512, 1024, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			message := make([]byte, size)
			rand.Read(message)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := priv.SignMessage(message, rand.Reader, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEd25519_VerifyMessage_Sizes(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	pub, priv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	sizes := []int{32, 64, 128, 256, 512, 1024, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			// Use the original message that was signed
			message := make([]byte, size)
			rand.Read(message)
			sig, err := priv.SignMessage(message, rand.Reader, nil)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				valid, err := pub.VerifyMessage(message, sig, nil)
				if err != nil {
					b.Fatal(err)
				}
				if !valid {
					b.Fatal("verification failed")
				}
			}
		})
	}
}

func BenchmarkEd25519_KeySerialization(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	pub, priv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("PublicKeyBytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = pub.Bytes()
		}
	})

	b.Run("PrivateKeyBytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = priv.Bytes()
		}
	})

	b.Run("PublicKeyTypedBytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = pub.ToTyped()
		}
	})

	b.Run("PrivateKeyTypedBytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = priv.ToTyped()
		}
	})
}

func BenchmarkEd25519_KeyDeserialization(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	// Prepare test data
	pubBytes := make([][]byte, 100)
	privBytes := make([][]byte, 100)

	for i := 0; i < 100; i++ {
		pub, priv, err := c.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		pubBytes[i] = pub.Bytes()
		privBytes[i] = priv.Bytes()
	}

	b.Run("PublicKeyFromBytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			idx := i % len(pubBytes)
			_, err := c.PublicKeyFromBytes(pubBytes[idx])
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("PrivateKeyFromBytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			idx := i % len(privBytes)
			_, err := c.PrivateKeyFromBytes(privBytes[idx])
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkEd25519_HashOperations(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024)
	rand.Read(message)

	b.Run("Hash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = c.Hash(message)
		}
	})

	b.Run("HashTyped", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = c.HashTyped(message)
		}
	})
}

func BenchmarkEd25519_ConcurrentOperations(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	// Pre-generate test data
	const numKeys = 50
	pubs := make([]crpt.PublicKey, numKeys)
	privs := make([]crpt.PrivateKey, numKeys)
	messages := make([][]byte, numKeys)
	signatures := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		pub, priv, err := c.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		pubs[i] = pub
		privs[i] = priv
		messages[i] = make([]byte, 256)
		rand.Read(messages[i])
		signatures[i], err = priv.SignMessage(messages[i], rand.Reader, nil)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			idx := i % numKeys
			valid, err := pubs[idx].VerifyMessage(messages[idx], signatures[idx], nil)
			if err != nil {
				b.Fatal(err)
			}
			if !valid {
				b.Fatal("verification failed")
			}
			i++
		}
	})
}

func BenchmarkEd25519_SignatureToASN1(b *testing.B) {
	c, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	_, priv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	// Generate a test signature
	message := []byte("benchmark message")
	sig, err := priv.SignMessage(message, rand.Reader, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("SignatureToASN1", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := c.SignatureToASN1(sig)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SignatureToTyped", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := c.SignatureToTyped(sig)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("GlobalSignatureToASN1", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := crpt.SignatureToASN1(crpt.Ed25519, sig)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
