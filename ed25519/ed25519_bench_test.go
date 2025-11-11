// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package ed25519

import (
	"crypto/rand"
	"testing"
)

// BenchmarkGenerateKey benchmarks key generation
func BenchmarkGenerateKey(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := crypt.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignMessage benchmarks message signing
func BenchmarkSignMessage(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	_, priv, err := crypt.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for signing")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := priv.SignMessage(message, rand.Reader, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyMessage benchmarks message verification
func BenchmarkVerifyMessage(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	pub, priv, err := crypt.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark message for verification")
	sig, err := priv.SignMessage(message, rand.Reader, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		valid, err := pub.VerifyMessage(message, sig, nil)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("verification failed")
		}
	}
}

// BenchmarkHash benchmarks hash computation
func BenchmarkHash(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("benchmark message for hashing")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = crypt.Hash(message)
	}
}

// BenchmarkBatchVerifier benchmarks batch verification
func BenchmarkBatchVerifier(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	// Prepare test data
	const batchSize = 100
	pubs := make([]PublicKey, batchSize)
	privs := make([]PrivateKey, batchSize)
	messages := make([][]byte, batchSize)
	signatures := make([][]byte, batchSize)

	for i := 0; i < batchSize; i++ {
		cpub, cpriv, err := crypt.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		// Convert to concrete types
		pubs[i] = cpub.(PublicKey)
		privs[i] = cpriv.(PrivateKey)
		messages[i] = []byte("benchmark message")
		signatures[i], err = cpriv.SignMessage(messages[i], rand.Reader, nil)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batchVerifier := NewBatchVerifier(nil)

		for j := 0; j < batchSize; j++ {
			err := batchVerifier.Add(pubs[j], messages[j], nil, signatures[j], nil)
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

// BenchmarkConcurrentOperations benchmarks concurrent crypto operations
func BenchmarkConcurrentOperations(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	// Prepare test data
	const numKeys = 10
	pubs := make([]PublicKey, numKeys)
	privs := make([]PrivateKey, numKeys)
	messages := make([][]byte, numKeys)
	signatures := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		cpub, cpriv, err := crypt.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		pubs[i] = cpub.(PublicKey)
		privs[i] = cpriv.(PrivateKey)
		messages[i] = []byte("concurrent benchmark message")
		signatures[i], err = cpriv.SignMessage(messages[i], rand.Reader, nil)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Round-robin through the test data
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
