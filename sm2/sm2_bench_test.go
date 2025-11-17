package sm2

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/crpt/go-crpt"
)

// BenchmarkGenerateKey benchmarks SM2 key generation.
func BenchmarkGenerateKey(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, _, err := crypt.GenerateKey(rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignMessage benchmarks SM2 message signing.
func BenchmarkSignMessage(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	_, priv, err := crypt.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for signing")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := priv.SignMessage(msg, rand.Reader, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignDigest benchmarks SM2 digest signing.
func BenchmarkSignDigest(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	_, priv, err := crypt.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	digest := crypt.Hash([]byte("benchmark digest"))

	b.ReportAllocs()
	b.ResetTimer()
	opts := NewSignerOpts(false, nil, crpt.Hash(crypto.SHA256))
	for i := 0; i < b.N; i++ {
		if _, err := priv.SignDigest(digest, rand.Reader, opts); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyMessage benchmarks SM2 verification.
func BenchmarkVerifyMessage(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	pub, priv, err := crypt.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for verification")
	sig, err := priv.SignMessage(msg, rand.Reader, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := pub.VerifyMessage(msg, sig, nil)
		if err != nil {
			b.Fatal(err)
		}
		if !ok {
			b.Fatal("verification failed")
		}
	}
}

// BenchmarkHash benchmarks SM2 hash helper.
func BenchmarkHash(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark hashing input")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = crypt.Hash(msg)
	}
}

// BenchmarkConcurrentVerify benchmarks verifying signatures in parallel.
func BenchmarkConcurrentVerify(b *testing.B) {
	crypt, err := New(nil)
	if err != nil {
		b.Fatal(err)
	}

	const keyCount = 8
	pubs := make([]crpt.PublicKey, keyCount)
	privs := make([]crpt.PrivateKey, keyCount)
	msgs := make([][]byte, keyCount)
	sigs := make([][]byte, keyCount)

	for i := 0; i < keyCount; i++ {
		cpub, cpriv, err := crypt.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		pubs[i] = cpub
		privs[i] = cpriv
		msgs[i] = []byte("parallel benchmark message")
		sigs[i], err = cpriv.SignMessage(msgs[i], rand.Reader, nil)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		idx := 0
		for pb.Next() {
			current := idx % keyCount
			ok, err := pubs[current].VerifyMessage(msgs[current], sigs[current], nil)
			if err != nil {
				b.Fatal(err)
			}
			if !ok {
				b.Fatal("verification failed")
			}
			idx++
		}
	})
}
