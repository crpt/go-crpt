package sm2_test

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/internal/test"
	. "github.com/crpt/go-crpt/sm2"
)

var testSM2PrivateKey = []byte{
	0xd6, 0x83, 0x35, 0x40, 0xd0, 0x19, 0xe0, 0x43,
	0x8a, 0x5d, 0xd7, 0x3b, 0x41, 0x4f, 0x26, 0xab,
	0x43, 0xd8, 0x06, 0x4b, 0x99, 0x67, 0x12, 0x06,
	0x94, 0x4e, 0x28, 0x4d, 0xbd, 0x96, 0x90, 0x93,
}

var (
	digestSHA256Opts = NewSignerOpts(false, nil, crpt.Hash(crypto.SHA256))
	digestSHA512Opts = NewSignerOpts(false, nil, crpt.Hash(crypto.SHA512))
)

func TestSM2Crpt(t *testing.T) {
	req := require.New(t)
	assr := assert.New(t)

	c, err := New(nil)
	req.NoError(err)

	t.Run("PublicKey/PrivateKey", func(t *testing.T) {
		test.Test_PrivateKey_PublicKey(t, c)
	})

	t.Run("KeyType & HashFunc", func(t *testing.T) {
		assr.Equal(crpt.SM2, c.KeyType())
		assr.Equal(crpt.Hash(crypto.SHA256), c.HashFunc())
	})

	t.Run("Hash helpers", func(t *testing.T) {
		test.Test_Hash(t, c)
	})

	t.Run("FromBytes/Sign/Verify", func(t *testing.T) {
		testSM2FromBytesSignVerify(t, c, testSM2PrivateKey)
	})

	t.Run("NewBatchVerifier", func(t *testing.T) {
		test.Test_NewBatchVerifier(t, c, crpt.SM2)
	})
}

func TestSM2_ErrorCases(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	t.Run("InvalidPublicKey", func(t *testing.T) {
		_, err := NewPublicKey(make([]byte, 10), c.SignerOpts())
		require.ErrorIs(t, err, ErrWrongPublicKeySize)
	})

	t.Run("InvalidPrivateKey", func(t *testing.T) {
		_, err := NewPrivateKey(make([]byte, 10), c.SignerOpts())
		require.ErrorIs(t, err, ErrWrongPrivateKeySize)
	})

	t.Run("SignatureConversionErrors", func(t *testing.T) {
		_, err := c.SignatureToTyped([]byte{0x01})
		require.ErrorIs(t, err, crpt.ErrWrongSignatureSize)

		_, err = c.SignatureToASN1([]byte{0x01})
		require.ErrorIs(t, err, crpt.ErrWrongSignatureSize)
	})

	t.Run("VerifyDigestWithBadSignature", func(t *testing.T) {
		pub, _, err := c.GenerateKey(rand.Reader)
		require.NoError(t, err)

		digest := make([]byte, 32)
		ok, err := pub.VerifyDigest(digest, []byte{0x30}, digestSHA256Opts)
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func TestSM2_KeySerializationRoundTrip(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		pub, priv, err := c.GenerateKey(rand.Reader)
		require.NoError(t, err)

		pubFromBytes, err := c.PublicKeyFromBytes(pub.Bytes())
		require.NoError(t, err)
		require.True(t, pub.Equal(pubFromBytes))

		privFromBytes, err := c.PrivateKeyFromBytes(priv.Bytes())
		require.NoError(t, err)
		require.True(t, priv.Equal(privFromBytes))

		message := []byte("round-trip test")
		sig, err := privFromBytes.SignMessage(message, rand.Reader, nil)
		require.NoError(t, err)

		ok, err := pubFromBytes.VerifyMessage(message, sig, nil)
		require.NoError(t, err)
		require.True(t, ok)
	}
}

func TestSM2_SignatureConversions(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)
	_, priv, err := c.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("signature conversions")
	sig, err := priv.SignMessage(message, rand.Reader, nil)
	require.NoError(t, err)

	typed, err := c.SignatureToTyped(sig)
	require.NoError(t, err)
	require.Equal(t, byte(KeyType), typed[0])
	require.Equal(t, sig, crpt.Signature(typed[1:]))

	asn1Copy, err := c.SignatureToASN1(sig)
	require.NoError(t, err)
	require.Equal(t, sig, crpt.Signature(asn1Copy))
	require.NotSame(t, &sig[0], &asn1Copy[0])
}

func TestSM2_CustomHashAndUID(t *testing.T) {
	opts := NewSignerOpts(true, []byte("custom-agent"), crpt.Hash(crypto.SHA512))
	c, err := New(opts)
	require.NoError(t, err)
	require.Equal(t, crpt.Hash(crypto.SHA512), c.HashFunc())

	pub, priv, err := c.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("custom hash and uid")
	sig, err := priv.SignMessage(message, rand.Reader, opts)
	require.NoError(t, err)

	ok, err := pub.VerifyMessage(message, sig, nil)
	require.NoError(t, err)
	require.True(t, ok)

	digest := c.Hash(message)
	digestSig, err := priv.SignDigest(digest, rand.Reader, digestSHA512Opts)
	require.NoError(t, err)

	ok, err = pub.VerifyDigest(digest, digestSig, digestSHA512Opts)
	require.NoError(t, err)
	require.True(t, ok)

	wrongDigest := append([]byte{}, digest...)
	wrongDigest[0] ^= 0xFF
	ok, err = pub.VerifyDigest(wrongDigest, digestSig, digestSHA512Opts)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestSM2_PublicKeyAddress(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)
	pub, _, err := c.GenerateKey(rand.Reader)
	require.NoError(t, err)

	address := pub.Address()
	require.Equal(t, pub.Bytes(), []byte(address))
}

func TestSM2_ConcurrentOperations(t *testing.T) {
	c, err := New(nil)
	require.NoError(t, err)

	const numGoroutines = 10
	pubs := make([]crpt.PublicKey, numGoroutines)
	privs := make([]crpt.PrivateKey, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		pub, priv, err := c.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pubs[i] = pub
		privs[i] = priv
	}

	var (
		wg    sync.WaitGroup
		errCh = make(chan error, numGoroutines)
	)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			message := []byte("concurrent message")
			for j := 0; j < 20; j++ {
				sig, err := privs[idx].SignMessage(message, rand.Reader, nil)
				if err != nil {
					errCh <- err
					return
				}
				ok, err := pubs[idx].VerifyMessage(message, sig, nil)
				if err != nil {
					errCh <- err
					return
				}
				if !ok {
					errCh <- fmt.Errorf("verification failed")
					return
				}
			}
			errCh <- nil
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

func testSM2FromBytesSignVerify(t *testing.T, c crpt.Crpt, privateKey []byte) {
	t.Helper()

	req := require.New(t)
	assr := assert.New(t)

	priv, err := c.PrivateKeyFromBytes(privateKey)
	req.NoError(err)

	_, err = c.PrivateKeyFromBytes(test.TestWrongData)
	assr.ErrorIs(err, crpt.ErrWrongPrivateKeySize)

	_, err = c.PublicKeyFromBytes(test.TestWrongData)
	assr.ErrorIs(err, crpt.ErrWrongPublicKeySize)

	_, err = c.SignatureToTyped(test.TestWrongData)
	assr.ErrorIs(err, crpt.ErrWrongSignatureSize)

	_, err = c.SignatureToASN1(test.TestWrongData)
	assr.ErrorIs(err, crpt.ErrWrongSignatureSize)

	message := []byte("sm2 message")
	message2 := []byte("sm2 alternate")

	sig1, err := priv.SignMessage(message, rand.Reader, nil)
	req.NoError(err)
	assr.NotZero(len(sig1))

	sig2, err := priv.SignMessage(message2, rand.Reader, nil)
	req.NoError(err)
	assr.NotZero(len(sig2))

	digest := c.Hash(message)
	sigDigest, err := priv.SignDigest(digest, rand.Reader, digestSHA256Opts)
	req.NoError(err)

	pub := priv.Public()

	ok, err := pub.VerifyMessage(message, sig1, nil)
	req.NoError(err)
	assr.True(ok)

	ok, err = pub.VerifyMessage(message, sig2, nil)
	req.NoError(err)
	assr.False(ok)

	ok, err = pub.VerifyDigest(digest, sigDigest, digestSHA256Opts)
	req.NoError(err)
	assr.True(ok)

	ok, err = pub.VerifyDigest(digest, sig2, digestSHA256Opts)
	req.NoError(err)
	assr.False(ok)

	typed, err := c.SignatureToTyped(sig1)
	req.NoError(err)
	assr.Equal(byte(KeyType), typed[0])
	assr.Equal(sig1, crpt.Signature(typed[1:]))

	asn1Copy, err := c.SignatureToASN1(sig1)
	req.NoError(err)
	assr.Equal(sig1, crpt.Signature(asn1Copy))
}
