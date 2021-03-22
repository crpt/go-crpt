// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package ed25519

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nexzhu/go-crpt"
)

var (
	testPrivateKey = []byte{
		0x7c, 0xbf, 0x09, 0xb2, 0x31, 0x35, 0x7f, 0x05, 0xb2, 0xd7, 0xcf, 0x8a, 0x43, 0x9e, 0xbb, 0xa1,
		0x4f, 0x78, 0x80, 0x11, 0x5e, 0x26, 0x22, 0x34, 0x71, 0xf5, 0x69, 0xb7, 0x5d, 0x6f, 0xe7, 0x51,
		0xc4, 0xdf, 0xd5, 0x6d, 0x89, 0x28, 0x5d, 0x2d, 0x0f, 0x9a, 0x04, 0x12, 0x91, 0x48, 0x41, 0x22,
		0x3b, 0x94, 0x06, 0xdb, 0xaf, 0x6c, 0xe5, 0x13, 0x07, 0xba, 0x57, 0x5b, 0xa4, 0x4c, 0xe5, 0x5f,
	}
	testSha3PrivateKey = []byte{
		0x42, 0xeb, 0x4b, 0xbe, 0x27, 0x0c, 0x3c, 0xf5, 0x63, 0xf7, 0xf2, 0xdd, 0xfc, 0x9e, 0xef, 0xbc,
		0xa6, 0xc8, 0xf0, 0x66, 0xf3, 0x45, 0xbd, 0x77, 0xae, 0x44, 0xd5, 0x5c, 0x5e, 0x02, 0xe2, 0x70,
		0xac, 0x6d, 0x1b, 0x20, 0x52, 0x1f, 0x97, 0xa1, 0xa4, 0xcd, 0xb8, 0xd7, 0xc7, 0x94, 0x4a, 0xed,
		0x01, 0x51, 0xa9, 0x50, 0xa5, 0x66, 0xe0, 0x2a, 0x0e, 0xf9, 0x6a, 0x0d, 0x60, 0x98, 0x87, 0xb8,
	}
	testWrongData = []byte{0x1, 0x2, 0x3, 0x4}
)

func TestEd25519Crpt(t *testing.T) {
	assert := assert.New(t)

	c, err := New(false, crypto.SHA256)
	assert.NoError(err)
	c3, err := New(true, crypto.SHA3_256)
	assert.NoError(err)
	msg := []byte{0x1, 0x2, 0x3, 0x4}

	t.Run("publicKey/privateKey", func(t *testing.T) {
		pub, priv, err := c.GenerateKey(nil)
		assert.NoError(err)
		pub3, priv3, err := c3.GenerateKey(nil)
		assert.NoError(err)
		//fmt.Printf("%x", priv3.Bytes())
		//fmt.Println(base64.StdEncoding.EncodeToString(priv3.Bytes()))

		assert.ElementsMatch(pub, pub.Address())
		assert.ElementsMatch(pub3, pub3.Address())

		assert.Equal(pub, priv.Public())
		assert.Equal(pub3, priv3.Public())
	})

	t.Run("Hash", func(t *testing.T) {
		h := c.Hash(msg)
		hash := crypto.SHA256.New()
		hash.Write(msg)
		h_ := hash.Sum(nil)
		assert.Equal(h_, h)

		h3 := c3.Hash(msg)
		hash3 := crypto.SHA3_256.New()
		hash3.Write(msg)
		h3_ := hash3.Sum(nil)
		assert.Equal(h3_, h3)
	})

	t.Run("XxxFromBytes, SignXxx, Verify", func(t *testing.T) {
		priv, err := c.PrivateKeyFromBytes(testPrivateKey)
		assert.NoError(err)
		priv3, err := c3.PrivateKeyFromBytes(testSha3PrivateKey)
		assert.NoError(err)

		_, err = c.PrivateKeyFromBytes(testWrongData)
		assert.Equal(ErrWrongPrivateKeySize, err)
		_, err = c3.PrivateKeyFromBytes(testWrongData)
		assert.Equal(ErrWrongPrivateKeySize, err)

		_, err = c.PublicKeyFromBytes(testWrongData)
		assert.Equal(ErrWrongPublicKeySize, err)
		_, err = c3.PublicKeyFromBytes(testWrongData)
		assert.Equal(ErrWrongPublicKeySize, err)

		_, err = c.SignatureFromBytes(testWrongData)
		assert.Equal(ErrWrongSignatureSize, err)
		_, err = c3.SignatureFromBytes(testWrongData)
		assert.Equal(ErrWrongSignatureSize, err)

		pub := priv.Public()
		pub3 := priv3.Public()
		assert.NotEqual(pub, pub3)

		sig, err := c.Sign(priv, msg, nil, crpt.NotHashed, nil)
		assert.NoError(err)
		_, err = c.Sign(priv3, msg, nil, crpt.NotHashed, nil)
		assert.Equal(ErrNotEd25519PrivateKey, err)

		sig3, err := c3.Sign(priv3, msg, nil, crpt.NotHashed, nil)
		assert.NoError(err)
		_, err = c3.Sign(priv, msg, nil, crpt.NotHashed, nil)
		assert.Equal(ErrNotEd25519SHA3PrivateKey, err)

		assert.NotEqual(sig, sig3)

		sig_, err := c.SignMessage(priv, msg, nil)
		assert.NoError(err)
		assert.Equal(sig, sig_)
		sig3_, err := c3.SignMessage(priv3, msg, nil)
		assert.NoError(err)
		assert.Equal(sig3, sig3_)

		assert.Panics(func() { c.SignDigest(priv, msg, crpt.NotHashed, nil) },
			"calling SignDigest should panic")
		assert.Panics(func() { c3.SignDigest(priv3, msg, crpt.NotHashed, nil) },
			"calling SignDigest should panic")

		ok, err := c.Verify(pub, msg, sig)
		assert.NoError(err)
		assert.True(ok)
		ok, err = c.Verify(pub, msg, sig3)
		assert.NoError(err)
		assert.False(ok)
		_, err = c.Verify(pub3, msg, sig3)
		assert.Equal(ErrNotEd25519PublicKey, err)

		ok, err = c3.Verify(pub3, msg, sig3)
		assert.NoError(err)
		assert.True(ok)
		ok, err = c3.Verify(pub3, msg, sig)
		assert.NoError(err)
		assert.False(ok)
		_, err = c3.Verify(pub, msg, sig3)
		assert.Equal(ErrNotEd25519SHA3PublicKey, err)
	})
}
