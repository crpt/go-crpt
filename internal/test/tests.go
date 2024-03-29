// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package test

import (
	"bytes"
	"crypto"
	_ "crypto/sha512"
	"fmt"
	"github.com/crpt/go-crpt/batch"
	"testing"

	"github.com/crpt/go-crpt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	h := TestHashFunc.New()
	h.Write(TestMsg)
	TestDigest = h.Sum(nil)
}

var (
	TestHashFunc          = crypto.SHA512
	TestEd25519PrivateKey = []byte{
		0x7c, 0xbf, 0x09, 0xb2, 0x31, 0x35, 0x7f, 0x05, 0xb2, 0xd7, 0xcf, 0x8a, 0x43, 0x9e, 0xbb, 0xa1,
		0x4f, 0x78, 0x80, 0x11, 0x5e, 0x26, 0x22, 0x34, 0x71, 0xf5, 0x69, 0xb7, 0x5d, 0x6f, 0xe7, 0x51,
		0xc4, 0xdf, 0xd5, 0x6d, 0x89, 0x28, 0x5d, 0x2d, 0x0f, 0x9a, 0x04, 0x12, 0x91, 0x48, 0x41, 0x22,
		0x3b, 0x94, 0x06, 0xdb, 0xaf, 0x6c, 0xe5, 0x13, 0x07, 0xba, 0x57, 0x5b, 0xa4, 0x4c, 0xe5, 0x5f,
	}
	TestEd25519PrivateKeyTyped = append([]byte{byte(crpt.Ed25519)}, TestEd25519PrivateKey...)
	TestWrongData              = []byte{0x1, 0x2, 0x3, 0x4}
	TestMsg                    = []byte{0x1, 0x2, 0x3, 0x4}
	TestDigest                 []byte
	TestMsg2                   = []byte{0x1, 0x2, 0x3, 0x4, 0x5}
)

func Test_Hash(t *testing.T, c crpt.Crpt) {
	assr := assert.New(t)

	h := c.Hash(TestMsg)
	ht := c.HashTyped(TestMsg)
	assr.Equal(byte(c.HashFunc()), ht[0])
	hash := c.HashFunc().New()
	hash.Write(TestMsg)
	h_ := hash.Sum(nil)
	assr.True(bytes.Equal(h_, h))
	assr.Equal(h_[1:], []byte(ht[1:]))

	randbin := []byte{0x1, 0x2, 0x3, 0x4}
	hash = c.HashFunc().New()
	hash.Write(TestMsg)
	h_ = c.SumHashTyped(hash, randbin)
	assr.Equal(byte(c.HashFunc()), h_[len(randbin)])
	assr.True(bytes.Equal(h_[len(randbin)+1:], h[1:]))
}

func Test_PrivateKey_PublicKey(t *testing.T, c crpt.Crpt) {
	req := require.New(t)
	assr := assert.New(t)

	pub, priv, err := c.GenerateKey(nil)
	req.NoError(err)
	//fmt.Printf("%x", priv.Bytes())
	//fmt.Println(base64.StdEncoding.EncodeToString(priv.Bytes()))
	assr.ElementsMatch(pub, pub.Address())
	assr.Equal(pub, priv.Public())

	pub2, priv2, err := c.GenerateKey(nil)
	req.NoError(err)
	assr.True(pub.Equal(pub))
	assr.False(pub.Equal(pub2))
	assr.False(pub2.Equal(pub))
	e := priv.Equal(priv)
	fmt.Println(e)
	assr.True(priv.Equal(priv))
	assr.False(priv.Equal(priv2))
	assr.False(priv2.Equal(priv))
}

func Test_XxxFromBytes_SignXxx_Verify(t *testing.T, c crpt.Crpt, privateKey []byte, kt crpt.KeyType) {
	req := require.New(t)
	assr := assert.New(t)

	var priv crpt.PrivateKey
	var err error
	if c != nil {
		priv, err = c.PrivateKeyFromBytes(privateKey)
	} else {
		priv, err = crpt.PrivateKeyFromTypedBytes(privateKey)
	}
	req.NoError(err)

	if c != nil {
		_, err = c.PrivateKeyFromBytes(TestWrongData)
	} else {
		_, err = crpt.PrivateKeyFromTypedBytes(TestWrongData)
	}
	assr.ErrorIs(err, crpt.ErrWrongPrivateKeySize)

	if c != nil {
		_, err = c.PublicKeyFromBytes(TestWrongData)
	} else {
		_, err = crpt.PublicKeyFromBytes(kt, TestWrongData)
	}
	assr.ErrorIs(err, crpt.ErrWrongPublicKeySize)

	if c != nil {
		_, err = c.SignatureToTyped(TestWrongData)
	} else {
		_, err = crpt.SignatureToTyped(kt, TestWrongData)
	}
	assr.ErrorIs(err, crpt.ErrWrongSignatureSize)

	var sig, sig2, sig_ crpt.Signature
	if c != nil {
		sig, err = c.Sign(priv, TestMsg, nil, crpt.NotHashed, nil)
		req.NoError(err)
		sig2, err = c.Sign(priv, TestMsg2, nil, crpt.NotHashed, nil)
		req.NoError(err)
	} else {
		sig, err = crpt.Sign(priv, TestMsg, nil, crpt.NotHashed, nil)
		req.NoError(err)
		sig2, err = crpt.Sign(priv, TestMsg2, nil, crpt.NotHashed, nil)
		req.NoError(err)
	}

	if c != nil {
		sig_, err = c.SignMessage(priv, TestMsg, nil)
	} else {
		sig_, err = crpt.SignMessage(priv, TestMsg, nil)
	}
	req.NoError(err)
	assr.Equal(sig, sig_)

	if c != nil {
		sig_, err = c.SignDigest(priv, TestDigest, TestHashFunc, nil)
	} else {
		sig_, err = crpt.SignDigest(priv, TestDigest, TestHashFunc, nil)
	}
	req.NoError(err)

	if c != nil {
		_, err = c.SignDigest(priv, TestMsg, crpt.NotHashed, nil)
	} else {
		_, err = crpt.SignDigest(priv, TestMsg, crpt.NotHashed, nil)
	}
	assr.ErrorIs(err, crpt.ErrInvalidHashFunc)

	pub := priv.Public()
	var ok bool
	if c != nil {
		ok, err = c.Verify(pub, TestMsg, nil, crpt.NotHashed, sig)
	} else {
		ok, err = crpt.Verify(pub, TestMsg, nil, crpt.NotHashed, sig)
	}
	assr.NoError(err)
	assr.True(ok)

	if c != nil {
		ok, err = c.Verify(pub, TestMsg, nil, crpt.NotHashed, sig2)
	} else {
		ok, err = crpt.Verify(pub, TestMsg, nil, crpt.NotHashed, sig2)
	}
	assr.NoError(err)
	assr.False(ok)

	if c != nil {
		ok, err = c.VerifyMessage(pub, TestMsg, sig)
	} else {
		ok, err = crpt.VerifyMessage(pub, TestMsg, sig)
	}
	assr.NoError(err)
	assr.True(ok)

	if c != nil {
		ok, err = c.VerifyMessage(pub, TestMsg, sig2)
	} else {
		ok, err = crpt.VerifyMessage(pub, TestMsg, sig2)
	}
	assr.NoError(err)
	assr.False(ok)

	if c != nil {
		ok, err = c.VerifyDigest(pub, TestDigest, TestHashFunc, sig_)
	} else {
		ok, err = crpt.VerifyDigest(pub, TestDigest, TestHashFunc, sig_)
	}
	assr.NoError(err)
	assr.True(ok)

	if c != nil {
		ok, err = c.VerifyDigest(pub, TestDigest, TestHashFunc, sig2)
	} else {
		ok, err = crpt.VerifyDigest(pub, TestDigest, TestHashFunc, sig2)
	}
	assr.NoError(err)
	assr.False(ok)
}

func Test_Batch(t *testing.T, c crpt.Crpt, kt crpt.KeyType) {
	req := require.New(t)

	v, ok := batch.NewBatchVerifier(kt)
	if !ok {
		return
	}

	var (
		pub  crpt.PublicKey
		priv crpt.PrivateKey
		err  error
	)
	for i := 0; i <= 38; i++ {
		if c != nil {
			pub, priv, err = c.GenerateKey(nil)
		} else {
			pub, priv, err = crpt.GenerateKey(kt, nil)
		}
		req.NoError(err)

		var msg []byte
		if i%2 == 0 {
			msg = []byte("easter")
		} else {
			msg = []byte("egg")
		}

		sig, err := priv.SignMessage(msg, nil)
		req.NoError(err)

		err = v.Add(pub, msg, sig)
		req.NoError(err)
	}

	ok, _ = v.Verify(nil)
	req.True(ok)
}
