// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package ed25519_test

import (
	"crypto"
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

	c, err := New(false, crypto.SHA256)
	req.NoError(err)
	c3, err := New(true, crypto.SHA3_256)
	req.NoError(err)

	t.Run("publicKey/privateKey", func(t *testing.T) {
		test.Test_PrivateKey_PublicKey(t, c)
		test.Test_PrivateKey_PublicKey(t, c3)
	})

	t.Run("KeyType & HashFunc", func(t *testing.T) {
		assr.Equal(crpt.Ed25519, c.KeyType())
		assr.Equal(crpt.Ed25519_SHA3_512, c3.KeyType())
		assr.Equal(crypto.SHA256, c.HashFunc())
		assr.Equal(crypto.SHA3_256, c3.HashFunc())
	})

	t.Run("Hash", func(t *testing.T) {
		test.Test_Hash(t, c)
		test.Test_Hash(t, c3)
	})

	t.Run("XxxFromBytes, SignXxx, Verify", func(t *testing.T) {
		test.Test_XxxFromBytes_SignXxx_Verify(t, c, test.TestEd25519PrivateKey, crpt.Ed25519)
		test.Test_XxxFromBytes_SignXxx_Verify(t, c3, test.TestEd25519SHA3PrivateKey, crpt.Ed25519_SHA3_512)

		priv, err := c.PrivateKeyFromBytes(test.TestEd25519PrivateKey)
		req.NoError(err)
		priv3, err := c3.PrivateKeyFromBytes(test.TestEd25519SHA3PrivateKey)
		req.NoError(err)

		pub := priv.Public()
		pub3 := priv3.Public()
		assr.NotEqual(pub, pub3)

		_, err = c.Sign(priv3, test.TestMsg, nil, crpt.NotHashed, nil)
		assr.Equal(ErrNotEd25519PrivateKey, err)

		sig, err := c.Sign(priv, test.TestMsg, nil, crpt.NotHashed, nil)
		req.NoError(err)
		sig3, err := c3.Sign(priv3, test.TestMsg, nil, crpt.NotHashed, nil)
		req.NoError(err)
		assr.NotEqual(sig, sig3)

		var ok bool
		ok, err = c.Verify(pub3, test.TestMsg, sig3)
		assr.False(ok)
		assr.Equal(ErrNotEd25519PublicKey, err)
		ok, err = c.Verify(pub, test.TestMsg, sig3)
		assr.False(ok)
		assr.Equal(ErrNotEd25519Signature, err)

		ok, err = c3.Verify(pub, test.TestMsg, sig3)
		assr.False(ok)
		assr.Equal(ErrNotEd25519SHA3PublicKey, err)
		ok, err = c3.Verify(pub3, test.TestMsg, sig)
		assr.False(ok)
		assr.Equal(ErrNotEd25519SHA3Signature, err)
	})
}
