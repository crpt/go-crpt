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

	c, err := New(crypto.SHA256)
	req.NoError(err)

	t.Run("PublicKey/PrivateKey", func(t *testing.T) {
		test.Test_PrivateKey_PublicKey(t, c)
	})

	t.Run("KeyType & HashFunc", func(t *testing.T) {
		assr.Equal(crpt.Ed25519, c.KeyType())
		assr.Equal(crypto.SHA256, c.HashFunc())
	})

	t.Run("Hash", func(t *testing.T) {
		test.Test_Hash(t, c)
	})

	t.Run("XxxFromBytes, SignXxx, Verify", func(t *testing.T) {
		test.Test_XxxFromBytes_SignXxx_Verify(t, c, test.TestEd25519PrivateKey, crpt.Ed25519)

		//priv, err := c.PrivateKeyFromBytes(test.TestEd25519PrivateKey)
		//req.NoError(err)
		//priv3, err := c3.PrivateKeyFromBytes(test.TestEd25519SHA3PrivateKey)
		//req.NoError(err)
		//
		//pub := priv.Public()
		//pub3 := priv3.Public()
		//assr.NotEqual(pub, pub3)

		//_, err = c.Sign(priv3, test.TestMsg, nil, crpt.NotHashed, nil)
		//assr.Equal(ErrNotEd25519PrivateKey, err)

		//sig, err := c.Sign(priv, test.TestMsg, nil, crpt.NotHashed, nil)
		//req.NoError(err)
		//sig3, err := c3.Sign(priv3, test.TestMsg, nil, crpt.NotHashed, nil)
		//req.NoError(err)
		//assr.NotEqual(sig, sig3)

		//var ok bool
		//ok, err = c.Verify(pub3, test.TestMsg, sig3)
		//assr.False(ok)
		//assr.Equal(ErrNotEd25519PublicKey, err)
		//ok, err = c.Verify(pub, test.TestMsg, sig3)
		//assr.NoError(err)
		//assr.False(ok)

		//ok, err = c3.Verify(pub, test.TestMsg, sig3)
		//assr.False(ok)
		//assr.Equal(ErrNotEd25519SHA3PublicKey, err)
		//ok, err = c3.Verify(pub3, test.TestMsg, sig)
		//assr.NoError(err)
		//assr.False(ok)
	})

	t.Run("Batch", func(t *testing.T) {
		test.Test_Batch(t, c, crpt.Ed25519)
	})
}
