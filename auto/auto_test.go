// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package auto_test

import (
	"crypto"
	"github.com/crpt/go-crpt/ed25519"
	"github.com/crpt/go-crpt/internal/test"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crpt/go-crpt"
	. "github.com/crpt/go-crpt/auto"
)

func TestAutoCrpt(t *testing.T) {
	req := require.New(t)
	assr := assert.New(t)

	c, err := New(crypto.SHA256)
	req.NoError(err)

	t.Run("KeyType & HashFunc", func(t *testing.T) {
		assr.Equal(crpt.Auto, c.KeyType())
		assr.Equal(crypto.SHA256, c.HashFunc())
	})

	t.Run("Hash", func(t *testing.T) {
		h := c.Hash(test.TestMsg)
		ht := c.HashTyped(test.TestMsg)
		hash := crypto.SHA256.New()
		hash.Write(test.TestMsg)
		h_ := hash.Sum(nil)
		assr.Equal(h_, h)
		assr.Equal(byte(crypto.SHA256), ht[0])
		assr.Equal(h_, []byte(ht[1:]))
	})

	t.Run("XxxFromBytes, SignXxx, Verify", func(t *testing.T) {
		test.Test_XxxFromBytes_SignXxx_Verify(t, c, test.TestEd25519PrivateKeyTyped, true)
		test.Test_XxxFromBytes_SignXxx_Verify(t, c, test.TestEd25519SHA3PrivateKeyTyped, true)

		ed25519crpt, err := ed25519.New(false, crypto.SHA256)
		req.NoError(err)
		priv, err := ed25519crpt.PrivateKeyFromBytes(test.TestEd25519PrivateKey)
		req.NoError(err)
		pub := priv.Public()

		ed25519sha3crpt, err := ed25519.New(true, crypto.SHA3_256)
		req.NoError(err)
		priv3, err := ed25519sha3crpt.PrivateKeyFromBytes(test.TestEd25519SHA3PrivateKey)
		req.NoError(err)
		sig3, err := c.Sign(priv3, test.TestMsg, nil, crpt.NotHashed, nil)
		req.NoError(err)

		ok, err := c.Verify(pub, test.TestMsg, sig3)
		assr.False(ok)
		assr.Equal(ErrKeyTypesDoesNotMatch, err)
	})
}
