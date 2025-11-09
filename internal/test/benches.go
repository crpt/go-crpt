// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package test

import (
	"testing"

	"github.com/crpt/go-crpt"
)

func BenchmarkSignMessage(b *testing.B, c crpt.Crpt, privateKey []byte, kt crpt.KeyType) {
	for i := 0; i < b.N*10000; i++ {
		var priv crpt.PrivateKey
		if c != nil {
			priv, _ = c.PrivateKeyFromBytes(privateKey)
		} else {
			priv, _ = crpt.PrivateKeyFromTyped(privateKey)
		}
		priv.SignMessage(TestMsg, nil)
	}
}

func BenchmarkVerify(b *testing.B, c crpt.Crpt, privateKey []byte, kt crpt.KeyType) {
	var priv crpt.PrivateKey
	if c != nil {
		priv, _ = c.PrivateKeyFromBytes(privateKey)
	} else {
		priv, _ = crpt.PrivateKeyFromTyped(privateKey)
	}
	sig, _ := priv.Sign(TestMsg, nil, crpt.NotHashed, nil)

	b.ResetTimer()
	for i := 0; i < b.N*10000; i++ {
		pub := priv.Public()
		pub.VerifyMessage(TestMsg, sig)
	}
}
