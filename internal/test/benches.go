package test

import (
	"github.com/crpt/go-crpt"
	"testing"
)

func BenchmarkSignMessage(b *testing.B, c crpt.Crpt, privateKey []byte, kt crpt.KeyType) {
	for i := 0; i < b.N*10000; i++ {
		var priv crpt.PrivateKey
		if c != nil {
			priv, _ = c.PrivateKeyFromBytes(privateKey)
		} else {
			priv, _ = crpt.PrivateKeyFromTypedBytes(privateKey)
		}

		if c != nil {
			c.SignMessage(priv, TestMsg, nil)
		} else {
			crpt.SignMessage(priv, TestMsg, nil)
		}
	}
}

func BenchmarkVerify(b *testing.B, c crpt.Crpt, privateKey []byte, kt crpt.KeyType) {
	var priv crpt.PrivateKey
	if c != nil {
		priv, _ = c.PrivateKeyFromBytes(privateKey)
	} else {
		priv, _ = crpt.PrivateKeyFromTypedBytes(privateKey)
	}

	var sig crpt.Signature
	if c != nil {
		sig, _ = c.Sign(priv, TestMsg, nil, crpt.NotHashed, nil)
	} else {
		sig, _ = crpt.Sign(priv, TestMsg, nil, crpt.NotHashed, nil)
	}

	b.ResetTimer()
	for i := 0; i < b.N*10000; i++ {
		pub := priv.Public()
		if c != nil {
			c.VerifyMessage(pub, TestMsg, sig)
		} else {
			crpt.VerifyMessage(pub, TestMsg, sig)
		}
	}
}
