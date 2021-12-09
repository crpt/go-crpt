// Copyright 2020 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crpt_test

import (
	"testing"

	. "github.com/crpt/go-crpt"
	_ "github.com/crpt/go-crpt/ed25519"
	"github.com/crpt/go-crpt/internal/test"
)

func BenchmarkCrpt(b *testing.B) {
	b.Run("SignMessage", func(b *testing.B) {
		test.BenchmarkSignMessage(b, nil, test.TestEd25519PrivateKeyTyped, Ed25519)
	})

	b.Run("Verify", func(b *testing.B) {
		test.BenchmarkVerify(b, nil, test.TestEd25519PrivateKeyTyped, Ed25519)
	})
}
