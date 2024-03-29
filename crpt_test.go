// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crpt_test

import (
	"testing"

	. "github.com/crpt/go-crpt"
	_ "github.com/crpt/go-crpt/ed25519"
	"github.com/crpt/go-crpt/internal/test"
)

func TestCrpt(t *testing.T) {
	t.Run("XxxFromBytes, SignXxx, Verify", func(t *testing.T) {
		test.Test_XxxFromBytes_SignXxx_Verify(t, nil, test.TestEd25519PrivateKeyTyped, Ed25519)
	})

	t.Run("Batch", func(t *testing.T) {
		test.Test_Batch(t, nil, Ed25519)
	})
}
