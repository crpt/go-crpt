// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package factory

import (
	"crypto"
	"github.com/nexzhu/go-crpt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCrpt(t *testing.T) {
	assert := assert.New(t)

	_, err := New(crpt.Ed25519, crypto.SHA256)
	assert.NoError(err)

	_, err = New(crpt.Ed25519_SHA3_512, crypto.SHA3_256)
	assert.NoError(err)

	_, err = New("NonExistentAlgorithm", crypto.Hash(0))
	assert.Equal(crpt.ErrAlgorithmNotSupported, err)

	_, err = New(crpt.Ed25519_SHA3_512, crypto.Hash(0))
	assert.Error(err)
}
