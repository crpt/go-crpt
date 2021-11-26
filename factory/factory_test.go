// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package factory

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crpt/go-crpt"
)

const NonExistentKeyType = crpt.CurrentKeyTypeCount

func TestCrpt(t *testing.T) {
	assert := assert.New(t)

	_, err := New(crpt.Ed25519, crypto.SHA256)
	assert.NoError(err)

	_, err = New(crpt.Ed25519_SHA3_512, crypto.SHA3_256)
	assert.NoError(err)

	_, err = New(NonExistentKeyType, crypto.Hash(0))
	assert.Equal(crpt.ErrKeyTypeNotSupported, err)

	_, err = New(crpt.Ed25519, crypto.Hash(0))
	assert.Error(err)

	MustNew(crpt.Ed25519, crypto.SHA256)

	assert.Panics(func() {
		MustNew(NonExistentKeyType, crypto.SHA256)
	}, "should panic")

	assert.Panics(func() {
		MustNew(crpt.Ed25519, crypto.Hash(0))
	}, "should panic")
}
