// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package batch

import (
	"github.com/crpt/go-crpt"
	"github.com/crpt/go-crpt/ed25519"
	//"github.com/crpt/go-crpt/sr25519"
)

// NewBatchVerifier checks if a key type implements BatchVerifier interface.
// Currently only ed25519 & sr25519 supports batch verification.
func NewBatchVerifier(kt crpt.KeyType) (crpt.BatchVerifier, bool) {
	switch kt {
	case ed25519.KeyType:
		return ed25519.NewBatchVerifier(), true
	//case sr25519.KeyType:
	//	return sr25519.NewBatchVerifier(), true
	default:
		// no support for batch verification
		return nil, false
	}
}

// SupportsBatchVerifier checks if a key type implements BatchVerifier interface.
func SupportsBatchVerifier(kt crpt.KeyType) bool {
	switch kt {
	case ed25519.KeyType /*, sr25519.KeyType*/ :
		return true
	default:
		return false
	}
}
