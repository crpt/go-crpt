// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package factory

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crpt/go-crpt"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		keyType  crpt.KeyType
		hashFunc crypto.Hash
		wantErr  bool
		errType  error
	}{
		{
			name:     "Ed25519 with SHA256 should work",
			keyType:  crpt.Ed25519,
			hashFunc: crypto.SHA256,
			wantErr:  false,
		},
		{
			name:     "Ed25519 with SHA512 should work",
			keyType:  crpt.Ed25519,
			hashFunc: crypto.SHA512,
			wantErr:  false,
		},
		{
			name:     "Ed25519 with zero hash function should work",
			keyType:  crpt.Ed25519,
			hashFunc: 0,
			wantErr:  false,
		},
		{
			name:     "Invalid key type should fail",
			keyType:  crpt.MaxCrpt,
			hashFunc: crypto.SHA256,
			wantErr:  true,
			errType:  crpt.ErrKeyTypeNotSupported,
		},
		{
			name:     "Unknown key type should fail",
			keyType:  crpt.KeyType(255),
			hashFunc: crypto.SHA256,
			wantErr:  true,
			errType:  crpt.ErrKeyTypeNotSupported,
		},
		{
			name:     "Zero key type should fail",
			keyType:  crpt.KeyType(0),
			hashFunc: crypto.SHA256,
			wantErr:  true,
			errType:  crpt.ErrKeyTypeNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.keyType, tt.hashFunc)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)

				// Test that the returned instance works
				assert.Equal(t, tt.keyType, got.KeyType())
				assert.Equal(t, tt.hashFunc, got.HashFunc())

				// Test basic functionality
				pub, priv, err := got.GenerateKey(rand.Reader)
				assert.NoError(t, err)
				assert.NotNil(t, pub)
				assert.NotNil(t, priv)

				// Test signing and verification
				message := []byte("test message")
				sig, err := priv.SignMessage(message, rand.Reader, nil)
				assert.NoError(t, err)
				assert.NotNil(t, sig)

				valid, err := pub.VerifyMessage(message, sig, nil)
				assert.NoError(t, err)
				assert.True(t, valid)
			}
		})
	}
}

func TestMustNew(t *testing.T) {
	tests := []struct {
		name        string
		keyType     crpt.KeyType
		hashFunc    crypto.Hash
		shouldPanic bool
		panicMsg    string
	}{
		{
			name:        "Ed25519 with SHA256 should work",
			keyType:     crpt.Ed25519,
			hashFunc:    crypto.SHA256,
			shouldPanic: false,
		},
		{
			name:        "Ed25519 with SHA512 should work",
			keyType:     crpt.Ed25519,
			hashFunc:    crypto.SHA512,
			shouldPanic: false,
		},
		{
			name:        "Invalid key type should panic",
			keyType:     crpt.MaxCrpt,
			hashFunc:    crypto.SHA256,
			shouldPanic: true,
			panicMsg:    "key type not supported",
		},
		{
			name:        "Unknown key type should panic",
			keyType:     crpt.KeyType(255),
			hashFunc:    crypto.SHA256,
			shouldPanic: true,
			panicMsg:    "key type not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r != nil {
						if tt.panicMsg != "" {
							// Handle both string and error types in panic
							var panicStr string
							switch v := r.(type) {
							case string:
								panicStr = v
							case error:
								panicStr = v.Error()
							}
							assert.Contains(t, panicStr, tt.panicMsg)
						}
					} else {
						t.Errorf("Expected panic for key type %d", tt.keyType)
					}
				}()
			}

			crypt := MustNew(tt.keyType, tt.hashFunc)

			if !tt.shouldPanic {
				assert.NotNil(t, crypt)
				assert.Equal(t, tt.keyType, crypt.KeyType())
				assert.Equal(t, tt.hashFunc, crypt.HashFunc())
			}
		})
	}
}

func TestMustNew_HashFunctionPanic(t *testing.T) {
	// Test that MustNew panics when ed25519.New fails due to invalid hash function
	defer func() {
		if r := recover(); r != nil {
			// Expected to panic due to unavailable hash function
			assert.NotNil(t, r)
			// Check if it contains an error message (string or error type)
			switch v := r.(type) {
			case string:
				assert.Contains(t, v, crpt.ErrInvalidHashFunc.Error())
			case error:
				assert.Contains(t, v.Error(), crpt.ErrInvalidHashFunc.Error())
			default:
				t.Errorf("Expected panic to contain string or error, got %T", r)
			}
		} else {
			t.Error("Expected panic for unavailable hash function")
		}
	}()

	// Use a hash function that's likely not available
	unavailableHash := crypto.Hash(999)
	MustNew(crpt.Ed25519, unavailableHash)
}

func TestNewWithKeyTypeStr(t *testing.T) {
	tests := []struct {
		name       string
		keyTypeStr string
		hashFunc   crypto.Hash
		wantErr    bool
		errType    error
	}{
		{
			name:       "Ed25519 string with SHA256 should work",
			keyTypeStr: "Ed25519",
			hashFunc:   crypto.SHA256,
			wantErr:    false,
		},
		{
			name:       "Ed25519 string with SHA512 should work",
			keyTypeStr: "Ed25519",
			hashFunc:   crypto.SHA512,
			wantErr:    false,
		},
		{
			name:       "Ed25519 string with zero hash function should work",
			keyTypeStr: "Ed25519",
			hashFunc:   0,
			wantErr:    false,
		},
		{
			name:       "SM2 string with SHA256 should work",
			keyTypeStr: "SM2",
			hashFunc:   crypto.SHA256,
			wantErr:    false,
		},
		{
			name:       "SM2 string with SHA512 should work",
			keyTypeStr: "SM2",
			hashFunc:   crypto.SHA512,
			wantErr:    false,
		},
		{
			name:       "Invalid key type string should fail",
			keyTypeStr: "InvalidType",
			hashFunc:   crypto.SHA256,
			wantErr:    true,
			errType:    crpt.ErrKeyTypeNotSupported,
		},
		{
			name:       "Empty key type string should fail",
			keyTypeStr: "",
			hashFunc:   crypto.SHA256,
			wantErr:    true,
			errType:    crpt.ErrKeyTypeNotSupported,
		},
		{
			name:       "Case sensitive Ed25519 lowercase should fail",
			keyTypeStr: "ed25519",
			hashFunc:   crypto.SHA256,
			wantErr:    true,
			errType:    crpt.ErrKeyTypeNotSupported,
		},
		{
			name:       "Case sensitive SM2 lowercase should fail",
			keyTypeStr: "sm2",
			hashFunc:   crypto.SHA256,
			wantErr:    true,
			errType:    crpt.ErrKeyTypeNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewWithKeyTypeStr(tt.keyTypeStr, tt.hashFunc)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)

				// Test that the returned instance works
				expectedKeyType := crpt.StrToKeyType[tt.keyTypeStr]
				assert.Equal(t, expectedKeyType, got.KeyType())
				assert.Equal(t, tt.hashFunc, got.HashFunc())

				// Test basic functionality
				pub, priv, err := got.GenerateKey(rand.Reader)
				assert.NoError(t, err)
				assert.NotNil(t, pub)
				assert.NotNil(t, priv)

				// Test signing and verification
				message := []byte("test message")
				sig, err := priv.SignMessage(message, rand.Reader, nil)
				assert.NoError(t, err)
				assert.NotNil(t, sig)

				valid, err := pub.VerifyMessage(message, sig, nil)
				assert.NoError(t, err)
				assert.True(t, valid)
			}
		})
	}
}

func TestMustNewWithKeyTypeStr(t *testing.T) {
	tests := []struct {
		name        string
		keyTypeStr  string
		hashFunc    crypto.Hash
		shouldPanic bool
	}{
		{
			name:        "Ed25519 string with SHA256 should not panic",
			keyTypeStr:  "Ed25519",
			hashFunc:    crypto.SHA256,
			shouldPanic: false,
		},
		{
			name:        "Ed25519 string with SHA512 should not panic",
			keyTypeStr:  "Ed25519",
			hashFunc:    crypto.SHA512,
			shouldPanic: false,
		},
		{
			name:        "SM2 string with SHA256 should not panic",
			keyTypeStr:  "SM2",
			hashFunc:    crypto.SHA256,
			shouldPanic: false,
		},
		{
			name:        "Invalid key type string should panic",
			keyTypeStr:  "InvalidType",
			hashFunc:    crypto.SHA256,
			shouldPanic: true,
		},
		{
			name:        "Empty key type string should panic",
			keyTypeStr:  "",
			hashFunc:    crypto.SHA256,
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				assert.Panics(t, func() {
					MustNewWithKeyTypeStr(tt.keyTypeStr, tt.hashFunc)
				})
			} else {
				assert.NotPanics(t, func() {
					crypt := MustNewWithKeyTypeStr(tt.keyTypeStr, tt.hashFunc)
					assert.NotNil(t, crypt)

					// Test that the returned instance works
					expectedKeyType := crpt.StrToKeyType[tt.keyTypeStr]
					assert.Equal(t, expectedKeyType, crypt.KeyType())
					assert.Equal(t, tt.hashFunc, crypt.HashFunc())

					// Test basic functionality
					pub, priv, err := crypt.GenerateKey(rand.Reader)
					assert.NoError(t, err)
					assert.NotNil(t, pub)
					assert.NotNil(t, priv)

					// Test signing and verification
					message := []byte("test message")
					sig, err := priv.SignMessage(message, rand.Reader, nil)
					assert.NoError(t, err)
					assert.NotNil(t, sig)

					valid, err := pub.VerifyMessage(message, sig, nil)
					assert.NoError(t, err)
					assert.True(t, valid)
				})
			}
		})
	}
}

func TestFactory_EdgeCases(t *testing.T) {
	t.Run("Multiple instances should be independent", func(t *testing.T) {
		crypt1, err := New(crpt.Ed25519, crypto.SHA512)
		require.NoError(t, err)

		crypt2, err := New(crpt.Ed25519, crypto.SHA512)
		require.NoError(t, err)

		// Generate different keys from each instance
		pub1, priv1, err := crypt1.GenerateKey(rand.Reader)
		require.NoError(t, err)

		pub2, priv2, err := crypt2.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Keys should be different
		assert.False(t, pub1.Equal(pub2))
		assert.False(t, priv1.Equal(priv2))

		// Signatures should work with their respective keys
		message := []byte("test message")
		sig1, err := priv1.SignMessage(message, rand.Reader, nil)
		require.NoError(t, err)

		sig2, err := priv2.SignMessage(message, rand.Reader, nil)
		require.NoError(t, err)

		// Verify signatures
		valid1, err := pub1.VerifyMessage(message, sig1, nil)
		require.NoError(t, err)
		assert.True(t, valid1)

		valid2, err := pub2.VerifyMessage(message, sig2, nil)
		require.NoError(t, err)
		assert.True(t, valid2)

		// Cross-verification should fail
		crossValid1, err := pub1.VerifyMessage(message, sig2, nil)
		require.NoError(t, err)
		assert.False(t, crossValid1)
	})

	t.Run("Different hash functions should work", func(t *testing.T) {
		hashFuncs := []crypto.Hash{
			crypto.SHA256,
			crypto.SHA512,
			0, // Zero hash function
		}

		for _, hf := range hashFuncs {
			crypt, err := New(crpt.Ed25519, hf)
			require.NoError(t, err)

			assert.Equal(t, crpt.Ed25519, crypt.KeyType())
			assert.Equal(t, hf, crypt.HashFunc())

			// Test basic functionality
			pub, priv, err := crypt.GenerateKey(rand.Reader)
			require.NoError(t, err)

			message := []byte("test message")
			sig, err := priv.SignMessage(message, rand.Reader, nil)
			require.NoError(t, err)

			valid, err := pub.VerifyMessage(message, sig, nil)
			require.NoError(t, err)
			assert.True(t, valid)
		}
	})
}
