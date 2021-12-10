// Copyright 2021 Nex Zhu. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crpt

import (
	"crypto"

	"github.com/multiformats/go-multihash"
)

// CryptoHashToMulticodec is the mapping from `crypto.Hash` to `multicodec`
// See: https://github.com/multiformats/multicodec/blob/master/table.csv
var CryptoHashToMulticodec = []uint64{
	0,
	0xd4,   // MD4         Hash = 1 + iota // import golang.org/x/crypto/md4
	0xd5,   // MD5                         // import crypto/md5
	0x11,   // SHA1                        // import crypto/sha1
	0x1013, // SHA224                      // import crypto/sha256
	0x12,   // SHA256                      // import crypto/sha256
	0x20,   // SHA384                      // import crypto/sha512
	0x13,   // SHA512                      // import crypto/sha512
	0,      // MD5SHA1                     // no implementation; MD5+SHA1 used for TLS RSA
	0x1053, // RIPEMD160                   // import golang.org/x/crypto/ripemd160
	0x17,   // SHA3_224                    // import golang.org/x/crypto/sha3
	0x16,   // SHA3_256                    // import golang.org/x/crypto/sha3
	0x15,   // SHA3_384                    // import golang.org/x/crypto/sha3
	0x14,   // SHA3_512                    // import golang.org/x/crypto/sha3
	0x1014, // SHA512_224                  // import crypto/sha512
	0x1015, // SHA512_256                  // import crypto/sha512
	0xb260, // BLAKE2s_256                 // import golang.org/x/crypto/blake2s
	0xb220, // BLAKE2b_256                 // import golang.org/x/crypto/blake2b
	0xb230, // BLAKE2b_384                 // import golang.org/x/crypto/blake2b
	0xb240, // BLAKE2b_512                 // import golang.org/x/crypto/blake2b
}

// MulticodecToCryptoHash is the mapping from `multicodec` to `crypto.Hash`
// See: https://github.com/multiformats/multicodec/blob/master/table.csv
var MulticodecToCryptoHash = map[uint64]crypto.Hash{
	multihash.SHA1:     crypto.SHA1,
	multihash.SHA2_256: crypto.SHA256,
	multihash.SHA2_512: crypto.SHA512,
	multihash.SHA3_224: crypto.SHA224,
	multihash.SHA3_256: crypto.SHA3_256,
	multihash.SHA3_384: crypto.SHA3_384,
	multihash.SHA3_512: crypto.SHA3_512,
	multihash.MD5:      crypto.MD5,
}
