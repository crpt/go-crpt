# go-crpt

**go-crpt** provides interfaces and implementations for common crypto operations in Go.

It's especially useful for DLT projects.

## Usage

See [godoc](https://pkg.go.dev/github.com/crpt/go-crpt).

## Currently available implementations:

## [ed25519](./ed25519/ed25519.go)

EPackage `ed25519` provides an Ed25519 implementation backed by
[curve25519-voi](https://github.com/oasisprotocol/curve25519-voi) package.

Note: earlier version of this package uses the following packages, replaced by
[curve25519-voi](https://github.com/oasisprotocol/curve25519-voi) because benchmarks show that it
has the better performance and supports signing pre-hashed messages by implementing
[Ed25519ph](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1).

Old docs:

> Package `ed25519` provides an Ed25519 implementation backed by [crypto/ed25519](https://pkg.go.dev/crypto/ed25519) std package,
but using [ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) package for signature verification,
which conforms to [ZIP 215](https://zips.z.cash/zip-0215) specification, making it suitable for consensus-critical contexts,
see [README from ed25519consensus](https://github.com/hdevalence/ed25519consensus) for the explanation.
>
> It also provides an Ed25519-SHA3-512 implementation backed by [go-ed25519-sha3-512](https://pkg.go.dev/github.com/crpt/go-ed25519-sha3-512) package,
which is a fork of [crypto/ed25519](https://pkg.go.dev/crypto/ed25519) std package, modified to use SHA3-512 instead of SHA-512.
using [go-ed25519consensus-sha3-512](https://pkg.go.dev/github.com/crpt/go-ed25519consensus-sha3-512) package for signature verification,
which is a fork of [ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) package, modified to use SHA3-512 instead of SHA-512.
So it's also suitable for consensus-critical contexts.
