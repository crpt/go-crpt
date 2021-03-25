# go-crpt

**go-crpt** provides interfaces and implementations for common crypto operations in Go.

It's especially useful for DLT projects.

## Usage

See [godoc](https://pkg.go.dev/github.com/crpt/go-crpt).

## Currently available implementations:

- Package `ed25519` provides the Ed25519 implementation backed by
  [crypto/ed25519](https://pkg.go.dev/crypto/ed25519), and the Ed25519-SHA3-512 implementation backd
  by [github.com/crpt/go-ed25519-sha3-512](https://pkg.go.dev/github.com/crpt/go-ed25519-sha3-512).
