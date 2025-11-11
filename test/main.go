package main

import (
	"crypto"
	"fmt"
	"reflect"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// type SignerOpts = ed25519.Options

// Type check
// var _ crypto.SignerOpts = (*SignerOpts)(nil)

func outer(nill *ed25519.Options) {
	fmt.Println(nill)
	fmt.Println(nill == nil)
	inner(nill)
}

func inner(nill crypto.SignerOpts) {
	fmt.Println(nill)
	fmt.Println(nill == nil) // This will fail

	// Fix: Use reflection to check if the underlying value is nil
	if nill == nil {
		fmt.Println("Interface is truly nil")
	} else if reflect.ValueOf(nill).IsNil() {
		fmt.Println("Interface contains nil pointer")
	} else {
		fmt.Println("Interface contains non-nil value")
	}
}

func main() {
	inner(nil)
	outer(nil)
}
