package main

import (
	"crypto"
	"fmt"
	"reflect"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

type SignerOpts = ed25519.Options

func BenchmarkNilCheck(b *testing.B) {
	var nilInterface crypto.SignerOpts = nil
	var nilPointer *SignerOpts = nil

	// Convert nil pointer to interface (this is the problematic case)
	var interfaceWithNilPointer crypto.SignerOpts = nilPointer

	b.Run("direct_nil_check", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = nilInterface == nil
		}
	})

	b.Run("reflection_nil_check", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = reflect.ValueOf(interfaceWithNilPointer).IsNil()
		}
	})

	b.Run("type_assertion_nil_check", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if opts, ok := interfaceWithNilPointer.(*SignerOpts); ok {
				_ = opts == nil
			}
		}
	})
}

func ExampleNilCheckBehavior() {
	var nilInterface crypto.SignerOpts = nil
	var nilPointer *SignerOpts = nil
	var interfaceWithNilPointer crypto.SignerOpts = nilPointer

	fmt.Println("Direct nil interface check:", nilInterface == nil)                    // true
	fmt.Println("Interface with nil pointer check:", interfaceWithNilPointer == nil)   // false
	fmt.Println("Reflection check:", reflect.ValueOf(interfaceWithNilPointer).IsNil()) // true

	// Type assertion approach
	if opts, ok := interfaceWithNilPointer.(*SignerOpts); ok {
		fmt.Println("Type assertion check:", opts == nil) // true
	}
}
