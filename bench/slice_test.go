package bench

import (
	"crypto/rand"
	"fmt"
	"testing"
)

type sholder struct {
	s []byte
	r []byte
}

func BenchmarkSliceGet(b *testing.B) {
	s := make([]byte, 33)
	rand.Read(s)
	r := s[1:33]
	sh := sholder{s, r}

	b.Run("re-slice * 100000", func(b *testing.B) {
		for n := 0; n < b.N*100000; n++ {
			r := s[1:33]
			if len(r) == 0 {
				fmt.Println(r)
			}
		}
	})

	b.Run("holder * 100000", func(b *testing.B) {
		for n := 0; n < b.N*100000; n++ {
			if len(sh.r) == 0 {
				fmt.Println(sh.r)
			}
		}
	})

	b.Run("copy", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			r := make([]byte, 32)
			copy(r, s[1:33])
			if len(r) == 0 {
				fmt.Println(r)
			}
		}
	})
}

func BenchmarkHolderCreate(b *testing.B) {
	b.Run("slice * 10000", func(b *testing.B) {
		for n := 0; n < b.N*10000; n++ {
			s := make([]byte, 33)
			rand.Read(s)
			if len(s) == 0 {
				fmt.Println(s)
			}
		}
	})

	b.Run("holder * 10000", func(b *testing.B) {
		for n := 0; n < b.N*10000; n++ {
			s := make([]byte, 33)
			rand.Read(s)
			r := s[1:33]
			sh := sholder{s, r}
			if len(sh.r) == 0 {
				fmt.Println(sh.r)
			}
		}
	})
}
