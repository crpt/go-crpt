package sm3

import (
	gsm3 "github.com/emmansun/gmsm/sm3"

	"github.com/crpt/go-crpt"
)

func init() {
	crpt.RegisterHash(crpt.SM3, gsm3.New)
}
