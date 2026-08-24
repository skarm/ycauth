package imds_test

import (
	"log"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/imds"
)

func ExampleNew() {
	source, err := imds.New()
	if err != nil {
		log.Fatal(err)
	}

	var tokenSource ycauth.TokenSource = source
	_ = tokenSource
}
