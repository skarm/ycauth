package authzkey_test

import (
	"context"
	"log"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/authzkey"
)

func ExampleNewFile() {
	source, err := authzkey.NewFile("authorized-key.json")
	if err != nil {
		log.Fatal(err)
	}

	// Cache is the TokenProvider intended for request paths: it coalesces
	// refreshes and keeps the private-key exchange off the hot path.
	tokens, err := ycauth.NewCache(source, ycauth.CacheConfig{})
	if err != nil {
		log.Fatal(err)
	}

	token, err := tokens.Token(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Pass token.Value as a Bearer credential to the Yandex Cloud client that
	// needs it. Do not log or persist the value.
	_ = token.Value
}
