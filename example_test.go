package ycauth_test

import (
	"context"
	"log"
	"time"

	"github.com/skarm/ycauth"
)

func ExampleNewCache() {
	source := ycauth.TokenSourceFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})

	provider, err := ycauth.NewCache(source, ycauth.CacheConfig{})
	if err != nil {
		log.Fatal(err)
	}

	_, _ = provider.Token(context.Background())
}
