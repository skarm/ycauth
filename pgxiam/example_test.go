package pgxiam_test

import (
	"context"
	"log"
	"time"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/pgxiam"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

func ExampleConfigurePool() {
	provider := exampleProvider()
	config, err := pgxpool.ParseConfig("postgres://service-account-id@proxy.example.test/database?sslmode=verify-full")
	if err != nil {
		log.Fatal(err)
	}
	pgxiam.ConfigurePool(config, provider)

	// pgxpool.NewWithConfig(ctx, config) creates the pool. BeforeConnect obtains
	// a current token for each new physical connection.
	_ = config
}

func ExampleStdlibOption() {
	provider := exampleProvider()
	config, err := pgx.ParseConfig("postgres://service-account-id@proxy.example.test/database?sslmode=verify-full")
	if err != nil {
		log.Fatal(err)
	}

	db := stdlib.OpenDB(*config, pgxiam.StdlibOption(provider))
	defer func() { _ = db.Close() }()
	// db.PingContext(ctx) establishes and verifies the first physical connection.
}

func exampleProvider() ycauth.TokenProvider {
	return ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})
}
