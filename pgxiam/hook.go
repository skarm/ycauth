// Package pgxiam injects Yandex Cloud IAM tokens into new pgx connections.
// It does not own DSNs, TLS configuration, endpoint discovery, or pools.
//
// The package sends each token as a connection password. Configure the DSN
// username as the service account ID (not its name), and use
// sslmode=verify-full with the Yandex Cloud CA. The pgx default,
// sslmode=prefer, can fall back to an unencrypted connection. This package
// cannot detect that fallback because it receives the configuration, not the
// negotiated connection.
package pgxiam

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/skarm/ycauth"
)

// BeforeConnect returns a hook that obtains an IAM token immediately before a
// physical PostgreSQL connection is established. The hook writes the token only
// to the connection-local config passed by pgx.
//
// BeforeConnect panics if provider is nil.
func BeforeConnect(provider ycauth.TokenProvider) func(context.Context, *pgx.ConnConfig) error {
	if provider == nil {
		panic("pgxiam: token provider must not be nil")
	}

	return func(ctx context.Context, config *pgx.ConnConfig) error {
		token, err := provider.Token(ctx)
		if err != nil {
			return fmt.Errorf("get PostgreSQL IAM token: %w", err)
		}

		config.Password = token.Value

		return nil
	}
}

// ConfigurePool adds IAM authentication to config while preserving its existing
// BeforeConnect hook. The existing hook runs first; IAM credentials are
// injected last so a static password cannot overwrite them.
//
// ConfigurePool panics if config or provider is nil. Call it before using config
// to create a pool.
func ConfigurePool(config *pgxpool.Config, provider ycauth.TokenProvider) {
	if config == nil {
		panic("pgxiam: pool config must not be nil")
	}

	previous := config.BeforeConnect
	iamHook := BeforeConnect(provider)

	config.BeforeConnect = func(ctx context.Context, connection *pgx.ConnConfig) error {
		if previous != nil {
			if err := previous(ctx, connection); err != nil {
				return fmt.Errorf("run existing PostgreSQL BeforeConnect hook: %w", err)
			}
		}

		return iamHook(ctx, connection)
	}
}

// StdlibOption returns the database/sql pgx option for per-connection IAM
// authentication. Pass it to [stdlib.OpenDB]; sql.Open with a static DSN cannot
// rotate IAM tokens.
//
// StdlibOption panics if provider is nil.
func StdlibOption(provider ycauth.TokenProvider) stdlib.OptionOpenDB {
	return stdlib.OptionBeforeConnect(BeforeConnect(provider))
}
