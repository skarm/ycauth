package pgxiam_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/pgxiam"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBeforeConnect(t *testing.T) {
	t.Parallel()

	config, err := pgx.ParseConfig("postgres://user:static@localhost/database")
	if err != nil {
		t.Fatalf("pgx.ParseConfig() error = %v", err)
	}
	provider := ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	if err := pgxiam.BeforeConnect(provider)(context.Background(), config); err != nil {
		t.Fatalf("BeforeConnect() error = %v", err)
	}
	if config.Password != "iam-token" {
		t.Fatalf("password = %q, want IAM token", config.Password)
	}
}

func TestBeforeConnectGetsTokenForEveryConnection(t *testing.T) {
	t.Parallel()

	base, err := pgx.ParseConfig("postgres://user:static@localhost/database")
	if err != nil {
		t.Fatalf("pgx.ParseConfig() error = %v", err)
	}
	calls := 0
	hook := pgxiam.BeforeConnect(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		calls++
		return ycauth.Token{Value: "iam-token-" + strconv.Itoa(calls), ExpiresAt: time.Now().Add(time.Hour)}, nil
	}))
	first := base.Copy()
	second := base.Copy()
	if err := hook(context.Background(), first); err != nil {
		t.Fatalf("first BeforeConnect() error = %v", err)
	}
	if err := hook(context.Background(), second); err != nil {
		t.Fatalf("second BeforeConnect() error = %v", err)
	}
	if first.Password != "iam-token-1" || second.Password != "iam-token-2" || calls != 2 {
		t.Fatalf("passwords = (%q, %q), calls = %d", first.Password, second.Password, calls)
	}
}

func TestBeforeConnectError(t *testing.T) {
	t.Parallel()

	sourceErr := errors.New("token unavailable")
	config, err := pgx.ParseConfig("postgres://user@localhost/database")
	if err != nil {
		t.Fatalf("pgx.ParseConfig() error = %v", err)
	}
	hook := pgxiam.BeforeConnect(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{}, sourceErr
	}))
	if err := hook(context.Background(), config); !errors.Is(err, sourceErr) {
		t.Fatalf("BeforeConnect() error = %v, want wrapped source error", err)
	}
}

func TestConfigurePoolPreservesExistingHook(t *testing.T) {
	t.Parallel()

	config, err := pgxpool.ParseConfig("postgres://user:static@localhost/database")
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig() error = %v", err)
	}
	previousCalled := false
	config.BeforeConnect = func(_ context.Context, connection *pgx.ConnConfig) error {
		previousCalled = true
		connection.Password = "previous"
		return nil
	}
	provider := ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		if !previousCalled {
			t.Error("token provider called before existing hook")
		}
		return ycauth.Token{Value: "iam-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	pgxiam.ConfigurePool(config, provider)

	connection := config.ConnConfig.Copy()
	if err := config.BeforeConnect(context.Background(), connection); err != nil {
		t.Fatalf("configured BeforeConnect() error = %v", err)
	}
	if !previousCalled || connection.Password != "iam-token" {
		t.Fatalf("previousCalled = %v, password = %q", previousCalled, connection.Password)
	}
	if config.ConnConfig.Password != "static" {
		t.Fatalf("base config password changed to %q", config.ConnConfig.Password)
	}
}

func TestNilArgumentsPanicAtSetup(t *testing.T) {
	t.Parallel()

	provider := ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{}, nil
	})
	panics := map[string]func(){
		"BeforeConnect":          func() { pgxiam.BeforeConnect(nil) },
		"ConfigurePool config":   func() { pgxiam.ConfigurePool(nil, provider) },
		"ConfigurePool provider": func() { pgxiam.ConfigurePool(&pgxpool.Config{}, nil) },
		"StdlibOption":           func() { pgxiam.StdlibOption(nil) },
	}
	for name, call := range panics {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatal("call did not panic on a nil argument")
				}
			}()
			call()
		})
	}
}
