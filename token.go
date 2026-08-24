// Package ycauth acquires and caches short-lived Yandex Cloud IAM tokens.
//
// Use [NewCache] to adapt a [TokenSource] to a concurrent [TokenProvider].
// Service-specific token sources and credential adapters live in separate
// modules.
package ycauth

import (
	"context"
	"log/slog"
	"time"
)

// Token contains a Yandex Cloud IAM bearer token and its expiration time.
//
// [Token.Value] is excluded from JSON and redacted by [Token.String],
// [Token.GoString], and [Token.LogValue]. Treat it as a secret when accessing
// it directly.
type Token struct {
	// Value is the bearer token. It is secret and excluded from JSON output.
	Value string `json:"-"`
	// ExpiresAt is the instant after which Value must not be used.
	ExpiresAt time.Time `json:"expiresAt"`
}

// ValidAt reports whether the token is non-empty and unexpired at now.
func (t Token) ValidAt(now time.Time) bool {
	return t.Value != "" && t.ExpiresAt.After(now)
}

// String returns a representation that never contains the token value.
func (t Token) String() string {
	return "ycauth.Token{Value:REDACTED, ExpiresAt:" + t.ExpiresAt.Format(time.RFC3339Nano) + "}"
}

// GoString returns a Go-syntax representation that never contains the token value.
func (t Token) GoString() string { return t.String() }

// LogValue returns a structured slog value that omits the token value.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("expires_at", t.ExpiresAt))
}

// TokenSource obtains fresh IAM tokens without caching them. Every call to
// [TokenSource.Acquire] may perform I/O.
type TokenSource interface {
	// Acquire obtains a fresh token. It must honor ctx while performing I/O.
	Acquire(context.Context) (Token, error)
}

// TokenSourceFunc adapts a function to TokenSource.
type TokenSourceFunc func(context.Context) (Token, error)

// Acquire calls f with ctx.
func (f TokenSourceFunc) Acquire(ctx context.Context) (Token, error) { return f(ctx) }

// TokenProvider returns cached IAM tokens for request paths. Implementations
// must coalesce refreshes and return a token that is valid when returned.
type TokenProvider interface {
	// Token returns a token valid at the time it is returned. It may wait for a
	// refresh and must honor ctx while waiting.
	Token(context.Context) (Token, error)
}

// TokenProviderFunc adapts a function to TokenProvider.
type TokenProviderFunc func(context.Context) (Token, error)

// Token calls f with ctx.
func (f TokenProviderFunc) Token(ctx context.Context) (Token, error) { return f(ctx) }
