package imds //nolint:testpackage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skarm/ycauth"
)

func TestSourceAcquire(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %s", request.Method)
		}
		if got := request.Header.Get("Metadata-Flavor"); got != "Google" {
			t.Errorf("Metadata-Flavor = %q", got)
		}
		if got := request.Header.Get("User-Agent"); got != "application/1.0" {
			t.Errorf("User-Agent = %q", got)
		}
		_, _ = io.WriteString(writer, `{"access_token":"imds-token","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer server.Close()

	source, err := New(WithEndpoint(server.URL), WithHTTPClient(server.Client()), WithUserAgent("application/1.0"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.now = func() time.Time { return now }
	token, err := source.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if token.Value != "imds-token" || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("Acquire() = %v", token)
	}
}

func TestSourceAcquireAPIError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	source, err := New(WithEndpoint(server.URL))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Acquire(context.Background())
	var apiErr *ycauth.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Acquire() error = %v, want 403 APIError", err)
	}
}

func TestSourceDoesNotFollowRedirectWithSuppliedClient(t *testing.T) {
	t.Parallel()

	forged := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		t.Error("the redirect target was fetched")
		_, _ = io.WriteString(writer, `{"access_token":"forged","expires_in":3600}`)
	}))
	defer forged.Close()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, forged.URL, http.StatusFound)
	}))
	defer server.Close()

	source, err := New(WithEndpoint(server.URL), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := source.Acquire(context.Background()); err == nil {
		t.Fatal("Acquire() error = nil, want the redirect refused")
	}
}

func TestSourceAcquireValidation(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{`},
		{name: "missing token", body: `{"expires_in":3600}`},
		{name: "zero expiration", body: `{"access_token":"token","expires_in":0}`},
		{name: "overflow", body: `{"access_token":"token","expires_in":9223372037}`},
		{name: "wrong token type", body: `{"access_token":"token","expires_in":3600,"token_type":"Basic"}`},
		{name: "oversized", body: strings.Repeat("x", int(maxResponseBodySize)+1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, testCase.body)
			}))
			defer server.Close()

			source, err := New(WithEndpoint(server.URL))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := source.Acquire(context.Background()); err == nil {
				t.Fatal("Acquire() error = nil")
			}
		})
	}
}

func TestSourceValidation(t *testing.T) {
	t.Parallel()

	if _, err := New(WithEndpoint("relative")); err == nil {
		t.Fatal("New(relative endpoint) error = nil")
	}
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	//nolint:staticcheck // Nil is intentional: this verifies defensive validation.
	if _, err := source.Acquire(nil); err == nil {
		t.Fatal("Acquire(nil) error = nil")
	}
}

func TestNewUsesProxyFreeBoundedClient(t *testing.T) {
	t.Parallel()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.client.Timeout != defaultHTTPTimeout {
		t.Fatalf("HTTP timeout = %s, want %s", source.client.Timeout, defaultHTTPTimeout)
	}
	transport, ok := source.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP transport = %T, want *http.Transport", source.client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("IMDS HTTP transport unexpectedly honors proxy environment")
	}
	if source.client.CheckRedirect == nil {
		t.Fatal("IMDS HTTP client unexpectedly follows redirects")
	}
}
