package httpx //nolint:testpackage

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (transport transportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestClientOrDefault(t *testing.T) {
	t.Parallel()

	if client := ClientOrDefault(nil); client.Timeout != defaultTimeout {
		t.Fatalf("default timeout = %s, want %s", client.Timeout, defaultTimeout)
	}

	transport := transportFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	custom := &http.Client{Transport: transport}
	got := ClientOrDefault(custom)
	if got == custom || got.Transport == nil || got.Timeout != defaultTimeout {
		t.Fatalf("ClientOrDefault(custom) = %#v", got)
	}
	if custom.Timeout != 0 || custom.CheckRedirect != nil {
		t.Fatal("ClientOrDefault() mutated the caller's client")
	}
	if err := got.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect() error = %v", err)
	}
}

func TestUserAgent(t *testing.T) {
	t.Parallel()

	if got := UserAgent(""); got != "ycauth" {
		t.Fatalf("UserAgent(empty) = %q", got)
	}
	if got := UserAgent(" application/1.0 "); got != "application/1.0" {
		t.Fatalf("UserAgent(custom) = %q", got)
	}
}

func TestSetJSONHeaders(t *testing.T) {
	t.Parallel()

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	SetJSONHeaders(request, "test-agent")
	if request.Header.Get("Accept") != "application/json" || request.Header.Get("Content-Type") != "application/json" ||
		request.Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("headers = %#v", request.Header)
	}

	request.Header.Set("User-Agent", "custom-agent")
	SetJSONHeaders(request, "test-agent")
	if request.Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("User-Agent = %q, want overwritten value", request.Header.Get("User-Agent"))
	}
}
