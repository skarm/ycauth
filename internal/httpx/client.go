package httpx

import (
	"net/http"
	"strings"
	"time"
)

const (
	defaultTimeout   = 10 * time.Second
	defaultUserAgent = "ycauth"
)

// ClientOrDefault returns a client with a finite timeout and redirects disabled.
// For a non-nil client, it shallow-copies the top-level configuration while
// preserving the transport and cookie jar. A nil client selects an empty
// default. Redirecting a credential request could disclose its secret body or
// Authorization header to another endpoint.
func ClientOrDefault(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}

	// Callers commonly share an http.Client. Copy its top-level configuration so
	// changing timeout and redirect handling here cannot affect unrelated users;
	// its Transport and Jar remain shared, while CheckRedirect is replaced below.
	configuredClient := *client
	if configuredClient.Timeout <= 0 {
		configuredClient.Timeout = defaultTimeout
	}

	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &configuredClient
}

// UserAgent returns the trimmed value, or the package default when value is
// blank.
func UserAgent(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}

	return defaultUserAgent
}

// SetJSONHeaders replaces the Accept, Content-Type, and User-Agent headers with
// values used by ycauth JSON API requests.
func SetJSONHeaders(request *http.Request, userAgent string) {
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", userAgent)
}
