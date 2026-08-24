// Package imds obtains IAM tokens from the Yandex Compute Cloud instance
// metadata service (IMDS). Use it on a virtual machine with an attached
// service account. IMDS supplies short-lived IAM tokens without an authorized
// key file.
package imds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/internal/httpx"
)

const (
	// DefaultEndpoint is the Compute Cloud instance-metadata endpoint for the
	// service account attached to the VM.
	DefaultEndpoint = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

	maxResponseBodySize = int64(64 << 10)
	defaultHTTPTimeout  = 2 * time.Second
	// maxExpiresIn rejects an implausible lifetime before converting it to a
	// duration. Values beyond seven days are rejected.
	maxExpiresIn = int64(7 * 24 * 3600)
)

//nolint:gochecknoglobals // one shared link-local client, deliberately proxy-free.
var defaultHTTPClient = &http.Client{
	Timeout:       defaultHTTPTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: func() *http.Transport {
		// IMDS is link-local: never route it through a proxy
		// and never follow a redirect that could leak the token elsewhere.
		transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert
		transport.Proxy = nil

		return transport
	}(),
}

// Option configures a [Source] created by [New].
type Option func(*options)

type options struct {
	endpoint  string
	userAgent string
	client    *http.Client
}

// WithEndpoint overrides the IMDS endpoint. It is primarily useful for private
// IMDS proxies and tests, and must use HTTPS unless it targets a
// loopback or link-local address.
func WithEndpoint(endpoint string) Option {
	return func(options *options) { options.endpoint = endpoint }
}

// WithHTTPClient supplies the [http.Client] used for IMDS requests. Source
// shallow-copies its top-level configuration, defaults a non-positive timeout,
// and disables redirects. The transport and cookie jar remain shared. A nil
// client selects the package default.
func WithHTTPClient(client *http.Client) Option {
	return func(options *options) { options.client = client }
}

// WithUserAgent overrides the User-Agent header. A blank value uses "ycauth".
func WithUserAgent(userAgent string) Option {
	return func(options *options) { options.userAgent = userAgent }
}

// Source obtains IAM tokens for the service account attached to a Compute
// Cloud virtual machine. A Source is safe for concurrent use.
type Source struct {
	endpoint  string
	userAgent string
	client    *http.Client
	now       func() time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

var _ ycauth.TokenSource = (*Source)(nil)

// New creates a token source for the service account attached to the current
// Compute Cloud VM. It returns an error if the endpoint configuration is
// invalid; endpoint availability is checked when Acquire is called.
func New(option ...Option) (*Source, error) {
	config := options{endpoint: DefaultEndpoint}

	for _, apply := range option {
		apply(&config)
	}

	endpoint, err := httpx.ValidateIMDSEndpoint(config.endpoint)
	if err != nil {
		return nil, fmt.Errorf("create IMDS IAM token source: %w", err)
	}

	// The shared default is already proxy-free and redirect-free; a supplied
	// client gets the same timeout floor and redirect ban as the other modules.
	client := defaultHTTPClient
	if config.client != nil {
		client = httpx.ClientOrDefault(config.client)
	}

	return &Source{
		endpoint:  endpoint,
		userAgent: httpx.UserAgent(config.userAgent),
		client:    client,
		now:       time.Now,
	}, nil
}

// Acquire requests a fresh IAM token from IMDS. It honors ctx during the HTTP
// request.
func (s *Source) Acquire(ctx context.Context) (ycauth.Token, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return ycauth.Token{}, fmt.Errorf("create IMDS IAM token request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("Metadata-Flavor", "Google")
	request.Header.Set("User-Agent", s.userAgent)

	// expires_in counts from the moment the service minted the token, so
	// anchor it before the round trip rather than after.
	issuedAt := s.now()

	response, err := s.client.Do(request)
	if err != nil {
		return ycauth.Token{}, fmt.Errorf("get IAM token from IMDS: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return ycauth.Token{}, httpx.ResponseError("get IAM token from IMDS", response, s.now())
	}

	var result tokenResponse
	if err := httpx.DecodeJSON(response.Body, maxResponseBodySize, &result); err != nil {
		return ycauth.Token{}, fmt.Errorf("decode IMDS IAM token response: %w", err)
	}

	if result.AccessToken == "" || result.ExpiresIn <= 0 || result.ExpiresIn > maxExpiresIn {
		return ycauth.Token{}, errors.New("decode IMDS IAM token response: token is empty or expiration is out of range")
	}

	if result.TokenType != "" && !strings.EqualFold(result.TokenType, "Bearer") {
		return ycauth.Token{}, errors.New("decode IMDS IAM token response: unsupported token type " + strconv.Quote(result.TokenType))
	}

	return ycauth.Token{
		Value:     result.AccessToken,
		ExpiresAt: issuedAt.Add(time.Duration(result.ExpiresIn) * time.Second),
	}, nil
}
