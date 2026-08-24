// Package authzkey exchanges a Yandex Cloud service account authorized key for
// short-lived IAM tokens. It signs exchange JWTs locally and sends only the
// signed JWT to IAM.
package authzkey

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/internal/httpx"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// DefaultEndpoint is the IAM endpoint for exchanging a signed JWT.
	DefaultEndpoint = "https://iam.api.cloud.yandex.net/iam/v1/tokens"

	tokenAudience = DefaultEndpoint
	jwtLifetime   = 10 * time.Minute
	// clockSkew backdates the JWT so that a host clock running slightly ahead
	// of IAM does not produce a token rejected as issued in the future.
	clockSkew           = 10 * time.Second
	maxResponseBodySize = int64(64 << 10)
	// maxKeyDocumentSize bounds the authorized-key JSON; a 4096-bit key with
	// its metadata is a few kilobytes.
	maxKeyDocumentSize = int64(16 << 10)
	// maxTokenLifetime rejects an implausible expiration: IAM tokens live for
	// hours, so a lifetime beyond 12 hours means the response cannot be trusted.
	maxTokenLifetime = 12 * time.Hour
	// maxExpirationClockSkew prevents an exactly 12-hour IAM token from being
	// rejected when the IAM service clock is slightly ahead of the client clock.
	// It is deliberately small so the upper lifetime bound remains meaningful.
	maxExpirationClockSkew = time.Minute
)

// Option configures a [Source] created by [NewFile] or [NewJSON].
type Option func(*options)

type options struct {
	endpoint  string
	userAgent string
	client    *http.Client
}

// WithEndpoint overrides the HTTPS request endpoint. Plain HTTP is accepted
// only for loopback endpoints. The JWT audience remains the fixed value
// required by Yandex Cloud.
func WithEndpoint(endpoint string) Option {
	return func(options *options) { options.endpoint = endpoint }
}

// WithHTTPClient supplies the [http.Client] used for token exchange. Source
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

// Source exchanges signed service account JWTs for IAM tokens. A Source is
// safe for concurrent use.
type Source struct {
	keyID            string
	serviceAccountID string
	privateKey       *rsa.PrivateKey
	endpoint         string
	userAgent        string
	client           *http.Client
	now              func() time.Time
}

type keyDocument struct {
	ID               string `json:"id"`
	ServiceAccountID string `json:"service_account_id"`
	PrivateKey       string `json:"private_key"`
}

type tokenRequest struct {
	JWT string `json:"jwt"`
}

type tokenResponse struct {
	IAMToken  string    `json:"iamToken"`
	ExpiresAt time.Time `json:"expiresAt"`
}

var _ ycauth.TokenSource = (*Source)(nil)

// NewFile opens, reads, and validates a service account authorized-key JSON
// file. It closes the file before returning.
func NewFile(path string, option ...Option) (*Source, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	source, err := NewJSON(file, option...)
	if err != nil {
		return nil, fmt.Errorf("create authorized-key source from %q: %w", path, err)
	}

	return source, nil
}

// NewJSON parses and validates one service account authorized-key JSON document
// from r. The complete document, including surrounding whitespace, must not
// exceed 16 KiB.
func NewJSON(r io.Reader, option ...Option) (*Source, error) {
	config := options{endpoint: DefaultEndpoint}

	for _, apply := range option {
		apply(&config)
	}

	endpoint, err := httpx.ValidateSecureEndpoint(config.endpoint)
	if err != nil {
		return nil, fmt.Errorf("create authorized-key source: %w", err)
	}

	var document keyDocument
	if err := httpx.DecodeJSON(r, maxKeyDocumentSize, &document); err != nil {
		return nil, fmt.Errorf("decode service-account authorized key: %w", err)
	}

	if document.ID == "" || document.ServiceAccountID == "" {
		return nil, errors.New("decode service-account authorized key: id and service_account_id are required")
	}

	privateKey, err := parsePrivateKey([]byte(document.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse service-account private key: %w", err)
	}

	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("validate service-account private key: %w", err)
	}

	if privateKey.N.BitLen() < 2048 {
		return nil, errors.New("validate service-account private key: RSA key must be at least 2048 bits")
	}

	return &Source{
		keyID:            document.ID,
		serviceAccountID: document.ServiceAccountID,
		privateKey:       privateKey,
		endpoint:         endpoint,
		userAgent:        httpx.UserAgent(config.userAgent),
		client:           httpx.ClientOrDefault(config.client),
		now:              time.Now,
	}, nil
}

// Acquire signs a fresh JWT and exchanges it for an IAM token. It honors ctx
// during the HTTP exchange. A malformed or semantically invalid successful
// response is retried once; transport and non-success HTTP errors are returned
// to the caller so its backoff policy remains authoritative.
func (s *Source) Acquire(ctx context.Context) (ycauth.Token, error) {
	token, retry, err := s.acquireOnce(ctx)
	if err == nil || !retry {
		return token, err
	}

	token, _, err = s.acquireOnce(ctx)

	return token, err
}

// acquireOnce reports retry=true only after an HTTP 200 response whose body
// could not be decoded or did not contain a usable token.
func (s *Source) acquireOnce(ctx context.Context) (ycauth.Token, bool, error) {
	signed, err := s.signedJWT(s.now().UTC())
	if err != nil {
		return ycauth.Token{}, false, err
	}

	// #nosec G117 -- the IAM API requires the signed JWT in this request field.
	body, err := json.Marshal(tokenRequest{JWT: signed})
	if err != nil {
		return ycauth.Token{}, false, fmt.Errorf("marshal IAM token request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return ycauth.Token{}, false, fmt.Errorf("create IAM token request: %w", err)
	}

	httpx.SetJSONHeaders(request, s.userAgent)

	response, err := s.client.Do(request)
	if err != nil {
		return ycauth.Token{}, false, fmt.Errorf("exchange service-account JWT for IAM token: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return ycauth.Token{}, false, httpx.ResponseError("exchange service-account JWT for IAM token", response, s.now())
	}

	var result tokenResponse
	if err := httpx.DecodeJSON(response.Body, maxResponseBodySize, &result); err != nil {
		return ycauth.Token{}, true, fmt.Errorf("decode IAM token response: %w", err)
	}

	now := s.now()
	token := ycauth.Token{Value: result.IAMToken, ExpiresAt: result.ExpiresAt}

	switch {
	case token.Value == "":
		return ycauth.Token{}, true, errors.New("decode IAM token response: token is empty")
	case !token.ExpiresAt.After(now):
		return ycauth.Token{}, true, fmt.Errorf("decode IAM token response: token expired at %s", token.ExpiresAt.Format(time.RFC3339Nano))
	case token.ExpiresAt.After(now.Add(maxTokenLifetime + maxExpirationClockSkew)):
		return ycauth.Token{}, true, fmt.Errorf(
			"decode IAM token response: expiration %s exceeds the maximum lifetime relative to client time %s",
			token.ExpiresAt.Format(time.RFC3339Nano),
			now.Format(time.RFC3339Nano),
		)
	}

	return token, false, nil
}

// signedJWT creates the short-lived PS256 assertion required by IAM.
func (s *Source) signedJWT(now time.Time) (string, error) {
	issuedAt := now.Add(-clockSkew)
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, jwt.RegisteredClaims{
		Issuer:    s.serviceAccountID,
		Audience:  jwt.ClaimStrings{tokenAudience},
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		NotBefore: jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(now.Add(jwtLifetime)),
	})
	token.Header["kid"] = s.keyID

	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign service-account JWT: %w", err)
	}

	return signed, nil
}

// parsePrivateKey accepts an unencrypted RSA key in PKCS #1 or PKCS #8 PEM
// form and rejects trailing data.
func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}

	// The DER copy is ours; drop it once the key is parsed out of it.
	defer clear(block.Bytes)

	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("unexpected data after PEM block")
	}

	if _, encrypted := block.Headers["DEK-Info"]; encrypted {
		return nil, errors.New("PEM block is encrypted, which is not supported")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, want RSA", parsed)
		}

		return key, nil
	default:
		return nil, errors.New("unsupported PEM block type " + block.Type)
	}
}
