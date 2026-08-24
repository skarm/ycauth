// Package s3iam creates and caches ephemeral Yandex Object Storage credentials
// for the AWS SDK for Go v2. [New] returns an [aws.CredentialsCache] ready for
// use as [aws.Config.Credentials].
package s3iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/internal/backoff"
	"github.com/skarm/ycauth/internal/httpx"
)

const (
	// DefaultEndpoint is the IAM endpoint that creates ephemeral AWS-compatible
	// access keys.
	DefaultEndpoint = "https://iam.api.cloud.yandex.net/iam/aws-compatibility/v1/ephemeralAccessKeys"
	// MinDuration is the shortest duration accepted by Yandex Cloud.
	MinDuration = 15 * time.Minute
	// MaxDuration is the longest duration accepted by Yandex Cloud.
	MaxDuration = 12 * time.Hour

	defaultDuration       = time.Hour
	defaultExpiryWindow   = time.Minute
	defaultExpiryJitter   = 0.2
	defaultRefreshTimeout = 10 * time.Second
	maxSessionNameLen     = 64
	maxSubjectIDLen       = 50
	maxResponseBodySize   = int64(64 << 10)
	credentialsSource     = "yc-ephemeral"
)

//nolint:gochecknoglobals // immutable retry policy shared by every credentials issuer.
var failureBackoff = backoff.Policy{
	Initial:    time.Second,
	Max:        30 * time.Second,
	Multiplier: 2,
	Jitter:     0.2,
}

// Config configures the ephemeral S3 credentials returned by [New]. Its zero
// value is invalid because [Config.SessionName] is required.
type Config struct {
	// SessionName identifies the ephemeral credentials session. It must contain
	// 1 to 64 AWS-compatible session-name characters.
	SessionName string
	// SubjectID optionally identifies the session subject. It must be valid UTF-8
	// and contain at most 50 characters.
	SubjectID string
	// Duration requests the credentials lifetime as a whole number of seconds
	// from [MinDuration] through [MaxDuration]. Zero uses one hour.
	Duration time.Duration
	// SessionPolicy optionally restricts the credentials. Construct it with
	// [PrefixPolicy] or [RawPolicy]. Its zero value omits the policy, allowing all
	// Object Storage permissions already granted to the subject.
	SessionPolicy SessionPolicy
	// Endpoint overrides DefaultEndpoint. It must use HTTPS unless it is a
	// loopback endpoint for a local emulator.
	Endpoint string
	// HTTPClient supplies the client used to create credentials. [New]
	// shallow-copies its top-level configuration, defaults a non-positive timeout,
	// and disables redirects. The transport and cookie jar remain shared. A nil
	// client selects the package default.
	HTTPClient *http.Client
	// UserAgent overrides the User-Agent header. An empty value uses "ycauth".
	UserAgent string
	// ExpiryWindow starts a refresh before the credentials expire. Zero uses one
	// minute. New requires it to be shorter than [Config.Duration] and clamps it
	// to the lifetime returned by the service.
	ExpiryWindow time.Duration
	// RefreshTimeout bounds the complete refresh, including IAM-token lookup.
	// Zero uses ten seconds. The AWS credentials cache lets a shared refresh
	// outlive the caller that triggered it.
	RefreshTimeout time.Duration
}

// credentialsIssuer obtains credentials and implements the AWS cache strategies
// that preserve service expiration across early refresh and failure backoff.
type credentialsIssuer struct {
	tokenProvider  ycauth.TokenProvider
	client         *http.Client
	endpoint       string
	userAgent      string
	refreshTimeout time.Duration
	// requestBody is constant for the issuer lifetime, so construction encodes it
	// once instead of on every refresh.
	requestBody  []byte
	now          func() time.Time
	jitterSource func() float64

	mu                    sync.Mutex
	failures              int
	nextAttemptAt         time.Time
	lastErr               error
	lastIssuedCredentials aws.Credentials
}

type createCredentialsRequest struct {
	SubjectID     string `json:"subjectId,omitempty"`
	SessionName   string `json:"sessionName"`
	SessionPolicy string `json:"policy,omitempty"`
	Duration      string `json:"duration"`
}

type createCredentialsResponse struct {
	AccessKeyID  string    `json:"accessKeyId"`
	Secret       string    `json:"secret"`
	SessionToken string    `json:"sessionToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

var (
	_ aws.CredentialsProvider                       = (*credentialsIssuer)(nil)
	_ aws.HandleFailRefreshCredentialsCacheStrategy = (*credentialsIssuer)(nil)
	_ aws.AdjustExpiresByCredentialsCacheStrategy   = (*credentialsIssuer)(nil)
)

// New creates a cached AWS credentials provider using tokenProvider. Assign the
// returned cache directly to [aws.Config.Credentials].
//
// New returns an error if tokenProvider is nil or config is invalid.
func New(tokenProvider ycauth.TokenProvider, config Config) (*aws.CredentialsCache, error) {
	provider, expiryWindow, err := newCredentialsIssuer(tokenProvider, config)
	if err != nil {
		return nil, err
	}

	return aws.NewCredentialsCache(provider, func(options *aws.CredentialsCacheOptions) {
		options.ExpiryWindow = expiryWindow
		options.ExpiryWindowJitterFrac = defaultExpiryJitter
	}), nil
}

// newCredentialsIssuer validates config and builds the provider wrapped by the
// AWS credentials cache.
func newCredentialsIssuer(tokenProvider ycauth.TokenProvider, config Config) (*credentialsIssuer, time.Duration, error) {
	const errPrefix = "create ephemeral S3 credentials provider: "

	if tokenProvider == nil {
		return nil, 0, errors.New(errPrefix + "token provider must not be nil")
	}

	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	endpoint, err := httpx.ValidateSecureEndpoint(endpoint)
	if err != nil {
		return nil, 0, fmt.Errorf(errPrefix+"%w", err)
	}

	sessionName := config.SessionName
	if !validSessionName(sessionName) {
		return nil, 0, errors.New(errPrefix + "session name must contain 1-" +
			strconv.Itoa(maxSessionNameLen) + " AWS-compatible characters")
	}

	subjectID := config.SubjectID
	if !utf8.ValidString(subjectID) || utf8.RuneCountInString(subjectID) > maxSubjectIDLen {
		return nil, 0, errors.New(errPrefix + "subject ID must be valid UTF-8 of at most " +
			strconv.Itoa(maxSubjectIDLen) + " characters")
	}

	duration := config.Duration
	if duration == 0 {
		duration = defaultDuration
	}

	if duration%time.Second != 0 || duration < MinDuration || duration > MaxDuration {
		return nil, 0, errors.New(errPrefix + "duration must be a whole number of seconds between " +
			MinDuration.String() + " and " + MaxDuration.String())
	}

	expiryWindow := config.ExpiryWindow
	if expiryWindow == 0 {
		expiryWindow = defaultExpiryWindow
	}

	if expiryWindow < 0 || expiryWindow >= duration {
		return nil, 0, errors.New(errPrefix + "expiry window must be non-negative and shorter than duration")
	}

	refreshTimeout := config.RefreshTimeout
	if refreshTimeout == 0 {
		refreshTimeout = defaultRefreshTimeout
	}

	if refreshTimeout < 0 {
		return nil, 0, errors.New(errPrefix + "refresh timeout must be non-negative")
	}

	requestBody, err := json.Marshal(createCredentialsRequest{
		SubjectID:     subjectID,
		SessionName:   sessionName,
		SessionPolicy: config.SessionPolicy.document,
		Duration:      strconv.FormatInt(int64(duration/time.Second), 10) + "s",
	})
	if err != nil {
		return nil, 0, fmt.Errorf(errPrefix+"encode request: %w", err)
	}

	return &credentialsIssuer{
		tokenProvider:  tokenProvider,
		client:         httpx.ClientOrDefault(config.HTTPClient),
		endpoint:       endpoint,
		userAgent:      httpx.UserAgent(config.UserAgent),
		refreshTimeout: refreshTimeout,
		requestBody:    requestBody,
		now:            time.Now,
		jitterSource:   rand.Float64,
	}, expiryWindow, nil
}

// validSessionName reports whether name matches the AWS session-name charset.
// Every accepted byte is ASCII, so the byte length is also the rune count.
func validSessionName(name string) bool {
	if len(name) == 0 || len(name) > maxSessionNameLen {
		return false
	}

	for index := range len(name) {
		switch character := name[index]; {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9':
		case strings.IndexByte("_+=,.@-", character) >= 0:
		default:
			return false
		}
	}

	return true
}

// Retrieve obtains and validates fresh ephemeral credentials. It runs on the
// credentials cache's shared refresh goroutine and converts a panic from the
// token provider or HTTP transport to an error.
func (p *credentialsIssuer) Retrieve(ctx context.Context) (credentials aws.Credentials, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			credentials = aws.Credentials{}
			err = p.recordFailure(fmt.Errorf("create ephemeral S3 credentials: refresh panicked: %v", recovered))
		}
	}()

	if suppressed := p.suppressedErr(); suppressed != nil {
		return aws.Credentials{}, suppressed
	}

	ctx, cancel := context.WithTimeout(ctx, p.refreshTimeout)
	defer cancel()

	token, err := p.tokenProvider.Token(ctx)
	if err != nil {
		return aws.Credentials{}, p.recordFailure(fmt.Errorf("get IAM token for ephemeral S3 credentials: %w", err))
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(p.requestBody))
	if err != nil {
		return aws.Credentials{}, p.recordFailure(fmt.Errorf("create ephemeral S3 credentials request: %w", err))
	}

	request.Header.Set("Authorization", "Bearer "+token.Value)
	httpx.SetJSONHeaders(request, p.userAgent)

	response, err := p.client.Do(request)
	if err != nil {
		return aws.Credentials{}, p.recordFailure(fmt.Errorf("create ephemeral S3 credentials: %w", err))
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return aws.Credentials{}, p.recordFailure(httpx.ResponseError("create ephemeral S3 credentials", response, p.now()))
	}

	var result createCredentialsResponse
	if err := httpx.DecodeJSON(response.Body, maxResponseBodySize, &result); err != nil {
		return aws.Credentials{}, p.recordFailure(fmt.Errorf("decode ephemeral S3 credentials response: %w", err))
	}

	if result.AccessKeyID == "" || result.Secret == "" || result.SessionToken == "" {
		return aws.Credentials{}, p.recordFailure(errors.New("decode ephemeral S3 credentials response: required fields are missing"))
	}

	// ExpiresAt is authoritative. Duration is a requested lifetime, not a
	// client-side upper bound guaranteed by the API. The service does guarantee
	// that credentials do not outlive the IAM token which authorized them.
	now := p.now()
	tokenExpiresAt := token.ExpiresAt.Round(0)

	if !result.ExpiresAt.After(now) || result.ExpiresAt.After(tokenExpiresAt) {
		return aws.Credentials{}, p.recordFailure(fmt.Errorf(
			"decode ephemeral S3 credentials response: expiration %s is outside (%s, %s]",
			result.ExpiresAt.Format(time.RFC3339Nano),
			now.Format(time.RFC3339Nano),
			tokenExpiresAt.Format(time.RFC3339Nano),
		))
	}

	issued := aws.Credentials{
		AccessKeyID:     result.AccessKeyID,
		SecretAccessKey: result.Secret,
		SessionToken:    result.SessionToken,
		CanExpire:       true,
		Expires:         result.ExpiresAt,
		Source:          credentialsSource,
	}

	p.recordSuccess(issued)

	return issued, nil
}

// suppressedErr returns the pending error while a previous failure is still
// being backed off, and nil when an attempt is allowed.
func (p *credentialsIssuer) suppressedErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.now().Before(p.nextAttemptAt) {
		return p.lastErr
	}

	return nil
}

// recordSuccess clears refresh backoff and preserves the credentials' actual
// service expiration for stale fallback.
func (p *credentialsIssuer) recordSuccess(credentials aws.Credentials) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.failures = 0
	p.nextAttemptAt = time.Time{}
	p.lastErr = nil
	p.lastIssuedCredentials = credentials
}

// recordFailure advances refresh backoff while returning the live failure to
// the current caller.
func (p *credentialsIssuer) recordFailure(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.failures = min(p.failures+1, backoff.MaxFailures)
	p.nextAttemptAt = p.now().Add(failureBackoff.Delay(p.failures, retryAfterHint(err), p.jitterSource))
	p.lastErr = fmt.Errorf("create ephemeral S3 credentials: %w until %s: %w",
		ycauth.ErrBackoff, p.nextAttemptAt.Format(time.RFC3339Nano), err)

	return err
}

// retryAfterHint returns the server-requested delay carried by err, if any.
func retryAfterHint(err error) time.Duration {
	var apiErr *ycauth.APIError
	if errors.As(err, &apiErr) {
		return apiErr.RetryAfter
	}

	return 0
}

// HandleFailToRefresh permits stale fallback only until the server-provided
// expiration time, never merely until the cache's adjusted expiration.
func (p *credentialsIssuer) HandleFailToRefresh(_ context.Context, previous aws.Credentials, refreshErr error) (aws.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if previous.HasKeys() && p.lastIssuedCredentials.AccessKeyID == previous.AccessKeyID && p.lastIssuedCredentials.Expires.After(p.now()) {
		return p.lastIssuedCredentials, nil
	}

	return aws.Credentials{}, refreshErr
}

// AdjustExpiresBy makes a failed refresh retry after backoff while preserving
// the real server expiration as the hard upper bound.
func (p *credentialsIssuer) AdjustExpiresBy(credentials aws.Credentials, duration time.Duration) (aws.Credentials, error) {
	now := p.now()
	adjusted := credentials.Expires.Add(duration)

	if duration < 0 {
		remaining := credentials.Expires.Sub(now)
		// The service can cap the requested credentials lifetime by the
		// remaining IAM-token lifetime. Keep at least half of the actual TTL so
		// a configured window cannot make fresh credentials instantly stale.
		if remaining > 0 && -duration > remaining/2 {
			adjusted = credentials.Expires.Add(-remaining / 2)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.failures > 0 && credentials.AccessKeyID == p.lastIssuedCredentials.AccessKeyID {
		adjusted = p.nextAttemptAt
		if adjusted.After(p.lastIssuedCredentials.Expires) {
			adjusted = p.lastIssuedCredentials.Expires
		}
	}

	credentials.Expires = adjusted

	return credentials, nil
}
