package s3iam //nolint:testpackage // White-box tests exercise backoff and real-expiration state.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/skarm/ycauth"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (transport transportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestNewCachesCredentials(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	policy, err := PrefixPolicy("bucket", "tenant", PermissionReadObject|PermissionListObjects)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	var requestCount atomic.Int64
	client := &http.Client{Transport: transportFunc(func(request *http.Request) (*http.Response, error) {
		requestCount.Add(1)
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer iam-token" {
			return nil, errors.New("invalid request: " + request.Method + ", authorization " + strconv.Quote(request.Header.Get("Authorization")))
		}
		if got := request.Header.Get("User-Agent"); got != "application/1.0" {
			return nil, errors.New("User-Agent = " + strconv.Quote(got))
		}
		var requestPayload createCredentialsRequest
		if err := json.NewDecoder(request.Body).Decode(&requestPayload); err != nil {
			return nil, err
		}
		if requestPayload.SubjectID != "subject" || requestPayload.SessionName != "session" || requestPayload.Duration != "3600s" || requestPayload.SessionPolicy != policy.JSON() {
			return nil, errors.New("unexpected request body")
		}
		return jsonResponse(http.StatusOK, `{"accessKeyId":"access","secret":"secret","sessionToken":"session-token","expiresAt":`+strconv.Quote(now.Add(time.Hour).Format(time.RFC3339Nano))+`}`), nil
	})}
	provider, err := New(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam-token", ExpiresAt: now.Add(2 * time.Hour)}, nil
	}), Config{
		SessionName:   "session",
		SubjectID:     "subject",
		Duration:      time.Hour,
		SessionPolicy: policy,
		Endpoint:      "https://iam.example.test/credentials",
		HTTPClient:    client,
		UserAgent:     "application/1.0",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	initialCredentials, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	cachedCredentials, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("second Retrieve() error = %v", err)
	}
	if initialCredentials.AccessKeyID != "access" || cachedCredentials.AccessKeyID != initialCredentials.AccessKeyID {
		t.Fatalf("credentials = (%#v, %#v)", initialCredentials, cachedCredentials)
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want 1", got)
	}
}

func TestCacheWindowUsesActualCredentialsLifetime(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	var requestCount atomic.Int64
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		requestCount.Add(1)
		return jsonResponse(http.StatusOK, `{"accessKeyId":"access","secret":"secret","sessionToken":"session-token","expiresAt":`+
			strconv.Quote(now.Add(20*time.Minute).Format(time.RFC3339Nano))+`}`), nil
	})}
	provider, err := New(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam-token", ExpiresAt: now.Add(20 * time.Minute)}, nil
	}), Config{
		SessionName:   "session",
		Duration:      time.Hour,
		SessionPolicy: policy,
		Endpoint:      "https://iam.example.test/credentials",
		HTTPClient:    client,
		ExpiryWindow:  45 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	first, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("second Retrieve() error = %v", err)
	}
	if !first.Expires.After(time.Now()) || !first.Expires.Before(now.Add(20*time.Minute)) {
		t.Fatalf("adjusted expiration = %s", first.Expires)
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want 1", got)
	}
}

func TestIssuerAPIErrorAndBackoff(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	var requestCount atomic.Int64
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		requestCount.Add(1)
		return jsonResponse(http.StatusServiceUnavailable, "unavailable"), nil
	})}
	provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "token", ExpiresAt: now.Add(time.Hour)}, nil
	}), Config{SessionName: "session", SessionPolicy: policy, Endpoint: "https://iam.example.test", HTTPClient: client})
	if err != nil {
		t.Fatalf("newCredentialsIssuer() error = %v", err)
	}
	provider.now = func() time.Time { return now }
	provider.jitterSource = func() float64 { return 0.5 }

	_, err = provider.Retrieve(context.Background())
	var apiErr *ycauth.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Retrieve() error = %v, want APIError 503", err)
	}
	_, err = provider.Retrieve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "backed off") {
		t.Fatalf("backoff Retrieve() error = %v", err)
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want 1", got)
	}
}

func TestIssuerStaleFallbackUsesActualExpiration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	issuedCredentials := aws.Credentials{
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		CanExpire:       true,
		Expires:         now.Add(time.Hour),
	}
	provider := &credentialsIssuer{
		now:                   func() time.Time { return now },
		lastIssuedCredentials: issuedCredentials,
		failures:              1,
		nextAttemptAt:         now.Add(10 * time.Second),
	}
	previous := issuedCredentials
	previous.Expires = now.Add(-time.Second)
	stale, err := provider.HandleFailToRefresh(context.Background(), previous, errors.New("refresh failed"))
	if err != nil || !stale.Expires.Equal(issuedCredentials.Expires) {
		t.Fatalf("HandleFailToRefresh() = (%#v, %v)", stale, err)
	}
	adjusted, err := provider.AdjustExpiresBy(stale, -time.Minute)
	if err != nil || !adjusted.Expires.Equal(provider.nextAttemptAt) {
		t.Fatalf("AdjustExpiresBy() = (%#v, %v)", adjusted, err)
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	tokenProvider := ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) { return ycauth.Token{}, nil })
	invalidConfigs := []Config{
		{},
		{SessionName: "bad session", SessionPolicy: policy},
		{SessionName: "session", SessionPolicy: policy, Duration: time.Minute},
		{SessionName: "session", SessionPolicy: policy, Endpoint: "relative"},
		{SessionName: "session", SessionPolicy: policy, Endpoint: "http://iam.example.test"},
		{SessionName: "session", SessionPolicy: policy, ExpiryWindow: 2 * time.Hour},
		{SessionName: "session", SessionPolicy: policy, RefreshTimeout: -time.Second},
		{SessionName: "session", SessionPolicy: policy, SubjectID: "subject-\xff"},
	}
	if _, err := New(nil, Config{SessionName: "session", SessionPolicy: policy}); err == nil {
		t.Fatal("New(nil provider) error = nil")
	}
	for _, config := range invalidConfigs {
		if _, err := New(tokenProvider, config); err == nil {
			t.Fatalf("New(%+v) error = nil", config)
		}
	}
}

func TestNewOmitsEmptySessionPolicy(t *testing.T) {
	t.Parallel()

	provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{}, nil
	}), Config{SessionName: "session"})
	if err != nil {
		t.Fatalf("newCredentialsIssuer() error = %v", err)
	}

	var requestPayload map[string]json.RawMessage
	if err := json.Unmarshal(provider.requestBody, &requestPayload); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if _, exists := requestPayload["policy"]; exists {
		t.Fatalf("request body unexpectedly contains policy: %s", provider.requestBody)
	}
}

func TestIssuerRefreshTimeoutIncludesTokenLookup(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(ctx context.Context) (ycauth.Token, error) {
		<-ctx.Done()
		return ycauth.Token{}, ctx.Err()
	}), Config{
		SessionName:    "session",
		SessionPolicy:  policy,
		Endpoint:       "https://iam.example.test",
		RefreshTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newCredentialsIssuer() error = %v", err)
	}

	started := time.Now()
	_, err = provider.Retrieve(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Retrieve() error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Retrieve() took %s", elapsed)
	}
}

func TestIssuerResponseValidation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	responseCases := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{`},
		{name: "missing fields", body: `{}`},
		{name: "expired", body: `{"accessKeyId":"access","secret":"secret","sessionToken":"token","expiresAt":` + strconv.Quote(now.Format(time.RFC3339Nano)) + `}`},
		{name: "expiration out of range", body: `{"accessKeyId":"access","secret":"secret","sessionToken":"token","expiresAt":` + strconv.Quote(now.AddDate(1, 0, 0).Format(time.RFC3339Nano)) + `}`},
	}
	for _, testCase := range responseCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, testCase.body), nil
			})}
			provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
				return ycauth.Token{Value: "iam", ExpiresAt: now.Add(time.Hour)}, nil
			}), Config{SessionName: "session", SessionPolicy: policy, Endpoint: "https://iam.example.test", HTTPClient: client})
			if err != nil {
				t.Fatalf("newCredentialsIssuer() error = %v", err)
			}
			provider.now = func() time.Time { return now }
			if _, err := provider.Retrieve(context.Background()); err == nil {
				t.Fatal("Retrieve() error = nil")
			}
		})
	}
}

func TestIssuerRejectsCredentialsBeyondRequestedOrTokenLifetime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}

	testCases := []struct {
		name              string
		duration          time.Duration
		tokenExpiresAt    time.Time
		responseExpiresAt time.Time
	}{
		{
			name:              "requested duration",
			duration:          30 * time.Minute,
			tokenExpiresAt:    now.Add(2 * time.Hour),
			responseExpiresAt: now.Add(31 * time.Minute),
		},
		{
			name:              "IAM token lifetime",
			duration:          time.Hour,
			tokenExpiresAt:    now.Add(20 * time.Minute),
			responseExpiresAt: now.Add(21 * time.Minute),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			body := `{"accessKeyId":"access","secret":"secret","sessionToken":"token","expiresAt":` +
				strconv.Quote(testCase.responseExpiresAt.Format(time.RFC3339Nano)) + `}`
			client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, body), nil
			})}
			provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
				return ycauth.Token{Value: "iam", ExpiresAt: testCase.tokenExpiresAt}, nil
			}), Config{
				SessionName:   "session",
				Duration:      testCase.duration,
				SessionPolicy: policy,
				Endpoint:      "https://iam.example.test",
				HTTPClient:    client,
			})
			if err != nil {
				t.Fatalf("newCredentialsIssuer() error = %v", err)
			}
			provider.now = func() time.Time { return now }

			if _, err := provider.Retrieve(context.Background()); err == nil {
				t.Fatal("Retrieve() error = nil")
			}
		})
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     strconv.Itoa(status) + " " + http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestIssuerContainsTokenProviderPanic(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		panic("token provider exploded")
	}), Config{SessionName: "session", SessionPolicy: policy})
	if err != nil {
		t.Fatalf("newCredentialsIssuer() error = %v", err)
	}

	credentials, err := provider.Retrieve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "panicked") || credentials.HasKeys() {
		t.Fatalf("Retrieve() = (%#v, %v), want a contained panic", credentials, err)
	}

	// The contained panic must also arm backoff instead of hot-looping.
	if _, err := provider.Retrieve(context.Background()); !errors.Is(err, ycauth.ErrBackoff) {
		t.Fatalf("Retrieve() during backoff error = %v, want ErrBackoff", err)
	}
}
