package s3iam //nolint:testpackage // White-box tests exercise backoff and real-expiration state.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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
		if requestPayload.SubjectID != "subject" || !strings.HasPrefix(requestPayload.SessionName, "session-") || requestPayload.Duration != "3600s" || requestPayload.SessionPolicy != policy.JSON() {
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
		{SessionName: strings.Repeat("x", 65), SessionPolicy: policy},
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

	now := time.Now().UTC()
	client := &http.Client{Transport: transportFunc(func(request *http.Request) (*http.Response, error) {
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			return nil, err
		}
		if _, exists := payload["policy"]; exists {
			return nil, errors.New("request body unexpectedly contains policy")
		}
		return jsonResponse(http.StatusOK, `{"accessKeyId":"access","secret":"secret","sessionToken":"token","expiresAt":`+
			strconv.Quote(now.Add(time.Hour).Format(time.RFC3339Nano))+`}`), nil
	})}
	provider, err := New(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam-token", ExpiresAt: now.Add(2 * time.Hour)}, nil
	}), Config{SessionName: "session", HTTPClient: client})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := provider.Retrieve(t.Context()); err != nil {
		t.Fatalf("Retrieve() error = %v", err)
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

func TestIssuerAcceptsServiceExpirationBeyondRequestedLifetime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}

	responseExpiresAt := now.Add(time.Hour)
	body := `{"accessKeyId":"access","secret":"secret","sessionToken":"token","expiresAt":` +
		strconv.Quote(responseExpiresAt.Format(time.RFC3339Nano)) + `}`
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, body), nil
	})}
	provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam", ExpiresAt: now.Add(2 * time.Hour)}, nil
	}), Config{
		SessionName:   "session",
		Duration:      30 * time.Minute,
		SessionPolicy: policy,
		Endpoint:      "https://iam.example.test",
		HTTPClient:    client,
	})
	if err != nil {
		t.Fatalf("newCredentialsIssuer() error = %v", err)
	}
	provider.now = func() time.Time { return now }

	credentials, err := provider.Retrieve(context.Background())
	if err != nil || !credentials.Expires.Equal(responseExpiresAt) {
		t.Fatalf("Retrieve() = (%#v, %v)", credentials, err)
	}
}

func TestIssuerRejectsCredentialsBeyondTokenLifetime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	tokenExpiresAt := now.Add(20 * time.Minute)
	body := `{"accessKeyId":"access","secret":"secret","sessionToken":"token","expiresAt":` +
		strconv.Quote(tokenExpiresAt.Add(time.Nanosecond).Format(time.RFC3339Nano)) + `}`
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, body), nil
	})}
	provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam", ExpiresAt: tokenExpiresAt}, nil
	}), Config{
		SessionName:   "session",
		Duration:      time.Hour,
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

type brokenError struct{}

func (brokenError) Error() string { return "IAM unavailable" }

func (brokenError) Unwrap() error { panic("Unwrap exploded") }

func TestIssuerCountsPanickingTokenProviderErrorOnce(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicy("bucket", "", PermissionReadObject)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	var calls atomic.Int64
	provider, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		calls.Add(1)
		return ycauth.Token{}, brokenError{}
	}), Config{SessionName: "session", SessionPolicy: policy})
	if err != nil {
		t.Fatalf("newCredentialsIssuer() error = %v", err)
	}
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	provider.now = func() time.Time { return now }

	credentials, err := provider.Retrieve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "panicked") || credentials.HasKeys() {
		t.Fatalf("Retrieve() = (%#v, %v), want a contained panic", credentials, err)
	}
	if provider.failures != 1 {
		t.Fatalf("failures = %d, want 1", provider.failures)
	}

	done := make(chan error, 1)
	go func() {
		_, err := provider.Retrieve(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ycauth.ErrBackoff) {
			t.Fatalf("Retrieve() during backoff error = %v, want ErrBackoff", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Retrieve() after a panicking error did not return")
	}
	if provider.failures != 1 || calls.Load() != 1 {
		t.Fatalf("during backoff: failures = %d, source calls = %d, want 1 each", provider.failures, calls.Load())
	}

	now = provider.nextAttemptAt
	if _, err := provider.Retrieve(context.Background()); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("Retrieve() after backoff error = %v, want a contained panic", err)
	}
	if provider.failures != 2 || calls.Load() != 2 {
		t.Fatalf("after retry: failures = %d, source calls = %d, want 2 each", provider.failures, calls.Load())
	}
}

func TestCacheRotationUsesFreshSigningKeys(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		tokenExpiresAt := time.Now().Add(12 * time.Hour)
		var names []string
		client := &http.Client{Transport: transportFunc(func(request *http.Request) (*http.Response, error) {
			var payload createCredentialsRequest
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				return nil, err
			}
			names = append(names, payload.SessionName)
			// Model an issuer that reuses the access key ID for the same
			// session name but rotates its secret on every issuance.
			body, err := json.Marshal(createCredentialsResponse{
				AccessKeyID:  payload.SessionName,
				Secret:       fmt.Sprintf("secret-%d", len(names)),
				SessionToken: fmt.Sprintf("token-%d", len(names)),
				ExpiresAt:    time.Now().Add(MinDuration),
			})
			if err != nil {
				return nil, err
			}
			return jsonResponse(http.StatusOK, string(body)), nil
		})}
		cache, err := New(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
			return ycauth.Token{Value: "iam-token", ExpiresAt: tokenExpiresAt}, nil
		}), Config{SessionName: "orders-api", Duration: MinDuration, HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}

		sign := func(signer *v4.Signer, credentials aws.Credentials) string {
			t.Helper()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://storage.yandexcloud.net/bucket/key", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := signer.SignHTTP(t.Context(), credentials, request, "UNSIGNED-PAYLOAD", "s3", "ru-central1", time.Now()); err != nil {
				t.Fatal(err)
			}
			return request.Header.Get("Authorization")
		}

		signer := v4.NewSigner()
		for rotation := range 3 {
			credentials, err := cache.Retrieve(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got, want := sign(signer, credentials), sign(v4.NewSigner(), credentials); got != want {
				t.Fatalf("rotation %d: cached signer used an obsolete signing key", rotation)
			}
			cached, err := cache.Retrieve(t.Context())
			if err != nil || cached.AccessKeyID != credentials.AccessKeyID {
				t.Fatalf("cached Retrieve() = (%#v, %v)", cached, err)
			}
			if len(names) != rotation+1 {
				t.Fatalf("issuances = %d, want %d", len(names), rotation+1)
			}
			if rotation < 2 {
				time.Sleep(MinDuration)
			}
		}
		seen := make(map[string]bool)
		for _, name := range names {
			if !strings.HasPrefix(name, "orders-api-") || !validSessionName(name) || seen[name] {
				t.Fatalf("invalid or reused session name %q", name)
			}
			seen[name] = true
		}
	})
}

func TestIssuerSessionNamesAreUniqueAcrossProviders(t *testing.T) {
	t.Parallel()

	for _, prefix := range []string{"a", "orders-api", strings.Repeat("x", 64)} {
		t.Run(prefix, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				seen := make(map[string]bool)
				client := &http.Client{Transport: transportFunc(func(request *http.Request) (*http.Response, error) {
					var payload createCredentialsRequest
					if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
						return nil, err
					}
					name := payload.SessionName
					index := strings.LastIndexByte(name, '-')
					if index <= 0 || index == len(name)-1 || !strings.HasPrefix(prefix, name[:index]) || !validSessionName(name) {
						return nil, fmt.Errorf("invalid session name %q for prefix %q", name, prefix)
					}
					if len(prefix) == 64 && len(name) != 64 {
						return nil, fmt.Errorf("session name length = %d, want 64", len(name))
					}
					if seen[name] {
						return nil, fmt.Errorf("reused session name %q", name)
					}
					seen[name] = true
					body, err := json.Marshal(createCredentialsResponse{
						AccessKeyID: "access", Secret: "secret", SessionToken: "token", ExpiresAt: time.Now().Add(time.Hour),
					})
					if err != nil {
						return nil, err
					}
					return jsonResponse(http.StatusOK, string(body)), nil
				})}
				for range 2 {
					issuer, _, err := newCredentialsIssuer(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
						return ycauth.Token{Value: "iam-token", ExpiresAt: time.Now().Add(2 * time.Hour)}, nil
					}), Config{SessionName: prefix, HTTPClient: client})
					if err != nil {
						t.Fatal(err)
					}
					for range 2 {
						if _, err := issuer.Retrieve(t.Context()); err != nil {
							t.Fatal(err)
						}
					}
				}
			})
		})
	}
}

func TestObserverReportsRefreshAndStaleFallback(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var events []RefreshEvent
		var serviceExpiration time.Time
		failed := false
		client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			if failed {
				return jsonResponse(http.StatusServiceUnavailable, "issuer unavailable"), nil
			}
			serviceExpiration = time.Now().Add(2 * time.Second)
			body, err := json.Marshal(createCredentialsResponse{
				AccessKeyID: "private-access", Secret: "private-secret", SessionToken: "private-session", ExpiresAt: serviceExpiration,
			})
			if err != nil {
				return nil, err
			}
			return jsonResponse(http.StatusOK, string(body)), nil
		})}
		cache, err := New(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
			return ycauth.Token{Value: "private-iam", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}), Config{SessionName: "observed", HTTPClient: client, Observer: ObserverFunc(func(event RefreshEvent) {
			events = append(events, event)
		})})
		if err != nil {
			t.Fatal(err)
		}
		first, err := cache.Retrieve(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0].Err != nil || events[0].UsedStale || events[0].Failures != 0 ||
			!events[0].ExpiresAt.Equal(serviceExpiration) || !strings.HasPrefix(events[0].SessionName, "observed-") {
			t.Fatalf("success events = %+v", events)
		}
		if !first.Expires.Before(events[0].ExpiresAt) {
			t.Fatal("observer must expose service expiration, not adjusted cache expiration")
		}
		if _, err := cache.Retrieve(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatal("cache hit emitted an event")
		}

		failed = true
		time.Sleep(1100 * time.Millisecond)
		if _, err := cache.Retrieve(t.Context()); err != nil {
			t.Fatalf("stale fallback: %v", err)
		}
		if len(events) != 2 || events[1].Err == nil || !events[1].UsedStale || events[1].Failures != 1 ||
			!events[1].ExpiresAt.Equal(serviceExpiration) || events[1].SessionName == events[0].SessionName {
			t.Fatalf("fallback events = %+v", events)
		}
		if _, err := cache.Retrieve(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 {
			t.Fatal("backoff emitted a duplicate event")
		}

		time.Sleep(2 * time.Second)
		if _, err := cache.Retrieve(t.Context()); err == nil {
			t.Fatal("expired credentials were reused")
		}
		if len(events) != 3 || events[2].Err == nil || events[2].UsedStale || events[2].Failures != 2 || !events[2].ExpiresAt.IsZero() {
			t.Fatalf("expired fallback events = %+v", events)
		}
		failed = false
		time.Sleep(30 * time.Second)
		if _, err := cache.Retrieve(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(events) != 4 || events[3].Err != nil || events[3].Failures != 0 || events[3].UsedStale {
			t.Fatalf("recovery events = %+v", events)
		}
		for _, event := range events {
			if event.FinishedAt.Before(event.StartedAt) {
				t.Fatal("invalid refresh duration")
			}
		}
		encoded, err := json.Marshal(events)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "private-") {
			t.Fatal("observer exposed credential material")
		}
	})
}

func TestObserverReportsIAMFailureOnce(t *testing.T) {
	t.Parallel()
	var events []RefreshEvent
	wantErr := errors.New("IAM unavailable")
	cache, err := New(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{}, wantErr
	}), Config{SessionName: "observed", Observer: ObserverFunc(func(event RefreshEvent) { events = append(events, event) })})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Retrieve(t.Context()); !errors.Is(err, wantErr) {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if _, err := cache.Retrieve(t.Context()); !errors.Is(err, ycauth.ErrBackoff) {
		t.Fatalf("backoff error = %v", err)
	}
	if len(events) != 1 || !errors.Is(events[0].Err, wantErr) || events[0].SessionName != "" || events[0].Failures != 1 || events[0].UsedStale {
		t.Fatalf("IAM failure events = %+v", events)
	}
}

func TestObserverPanicDoesNotAffectCredentials(t *testing.T) {
	t.Parallel()
	for _, failed := range []bool{false, true} {
		t.Run(strconv.FormatBool(failed), func(t *testing.T) {
			t.Parallel()
			var observations atomic.Int64
			client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				if failed {
					return jsonResponse(http.StatusServiceUnavailable, "issuer unavailable"), nil
				}
				body, err := json.Marshal(createCredentialsResponse{AccessKeyID: "access", Secret: "secret", SessionToken: "session", ExpiresAt: time.Now().Add(time.Hour)})
				if err != nil {
					return nil, err
				}
				return jsonResponse(http.StatusOK, string(body)), nil
			})}
			cache, err := New(ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
				return ycauth.Token{Value: "iam", ExpiresAt: time.Now().Add(2 * time.Hour)}, nil
			}), Config{SessionName: "observed", HTTPClient: client, Observer: ObserverFunc(func(RefreshEvent) {
				observations.Add(1)
				panic("observer failed")
			})})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := cache.Retrieve(t.Context())
			if (err != nil) != failed || credentials.HasKeys() == failed {
				t.Fatalf("Retrieve() = (%#v, %v)", credentials, err)
			}
			if observations.Load() != 1 {
				t.Fatal("observer was not called once")
			}
		})
	}
}
