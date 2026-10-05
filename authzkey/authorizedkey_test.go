package authzkey //nolint:testpackage

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/skarm/ycauth"
)

var testKey = sync.OnceValues(func() (*rsa.PrivateKey, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	document, err := json.Marshal(keyDocument{ID: "key-id", ServiceAccountID: "service-account-id", PrivateKey: string(encoded)})
	if err != nil {
		panic(err)
	}
	return key, document
})

func TestSourceAcquire(t *testing.T) {
	t.Parallel()

	key, document := testKey()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(12 * time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Accept") != "application/json" {
			t.Errorf("request = %s, Accept %q", request.Method, request.Header.Get("Accept"))
		}
		if got := request.Header.Get("User-Agent"); got != "application/1.0" {
			t.Errorf("User-Agent = %q", got)
		}
		var body tokenRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		claims := &jwt.RegisteredClaims{}
		parsed, err := jwt.ParseWithClaims(body.JWT, claims, func(token *jwt.Token) (any, error) {
			if token.Header["kid"] != "key-id" {
				return nil, errors.New("unexpected JWT key ID")
			}
			return &key.PublicKey, nil
		}, jwt.WithValidMethods([]string{"PS256"}), jwt.WithAudience(tokenAudience), jwt.WithIssuer("service-account-id"), jwt.WithTimeFunc(func() time.Time { return now }))
		if err != nil || !parsed.Valid {
			t.Errorf("parse JWT = (%v, %v)", parsed, err)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if claims.NotBefore == nil || !claims.NotBefore.Equal(claims.IssuedAt.Time) {
			t.Errorf("JWT nbf = %v, want iat %v", claims.NotBefore, claims.IssuedAt)
		}
		if got := claims.IssuedAt.Sub(now); got != -clockSkew {
			t.Errorf("JWT iat offset = %s, want -%s", got, clockSkew)
		}
		if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != jwtLifetime+clockSkew {
			t.Errorf("JWT lifetime = %s, want %s", got, jwtLifetime+clockSkew)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"iamToken":"iam-token","expiresAt":`+strconv.Quote(expiresAt.Format(time.RFC3339Nano))+`}`)
	}))
	defer server.Close()

	source, err := NewJSON(bytes.NewReader(document), WithEndpoint(server.URL), WithHTTPClient(server.Client()), WithUserAgent("application/1.0"))
	if err != nil {
		t.Fatalf("NewJSON() error = %v", err)
	}
	source.now = func() time.Time { return now }
	token, err := source.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if token.Value != "iam-token" || !token.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Acquire() = %v", token)
	}
}

func TestSourceAcquireResponseValidation(t *testing.T) {
	t.Parallel()

	_, document := testKey()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	responseCases := []struct {
		name      string
		body      string
		wantError string
	}{
		{name: "malformed JSON", body: `{`, wantError: "unexpected end of JSON input"},
		{name: "missing fields", body: `{}`, wantError: "token is empty"},
		{name: "expired", body: `{"iamToken":"token","expiresAt":` + strconv.Quote(now.Add(-time.Second).Format(time.RFC3339Nano)) + `}`, wantError: "token expired at"},
		{name: "oversized", body: strings.Repeat("x", int(maxResponseBodySize)+1), wantError: "JSON exceeds"},
		{name: "implausible lifetime", body: `{"iamToken":"token","expiresAt":` +
			strconv.Quote(now.Add(30*24*time.Hour).Format(time.RFC3339Nano)) + `}`, wantError: "exceeds the maximum lifetime"},
	}
	for _, testCase := range responseCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, testCase.body)
			}))
			defer server.Close()

			source, err := NewJSON(bytes.NewReader(document), WithEndpoint(server.URL), WithHTTPClient(server.Client()))
			if err != nil {
				t.Fatalf("NewJSON() error = %v", err)
			}
			source.now = func() time.Time { return now }
			if _, err := source.Acquire(context.Background()); err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("Acquire() error = %v, want containing %q", err, testCase.wantError)
			}
		})
	}
}

func TestSourceAcquireAllowsMaximumLifetimeWithClockSkew(t *testing.T) {
	t.Parallel()

	_, document := testKey()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(maxTokenLifetime + maxExpirationClockSkew)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"iamToken":"iam-token","expiresAt":`+strconv.Quote(expiresAt.Format(time.RFC3339Nano))+`}`)
	}))
	defer server.Close()

	source, err := NewJSON(bytes.NewReader(document), WithEndpoint(server.URL), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewJSON() error = %v", err)
	}
	source.now = func() time.Time { return now }

	token, err := source.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if token.Value != "iam-token" || !token.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Acquire() = %v", token)
	}
}

func TestSourceAcquireRetriesInvalidSuccessfulResponse(t *testing.T) {
	t.Parallel()

	_, document := testKey()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = io.WriteString(writer, `{}`)
			return
		}

		_, _ = io.WriteString(writer, `{"iamToken":"iam-token","expiresAt":`+strconv.Quote(expiresAt.Format(time.RFC3339Nano))+`}`)
	}))
	defer server.Close()

	source, err := NewJSON(bytes.NewReader(document), WithEndpoint(server.URL), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewJSON() error = %v", err)
	}
	source.now = func() time.Time { return now }

	token, err := source.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if token.Value != "iam-token" || !token.ExpiresAt.Equal(expiresAt) || requests.Load() != 2 {
		t.Fatalf("Acquire() = %v after %d requests", token, requests.Load())
	}
}

func TestSourceAcquireRejectsNilContext(t *testing.T) {
	t.Parallel()

	_, document := testKey()
	source, err := NewJSON(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("NewJSON() error = %v", err)
	}
	//nolint:staticcheck // Nil is intentional: this verifies defensive validation.
	if _, err := source.Acquire(nil); err == nil {
		t.Fatal("Acquire(nil) error = nil")
	}
}

func TestSourceAcquireAPIError(t *testing.T) {
	t.Parallel()

	_, document := testKey()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("Retry-After", "7")
		writer.Header().Set("X-Request-ID", "request-id")
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := NewJSON(bytes.NewReader(document), WithEndpoint(server.URL))
	if err != nil {
		t.Fatalf("NewJSON() error = %v", err)
	}
	_, err = source.Acquire(context.Background())
	var apiErr *ycauth.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Acquire() error = %v, want *APIError", err)
	}
	if !apiErr.Temporary() || apiErr.RetryAfter != 7*time.Second || apiErr.RequestID != "request-id" {
		t.Fatalf("APIError = %#v", apiErr)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1 because HTTP errors must use caller backoff", requests.Load())
	}
}

// keyDocumentWithout returns a valid authorized key with one identifier blanked.
func keyDocumentWithout(field string) []byte {
	_, encoded := testKey()

	var document keyDocument
	if err := json.Unmarshal(encoded, &document); err != nil {
		panic(err)
	}

	switch field {
	case "id":
		document.ID = ""
	case "service_account_id":
		document.ServiceAccountID = ""
	}

	data, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}

	return data
}

func TestNewJSONValidation(t *testing.T) {
	t.Parallel()
	_, validDocument := testKey()

	invalidInputCases := []struct {
		name string
		data []byte
		opts []Option
	}{
		{name: "malformed", data: []byte("{")},
		{name: "missing fields", data: []byte(`{}`)},
		{name: "bad PEM", data: []byte(`{"id":"id","service_account_id":"sa","private_key":"bad"}`)},
		{name: "missing id", data: keyDocumentWithout("id")},
		{name: "missing service account", data: keyDocumentWithout("service_account_id")},
		{name: "oversized document", data: func() []byte {
			_, document := testKey()

			return append(append([]byte(nil), bytes.Repeat([]byte(" "), int(maxKeyDocumentSize))...), document...)
		}()},
		{name: "second document", data: append(append([]byte(nil), validDocument...), []byte(`{}`)...)},
		{name: "oversized valid document", data: append(append([]byte(nil), validDocument...),
			bytes.Repeat([]byte(" "), int(maxKeyDocumentSize))...)},
		{name: "bad endpoint", data: func() []byte { _, data := testKey(); return data }(), opts: []Option{WithEndpoint("relative")}},
	}
	for _, testCase := range invalidInputCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewJSON(bytes.NewReader(testCase.data), testCase.opts...); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("NewJSON() error = %v", err)
			}
		})
	}
}

func TestNewJSONRejectsWeakRSAKey(t *testing.T) {
	t.Parallel()

	// #nosec G403 -- deliberately weak key verifies that NewJSON rejects it.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	document, err := json.Marshal(keyDocument{ID: "key-id", ServiceAccountID: "service-account-id", PrivateKey: string(encoded)})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := NewJSON(bytes.NewReader(document)); err == nil || !strings.Contains(err.Error(), "at least 2048 bits") {
		t.Fatalf("NewJSON() error = %v, want weak-key error", err)
	}
}

func TestNewFile(t *testing.T) {
	t.Parallel()

	_, document := testKey()
	path := filepath.Join(t.TempDir(), "authorized-key.json")
	if err := os.WriteFile(path, document, 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("os.Chmod() error = %v", err)
	}
	if _, err := NewFile(path); err != nil {
		t.Fatalf("NewFile() error = %v", err)
	}
	if _, err := NewFile(""); err == nil {
		t.Fatal("NewFile(empty) error = nil")
	}
	if _, err := NewFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("NewFile(missing) error = nil")
	}
}

func TestNewJSONAcceptsPKCS8RSAAndRejectsOtherPEMData(t *testing.T) {
	t.Parallel()

	key, _ := testKey()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	document := func(privateKey []byte) []byte {
		data, err := json.Marshal(keyDocument{ID: "key-id", ServiceAccountID: "service-account-id", PrivateKey: string(privateKey)})
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		return data
	}
	if _, err := NewJSON(bytes.NewReader(document(encoded))); err != nil {
		t.Fatalf("NewJSON(PKCS8 RSA) error = %v", err)
	}
	if _, err := NewJSON(bytes.NewReader(document(append(encoded, []byte("unexpected")...)))); err == nil {
		t.Fatal("NewJSON(PEM with trailing data) error = nil")
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey(EC) error = %v", err)
	}
	if _, err := NewJSON(bytes.NewReader(document(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8})))); err == nil {
		t.Fatal("NewJSON(EC key) error = nil")
	}
}
