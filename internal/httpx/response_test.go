package httpx //nolint:testpackage

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/skarm/ycauth"
)

type countingReader struct {
	reader io.Reader
	read   int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.read += int64(count)

	return count, err
}

func TestErrorBodyStaysWithinTheBound(t *testing.T) {
	t.Parallel()

	// Alternating invalid and valid bytes: replacing each invalid run would
	// grow the excerpt past its bound instead of shrinking it.
	hostile := bytes.Repeat([]byte{0xff, 'a'}, int(maxErrorBody))
	for _, data := range [][]byte{hostile, hostile[:maxErrorBody], {0xff}, nil} {
		body := errorBody(data)
		if int64(len(body)) > maxErrorBody+int64(len("…")) {
			t.Fatalf("errorBody(%d bytes) = %d bytes, want at most %d", len(data), len(body), maxErrorBody)
		}
		if !utf8.ValidString(body) {
			t.Fatalf("errorBody(%d bytes) is not valid UTF-8", len(data))
		}
	}
}

func TestReadErrorBodyDrainsOnlyPlausiblyReusableResponses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		size          int64
		contentLength int64
		wantRead      int64
	}{
		{name: "short body", size: 32, contentLength: 32, wantRead: 32},
		{
			name:          "unknown bounded drain",
			size:          maxErrorBody + 1 + maxDrain + 32,
			contentLength: -1,
			wantRead:      maxErrorBody + 1 + maxDrain + 1,
		},
		{
			name:          "known excessive tail",
			size:          maxErrorBody + 1 + maxDrain + 32,
			contentLength: maxErrorBody + 1 + maxDrain + 32,
			wantRead:      maxErrorBody + 1,
		},
		{
			name:          "known reusable tail",
			size:          maxErrorBody + 1 + maxDrain,
			contentLength: maxErrorBody + 1 + maxDrain,
			wantRead:      maxErrorBody + 1 + maxDrain,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			reader := &countingReader{reader: strings.NewReader(strings.Repeat("x", int(testCase.size)))}
			body, err := readErrorBody(reader, testCase.contentLength)
			if err != nil {
				t.Fatalf("readErrorBody() error = %v", err)
			}
			if reader.read != testCase.wantRead {
				t.Fatalf("readErrorBody() read %d bytes, want %d", reader.read, testCase.wantRead)
			}
			if testCase.size > maxErrorBody && !strings.HasSuffix(body, "…") {
				t.Fatalf("readErrorBody() = %q, want truncated excerpt", body)
			}
		})
	}
}

func TestResponseError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	response := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Header: http.Header{
			"Retry-After":  {"7"},
			"X-Request-Id": {"request-id"},
		},
		Body: io.NopCloser(strings.NewReader(strings.Repeat("x", int(maxErrorBody)+1))),
	}
	err := ResponseError("exchange token", response, now)
	var apiErr *ycauth.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("ResponseError() = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusServiceUnavailable || apiErr.RequestID != "request-id" || apiErr.RetryAfter != 7*time.Second {
		t.Fatalf("APIError = %#v", apiErr)
	}
	if !strings.HasSuffix(apiErr.Body, "…") {
		t.Fatalf("truncated body = %q", apiErr.Body)
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	retryAfterCases := []struct {
		value string
		want  time.Duration
	}{
		{value: "7", want: 7 * time.Second},
		{value: "-1", want: 0},
		{value: now.Add(time.Minute).Format(http.TimeFormat), want: time.Minute},
		// An untrusted hint must not be able to suspend refreshes for longer
		// than maxRetryAfter, whether it arrives as seconds or as a date.
		{value: "9223372036854775807", want: maxRetryAfter},
		{value: "2592000", want: maxRetryAfter},
		{value: now.AddDate(1, 0, 0).Format(http.TimeFormat), want: maxRetryAfter},
		{value: "invalid", want: 0},
	}
	for _, testCase := range retryAfterCases {
		if got := retryAfter(testCase.value, now); got != testCase.want {
			t.Errorf("retryAfter(%q) = %s, want %s", testCase.value, got, testCase.want)
		}
	}
}
