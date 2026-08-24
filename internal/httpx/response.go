package httpx

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/ycauth"
)

const (
	maxErrorBody = int64(4 << 10)
	// maxRetryAfter bounds an untrusted Retry-After hint. Without it a single
	// response could suspend refreshes for as long as the server likes.
	maxRetryAfter = 5 * time.Minute
	// maxDrain bounds the known or plausible tail of an error body consumed to
	// make its connection reusable. Larger known bodies are closed immediately.
	maxDrain = int64(64 << 10)
	// maxRequestIDLen bounds the upstream request id copied into error strings.
	maxRequestIDLen = 128
)

// ResponseError converts a non-success response into a [ycauth.APIError]. It
// bounds the response-body excerpt, request ID, and Retry-After delay.
func ResponseError(operation string, response *http.Response, now time.Time) error {
	body, err := readErrorBody(response.Body, response.ContentLength)
	if err != nil {
		return fmt.Errorf("%s: read error response: %w", operation, err)
	}

	return &ycauth.APIError{
		Op:         operation,
		StatusCode: response.StatusCode,
		Body:       body,
		RequestID:  requestID(response.Header),
		RetryAfter: retryAfter(response.Header.Get("Retry-After"), now),
	}
}

// readErrorBody returns a bounded, valid UTF-8 excerpt. When practical, it also
// consumes a bounded remainder so the HTTP transport can reuse the connection.
func readErrorBody(body io.Reader, contentLength int64) (string, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxErrorBody+1))
	if err != nil {
		return "", err
	}

	// A short body has already reached EOF. For a truncated body, consume a
	// bounded tail only when its declared size is small enough to save the
	// connection, or when the size is unknown and reuse is still plausible.
	if int64(len(data)) > maxErrorBody && shouldDrain(contentLength, int64(len(data))) {
		// The extra byte lets an exactly maxDrain-byte tail expose its final EOF.
		_, _ = io.Copy(io.Discard, io.LimitReader(body, maxDrain+1))
	}

	return strings.TrimSpace(errorBody(data)), nil
}

// shouldDrain reports whether the unread body may fit within maxDrain. A
// non-positive content length represents an unknown size worth probing.
func shouldDrain(contentLength, bytesRead int64) bool {
	return contentLength <= 0 || contentLength-bytesRead <= maxDrain
}

// errorBody truncates the upstream body on a rune boundary and drops any
// invalid UTF-8 so the result stays safe to embed in an error string. Dropping
// rather than replacing keeps the result within maxErrorBody: a replacement
// character is three bytes and would let a hostile body grow the excerpt.
func errorBody(data []byte) string {
	if int64(len(data)) <= maxErrorBody {
		return strings.ToValidUTF8(string(data), "")
	}

	return strings.ToValidUTF8(string(data[:maxErrorBody]), "") + "…"
}

// requestID returns the first bounded request identifier recognized by Yandex
// Cloud APIs.
func requestID(header http.Header) string {
	for _, name := range []string{"X-Request-Id", "X-Server-Trace-Id", "X-Trace-Id"} {
		if value := strings.TrimSpace(header.Get(name)); value != "" && len(value) <= maxRequestIDLen {
			return value
		}
	}

	return ""
}

// retryAfter parses an HTTP Retry-After value and clamps it to maxRetryAfter.
func retryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		switch {
		case seconds <= 0:
			return 0
		case seconds > int64(maxRetryAfter/time.Second):
			return maxRetryAfter
		default:
			return time.Duration(seconds) * time.Second
		}
	}

	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}

	return min(when.Sub(now), maxRetryAfter)
}
