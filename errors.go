package ycauth

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// ErrBackoff indicates that a previous refresh failure is still being backed
// off. Use [errors.Is] to distinguish a suppressed retry from a live request
// that failed.
var ErrBackoff = errors.New("refresh is backed off")

// APIError describes a non-success response from a Yandex Cloud HTTP API.
//
// Body holds up to a few kilobytes of the upstream response. Treat it as
// untrusted, potentially sensitive data: [APIError.Error] includes it, so any
// log that records the error also records the body excerpt.
type APIError struct {
	// Op identifies the operation that received the response.
	Op string
	// StatusCode is the HTTP status code returned by the API.
	StatusCode int
	// Body is a bounded, untrusted excerpt of the response body.
	Body string
	// RequestID identifies the upstream request when the API supplied one.
	RequestID string
	// RetryAfter is the server-requested delay, bounded to a few minutes, or
	// zero when none was supplied.
	RetryAfter time.Duration
}

// Error formats the operation, HTTP status, request ID, and bounded response
// body. The result may contain sensitive upstream data from [APIError.Body].
func (e *APIError) Error() string {
	status := "HTTP " + strconv.Itoa(e.StatusCode)
	if text := http.StatusText(e.StatusCode); text != "" {
		status += " " + text
	}

	if e.RequestID != "" {
		status += " (request " + e.RequestID + ")"
	}

	if e.Body == "" {
		return e.Op + ": " + status
	}

	return e.Op + ": " + status + ": " + e.Body
}

// Temporary reports whether retrying the operation later may succeed.
func (e *APIError) Temporary() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// retryAfterHint returns the server-requested delay carried by err, if any.
func retryAfterHint(err error) time.Duration {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.RetryAfter
	}

	return 0
}
