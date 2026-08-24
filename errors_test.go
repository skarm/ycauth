package ycauth_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/skarm/ycauth"
)

func TestAPIErrorMessage(t *testing.T) {
	t.Parallel()

	err := &ycauth.APIError{
		Op:         "exchange token",
		StatusCode: http.StatusTooManyRequests,
		Body:       "slow down",
		RequestID:  "request-id",
	}
	if got := err.Error(); !strings.Contains(got, "request-id") || !strings.Contains(got, "slow down") ||
		!strings.Contains(got, "429") {
		t.Fatalf("Error() = %q", got)
	}
	if got := (&ycauth.APIError{Op: "op", StatusCode: 503}).Error(); got != "op: HTTP 503 Service Unavailable" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestAPIErrorTemporary(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		if !(&ycauth.APIError{StatusCode: status}).Temporary() {
			t.Errorf("status %d is not temporary", status)
		}
	}
	if (&ycauth.APIError{StatusCode: http.StatusUnauthorized}).Temporary() {
		t.Error("401 must not be temporary")
	}
}
