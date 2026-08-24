package httpx //nolint:testpackage // Fuzz targets exercise unexported parsers.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func FuzzRetryAfter(f *testing.F) {
	for _, seed := range []string{
		"", "0", "-1", "120", " 30 ", "9223372036854775807", "99999999999999999999",
		"Wed, 21 Oct 2026 07:28:00 GMT", "not-a-date", "+5", "1e3",
	} {
		f.Add(seed)
	}

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, value string) {
		if got := retryAfter(value, now); got < 0 {
			t.Fatalf("retryAfter(%q) = %s, want a non-negative delay", value, got)
		}
	})
}

func FuzzResponseError(f *testing.F) {
	for _, seed := range [][]byte{
		nil, []byte("{}"), []byte("plain text"), []byte("\xff\xfe invalid utf8"),
		[]byte(strings.Repeat("a", int(maxErrorBody)+64)),
	} {
		f.Add(seed)
	}

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, body []byte) {
		recorder := httptest.NewRecorder()
		recorder.WriteHeader(http.StatusBadGateway)
		_, _ = recorder.Write(body)

		err := ResponseError("fuzz", recorder.Result(), now)

		message := err.Error()
		if !utf8.ValidString(message) {
			t.Fatalf("error message is not valid UTF-8: %q", message)
		}

		if int64(len(message)) > maxErrorBody+128 {
			t.Fatalf("error message length = %d, want the body bounded", len(message))
		}
	})
}
