package ycauth_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skarm/ycauth"
)

func TestTokenRedactsValue(t *testing.T) {
	t.Parallel()

	token := ycauth.Token{Value: "super-secret", ExpiresAt: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)}
	for _, formatted := range []string{fmt.Sprint(token), fmt.Sprintf("%+v", token), fmt.Sprintf("%#v", token)} {
		if strings.Contains(formatted, token.Value) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("formatted token = %q, want redacted", formatted)
		}
	}

	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), token.Value) {
		t.Fatalf("JSON token = %s, contains secret", encoded)
	}
	if value := token.LogValue(); strings.Contains(value.String(), token.Value) {
		t.Fatalf("LogValue() = %v, contains secret", value)
	}
}
