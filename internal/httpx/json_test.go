package httpx //nolint:testpackage

import (
	"bytes"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	t.Parallel()

	valid := []byte(`{"value":"ok"}`)
	testCases := []struct {
		name    string
		data    []byte
		limit   int64
		wantErr bool
	}{
		{name: "valid", data: valid, limit: int64(len(valid))},
		{name: "trailing whitespace", data: append(append([]byte(nil), valid...), '\n'), limit: int64(len(valid) + 1)},
		{name: "second document", data: append(append([]byte(nil), valid...), []byte(`{}`)...), limit: int64(len(valid) + 2), wantErr: true},
		{name: "oversized valid document", data: append(append([]byte(nil), valid...), ' '), limit: int64(len(valid)), wantErr: true},
		{name: "malformed", data: []byte(`{`), limit: 1, wantErr: true},
		{name: "invalid UTF-8", data: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, limit: 9, wantErr: true},
		{name: "invalid limit", data: valid, limit: 0, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var result struct {
				Value string `json:"value"`
			}
			err := DecodeJSON(bytes.NewReader(testCase.data), testCase.limit, &result)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("DecodeJSON() error = %v, wantErr %v", err, testCase.wantErr)
			}
			if !testCase.wantErr && result.Value != "ok" {
				t.Fatalf("DecodeJSON() value = %q, want ok", result.Value)
			}
		})
	}
}
