package authzkey //nolint:testpackage // Fuzz targets exercise the unexported parser.

import (
	"bytes"
	"testing"
)

func FuzzParsePrivateKey(f *testing.F) {
	for _, seed := range []string{
		"",
		"not pem",
		"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
		"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
		"-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0\n\nAAAA\n-----END PRIVATE KEY-----\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, document string) {
		key, err := parsePrivateKey([]byte(document))
		switch {
		case err != nil && key != nil:
			t.Fatalf("parsePrivateKey() returned a key alongside error %v", err)
		case err == nil && key == nil:
			t.Fatal("parsePrivateKey() returned no key and no error")
		}
	})
}

func FuzzNewJSON(f *testing.F) {
	for _, seed := range []string{
		"", "{}", "null", `{"id":"a","service_account_id":"b","private_key":"c"}`,
		`{"id":"  ","service_account_id":"b","private_key":"-----BEGIN PRIVATE KEY-----"}`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, document string) {
		source, err := NewJSON(bytes.NewReader([]byte(document)))
		if err == nil && source == nil {
			t.Fatal("NewJSON() returned no source and no error")
		}
	})
}
