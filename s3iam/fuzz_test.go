package s3iam //nolint:testpackage // Fuzz targets assert on the unexported document.

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzRawPolicy(f *testing.F) {
	for _, seed := range []string{
		"", "{}", "   ", "null", "[]", `{"Version":"2012-10-17"}`,
		`{"Version":"2012-10-17","Statement":[]}` + "\n\t ", `{"a":`, strings.Repeat("{", 512),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, document string) {
		policy, err := RawPolicy([]byte(document))
		if err != nil {
			if policy.JSON() != "" {
				t.Fatalf("RawPolicy() returned a document alongside error %v", err)
			}

			return
		}

		if !json.Valid([]byte(policy.JSON())) {
			t.Fatalf("RawPolicy() produced invalid JSON: %q", policy.JSON())
		}

		if count := utf8.RuneCountInString(policy.JSON()); count > maxPolicyLength {
			t.Fatalf("policy length = %d, want at most %d", count, maxPolicyLength)
		}
	})
}

func FuzzPrefixPolicy(f *testing.F) {
	for _, seed := range []struct {
		bucket      string
		prefix      string
		permissions uint32
	}{
		{"bucket", "prefix", uint32(allPermissions)},
		{"bucket", "", uint32(PermissionReadObject)},
		{"bucket", "/nested/path/", uint32(PermissionListObjects)},
		{"bad bucket", "prefix", uint32(PermissionReadObject)},
		{"\x96", "0", uint32(PermissionReadObject)},      // invalid UTF-8 once rewrote the ARN
		{"bucket", "\xff", uint32(PermissionReadObject)}, // invalid UTF-8 in the prefix
		{"bucket", `"},{"Effect":"Allow"`, uint32(PermissionReadObject)},
	} {
		f.Add(seed.bucket, seed.prefix, seed.permissions)
	}

	f.Fuzz(func(t *testing.T, bucket, prefix string, permissions uint32) {
		policy, err := PrefixPolicy(bucket, prefix, Permissions(permissions))
		if err != nil {
			return
		}

		document := policy.JSON()
		if !json.Valid([]byte(document)) {
			t.Fatalf("PrefixPolicy() produced invalid JSON: %q", document)
		}

		// A crafted bucket or prefix must never escape into extra statements.
		var decoded policyDocument
		if err := json.Unmarshal([]byte(document), &decoded); err != nil {
			t.Fatalf("decode generated policy: %v", err)
		}

		if len(decoded.Statement) > 3 {
			t.Fatalf("statement count = %d, want at most 3", len(decoded.Statement))
		}

		for _, statement := range decoded.Statement {
			if statement.Effect != "Allow" {
				t.Fatalf("statement effect = %q, want Allow", statement.Effect)
			}

			for _, resource := range statement.Resource {
				if !strings.HasPrefix(resource, "arn:aws:s3:::"+bucket) {
					t.Fatalf("resource %q escaped bucket %q", resource, bucket)
				}
			}
		}
	})
}
