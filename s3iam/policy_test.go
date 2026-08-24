package s3iam //nolint:testpackage // White-box assertions verify the generated policy structure.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestPrefixPolicy(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicy("bucket", "tenant/42", allPermissions)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	if len(policy.JSON()) > maxPolicyLength {
		t.Fatalf("policy length = %d", len(policy.JSON()))
	}

	var document policyDocument
	if err := json.Unmarshal([]byte(policy.JSON()), &document); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if document.Version != "2012-10-17" || len(document.Statement) != 3 {
		t.Fatalf("policy = %#v", document)
	}

	list := document.Statement[0]
	if !contains(list.Action, "s3:ListBucket") || list.Resource[0] != "arn:aws:s3:::bucket" {
		t.Fatalf("list statement = %#v", list)
	}
	prefixes := list.Condition["StringLike"]["s3:prefix"]
	if len(prefixes) != 2 || prefixes[0] != "tenant/42" || prefixes[1] != "tenant/42/*" {
		t.Fatalf("prefix condition = %#v", prefixes)
	}

	bucket := document.Statement[1]
	if len(bucket.Action) != 1 || !contains(bucket.Action, "s3:GetBucketLocation") {
		t.Fatalf("bucket statement = %#v", bucket)
	}
	objects := document.Statement[2]
	for _, action := range []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"} {
		if !contains(objects.Action, action) {
			t.Errorf("object actions %v do not contain %s", objects.Action, action)
		}
	}
	if objects.Resource[0] != "arn:aws:s3:::bucket/tenant/42/*" {
		t.Fatalf("object resource = %q", objects.Resource[0])
	}
}

func TestMultipartPolicyDoesNotGrantBucketWideListing(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicy("bucket", "tenant", PermissionMultipartUpload)
	if err != nil {
		t.Fatalf("PrefixPolicy() error = %v", err)
	}
	if strings.Contains(policy.JSON(), "s3:ListBucketMultipartUploads") {
		t.Fatalf("policy grants bucket-wide multipart listing: %s", policy.JSON())
	}
}

func TestPrefixPolicyRequiresExplicitPermissions(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		bucket      string
		permissions Permissions
	}{
		{bucket: "", permissions: PermissionReadObject},
		{bucket: "bad bucket", permissions: PermissionReadObject},
		{bucket: "bad*bucket", permissions: PermissionReadObject},
		{bucket: "bucket", permissions: 0},
		{bucket: "bucket", permissions: 1 << 30},
	} {
		if _, err := PrefixPolicy(testCase.bucket, "", testCase.permissions); err == nil {
			t.Fatalf("PrefixPolicy(%q, %d) error = nil", testCase.bucket, testCase.permissions)
		}
	}
	if _, err := PrefixPolicy("bucket", "tenant/*", PermissionReadObject); err == nil {
		t.Fatal("PrefixPolicy(wildcard prefix) error = nil")
	}
}

func TestRawPolicy(t *testing.T) {
	t.Parallel()

	policy, err := RawPolicy([]byte(` {
        "Version": "2012-10-17",
        "Statement": []
    } `))
	if err != nil {
		t.Fatalf("RawPolicy() error = %v", err)
	}
	if strings.Contains(policy.JSON(), "\n") {
		t.Fatalf("RawPolicy() = %q, want compact JSON", policy.JSON())
	}
	if _, err := RawPolicy([]byte(`[]`)); err == nil {
		t.Fatal("RawPolicy(array) error = nil")
	}
	if _, err := RawPolicy([]byte(`{`)); err == nil {
		t.Fatal("RawPolicy(malformed) error = nil")
	}
	if _, err := RawPolicy([]byte(`{"x":"` + strings.Repeat("x", maxPolicyLength) + `"}`)); err == nil {
		t.Fatal("RawPolicy(oversized) error = nil")
	}
}

func contains(values []string, want string) bool {
	return slices.Contains(values, want)
}

func TestPrefixPolicyRejectsUnusableBucketAndPrefix(t *testing.T) {
	t.Parallel()

	buckets := []string{
		"", "ab", strings.Repeat("b", 64), "Bucket", "bad bucket", "bucket/name", "b\xc3(", "\x96",
		".abc", "abc-", "a..b", "a.-b", "a-.b", "10.1.3.9",
	}
	for _, bucket := range buckets {
		if _, err := PrefixPolicy(bucket, "", PermissionReadObject); err == nil {
			t.Errorf("PrefixPolicy(%q) error = nil", bucket)
		}
	}

	prefixes := []string{
		"/tenant", "tenant/", "/", "with*wildcard", "with?wildcard", "with$variable", "with\nnewline", "invalid\xffutf8",
	}
	for _, prefix := range prefixes {
		if _, err := PrefixPolicy("bucket", prefix, PermissionReadObject); err == nil {
			t.Errorf("PrefixPolicy(prefix %q) error = nil", prefix)
		}
	}
}

func BenchmarkPrefixPolicy(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		if _, err := PrefixPolicy("bucket", "tenant/42", allPermissions); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRawPolicy(b *testing.B) {
	document := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]}
		]
	}`)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := RawPolicy(document); err != nil {
			b.Fatal(err)
		}
	}
}
