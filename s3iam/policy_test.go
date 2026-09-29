package s3iam //nolint:testpackage // White-box assertions verify the generated policy structure.

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPrefixPoliciesKeepsGrantsIndependent(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicies(
		PrefixGrant{Bucket: "source-bucket", Prefix: "incoming", Permissions: PermissionReadObject | PermissionListObjects},
		PrefixGrant{Bucket: "target-bucket", Prefix: "processed", Permissions: PermissionWriteObject | PermissionListObjects},
		PrefixGrant{Bucket: "source-bucket", Prefix: "archive", Permissions: PermissionDeleteObject | PermissionListObjects},
	)
	if err != nil {
		t.Fatal(err)
	}
	var got policyDocument
	if err := json.Unmarshal([]byte(policy.JSON()), &got); err != nil {
		t.Fatal(err)
	}
	want := policyDocument{Version: "2012-10-17", Statement: []policyStatement{
		{Effect: "Allow", Principal: "*", Action: []string{"s3:ListBucket"}, Resource: []string{"arn:aws:s3:::source-bucket"},
			Condition: map[string]map[string][]string{"StringLike": {"s3:prefix": {"incoming", "incoming/*"}}}},
		{Effect: "Allow", Principal: "*", Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::source-bucket/incoming/*"}},
		{Effect: "Allow", Principal: "*", Action: []string{"s3:ListBucket"}, Resource: []string{"arn:aws:s3:::target-bucket"},
			Condition: map[string]map[string][]string{"StringLike": {"s3:prefix": {"processed", "processed/*"}}}},
		{Effect: "Allow", Principal: "*", Action: []string{"s3:PutObject"}, Resource: []string{"arn:aws:s3:::target-bucket/processed/*"}},
		{Effect: "Allow", Principal: "*", Action: []string{"s3:ListBucket"}, Resource: []string{"arn:aws:s3:::source-bucket"},
			Condition: map[string]map[string][]string{"StringLike": {"s3:prefix": {"archive", "archive/*"}}}},
		{Effect: "Allow", Principal: "*", Action: []string{"s3:DeleteObject"}, Resource: []string{"arn:aws:s3:::source-bucket/archive/*"}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy = %s, want %#v", policy.JSON(), want)
	}
}

func TestPrefixPoliciesWholeBucket(t *testing.T) {
	t.Parallel()

	policy, err := PrefixPolicies(PrefixGrant{Bucket: "bucket", Permissions: PermissionReadObject | PermissionListObjects})
	if err != nil {
		t.Fatal(err)
	}
	var got policyDocument
	if err := json.Unmarshal([]byte(policy.JSON()), &got); err != nil {
		t.Fatal(err)
	}
	want := policyDocument{Version: "2012-10-17", Statement: []policyStatement{
		{Effect: "Allow", Principal: "*", Action: []string{"s3:ListBucket"}, Resource: []string{"arn:aws:s3:::bucket"}},
		{Effect: "Allow", Principal: "*", Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::bucket/*"}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy = %s, want %#v", policy.JSON(), want)
	}
}

func TestPrefixPoliciesRejectsInvalidGrants(t *testing.T) {
	t.Parallel()

	if policy, err := PrefixPolicies(); err == nil || policy.JSON() != "" {
		t.Fatalf("empty grants: policy = %q, error = %v", policy.JSON(), err)
	}
	valid := PrefixGrant{Bucket: "bucket", Prefix: "tenant", Permissions: PermissionReadObject}
	for _, invalid := range []PrefixGrant{
		{},
		{Bucket: "bad bucket", Permissions: PermissionReadObject},
		{Bucket: "bucket", Prefix: "bad/*", Permissions: PermissionReadObject},
		{Bucket: "bucket", Prefix: "/tenant", Permissions: PermissionReadObject},
		{Bucket: "bucket", Prefix: "tenant/", Permissions: PermissionReadObject},
		{Bucket: "bucket", Prefix: "invalid\xff", Permissions: PermissionReadObject},
		{Bucket: "bucket", Permissions: 0},
		{Bucket: "bucket", Permissions: 1 << 30},
	} {
		policy, err := PrefixPolicies(valid, invalid)
		if err == nil || policy.JSON() != "" {
			t.Fatalf("grant %#v: policy = %q, error = %v", invalid, policy.JSON(), err)
		}
		if !strings.Contains(err.Error(), "grant 2:") {
			t.Fatalf("error does not identify invalid grant: %v", err)
		}
	}
}

func TestPrefixPoliciesCombinedCharacterLimit(t *testing.T) {
	t.Parallel()

	first := PrefixGrant{Bucket: "source-bucket", Prefix: "я", Permissions: PermissionReadObject}
	second := PrefixGrant{Bucket: "target-bucket", Prefix: "output", Permissions: PermissionWriteObject}
	base, err := PrefixPolicies(first, second)
	if err != nil {
		t.Fatal(err)
	}
	first.Prefix += strings.Repeat("я", maxPolicyLength-utf8.RuneCountInString(base.JSON()))
	policy, err := PrefixPolicies(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if count := utf8.RuneCountInString(policy.JSON()); count != maxPolicyLength {
		t.Fatalf("policy length = %d, want %d", count, maxPolicyLength)
	}
	first.Prefix += "я"
	for _, grant := range []PrefixGrant{first, second} {
		if _, err := PrefixPolicy(grant.Bucket, grant.Prefix, grant.Permissions); err != nil {
			t.Fatalf("individual grant must fit: %v", err)
		}
	}
	if policy, err := PrefixPolicies(first, second); err == nil || policy.JSON() != "" {
		t.Fatalf("oversized combined policy = %q, error = %v", policy.JSON(), err)
	}
}

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
