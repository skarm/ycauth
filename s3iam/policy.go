package s3iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// policyLanguageVersion identifies the AWS IAM policy language supported by
	// Yandex Object Storage. It is not the policy's creation or modification date.
	policyLanguageVersion = "2012-10-17"
	maxPolicyLength       = 2048
	minBucketLength       = 3
	maxBucketLength       = 63
)

// Permissions is a bit set of permissions accepted by [PrefixPolicy] and
// [PrefixPolicies]. Combine permissions with the bitwise OR operator.
type Permissions uint32

const (
	// PermissionReadObject permits downloading objects.
	PermissionReadObject Permissions = 1 << iota
	// PermissionListObjects permits listing objects under the configured prefix.
	PermissionListObjects
	// PermissionWriteObject permits uploading objects.
	PermissionWriteObject
	// PermissionDeleteObject permits deleting objects.
	PermissionDeleteObject
	// PermissionMultipartUpload permits multipart upload operations for objects in
	// the prefix, including listing parts and aborting an upload. It implies the
	// same s3:PutObject grant as PermissionWriteObject, because a multipart upload
	// writes objects. It does not permit listing every multipart upload in the
	// bucket.
	PermissionMultipartUpload
	// PermissionBucketLocation permits reading the bucket location.
	PermissionBucketLocation
)

const allPermissions = PermissionReadObject | PermissionListObjects | PermissionWriteObject | PermissionDeleteObject | PermissionMultipartUpload | PermissionBucketLocation

// SessionPolicy is a validated, compact inline policy for ephemeral
// credentials. Construct a SessionPolicy with [PrefixPolicy], [PrefixPolicies],
// or [RawPolicy].
// Its zero value tells [New] to omit the policy and use all Object Storage
// permissions already granted to the subject.
type SessionPolicy struct {
	document string
}

// JSON returns the compact JSON policy document accepted by Yandex Cloud.
func (p SessionPolicy) JSON() string { return p.document }

// RawPolicy validates and compacts one custom JSON object. The compact document
// must not exceed 2,048 Unicode characters.
func RawPolicy(data []byte) (SessionPolicy, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return SessionPolicy{}, errors.New("create S3 policy: JSON document must be a non-empty object")
	}

	// Compact validates the syntax while it rewrites, so no separate parse.
	var compact bytes.Buffer
	if err := json.Compact(&compact, trimmed); err != nil {
		return SessionPolicy{}, fmt.Errorf("create S3 policy: compact JSON: %w", err)
	}

	return sessionPolicyFromJSON(compact.Bytes())
}

// PrefixPolicy builds a least-privilege policy for one bucket and object prefix.
// It rejects prefixes that begin or end with a slash or contain policy
// metacharacters, control characters, or invalid UTF-8.
//
// An empty prefix deliberately covers the whole bucket, so pass one only when
// that is intended: an unset variable widens the policy rather than failing.
func PrefixPolicy(bucket, prefix string, permissions Permissions) (SessionPolicy, error) {
	return PrefixPolicies(PrefixGrant{Bucket: bucket, Prefix: prefix, Permissions: permissions})
}

// PrefixGrant grants permissions for one bucket and object prefix.
type PrefixGrant struct {
	// Bucket is a DNS-style Object Storage bucket name.
	Bucket string
	// Prefix is a literal object prefix with the same restrictions as [PrefixPolicy].
	// An empty prefix deliberately covers the whole bucket.
	Prefix string
	// Permissions must contain at least one supported permission.
	Permissions Permissions
}

// PrefixPolicies builds one session policy from one or more grants. Grants may
// refer to different buckets or different prefixes in the same bucket. Their
// permissions are additive; a narrower grant does not restrict a broader one.
// Each grant preserves its own resources and listing conditions.
//
// An empty grant list or any invalid grant returns an error. The complete compact
// policy must fit the 2,048-character limit. Pass the result to [Config.SessionPolicy].
func PrefixPolicies(grants ...PrefixGrant) (SessionPolicy, error) {
	if len(grants) == 0 {
		return SessionPolicy{}, errors.New("create S3 prefix policies: at least one grant is required")
	}

	var statements []policyStatement

	for index, grant := range grants {
		grantStatements, err := prefixStatements(grant.Bucket, grant.Prefix, grant.Permissions)
		if err != nil {
			return SessionPolicy{}, fmt.Errorf("create S3 prefix policies: grant %d: %w", index+1, err)
		}

		statements = append(statements, grantStatements...)
	}

	data, err := json.Marshal(policyDocument{Version: policyLanguageVersion, Statement: statements})
	if err != nil {
		return SessionPolicy{}, fmt.Errorf("create S3 prefix policy: encode JSON: %w", err)
	}

	return sessionPolicyFromJSON(data)
}

// prefixStatements validates a grant and builds its independent statements.
func prefixStatements(bucket, prefix string, permissions Permissions) ([]policyStatement, error) {
	if !validBucket(bucket) {
		return nil, errors.New("create S3 prefix policy: invalid bucket " + strconv.Quote(bucket))
	}

	if permissions == 0 {
		return nil, errors.New("create S3 prefix policy: at least one permission is required")
	}

	if unknown := permissions &^ allPermissions; unknown != 0 {
		return nil, errors.New("create S3 prefix policy: unsupported permission bits 0x" + strconv.FormatUint(uint64(unknown), 16))
	}

	if strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") {
		return nil, errors.New("create S3 prefix policy: prefix must not begin or end with a slash")
	}

	if !validPrefix(prefix) {
		return nil, errors.New("create S3 prefix policy: invalid prefix " + strconv.Quote(prefix))
	}

	bucketARN := "arn:aws:s3:::" + bucket

	objectARN := bucketARN + "/*"
	if prefix != "" {
		objectARN = bucketARN + "/" + prefix + "/*"
	}

	statements := make([]policyStatement, 0, 3)

	if permissions&PermissionListObjects != 0 {
		statement := policyStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    []string{"s3:ListBucket"},
			Resource:  []string{bucketARN},
		}

		if prefix != "" {
			statement.Condition = map[string]map[string][]string{
				"StringLike": {"s3:prefix": {prefix, prefix + "/*"}},
			}
		}

		statements = append(statements, statement)
	}

	if permissions&PermissionBucketLocation != 0 {
		statements = append(statements, policyStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    []string{"s3:GetBucketLocation"},
			Resource:  []string{bucketARN},
		})
	}

	objectActions := make([]string, 0, 5)
	if permissions&PermissionReadObject != 0 {
		objectActions = append(objectActions, "s3:GetObject")
	}

	if permissions&(PermissionWriteObject|PermissionMultipartUpload) != 0 {
		objectActions = append(objectActions, "s3:PutObject")
	}

	if permissions&PermissionDeleteObject != 0 {
		objectActions = append(objectActions, "s3:DeleteObject")
	}

	if permissions&PermissionMultipartUpload != 0 {
		objectActions = append(objectActions, "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts")
	}

	if len(objectActions) != 0 {
		statements = append(statements, policyStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    objectActions,
			Resource:  []string{objectARN},
		})
	}

	return statements, nil
}

// validBucket applies the Object Storage DNS-style naming rules and rejects IPv4
// address literals.
func validBucket(bucket string) bool {
	if len(bucket) < minBucketLength || len(bucket) > maxBucketLength {
		return false
	}

	if address, err := netip.ParseAddr(bucket); err == nil && address.Is4() {
		return false
	}

	if !bucketAlphaNumeric(bucket[0]) || !bucketAlphaNumeric(bucket[len(bucket)-1]) {
		return false
	}

	for index := range len(bucket) {
		character := bucket[index]
		if !bucketAlphaNumeric(character) && character != '-' && character != '.' {
			return false
		}

		if character == '.' && (!bucketAlphaNumeric(bucket[index-1]) || !bucketAlphaNumeric(bucket[index+1])) {
			return false
		}
	}

	return true
}

// bucketAlphaNumeric reports whether character is a lowercase ASCII letter or
// decimal digit accepted at a bucket-label boundary.
func bucketAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

// validPrefix accepts literal UTF-8 prefixes without policy metacharacters or
// control characters.
func validPrefix(prefix string) bool {
	if !utf8.ValidString(prefix) {
		return false
	}

	for _, character := range prefix {
		if character == '*' || character == '?' || character == '$' ||
			character == utf8.RuneError || unicode.IsControl(character) {
			return false
		}
	}

	return true
}

type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect    string                         `json:"Effect"`
	Principal string                         `json:"Principal"`
	Action    []string                       `json:"Action"`
	Resource  []string                       `json:"Resource"`
	Condition map[string]map[string][]string `json:"Condition,omitempty"`
}

// sessionPolicyFromJSON enforces the service's character limit on compact
// policy JSON.
func sessionPolicyFromJSON(data []byte) (SessionPolicy, error) {
	if utf8.RuneCount(data) > maxPolicyLength {
		return SessionPolicy{}, errors.New("create S3 policy: compact JSON exceeds " + strconv.Itoa(maxPolicyLength) + " characters")
	}

	return SessionPolicy{document: string(data)}, nil
}
