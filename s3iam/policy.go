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
// Use [AllPermissions] to grant every supported action.
//
// It covers all actions in the Yandex Object Storage policy action reference:
// https://yandex.cloud/en/docs/storage/s3/api-ref/policy/actions.
// Object permissions apply to the configured prefix. With a non-empty prefix,
// object and version listings require that prefix followed by a slash (or a deeper prefix).
// Bucket configuration permissions and PermissionListMultipartUploads apply to
// the entire bucket even when a non-empty object prefix is supplied.
type Permissions uint32

const (
	// PermissionReadObject permits downloading objects (s3:GetObject).
	PermissionReadObject Permissions = 1 << iota
	// PermissionListObjects permits listing objects under the prefix (s3:ListBucket).
	PermissionListObjects
	// PermissionWriteObject permits uploading objects (s3:PutObject).
	PermissionWriteObject
	// PermissionDeleteObject permits deleting objects without a version ID (s3:DeleteObject).
	PermissionDeleteObject
	// PermissionMultipartUpload permits uploading objects, aborting uploads, and
	// listing uploaded parts (s3:PutObject, s3:AbortMultipartUpload, and
	// s3:ListMultipartUploadParts). It does not permit listing uploads in the bucket.
	PermissionMultipartUpload
	// PermissionBucketLocation permits reading the bucket location (s3:GetBucketLocation).
	PermissionBucketLocation
	// PermissionReadObjectVersion permits downloading specific object versions (s3:GetObjectVersion).
	PermissionReadObjectVersion
	// PermissionDeleteObjectVersion permits deleting specific object versions (s3:DeleteObjectVersion).
	PermissionDeleteObjectVersion
	// PermissionListObjectVersions permits listing object versions under the prefix (s3:ListBucketVersions).
	PermissionListObjectVersions
	// PermissionReadObjectACL permits reading object ACLs (s3:GetObjectAcl).
	PermissionReadObjectACL
	// PermissionWriteObjectACL permits setting object ACLs (s3:PutObjectAcl).
	PermissionWriteObjectACL
	// PermissionReadObjectVersionACL permits reading object-version ACLs (s3:GetObjectVersionAcl).
	PermissionReadObjectVersionACL
	// PermissionWriteObjectVersionACL permits setting object-version ACLs (s3:PutObjectVersionAcl).
	PermissionWriteObjectVersionACL
	// PermissionAbortMultipartUpload permits aborting multipart uploads (s3:AbortMultipartUpload).
	PermissionAbortMultipartUpload
	// PermissionListMultipartUploadParts permits listing uploaded parts (s3:ListMultipartUploadParts).
	PermissionListMultipartUploadParts
	// PermissionListMultipartUploads permits listing uploads in the entire bucket (s3:ListBucketMultipartUploads).
	PermissionListMultipartUploads
	// PermissionReadBucketACL permits reading the bucket ACL (s3:GetBucketAcl).
	PermissionReadBucketACL
	// PermissionWriteBucketACL permits setting the bucket ACL (s3:PutBucketAcl).
	PermissionWriteBucketACL
	// PermissionReadBucketCORS permits reading the bucket CORS configuration (s3:GetBucketCORS).
	PermissionReadBucketCORS
	// PermissionWriteBucketCORS permits setting the bucket CORS configuration (s3:PutBucketCORS).
	PermissionWriteBucketCORS
	// PermissionReadBucketVersioning permits reading the bucket versioning state (s3:GetBucketVersioning).
	PermissionReadBucketVersioning
	// PermissionWriteBucketVersioning permits setting the bucket versioning state (s3:PutBucketVersioning).
	PermissionWriteBucketVersioning
	// PermissionReadBucketWebsite permits reading the bucket website configuration (s3:GetBucketWebsite).
	PermissionReadBucketWebsite
	// PermissionWriteBucketWebsite permits setting the bucket website configuration (s3:PutBucketWebsite).
	PermissionWriteBucketWebsite
	// PermissionDeleteBucketWebsite permits deleting the bucket website configuration (s3:DeleteBucketWebsite).
	PermissionDeleteBucketWebsite
	// PermissionReadBucketEncryption permits reading the bucket encryption configuration (s3:GetEncryptionConfiguration).
	PermissionReadBucketEncryption
	// PermissionWriteBucketEncryption permits setting the bucket encryption configuration (s3:PutEncryptionConfiguration).
	PermissionWriteBucketEncryption
	// PermissionReadBucketLifecycle permits reading the bucket lifecycle rules (s3:GetLifecycleConfiguration).
	PermissionReadBucketLifecycle
	// PermissionWriteBucketLifecycle permits setting the bucket lifecycle rules (s3:PutLifecycleConfiguration).
	PermissionWriteBucketLifecycle
)

// AllPermissions combines the individual flags for every supported action.
// The overlapping PermissionMultipartUpload bundle is omitted so that individual
// actions can be removed with &^. Bucket permissions still cover the entire
// bucket when a non-empty object prefix is supplied.
// Its value may grow when support for additional actions is added.
const AllPermissions = PermissionReadObject | PermissionListObjects | PermissionWriteObject |
	PermissionDeleteObject | PermissionBucketLocation |
	PermissionReadObjectVersion | PermissionDeleteObjectVersion | PermissionListObjectVersions |
	PermissionReadObjectACL | PermissionWriteObjectACL | PermissionReadObjectVersionACL |
	PermissionWriteObjectVersionACL | PermissionAbortMultipartUpload | PermissionListMultipartUploadParts |
	PermissionListMultipartUploads | PermissionReadBucketACL | PermissionWriteBucketACL |
	PermissionReadBucketCORS | PermissionWriteBucketCORS | PermissionReadBucketVersioning |
	PermissionWriteBucketVersioning | PermissionReadBucketWebsite | PermissionWriteBucketWebsite |
	PermissionDeleteBucketWebsite | PermissionReadBucketEncryption | PermissionWriteBucketEncryption |
	PermissionReadBucketLifecycle | PermissionWriteBucketLifecycle

// supportedPermissions also accepts the original multipart-upload bundle bit.
const supportedPermissions = AllPermissions | PermissionMultipartUpload

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

// RawPolicy validates and compacts one custom UTF-8 JSON object. The compact
// document must not exceed 2,048 Unicode characters.
func RawPolicy(data []byte) (SessionPolicy, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return SessionPolicy{}, errors.New("create S3 policy: JSON document must be a non-empty object")
	}

	if !utf8.Valid(trimmed) {
		return SessionPolicy{}, errors.New("create S3 policy: JSON document must be valid UTF-8")
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
// Listing requests must use the prefix followed by a slash (or a deeper prefix)
// so that similarly named sibling prefixes cannot be listed.
// This applies to object and object-version listings. Bucket configuration
// permissions and PermissionListMultipartUploads always cover the entire bucket.
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
	// Bucket configuration permissions and PermissionListMultipartUploads are
	// bucket-wide regardless of this value.
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

	if unknown := permissions &^ supportedPermissions; unknown != 0 {
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

	listActions := permissionActions(permissions, []permissionAction{
		{PermissionListObjects, "s3:ListBucket"},
		{PermissionListObjectVersions, "s3:ListBucketVersions"},
	})
	if len(listActions) != 0 {
		statement := policyStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    listActions,
			Resource:  []string{bucketARN},
		}

		if prefix != "" {
			statement.Condition = map[string]map[string][]string{
				"StringLike": {"s3:prefix": {prefix + "/*"}},
			}
		}

		statements = append(statements, statement)
	}

	bucketActions := permissionActions(permissions, []permissionAction{
		{PermissionBucketLocation, "s3:GetBucketLocation"},
		{PermissionListMultipartUploads, "s3:ListBucketMultipartUploads"},
		{PermissionReadBucketACL, "s3:GetBucketAcl"},
		{PermissionWriteBucketACL, "s3:PutBucketAcl"},
		{PermissionReadBucketCORS, "s3:GetBucketCORS"},
		{PermissionWriteBucketCORS, "s3:PutBucketCORS"},
		{PermissionReadBucketVersioning, "s3:GetBucketVersioning"},
		{PermissionWriteBucketVersioning, "s3:PutBucketVersioning"},
		{PermissionReadBucketWebsite, "s3:GetBucketWebsite"},
		{PermissionWriteBucketWebsite, "s3:PutBucketWebsite"},
		{PermissionDeleteBucketWebsite, "s3:DeleteBucketWebsite"},
		{PermissionReadBucketEncryption, "s3:GetEncryptionConfiguration"},
		{PermissionWriteBucketEncryption, "s3:PutEncryptionConfiguration"},
		{PermissionReadBucketLifecycle, "s3:GetLifecycleConfiguration"},
		{PermissionWriteBucketLifecycle, "s3:PutLifecycleConfiguration"},
	})
	if len(bucketActions) != 0 {
		statements = append(statements, policyStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    bucketActions,
			Resource:  []string{bucketARN},
		})
	}

	objectActions := permissionActions(permissions, []permissionAction{
		{PermissionReadObject, "s3:GetObject"},
		{PermissionWriteObject | PermissionMultipartUpload, "s3:PutObject"},
		{PermissionDeleteObject, "s3:DeleteObject"},
		{PermissionAbortMultipartUpload | PermissionMultipartUpload, "s3:AbortMultipartUpload"},
		{PermissionListMultipartUploadParts | PermissionMultipartUpload, "s3:ListMultipartUploadParts"},
		{PermissionReadObjectVersion, "s3:GetObjectVersion"},
		{PermissionDeleteObjectVersion, "s3:DeleteObjectVersion"},
		{PermissionReadObjectACL, "s3:GetObjectAcl"},
		{PermissionWriteObjectACL, "s3:PutObjectAcl"},
		{PermissionReadObjectVersionACL, "s3:GetObjectVersionAcl"},
		{PermissionWriteObjectVersionACL, "s3:PutObjectVersionAcl"},
	})
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

type permissionAction struct {
	permissions Permissions
	action      string
}

// permissionActions emits each action once when any of its permission bits is set.
func permissionActions(permissions Permissions, rules []permissionAction) []string {
	actions := make([]string, 0, len(rules))
	for _, rule := range rules {
		if permissions&rule.permissions != 0 {
			actions = append(actions, rule.action)
		}
	}

	return actions
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
