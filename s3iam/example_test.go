package s3iam_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/s3iam"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func ExampleNew() {
	tokens := ycauth.TokenProviderFunc(func(context.Context) (ycauth.Token, error) {
		return ycauth.Token{Value: "iam-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	policy, err := s3iam.PrefixPolicy("bucket", "tenant/42", s3iam.PermissionReadObject|s3iam.PermissionListObjects)
	if err != nil {
		log.Fatal(err)
	}
	credentials, err := s3iam.New(tokens, s3iam.Config{
		SessionName:   "example",
		Duration:      time.Hour,
		SessionPolicy: policy,
	})
	if err != nil {
		log.Fatal(err)
	}

	config := aws.Config{Credentials: credentials}
	client := s3.NewFromConfig(config, func(options *s3.Options) {
		options.HTTPSignerV4 = s3iam.Signer{}
	})
	_ = client
}

func ExamplePrefixPolicies() {
	policy, err := s3iam.PrefixPolicies(
		s3iam.PrefixGrant{
			Bucket:      "source-bucket",
			Prefix:      "incoming",
			Permissions: s3iam.PermissionReadObject | s3iam.PermissionListObjects,
		},
		s3iam.PrefixGrant{
			Bucket:      "target-bucket",
			Prefix:      "processed",
			Permissions: s3iam.PermissionWriteObject,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Pass this configuration to s3iam.New to share credentials across buckets.
	config := s3iam.Config{SessionName: "copy-objects", SessionPolicy: policy}
	_ = config
}

func ExamplePrefixPolicy_versions() {
	policy, err := s3iam.PrefixPolicy("bucket", "tenant/42",
		s3iam.PermissionReadObjectVersion|s3iam.PermissionListObjectVersions,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(policy.JSON())
	// Output: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:ListBucketVersions"],"Resource":["arn:aws:s3:::bucket"],"Condition":{"StringLike":{"s3:prefix":["tenant/42/*"]}}},{"Effect":"Allow","Principal":"*","Action":["s3:GetObjectVersion"],"Resource":["arn:aws:s3:::bucket/tenant/42/*"]}]}
}

func ExamplePrefixPolicy_bucketConfiguration() {
	policy, err := s3iam.PrefixPolicy("bucket", "",
		s3iam.PermissionWriteBucketLifecycle|
			s3iam.PermissionReadBucketVersioning|
			s3iam.PermissionListMultipartUploads,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(policy.JSON())
	// Output: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:ListBucketMultipartUploads","s3:GetBucketVersioning","s3:PutLifecycleConfiguration"],"Resource":["arn:aws:s3:::bucket"]}]}
}

func ExampleAllPermissions() {
	// Each action can be excluded from AllPermissions with &^.
	policy, err := s3iam.PrefixPolicy("bucket", "",
		s3iam.AllPermissions&^(s3iam.PermissionDeleteObject|s3iam.PermissionDeleteObjectVersion),
	)
	if err != nil {
		log.Fatal(err)
	}

	config := s3iam.Config{SessionName: "bucket-maintenance", SessionPolicy: policy}
	_ = config
}
