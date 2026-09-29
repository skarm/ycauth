package s3iam_test

import (
	"context"
	"log"
	"time"

	"github.com/skarm/ycauth"
	"github.com/skarm/ycauth/s3iam"

	"github.com/aws/aws-sdk-go-v2/aws"
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
	_ = config
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
