package s3iam

import (
	"context"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Signer signs S3 requests without reusing derived signing keys between requests.
// This supports ephemeral credentials whose secret changes while their access
// key ID remains the same. Changing the session name cannot invalidate the AWS
// SDK's signing-key cache.
//
// Assign Signer{} to s3.Options.HTTPSignerV4 when using credentials from [New].
// The zero value is ready to use and may be shared by concurrent requests.
type Signer struct{}

var _ v4.HTTPSigner = Signer{}

// SignHTTP signs r using the supplied credentials and S3 path-escaping defaults.
// Per-call options are forwarded to the fresh AWS signer.
func (Signer) SignHTTP(ctx context.Context, credentials aws.Credentials, r *http.Request,
	payloadHash, service, region string, signingTime time.Time, optFns ...func(*v4.SignerOptions),
) error {
	signer := v4.NewSigner(func(options *v4.SignerOptions) {
		options.DisableURIPathEscaping = true
	})

	return signer.SignHTTP(ctx, credentials, r, payloadHash, service, region, signingTime, optFns...)
}
