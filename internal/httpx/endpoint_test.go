package httpx //nolint:testpackage

import "testing"

func TestValidateSecureEndpoint(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"",
		"relative",
		"ftp://example.test",
		"://bad",
		"http://iam.example.test/token",
		"https://user:password@iam.example.test/token",
	} {
		if _, err := ValidateSecureEndpoint(endpoint); err == nil {
			t.Errorf("ValidateSecureEndpoint(%q) error = nil", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://iam.example.test/token",
		"http://localhost:8080/token",
		"http://127.0.0.1:8080/token",
		"http://[::1]:8080/token",
	} {
		if got, err := ValidateSecureEndpoint(endpoint); err != nil || got != endpoint {
			t.Errorf("ValidateSecureEndpoint(%q) = (%q, %v)", endpoint, got, err)
		}
	}

	// Only IMDS may be reached over plain HTTP off-loopback.
	const imds = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
	if _, err := ValidateSecureEndpoint(imds); err == nil {
		t.Error("ValidateSecureEndpoint(link-local) error = nil")
	}
	if got, err := ValidateIMDSEndpoint(imds); err != nil || got != imds {
		t.Errorf("ValidateIMDSEndpoint(%q) = (%q, %v)", imds, got, err)
	}
	for _, endpoint := range []string{"http://iam.example.test/token", "http://169.254.169.254@evil.test/token"} {
		if _, err := ValidateIMDSEndpoint(endpoint); err == nil {
			t.Errorf("ValidateIMDSEndpoint(%q) error = nil", endpoint)
		}
	}
}
