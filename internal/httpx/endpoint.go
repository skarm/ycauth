package httpx

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ValidateSecureEndpoint returns endpoint unchanged when it is an absolute
// HTTPS URL. It also permits plain HTTP for loopback endpoints used by local
// emulators and tests.
func ValidateSecureEndpoint(endpoint string) (string, error) {
	return validateEndpoint(endpoint, false)
}

// ValidateIMDSEndpoint applies [ValidateSecureEndpoint] rules and also permits
// plain HTTP for link-local IMDS addresses.
func ValidateIMDSEndpoint(endpoint string) (string, error) {
	return validateEndpoint(endpoint, true)
}

// validateEndpoint checks the shared credential-endpoint rules. linkLocal adds
// the IMDS exception for plain HTTP.
func validateEndpoint(endpoint string, linkLocal bool) (string, error) {
	parsed, err := parseEndpoint(endpoint)
	if err != nil {
		return "", errors.New("endpoint must be an absolute HTTP(S) URL: " + strconv.Quote(endpoint))
	}

	if parsed.Scheme == "https" || parsed.Scheme == "http" && localHost(parsed.Hostname(), linkLocal) {
		return endpoint, nil
	}

	return "", errors.New("credential endpoint must use HTTPS unless it targets a local address: " + strconv.Quote(endpoint))
}

// parseEndpoint accepts absolute HTTP(S) request URLs without user information.
func parseEndpoint(endpoint string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("invalid endpoint")
	}

	return parsed, nil
}

// localHost reports whether host is unreachable from outside the machine, so
// plain HTTP to it cannot expose a credential to the network. Link-local
// addresses count only where the caller expects IMDS.
func localHost(host string, linkLocal bool) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	address := net.ParseIP(host)
	if address == nil {
		return false
	}

	return address.IsLoopback() || linkLocal && address.IsLinkLocalUnicast()
}
