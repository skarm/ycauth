// Package backoff computes bounded exponential retry delays with proportional
// jitter for ycauth modules.
package backoff

import (
	"errors"
	"math"
	"time"
)

// MaxFailures bounds the consecutive-failure counter so that callers can keep
// it in an int without the exponent overflowing.
const MaxFailures = 64

// Policy describes exponential backoff with proportional jitter.
type Policy struct {
	// Initial is the delay after the first failure.
	Initial time.Duration
	// Max caps a computed delay.
	Max time.Duration
	// Multiplier scales a delay for each consecutive failure.
	Multiplier float64
	// Jitter is the proportional random variation in the range [0, 1].
	Jitter float64
}

// Validate reports whether the policy describes a usable delay sequence.
func (p Policy) Validate() error {
	switch {
	case p.Initial <= 0:
		return errors.New("backoff initial duration must be positive")
	case p.Max < p.Initial:
		return errors.New("backoff maximum must not be less than its initial duration")
	case p.Multiplier < 1 || math.IsNaN(p.Multiplier) || math.IsInf(p.Multiplier, 0):
		return errors.New("backoff multiplier must be at least one")
	case p.Jitter < 0 || p.Jitter > 1 || math.IsNaN(p.Jitter):
		return errors.New("backoff jitter must be between zero and one")
	}

	return nil
}

// Delay returns the wait after the given number of consecutive failures. It
// treats values below one as the first failure.
//
// A retryAfter hint longer than the computed delay takes precedence, even when
// it exceeds [Policy.Max]. Delay calls jitterSource only when [Policy.Jitter]
// is nonzero; the function must return a value in [0, 1).
func (p Policy) Delay(failures int, retryAfter time.Duration, jitterSource func() float64) time.Duration {
	exponent := math.Pow(p.Multiplier, float64(max(failures, 1)-1))

	delay := p.Max
	if scaled := float64(p.Initial) * exponent; scaled < float64(p.Max) {
		delay = time.Duration(scaled)
	}

	if retryAfter > delay {
		return retryAfter
	}

	if p.Jitter == 0 {
		return delay
	}

	jittered := float64(delay) * (1 - p.Jitter + 2*p.Jitter*jitterSource())
	if jittered >= float64(p.Max) {
		return p.Max
	}

	return time.Duration(jittered)
}
