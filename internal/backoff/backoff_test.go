package backoff_test

import (
	"math"
	"testing"
	"time"

	"github.com/skarm/ycauth/internal/backoff"
)

func testPolicy() backoff.Policy {
	return backoff.Policy{Initial: 10 * time.Second, Max: 30 * time.Second, Multiplier: 2, Jitter: 0.2}
}

func TestDelayGrowsAndNeverExceedsMaximum(t *testing.T) {
	t.Parallel()

	upper := func() float64 { return 1 }
	if got := testPolicy().Delay(1, 0, upper); got != 12*time.Second {
		t.Fatalf("first delay = %s, want 12s", got)
	}
	if got := testPolicy().Delay(3, 0, upper); got != 30*time.Second {
		t.Fatalf("saturated delay = %s, want 30s", got)
	}

	lower := func() float64 { return 0 }
	if got := testPolicy().Delay(1, 0, lower); got != 8*time.Second {
		t.Fatalf("jittered floor = %s, want 8s", got)
	}
}

func TestDelayStaysWithinBoundsForEveryFailureCount(t *testing.T) {
	t.Parallel()

	for _, jitterSource := range []func() float64{func() float64 { return 0 }, func() float64 { return 0.5 }, func() float64 { return 1 }} {
		for failures := range backoff.MaxFailures + 2 {
			got := testPolicy().Delay(failures, 0, jitterSource)
			if got < 0 || got > testPolicy().Max {
				t.Fatalf("Delay(%d) = %s, out of [0, %s]", failures, got, testPolicy().Max)
			}
		}
	}
}

func TestDelayHonoursLongerRetryAfter(t *testing.T) {
	t.Parallel()

	if got := testPolicy().Delay(1, time.Minute, func() float64 { return 0 }); got != time.Minute {
		t.Fatalf("delay = %s, want the Retry-After hint", got)
	}
	if got := testPolicy().Delay(3, time.Second, func() float64 { return 1 }); got != 30*time.Second {
		t.Fatalf("delay = %s, want the computed delay to win", got)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	if err := testPolicy().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	invalid := []backoff.Policy{
		{Initial: 0, Max: time.Second, Multiplier: 2},
		{Initial: time.Second, Max: time.Millisecond, Multiplier: 2},
		{Initial: time.Second, Max: time.Second, Multiplier: 0.5},
		{Initial: time.Second, Max: time.Second, Multiplier: math.NaN()},
		{Initial: time.Second, Max: time.Second, Multiplier: math.Inf(1)},
		{Initial: time.Second, Max: time.Second, Multiplier: 1, Jitter: -1},
		{Initial: time.Second, Max: time.Second, Multiplier: 1, Jitter: 2},
		{Initial: time.Second, Max: time.Second, Multiplier: 1, Jitter: math.NaN()},
	}
	for _, invalidPolicy := range invalid {
		if err := invalidPolicy.Validate(); err == nil {
			t.Fatalf("Validate(%+v) error = nil", invalidPolicy)
		}
	}
}
