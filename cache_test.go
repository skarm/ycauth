package ycauth //nolint:testpackage

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func TestCacheTokenRejectsNilContext(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	cache, err := NewCache(TokenSourceFunc(func(context.Context) (Token, error) {
		calls.Add(1)
		return Token{Value: "token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}), CacheConfig{})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}

	for _, state := range []string{"empty", "warm"} {
		if state == "warm" {
			if _, err := cache.Token(context.Background()); err != nil {
				t.Fatalf("warm cache: %v", err)
			}
		}

		token, err := cache.Token(nil) //nolint:staticcheck // Exercise rejection of a nil context.
		if err == nil || err.Error() != "get IAM token: context must not be nil" || token != (Token{}) {
			t.Fatalf("%s cache Token(nil) = (%v, %v), want an empty token and nil-context error", state, token, err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want only the warm-up call", got)
	}
}

func TestCacheCachesAndCoalesces(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	var calls atomic.Int64
	release := make(chan struct{})
	source := TokenSourceFunc(func(context.Context) (Token, error) {
		calls.Add(1)
		<-release
		return Token{Value: "token", ExpiresAt: now.Add(time.Hour)}, nil
	})
	cache, err := newCache(source, CacheConfig{}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	const callers = 32
	results := make(chan Token, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			token, err := cache.Token(context.Background())
			results <- token
			errs <- err
		}()
	}

	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if token := <-results; token.Value != "token" {
			t.Fatalf("Token() = %v", token)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want 1", got)
	}

	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("cached Token() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls after cache hit = %d, want 1", got)
	}
}

func TestCacheDoesNotServeTokenPastAbsoluteExpiration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	var calls atomic.Int64
	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) == 1 {
			return Token{Value: "old", ExpiresAt: now.Add(time.Hour)}, nil
		}

		return Token{Value: "new", ExpiresAt: now.Add(2 * time.Hour)}, nil
	}), CacheConfig{}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("warm cache: %v", err)
	}

	// Model a forward wall-clock correction while the monotonic refresh
	// schedule still says that an hour remains. Absolute expiration must win.
	corrected := *cache.current.Load()
	corrected.token.ExpiresAt = now.Add(-time.Second)
	cache.current.Store(&corrected)

	token, err := cache.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if token.Value != "new" || calls.Load() != 2 {
		t.Fatalf("Token() = %q after %d source calls, want new after 2", token.Value, calls.Load())
	}
}

func TestCacheLeaderCancellationDoesNotCancelRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	source := TokenSourceFunc(func(ctx context.Context) (Token, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return Token{Value: "shared", ExpiresAt: now.Add(time.Hour)}, nil
		case <-ctx.Done():
			return Token{}, ctx.Err()
		}
	})
	cache, err := newCache(source, CacheConfig{}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := cache.Token(leaderCtx)
		leaderDone <- err
	}()
	<-started

	followerResult := make(chan tokenResult, 1)
	go func() {
		token, err := cache.Token(context.Background())
		followerResult <- tokenResult{token: token, err: err}
	}()
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}

	close(release)
	follower := <-followerResult
	if follower.err != nil || follower.token.Value != "shared" {
		t.Fatalf("follower = (%v, %v), want shared token", follower.token, follower.err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want 1", got)
	}
}

func TestCacheBackoffAndStaleFallback(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	refreshErr := errors.New("IAM unavailable")
	var mu sync.Mutex
	calls := 0
	source := TokenSourceFunc(func(context.Context) (Token, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		switch calls {
		case 1:
			return Token{Value: "old", ExpiresAt: now.Add(time.Hour)}, nil
		case 2:
			return Token{}, refreshErr
		default:
			return Token{Value: "new", ExpiresAt: clock.Now().Add(time.Hour)}, nil
		}
	})

	events := make(chan RefreshEvent, 3)
	cache, err := newCache(source, CacheConfig{
		RefreshBefore:      2 * time.Hour,
		MinRefreshInterval: time.Second,
		Backoff: BackoffConfig{
			Initial:    10 * time.Second,
			Max:        10 * time.Second,
			Multiplier: 1,
		},
		Observer: ObserverFunc(func(event RefreshEvent) { events <- event }),
	}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	first, err := cache.Token(context.Background())
	if err != nil || first.Value != "old" {
		t.Fatalf("first Token() = (%v, %v)", first, err)
	}
	<-events
	clock.Advance(31 * time.Minute)

	stale, err := cache.Token(context.Background())
	if err != nil || stale.Value != "old" {
		t.Fatalf("stale Token() = (%v, %v)", stale, err)
	}
	if event := <-events; !event.UsedStale || !errors.Is(event.Err, refreshErr) {
		t.Fatalf("refresh event = %#v, want stale error", event)
	}

	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("backoff Token() error = %v", err)
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("source calls during backoff = %d, want 2", gotCalls)
	}

	// Once backoff lapses the still-valid token is served immediately while
	// the refresh runs in the background.
	clock.Advance(11 * time.Second)
	served, err := cache.Token(context.Background())
	if err != nil || served.Value != "old" {
		t.Fatalf("Token() during background refresh = (%v, %v), want old token", served, err)
	}

	if event := <-events; event.Err != nil {
		t.Fatalf("background refresh event = %#v", event)
	}

	refreshed, err := cache.Token(context.Background())
	if err != nil || refreshed.Value != "new" {
		t.Fatalf("refreshed Token() = (%v, %v)", refreshed, err)
	}
}

func TestCacheBacksOffWithoutCachedToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	refreshErr := errors.New("IAM unavailable")
	var calls atomic.Int64
	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) == 1 {
			return Token{}, refreshErr
		}
		return Token{Value: "recovered", ExpiresAt: clock.Now().Add(time.Hour)}, nil
	}), CacheConfig{Backoff: BackoffConfig{
		Initial:    10 * time.Second,
		Max:        10 * time.Second,
		Multiplier: 1,
	}}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	if _, err := cache.Token(context.Background()); !errors.Is(err, refreshErr) {
		t.Fatalf("first Token() error = %v, want source error", err)
	}
	if _, err := cache.Token(context.Background()); !errors.Is(err, refreshErr) {
		t.Fatalf("backoff Token() error = %v, want source error", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls during backoff = %d, want 1", got)
	}

	clock.Advance(10 * time.Second)
	token, err := cache.Token(context.Background())
	if err != nil || token.Value != "recovered" {
		t.Fatalf("recovered Token() = (%v, %v)", token, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls after backoff = %d, want 2", got)
	}
}

func TestCacheHonorsRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	apiErr := &APIError{Op: "exchange token", StatusCode: 429, RetryAfter: time.Minute}
	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		return Token{}, errors.Join(errors.New("request failed"), apiErr)
	}), CacheConfig{Backoff: BackoffConfig{
		Initial:    time.Second,
		Max:        time.Second,
		Multiplier: 1,
	}}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	if _, err := cache.Token(context.Background()); !errors.Is(err, apiErr) {
		t.Fatalf("Token() error = %v, want API error", err)
	}
	cache.mu.Lock()
	nextAttemptAt := cache.nextAttemptAt
	cache.mu.Unlock()
	if want := now.Add(time.Minute); !nextAttemptAt.Equal(want) {
		t.Fatalf("next attempt = %s, want %s", nextAttemptAt, want)
	}
}

func TestCacheCapsRefreshWindowForShortLivedToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		return Token{Value: "token", ExpiresAt: now.Add(time.Minute)}, nil
	}), CacheConfig{}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}
	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	snapshot := cache.current.Load()
	if want := 30 * time.Second; snapshot.base.Add(snapshot.refreshIn) != now.Add(want) {
		t.Fatalf("refresh in = %s, want %s", snapshot.refreshIn, want)
	}
}

func TestCacheRefreshTimeout(t *testing.T) {
	t.Parallel()

	cache, err := NewCache(TokenSourceFunc(func(ctx context.Context) (Token, error) {
		<-ctx.Done()
		return Token{}, ctx.Err()
	}), CacheConfig{RefreshTimeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	if _, err := cache.Token(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Token() error = %v, want deadline exceeded", err)
	}
}

func TestCacheContainsObserverPanic(t *testing.T) {
	t.Parallel()

	observed := make(chan struct{})
	cache, err := NewCache(TokenSourceFunc(func(context.Context) (Token, error) {
		return Token{Value: "token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}), CacheConfig{Observer: ObserverFunc(func(RefreshEvent) {
		close(observed)
		panic("observer failed")
	})})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	<-observed
	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("cached Token() error = %v", err)
	}
}

// BenchmarkCacheHit measures the production hot path, clock included: NewCache
// is used deliberately so the benchmark cannot hide the cost of reading time.
func BenchmarkCacheHit(b *testing.B) {
	cache, err := NewCache(TokenSourceFunc(func(context.Context) (Token, error) {
		return Token{Value: "token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}), CacheConfig{})
	if err != nil {
		b.Fatalf("NewCache() error = %v", err)
	}
	if _, err := cache.Token(context.Background()); err != nil {
		b.Fatalf("warm cache: %v", err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := cache.Token(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func TestNewCacheValidation(t *testing.T) {
	t.Parallel()

	source := TokenSourceFunc(func(context.Context) (Token, error) { return Token{}, nil })
	invalidConfigs := []CacheConfig{
		{RefreshBefore: -1},
		{RefreshTimeout: -1},
		{MinRefreshInterval: -1},
		{Backoff: BackoffConfig{Initial: time.Second, Max: time.Millisecond, Multiplier: 2}},
		{Backoff: BackoffConfig{Initial: time.Second, Max: time.Second, Multiplier: 0.5}},
		{Backoff: BackoffConfig{Initial: time.Second, Max: time.Second, Multiplier: 1, Jitter: 2}},
		{Backoff: BackoffConfig{Initial: time.Second, Max: time.Second, Multiplier: math.NaN()}},
		{Backoff: BackoffConfig{Initial: time.Second, Max: time.Second, Multiplier: 1, Jitter: math.Inf(1)}},
	}
	for _, config := range invalidConfigs {
		if _, err := NewCache(source, config); err == nil {
			t.Fatalf("NewCache(%+v) error = nil", config)
		}
	}

	if _, err := NewCache(nil, CacheConfig{}); err == nil {
		t.Fatal("NewCache(nil source) error = nil")
	}
}

func TestNewCacheDefaultsUnsetBackoffFields(t *testing.T) {
	t.Parallel()

	source := TokenSourceFunc(func(context.Context) (Token, error) { return Token{}, nil })
	cache, err := NewCache(source, CacheConfig{Backoff: BackoffConfig{Jitter: 0.5}})
	if err != nil {
		t.Fatalf("NewCache(partial backoff) error = %v", err)
	}
	if cache.backoff.Jitter != 0.5 || cache.backoff.Initial != defaultBackoffInitial ||
		cache.backoff.Max != defaultBackoffMax || cache.backoff.Multiplier != defaultBackoffMultiplier {
		t.Fatalf("backoff policy = %+v", cache.backoff)
	}
}

func TestCacheContainsSourcePanic(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	cache, err := NewCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) == 1 {
			panic("source exploded")
		}

		return Token{Value: "recovered", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}), CacheConfig{Backoff: BackoffConfig{Initial: time.Nanosecond, Max: time.Nanosecond, Multiplier: 1}})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := cache.Token(ctx); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("Token() error = %v, want a contained panic", err)
	}

	// The cache must not be wedged: a later call still reaches the source.
	token, err := cache.Token(ctx)
	if err != nil || token.Value != "recovered" {
		t.Fatalf("Token() after panic = (%v, %v)", token, err)
	}
}

// brokenError stands in for a caller error type with a buggy method: errors.As
// walks it while the refresh publishes its result.
type brokenError struct{}

func (brokenError) Error() string { return "IAM unavailable" }

func (brokenError) Unwrap() error { panic("Unwrap exploded") }

func TestCacheContainsPanickingSourceError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	var calls atomic.Int64
	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) == 1 {
			return Token{}, brokenError{}
		}

		return Token{Value: "recovered", ExpiresAt: now.Add(time.Hour)}, nil
	}), CacheConfig{Backoff: BackoffConfig{Initial: time.Second, Max: time.Second, Multiplier: 1}}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := cache.Token(ctx); err == nil {
		t.Fatal("Token() error = nil, want the contained panic")
	}
	cache.mu.Lock()
	failures := cache.failures
	cache.mu.Unlock()
	if failures != 1 {
		t.Fatalf("failures = %d, want 1", failures)
	}

	// The panic must not have kept the refresh slot or stranded later callers.
	clock.Advance(time.Second)
	token, err := cache.Token(ctx)
	if err != nil || token.Value != "recovered" {
		t.Fatalf("Token() after a panicking error = (%v, %v)", token, err)
	}
}

func TestCacheRefreshTimeoutOutlastsASourceIgnoringContext(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	var calls atomic.Int64
	cache, err := NewCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) == 1 {
			<-release // never looks at ctx

			return Token{}, errors.New("too late")
		}

		return Token{Value: "recovered", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}), CacheConfig{
		RefreshTimeout: 20 * time.Millisecond,
		Backoff:        BackoffConfig{Initial: time.Nanosecond, Max: time.Nanosecond, Multiplier: 1},
	})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}

	if _, err := cache.Token(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Token() error = %v, want the refresh timeout", err)
	}

	// The stuck refresh must no longer own the cache.
	token, err := cache.Token(context.Background())
	if err != nil || token.Value != "recovered" {
		t.Fatalf("Token() after a stuck refresh = (%v, %v)", token, err)
	}
}

func TestCacheServesTokenWithoutBlockingDuringRefreshWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	release := make(chan struct{})
	var calls atomic.Int64
	events := make(chan RefreshEvent, 2)

	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) > 1 {
			<-release // a slow IAM must not be observable by callers
		}

		return Token{Value: "token", ExpiresAt: clock.Now().Add(time.Hour)}, nil
	}), CacheConfig{
		RefreshBefore:      30 * time.Minute,
		MinRefreshInterval: time.Second,
		Observer:           ObserverFunc(func(event RefreshEvent) { events <- event }),
	}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("warm Token() error = %v", err)
	}
	<-events

	clock.Advance(31 * time.Minute)

	done := make(chan struct{})
	go func() {
		defer close(done)

		for range 100 {
			if _, err := cache.Token(context.Background()); err != nil {
				t.Errorf("Token() during refresh window error = %v", err)

				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Token() blocked on the background refresh")
	}

	// While the refresh is pending, readers must not be sent back to the lock.
	if snapshot := cache.current.Load(); snapshot.refreshIn != snapshot.expiresIn {
		t.Fatalf("refresh in = %s, want the token lifetime %s while a refresh is pending",
			snapshot.refreshIn, snapshot.expiresIn)
	}

	close(release)
	<-events

	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls = %d, want 2 coalesced refreshes", got)
	}
}

// TestCacheHitTakesNoLockWhileBackedOff pins the hot-path guarantee: a valid
// token is served from the snapshot even when the mutex is held, which is what
// keeps a failing refresh from serialising every caller for the whole window.
func TestCacheHitTakesNoLockWhileBackedOff(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	events := make(chan RefreshEvent, 2)
	var calls atomic.Int64

	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) == 1 {
			return Token{Value: "token", ExpiresAt: now.Add(time.Hour)}, nil
		}

		return Token{}, errors.New("IAM unavailable")
	}), CacheConfig{
		RefreshBefore:      30 * time.Minute,
		MinRefreshInterval: time.Second,
		Observer:           ObserverFunc(func(event RefreshEvent) { events <- event }),
	}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	if _, err := cache.Token(context.Background()); err != nil {
		t.Fatalf("warm Token() error = %v", err)
	}
	<-events

	clock.Advance(31 * time.Minute)

	if token, err := cache.Token(context.Background()); err != nil || token.Value != "token" {
		t.Fatalf("Token() in refresh window = (%v, %v)", token, err)
	}
	if event := <-events; event.Err == nil || !event.UsedStale {
		t.Fatalf("refresh event = %#v, want a failure serving the stale token", event)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	served := make(chan Token, 1)
	go func() {
		if token, err := cache.Token(context.Background()); err == nil {
			served <- token
		}
	}()

	select {
	case token := <-served:
		if token.Value != "token" {
			t.Fatalf("Token() = %v, want the cached token", token)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Token() blocked on the cache mutex")
	}
}

func TestCacheInvalidateForcesRefresh(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	cache, err := NewCache(TokenSourceFunc(func(context.Context) (Token, error) {
		return Token{
			Value:     "token-" + strconv.FormatInt(calls.Add(1), 10),
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}), CacheConfig{})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}

	first, err := cache.Token(context.Background())
	if err != nil || first.Value != "token-1" {
		t.Fatalf("first Token() = (%v, %v)", first, err)
	}

	if cached, err := cache.Token(context.Background()); err != nil || cached.Value != "token-1" {
		t.Fatalf("cached Token() = (%v, %v)", cached, err)
	}

	cache.Invalidate()

	second, err := cache.Token(context.Background())
	if err != nil || second.Value != "token-2" {
		t.Fatalf("Token() after Invalidate() = (%v, %v)", second, err)
	}
}

func TestCacheInvalidateClearsBackoff(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	refreshErr := errors.New("IAM unavailable")
	var calls atomic.Int64

	cache, err := newCache(TokenSourceFunc(func(context.Context) (Token, error) {
		if calls.Add(1) == 1 {
			return Token{}, refreshErr
		}

		return Token{Value: "recovered", ExpiresAt: clock.Now().Add(time.Hour)}, nil
	}), CacheConfig{Backoff: BackoffConfig{
		Initial:    time.Hour,
		Max:        time.Hour,
		Multiplier: 1,
	}}, clock.Now, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("newCache() error = %v", err)
	}

	if _, err := cache.Token(context.Background()); !errors.Is(err, refreshErr) {
		t.Fatalf("Token() error = %v, want the source error", err)
	}
	if _, err := cache.Token(context.Background()); !errors.Is(err, ErrBackoff) {
		t.Fatalf("backoff Token() error = %v, want ErrBackoff", err)
	}

	cache.Invalidate()

	token, err := cache.Token(context.Background())
	if err != nil || token.Value != "recovered" {
		t.Fatalf("Token() after Invalidate() = (%v, %v)", token, err)
	}
}

func BenchmarkCacheHitParallel(b *testing.B) {
	cache, err := NewCache(TokenSourceFunc(func(context.Context) (Token, error) {
		return Token{Value: "token", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}), CacheConfig{})
	if err != nil {
		b.Fatalf("NewCache() error = %v", err)
	}

	ctx := context.Background()
	if _, err := cache.Token(ctx); err != nil {
		b.Fatalf("warm cache: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := cache.Token(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
}
