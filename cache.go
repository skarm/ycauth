package ycauth

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skarm/ycauth/internal/backoff"
)

const (
	defaultRefreshBefore      = 5 * time.Minute
	defaultRefreshTimeout     = 10 * time.Second
	defaultMinRefreshInterval = 5 * time.Second
	defaultBackoffInitial     = time.Second
	defaultBackoffMax         = 30 * time.Second
	defaultBackoffMultiplier  = 2
	defaultBackoffJitter      = 0.2
)

// BackoffConfig controls retry throttling after failed refreshes. Its zero value
// selects the default policy.
type BackoffConfig struct {
	// Initial is the delay after the first failed refresh. Zero uses the default.
	Initial time.Duration
	// Max caps a computed retry delay. Zero uses the default.
	Max time.Duration
	// Multiplier scales the delay after each consecutive failure. Zero uses the
	// default.
	Multiplier float64
	// Jitter is the proportional random variation in the range [0, 1]. Zero uses
	// the default, so retries are always jittered.
	Jitter float64
}

// RefreshEvent describes a completed refresh without exposing token material.
type RefreshEvent struct {
	// StartedAt is when the refresh began.
	StartedAt time.Time
	// FinishedAt is when the refresh completed.
	FinishedAt time.Time
	// ExpiresAt is the returned token's expiration, or zero when no token was returned.
	ExpiresAt time.Time
	// Err is the refresh error, or nil on success.
	Err error
	// Failures counts consecutive failed refreshes including this one, and is
	// zero on success.
	Failures int
	// UsedStale reports that the previous, still-valid token was served
	// because this refresh failed.
	UsedStale bool
}

// Observer receives a [RefreshEvent] after the cache publishes each refresh
// result. Cache calls the observer on the refresh goroutine, so implementations
// must return promptly. [Cache] recovers observer panics.
type Observer interface {
	// ObserveRefresh receives one event after each refresh completes.
	ObserveRefresh(RefreshEvent)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(RefreshEvent)

// ObserveRefresh calls f with event.
func (f ObserverFunc) ObserveRefresh(event RefreshEvent) { f(event) }

// CacheConfig configures a [Cache]. Its zero value selects safe defaults.
type CacheConfig struct {
	// RefreshBefore starts a background refresh this long before expiration.
	// Zero uses the default.
	RefreshBefore time.Duration
	// RefreshTimeout limits an individual refresh. Zero uses the default.
	RefreshTimeout time.Duration
	// MinRefreshInterval limits how often a valid token may be refreshed, as
	// far as its lifetime allows: a token expiring sooner is refreshed as often
	// as it must be. Zero uses the default.
	MinRefreshInterval time.Duration
	// Backoff controls retry delays after a failed refresh. Its zero value uses
	// the default policy.
	Backoff BackoffConfig
	// Observer receives completed refresh events. A nil Observer disables events.
	Observer Observer
}

// Cache caches IAM tokens and coalesces concurrent refreshes.
//
// Cache is safe for concurrent use. It serves cache hits from an atomic
// snapshot without taking a lock. Once a token enters its refresh window,
// Cache returns that token immediately and refreshes it in the background.
//
// A shared refresh uses [context.Background] and
// [CacheConfig.RefreshTimeout]. It can outlive the caller that triggered it and
// does not inherit caller-specific deadlines, cancellation, or values.
type Cache struct {
	tokenSource        TokenSource
	refreshBefore      time.Duration
	refreshTimeout     time.Duration
	minRefreshInterval time.Duration
	backoff            backoff.Policy
	observer           Observer
	now                func() time.Time
	jitterSource       func() float64

	// current is the hot read path and is nil until the first refresh lands.
	current atomic.Pointer[tokenSnapshot]

	mu            sync.Mutex
	refresh       *refreshCall
	nextAttemptAt time.Time
	backoffErr    error
	failures      int
}

// tokenSnapshot is an immutable view published to readers without locking.
//
// Refresh deadlines are durations from base so their scheduling uses the
// monotonic clock when available. Token validity is checked separately against
// its absolute ExpiresAt value, so a wall-clock correction cannot keep an
// expired token alive.
type tokenSnapshot struct {
	token Token
	// base is when this snapshot was published.
	base time.Time
	// refreshIn is when a reader holding this token should take the lock again:
	// the start of the refresh window, or the next useful attempt while a refresh
	// is pending or backed off.
	refreshIn time.Duration
	// expiresIn keeps readers off the refresh lock until the scheduled expiry
	// while a refresh is already in flight; ExpiresAt remains authoritative.
	expiresIn time.Duration
}

// newSnapshot describes token as of base, with the next lock-taking deadline.
func newSnapshot(token Token, base time.Time, refreshAt time.Time) *tokenSnapshot {
	// ExpiresAt represents an absolute service deadline. Strip any process-local
	// monotonic reading a custom source may have attached so comparisons use the
	// wall clock even after a clock correction or machine suspend.
	token.ExpiresAt = token.ExpiresAt.Round(0)

	return &tokenSnapshot{
		token:     token,
		base:      base,
		refreshIn: refreshAt.Sub(base),
		expiresIn: token.ExpiresAt.Sub(base),
	}
}

type refreshCall struct {
	done   chan struct{}
	result tokenResult
}

type tokenResult struct {
	token Token
	err   error
}

var _ TokenProvider = (*Cache)(nil)

// NewCache creates a token cache for tokenSource, which must not be nil. It
// defers the first acquisition until [Cache.Token] is called.
func NewCache(tokenSource TokenSource, config CacheConfig) (*Cache, error) {
	return newCache(tokenSource, config, time.Now, rand.Float64)
}

// newCache constructs a cache with injectable time and randomness sources for
// deterministic tests.
func newCache(tokenSource TokenSource, config CacheConfig, now func() time.Time, jitterSource func() float64) (*Cache, error) {
	switch {
	case tokenSource == nil:
		return nil, errors.New("create IAM token cache: token source must not be nil")
	case config.RefreshBefore < 0:
		return nil, errors.New("create IAM token cache: refresh window must not be negative")
	case config.RefreshTimeout < 0:
		return nil, errors.New("create IAM token cache: refresh timeout must not be negative")
	case config.MinRefreshInterval < 0:
		return nil, errors.New("create IAM token cache: minimum refresh interval must not be negative")
	}

	policy, err := backoffPolicy(config.Backoff)
	if err != nil {
		return nil, fmt.Errorf("create IAM token cache: %w", err)
	}

	return &Cache{
		tokenSource:        tokenSource,
		refreshBefore:      orDefault(config.RefreshBefore, defaultRefreshBefore),
		refreshTimeout:     orDefault(config.RefreshTimeout, defaultRefreshTimeout),
		minRefreshInterval: orDefault(config.MinRefreshInterval, defaultMinRefreshInterval),
		backoff:            policy,
		observer:           config.Observer,
		now:                now,
		jitterSource:       jitterSource,
	}, nil
}

// Token returns a cached token, or waits for the shared refresh when no valid
// token is cached. Cancellation stops only this caller's wait; it never
// cancels a refresh needed by others. A nil context returns an error.
func (c *Cache) Token(ctx context.Context) (Token, error) {
	if ctx == nil {
		return Token{}, errors.New("get IAM token: context must not be nil")
	}

	for {
		current := c.current.Load()
		now := c.now()

		if current != nil && current.token.ValidAt(now) {
			if elapsed := now.Sub(current.base); elapsed >= current.refreshIn {
				// Inside the refresh window: start the refresh but keep
				// serving the token we hold instead of blocking on the
				// network.
				_, _ = c.beginRefresh(now, current)
			}

			return current.token, nil
		}

		call, err := c.beginRefresh(now, current)
		if err != nil {
			return Token{}, err
		}

		if call == nil {
			// A refresh landed while we waited for the lock, so the decision
			// above was made on a stale snapshot. Take it again.
			continue
		}

		select {
		case <-ctx.Done():
			return Token{}, fmt.Errorf("get IAM token: %w", ctx.Err())
		case <-call.done:
			return call.result.token, call.result.err
		}
	}
}

// Invalidate drops the cached token and any pending backoff so that the next
// Token call acquires a new token. Call it only when the IAM token itself is
// known to be invalid; a refresh already in flight completes normally.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	c.current.Store(nil)
	c.nextAttemptAt = time.Time{}
	c.backoffErr = nil
	c.failures = 0
	c.mu.Unlock()
}

// beginRefresh joins the in-flight refresh or starts one. observed is the
// snapshot the caller based its decision on; when it is no longer current the
// decision is stale and beginRefresh returns nothing so the caller retries.
// It returns a nil call and the pending error when backoff forbids an attempt.
func (c *Cache) beginRefresh(now time.Time, observed *tokenSnapshot) (*refreshCall, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.refresh != nil {
		return c.refresh, nil
	}

	if c.current.Load() != observed {
		return nil, nil
	}

	if now.Before(c.nextAttemptAt) {
		return nil, c.backoffErr
	}

	call := &refreshCall{done: make(chan struct{})}
	c.refresh = call

	// Until this refresh lands there is nothing for a reader holding the token
	// to start, so republish it with its refresh deadline moved to expiry and
	// keep those readers off this lock.
	if observed != nil {
		pending := *observed
		pending.refreshIn = pending.expiresIn
		c.current.Store(&pending)
	}

	go c.runRefresh(call)

	return call, nil
}

// runRefresh performs the shared refresh on its own goroutine. It invokes
// caller-controlled code through the token source, returned error, and
// observer. Source and observer calls recover locally; abandonRefresh catches
// any remaining panic, including one from an error method.
func (c *Cache) runRefresh(call *refreshCall) {
	defer func() {
		if recovered := recover(); recovered != nil {
			c.abandonRefresh(call, fmt.Errorf("get IAM token: refresh panicked: %v", recovered))
		}
	}()

	startedAt := c.now()

	token, err := c.acquireToken()

	c.observe(c.publish(call, startedAt, token, err))
}

// abandonRefresh releases the refresh slot and any waiters after a panic left
// the refresh incomplete, so a broken source cannot wedge the cache.
func (c *Cache) abandonRefresh(call *refreshCall, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.refresh != call {
		return // publish already completed the call; the panic came later.
	}

	c.failures = min(c.failures+1, backoff.MaxFailures)
	c.nextAttemptAt = c.now().Add(c.backoff.Delay(c.failures, 0, c.jitterSource))
	c.backoffErr = err
	c.refresh = nil
	call.result = tokenResult{err: err}

	close(call.done)
}

// publish stores the outcome of a refresh, completes call, and returns the
// event describing what happened.
func (c *Cache) publish(call *refreshCall, startedAt time.Time, token Token, err error) RefreshEvent {
	finishedAt := c.now()

	if err == nil {
		// ExpiresAt is an absolute service deadline. Do not let a monotonic
		// component supplied by caller code hide a wall-clock correction.
		token.ExpiresAt = token.ExpiresAt.Round(0)

		switch {
		case token.Value == "":
			err = errors.New("acquire IAM token: source returned an empty token")
		case !token.ExpiresAt.After(finishedAt):
			err = errors.New("acquire IAM token: source returned an expired token")
		}
	}

	event := RefreshEvent{StartedAt: startedAt, FinishedAt: finishedAt, Err: err}
	hint := retryAfterHint(err)

	c.mu.Lock()
	defer c.mu.Unlock()

	previous := c.current.Load()

	if err == nil {
		c.current.Store(newSnapshot(token, finishedAt, c.nextRefreshAt(finishedAt, token.ExpiresAt)))
		c.nextAttemptAt = time.Time{}
		c.backoffErr = nil
		c.failures = 0
		call.result.token = token
		event.ExpiresAt = token.ExpiresAt
	} else {
		c.failures = min(c.failures+1, backoff.MaxFailures)
		c.nextAttemptAt = finishedAt.Add(c.backoff.Delay(c.failures, hint, c.jitterSource))
		// Built once per backoff window rather than per suppressed call.
		c.backoffErr = fmt.Errorf("get IAM token: %w until %s: %w", ErrBackoff, c.nextAttemptAt.Format(time.RFC3339Nano), err)
		event.Failures = c.failures

		if previous != nil && previous.token.ValidAt(finishedAt) {
			// Serve the still-valid token without the lock until a retry is due.
			c.current.Store(newSnapshot(previous.token, finishedAt, c.nextAttemptAt))
			call.result.token = previous.token
			event.ExpiresAt = previous.token.ExpiresAt
			event.UsedStale = true
		} else {
			call.result.err = err
		}
	}

	c.refresh = nil

	close(call.done)

	return event
}

// acquireToken runs the source under its own timeout. A separate goroutine
// prevents a source that ignores ctx from pinning the cache to a refresh that
// never ends. The cache stops waiting at RefreshTimeout and converts a source
// panic to an error.
func (c *Cache) acquireToken() (Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.refreshTimeout)
	defer cancel()

	acquired := make(chan tokenResult, 1)

	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				acquired <- tokenResult{err: fmt.Errorf("acquire IAM token: token source panicked: %v", recovered)}
			}
		}()

		token, err := c.tokenSource.Acquire(ctx)
		if err != nil {
			err = fmt.Errorf("acquire IAM token: %w", err)
		}

		acquired <- tokenResult{token: token, err: err}
	}()

	select {
	case result := <-acquired:
		return result.token, result.err
	case <-ctx.Done():
		return Token{}, fmt.Errorf("acquire IAM token: %w", ctx.Err())
	}
}

// nextRefreshAt schedules a refresh within the configured window while
// respecting the minimum interval and leaving time for a final retry.
func (c *Cache) nextRefreshAt(now, expiresAt time.Time) time.Time {
	ttl := expiresAt.Sub(now)
	target := expiresAt.Add(-min(c.refreshBefore, ttl/2))

	// Never schedule a refresh sooner than the minimum interval, except when
	// the token expires first: serving an expired token is worse than
	// refreshing more often than asked.
	if earliest := now.Add(c.minRefreshInterval); target.Before(earliest) {
		target = earliest
	}

	if latest := expiresAt.Add(-min(time.Second, ttl/10)); target.After(latest) {
		target = latest
	}

	return target
}

// observe reports event and contains a panic from caller-controlled observer
// code.
func (c *Cache) observe(event RefreshEvent) {
	if c.observer == nil {
		return
	}

	defer func() { _ = recover() }()

	c.observer.ObserveRefresh(event)
}

// backoffPolicy applies defaults and validates the public backoff config.
func backoffPolicy(config BackoffConfig) (backoff.Policy, error) {
	policy := backoff.Policy{
		Initial:    orDefault(config.Initial, defaultBackoffInitial),
		Max:        orDefault(config.Max, defaultBackoffMax),
		Multiplier: orDefault(config.Multiplier, defaultBackoffMultiplier),
		Jitter:     orDefault(config.Jitter, defaultBackoffJitter),
	}

	if err := policy.Validate(); err != nil {
		return backoff.Policy{}, err
	}

	return policy, nil
}

// orDefault substitutes fallback for an unset configuration value.
func orDefault[T time.Duration | float64](value, fallback T) T {
	if value == 0 {
		return fallback
	}

	return value
}
