package forwarder

// retry.go — exponential backoff with jitter for the HTTP forwarder.

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// RetryPolicy controls how retries behave.
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Multiplier  float64
}

// DefaultRetryPolicy returns sensible defaults for the event forwarder.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: 8,
		BaseDelay:   500 * time.Millisecond,
		MaxDelay:    5 * time.Minute,
		Multiplier:  2.0,
	}
}

// Do calls fn repeatedly until it returns nil, the context is cancelled, or
// MaxAttempts is exhausted. It returns the last non-nil error.
func (r RetryPolicy) Do(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < r.MaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err = fn()
		if err == nil {
			return nil
		}

		if attempt == r.MaxAttempts-1 {
			break
		}

		delay := r.delay(attempt)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}

// delay computes the backoff duration for a given attempt (0-indexed)
// using exponential growth with full-jitter.
func (r RetryPolicy) delay(attempt int) time.Duration {
	exp := math.Pow(r.Multiplier, float64(attempt))
	d := time.Duration(float64(r.BaseDelay) * exp)
	if d > r.MaxDelay {
		d = r.MaxDelay
	}
	// Full jitter: random value in [0, d)
	jitter := time.Duration(rand.Int63n(int64(d + 1)))
	return jitter
}

// IsRetryable returns true for errors that are worth retrying
// (network errors, 5xx responses, rate limits).
func IsRetryable(statusCode int) bool {
	switch statusCode {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}
