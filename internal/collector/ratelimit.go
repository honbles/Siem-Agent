package collector

// ratelimit.go — per-source sliding window rate limiter and event deduplicator.
// Wraps the output channel and silently drops events that exceed the
// configured per-source rate, or that are exact duplicates within a window.
// Build tag: none — pure Go, cross-platform.

import (
	"sync"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

// RateLimitConfig sets limits per event source.
type RateLimitConfig struct {
	// MaxPerSecond is the maximum events per second per source (0 = unlimited).
	MaxPerSecond int
	// DedupeWindow is how long to suppress duplicate event IDs (0 = no dedup).
	DedupeWindow time.Duration
}

// DefaultRateLimitConfig is a reasonable default for most deployments.
var DefaultRateLimitConfig = RateLimitConfig{
	MaxPerSecond: 500,            // 500 events/sec per source
	DedupeWindow: 5 * time.Second, // suppress exact duplicates within 5s
}

type sourceState struct {
	// Sliding window: count of events in the last second
	windowStart time.Time
	windowCount int
	// Dedup: recent event IDs → expiry time
	recentIDs map[string]time.Time
}

// RateLimiter wraps an event channel and enforces per-source rate limits.
type RateLimiter struct {
	cfg    RateLimitConfig
	mu     sync.Mutex
	states map[string]*sourceState // keyed by event Source
}

func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		cfg:    cfg,
		states: make(map[string]*sourceState),
	}
}

// Allow returns true if the event should be forwarded, false if it should be dropped.
func (r *RateLimiter) Allow(ev *schema.Event) bool {
	if r.cfg.MaxPerSecond == 0 && r.cfg.DedupeWindow == 0 {
		return true
	}

	key := string(ev.EventType) + ":" + ev.Source
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.states[key]
	if !ok {
		s = &sourceState{
			windowStart: now,
			recentIDs:   make(map[string]time.Time),
		}
		r.states[key] = s
	}

	// ── Deduplication ─────────────────────────────────────────────────────
	if r.cfg.DedupeWindow > 0 && ev.ID != "" {
		if expiry, seen := s.recentIDs[ev.ID]; seen && now.Before(expiry) {
			GlobalHealth.EventsDropped.Add(1)
			return false
		}
		// Expire old entries periodically (every 100 checks)
		if len(s.recentIDs) > 1000 {
			for id, expiry := range s.recentIDs {
				if now.After(expiry) {
					delete(s.recentIDs, id)
				}
			}
		}
		s.recentIDs[ev.ID] = now.Add(r.cfg.DedupeWindow)
	}

	// ── Rate limiting ──────────────────────────────────────────────────────
	if r.cfg.MaxPerSecond > 0 {
		if now.Sub(s.windowStart) > time.Second {
			// New window
			s.windowStart = now
			s.windowCount = 0
		}
		if s.windowCount >= r.cfg.MaxPerSecond {
			GlobalHealth.EventsDropped.Add(1)
			return false
		}
		s.windowCount++
	}

	GlobalHealth.EventsCollected.Add(1)
	return true
}

// FilteredChannel wraps an input channel, applies rate limiting, and forwards
// allowed events to the output channel. Run this in a goroutine.
func FilteredChannel(in <-chan schema.Event, out chan<- schema.Event, limiter *RateLimiter) {
	for ev := range in {
		if limiter.Allow(&ev) {
			select {
			case out <- ev:
			default:
				GlobalHealth.EventsDropped.Add(1)
			}
		}
	}
}
