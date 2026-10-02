package garagat

import (
	"fmt"
	"sync"
	"time"
)

// RateLimitingMethod selects how the rate limiter waits.
type RateLimitingMethod int

const (
	// RateAuto sleeps when the sleep resolution allows it, then spins.
	RateAuto RateLimitingMethod = iota
	// RateActive only spins.
	RateActive
	// RateSleep only sleeps.
	RateSleep
	// RateNone does not wait.
	RateNone
)

// ParseRateLimitingMethod parses auto, active, sleep or none.
func ParseRateLimitingMethod(s string) (RateLimitingMethod, error) {
	switch s {
	case "auto":
		return RateAuto, nil
	case "active":
		return RateActive, nil
	case "sleep":
		return RateSleep, nil
	case "none":
		return RateNone, nil
	}
	return 0, fmt.Errorf("%s is not a valid rate limiting method (auto, active, sleep, none)", s)
}

func (m RateLimitingMethod) String() string {
	return [...]string{"auto", "active", "sleep", "none"}[m]
}

// RateLimiter limits the rate at which a loop runs. Call Wait every `steps`
// items to reach `rate` items per second.
type RateLimiter struct {
	method          RateLimitingMethod
	sleepResolution time.Duration
	targetDelta     time.Duration
	last            time.Time
	stats           *RateLimiterStatistics
}

// NewRateLimiter returns a rate limiter for targetRate items per second,
// called every steps items.
func NewRateLimiter(targetRate, steps uint64, method RateLimitingMethod) (*RateLimiter, error) {
	if targetRate == 0 {
		return nil, fmt.Errorf("target_rate must be > 0")
	}
	if steps == 0 {
		steps = 1
	}
	delta := time.Duration(steps * 1_000_000_000 / targetRate)
	return &RateLimiter{
		method:          method,
		sleepResolution: sleepResolution(),
		targetDelta:     delta,
		last:            time.Now(),
		stats:           &RateLimiterStatistics{steps: steps, targetDelta: delta},
	}, nil
}

// Wait blocks until targetDelta has elapsed since the previous call.
func (r *RateLimiter) Wait() {
	now := time.Now()
	delta := now.Sub(r.last)
	r.stats.recordInterCall(delta)

	// (1) Early return if we do not need to wait.
	if delta >= r.targetDelta {
		r.last = time.Now()
		r.stats.recordEffective(delta)
		return
	}

	// (2) Sleep if possible.
	if (r.method == RateAuto || r.method == RateSleep) && r.sleepResolution < r.targetDelta-delta {
		time.Sleep(r.targetDelta - delta)
	}

	// (3) Spin wait.
	for {
		delta = time.Since(r.last)
		if !(r.method == RateAuto || r.method == RateActive) || delta >= r.targetDelta {
			break
		}
	}
	r.stats.recordEffective(delta)
	r.last = time.Now()
}

// Statistics returns the rate limiter statistics, safe for concurrent reads.
func (r *RateLimiter) Statistics() *RateLimiterStatistics { return r.stats }

func sleepResolution() time.Duration {
	var worst time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		time.Sleep(time.Nanosecond)
		worst = max(worst, time.Since(start))
	}
	return worst
}

// circular keeps the last 64 values.
type circular struct {
	values [64]float64
	cursor int
}

func (c *circular) push(v float64) {
	c.values[c.cursor%len(c.values)] = v
	c.cursor++
}

func (c *circular) average() float64 {
	n := min(c.cursor, len(c.values))
	if n == 0 {
		return 0
	}
	var sum float64
	for _, v := range c.values[:n] {
		sum += v
	}
	return sum / float64(n)
}

// RateLimiterStatistics records the deltas between rate limiter calls.
type RateLimiterStatistics struct {
	mu          sync.Mutex
	steps       uint64
	targetDelta time.Duration
	effective   circular
	interCall   circular
}

func (s *RateLimiterStatistics) recordEffective(d time.Duration) {
	s.mu.Lock()
	s.effective.push(float64(d.Nanoseconds()))
	s.mu.Unlock()
}

func (s *RateLimiterStatistics) recordInterCall(d time.Duration) {
	s.mu.Lock()
	s.interCall.push(float64(d.Nanoseconds()))
	s.mu.Unlock()
}

// AverageUtilization is the fraction of the target delta spent outside the
// rate limiter.
func (s *RateLimiterStatistics) AverageUtilization() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interCall.average() / float64(s.targetDelta.Nanoseconds())
}

// AverageRate is the effective rate achieved, in items per second.
func (s *RateLimiterStatistics) AverageRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	avg := s.effective.average()
	if avg <= 0 {
		return 0
	}
	return float64(s.steps) * 1e9 / avg
}

func (s *RateLimiterStatistics) String() string {
	return fmt.Sprintf("average_rate=%g average_utilization=%g", s.AverageRate(), s.AverageUtilization()*100)
}
