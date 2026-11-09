package runtime

import (
	"sync"
	"time"
)

// Seed at package initialization so even the first verifier uses time elapsed
// since startup. Constructing a verifier must never reset this clock.
var processClock = newVerificationClock(time.Now())

type verificationClock struct {
	mu     sync.Mutex
	base   time.Time // wall time at monotonic elapsed zero, adjusted only forward
	sample func() (wall time.Time, elapsed time.Duration)
}

// newVerificationClock retains the monotonic reading in start for elapsed time.
func newVerificationClock(start time.Time) *verificationClock {
	return &verificationClock{base: start.UTC(), sample: func() (time.Time, time.Duration) {
		t := time.Now()
		// Sub must use the original readings, before UTC strips monotonic time.
		return t.UTC(), t.Sub(start)
	}}
}

// now returns a nondecreasing UTC time, or ErrClockRollback for excessive lag.
func (c *verificationClock) now(skew time.Duration) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Sample under the lock so concurrent calls are processed in time order.
	wall, elapsed := c.sample()
	floor := c.base.Add(elapsed)
	if wall.After(floor) {
		c.base = wall.Add(-elapsed)
		return wall, nil
	}
	if skew < 0 {
		skew = 0
	}
	if floor.Sub(wall) > skew {
		return time.Time{}, ErrClockRollback
	}
	return floor, nil
}
