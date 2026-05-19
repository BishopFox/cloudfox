package azure

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"golang.org/x/time/rate"
)

// AIMD (Additive Increase, Multiplicative Decrease) rate controller.
// Starts at a high rate, backs off on 429s, and gradually ramps back up
// when requests succeed without throttling.
//
// Unlike the old AdaptiveSlowdown (fire-and-forget timer restore with race conditions),
// this tracks a single authoritative "target rate" and uses success signals to ramp up.

type aimdLimiter struct {
	mu          sync.Mutex
	name        string        // "Graph" or "ARM" for log messages
	limiter     *rate.Limiter
	currentRate rate.Limit // authoritative target rate
	maxRate     rate.Limit // ceiling (never exceed)
	minRate     rate.Limit // floor (never go below)
	increment   rate.Limit // additive increase per ramp-up step
	burstRatio  int        // burst = currentRate * burstRatio (minimum 1)

	// Ramp-up state: after a throttle, we need N consecutive success windows
	// before increasing the rate. This prevents oscillation.
	successCount   int // consecutive successes since last throttle
	rampUpInterval int // how many successes before we increase rate

	// Cooldown: after a throttle, don't ramp up for this duration
	lastThrottle time.Time
	cooldownBase time.Duration // minimum cooldown before ramp-up starts
}

func newAIMDLimiter(name string, startRate, maxRate, minRate, increment rate.Limit, burstRatio, rampUpInterval int, cooldownBase time.Duration) *aimdLimiter {
	burst := int(startRate) * burstRatio
	if burst < 1 {
		burst = 1
	}
	return &aimdLimiter{
		name:           name,
		limiter:        rate.NewLimiter(startRate, burst),
		currentRate:    startRate,
		maxRate:        maxRate,
		minRate:        minRate,
		increment:      increment,
		burstRatio:     burstRatio,
		rampUpInterval: rampUpInterval,
		cooldownBase:   cooldownBase,
	}
}

// Wait blocks until the rate limiter allows a request.
func (a *aimdLimiter) Wait(ctx context.Context) error {
	return a.limiter.Wait(ctx)
}

// OnThrottle is called when a 429 is received. Halves the rate (multiplicative decrease).
func (a *aimdLimiter) OnThrottle() {
	a.mu.Lock()
	defer a.mu.Unlock()

	previous := a.currentRate
	reduced := a.currentRate / 2
	if reduced < a.minRate {
		reduced = a.minRate
	}

	a.currentRate = reduced
	a.successCount = 0
	a.lastThrottle = time.Now()
	a.applyRate()

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger := internal.NewLogger()
		logger.ErrorM(
			fmt.Sprintf("[%s] 429 throttled: %.1f → %.1f req/s (burst %d)",
				a.name, float64(previous), float64(a.currentRate), a.limiter.Burst()),
			"rate-limiter",
		)
	}
}

// OnSuccess is called after a successful (non-429) response. Tracks consecutive
// successes and ramps up the rate when conditions are met.
func (a *aimdLimiter) OnSuccess() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Already at max, nothing to do
	if a.currentRate >= a.maxRate {
		return
	}

	// Still in cooldown after a throttle
	if !a.lastThrottle.IsZero() && time.Since(a.lastThrottle) < a.cooldownBase {
		return
	}

	a.successCount++
	if a.successCount >= a.rampUpInterval {
		a.successCount = 0
		newRate := a.currentRate + a.increment
		if newRate > a.maxRate {
			newRate = a.maxRate
		}
		a.currentRate = newRate
		a.applyRate()

		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger := internal.NewLogger()
			logger.InfoM(
				fmt.Sprintf("[%s] Rate increased: %.1f → %.1f req/s (burst %d)",
					a.name, float64(a.currentRate-a.increment), float64(a.currentRate), a.limiter.Burst()),
				"rate-limiter",
			)
		}
	}
}

// applyRate sets the limiter to the current target rate. Must be called with mu held.
func (a *aimdLimiter) applyRate() {
	burst := int(a.currentRate) * a.burstRatio
	if burst < 1 {
		burst = 1
	}
	a.limiter.SetLimit(a.currentRate)
	a.limiter.SetBurst(burst)
}

// CurrentRate returns the current rate for diagnostics.
func (a *aimdLimiter) CurrentRate() rate.Limit {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.currentRate
}

// ---------------------------------------------------------------------------
// Global instances
// ---------------------------------------------------------------------------

var (
	armAIMD     *aimdLimiter
	graphAIMD   *aimdLimiter
	limiterOnce sync.Once
)

func initLimiters() {
	limiterOnce.Do(func() {
		// ARM: Azure advertises 12,000 req/hour/subscription (~3.3/s per sub) but
		// tenant-scoped calls share a higher pool. Start at 12/s, ceiling 20/s.
		armAIMD = newAIMDLimiter(
			"ARM",
			12,             // startRate: 12 req/s
			20,             // maxRate: ceiling
			1,              // minRate: floor
			1,              // increment: +1 req/s per ramp-up step
			2,              // burstRatio: burst = 2x rate
			50,             // rampUpInterval: 50 successes before increasing
			30*time.Second, // cooldownBase: wait 30s after throttle before ramping
		)

		// Graph: Azure advertises 10,000 req/10min per app (~16.7/s) but
		// service-specific limits (directory reads, etc.) are much higher.
		// Start at 20/s, ceiling 50/s. The AIMD algorithm self-corrects
		// on 429s (halves rate), so an aggressive ceiling is safe.
		graphMaxRate := rate.Limit(50)
		graphStartRate := rate.Limit(20)
		if globals.AZ_GRAPH_RPS > 0 {
			graphMaxRate = rate.Limit(globals.AZ_GRAPH_RPS)
			graphStartRate = graphMaxRate / 2
			if graphStartRate < 1 {
				graphStartRate = 1
			}
		}
		graphAIMD = newAIMDLimiter(
			"Graph",
			graphStartRate,  // startRate: 20 req/s (was 10)
			graphMaxRate,    // maxRate: ceiling 50 (was 15)
			1,               // minRate: floor
			1,               // increment: +1 req/s per ramp-up step
			2,               // burstRatio: burst = 2x rate
			50,              // rampUpInterval: 50 successes before increasing
			30*time.Second,  // cooldownBase: wait 30s after throttle before ramping
		)
	})
}

// ---------------------------------------------------------------------------
// Public API (unchanged signatures for backward compatibility)
// ---------------------------------------------------------------------------

// WaitARM blocks until the ARM rate limiter allows a request.
func WaitARM(ctx context.Context) error { initLimiters(); return armAIMD.Wait(ctx) }

// WaitGraph blocks until the Graph rate limiter allows a request.
func WaitGraph(ctx context.Context) error { initLimiters(); return graphAIMD.Wait(ctx) }

// OnThrottleARM signals a 429 from ARM. Halves the rate.
func OnThrottleARM() { initLimiters(); armAIMD.OnThrottle() }

// OnThrottleGraph signals a 429 from Graph. Halves the rate.
func OnThrottleGraph() { initLimiters(); graphAIMD.OnThrottle() }

// OnSuccessARM signals a successful ARM response. May ramp up the rate.
func OnSuccessARM() { initLimiters(); armAIMD.OnSuccess() }

// OnSuccessGraph signals a successful Graph response. May ramp up the rate.
func OnSuccessGraph() { initLimiters(); graphAIMD.OnSuccess() }

// GetARMLimiter returns the underlying rate.Limiter (used by ARM SDK policy).
func GetARMLimiter() *rate.Limiter { initLimiters(); return armAIMD.limiter }

// GetGraphLimiter returns the underlying rate.Limiter.
func GetGraphLimiter() *rate.Limiter { initLimiters(); return graphAIMD.limiter }

// AdaptiveSlowdown is deprecated. Use OnThrottleARM/OnThrottleGraph instead.
// Kept so any stray callers compile. The cooldown parameter is ignored; AIMD
// manages its own cooldown state.
func AdaptiveSlowdown(limiter *rate.Limiter, _ time.Duration) {
	initLimiters()
	if limiter == armAIMD.limiter {
		armAIMD.OnThrottle()
	} else if limiter == graphAIMD.limiter {
		graphAIMD.OnThrottle()
	}
}

// ---------------------------------------------------------------------------
// Jitter helper
// ---------------------------------------------------------------------------

// jitter returns a random duration in [0, maxJitter). Used to spread concurrent
// requests after a throttle event to avoid thundering herd.
func jitter(maxJitter time.Duration) time.Duration {
	if maxJitter <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(maxJitter)))
}
