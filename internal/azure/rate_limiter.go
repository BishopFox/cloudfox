package azure

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	armLimiter   *rate.Limiter
	graphLimiter *rate.Limiter
	limiterOnce  sync.Once
	limiterMu    sync.Mutex
)

func initLimiters() {
	limiterOnce.Do(func() {
		armLimiter = rate.NewLimiter(rate.Limit(8), 12)  // 8/s sustained, burst 12
		graphLimiter = rate.NewLimiter(rate.Limit(5), 8) // 5/s sustained, burst 8
	})
}

func WaitARM(ctx context.Context) error   { initLimiters(); return armLimiter.Wait(ctx) }
func WaitGraph(ctx context.Context) error  { initLimiters(); return graphLimiter.Wait(ctx) }

func GetARMLimiter() *rate.Limiter   { initLimiters(); return armLimiter }
func GetGraphLimiter() *rate.Limiter { initLimiters(); return graphLimiter }

// AdaptiveSlowdown halves the rate when throttled, restores after cooldown.
func AdaptiveSlowdown(limiter *rate.Limiter, cooldown time.Duration) {
	limiterMu.Lock()
	current := limiter.Limit()
	reduced := current / 2
	if reduced < rate.Limit(0.5) {
		reduced = rate.Limit(0.5)
	}
	limiter.SetLimit(reduced)
	limiterMu.Unlock()

	go func() {
		time.Sleep(cooldown)
		limiterMu.Lock()
		limiter.SetLimit(current)
		limiterMu.Unlock()
	}()
}
