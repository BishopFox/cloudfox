package sdk

import (
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// GCPSDKCache is the centralized cache for all GCP SDK calls
// Uses the same caching library as AWS and Azure (github.com/patrickmn/go-cache)
// Default expiration: 2 hours, cleanup interval: 10 minutes
var GCPSDKCache = cache.New(2*time.Hour, 10*time.Minute)

// CacheKey generates a consistent cache key from components
// Example: CacheKey("buckets", "my-project") -> "buckets-my-project"
func CacheKey(parts ...string) string {
	return strings.Join(parts, "-")
}

// ClearCache clears all entries from the cache
func ClearCache() {
	GCPSDKCache.Flush()
}

// CacheStats returns cache statistics
type CacheStats struct {
	ItemCount int
	Hits      uint64
	Misses    uint64
}

// GetCacheStats returns current cache statistics
func GetCacheStats() CacheStats {
	return CacheStats{
		ItemCount: GCPSDKCache.ItemCount(),
		// Note: go-cache doesn't track hits/misses directly
		// These would need custom implementation if needed
	}
}

// SetCacheExpiration sets a custom expiration for an item
func SetCacheExpiration(key string, value interface{}, expiration time.Duration) {
	GCPSDKCache.Set(key, value, expiration)
}

// GetFromCache retrieves an item from cache
func GetFromCache(key string) (interface{}, bool) {
	return GCPSDKCache.Get(key)
}

// SetInCache stores an item in cache with default expiration
func SetInCache(key string, value interface{}) {
	GCPSDKCache.Set(key, value, 0) // 0 = use default expiration
}

// DeleteFromCache removes an item from cache
func DeleteFromCache(key string) {
	GCPSDKCache.Delete(key)
}
