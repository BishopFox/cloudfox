package azure

import (
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// AzureDataCache is the centralized in-memory cache for Azure API responses.
// It persists across all commands within a single process (e.g., all-checks).
// Default expiration: 2 hours, cleanup interval: 10 minutes.
var AzureDataCache = cache.New(2*time.Hour, 10*time.Minute)

// AzCacheKey generates a consistent cache key from components.
// Example: AzCacheKey("resource-groups", "sub-123") -> "az-resource-groups-sub-123"
func AzCacheKey(parts ...string) string {
	return "az-" + strings.Join(parts, "-")
}

// ClearAzureCache flushes all entries from the in-memory cache.
func ClearAzureCache() {
	AzureDataCache.Flush()
}

// GetAzureCacheStats returns the number of items currently in the cache.
func GetAzureCacheStats() int {
	return AzureDataCache.ItemCount()
}
