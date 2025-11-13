package sdk

import (
	"time"

	"github.com/patrickmn/go-cache"
)

// AzureSDKCache is the centralized cache for all Azure SDK calls
// Uses the same caching library as AWS (github.com/patrickmn/go-cache)
var AzureSDKCache = cache.New(2*time.Hour, 10*time.Minute)

// CacheKey generates a consistent cache key from components
func CacheKey(parts ...string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += "-"
		}
		result += part
	}
	return result
}
