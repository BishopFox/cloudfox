package sdk

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	// SharedCache is the centralized cache for Kubernetes data
	SharedCache = cache.New(2*time.Hour, 10*time.Minute)
)

// CacheKey generates a standardized cache key
func CacheKey(prefix string, parts ...string) string {
	key := prefix
	for _, part := range parts {
		if part != "" {
			key += "-" + part
		}
	}
	return key
}

// Get retrieves an item from the cache
func Get(key string) (interface{}, bool) {
	return SharedCache.Get(key)
}

// Set stores an item in the cache with default expiration
func Set(key string, value interface{}) {
	SharedCache.Set(key, value, cache.DefaultExpiration)
}

// SetWithExpiration stores an item with a custom expiration
func SetWithExpiration(key string, value interface{}, expiration time.Duration) {
	SharedCache.Set(key, value, expiration)
}

// Delete removes an item from the cache
func Delete(key string) {
	SharedCache.Delete(key)
}

// Flush clears all items from the cache
func Flush() {
	SharedCache.Flush()
}

// GetOrSet retrieves from cache or calls the provider function and caches the result
func GetOrSet[T any](key string, provider func() (T, error)) (T, error) {
	if cached, found := Get(key); found {
		if value, ok := cached.(T); ok {
			return value, nil
		}
	}

	value, err := provider()
	if err != nil {
		var zero T
		return zero, err
	}

	Set(key, value)
	return value, nil
}
