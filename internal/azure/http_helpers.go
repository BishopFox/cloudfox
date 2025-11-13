package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// RateLimitConfig holds configuration for rate limit handling
type RateLimitConfig struct {
	MaxRetries        int           // Maximum number of retry attempts (default: 8)
	InitialDelay      time.Duration // Initial delay for exponential backoff (default: 2s)
	MaxDelay          time.Duration // Maximum delay between retries (default: 5 minutes)
	EnableBackoff     bool          // Use exponential backoff (default: true)
	RespectRetryAfter bool          // Respect Retry-After header (default: true)
}

// DefaultRateLimitConfig returns the default configuration for rate limiting
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		MaxRetries:        8,
		InitialDelay:      2 * time.Second,
		MaxDelay:          5 * time.Minute,
		EnableBackoff:     true,
		RespectRetryAfter: true,
	}
}

// HTTPRequestWithRetry performs an HTTP request with intelligent rate limit handling
// This function should be used for all API calls that may experience rate limiting
func HTTPRequestWithRetry(ctx context.Context, method, url, token string, body io.Reader, config RateLimitConfig) ([]byte, error) {
	logger := internal.NewLogger()

	for attempt := 0; attempt < config.MaxRetries; attempt++ {
		// Apply delay before retry (skip first attempt)
		if attempt > 0 {
			delay := calculateDelay(attempt, config)
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Retry attempt %d/%d after %v delay", attempt+1, config.MaxRetries, delay), "http-retry")
			}

			select {
			case <-time.After(delay):
				// Continue after delay
			case <-ctx.Done():
				return nil, fmt.Errorf("request cancelled: %v", ctx.Err())
			}
		}

		// Create request
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		// Set headers
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("HTTP request failed: %v", err), "http-retry")
			}
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("request failed after %d attempts: %v", config.MaxRetries, err)
			}
			continue
		}

		// Read response body
		responseBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to read response: %v", err), "http-retry")
			}
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("failed to read response after %d attempts: %v", config.MaxRetries, err)
			}
			continue
		}

		// Handle rate limiting (429)
		if resp.StatusCode == 429 {
			retryAfter := extractRetryAfter(resp, config)

			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Rate limited (429) - will retry after %v", retryAfter), "http-retry")

				// Try to parse error details
				var errResp struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if json.Unmarshal(responseBody, &errResp) == nil {
					logger.ErrorM(fmt.Sprintf("Throttle reason: %s - %s", errResp.Error.Code, errResp.Error.Message), "http-retry")
				}
			}

			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("rate limited after %d retries (last delay: %v): %s", config.MaxRetries, retryAfter, string(responseBody))
			}

			// Wait for the specified retry-after duration before next attempt
			select {
			case <-time.After(retryAfter):
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("request cancelled while waiting for rate limit: %v", ctx.Err())
			}
		}

		// Handle server errors (5xx) - retryable
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Server error (%d) - will retry", resp.StatusCode), "http-retry")
			}
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("server error after %d retries: status %d: %s", config.MaxRetries, resp.StatusCode, string(responseBody))
			}
			continue
		}

		// Handle client errors (4xx except 429) - not retryable
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			return nil, fmt.Errorf("client error: status %d: %s", resp.StatusCode, string(responseBody))
		}

		// Success (2xx)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return responseBody, nil
		}

		// Unexpected status code
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(responseBody))
	}

	return nil, fmt.Errorf("exceeded maximum retries (%d)", config.MaxRetries)
}

// extractRetryAfter extracts the Retry-After duration from response headers
// Falls back to exponential backoff if header is not present
func extractRetryAfter(resp *http.Response, config RateLimitConfig) time.Duration {
	logger := internal.NewLogger()

	// Check for Retry-After header
	if config.RespectRetryAfter {
		if retryAfterHeader := resp.Header.Get("Retry-After"); retryAfterHeader != "" {
			// Try parsing as seconds (integer)
			if seconds, err := strconv.Atoi(retryAfterHeader); err == nil {
				duration := time.Duration(seconds) * time.Second
				// Cap at MaxDelay
				if duration > config.MaxDelay {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.InfoM(fmt.Sprintf("Retry-After header suggests %v, capping at %v", duration, config.MaxDelay), "http-retry")
					}
					return config.MaxDelay
				}
				return duration
			}

			// Try parsing as HTTP date (RFC1123)
			if retryTime, err := time.Parse(time.RFC1123, retryAfterHeader); err == nil {
				duration := time.Until(retryTime)
				if duration < 0 {
					duration = config.InitialDelay
				}
				// Cap at MaxDelay
				if duration > config.MaxDelay {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.InfoM(fmt.Sprintf("Retry-After header suggests %v, capping at %v", duration, config.MaxDelay), "http-retry")
					}
					return config.MaxDelay
				}
				return duration
			}
		}
	}

	// Fallback: use a longer default delay for Graph API throttling
	// Microsoft Graph can throttle for extended periods
	return 60 * time.Second
}

// calculateDelay calculates the delay for exponential backoff
func calculateDelay(attempt int, config RateLimitConfig) time.Duration {
	if !config.EnableBackoff {
		return config.InitialDelay
	}

	// Exponential backoff: InitialDelay * 2^(attempt-1)
	// attempt-1 because we want: 2s, 4s, 8s, 16s, 32s, 64s, 128s...
	delay := config.InitialDelay * time.Duration(1<<uint(attempt-1))

	// Cap at MaxDelay
	if delay > config.MaxDelay {
		return config.MaxDelay
	}

	return delay
}

// GraphAPIRequestWithRetry is a convenience wrapper for Microsoft Graph API requests
func GraphAPIRequestWithRetry(ctx context.Context, method, url, token string) ([]byte, error) {
	// Use more aggressive settings for Graph API
	config := RateLimitConfig{
		MaxRetries:        8,
		InitialDelay:      5 * time.Second,
		MaxDelay:          5 * time.Minute,
		EnableBackoff:     true,
		RespectRetryAfter: true,
	}

	return HTTPRequestWithRetry(ctx, method, url, token, nil, config)
}

// GraphAPIPagedRequest handles paginated Graph API requests with rate limiting
func GraphAPIPagedRequest(ctx context.Context, initialURL, token string, processPage func(data []byte) (hasMore bool, nextURL string, err error)) error {
	logger := internal.NewLogger()
	url := initialURL
	pageCount := 0
	config := RateLimitConfig{
		MaxRetries:        8,
		InitialDelay:      5 * time.Second,
		MaxDelay:          5 * time.Minute,
		EnableBackoff:     true,
		RespectRetryAfter: true,
	}

	for url != "" {
		pageCount++
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Fetching page %d", pageCount), "graph-paged")
		}

		// Fetch page with retry logic
		body, err := HTTPRequestWithRetry(ctx, "GET", url, token, nil, config)
		if err != nil {
			return fmt.Errorf("failed to fetch page %d: %v", pageCount, err)
		}

		// Process page
		hasMore, nextURL, err := processPage(body)
		if err != nil {
			return fmt.Errorf("failed to process page %d: %v", pageCount, err)
		}

		if !hasMore {
			break
		}

		url = nextURL

		// Add delay between pages to avoid rapid-fire requests
		if url != "" {
			delay := 1 * time.Second
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Pausing %v before next page", delay), "graph-paged")
			}
			select {
			case <-time.After(delay):
				// Continue
			case <-ctx.Done():
				return fmt.Errorf("request cancelled: %v", ctx.Err())
			}
		}
	}

	return nil
}

// ParseGraphError attempts to parse a Graph API error response
func ParseGraphError(body []byte) (code string, message string) {
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &errResp); err == nil {
		return errResp.Error.Code, errResp.Error.Message
	}

	return "", string(body)
}

// IsThrottlingError checks if an error string indicates throttling
func IsThrottlingError(errMsg string) bool {
	throttleKeywords := []string{
		"429",
		"TooManyRequests",
		"rate limit",
		"throttle",
		"throttling",
	}

	errLower := strings.ToLower(errMsg)
	for _, keyword := range throttleKeywords {
		if strings.Contains(errLower, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}
