package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
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

		// Rate limit before each attempt
		if strings.Contains(url, "graph.microsoft.com") {
			if err := WaitGraph(ctx); err != nil {
				return nil, fmt.Errorf("rate limiter cancelled: %v", err)
			}
		} else if strings.Contains(url, "management.azure.com") {
			if err := WaitARM(ctx); err != nil {
				return nil, fmt.Errorf("rate limiter cancelled: %v", err)
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

			// Signal AIMD controller to halve the rate
			isGraph := strings.Contains(url, "graph.microsoft.com")
			if isGraph {
				OnThrottleGraph()
			} else {
				OnThrottleARM()
			}

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

			// Wait for retry-after + jitter to avoid thundering herd
			wait := retryAfter + jitter(2*time.Second)
			select {
			case <-time.After(wait):
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

		// Success (2xx) - signal AIMD controller so it can ramp up
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if strings.Contains(url, "graph.microsoft.com") {
				OnSuccessGraph()
			} else if strings.Contains(url, "management.azure.com") {
				OnSuccessARM()
			}
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
		// No inter-page delay: the AIMD rate limiter in HTTPRequestWithRetry
		// already paces requests. Adding a fixed delay here would undercount
		// actual throughput capacity.
	}

	return nil
}

// ---------------------------------------------------------------------------
// Graph Batch API ($batch endpoint)
// ---------------------------------------------------------------------------

// GraphBatchSubRequest is a single sub-request in a Graph $batch call.
type GraphBatchSubRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

// GraphBatchSubResponse is a single sub-response from a Graph $batch call.
type GraphBatchSubResponse struct {
	ID     string          `json:"id"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// GraphBatchRequest sends up to 20 sub-requests to the Graph $batch endpoint
// and returns the sub-responses. The caller is responsible for chunking
// requests into batches of <= 20 (the Graph API maximum).
func GraphBatchRequest(ctx context.Context, token string, requests []GraphBatchSubRequest) ([]GraphBatchSubResponse, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	if len(requests) > 20 {
		return nil, fmt.Errorf("Graph $batch limit is 20 sub-requests, got %d", len(requests))
	}

	payload := struct {
		Requests []GraphBatchSubRequest `json:"requests"`
	}{Requests: requests}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	config := RateLimitConfig{
		MaxRetries:        8,
		InitialDelay:      5 * time.Second,
		MaxDelay:          5 * time.Minute,
		EnableBackoff:     true,
		RespectRetryAfter: true,
	}

	body, err := HTTPRequestWithRetry(ctx, "POST", "https://graph.microsoft.com/v1.0/$batch", token,
		strings.NewReader(string(payloadBytes)), config)
	if err != nil {
		return nil, fmt.Errorf("batch request failed: %w", err)
	}

	var result struct {
		Responses []GraphBatchSubResponse `json:"responses"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse batch response: %w", err)
	}

	return result.Responses, nil
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

// NewAuthenticatedRequest creates an HTTP request with bearer token authentication
func NewAuthenticatedRequest(method, url, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

// SendAuthenticatedRequest sends an HTTP request and returns the response
func SendAuthenticatedRequest(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

// UnmarshalResponseBody reads and unmarshals JSON response body
func UnmarshalResponseBody(resp *http.Response, v interface{}) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Azure SDK error helpers
// ---------------------------------------------------------------------------

// IsAccessDenied returns true if the error is an Azure 403 AuthorizationFailed response.
func IsAccessDenied(err error) bool {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == 403
	}
	return false
}

// AzureAPIErrorSummary returns a short, human-readable summary of an Azure SDK error.
// For ResponseError it extracts the status code and error code; for other errors it
// returns the error message directly (no multi-line HTTP response dump).
func AzureAPIErrorSummary(err error) string {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		code := respErr.ErrorCode
		if code == "" {
			code = "Unknown"
		}
		return fmt.Sprintf("HTTP %d (%s)", respErr.StatusCode, code)
	}
	return err.Error()
}
