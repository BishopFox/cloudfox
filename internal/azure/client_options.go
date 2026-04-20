package azure

import (
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// rateLimitPolicy implements policy.Policy to inject rate limiting into the SDK pipeline.
type rateLimitPolicy struct{}

func (p *rateLimitPolicy) Do(req *policy.Request) (*http.Response, error) {
	if err := WaitARM(req.Raw().Context()); err != nil {
		return nil, err
	}
	return req.Next()
}

// DefaultARMClientOptions returns *arm.ClientOptions with retry tuned for Azure throttling.
// SDK defaults: 3 retries, 800ms delay, 60s max. Azure 429s often have Retry-After: 30-120s.
// These settings survive typical throttle windows without losing data.
func DefaultARMClientOptions() *arm.ClientOptions {
	return &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Retry: policy.RetryOptions{
				MaxRetries:    8,
				RetryDelay:    4 * time.Second,
				MaxRetryDelay: 5 * time.Minute,
				// StatusCodes defaults already include 408, 429, 500, 502, 503, 504
			},
			PerRetryPolicies: []policy.Policy{
				&rateLimitPolicy{},
			},
		},
	}
}
