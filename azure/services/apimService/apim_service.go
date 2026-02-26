// Package apimservice provides Azure API Management service abstractions
//
// This service layer abstracts Azure API Management API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package apimservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for APIM service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "apimservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// APIMService provides methods for interacting with Azure API Management
type APIMService struct {
	session *azinternal.SafeSession
}

// New creates a new APIMService instance
func New(session *azinternal.SafeSession) *APIMService {
	return &APIMService{
		session: session,
	}
}

// NewWithSession creates a new APIMService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *APIMService {
	return New(session)
}

// ServiceInfo represents an API Management service instance
type ServiceInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	SKU               string
	GatewayURL        string
	PortalURL         string
	ManagementAPIURL  string
	PublisherEmail    string
	PublisherName     string
	VirtualNetworkType string
}

// APIInfo represents an API within APIM
type APIInfo struct {
	Name        string
	DisplayName string
	Path        string
	Protocols   []string
	ServiceURL  string
	APIVersion  string
}

// SubscriptionInfo represents an APIM subscription
type SubscriptionInfo struct {
	Name         string
	DisplayName  string
	Scope        string
	State        string
	PrimaryKey   string
	SecondaryKey string
}

// NamedValueInfo represents a named value (property) in APIM
type NamedValueInfo struct {
	Name        string
	DisplayName string
	Value       string
	Secret      bool
	Tags        []string
}

// getARMCredential returns ARM credential from session
func (s *APIMService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListServices returns all API Management services in a subscription
func (s *APIMService) ListServices(ctx context.Context, subID string) ([]*armapimanagement.ServiceResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armapimanagement.NewServiceClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create APIM client: %w", err)
	}

	pager := client.NewListPager(nil)
	var services []*armapimanagement.ServiceResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return services, fmt.Errorf("failed to list APIM services: %w", err)
		}
		services = append(services, page.Value...)
	}

	return services, nil
}

// ListServicesByResourceGroup returns all APIM services in a resource group
func (s *APIMService) ListServicesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armapimanagement.ServiceResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armapimanagement.NewServiceClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create APIM client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var services []*armapimanagement.ServiceResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return services, fmt.Errorf("failed to list APIM services: %w", err)
		}
		services = append(services, page.Value...)
	}

	return services, nil
}

// GetService returns a specific APIM service
func (s *APIMService) GetService(ctx context.Context, subID, rgName, serviceName string) (*armapimanagement.ServiceResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armapimanagement.NewServiceClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create APIM client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, serviceName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get APIM service: %w", err)
	}

	return &resp.ServiceResource, nil
}

// ListAPIs returns all APIs in an APIM service
func (s *APIMService) ListAPIs(ctx context.Context, subID, rgName, serviceName string) ([]*armapimanagement.APIContract, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armapimanagement.NewAPIClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}

	pager := client.NewListByServicePager(rgName, serviceName, nil)
	var apis []*armapimanagement.APIContract

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return apis, fmt.Errorf("failed to list APIs: %w", err)
		}
		apis = append(apis, page.Value...)
	}

	return apis, nil
}

// ListSubscriptions returns all subscriptions in an APIM service
func (s *APIMService) ListSubscriptions(ctx context.Context, subID, rgName, serviceName string) ([]*armapimanagement.SubscriptionContract, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armapimanagement.NewSubscriptionClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription client: %w", err)
	}

	pager := client.NewListPager(rgName, serviceName, nil)
	var subscriptions []*armapimanagement.SubscriptionContract

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return subscriptions, fmt.Errorf("failed to list subscriptions: %w", err)
		}
		subscriptions = append(subscriptions, page.Value...)
	}

	return subscriptions, nil
}

// ListNamedValues returns all named values in an APIM service
func (s *APIMService) ListNamedValues(ctx context.Context, subID, rgName, serviceName string) ([]*armapimanagement.NamedValueContract, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armapimanagement.NewNamedValueClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create named value client: %w", err)
	}

	pager := client.NewListByServicePager(rgName, serviceName, nil)
	var namedValues []*armapimanagement.NamedValueContract

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return namedValues, fmt.Errorf("failed to list named values: %w", err)
		}
		namedValues = append(namedValues, page.Value...)
	}

	return namedValues, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// =============================================================================
// Cached Methods
// =============================================================================

// CachedListServices returns all APIM services with caching
func (s *APIMService) CachedListServices(ctx context.Context, subID string) ([]*armapimanagement.ServiceResource, error) {
	key := cacheKey("services", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armapimanagement.ServiceResource), nil
	}
	result, err := s.ListServices(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListAPIs returns all APIs in an APIM service with caching
func (s *APIMService) CachedListAPIs(ctx context.Context, subID, rgName, serviceName string) ([]*armapimanagement.APIContract, error) {
	key := cacheKey("apis", subID, rgName, serviceName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armapimanagement.APIContract), nil
	}
	result, err := s.ListAPIs(ctx, subID, rgName, serviceName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListSubscriptions returns all subscriptions in an APIM service with caching
func (s *APIMService) CachedListSubscriptions(ctx context.Context, subID, rgName, serviceName string) ([]*armapimanagement.SubscriptionContract, error) {
	key := cacheKey("subscriptions", subID, rgName, serviceName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armapimanagement.SubscriptionContract), nil
	}
	result, err := s.ListSubscriptions(ctx, subID, rgName, serviceName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListNamedValues returns all named values in an APIM service with caching
func (s *APIMService) CachedListNamedValues(ctx context.Context, subID, rgName, serviceName string) ([]*armapimanagement.NamedValueContract, error) {
	key := cacheKey("namedvalues", subID, rgName, serviceName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armapimanagement.NamedValueContract), nil
	}
	result, err := s.ListNamedValues(ctx, subID, rgName, serviceName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
