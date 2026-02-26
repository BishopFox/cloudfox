// Package webappservice provides Azure Web Apps service abstractions
//
// This service layer abstracts Azure App Service API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package webappservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for Web App service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "webappservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// WebAppService provides methods for interacting with Azure Web Apps
type WebAppService struct {
	session *azinternal.SafeSession
}

// New creates a new WebAppService instance
func New(session *azinternal.SafeSession) *WebAppService {
	return &WebAppService{
		session: session,
	}
}

// NewWithSession creates a new WebAppService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *WebAppService {
	return New(session)
}

// WebAppInfo represents an Azure Web App
type WebAppInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	State             string
	DefaultHostName   string
	HTTPSOnly         bool
	Kind              string
	OutboundIPAddresses string
	SystemAssignedID  string
	UserAssignedIDs   []string
}

// AppServicePlanInfo represents an App Service Plan
type AppServicePlanInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	SKU           string
	Tier          string
	Capacity      int32
	Kind          string
	NumberOfSites int32
}

// DeploymentSlotInfo represents a deployment slot
type DeploymentSlotInfo struct {
	Name            string
	WebAppName      string
	ResourceGroup   string
	State           string
	DefaultHostName string
}

// getARMCredential returns ARM credential from session
func (s *WebAppService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListWebApps returns all web apps in a subscription (excluding function apps)
func (s *WebAppService) ListWebApps(ctx context.Context, subID string) ([]*armappservice.Site, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	pager := client.NewListPager(nil)
	var webApps []*armappservice.Site

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return webApps, fmt.Errorf("failed to list web apps: %w", err)
		}
		// Filter out function apps
		for _, site := range page.Value {
			if site.Kind != nil && !isFunctionApp(*site.Kind) {
				webApps = append(webApps, site)
			}
		}
	}

	return webApps, nil
}

// ListWebAppsByResourceGroup returns all web apps in a resource group
func (s *WebAppService) ListWebAppsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armappservice.Site, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var webApps []*armappservice.Site

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return webApps, fmt.Errorf("failed to list web apps: %w", err)
		}
		for _, site := range page.Value {
			if site.Kind != nil && !isFunctionApp(*site.Kind) {
				webApps = append(webApps, site)
			}
		}
	}

	return webApps, nil
}

// GetWebApp returns a specific web app
func (s *WebAppService) GetWebApp(ctx context.Context, subID, rgName, appName string) (*armappservice.Site, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, appName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get web app: %w", err)
	}

	return &resp.Site, nil
}

// GetAppSettings returns the application settings for a web app
func (s *WebAppService) GetAppSettings(ctx context.Context, subID, rgName, appName string) (map[string]string, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	resp, err := client.ListApplicationSettings(ctx, rgName, appName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get app settings: %w", err)
	}

	settings := make(map[string]string)
	if resp.Properties != nil {
		for k, v := range resp.Properties {
			if v != nil {
				settings[k] = *v
			}
		}
	}

	return settings, nil
}

// GetConnectionStrings returns the connection strings for a web app
func (s *WebAppService) GetConnectionStrings(ctx context.Context, subID, rgName, appName string) (map[string]string, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	resp, err := client.ListConnectionStrings(ctx, rgName, appName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection strings: %w", err)
	}

	connStrings := make(map[string]string)
	if resp.Properties != nil {
		for k, v := range resp.Properties {
			if v != nil && v.Value != nil {
				connStrings[k] = *v.Value
			}
		}
	}

	return connStrings, nil
}

// ListAppServicePlans returns all App Service Plans in a subscription
func (s *WebAppService) ListAppServicePlans(ctx context.Context, subID string) ([]*armappservice.Plan, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewPlansClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create plans client: %w", err)
	}

	pager := client.NewListPager(nil)
	var plans []*armappservice.Plan

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return plans, fmt.Errorf("failed to list plans: %w", err)
		}
		plans = append(plans, page.Value...)
	}

	return plans, nil
}

// ListDeploymentSlots returns all deployment slots for a web app
func (s *WebAppService) ListDeploymentSlots(ctx context.Context, subID, rgName, appName string) ([]*armappservice.Site, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	pager := client.NewListSlotsPager(rgName, appName, nil)
	var slots []*armappservice.Site

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return slots, fmt.Errorf("failed to list slots: %w", err)
		}
		slots = append(slots, page.Value...)
	}

	return slots, nil
}

// isFunctionApp checks if the kind string indicates a function app
func isFunctionApp(kind string) bool {
	return kind == "functionapp" || kind == "functionapp,linux" ||
		kind == "functionapp,workflowapp" || kind == "functionapp,linux,container"
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

// CachedListWebApps returns all web apps with caching
func (s *WebAppService) CachedListWebApps(ctx context.Context, subID string) ([]*armappservice.Site, error) {
	key := cacheKey("webapps", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappservice.Site), nil
	}
	result, err := s.ListWebApps(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListAppServicePlans returns all App Service Plans with caching
func (s *WebAppService) CachedListAppServicePlans(ctx context.Context, subID string) ([]*armappservice.Plan, error) {
	key := cacheKey("plans", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappservice.Plan), nil
	}
	result, err := s.ListAppServicePlans(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListDeploymentSlots returns all deployment slots for a web app with caching
func (s *WebAppService) CachedListDeploymentSlots(ctx context.Context, subID, rgName, appName string) ([]*armappservice.Site, error) {
	key := cacheKey("slots", subID, rgName, appName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappservice.Site), nil
	}
	result, err := s.ListDeploymentSlots(ctx, subID, rgName, appName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
