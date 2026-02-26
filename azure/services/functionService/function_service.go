// Package functionservice provides Azure Functions service abstractions
//
// This service layer abstracts Azure Functions API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package functionservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for function service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "functionservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// FunctionService provides methods for interacting with Azure Functions
type FunctionService struct {
	session *azinternal.SafeSession
}

// New creates a new FunctionService instance
func New(session *azinternal.SafeSession) *FunctionService {
	return &FunctionService{
		session: session,
	}
}

// NewWithSession creates a new FunctionService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *FunctionService {
	return New(session)
}

// FunctionAppInfo represents an Azure Function App
type FunctionAppInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	State             string
	DefaultHostName   string
	HTTPSOnly         bool
	Kind              string
	RuntimeStack      string
	FunctionsVersion  string
	SystemAssignedID  string
	UserAssignedIDs   []string
}

// FunctionInfo represents a single function within a Function App
type FunctionInfo struct {
	Name           string
	FunctionAppName string
	Trigger        string
	IsDisabled     bool
	Language       string
}

// AppSettingInfo represents an application setting
type AppSettingInfo struct {
	Name  string
	Value string
}

// getARMCredential returns ARM credential from session
func (s *FunctionService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListFunctionApps returns all function apps in a subscription
func (s *FunctionService) ListFunctionApps(ctx context.Context, subID string) ([]*armappservice.Site, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	pager := client.NewListPager(nil)
	var functionApps []*armappservice.Site

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return functionApps, fmt.Errorf("failed to list web apps: %w", err)
		}
		// Filter to only function apps
		for _, site := range page.Value {
			if site.Kind != nil && containsFunctionApp(*site.Kind) {
				functionApps = append(functionApps, site)
			}
		}
	}

	return functionApps, nil
}

// ListFunctionAppsByResourceGroup returns all function apps in a resource group
func (s *FunctionService) ListFunctionAppsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armappservice.Site, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var functionApps []*armappservice.Site

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return functionApps, fmt.Errorf("failed to list web apps: %w", err)
		}
		// Filter to only function apps
		for _, site := range page.Value {
			if site.Kind != nil && containsFunctionApp(*site.Kind) {
				functionApps = append(functionApps, site)
			}
		}
	}

	return functionApps, nil
}

// GetFunctionApp returns a specific function app
func (s *FunctionService) GetFunctionApp(ctx context.Context, subID, rgName, appName string) (*armappservice.Site, error) {
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
		return nil, fmt.Errorf("failed to get function app: %w", err)
	}

	return &resp.Site, nil
}

// ListFunctions returns all functions in a function app
func (s *FunctionService) ListFunctions(ctx context.Context, subID, rgName, appName string) ([]*armappservice.FunctionEnvelope, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create web apps client: %w", err)
	}

	pager := client.NewListFunctionsPager(rgName, appName, nil)
	var functions []*armappservice.FunctionEnvelope

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return functions, fmt.Errorf("failed to list functions: %w", err)
		}
		functions = append(functions, page.Value...)
	}

	return functions, nil
}

// GetAppSettings returns the application settings for a function app
func (s *FunctionService) GetAppSettings(ctx context.Context, subID, rgName, appName string) (map[string]string, error) {
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

// GetConnectionStrings returns the connection strings for a function app
func (s *FunctionService) GetConnectionStrings(ctx context.Context, subID, rgName, appName string) (map[string]string, error) {
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

// containsFunctionApp checks if the kind string indicates a function app
func containsFunctionApp(kind string) bool {
	return kind == "functionapp" || kind == "functionapp,linux" ||
		kind == "functionapp,workflowapp" || kind == "functionapp,linux,container"
}

// =============================================================================
// Cached Methods
// =============================================================================

// CachedListFunctionApps returns all function apps with caching
func (s *FunctionService) CachedListFunctionApps(ctx context.Context, subID string) ([]*armappservice.Site, error) {
	key := cacheKey("functionapps", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappservice.Site), nil
	}
	result, err := s.ListFunctionApps(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListFunctionAppsByResourceGroup returns function apps in a resource group with caching
func (s *FunctionService) CachedListFunctionAppsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armappservice.Site, error) {
	key := cacheKey("functionapps", subID, rgName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappservice.Site), nil
	}
	result, err := s.ListFunctionAppsByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListFunctions returns all functions in a function app with caching
func (s *FunctionService) CachedListFunctions(ctx context.Context, subID, rgName, appName string) ([]*armappservice.FunctionEnvelope, error) {
	key := cacheKey("functions", subID, rgName, appName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappservice.FunctionEnvelope), nil
	}
	result, err := s.ListFunctions(ctx, subID, rgName, appName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
