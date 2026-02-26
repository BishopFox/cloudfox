// Package containerservice provides Azure Container Apps/Instances service abstractions
//
// This service layer abstracts Azure Container API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package containerservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for container service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "containerservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// ContainerService provides methods for interacting with Azure Container Apps and Instances
type ContainerService struct {
	session *azinternal.SafeSession
}

// New creates a new ContainerService instance
func New(session *azinternal.SafeSession) *ContainerService {
	return &ContainerService{
		session: session,
	}
}

// NewWithSession creates a new ContainerService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *ContainerService {
	return New(session)
}

// ContainerAppInfo represents an Azure Container App
type ContainerAppInfo struct {
	Name               string
	ResourceGroup      string
	Location           string
	EnvironmentName    string
	ProvisioningState  string
	LatestRevisionName string
	LatestRevisionFQDN string
	IngressEnabled     bool
	IngressFQDN        string
	SystemAssignedID   string
	UserAssignedIDs    []string
}

// ContainerAppEnvironmentInfo represents a Container Apps Environment
type ContainerAppEnvironmentInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	ProvisioningState string
	DefaultDomain     string
	StaticIP          string
	VNetSubnetID      string
}

// ContainerGroupInfo represents an Azure Container Instance group
type ContainerGroupInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	OSType            string
	ProvisioningState string
	IPAddress         string
	FQDN              string
	RestartPolicy     string
	Containers        []ContainerInfo
}

// ContainerInfo represents a container within a group
type ContainerInfo struct {
	Name         string
	Image        string
	CPUCores     float64
	MemoryGB     float64
	Ports        []int32
	EnvironmentVars map[string]string
}

// getARMCredential returns ARM credential from session
func (s *ContainerService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListContainerApps returns all Container Apps in a subscription
func (s *ContainerService) ListContainerApps(ctx context.Context, subID string) ([]*armappcontainers.ContainerApp, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappcontainers.NewContainerAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container apps client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var apps []*armappcontainers.ContainerApp

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return apps, fmt.Errorf("failed to list container apps: %w", err)
		}
		apps = append(apps, page.Value...)
	}

	return apps, nil
}

// ListContainerAppsByResourceGroup returns all Container Apps in a resource group
func (s *ContainerService) ListContainerAppsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armappcontainers.ContainerApp, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappcontainers.NewContainerAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container apps client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var apps []*armappcontainers.ContainerApp

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return apps, fmt.Errorf("failed to list container apps: %w", err)
		}
		apps = append(apps, page.Value...)
	}

	return apps, nil
}

// ListContainerAppEnvironments returns all Container App Environments in a subscription
func (s *ContainerService) ListContainerAppEnvironments(ctx context.Context, subID string) ([]*armappcontainers.ManagedEnvironment, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappcontainers.NewManagedEnvironmentsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create environments client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var envs []*armappcontainers.ManagedEnvironment

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return envs, fmt.Errorf("failed to list environments: %w", err)
		}
		envs = append(envs, page.Value...)
	}

	return envs, nil
}

// GetContainerAppSecrets returns the secrets for a Container App
func (s *ContainerService) GetContainerAppSecrets(ctx context.Context, subID, rgName, appName string) ([]*armappcontainers.ContainerAppSecret, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armappcontainers.NewContainerAppsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container apps client: %w", err)
	}

	resp, err := client.ListSecrets(ctx, rgName, appName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	return resp.Value, nil
}

// ListContainerGroups returns all Container Instance groups in a subscription
func (s *ContainerService) ListContainerGroups(ctx context.Context, subID string) ([]*armcontainerinstance.ContainerGroup, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerinstance.NewContainerGroupsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container groups client: %w", err)
	}

	pager := client.NewListPager(nil)
	var groups []*armcontainerinstance.ContainerGroup

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return groups, fmt.Errorf("failed to list container groups: %w", err)
		}
		groups = append(groups, page.Value...)
	}

	return groups, nil
}

// ListContainerGroupsByResourceGroup returns all Container Instance groups in a resource group
func (s *ContainerService) ListContainerGroupsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcontainerinstance.ContainerGroup, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerinstance.NewContainerGroupsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container groups client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var groups []*armcontainerinstance.ContainerGroup

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return groups, fmt.Errorf("failed to list container groups: %w", err)
		}
		groups = append(groups, page.Value...)
	}

	return groups, nil
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

// CachedListContainerApps returns all Container Apps with caching
func (s *ContainerService) CachedListContainerApps(ctx context.Context, subID string) ([]*armappcontainers.ContainerApp, error) {
	key := cacheKey("containerapps", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappcontainers.ContainerApp), nil
	}
	result, err := s.ListContainerApps(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListContainerAppEnvironments returns all Container App Environments with caching
func (s *ContainerService) CachedListContainerAppEnvironments(ctx context.Context, subID string) ([]*armappcontainers.ManagedEnvironment, error) {
	key := cacheKey("environments", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armappcontainers.ManagedEnvironment), nil
	}
	result, err := s.ListContainerAppEnvironments(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListContainerGroups returns all Container Instance groups with caching
func (s *ContainerService) CachedListContainerGroups(ctx context.Context, subID string) ([]*armcontainerinstance.ContainerGroup, error) {
	key := cacheKey("containergroups", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcontainerinstance.ContainerGroup), nil
	}
	result, err := s.ListContainerGroups(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
