// Package acrservice provides Azure Container Registry service abstractions
//
// This service layer abstracts Azure ACR API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package acrservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for ACR service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "acrservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// ACRService provides methods for interacting with Azure Container Registry
type ACRService struct {
	session *azinternal.SafeSession
}

// New creates a new ACRService instance
func New(session *azinternal.SafeSession) *ACRService {
	return &ACRService{
		session: session,
	}
}

// NewWithSession creates a new ACRService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *ACRService {
	return New(session)
}

// RegistryInfo represents an Azure Container Registry with security-relevant fields
type RegistryInfo struct {
	Name             string
	ResourceGroup    string
	Location         string
	LoginServer      string
	AdminEnabled     bool
	AdminUsername    string
	SKU              string
	SystemAssignedID string
	UserAssignedIDs  []string
}

// RepositoryInfo represents a repository within an ACR
type RepositoryInfo struct {
	RegistryName string
	Name         string
}

// TagInfo represents a tag within a repository
type TagInfo struct {
	RegistryName   string
	RepositoryName string
	Name           string
	Digest         string
}

// getARMCredential returns ARM credential from session
func (s *ACRService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// getACRCredential returns ACR-specific credential from session
func (s *ACRService) getACRCredential(loginServer string) (*azinternal.StaticTokenCredential, error) {
	// ACR uses a different scope for data plane operations
	acrScope := fmt.Sprintf("https://%s", loginServer)
	token, err := s.session.GetTokenForResource(acrScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACR token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListRegistriesByResourceGroup returns all container registries in a resource group
func (s *ACRService) ListRegistriesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcontainerregistry.Registry, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewRegistriesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create registries client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var registries []*armcontainerregistry.Registry

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return registries, fmt.Errorf("failed to list registries: %w", err)
		}
		registries = append(registries, page.Value...)
	}

	return registries, nil
}

// ListRegistries returns all container registries in a subscription
func (s *ACRService) ListRegistries(ctx context.Context, subID string) ([]*armcontainerregistry.Registry, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewRegistriesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create registries client: %w", err)
	}

	pager := client.NewListPager(nil)
	var registries []*armcontainerregistry.Registry

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return registries, fmt.Errorf("failed to list registries: %w", err)
		}
		registries = append(registries, page.Value...)
	}

	return registries, nil
}

// GetRegistryCredentials returns admin credentials for a registry (if admin is enabled)
func (s *ACRService) GetRegistryCredentials(ctx context.Context, subID, rgName, registryName string) (*armcontainerregistry.RegistryListCredentialsResult, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerregistry.NewRegistriesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create registries client: %w", err)
	}

	resp, err := client.ListCredentials(ctx, rgName, registryName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get registry credentials: %w", err)
	}

	return &resp.RegistryListCredentialsResult, nil
}

// ListRepositories returns all repositories in a container registry
func (s *ACRService) ListRepositories(ctx context.Context, loginServer string) ([]string, error) {
	cred, err := s.getACRCredential(loginServer)
	if err != nil {
		return nil, err
	}

	client, err := azcontainerregistry.NewClient(fmt.Sprintf("https://%s", loginServer), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACR client: %w", err)
	}

	pager := client.NewListRepositoriesPager(nil)
	var repos []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return repos, fmt.Errorf("failed to list repositories: %w", err)
		}
		if page.Repositories.Names != nil {
			for _, name := range page.Repositories.Names {
				if name != nil {
					repos = append(repos, *name)
				}
			}
		}
	}

	return repos, nil
}

// ListTags returns all tags for a repository in a container registry
func (s *ACRService) ListTags(ctx context.Context, loginServer, repoName string) ([]string, error) {
	cred, err := s.getACRCredential(loginServer)
	if err != nil {
		return nil, err
	}

	client, err := azcontainerregistry.NewClient(fmt.Sprintf("https://%s", loginServer), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACR client: %w", err)
	}

	pager := client.NewListTagsPager(repoName, nil)
	var tags []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return tags, fmt.Errorf("failed to list tags: %w", err)
		}
		if page.Tags != nil {
			for _, tag := range page.Tags {
				if tag.Name != nil {
					tags = append(tags, *tag.Name)
				}
			}
		}
	}

	return tags, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ============================================================================
// CACHED METHODS - Use these in command modules for better performance
// ============================================================================

// CachedListRegistriesByResourceGroup returns cached registries for a resource group
func (s *ACRService) CachedListRegistriesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcontainerregistry.Registry, error) {
	key := cacheKey("registries-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcontainerregistry.Registry), nil
	}

	result, err := s.ListRegistriesByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListRegistries returns cached registries for a subscription
func (s *ACRService) CachedListRegistries(ctx context.Context, subID string) ([]*armcontainerregistry.Registry, error) {
	key := cacheKey("registries", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcontainerregistry.Registry), nil
	}

	result, err := s.ListRegistries(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListRepositories returns cached repositories for a registry
func (s *ACRService) CachedListRepositories(ctx context.Context, loginServer string) ([]string, error) {
	key := cacheKey("repositories", loginServer)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]string), nil
	}

	result, err := s.ListRepositories(ctx, loginServer)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListTags returns cached tags for a repository
func (s *ACRService) CachedListTags(ctx context.Context, loginServer, repoName string) ([]string, error) {
	key := cacheKey("tags", loginServer, repoName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]string), nil
	}

	result, err := s.ListTags(ctx, loginServer, repoName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
