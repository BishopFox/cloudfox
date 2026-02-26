// Package mlservice provides Azure Machine Learning service abstractions
//
// This service layer abstracts Azure ML API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package mlservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning/v3"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for ML service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "mlservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// MLService provides methods for interacting with Azure Machine Learning
type MLService struct {
	session *azinternal.SafeSession
}

// New creates a new MLService instance
func New(session *azinternal.SafeSession) *MLService {
	return &MLService{
		session: session,
	}
}

// NewWithSession creates a new MLService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *MLService {
	return New(session)
}

// WorkspaceInfo represents an Azure ML workspace
type WorkspaceInfo struct {
	Name                  string
	ResourceGroup         string
	Location              string
	Description           string
	StorageAccount        string
	KeyVault              string
	ApplicationInsights   string
	ContainerRegistry     string
	PublicNetworkAccess   string
	SystemAssignedID      string
	UserAssignedIDs       []string
}

// ComputeInfo represents an ML compute resource
type ComputeInfo struct {
	Name          string
	WorkspaceName string
	ComputeType   string
	Location      string
	State         string
	VMSize        string
	NodeCount     int32
}

// DatastoreInfo represents an ML datastore
type DatastoreInfo struct {
	Name          string
	WorkspaceName string
	DatastoreType string
	AccountName   string
	ContainerName string
	IsDefault     bool
}

// EnvironmentInfo represents an ML environment
type EnvironmentInfo struct {
	Name          string
	WorkspaceName string
	Version       string
	Description   string
	Image         string
}

// getARMCredential returns ARM credential from session
func (s *MLService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListWorkspaces returns all ML workspaces in a subscription
func (s *MLService) ListWorkspaces(ctx context.Context, subID string) ([]*armmachinelearning.Workspace, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmachinelearning.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ML workspaces client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var workspaces []*armmachinelearning.Workspace

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return workspaces, fmt.Errorf("failed to list ML workspaces: %w", err)
		}
		workspaces = append(workspaces, page.Value...)
	}

	return workspaces, nil
}

// ListWorkspacesByResourceGroup returns all ML workspaces in a resource group
func (s *MLService) ListWorkspacesByResourceGroup(ctx context.Context, subID, rgName string) ([]*armmachinelearning.Workspace, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmachinelearning.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ML workspaces client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var workspaces []*armmachinelearning.Workspace

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return workspaces, fmt.Errorf("failed to list ML workspaces: %w", err)
		}
		workspaces = append(workspaces, page.Value...)
	}

	return workspaces, nil
}

// GetWorkspace returns a specific ML workspace
func (s *MLService) GetWorkspace(ctx context.Context, subID, rgName, workspaceName string) (*armmachinelearning.Workspace, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmachinelearning.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ML workspaces client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, workspaceName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get ML workspace: %w", err)
	}

	return &resp.Workspace, nil
}

// ListComputes returns all compute resources in a workspace
func (s *MLService) ListComputes(ctx context.Context, subID, rgName, workspaceName string) ([]*armmachinelearning.ComputeResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmachinelearning.NewComputeClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute client: %w", err)
	}

	pager := client.NewListPager(rgName, workspaceName, nil)
	var computes []*armmachinelearning.ComputeResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return computes, fmt.Errorf("failed to list computes: %w", err)
		}
		computes = append(computes, page.Value...)
	}

	return computes, nil
}

// ListDatastores returns all datastores in a workspace
func (s *MLService) ListDatastores(ctx context.Context, subID, rgName, workspaceName string) ([]*armmachinelearning.Datastore, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmachinelearning.NewDatastoresClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create datastores client: %w", err)
	}

	pager := client.NewListPager(rgName, workspaceName, nil)
	var datastores []*armmachinelearning.Datastore

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return datastores, fmt.Errorf("failed to list datastores: %w", err)
		}
		datastores = append(datastores, page.Value...)
	}

	return datastores, nil
}

// ListEnvironments returns all environments in a workspace
func (s *MLService) ListEnvironments(ctx context.Context, subID, rgName, workspaceName string) ([]*armmachinelearning.EnvironmentContainer, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmachinelearning.NewEnvironmentContainersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create environments client: %w", err)
	}

	pager := client.NewListPager(rgName, workspaceName, nil)
	var envs []*armmachinelearning.EnvironmentContainer

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return envs, fmt.Errorf("failed to list environments: %w", err)
		}
		envs = append(envs, page.Value...)
	}

	return envs, nil
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

// CachedListWorkspaces returns all ML workspaces with caching
func (s *MLService) CachedListWorkspaces(ctx context.Context, subID string) ([]*armmachinelearning.Workspace, error) {
	key := cacheKey("workspaces", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armmachinelearning.Workspace), nil
	}
	result, err := s.ListWorkspaces(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListComputes returns all compute resources in a workspace with caching
func (s *MLService) CachedListComputes(ctx context.Context, subID, rgName, workspaceName string) ([]*armmachinelearning.ComputeResource, error) {
	key := cacheKey("computes", subID, rgName, workspaceName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armmachinelearning.ComputeResource), nil
	}
	result, err := s.ListComputes(ctx, subID, rgName, workspaceName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListDatastores returns all datastores in a workspace with caching
func (s *MLService) CachedListDatastores(ctx context.Context, subID, rgName, workspaceName string) ([]*armmachinelearning.Datastore, error) {
	key := cacheKey("datastores", subID, rgName, workspaceName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armmachinelearning.Datastore), nil
	}
	result, err := s.ListDatastores(ctx, subID, rgName, workspaceName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
