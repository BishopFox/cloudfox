// Package aksservice provides Azure Kubernetes Service abstractions
//
// This service layer abstracts Azure AKS API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package aksservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for AKS service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "aksservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// AKSService provides methods for interacting with Azure Kubernetes Service
type AKSService struct {
	session *azinternal.SafeSession
}

// New creates a new AKSService instance
func New(session *azinternal.SafeSession) *AKSService {
	return &AKSService{
		session: session,
	}
}

// NewWithSession creates a new AKSService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *AKSService {
	return New(session)
}

// ClusterInfo represents an AKS cluster with security-relevant fields
type ClusterInfo struct {
	Name             string
	ResourceGroup    string
	Location         string
	K8sVersion       string
	DNSPrefix        string
	FQDN             string
	PrivateFQDN      string
	IsPrivate        bool
	EnableRBAC       bool
	AzureADEnabled   bool
	SystemAssignedID string
	UserAssignedIDs  []string
	NodeResourceGroup string
}

// NodePoolInfo represents an AKS node pool
type NodePoolInfo struct {
	ClusterName   string
	Name          string
	VMSize        string
	Count         int32
	MinCount      int32
	MaxCount      int32
	OSDiskSizeGB  int32
	EnableAutoScale bool
	Mode          string
}

// getARMCredential returns ARM credential from session
func (s *AKSService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListClustersByResourceGroup returns all AKS clusters in a resource group
func (s *AKSService) ListClustersByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcontainerservice.ManagedCluster, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create managed clusters client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var clusters []*armcontainerservice.ManagedCluster

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return clusters, fmt.Errorf("failed to list clusters: %w", err)
		}
		clusters = append(clusters, page.Value...)
	}

	return clusters, nil
}

// ListClusters returns all AKS clusters in a subscription
func (s *AKSService) ListClusters(ctx context.Context, subID string) ([]*armcontainerservice.ManagedCluster, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create managed clusters client: %w", err)
	}

	pager := client.NewListPager(nil)
	var clusters []*armcontainerservice.ManagedCluster

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return clusters, fmt.Errorf("failed to list clusters: %w", err)
		}
		clusters = append(clusters, page.Value...)
	}

	return clusters, nil
}

// GetCluster returns a specific AKS cluster
func (s *AKSService) GetCluster(ctx context.Context, subID, rgName, clusterName string) (*armcontainerservice.ManagedCluster, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create managed clusters client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, clusterName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster: %w", err)
	}

	return &resp.ManagedCluster, nil
}

// GetClusterCredentials returns admin or user credentials for an AKS cluster
func (s *AKSService) GetClusterCredentials(ctx context.Context, subID, rgName, clusterName string, admin bool) (*armcontainerservice.CredentialResults, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create managed clusters client: %w", err)
	}

	var resp armcontainerservice.ManagedClustersClientListClusterAdminCredentialsResponse
	if admin {
		resp, err = client.ListClusterAdminCredentials(ctx, rgName, clusterName, nil)
	} else {
		userResp, userErr := client.ListClusterUserCredentials(ctx, rgName, clusterName, nil)
		if userErr != nil {
			return nil, fmt.Errorf("failed to get cluster credentials: %w", userErr)
		}
		return &userResp.CredentialResults, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get cluster credentials: %w", err)
	}

	return &resp.CredentialResults, nil
}

// ListAgentPools returns all agent pools for an AKS cluster
func (s *AKSService) ListAgentPools(ctx context.Context, subID, rgName, clusterName string) ([]*armcontainerservice.AgentPool, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armcontainerservice.NewAgentPoolsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent pools client: %w", err)
	}

	pager := client.NewListPager(rgName, clusterName, nil)
	var pools []*armcontainerservice.AgentPool

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return pools, fmt.Errorf("failed to list agent pools: %w", err)
		}
		pools = append(pools, page.Value...)
	}

	return pools, nil
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

// CachedListClustersByResourceGroup returns cached AKS clusters for a resource group
func (s *AKSService) CachedListClustersByResourceGroup(ctx context.Context, subID, rgName string) ([]*armcontainerservice.ManagedCluster, error) {
	key := cacheKey("clusters-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcontainerservice.ManagedCluster), nil
	}

	result, err := s.ListClustersByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListClusters returns cached AKS clusters for a subscription
func (s *AKSService) CachedListClusters(ctx context.Context, subID string) ([]*armcontainerservice.ManagedCluster, error) {
	key := cacheKey("clusters", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcontainerservice.ManagedCluster), nil
	}

	result, err := s.ListClusters(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListAgentPools returns cached agent pools for a cluster
func (s *AKSService) CachedListAgentPools(ctx context.Context, subID, rgName, clusterName string) ([]*armcontainerservice.AgentPool, error) {
	key := cacheKey("agentpools", subID, rgName, clusterName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armcontainerservice.AgentPool), nil
	}

	result, err := s.ListAgentPools(ctx, subID, rgName, clusterName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
