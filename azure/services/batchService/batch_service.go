// Package batchservice provides Azure Batch service abstractions
//
// This service layer abstracts Azure Batch API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package batchservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for Batch service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "batchservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// BatchService provides methods for interacting with Azure Batch
type BatchService struct {
	session *azinternal.SafeSession
}

// New creates a new BatchService instance
func New(session *azinternal.SafeSession) *BatchService {
	return &BatchService{
		session: session,
	}
}

// NewWithSession creates a new BatchService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *BatchService {
	return New(session)
}

// AccountInfo represents an Azure Batch account
type AccountInfo struct {
	Name                  string
	ResourceGroup         string
	Location              string
	AccountEndpoint       string
	PoolAllocationMode    string
	PublicNetworkAccess   string
	AutoStorageAccountID  string
	DedicatedCoreQuota    int32
	LowPriorityCoreQuota  int32
	PoolQuota             int32
}

// PoolInfo represents a Batch pool
type PoolInfo struct {
	Name                string
	AccountName         string
	VMSize              string
	CurrentDedicatedNodes int32
	CurrentLowPriorityNodes int32
	TargetDedicatedNodes int32
	State               string
	AllocationState     string
}

// ApplicationInfo represents a Batch application
type ApplicationInfo struct {
	Name        string
	AccountName string
	DisplayName string
	Versions    []string
}

// getARMCredential returns ARM credential from session
func (s *BatchService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListAccounts returns all Batch accounts in a subscription
func (s *BatchService) ListAccounts(ctx context.Context, subID string) ([]*armbatch.Account, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armbatch.NewAccountClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create batch account client: %w", err)
	}

	pager := client.NewListPager(nil)
	var accounts []*armbatch.Account

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list batch accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// ListAccountsByResourceGroup returns all Batch accounts in a resource group
func (s *BatchService) ListAccountsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armbatch.Account, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armbatch.NewAccountClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create batch account client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var accounts []*armbatch.Account

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list batch accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// GetAccountKeys returns the keys for a Batch account
func (s *BatchService) GetAccountKeys(ctx context.Context, subID, rgName, accountName string) (*armbatch.AccountKeys, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armbatch.NewAccountClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create batch account client: %w", err)
	}

	resp, err := client.GetKeys(ctx, rgName, accountName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get batch account keys: %w", err)
	}

	return &resp.AccountKeys, nil
}

// ListPools returns all pools in a Batch account
func (s *BatchService) ListPools(ctx context.Context, subID, rgName, accountName string) ([]*armbatch.Pool, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armbatch.NewPoolClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool client: %w", err)
	}

	pager := client.NewListByBatchAccountPager(rgName, accountName, nil)
	var pools []*armbatch.Pool

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return pools, fmt.Errorf("failed to list pools: %w", err)
		}
		pools = append(pools, page.Value...)
	}

	return pools, nil
}

// ListApplications returns all applications in a Batch account
func (s *BatchService) ListApplications(ctx context.Context, subID, rgName, accountName string) ([]*armbatch.Application, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armbatch.NewApplicationClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create application client: %w", err)
	}

	pager := client.NewListPager(rgName, accountName, nil)
	var apps []*armbatch.Application

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return apps, fmt.Errorf("failed to list applications: %w", err)
		}
		apps = append(apps, page.Value...)
	}

	return apps, nil
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

// CachedListAccounts returns all Batch accounts with caching
func (s *BatchService) CachedListAccounts(ctx context.Context, subID string) ([]*armbatch.Account, error) {
	key := cacheKey("accounts", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armbatch.Account), nil
	}
	result, err := s.ListAccounts(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPools returns all pools in a Batch account with caching
func (s *BatchService) CachedListPools(ctx context.Context, subID, rgName, accountName string) ([]*armbatch.Pool, error) {
	key := cacheKey("pools", subID, rgName, accountName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armbatch.Pool), nil
	}
	result, err := s.ListPools(ctx, subID, rgName, accountName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListApplications returns all applications in a Batch account with caching
func (s *BatchService) CachedListApplications(ctx context.Context, subID, rgName, accountName string) ([]*armbatch.Application, error) {
	key := cacheKey("applications", subID, rgName, accountName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armbatch.Application), nil
	}
	result, err := s.ListApplications(ctx, subID, rgName, accountName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
