// Package storageservice provides Azure Storage service abstractions
//
// This service layer abstracts Azure Storage API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package storageservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for storage service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "storageservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// StorageService provides methods for interacting with Azure Storage
type StorageService struct {
	session *azinternal.SafeSession
}

// New creates a new StorageService instance
func New(session *azinternal.SafeSession) *StorageService {
	return &StorageService{
		session: session,
	}
}

// NewWithSession creates a new StorageService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *StorageService {
	return New(session)
}

// StorageAccountKey represents a storage account access key
type StorageAccountKey struct {
	KeyName    string
	Value      string
	Permission string
}

// ContainerInfo represents an Azure Blob container with security-relevant fields
type ContainerInfo struct {
	Name                        string
	URL                         string
	Public                      string
	Location                    string
	Kind                        string
	LastModified                string
	LeaseState                  string
	LeaseStatus                 string
	HasImmutabilityPolicy       string
	HasLegalHold                string
	DefaultEncryptionScope      string
	DenyEncryptionScopeOverride string
	PublicAccessWarning         string
}

// FileShareInfo represents an Azure File Share
type FileShareInfo struct {
	AccountName   string
	ResourceGroup string
	ShareName     string
	Quota         int32 // Quota in GB
	UsageBytes    int64
	AccessTier    string
}

// TableInfo represents an Azure Storage Table
type TableInfo struct {
	AccountName   string
	ResourceGroup string
	TableName     string
}

// PublicBlobInfo represents a publicly accessible blob file
type PublicBlobInfo struct {
	AccountName   string
	ContainerName string
	BlobName      string
	BlobURL       string
	SizeBytes     int64
}

// SASInfo represents a Storage SAS token / stored access policy
type SASInfo struct {
	AccountName   string
	ResourceGroup string
	ContainerName string
	PolicyName    string
	Identifier    string
	Permissions   string
}

// getARMCredential returns ARM credential from session
func (s *StorageService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListStorageAccountsByResourceGroup returns all storage accounts in a resource group
func (s *StorageService) ListStorageAccountsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armstorage.Account, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	clientFactory, err := armstorage.NewClientFactory(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client factory: %w", err)
	}

	accountsClient := clientFactory.NewAccountsClient()
	pager := accountsClient.NewListByResourceGroupPager(rgName, nil)
	var accounts []*armstorage.Account

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list storage accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// ListStorageAccounts returns all storage accounts in a subscription
func (s *StorageService) ListStorageAccounts(ctx context.Context, subID string) ([]*armstorage.Account, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	clientFactory, err := armstorage.NewClientFactory(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client factory: %w", err)
	}

	accountsClient := clientFactory.NewAccountsClient()
	pager := accountsClient.NewListPager(nil)
	var accounts []*armstorage.Account

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list storage accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// GetStorageAccountKeys returns the access keys for a storage account
func (s *StorageService) GetStorageAccountKeys(ctx context.Context, subID, accountName, resourceGroup string) ([]StorageAccountKey, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	clientFactory, err := armstorage.NewClientFactory(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client factory: %w", err)
	}

	keysClient := clientFactory.NewAccountsClient()
	resp, err := keysClient.ListKeys(ctx, resourceGroup, accountName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list storage account keys: %w", err)
	}

	if resp.Keys == nil {
		return nil, nil
	}

	var keys []StorageAccountKey
	for _, k := range resp.Keys {
		if k.KeyName != nil && k.Value != nil && k.Permissions != nil {
			keys = append(keys, StorageAccountKey{
				KeyName:    *k.KeyName,
				Value:      *k.Value,
				Permission: string(*k.Permissions),
			})
		}
	}

	return keys, nil
}

// ListContainers returns all blob containers for a storage account
func (s *StorageService) ListContainers(ctx context.Context, subID, accountName, resourceGroup, location, kind string) ([]ContainerInfo, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	storageClient, err := armstorage.NewBlobContainersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create BlobContainers client: %w", err)
	}

	pager := storageClient.NewListPager(resourceGroup, accountName, nil)
	var containers []ContainerInfo

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return containers, fmt.Errorf("failed to list containers: %w", err)
		}

		for _, c := range page.Value {
			cName := safeString(c.Name)
			cPublic := "Private Only"
			publicAccessWarning := "✓ Secure (Private)"

			if c.Properties != nil && c.Properties.PublicAccess != nil {
				switch *c.Properties.PublicAccess {
				case armstorage.PublicAccessBlob:
					cPublic = "⚠ Blobs Public"
					publicAccessWarning = "⚠ WARNING: Blobs are publicly accessible"
				case armstorage.PublicAccessContainer:
					cPublic = "⚠ Container And Blobs Public"
					publicAccessWarning = "⚠ CRITICAL: Container listing + blobs publicly accessible"
				case armstorage.PublicAccessNone:
					cPublic = "Private Only"
					publicAccessWarning = "✓ Secure (Private)"
				default:
					cPublic = string(*c.Properties.PublicAccess)
				}
			}

			// Last Modified
			lastModified := "N/A"
			if c.Properties != nil && c.Properties.LastModifiedTime != nil {
				lastModified = c.Properties.LastModifiedTime.Format("2006-01-02 15:04:05")
			}

			// Lease State and Status
			leaseState := "N/A"
			leaseStatus := "N/A"
			if c.Properties != nil {
				if c.Properties.LeaseState != nil {
					leaseState = string(*c.Properties.LeaseState)
				}
				if c.Properties.LeaseStatus != nil {
					leaseStatus = string(*c.Properties.LeaseStatus)
				}
			}

			// Immutability Policy
			hasImmutabilityPolicy := "No"
			if c.Properties != nil && c.Properties.HasImmutabilityPolicy != nil && *c.Properties.HasImmutabilityPolicy {
				hasImmutabilityPolicy = "✓ Yes"
			}

			// Legal Hold
			hasLegalHold := "No"
			if c.Properties != nil && c.Properties.HasLegalHold != nil && *c.Properties.HasLegalHold {
				hasLegalHold = "✓ Yes"
			}

			// Default Encryption Scope
			defaultEncryptionScope := "N/A"
			if c.Properties != nil && c.Properties.DefaultEncryptionScope != nil {
				defaultEncryptionScope = *c.Properties.DefaultEncryptionScope
			}

			// Deny Encryption Scope Override
			denyEncryptionScopeOverride := "No"
			if c.Properties != nil && c.Properties.DenyEncryptionScopeOverride != nil && *c.Properties.DenyEncryptionScopeOverride {
				denyEncryptionScopeOverride = "Yes"
			}

			containers = append(containers, ContainerInfo{
				Name:                        cName,
				URL:                         fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", accountName, cName),
				Public:                      cPublic,
				Location:                    location,
				Kind:                        kind,
				LastModified:                lastModified,
				LeaseState:                  leaseState,
				LeaseStatus:                 leaseStatus,
				HasImmutabilityPolicy:       hasImmutabilityPolicy,
				HasLegalHold:                hasLegalHold,
				DefaultEncryptionScope:      defaultEncryptionScope,
				DenyEncryptionScopeOverride: denyEncryptionScopeOverride,
				PublicAccessWarning:         publicAccessWarning,
			})
		}
	}

	return containers, nil
}

// ListFileShares returns all file shares for a storage account
func (s *StorageService) ListFileShares(ctx context.Context, subID, accountName, resourceGroup string) ([]FileShareInfo, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	storageClient, err := armstorage.NewFileSharesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create FileShares client: %w", err)
	}

	pager := storageClient.NewListPager(resourceGroup, accountName, nil)
	var shares []FileShareInfo

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return shares, fmt.Errorf("failed to list file shares: %w", err)
		}

		for _, share := range page.Value {
			if share.Name == nil {
				continue
			}

			info := FileShareInfo{
				AccountName:   accountName,
				ResourceGroup: resourceGroup,
				ShareName:     safeString(share.Name),
			}

			if share.Properties != nil {
				if share.Properties.ShareQuota != nil {
					info.Quota = *share.Properties.ShareQuota
				}
				if share.Properties.ShareUsageBytes != nil {
					info.UsageBytes = *share.Properties.ShareUsageBytes
				}
				if share.Properties.AccessTier != nil {
					info.AccessTier = string(*share.Properties.AccessTier)
				}
			}

			shares = append(shares, info)
		}
	}

	return shares, nil
}

// ListTables returns all tables for a storage account
func (s *StorageService) ListTables(ctx context.Context, subID, accountName, resourceGroup string) ([]TableInfo, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	storageClient, err := armstorage.NewTableClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Table client: %w", err)
	}

	pager := storageClient.NewListPager(resourceGroup, accountName, nil)
	var tables []TableInfo

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return tables, fmt.Errorf("failed to list tables: %w", err)
		}

		for _, table := range page.Value {
			if table.Name == nil {
				continue
			}

			tables = append(tables, TableInfo{
				AccountName:   accountName,
				ResourceGroup: resourceGroup,
				TableName:     safeString(table.Name),
			})
		}
	}

	return tables, nil
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

// CachedListStorageAccountsByResourceGroup returns cached storage accounts for a resource group
func (s *StorageService) CachedListStorageAccountsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armstorage.Account, error) {
	key := cacheKey("accounts-by-rg", subID, rgName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armstorage.Account), nil
	}

	result, err := s.ListStorageAccountsByResourceGroup(ctx, subID, rgName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListStorageAccounts returns cached storage accounts for a subscription
func (s *StorageService) CachedListStorageAccounts(ctx context.Context, subID string) ([]*armstorage.Account, error) {
	key := cacheKey("accounts", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armstorage.Account), nil
	}

	result, err := s.ListStorageAccounts(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListContainers returns cached containers for a storage account
func (s *StorageService) CachedListContainers(ctx context.Context, subID, accountName, resourceGroup, location, kind string) ([]ContainerInfo, error) {
	key := cacheKey("containers", subID, accountName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]ContainerInfo), nil
	}

	result, err := s.ListContainers(ctx, subID, accountName, resourceGroup, location, kind)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListFileShares returns cached file shares for a storage account
func (s *StorageService) CachedListFileShares(ctx context.Context, subID, accountName, resourceGroup string) ([]FileShareInfo, error) {
	key := cacheKey("fileshares", subID, accountName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]FileShareInfo), nil
	}

	result, err := s.ListFileShares(ctx, subID, accountName, resourceGroup)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListTables returns cached tables for a storage account
func (s *StorageService) CachedListTables(ctx context.Context, subID, accountName, resourceGroup string) ([]TableInfo, error) {
	key := cacheKey("tables", subID, accountName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]TableInfo), nil
	}

	result, err := s.ListTables(ctx, subID, accountName, resourceGroup)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
