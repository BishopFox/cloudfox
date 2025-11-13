package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// Returns storage account keys for a given account
type StorageAccountKey struct {
	KeyName    string
	Value      string
	Permission string
}

type ContainerInfo struct {
	Name                    string
	URL                     string
	Public                  string
	Location                string
	Kind                    string
	LastModified            string
	LeaseState              string
	LeaseStatus             string
	HasImmutabilityPolicy   string
	HasLegalHold            string
	DefaultEncryptionScope  string
	DenyEncryptionScopeOverride string
	PublicAccessWarning     string
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

// Returns all storage accounts for a subscription
//func GetStorageAccountsPerSubscription(subID string) []*armstorage.Account {
//	cred := GetCredential()
//	if cred == nil {
//		return nil
//	}
//
//	clientFactory, err := armstorage.NewClientFactory(subID, cred, nil)
//	if err != nil {
//		return nil
//	}
//
//	accountsClient := clientFactory.NewAccountsClient()
//	pager := accountsClient.NewListPager(nil)
//	accounts := []*armstorage.Account{}
//
//	ctx := context.Background()
//	for pager.More() {
//		page, err := pager.NextPage(ctx)
//		if err != nil {
//			break
//		}
//		for _, acct := range page.Value {
//			accounts = append(accounts, acct)
//		}
//	}
//
//	return accounts
//}

// Returns all storage accounts for resource group
func GetStorageAccountsPerResourceGroup(session *SafeSession, subID, rgName string) []*armstorage.Account {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}

	clientFactory, err := armstorage.NewClientFactory(subID, cred, nil)
	if err != nil {
		return nil
	}

	accountsClient := clientFactory.NewAccountsClient()
	pager := accountsClient.NewListByResourceGroupPager(rgName, nil)
	accounts := []*armstorage.Account{}

	ctx := context.Background()
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acct := range page.Value {
			accounts = append(accounts, acct)
		}
	}

	return accounts
}

func GetStorageAccountKeys(session *SafeSession, subID, accountName, resourceGroup string) []StorageAccountKey {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}

	clientFactory, err := armstorage.NewClientFactory(subID, cred, nil)
	if err != nil {
		return nil
	}

	keysClient := clientFactory.NewAccountsClient()
	resp, err := keysClient.ListKeys(context.Background(), resourceGroup, accountName, nil)
	if err != nil || resp.Keys == nil {
		return nil
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

	return keys
}

// ListContainers returns all containers for a given storage account
func ListContainers(ctx context.Context, session *SafeSession, subID, accountName, resourceGroup, location, kind string) ([]ContainerInfo, error) {
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subID, err)
	}

	cred := &StaticTokenCredential{Token: token}

	storageClient, err := armstorage.NewBlobContainersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create BlobContainers client: %w", err)
	}

	pager := storageClient.NewListPager(resourceGroup, accountName, nil)
	var containers []ContainerInfo

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to fetch container page for account %s: %v\n", accountName, err), globals.AZ_STORAGE_MODULE_NAME)
			}
			break
		}

		for _, c := range page.Value {
			cName := SafeString(*c.Name)
			cPublic := "Private Only"
			publicAccessWarning := "✓ Secure (Private)"

			if c.Properties != nil && c.Properties.PublicAccess != nil {
				switch *c.Properties.PublicAccess {
				case armstorage.PublicAccessBlob:
					cPublic = "⚠ Blobs Public" // blobs accessible, container listing disabled
					publicAccessWarning = "⚠ WARNING: Blobs are publicly accessible"
				case armstorage.PublicAccessContainer:
					cPublic = "⚠ Container And Blobs Public" // full container + blob access
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

// ListFileShares returns all file shares for a given storage account
func ListFileShares(ctx context.Context, session *SafeSession, subID, accountName, resourceGroup string) ([]FileShareInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	storageClient, err := armstorage.NewFileSharesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create FileShares client: %w", err)
	}

	pager := storageClient.NewListPager(resourceGroup, accountName, nil)
	var shares []FileShareInfo

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return shares, err // Return partial results on error
		}

		for _, share := range page.Value {
			if share.Name == nil {
				continue
			}

			info := FileShareInfo{
				AccountName:   accountName,
				ResourceGroup: resourceGroup,
				ShareName:     SafeString(*share.Name),
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

// ListTables returns all tables for a given storage account
func ListTables(ctx context.Context, session *SafeSession, subID, accountName, resourceGroup string) ([]TableInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	storageClient, err := armstorage.NewTableClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Table client: %w", err)
	}

	pager := storageClient.NewListPager(resourceGroup, accountName, nil)
	var tables []TableInfo

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return tables, err // Return partial results on error
		}

		for _, table := range page.Value {
			if table.Name == nil {
				continue
			}

			tables = append(tables, TableInfo{
				AccountName:   accountName,
				ResourceGroup: resourceGroup,
				TableName:     SafeString(*table.Name),
			})
		}
	}

	return tables, nil
}
