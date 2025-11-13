package sdk

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
)

// CachedGetStorageAccountsPerResourceGroup returns cached storage accounts for a resource group
func CachedGetStorageAccountsPerResourceGroup(session *azinternal.SafeSession, subscriptionID, resourceGroup string) []*armstorage.Account {
	cacheKey := CacheKey("storage-accounts", subscriptionID, resourceGroup)

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.([]*armstorage.Account)
	}

	// Cache miss - call actual function
	result := azinternal.GetStorageAccountsPerResourceGroup(session, subscriptionID, resourceGroup)

	// Store in cache
	AzureSDKCache.Set(cacheKey, result, 0)

	return result
}
