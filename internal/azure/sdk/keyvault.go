package sdk

import (
	"context"

	azinternal "github.com/BishopFox/cloudfox/internal/azure"
)

// CachedGetKeyVaultsPerResourceGroup returns cached Key Vaults for a resource group
func CachedGetKeyVaultsPerResourceGroup(ctx context.Context, session *azinternal.SafeSession, subscriptionID, resourceGroup string) ([]azinternal.AzureVault, error) {
	cacheKey := CacheKey("keyvaults", subscriptionID, resourceGroup)

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.([]azinternal.AzureVault), nil
	}

	// Cache miss - call actual function
	result, err := azinternal.GetKeyVaultsPerResourceGroup(ctx, session, subscriptionID, resourceGroup)
	if err != nil {
		return nil, err
	}

	// Store in cache
	AzureSDKCache.Set(cacheKey, result, 0)

	return result, nil
}
