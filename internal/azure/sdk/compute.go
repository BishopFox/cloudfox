package sdk

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
)

// CachedGetVMsPerSubscription returns cached VMs for a subscription
func CachedGetVMsPerSubscription(session *azinternal.SafeSession, subscriptionID string) []*armcompute.VirtualMachine {
	cacheKey := CacheKey("vms", subscriptionID, "")

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.([]*armcompute.VirtualMachine)
	}

	// Cache miss - get VMs from Azure
	ctx := context.Background()
	vms, err := azinternal.GetVMsPerSubscription(ctx, session, subscriptionID)
	if err != nil {
		return []*armcompute.VirtualMachine{}
	}

	// Store in cache
	AzureSDKCache.Set(cacheKey, vms, 0)
	return vms
}

// CachedGetVMsPerResourceGroupObject returns cached VMs for a resource group
// Note: This function has a complex signature with lootMap - consider refactoring in future
func CachedGetVMsPerResourceGroupObject(session *azinternal.SafeSession, subscriptionID, resourceGroup string, lootMap map[string]*internal.LootFile, tenantName string, tenantID string) ([][]string, string) {
	cacheKey := CacheKey("vms-object", subscriptionID, resourceGroup)

	// Check cache first (only cache the table rows, not the loot)
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		cachedData := cached.(struct {
			rows    [][]string
			csvName string
		})
		return cachedData.rows, cachedData.csvName
	}

	// Cache miss - call actual function
	rows, csvName := azinternal.GetVMsPerResourceGroupObject(session, subscriptionID, resourceGroup, lootMap, tenantName, tenantID)

	// Store in cache (cache structure with both returns)
	AzureSDKCache.Set(cacheKey, struct {
		rows    [][]string
		csvName string
	}{rows, csvName}, 0)

	return rows, csvName
}
