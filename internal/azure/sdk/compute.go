package sdk

import (
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
)

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
