package sdk

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
)

// CachedGetAKSClustersPerResourceGroup returns cached AKS clusters for a resource group
func CachedGetAKSClustersPerResourceGroup(ctx context.Context, session *azinternal.SafeSession, subscriptionID, resourceGroup string) ([]*armcontainerservice.ManagedCluster, error) {
	cacheKey := CacheKey("aks-clusters", subscriptionID, resourceGroup)

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.([]*armcontainerservice.ManagedCluster), nil
	}

	// Cache miss - call actual function
	result, err := azinternal.GetAKSClustersPerResourceGroup(ctx, session, subscriptionID, resourceGroup)
	if err != nil {
		return nil, err
	}

	// Store in cache
	AzureSDKCache.Set(cacheKey, result, 0)

	return result, nil
}

// CachedGetAKSCluster gets a specific AKS cluster (useful for getting updated details)
func CachedGetAKSCluster(ctx context.Context, session *azinternal.SafeSession, subscriptionID, resourceGroup, clusterName string) (*armcontainerservice.ManagedCluster, error) {
	cacheKey := CacheKey("aks-cluster", subscriptionID, resourceGroup, clusterName)

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.(*armcontainerservice.ManagedCluster), nil
	}

	// Cache miss - fetch from Azure
	token, err := session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		return nil, err
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	client, err := armcontainerservice.NewManagedClustersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Get(ctx, resourceGroup, clusterName, nil)
	if err != nil {
		return nil, err
	}

	// Store in cache
	AzureSDKCache.Set(cacheKey, &resp.ManagedCluster, 0)

	return &resp.ManagedCluster, nil
}
