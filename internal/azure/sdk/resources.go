package sdk

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
)

// CachedGetResourceGroupsPerSubscription returns cached resource groups for a subscription
// This is one of the most frequently called functions across all Azure modules
func CachedGetResourceGroupsPerSubscription(session *azinternal.SafeSession, subscriptionID string) []*armresources.ResourceGroup {
	cacheKey := CacheKey("resource-groups", subscriptionID)

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.([]*armresources.ResourceGroup)
	}

	// Cache miss - call actual function
	result := azinternal.GetResourceGroupsPerSubscription(session, subscriptionID)

	// Store in cache
	AzureSDKCache.Set(cacheKey, result, 0) // Use default expiration (2 hours)

	return result
}

// CachedGetARMResourcesClient returns a cached ARM resources client
func CachedGetARMResourcesClient(session *azinternal.SafeSession, tenantID, subscriptionID string) (*armresources.Client, error) {
	// Note: We don't cache the client itself, but we can optimize token retrieval
	// Clients are lightweight, but token fetching is expensive
	return azinternal.GetARMresourcesClient(session, tenantID, subscriptionID)
}

// CachedListResourcesByType lists resources of a specific type in a subscription
func CachedListResourcesByType(ctx context.Context, session *azinternal.SafeSession, subscriptionID, resourceType string) ([]*armresources.GenericResourceExpanded, error) {
	cacheKey := CacheKey("resources-by-type", subscriptionID, resourceType)

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.([]*armresources.GenericResourceExpanded), nil
	}

	// Cache miss - fetch from Azure
	token, err := session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		return nil, err
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	client, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []*armresources.GenericResourceExpanded
	filter := "resourceType eq '" + resourceType + "'"
	pager := client.NewListPager(&armresources.ClientListOptions{
		Filter: &filter,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		results = append(results, page.Value...)
	}

	// Store in cache
	AzureSDKCache.Set(cacheKey, results, 0)

	return results, nil
}

// CachedGetResource gets a specific resource by ID
func CachedGetResource(ctx context.Context, session *azinternal.SafeSession, subscriptionID, resourceID string, apiVersion string) (*armresources.GenericResource, error) {
	cacheKey := CacheKey("resource", subscriptionID, resourceID, apiVersion)

	// Check cache first
	if cached, found := AzureSDKCache.Get(cacheKey); found {
		return cached.(*armresources.GenericResource), nil
	}

	// Cache miss - fetch from Azure
	token, err := session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		return nil, err
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	client, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetByID(ctx, resourceID, apiVersion, nil)
	if err != nil {
		return nil, err
	}

	// Store in cache
	AzureSDKCache.Set(cacheKey, &resp.GenericResource, 0)

	return &resp.GenericResource, nil
}
