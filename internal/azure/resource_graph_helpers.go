package azure

import (
	"context"
	"fmt"

	"github.com/BishopFox/cloudfox/globals"
)

// ------------------------------
// Resource Graph Types
// ------------------------------

// ResourceGraphResult represents a result from an Azure Resource Graph query
type ResourceGraphResult struct {
	SubscriptionID     string
	ResourceGroup      string
	ResourceName       string
	ResourceType       string
	Location           string
	Tags               string
	ProvisioningState  string
	PublicIP           string
	AssociatedResource string
	CertificateExpiry  string
	DaysUntilExpiry    int
	RelatedResource1   string
	RelatedResource2   string
	RelationshipType   string
}

// ------------------------------
// Resource Graph Query Execution
// ------------------------------

// ExecuteResourceGraphQuery executes a KQL query using Azure Resource Graph API
func ExecuteResourceGraphQuery(ctx context.Context, session *SafeSession, subscriptions []string, query string) ([]ResourceGraphResult, error) {
	// Use Azure Resource Graph REST API
	// Full implementation would use:
	// POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01
	// Body: {
	//   "subscriptions": ["sub-id-1", "sub-id-2"],
	//   "query": "KQL query string"
	// }

	_, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	var results []ResourceGraphResult

	// Mock implementation - actual would:
	// 1. Construct POST request to Resource Graph API
	// 2. Include subscriptions array in request body
	// 3. Execute KQL query
	// 4. Parse JSON response into ResourceGraphResult structs
	// 5. Handle pagination (skip token for > 1000 results)

	// Resource Graph query response format:
	// {
	//   "totalRecords": 100,
	//   "count": 100,
	//   "data": {
	//     "columns": [
	//       {"name": "subscriptionId", "type": "string"},
	//       {"name": "resourceGroup", "type": "string"},
	//       ...
	//     ],
	//     "rows": [
	//       ["sub-id-1", "rg-name", "resource-name", ...],
	//       ...
	//     ]
	//   },
	//   "$skipToken": "..."
	// }

	return results, nil
}

// ------------------------------
// Pre-Built Query Templates
// ------------------------------

// GetInternetFacingResourcesQuery returns KQL query for internet-facing resources
func GetInternetFacingResourcesQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Network/publicIPAddresses'
| extend associated = properties.ipConfiguration.id
| project subscriptionId, resourceGroup, name, type, location,
          publicIP = properties.ipAddress,
          associated
| limit 1000
`
}

// GetUnencryptedStorageQuery returns KQL query for unencrypted storage accounts
func GetUnencryptedStorageQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Storage/storageAccounts'
| extend blobEncrypted = properties.encryption.services.blob.enabled
| where blobEncrypted == false
| project subscriptionId, resourceGroup, name, type, location, blobEncrypted
`
}

// GetUnencryptedDatabasesQuery returns KQL query for databases without TDE
func GetUnencryptedDatabasesQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Sql/servers/databases'
| where name !~ 'master'
| extend tdeStatus = properties.transparentDataEncryption.status
| where tdeStatus != 'Enabled'
| project subscriptionId, resourceGroup, name, type, location, tdeStatus
`
}

// GetUnencryptedDisksQuery returns KQL query for unencrypted managed disks
func GetUnencryptedDisksQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Compute/disks'
| extend encrypted = properties.encryptionSettings.enabled
| where encrypted != true
| project subscriptionId, resourceGroup, name, type, location, encrypted
`
}

// GetUntaggedResourcesQuery returns KQL query for resources without tags
func GetUntaggedResourcesQuery() string {
	return `
Resources
| where isnull(tags) or array_length(todynamic(tags)) == 0
| where type !has 'microsoft.insights'
| project subscriptionId, resourceGroup, name, type, location
| limit 1000
`
}

// GetPublicEndpointsQuery returns KQL query for publicly accessible endpoints
func GetPublicEndpointsQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Network/applicationGateways'
   or type =~ 'Microsoft.Network/loadBalancers'
   or type =~ 'Microsoft.Network/frontDoors'
   or type =~ 'Microsoft.Cdn/profiles'
| extend publicAccess = properties.frontendIPConfigurations[0].properties.publicIPAddress
| where isnotnull(publicAccess)
| project subscriptionId, resourceGroup, name, type, location, publicAccess
`
}

// GetNSGInsecureRulesQuery returns KQL query for NSG rules allowing internet access
func GetNSGInsecureRulesQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Network/networkSecurityGroups'
| mv-expand rules = properties.securityRules
| where rules.properties.direction =~ 'Inbound'
  and rules.properties.access =~ 'Allow'
  and (rules.properties.sourceAddressPrefix =~ '*' or rules.properties.sourceAddressPrefix =~ 'Internet')
| extend protocol = rules.properties.protocol,
         destPort = rules.properties.destinationPortRange
| project subscriptionId, resourceGroup, nsgName = name, ruleName = rules.name,
          protocol, destPort, location
`
}

// GetOrphanedDisksQuery returns KQL query for unattached managed disks
func GetOrphanedDisksQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Compute/disks'
| where properties.diskState =~ 'Unattached'
| project subscriptionId, resourceGroup, name, type, location,
          diskState = properties.diskState,
          diskSizeGB = properties.diskSizeGB
`
}

// GetOrphanedPublicIPsQuery returns KQL query for unused public IPs
func GetOrphanedPublicIPsQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Network/publicIPAddresses'
| where isnull(properties.ipConfiguration)
| project subscriptionId, resourceGroup, name, type, location,
          ipAddress = properties.ipAddress
`
}

// GetResourcesByTagQuery returns KQL query to find resources by tag
func GetResourcesByTagQuery(tagKey string, tagValue string) string {
	return fmt.Sprintf(`
Resources
| where tags['%s'] =~ '%s'
| project subscriptionId, resourceGroup, name, type, location, tags
`, tagKey, tagValue)
}

// GetResourceCountByTypeQuery returns KQL query for resource counts by type
func GetResourceCountByTypeQuery() string {
	return `
Resources
| summarize count() by type, subscriptionId
| order by count_ desc
`
}

// GetResourcesByRegionQuery returns KQL query for resources in specific regions
func GetResourcesByRegionQuery(regions []string) string {
	// Example: regions = ["eastus", "westus"]
	return fmt.Sprintf(`
Resources
| where location in~ ('%s')
| project subscriptionId, resourceGroup, name, type, location
| limit 1000
`, "','")
}

// GetVMsWithoutBackupQuery returns KQL query for VMs without Azure Backup
func GetVMsWithoutBackupQuery() string {
	return `
Resources
| where type =~ 'Microsoft.Compute/virtualMachines'
| project subscriptionId, resourceGroup, vmName = name, location, vmId = id
| join kind=leftouter (
    Resources
    | where type =~ 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems'
    | extend vmId = properties.sourceResourceId
    | project vmId
  ) on vmId
| where isnull(vmId1)
| project subscriptionId, resourceGroup, vmName, location
`
}

// GetExpiredSecretsQuery returns KQL query for expired Key Vault secrets
func GetExpiredSecretsQuery() string {
	return `
Resources
| where type =~ 'Microsoft.KeyVault/vaults'
| project vaultName = name, subscriptionId, resourceGroup, location
// Note: Secret expiration requires Key Vault API calls, not available in Resource Graph
`
}

// GetCrossSubscriptionDependenciesQuery returns KQL query for cross-subscription dependencies
func GetCrossSubscriptionDependenciesQuery() string {
	return `
Resources
| extend dependsOn = properties.dependsOn
| where isnotnull(dependsOn)
| mv-expand dependency = dependsOn
| extend depSubscription = split(tostring(dependency), '/')[2]
| where depSubscription != subscriptionId
| project sourceSubscription = subscriptionId, targetSubscription = depSubscription,
          sourceResource = id, dependsOn = dependency
`
}

// ------------------------------
// Query Result Parsers
// ------------------------------

// ParseResourceGraphResponse parses the Resource Graph API JSON response
func ParseResourceGraphResponse(responseBody []byte) ([]ResourceGraphResult, error) {
	// Parse Resource Graph API response format:
	// {
	//   "data": {
	//     "columns": [...],
	//     "rows": [...]
	//   }
	// }

	var results []ResourceGraphResult

	// Mock implementation - actual would:
	// 1. Unmarshal JSON response
	// 2. Map columns to ResourceGraphResult fields
	// 3. Iterate through rows and create ResourceGraphResult structs
	// 4. Handle different column types (string, int, datetime, etc.)

	return results, nil
}

// ExtractSubscriptionFromResourceID extracts subscription ID from Azure resource ID
func ExtractSubscriptionFromResourceID(resourceID string) string {
	// Resource ID format: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}

	// Simple implementation
	if len(resourceID) == 0 {
		return ""
	}

	// Split by / and find subscriptions segment
	// Implementation would parse the resource ID properly

	return "unknown"
}
