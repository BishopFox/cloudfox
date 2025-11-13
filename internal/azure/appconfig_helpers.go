package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration"
	"github.com/BishopFox/cloudfox/globals"
)

// ==================== APP CONFIGURATION STRUCTURES ====================

// AppConfigStore represents an Azure App Configuration store
type AppConfigStore struct {
	Name                string
	ID                  string
	Location            string
	ResourceGroup       string
	SubscriptionID      string
	Endpoint            string
	ProvisioningState   string
	PublicNetworkAccess string
	IdentityType        string
	PrincipalID         string
	TenantID            string
	SKUName             string
	CreationDate        string
	UserAssignedIDs     string
}

// AppConfigAccessKey represents an access key for App Configuration
type AppConfigAccessKey struct {
	ID               string
	Name             string
	Value            string
	ConnectionString string
	LastModified     string
	ReadOnly         bool
}

// ==================== APP CONFIGURATION HELPERS ====================

// GetAppConfigStores retrieves all App Configuration stores in a subscription
func GetAppConfigStores(session *SafeSession, subscriptionID string, resourceGroups []string) ([]AppConfigStore, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armappconfiguration.NewConfigurationStoresClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []AppConfigStore

	// If specific resource groups provided, enumerate those
	if len(resourceGroups) > 0 {
		for _, rgName := range resourceGroups {
			pager := client.NewListByResourceGroupPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, store := range page.Value {
					results = append(results, convertAppConfigStore(ctx, session, store, rgName, subscriptionID))
				}
			}
		}
	} else {
		// Otherwise, enumerate all App Configuration stores in subscription
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return results, err
			}
			for _, store := range page.Value {
				rgName := GetResourceGroupFromID(SafeStringPtr(store.ID))
				results = append(results, convertAppConfigStore(ctx, session, store, rgName, subscriptionID))
			}
		}
	}

	return results, nil
}

// convertAppConfigStore converts SDK App Configuration store to our struct
func convertAppConfigStore(ctx context.Context, session *SafeSession, store *armappconfiguration.ConfigurationStore, resourceGroup, subscriptionID string) AppConfigStore {
	result := AppConfigStore{
		Name:           SafeStringPtr(store.Name),
		ID:             SafeStringPtr(store.ID),
		Location:       SafeStringPtr(store.Location),
		ResourceGroup:  resourceGroup,
		SubscriptionID: subscriptionID,
	}

	if store.Properties != nil {
		result.Endpoint = SafeStringPtr(store.Properties.Endpoint)
		// ProvisioningState is an enum type
		if store.Properties.ProvisioningState != nil {
			result.ProvisioningState = string(*store.Properties.ProvisioningState)
		}
		if store.Properties.PublicNetworkAccess != nil {
			result.PublicNetworkAccess = string(*store.Properties.PublicNetworkAccess)
		}
		if store.Properties.CreationDate != nil {
			result.CreationDate = store.Properties.CreationDate.String()
		}
	}

	if store.SKU != nil {
		result.SKUName = SafeStringPtr(store.SKU.Name)
	}

	// Extract managed identity information
	if store.Identity != nil {
		if store.Identity.Type != nil {
			result.IdentityType = string(*store.Identity.Type)
		}
		result.PrincipalID = SafeStringPtr(store.Identity.PrincipalID)
		result.TenantID = SafeStringPtr(store.Identity.TenantID)

		// Fetch user-assigned identities
		if store.Identity.UserAssignedIdentities != nil {
			var userIDs []string

			for uaID := range store.Identity.UserAssignedIdentities {
				userIDs = append(userIDs, uaID)
			}

			if len(userIDs) > 0 {
				result.UserAssignedIDs = ""
				for i, id := range userIDs {
					if i > 0 {
						result.UserAssignedIDs += ", "
					}
					result.UserAssignedIDs += id
				}
			} else {
				result.UserAssignedIDs = "N/A"
			}
		} else {
			result.UserAssignedIDs = "N/A"
		}
	} else {
		result.UserAssignedIDs = "N/A"
	}

	return result
}

// GetAppConfigAccessKeys retrieves access keys for an App Configuration store
func GetAppConfigAccessKeys(session *SafeSession, subscriptionID, resourceGroup, storeName string) ([]AppConfigAccessKey, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()

	client, err := armappconfiguration.NewConfigurationStoresClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	var results []AppConfigAccessKey

	pager := client.NewListKeysPager(resourceGroup, storeName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return results, err
		}

		for _, key := range page.Value {
			if key == nil {
				continue
			}

			accessKey := AppConfigAccessKey{
				ID:               SafeStringPtr(key.ID),
				Name:             SafeStringPtr(key.Name),
				Value:            SafeStringPtr(key.Value),
				ConnectionString: SafeStringPtr(key.ConnectionString),
				ReadOnly:         key.ReadOnly != nil && *key.ReadOnly,
			}

			if key.LastModified != nil {
				accessKey.LastModified = key.LastModified.String()
			}

			results = append(results, accessKey)
		}
	}

	return results, nil
}

// GenerateAppConfigAccessScript generates a PowerShell/bash script for accessing App Configuration data
func GenerateAppConfigAccessScript(store AppConfigStore, keys []AppConfigAccessKey) string {
	template := fmt.Sprintf("# App Configuration Store Access Script\n")
	template += fmt.Sprintf("# Store: %s\n", store.Name)
	template += fmt.Sprintf("# Resource Group: %s\n", store.ResourceGroup)
	template += fmt.Sprintf("# Subscription: %s\n", store.SubscriptionID)
	template += fmt.Sprintf("# Endpoint: %s\n\n", store.Endpoint)

	if len(keys) == 0 {
		template += "# No access keys found or insufficient permissions to list keys\n\n"
		return template
	}

	// Get the first read-write key
	var readWriteKey *AppConfigAccessKey
	var readOnlyKey *AppConfigAccessKey

	for i := range keys {
		if !keys[i].ReadOnly && readWriteKey == nil {
			readWriteKey = &keys[i]
		}
		if keys[i].ReadOnly && readOnlyKey == nil {
			readOnlyKey = &keys[i]
		}
	}

	// Prefer read-only key for enumeration
	var selectedKey *AppConfigAccessKey
	if readOnlyKey != nil {
		selectedKey = readOnlyKey
	} else if readWriteKey != nil {
		selectedKey = readWriteKey
	}

	if selectedKey == nil {
		template += "# No valid access keys available\n\n"
		return template
	}

	template += fmt.Sprintf("# Using key: %s (%s)\n\n", selectedKey.Name, map[bool]string{true: "read-only", false: "read-write"}[selectedKey.ReadOnly])

	// Extract endpoint hostname
	endpoint := store.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("%s.azconfig.io", store.Name)
	}
	// Remove https:// if present
	if len(endpoint) > 8 && endpoint[:8] == "https://" {
		endpoint = endpoint[8:]
	}

	template += "## Method 1: Using PowerShell with HMAC-SHA256 Authentication\n\n"
	template += "```powershell\n"
	template += "# HMAC-SHA256 signing functions\n"
	template += `function Compute-SHA256Hash([string]$content) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToBase64String($sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($content)))
    } finally { $sha256.Dispose() }
}

function Compute-HMACSHA256Hash([string]$secret, [string]$content) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($secret))
    try {
        return [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($content)))
    } finally { $hmac.Dispose() }
}

function Sign-Request([string]$hostname, [string]$method, [string]$url, [string]$body, [string]$credential, [string]$secret) {
    $verb = $method.ToUpperInvariant()
    $utcNow = (Get-Date).ToUniversalTime().ToString("R", [Globalization.DateTimeFormatInfo]::InvariantInfo)
    $contentHash = Compute-SHA256Hash $body
    $signedHeaders = "x-ms-date;host;x-ms-content-sha256"
    $stringToSign = $verb + "` + "`" + `n" + $url + "` + "`" + `n" + $utcNow + ";" + $hostname + ";" + $contentHash
    $signature = Compute-HMACSHA256Hash $secret $stringToSign

    return @{
        "x-ms-date" = $utcNow
        "x-ms-content-sha256" = $contentHash
        "Authorization" = "HMAC-SHA256 Credential=" + $credential + "&SignedHeaders=" + $signedHeaders + "&Signature=" + $signature
    }
}

`
	template += "# Set credentials\n"
	template += fmt.Sprintf("$appConfigName = \"%s\"\n", endpoint)
	template += fmt.Sprintf("$keyId = \"%s\"\n", selectedKey.ID)
	template += fmt.Sprintf("$keySecret = \"%s\"\n\n", selectedKey.Value)

	template += "# List all key-values\n"
	template += "$uri = [System.Uri]::new(\"https://$appConfigName/kv?api-version=1.0\")\n"
	template += "$headers = Sign-Request $uri.Authority \"GET\" $uri.PathAndQuery $null $keyId $keySecret\n"
	template += "$response = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers\n"
	template += "$config = ([System.Text.Encoding]::ASCII.GetString($response.Content) | ConvertFrom-Json)\n"
	template += "$config.items | Select-Object key, value, label, content_type, locked, last_modified | Format-Table\n\n"

	template += "# Get specific key\n"
	template += "$keyName = \"myConfigKey\"  # Replace with actual key name\n"
	template += "$uri = [System.Uri]::new(\"https://$appConfigName/kv/$keyName?api-version=1.0\")\n"
	template += "$headers = Sign-Request $uri.Authority \"GET\" $uri.PathAndQuery $null $keyId $keySecret\n"
	template += "$response = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers\n"
	template += "([System.Text.Encoding]::ASCII.GetString($response.Content) | ConvertFrom-Json)\n"
	template += "```\n\n"

	template += "## Method 2: Using Connection String with Azure CLI/SDK\n\n"
	template += "```bash\n"
	template += "# Set connection string\n"
	template += fmt.Sprintf("export CONNECTION_STRING=\"%s\"\n\n", selectedKey.ConnectionString)
	template += "# Using Azure App Configuration CLI extension\n"
	template += "az appconfig kv list --connection-string \"$CONNECTION_STRING\" -o table\n\n"
	template += "# Get specific key\n"
	template += "az appconfig kv show --connection-string \"$CONNECTION_STRING\" --key \"myConfigKey\"\n\n"
	template += "# Export all configuration\n"
	template += "az appconfig kv export --connection-string \"$CONNECTION_STRING\" --destination file --path config.json --format json\n"
	template += "```\n\n"

	template += "## Method 3: Using REST API with curl\n\n"
	template += "```bash\n"
	template += "# Note: HMAC-SHA256 signing is complex in bash\n"
	template += "# Easier to use PowerShell method above or Azure CLI\n"
	template += "# Example using connection string parsing:\n\n"
	template += fmt.Sprintf("CONNECTION_STRING=\"%s\"\n", selectedKey.ConnectionString)
	template += "# Parse connection string to extract endpoint, id, and secret\n"
	template += "# Then implement HMAC-SHA256 signing (non-trivial in bash)\n"
	template += "```\n\n"

	template += "## Method 4: Using Python SDK\n\n"
	template += "```python\n"
	template += "from azure.appconfiguration import AzureAppConfigurationClient\n\n"
	template += fmt.Sprintf("connection_string = \"%s\"\n", selectedKey.ConnectionString)
	template += "client = AzureAppConfigurationClient.from_connection_string(connection_string)\n\n"
	template += "# List all configuration settings\n"
	template += "for item in client.list_configuration_settings():\n"
	template += "    print(f\"{item.key}: {item.value}\")\n\n"
	template += "# Get specific key\n"
	template += "config = client.get_configuration_setting(key=\"myConfigKey\")\n"
	template += "print(f\"Value: {config.value}\")\n"
	template += "```\n\n"

	return template
}
