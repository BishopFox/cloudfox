package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

type StorageSASToken struct {
	AccountName   string
	ResourceGroup string
	PolicyName    string
	Identifier    string
	Permissions   string
	Start         string
	Expiry        string
}

type EventHubSASToken struct {
	ResourceName  string
	ResourceGroup string
	PolicyName    string
	Identifier    string
	Permissions   string
	Region        string
}

// ---------- Additional credential types from Get-AzPasswords.ps1 ----------

type ACRCredential struct {
	RegistryName  string
	LoginServer   string
	ResourceGroup string
	Region        string
	Username      string
	Password      string
	Password2     string
}

type CosmosDBKey struct {
	AccountName   string
	ResourceGroup string
	Region        string
	KeyType       string
	KeyValue      string
}

type FunctionAppKey struct {
	AppName       string
	ResourceGroup string
	Region        string
	KeyType       string
	KeyName       string
	KeyValue      string
}

type ContainerAppSecret struct {
	AppName       string
	ResourceGroup string
	Region        string
	SecretName    string
	SecretValue   string
}

type APIManagementSecret struct {
	ServiceName   string
	ResourceGroup string
	Region        string
	SecretName    string
	SecretValue   string
}

type ServiceBusKey struct {
	NamespaceName    string
	ResourceGroup    string
	Region           string
	KeyName          string
	KeyType          string
	KeyValue         string
	ConnectionString string
}

type AppConfigKey struct {
	StoreName        string
	ResourceGroup    string
	Region           string
	KeyName          string
	ConnectionString string
}

type BatchAccountKey struct {
	AccountName   string
	ResourceGroup string
	Region        string
	KeyType       string
	KeyValue      string
}

type CognitiveServicesKey struct {
	AccountName   string
	ResourceGroup string
	Region        string
	Endpoint      string
	KeyType       string
	KeyValue      string
}

// AddServicePrincipalSecret adds a SP secret to tableRows and lootMap
func AddServicePrincipalSecret(wg *sync.WaitGroup, mu *sync.Mutex, tableRows *[][]string, lootMap map[string]*internal.LootFile, lootFileName, tenantName, tenantID, subID, subName, appName, appID, secretName, keyID, endDate string) {
	// Table - Updated to match new 16-column structure with tenant columns
	mu.Lock()
	*tableRows = append(*tableRows, []string{
		tenantName,                 // 1. Tenant Name
		tenantID,                   // 2. Tenant ID
		subID,                      // 3. Subscription ID
		subName,                    // 4. Subscription Name
		"N/A",                      // 5. Resource Group
		"N/A",                      // 6. Region
		appName,                    // 7. Resource Name
		"Service Principal",        // 8. Resource Type
		appID,                      // 9. Application ID
		secretName,                 // 10. Key/Cert Name
		"Service Principal Secret", // 11. Key/Cert Type
		keyID,                      // 12. Identifier/Thumbprint
		"N/A",                      // 13. Secret Hint
		"N/A",                      // 14. Cert Start Time
		endDate,                    // 15. Cert Expiry
		"N/A",                      // 16. Permissions/Scope
	})
	mu.Unlock()

	// Loot
	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()
		lootMap[lootFileName].Contents += fmt.Sprintf(
			"## Service Principal: %s, Secret: %s\n"+
				"az ad app credential list --id %s\n"+
				"Get-AzADAppCredential -ObjectId %s\n\n",
			appName, secretName, appID, appID,
		)
	}()
}

// AddServicePrincipalCertificate adds a SP certificate to tableRows and lootMap
func AddServicePrincipalCertificate(wg *sync.WaitGroup, mu *sync.Mutex, tableRows *[][]string, lootMap map[string]*internal.LootFile, lootFileName, tenantName, tenantID, subID, subName, appName, appID, certName, thumbprint, expiryDate string) {
	// Table - Updated to match new 16-column structure with tenant columns
	mu.Lock()
	*tableRows = append(*tableRows, []string{
		tenantName,                      // 1. Tenant Name
		tenantID,                        // 2. Tenant ID
		subID,                           // 3. Subscription ID
		subName,                         // 4. Subscription Name
		"N/A",                           // 5. Resource Group
		"N/A",                           // 6. Region
		appName,                         // 7. Resource Name
		"Service Principal",             // 8. Resource Type
		appID,                           // 9. Application ID
		certName,                        // 10. Key/Cert Name
		"Service Principal Certificate", // 11. Key/Cert Type
		thumbprint,                      // 12. Identifier/Thumbprint
		"N/A",                           // 13. Secret Hint
		"N/A",                           // 14. Cert Start Time
		expiryDate,                      // 15. Cert Expiry
		"N/A",                           // 16. Permissions/Scope
	})
	mu.Unlock()

	// Loot
	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()
		lootMap[lootFileName].Contents += fmt.Sprintf(
			"## Service Principal: %s, Certificate: %s\n"+
				"az ad app credential list --id %s\n"+
				"Get-AzADAppCredential -ObjectId %s\n\n",
			appName, certName, appID, appID,
		)
	}()
}

// Enumerate Event Hub
func GetEventHubSASTokens(session *SafeSession, subID string) []EventHubSASToken {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}

	ctx := context.Background()
	var results []EventHubSASToken

	// Event Hubs
	ehFactory, err := armeventhub.NewClientFactory(subID, cred, nil)
	if err == nil {
		nsClient := ehFactory.NewNamespacesClient()
		pager := nsClient.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, ns := range page.Value {
				if ns.Name == nil || ns.ID == nil {
					continue
				}
				rgName := GetResourceGroupFromID(*ns.ID)
				rulesClient := ehFactory.NewNamespacesClient()
				rulesPager := rulesClient.NewListAuthorizationRulesPager(rgName, *ns.Name, nil)
				for rulesPager.More() {
					rulesPage, err := rulesPager.NextPage(ctx)
					if err != nil {
						break
					}
					for _, rule := range rulesPage.Value {
						permissions := ""
						if rule.Properties != nil && rule.Properties.Rights != nil {
							for _, right := range rule.Properties.Rights {
								if right != nil {
									permissions += string(*right) + ","
								}
							}
							// Remove trailing comma
							if len(permissions) > 0 {
								permissions = permissions[:len(permissions)-1]
							}
						}

						results = append(results, EventHubSASToken{
							ResourceName:  SafeStringPtr(ns.Name),
							ResourceGroup: rgName,
							PolicyName:    SafeStringPtr(rule.Name),
							Identifier:    SafeStringPtr(rule.Name),
							Permissions:   permissions,
							Region:        SafeStringPtr(ns.Location),
						})
					}
				}
			}
		}
	}

	return results
}

// ==================== GET-AZPASSWORDS CREDENTIAL EXTRACTORS ====================

// GetACRCredentials extracts admin credentials from Container Registries
func GetACRCredentials(session *SafeSession, subID string, resourceGroups []string) []ACRCredential {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []ACRCredential

	regClient, err := armcontainerregistry.NewRegistriesClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := regClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, reg := range page.Value {
				// Check if admin user is enabled
				if reg.Properties == nil || reg.Properties.AdminUserEnabled == nil || !*reg.Properties.AdminUserEnabled {
					continue
				}

				regName := SafeStringPtr(reg.Name)
				loginServer := SafeStringPtr(reg.Properties.LoginServer)
				region := SafeStringPtr(reg.Location)

				// Get credentials
				resp, err := regClient.ListCredentials(ctx, rgName, regName, nil)
				if err != nil {
					continue
				}

				username := SafeStringPtr(resp.Username)
				password := ""
				password2 := ""
				if len(resp.Passwords) > 0 {
					password = SafeStringPtr(resp.Passwords[0].Value)
				}
				if len(resp.Passwords) > 1 {
					password2 = SafeStringPtr(resp.Passwords[1].Value)
				}

				results = append(results, ACRCredential{
					RegistryName:  regName,
					LoginServer:   loginServer,
					ResourceGroup: rgName,
					Region:        region,
					Username:      username,
					Password:      password,
					Password2:     password2,
				})
			}
		}
	}

	return results
}

// GetCosmosDBKeys extracts all keys from CosmosDB accounts
func GetCosmosDBKeys(session *SafeSession, subID string, resourceGroups []string) []CosmosDBKey {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []CosmosDBKey

	cosmosClient, err := armcosmos.NewDatabaseAccountsClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := cosmosClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, account := range page.Value {
				accountName := SafeStringPtr(account.Name)
				region := SafeStringPtr(account.Location)

				// Get all keys
				resp, err := cosmosClient.ListKeys(ctx, rgName, accountName, nil)
				if err != nil {
					continue
				}

				// Add all 4 key types
				if resp.PrimaryReadonlyMasterKey != nil {
					results = append(results, CosmosDBKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						KeyType:       "PrimaryReadonlyMasterKey",
						KeyValue:      *resp.PrimaryReadonlyMasterKey,
					})
				}
				if resp.SecondaryReadonlyMasterKey != nil {
					results = append(results, CosmosDBKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						KeyType:       "SecondaryReadonlyMasterKey",
						KeyValue:      *resp.SecondaryReadonlyMasterKey,
					})
				}
				if resp.PrimaryMasterKey != nil {
					results = append(results, CosmosDBKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						KeyType:       "PrimaryMasterKey",
						KeyValue:      *resp.PrimaryMasterKey,
					})
				}
				if resp.SecondaryMasterKey != nil {
					results = append(results, CosmosDBKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						KeyType:       "SecondaryMasterKey",
						KeyValue:      *resp.SecondaryMasterKey,
					})
				}
			}
		}
	}

	return results
}

// GetFunctionAppKeys extracts keys from Function Apps
func GetFunctionAppKeys(session *SafeSession, subID string, resourceGroups []string) []FunctionAppKey {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []FunctionAppKey

	webClient, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := webClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, site := range page.Value {
				// Skip if not a function app
				if site.Kind == nil || !containsSubstring(*site.Kind, "functionapp") {
					continue
				}

				appName := SafeStringPtr(site.Name)
				region := SafeStringPtr(site.Location)

				// Extract Storage Account Keys from app settings
				settingsResp, err := webClient.ListApplicationSettings(ctx, rgName, appName, nil)
				if err == nil && settingsResp.Properties != nil {
					// WEBSITE_CONTENTAZUREFILECONNECTIONSTRING
					if connStr, ok := settingsResp.Properties["WEBSITE_CONTENTAZUREFILECONNECTIONSTRING"]; ok && connStr != nil {
						results = append(results, FunctionAppKey{
							AppName:       appName,
							ResourceGroup: rgName,
							Region:        region,
							KeyType:       "Content Storage Connection String",
							KeyName:       "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING",
							KeyValue:      *connStr,
						})
					}
					// AzureWebJobsStorage
					if connStr, ok := settingsResp.Properties["AzureWebJobsStorage"]; ok && connStr != nil {
						results = append(results, FunctionAppKey{
							AppName:       appName,
							ResourceGroup: rgName,
							Region:        region,
							KeyType:       "Job Storage Connection String",
							KeyName:       "AzureWebJobsStorage",
							KeyValue:      *connStr,
						})
					}
				}

				// Get function host keys via REST API
				funcKeys, err := getFunctionHostKeys(session, subID, rgName, appName)
				if err == nil {
					for keyName, keyValue := range funcKeys {
						results = append(results, FunctionAppKey{
							AppName:       appName,
							ResourceGroup: rgName,
							Region:        region,
							KeyType:       "Function Host Key",
							KeyName:       keyName,
							KeyValue:      keyValue,
						})
					}
				}
			}
		}
	}

	return results
}

// getFunctionHostKeys - REST API helper to get function keys
func getFunctionHostKeys(session *SafeSession, subID, rgName, appName string) (map[string]string, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/host/default/listkeys?api-version=2022-03-01",
		subID, rgName, appName)

	// Use retry logic for ARM API
	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(context.Background(), "POST", url, token, nil, config)
	if err != nil {
		return nil, fmt.Errorf("failed to get function keys: %v", err)
	}

	var result struct {
		MasterKey    string            `json:"masterKey"`
		FunctionKeys map[string]string `json:"functionKeys"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	keys := make(map[string]string)
	if result.MasterKey != "" {
		keys["master"] = result.MasterKey
	}
	for name, value := range result.FunctionKeys {
		keys[name] = value
	}

	return keys, nil
}

// GetContainerAppSecrets extracts secrets from Container Apps
func GetContainerAppSecrets(session *SafeSession, subID string, resourceGroups []string) []ContainerAppSecret {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}

	var results []ContainerAppSecret
	ctx := context.Background()

	// Configure retry for ARM API
	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	for _, rgName := range resourceGroups {
		// Use REST API since SDK may not have full support
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/containerApps?api-version=2023-05-01",
			subID, rgName)

		// List container apps with retry logic
		body, err := HTTPRequestWithRetry(ctx, "GET", url, token, nil, config)
		if err != nil {
			// Log error but continue with other resource groups
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger := internal.NewLogger()
				logger.ErrorM(fmt.Sprintf("Failed to list container apps in RG %s: %v", rgName, err), "container-apps")
			}
			continue
		}

		var listResp struct {
			Value []struct {
				Name     string `json:"name"`
				ID       string `json:"id"`
				Location string `json:"location"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &listResp); err != nil {
			continue
		}

		for _, app := range listResp.Value {
			// Get secrets for this app with retry logic
			secretsURL := fmt.Sprintf("https://management.azure.com%s/listSecrets?api-version=2023-05-01", app.ID)
			secretsBody, err := HTTPRequestWithRetry(ctx, "POST", secretsURL, token, nil, config)
			if err != nil {
				// Log error but continue with other apps
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger := internal.NewLogger()
					logger.ErrorM(fmt.Sprintf("Failed to list secrets for app %s: %v", app.Name, err), "container-apps")
				}
				continue
			}

			var secrets struct {
				Value []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"value"`
			}
			if err := json.Unmarshal(secretsBody, &secrets); err != nil {
				continue
			}

			for _, secret := range secrets.Value {
				results = append(results, ContainerAppSecret{
					AppName:       app.Name,
					ResourceGroup: rgName,
					Region:        app.Location,
					SecretName:    secret.Name,
					SecretValue:   secret.Value,
				})
			}
		}
	}

	return results
}

// GetAPIManagementSecrets extracts named value secrets from API Management services
func GetAPIManagementSecrets(session *SafeSession, subID string, resourceGroups []string) []APIManagementSecret {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []APIManagementSecret

	apimClient, err := armapimanagement.NewServiceClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	namedValuesClient, err := armapimanagement.NewNamedValueClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := apimClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, service := range page.Value {
				serviceName := SafeStringPtr(service.Name)
				region := SafeStringPtr(service.Location)

				// List named values
				nvPager := namedValuesClient.NewListByServicePager(rgName, serviceName, nil)
				for nvPager.More() {
					nvPage, err := nvPager.NextPage(ctx)
					if err != nil {
						break
					}

					for _, nv := range nvPage.Value {
						// Only get secrets (not Key Vault references)
						if nv.Properties != nil && nv.Properties.Secret != nil && *nv.Properties.Secret {
							// Get the secret value
							secretResp, err := namedValuesClient.ListValue(ctx, rgName, serviceName, SafeStringPtr(nv.Name), nil)
							if err == nil && secretResp.Value != nil {
								results = append(results, APIManagementSecret{
									ServiceName:   serviceName,
									ResourceGroup: rgName,
									Region:        region,
									SecretName:    SafeStringPtr(nv.Name),
									SecretValue:   *secretResp.Value,
								})
							}
						}
					}
				}
			}
		}
	}

	return results
}

// GetServiceBusKeys extracts namespace keys from Service Bus
func GetServiceBusKeys(session *SafeSession, subID string, resourceGroups []string) []ServiceBusKey {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []ServiceBusKey

	nsClient, err := armservicebus.NewNamespacesClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := nsClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, ns := range page.Value {
				nsName := SafeStringPtr(ns.Name)
				region := SafeStringPtr(ns.Location)

				// List authorization rules
				rulesPager := nsClient.NewListAuthorizationRulesPager(rgName, nsName, nil)
				for rulesPager.More() {
					rulesPage, err := rulesPager.NextPage(ctx)
					if err != nil {
						break
					}

					for _, rule := range rulesPage.Value {
						ruleName := SafeStringPtr(rule.Name)

						// Get keys
						keysResp, err := nsClient.ListKeys(ctx, rgName, nsName, ruleName, nil)
						if err != nil {
							continue
						}

						// Primary key
						if keysResp.PrimaryKey != nil {
							results = append(results, ServiceBusKey{
								NamespaceName:    nsName,
								ResourceGroup:    rgName,
								Region:           region,
								KeyName:          ruleName,
								KeyType:          "Primary",
								KeyValue:         *keysResp.PrimaryKey,
								ConnectionString: SafeStringPtr(keysResp.PrimaryConnectionString),
							})
						}

						// Secondary key
						if keysResp.SecondaryKey != nil {
							results = append(results, ServiceBusKey{
								NamespaceName:    nsName,
								ResourceGroup:    rgName,
								Region:           region,
								KeyName:          ruleName,
								KeyType:          "Secondary",
								KeyValue:         *keysResp.SecondaryKey,
								ConnectionString: SafeStringPtr(keysResp.SecondaryConnectionString),
							})
						}
					}
				}
			}
		}
	}

	return results
}

// GetAppConfigKeys extracts access keys from App Configuration stores
func GetAppConfigKeys(session *SafeSession, subID string, resourceGroups []string) []AppConfigKey {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []AppConfigKey

	configClient, err := armappconfiguration.NewConfigurationStoresClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := configClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, store := range page.Value {
				storeName := SafeStringPtr(store.Name)
				region := SafeStringPtr(store.Location)

				// List keys
				keysPager := configClient.NewListKeysPager(rgName, storeName, nil)
				for keysPager.More() {
					keysPage, err := keysPager.NextPage(ctx)
					if err != nil {
						break
					}

					for _, key := range keysPage.Value {
						results = append(results, AppConfigKey{
							StoreName:        storeName,
							ResourceGroup:    rgName,
							Region:           region,
							KeyName:          SafeStringPtr(key.Name),
							ConnectionString: SafeStringPtr(key.ConnectionString),
						})
					}
				}
			}
		}
	}

	return results
}

// GetBatchAccountKeys extracts access keys from Batch accounts
func GetBatchAccountKeys(session *SafeSession, subID string, resourceGroups []string) []BatchAccountKey {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []BatchAccountKey

	batchClient, err := armbatch.NewAccountClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := batchClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, account := range page.Value {
				accountName := SafeStringPtr(account.Name)
				region := SafeStringPtr(account.Location)

				// Get keys
				keysResp, err := batchClient.GetKeys(ctx, rgName, accountName, nil)
				if err != nil {
					continue
				}

				// Primary key
				if keysResp.Primary != nil {
					results = append(results, BatchAccountKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						KeyType:       "Primary",
						KeyValue:      *keysResp.Primary,
					})
				}

				// Secondary key
				if keysResp.Secondary != nil {
					results = append(results, BatchAccountKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						KeyType:       "Secondary",
						KeyValue:      *keysResp.Secondary,
					})
				}
			}
		}
	}

	return results
}

// GetCognitiveServicesKeys extracts API keys from Cognitive Services (including OpenAI)
func GetCognitiveServicesKeys(session *SafeSession, subID string, resourceGroups []string) []CognitiveServicesKey {
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil
	}
	cred := &StaticTokenCredential{Token: token}
	ctx := context.Background()
	var results []CognitiveServicesKey

	cogClient, err := armcognitiveservices.NewAccountsClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	for _, rgName := range resourceGroups {
		pager := cogClient.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}

			for _, account := range page.Value {
				accountName := SafeStringPtr(account.Name)
				region := SafeStringPtr(account.Location)
				endpoint := ""
				if account.Properties != nil && account.Properties.Endpoint != nil {
					endpoint = *account.Properties.Endpoint
				}

				// Get keys
				keysResp, err := cogClient.ListKeys(ctx, rgName, accountName, nil)
				if err != nil {
					continue
				}

				// Key1
				if keysResp.Key1 != nil {
					results = append(results, CognitiveServicesKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						Endpoint:      endpoint,
						KeyType:       "Primary",
						KeyValue:      *keysResp.Key1,
					})
				}

				// Key2
				if keysResp.Key2 != nil {
					results = append(results, CognitiveServicesKey{
						AccountName:   accountName,
						ResourceGroup: rgName,
						Region:        region,
						Endpoint:      endpoint,
						KeyType:       "Secondary",
						KeyValue:      *keysResp.Key2,
					})
				}
			}
		}
	}

	return results
}

// containsSubstring checks if a string contains a substring
func containsSubstring(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// CURRENT SDK DOESNT SUPPORT...WAITING FOR NEWER VERSION
// GetStorageSASToken enumerates all SAS tokens / stored access policies for a subscription
//func GetStorageSASToken(subID string) []SASInfo {
//	ctx := context.Background()
//	cred := GetCredential()
//	if cred == nil {
//		return nil
//	}
//
//	var results []SASInfo
//
//	// Enumerate storage accounts
//	storageAccounts := GetStorageAccountsPerSubscription(subID)
//
//	for _, sa := range storageAccounts {
//		accountName := SafeStringPtr(sa.Name)
//		resourceGroup := "N/A"
//		if sa.ID != nil {
//			resourceGroup = GetResourceGroupNameFromID(*sa.ID)
//		}
//
//		location := ""
//		if sa.Location != nil {
//			location = string(*sa.Location)
//		}
//
//		kind := ""
//		if sa.Kind != nil {
//			kind = string(*sa.Kind)
//		}
//
//		// Use existing ListContainers helper
//		containers, err := ListContainers(ctx, subID, accountName, resourceGroup, location, kind, cred)
//		if err != nil {
//			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//				fmt.Printf("Failed to list containers for account %s: %v\n", accountName, err)
//			}
//			continue
//		}
//
//		blobClient, err := armstorage.NewBlobContainersClient(subID, cred, nil)
//		if err != nil {
//			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//				fmt.Printf("Failed to create BlobContainers client for account %s: %v\n", accountName, err)
//			}
//			continue
//		}
//
//		for _, c := range containers {
//			containerName := c.Name
//
//			// -------------------- List Stored Access Policies --------------------
//			resp, err := blobClient.GetAccessPolicy(ctx, resourceGroup, accountName, containerName, nil)
//			if err != nil {
//				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//					fmt.Printf("Failed to get access policy for container %s: %v\n", containerName, err)
//				}
//				continue
//			}
//
//			for _, identifier := range resp.SignedIdentifiers {
//				results = append(results, SASInfo{
//					AccountName:   accountName,
//					ResourceGroup: resourceGroup,
//					ContainerName: containerName,
//					PolicyName:    SafeString(identifier.ID),
//					Identifier:    SafeString(identifier.ID),
//					Permissions:   SafeString(identifier.AccessPolicy.Permissions),
//				})
//			}
//		}
//	}
//
//	return results
//}
