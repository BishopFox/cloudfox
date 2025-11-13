package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzAccessKeysCommand = &cobra.Command{
	Use:     "access-keys",
	Aliases: []string{"keys", "certs"},
	Short:   "Enumerate Azure access keys and certificates",
	Long: `
Enumerate Azure access keys and certificates for a specific tenant:
./cloudfox az accesskeys --tenant TENANT_ID

Enumerate Azure access keys and certificates for a specific subscription:
./cloudfox az accesskeys --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListAccessKeys,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type AccessKeysModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions  []string
	AccessKeysRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type AccessKeysOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AccessKeysOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AccessKeysOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListAccessKeys(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_ACCESSKEYS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &AccessKeysModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		AccessKeysRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"accesskeys-commands":                   {Name: "accesskeys-commands", Contents: ""},
			"accesskeys-certificate-usage-commands": {Name: "accesskeys-certificate-usage-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintAccessKeys(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *AccessKeysModule) PrintAccessKeys(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_ACCESSKEYS_MODULE_NAME)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_ACCESSKEYS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_ACCESSKEYS_MODULE_NAME, m.processSubscription)

			// Enumerate app registration credentials (tenant-level: both secrets and certificates)
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM("Enumerating app registration credentials...", globals.AZ_ACCESSKEYS_MODULE_NAME)
			}
			m.processAppRegistrationCredentials(ctx, logger)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating access keys for %d subscription(s)", len(m.Subscriptions)), globals.AZ_ACCESSKEYS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_ACCESSKEYS_MODULE_NAME, m.processSubscription)

		// Enumerate app registration credentials (tenant-level: both secrets and certificates)
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM("Enumerating app registration credentials...", globals.AZ_ACCESSKEYS_MODULE_NAME)
		}
		m.processAppRegistrationCredentials(ctx, logger)
	}

	// Generate certificate usage documentation
	m.generateCertificateUsageLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *AccessKeysModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()

	// -------------------- Subscription-level operations (after RG processing) --------------------
	m.processSubscriptionLevelKeys(ctx, subID, subName)
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *AccessKeysModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Storage Accounts
	storageAccounts := azinternal.GetStorageAccountsPerResourceGroup(m.Session, subID, rgName)
	for _, sa := range storageAccounts {
		saName := azinternal.SafeStringPtr(sa.Name)
		saRG := "N/A"
		region := "N/A"
		if sa.ID != nil {
			saRG = azinternal.GetResourceGroupFromID(*sa.ID)
		}
		if sa.Location != nil {
			region = *sa.Location
		}
		if m.ResourceGroupFlag != "" && saRG != rgName {
			continue
		}

		keys := azinternal.GetStorageAccountKeys(m.Session, subID, saName, saRG)
		for _, key := range keys {
			m.mu.Lock()
			m.AccessKeysRows = append(m.AccessKeysRows, []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				saRG,
				region,
				saName,
				"Storage Account",
				"N/A",
				key.KeyName,
				"Storage Account Key",
				key.Value,
				"N/A",
				"Never",
				key.Permission,
			})

			// Loot
			m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
				"## Storage Account: %s, Key: %s\n"+
					"# Az CLI:\n"+
					"az account set --subscription %s\n"+
					"az storage account keys list --account-name %s --resource-group %s\n"+
					"# PowerShell:\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"Get-AzStorageAccountKey -Name %s -ResourceGroupName %s\n\n",
				saName, key.KeyName, subID, saName, saRG, subID, saName, saRG)
			m.mu.Unlock()
		}
	}

	// Key Vaults
	keyVaults, err := azinternal.GetKeyVaultsPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get KeyVaults for subscription %s: %v", subID, err), globals.AZ_KEYVAULT_MODULE_NAME)
		}
		return
	}

	for _, kv := range keyVaults {
		if m.ResourceGroupFlag != "" && !strings.Contains(m.ResourceGroupFlag, kv.ResourceGroup) {
			continue
		}
		kvName := kv.VaultName
		kvRG := kv.ResourceGroup
		region := "N/A"
		if kv.Region != "" {
			region = kv.Region
		}

		certs, err := azinternal.GetCertificatesPerKeyVault(ctx, m.Session, fmt.Sprintf("https://%s.vault.azure.net/", kvName))
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Failed to get certificates for vault %s: %v", kvName, err), globals.AZ_KEYVAULT_MODULE_NAME)
			}
			continue
		}

		for _, cert := range certs {
			m.mu.Lock()
			m.AccessKeysRows = append(m.AccessKeysRows, []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				kvRG,
				region,
				kvName,
				"Key Vault",
				"N/A",
				cert.Name,
				"Key Vault Certificate",
				cert.Thumbprint,
				"N/A",
				cert.ExpiresOn,
				"N/A",
			})

			// Loot
			m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
				"## Key Vault: %s, Certificate: %s\n"+
					"# Az CLI:\n"+
					"az account set --subscription %s\n"+
					"az keyvault certificate show --vault-name %s --name %s\n"+
					"# PowerShell:\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"Get-AzKeyVaultCertificate -VaultName %s -Name %s\n\n",
				kvName, cert.Name, subID, kvName, cert.Name, subID, kvName, cert.Name)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Process subscription-level keys (service principals, event hubs, Get-AzPasswords additions, etc.)
// ------------------------------
func (m *AccessKeysModule) processSubscriptionLevelKeys(ctx context.Context, subID, subName string) {
	resourceGroups := m.ResolveResourceGroups(subID)

	// ==================== ORIGINAL EXTRACTORS ====================
	// Service Principals (AD Apps)
	apps := azinternal.GetServicePrincipalsPerSubscription(ctx, m.Session, subID)
	for _, app := range apps {
		appName := azinternal.SafeString(app.DisplayName)
		appID := azinternal.SafeString(app.AppID)

		// Secrets
		secrets := azinternal.GetServicePrincipalSecrets(ctx, m.Session, appID)
		for _, sec := range secrets {
			m.mu.Lock()
			azinternal.AddServicePrincipalSecret(nil, nil, &m.AccessKeysRows, m.LootMap, "accesskeys-commands", m.TenantName, m.TenantID, subID, subName, appName, appID, sec.DisplayName, sec.KeyID, sec.EndDate)
			m.mu.Unlock()
		}

		// Certificates
		certs := azinternal.GetServicePrincipalCertificates(ctx, m.Session, appID)
		for _, cert := range certs {
			m.mu.Lock()
			azinternal.AddServicePrincipalCertificate(nil, nil, &m.AccessKeysRows, m.LootMap, "accesskeys-commands", m.TenantName, m.TenantID, subID, subName, appName, appID, cert.Name, cert.Thumbprint, cert.ExpiryDate)
			m.mu.Unlock()
		}
	}

	// Event Hubs / Service Bus SAS tokens (subscription-scoped)
	ehSASTokens := azinternal.GetEventHubSASTokens(m.Session, subID)
	for _, sas := range ehSASTokens {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			sas.ResourceGroup,
			sas.Region,
			sas.ResourceName,
			"Event Hub / Service Bus",
			"N/A",
			sas.PolicyName,
			"Event Hub / Service Bus SAS Token",
			sas.Identifier,
			"N/A",
			"Never",
			sas.Permissions,
		})

		// Loot
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## Event Hub / Service Bus SAS: %s, Policy: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az eventhubs authorization-rule list --resource-group %s --namespace-name %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzEventHubAuthorizationRule -ResourceGroupName %s -Namespace %s\n\n",
			sas.ResourceName, sas.PolicyName, subID, sas.ResourceGroup, sas.ResourceName, subID, sas.ResourceGroup, sas.ResourceName)
		m.mu.Unlock()
	}

	// ==================== GET-AZPASSWORDS ADDITIONS ====================

	// 1. ACR Admin Credentials
	acrCreds := azinternal.GetACRCredentials(m.Session, subID, resourceGroups)
	for _, acr := range acrCreds {
		// Password 1
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			acr.ResourceGroup,
			acr.Region,
			acr.RegistryName,
			"Container Registry",
			"N/A",
			acr.Username + "-password",
			"ACR Admin Password",
			acr.Password,
			"N/A",
			"Never",
			"ReadWrite",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## ACR: %s, Username: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az acr credential show --name %s --resource-group %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzContainerRegistryCredential -Name %s -ResourceGroupName %s\n\n",
			acr.RegistryName, acr.Username, subID, acr.RegistryName, acr.ResourceGroup, subID, acr.RegistryName, acr.ResourceGroup)
		m.mu.Unlock()

		// Password 2
		if acr.Password2 != "" {
			m.mu.Lock()
			m.AccessKeysRows = append(m.AccessKeysRows, []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				acr.ResourceGroup,
				acr.Region,
				acr.RegistryName,
				"Container Registry",
				"N/A",
				acr.Username + "-password2",
				"ACR Admin Password",
				acr.Password2,
				"N/A",
				"Never",
				"ReadWrite",
			})
			m.mu.Unlock()
		}
	}

	// 2. CosmosDB Keys
	cosmosKeys := azinternal.GetCosmosDBKeys(m.Session, subID, resourceGroups)
	for _, key := range cosmosKeys {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			key.ResourceGroup,
			key.Region,
			key.AccountName,
			"Cosmos DB Account",
			"N/A",
			key.KeyType,
			"CosmosDB Key",
			key.KeyValue,
			"N/A",
			"Never",
			"ReadWrite",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## CosmosDB: %s, Key: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az cosmosdb keys list --name %s --resource-group %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzCosmosDBAccountKey -Name %s -ResourceGroupName %s\n\n",
			key.AccountName, key.KeyType, subID, key.AccountName, key.ResourceGroup, subID, key.AccountName, key.ResourceGroup)
		m.mu.Unlock()
	}

	// 3. Function App Keys
	funcKeys := azinternal.GetFunctionAppKeys(m.Session, subID, resourceGroups)
	for _, key := range funcKeys {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			key.ResourceGroup,
			key.Region,
			key.AppName,
			"Function App",
			"N/A",
			key.KeyName,
			"Function App " + key.KeyType,
			key.KeyValue,
			"N/A",
			"Never",
			"Execute",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## Function App: %s, Key: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az functionapp keys list --name %s --resource-group %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzFunctionAppSetting -Name %s -ResourceGroupName %s\n\n",
			key.AppName, key.KeyName, subID, key.AppName, key.ResourceGroup, subID, key.AppName, key.ResourceGroup)
		m.mu.Unlock()
	}

	// 4. Container App Secrets
	containerSecrets := azinternal.GetContainerAppSecrets(m.Session, subID, resourceGroups)
	for _, secret := range containerSecrets {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			secret.ResourceGroup,
			secret.Region,
			secret.AppName,
			"Container App",
			"N/A",
			secret.SecretName,
			"Container App Secret",
			secret.SecretValue,
			"N/A",
			"Never",
			"N/A",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## Container App: %s, Secret: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az containerapp secret list --name %s --resource-group %s\n\n",
			secret.AppName, secret.SecretName, subID, secret.AppName, secret.ResourceGroup)
		m.mu.Unlock()
	}

	// 5. API Management Secrets
	apimSecrets := azinternal.GetAPIManagementSecrets(m.Session, subID, resourceGroups)
	for _, secret := range apimSecrets {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			secret.ResourceGroup,
			secret.Region,
			secret.ServiceName,
			"API Management",
			"N/A",
			secret.SecretName,
			"API Management Secret",
			secret.SecretValue,
			"N/A",
			"Never",
			"N/A",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## API Management: %s, Secret: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az apim nv show --service-name %s --resource-group %s --named-value-id %s\n\n",
			secret.ServiceName, secret.SecretName, subID, secret.ServiceName, secret.ResourceGroup, secret.SecretName)
		m.mu.Unlock()
	}

	// 6. Service Bus Keys
	serviceBusKeys := azinternal.GetServiceBusKeys(m.Session, subID, resourceGroups)
	for _, key := range serviceBusKeys {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			key.ResourceGroup,
			key.Region,
			key.NamespaceName,
			"Service Bus Namespace",
			"N/A",
			key.KeyName + "-" + key.KeyType,
			"Service Bus Key",
			key.KeyValue,
			"N/A",
			"Never",
			"Manage",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## Service Bus: %s, Key: %s (%s)\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az servicebus namespace authorization-rule keys list --namespace-name %s --resource-group %s --name %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzServiceBusKey -Namespace %s -ResourceGroupName %s -Name %s\n"+
				"# Connection String: %s\n\n",
			key.NamespaceName, key.KeyName, key.KeyType, subID, key.NamespaceName, key.ResourceGroup, key.KeyName,
			subID, key.NamespaceName, key.ResourceGroup, key.KeyName, key.ConnectionString)
		m.mu.Unlock()
	}

	// 7. App Configuration Keys
	appConfigKeys := azinternal.GetAppConfigKeys(m.Session, subID, resourceGroups)
	for _, key := range appConfigKeys {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			key.ResourceGroup,
			key.Region,
			key.StoreName,
			"App Configuration Store",
			"N/A",
			key.KeyName,
			"App Configuration Key",
			key.ConnectionString,
			"N/A",
			"Never",
			"ReadWrite",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## App Configuration: %s, Key: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az appconfig credential list --name %s --resource-group %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzAppConfigurationStoreKey -Name %s -ResourceGroupName %s\n\n",
			key.StoreName, key.KeyName, subID, key.StoreName, key.ResourceGroup, subID, key.StoreName, key.ResourceGroup)
		m.mu.Unlock()
	}

	// 8. Batch Account Keys
	batchKeys := azinternal.GetBatchAccountKeys(m.Session, subID, resourceGroups)
	for _, key := range batchKeys {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			key.ResourceGroup,
			key.Region,
			key.AccountName,
			"Batch Account",
			"N/A",
			key.KeyType,
			"Batch Account Key",
			key.KeyValue,
			"N/A",
			"Never",
			"FullAccess",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## Batch Account: %s, Key: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az batch account keys list --name %s --resource-group %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzBatchAccountKeys -AccountName %s\n\n",
			key.AccountName, key.KeyType, subID, key.AccountName, key.ResourceGroup, subID, key.AccountName)
		m.mu.Unlock()
	}

	// 9. Cognitive Services (OpenAI) Keys
	cognitiveKeys := azinternal.GetCognitiveServicesKeys(m.Session, subID, resourceGroups)
	for _, key := range cognitiveKeys {
		m.mu.Lock()
		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			key.ResourceGroup,
			key.Region,
			key.AccountName,
			"Cognitive Services Account",
			"N/A",
			key.KeyType,
			"Cognitive Services Key (OpenAI)",
			key.KeyValue,
			"N/A",
			"Never",
			"API Access",
		})
		m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
			"## Cognitive Services (OpenAI): %s, Key: %s\n"+
				"# Endpoint: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az cognitiveservices account keys list --name %s --resource-group %s\n"+
				"# PowerShell:\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzCognitiveServicesAccountKey -Name %s -ResourceGroupName %s\n\n",
			key.AccountName, key.KeyType, key.Endpoint, subID, key.AccountName, key.ResourceGroup, subID, key.AccountName, key.ResourceGroup)
		m.mu.Unlock()
	}
}

// ------------------------------
// Process app registration credentials (tenant-level)
// ------------------------------
func (m *AccessKeysModule) processAppRegistrationCredentials(ctx context.Context, logger internal.Logger) {
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Starting app registration credentials enumeration...", globals.AZ_ACCESSKEYS_MODULE_NAME)
	}

	credentials, err := azinternal.GetAppRegistrationCredentials(ctx, m.Session)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to enumerate app registration credentials: %v", err), globals.AZ_ACCESSKEYS_MODULE_NAME)

		// Provide specific guidance based on error type
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "429") || strings.Contains(errorMsg, "rate limited") || strings.Contains(errorMsg, "TooManyRequests") {
			logger.ErrorM("Microsoft Graph API rate limit exceeded - this is expected with many app registrations", globals.AZ_ACCESSKEYS_MODULE_NAME)
			logger.ErrorM("The tool implements retry logic, but the API may be throttling aggressively", globals.AZ_ACCESSKEYS_MODULE_NAME)
		} else if strings.Contains(errorMsg, "403") || strings.Contains(errorMsg, "Forbidden") {
			logger.ErrorM("This is due to insufficient Graph API permissions (Application.Read.All required)", globals.AZ_ACCESSKEYS_MODULE_NAME)
		} else if strings.Contains(errorMsg, "401") || strings.Contains(errorMsg, "Unauthorized") {
			logger.ErrorM("Authentication failed - token may have expired", globals.AZ_ACCESSKEYS_MODULE_NAME)
		}

		// Still process any partial results that were collected
		if len(credentials) == 0 {
			return
		}
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Processing %d partial credential(s) collected before error", len(credentials)), globals.AZ_ACCESSKEYS_MODULE_NAME)
		}
	}

	if len(credentials) == 0 {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM("No app registration credentials found (or no access)", globals.AZ_ACCESSKEYS_MODULE_NAME)
		}
		return
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d app registration credential(s)", len(credentials)), globals.AZ_ACCESSKEYS_MODULE_NAME)
	}

	// Add each credential as a row
	for _, cred := range credentials {
		m.mu.Lock()

		// Determine the key/cert type and identifier based on credential type
		var keyType, identifier string
		if cred.CredType == "Password" {
			keyType = "App Registration Client Secret"
			identifier = cred.ClientSecretHint
		} else {
			keyType = "App Registration Certificate"
			identifier = cred.Thumbprint
		}

		// Format timestamps and calculate status
		startTime := "N/A"
		endTime := "N/A"
		status := "Unknown"
		daysUntilExpiry := "N/A"
		credentialAge := "N/A"
		longLivedWarning := "No"

		var startTimeParsed, endTimeParsed time.Time
		var startErr, endErr error

		if cred.StartDateTime != "" {
			// Try parsing ISO8601/RFC3339 format
			startTimeParsed, startErr = time.Parse(time.RFC3339, cred.StartDateTime)
			if startErr == nil {
				startTime = startTimeParsed.Format("2006-01-02")
				// Calculate credential age
				ageInDays := int(time.Since(startTimeParsed).Hours() / 24)
				credentialAge = fmt.Sprintf("%d days", ageInDays)

				// Flag long-lived credentials (>365 days)
				if ageInDays > 365 {
					longLivedWarning = fmt.Sprintf("⚠ Yes (%d days old)", ageInDays)
				}
			} else {
				startTime = cred.StartDateTime
			}
		}

		if cred.EndDateTime != "" {
			// Try parsing ISO8601/RFC3339 format
			endTimeParsed, endErr = time.Parse(time.RFC3339, cred.EndDateTime)
			if endErr == nil {
				endTime = endTimeParsed.Format("2006-01-02")

				// Calculate days until expiry and status
				now := time.Now()
				daysRemaining := int(endTimeParsed.Sub(now).Hours() / 24)

				if daysRemaining < 0 {
					status = "✗ Expired"
					daysUntilExpiry = fmt.Sprintf("%d (EXPIRED)", daysRemaining)
				} else if daysRemaining <= 30 {
					status = "⚠ Expiring Soon"
					daysUntilExpiry = fmt.Sprintf("%d (< 30 days)", daysRemaining)
				} else {
					status = "✓ Active"
					daysUntilExpiry = fmt.Sprintf("%d", daysRemaining)
				}
			} else {
				endTime = cred.EndDateTime
			}
		} else {
			// No expiry date means it doesn't expire (some old secrets)
			status = "✓ Active"
			daysUntilExpiry = "No Expiry"
		}

		m.AccessKeysRows = append(m.AccessKeysRows, []string{
			m.TenantName,
			m.TenantID,
			"Tenant Level",     // Subscription ID -> Show "Tenant Level" for App Registrations
			m.TenantName,       // Subscription Name -> Tenant Name
			"N/A",              // Resource Group
			"Global",           // Region -> Global for tenant resources
			cred.AppName,       // Resource Name
			"App Registration", // Resource Type
			cred.AppID,         // Application ID
			cred.CredName,      // Key/Cert Name
			keyType,            // Key/Cert Type
			identifier,         // Identifier/Thumbprint
			startTime,          // Cert Start Time
			endTime,            // Cert Expiry
			status,             // Status (Active/Expired/Expiring Soon)
			daysUntilExpiry,    // Days Until Expiry
			credentialAge,      // Credential Age
			longLivedWarning,   // Long-Lived Warning (>365 days)
			cred.Permissions,   // Permissions/Scope - actual API permissions
		})

		// Add to loot
		if cred.CredType == "Password" {
			m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
				"## App Registration: %s (Client Secret)\n"+
					"# Application ID: %s\n"+
					"# Secret Name: %s\n"+
					"# Valid From: %s\n"+
					"# Expires: %s\n"+
					"# Permissions: %s\n"+
					"# NOTE: You cannot retrieve the secret value via API after creation.\n"+
					"# If you have the actual secret value, authenticate with:\n"+
					"# Az CLI:\n"+
					"az login --service-principal --username %s --tenant %s --password <SECRET_VALUE>\n"+
					"# PowerShell:\n"+
					"$SecurePassword = ConvertTo-SecureString -String '<SECRET_VALUE>' -AsPlainText -Force\n"+
					"$Credential = New-Object System.Management.Automation.PSCredential('%s', $SecurePassword)\n"+
					"Connect-AzAccount -ServicePrincipal -Credential $Credential -Tenant %s\n\n",
				cred.AppName, cred.AppID, cred.CredName,
				startTime, endTime, cred.Permissions, cred.AppID, m.TenantID, cred.AppID, m.TenantID)
		} else {
			m.LootMap["accesskeys-commands"].Contents += fmt.Sprintf(
				"## App Registration: %s (Certificate)\n"+
					"# Application ID: %s\n"+
					"# Certificate Name: %s\n"+
					"# Thumbprint: %s\n"+
					"# Valid From: %s\n"+
					"# Expires: %s\n"+
					"# Permissions: %s\n"+
					"# Az CLI:\n"+
					"az login --service-principal --username %s --tenant %s --certificate <CERT_PATH>\n"+
					"# PowerShell:\n"+
					"$cert = Get-Item Cert:\\CurrentUser\\My\\%s\n"+
					"Connect-AzAccount -ServicePrincipal -ApplicationId %s -TenantId %s -Certificate $cert\n\n",
				cred.AppName, cred.AppID, cred.CredName, cred.Thumbprint,
				startTime, endTime, cred.Permissions, cred.AppID, m.TenantID, cred.Thumbprint, cred.AppID, m.TenantID)
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Generate certificate usage documentation
// ------------------------------
func (m *AccessKeysModule) generateCertificateUsageLoot() {
	lf := m.LootMap["accesskeys-certificate-usage-commands"]

	// Check if we have any certificates to document
	hasCertificates := false

	// Check if app registration certificates were found
	appRegCerts := m.LootMap["app-registration-certificates"]
	if appRegCerts != nil && appRegCerts.Contents != "" {
		hasCertificates = true
	}

	// Check if any service principal or key vault certificates are in the table
	for _, row := range m.AccessKeysRows {
		if len(row) >= 7 {
			keyType := row[6]
			if strings.Contains(keyType, "Certificate") {
				hasCertificates = true
				break
			}
		}
	}

	// If no certificates found, return
	if !hasCertificates {
		return
	}

	// Generate comprehensive certificate usage documentation
	lf.Contents += fmt.Sprintf("# Azure Certificate Authentication Usage Guide\n\n")
	lf.Contents += fmt.Sprintf("This guide provides detailed instructions for using discovered certificates to authenticate to Azure.\n")
	lf.Contents += fmt.Sprintf("Certificates can be used for service principal authentication and provide powerful access to Azure resources.\n\n")

	lf.Contents += fmt.Sprintf("## Table of Contents\n")
	lf.Contents += fmt.Sprintf("1. Extract Certificate from App Registration\n")
	lf.Contents += fmt.Sprintf("2. Azure CLI Authentication with Certificate\n")
	lf.Contents += fmt.Sprintf("3. PowerShell Authentication with Certificate\n")
	lf.Contents += fmt.Sprintf("4. Certificate Format Conversion (PFX to PEM)\n")
	lf.Contents += fmt.Sprintf("5. REST API Authentication with Certificate\n")
	lf.Contents += fmt.Sprintf("6. Using Key Vault Certificates\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 1: Extract Certificate from App Registration
	lf.Contents += fmt.Sprintf("## 1. Extract Certificate from App Registration\n\n")

	lf.Contents += fmt.Sprintf("If you have access to an app registration with an embedded PFX certificate,\n")
	lf.Contents += fmt.Sprintf("you can extract it using the Azure CLI or Microsoft Graph API.\n\n")

	lf.Contents += fmt.Sprintf("### Method 1: Using Azure CLI\n\n")
	lf.Contents += fmt.Sprintf("# List all credentials for an application\n")
	lf.Contents += fmt.Sprintf("az ad app credential list --id <APP-ID>\n\n")

	lf.Contents += fmt.Sprintf("# The 'customKeyIdentifier' field contains base64-encoded certificate data\n")
	lf.Contents += fmt.Sprintf("# Extract and decode it to save as a PFX file\n\n")

	lf.Contents += fmt.Sprintf("### Method 2: Using Microsoft Graph API\n\n")
	lf.Contents += fmt.Sprintf("TENANT_ID=<YOUR-TENANT-ID>\n")
	lf.Contents += fmt.Sprintf("APP_ID=<TARGET-APP-ID>\n")
	lf.Contents += fmt.Sprintf("ACCESS_TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)\n\n")

	lf.Contents += fmt.Sprintf("# Get application details including keyCredentials\n")
	lf.Contents += fmt.Sprintf("curl -X GET \"https://graph.microsoft.com/v1.0/applications?\\$filter=appId eq '$APP_ID'&\\$select=keyCredentials\" \\\n")
	lf.Contents += fmt.Sprintf("  -H \"Authorization: Bearer $ACCESS_TOKEN\"\n\n")

	lf.Contents += fmt.Sprintf("# The 'key' field in keyCredentials contains base64-encoded certificate (PFX or CER)\n")
	lf.Contents += fmt.Sprintf("# If the size is > 2000 bytes, it's likely a PFX with embedded private key\n\n")

	lf.Contents += fmt.Sprintf("# Save the base64 data to a file and decode it\n")
	lf.Contents += fmt.Sprintf("echo \"<BASE64-CERT-DATA>\" | base64 -d > certificate.pfx\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 2: Azure CLI Authentication
	lf.Contents += fmt.Sprintf("## 2. Azure CLI Authentication with Certificate\n\n")

	lf.Contents += fmt.Sprintf("Once you have the certificate file, you can authenticate using az login.\n\n")

	lf.Contents += fmt.Sprintf("### Using PEM Certificate (Linux/macOS)\n\n")
	lf.Contents += fmt.Sprintf("TENANT_ID=<TENANT-ID>\n")
	lf.Contents += fmt.Sprintf("APP_ID=<APPLICATION-CLIENT-ID>\n")
	lf.Contents += fmt.Sprintf("CERT_PATH=/path/to/certificate.pem\n\n")

	lf.Contents += fmt.Sprintf("# Login with service principal using certificate\n")
	lf.Contents += fmt.Sprintf("az login --service-principal \\\n")
	lf.Contents += fmt.Sprintf("  --username $APP_ID \\\n")
	lf.Contents += fmt.Sprintf("  --tenant $TENANT_ID \\\n")
	lf.Contents += fmt.Sprintf("  --certificate $CERT_PATH\n\n")

	lf.Contents += fmt.Sprintf("# If certificate is password-protected\n")
	lf.Contents += fmt.Sprintf("az login --service-principal \\\n")
	lf.Contents += fmt.Sprintf("  --username $APP_ID \\\n")
	lf.Contents += fmt.Sprintf("  --tenant $TENANT_ID \\\n")
	lf.Contents += fmt.Sprintf("  --certificate $CERT_PATH \\\n")
	lf.Contents += fmt.Sprintf("  --password <CERT-PASSWORD>\n\n")

	lf.Contents += fmt.Sprintf("# After successful login, list subscriptions\n")
	lf.Contents += fmt.Sprintf("az account list\n\n")

	lf.Contents += fmt.Sprintf("# Set active subscription\n")
	lf.Contents += fmt.Sprintf("az account set --subscription <SUBSCRIPTION-ID>\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 3: PowerShell Authentication
	lf.Contents += fmt.Sprintf("## 3. PowerShell Authentication with Certificate\n\n")

	lf.Contents += fmt.Sprintf("### Method 1: Using Certificate from File\n\n")
	lf.Contents += fmt.Sprintf("$tenantId = \"<TENANT-ID>\"\n")
	lf.Contents += fmt.Sprintf("$appId = \"<APPLICATION-CLIENT-ID>\"\n")
	lf.Contents += fmt.Sprintf("$certPath = \"C:\\path\\to\\certificate.pfx\"\n")
	lf.Contents += fmt.Sprintf("$certPassword = ConvertTo-SecureString -String \"<PASSWORD>\" -AsPlainText -Force\n\n")

	lf.Contents += fmt.Sprintf("# Load certificate from PFX file\n")
	lf.Contents += fmt.Sprintf("$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, $certPassword)\n\n")

	lf.Contents += fmt.Sprintf("# Connect to Azure with certificate\n")
	lf.Contents += fmt.Sprintf("Connect-AzAccount -ServicePrincipal `\n")
	lf.Contents += fmt.Sprintf("  -TenantId $tenantId `\n")
	lf.Contents += fmt.Sprintf("  -ApplicationId $appId `\n")
	lf.Contents += fmt.Sprintf("  -Certificate $cert\n\n")

	lf.Contents += fmt.Sprintf("### Method 2: Using Certificate from Certificate Store\n\n")
	lf.Contents += fmt.Sprintf("# First, import certificate to Windows Certificate Store\n")
	lf.Contents += fmt.Sprintf("$certPath = \"C:\\path\\to\\certificate.pfx\"\n")
	lf.Contents += fmt.Sprintf("$certPassword = ConvertTo-SecureString -String \"<PASSWORD>\" -AsPlainText -Force\n")
	lf.Contents += fmt.Sprintf("Import-PfxCertificate -FilePath $certPath -CertStoreLocation Cert:\\CurrentUser\\My -Password $certPassword\n\n")

	lf.Contents += fmt.Sprintf("# Get certificate by thumbprint\n")
	lf.Contents += fmt.Sprintf("$thumbprint = \"<CERTIFICATE-THUMBPRINT>\"\n")
	lf.Contents += fmt.Sprintf("$cert = Get-Item Cert:\\CurrentUser\\My\\$thumbprint\n\n")

	lf.Contents += fmt.Sprintf("# Connect to Azure\n")
	lf.Contents += fmt.Sprintf("Connect-AzAccount -ServicePrincipal `\n")
	lf.Contents += fmt.Sprintf("  -TenantId $tenantId `\n")
	lf.Contents += fmt.Sprintf("  -ApplicationId $appId `\n")
	lf.Contents += fmt.Sprintf("  -Certificate $cert\n\n")

	lf.Contents += fmt.Sprintf("# List available subscriptions\n")
	lf.Contents += fmt.Sprintf("Get-AzSubscription\n\n")

	lf.Contents += fmt.Sprintf("# Set active subscription\n")
	lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId <SUBSCRIPTION-ID>\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 4: Certificate Format Conversion
	lf.Contents += fmt.Sprintf("## 4. Certificate Format Conversion (PFX to PEM)\n\n")

	lf.Contents += fmt.Sprintf("Azure CLI on Linux/macOS requires PEM format. Convert PFX to PEM using OpenSSL.\n\n")

	lf.Contents += fmt.Sprintf("### Convert PFX to PEM (with private key)\n\n")
	lf.Contents += fmt.Sprintf("# Extract private key and certificate to PEM format\n")
	lf.Contents += fmt.Sprintf("openssl pkcs12 -in certificate.pfx -out certificate.pem -nodes\n\n")

	lf.Contents += fmt.Sprintf("# If you want to encrypt the private key in the PEM file\n")
	lf.Contents += fmt.Sprintf("openssl pkcs12 -in certificate.pfx -out certificate.pem\n\n")

	lf.Contents += fmt.Sprintf("### Extract only the private key\n\n")
	lf.Contents += fmt.Sprintf("openssl pkcs12 -in certificate.pfx -nocerts -out private-key.pem -nodes\n\n")

	lf.Contents += fmt.Sprintf("### Extract only the certificate (public key)\n\n")
	lf.Contents += fmt.Sprintf("openssl pkcs12 -in certificate.pfx -nokeys -out certificate-only.pem\n\n")

	lf.Contents += fmt.Sprintf("### Convert PEM back to PFX\n\n")
	lf.Contents += fmt.Sprintf("openssl pkcs12 -export -out certificate.pfx \\\n")
	lf.Contents += fmt.Sprintf("  -inkey private-key.pem \\\n")
	lf.Contents += fmt.Sprintf("  -in certificate-only.pem\n\n")

	lf.Contents += fmt.Sprintf("### Get certificate thumbprint\n\n")
	lf.Contents += fmt.Sprintf("openssl x509 -in certificate.pem -fingerprint -noout | sed 's/://g'\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 5: REST API Authentication
	lf.Contents += fmt.Sprintf("## 5. REST API Authentication with Certificate\n\n")

	lf.Contents += fmt.Sprintf("Use certificates to obtain access tokens for direct REST API calls.\n\n")

	lf.Contents += fmt.Sprintf("### Generate JWT Assertion with Certificate\n\n")
	lf.Contents += fmt.Sprintf("# This is a complex process. Here's a Python example using PyJWT:\n\n")

	lf.Contents += fmt.Sprintf("```python\n")
	lf.Contents += fmt.Sprintf("import jwt\n")
	lf.Contents += fmt.Sprintf("import time\n")
	lf.Contents += fmt.Sprintf("import requests\n")
	lf.Contents += fmt.Sprintf("from cryptography.hazmat.primitives import serialization\n")
	lf.Contents += fmt.Sprintf("from cryptography.hazmat.backends import default_backend\n\n")

	lf.Contents += fmt.Sprintf("# Configuration\n")
	lf.Contents += fmt.Sprintf("tenant_id = \"<TENANT-ID>\"\n")
	lf.Contents += fmt.Sprintf("client_id = \"<APP-ID>\"\n")
	lf.Contents += fmt.Sprintf("cert_thumbprint = \"<CERT-THUMBPRINT>\"\n")
	lf.Contents += fmt.Sprintf("private_key_path = \"private-key.pem\"\n\n")

	lf.Contents += fmt.Sprintf("# Load private key\n")
	lf.Contents += fmt.Sprintf("with open(private_key_path, 'rb') as key_file:\n")
	lf.Contents += fmt.Sprintf("    private_key = serialization.load_pem_private_key(\n")
	lf.Contents += fmt.Sprintf("        key_file.read(),\n")
	lf.Contents += fmt.Sprintf("        password=None,\n")
	lf.Contents += fmt.Sprintf("        backend=default_backend()\n")
	lf.Contents += fmt.Sprintf("    )\n\n")

	lf.Contents += fmt.Sprintf("# Create JWT assertion\n")
	lf.Contents += fmt.Sprintf("now = int(time.time())\n")
	lf.Contents += fmt.Sprintf("claims = {\n")
	lf.Contents += fmt.Sprintf("    'aud': f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',\n")
	lf.Contents += fmt.Sprintf("    'exp': now + 3600,\n")
	lf.Contents += fmt.Sprintf("    'iss': client_id,\n")
	lf.Contents += fmt.Sprintf("    'jti': '<UNIQUE-JWT-ID>',\n")
	lf.Contents += fmt.Sprintf("    'nbf': now,\n")
	lf.Contents += fmt.Sprintf("    'sub': client_id\n")
	lf.Contents += fmt.Sprintf("}\n\n")

	lf.Contents += fmt.Sprintf("# Sign JWT with certificate\n")
	lf.Contents += fmt.Sprintf("headers = {'x5t': cert_thumbprint}\n")
	lf.Contents += fmt.Sprintf("assertion = jwt.encode(claims, private_key, algorithm='RS256', headers=headers)\n\n")

	lf.Contents += fmt.Sprintf("# Request access token\n")
	lf.Contents += fmt.Sprintf("token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'\n")
	lf.Contents += fmt.Sprintf("data = {\n")
	lf.Contents += fmt.Sprintf("    'client_id': client_id,\n")
	lf.Contents += fmt.Sprintf("    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',\n")
	lf.Contents += fmt.Sprintf("    'client_assertion': assertion,\n")
	lf.Contents += fmt.Sprintf("    'scope': 'https://management.azure.com/.default',\n")
	lf.Contents += fmt.Sprintf("    'grant_type': 'client_credentials'\n")
	lf.Contents += fmt.Sprintf("}\n\n")

	lf.Contents += fmt.Sprintf("response = requests.post(token_url, data=data)\n")
	lf.Contents += fmt.Sprintf("access_token = response.json().get('access_token')\n")
	lf.Contents += fmt.Sprintf("print(f'Access Token: {access_token}')\n")
	lf.Contents += fmt.Sprintf("```\n\n")

	lf.Contents += fmt.Sprintf("### Using cURL (with pre-generated JWT)\n\n")
	lf.Contents += fmt.Sprintf("TENANT_ID=<TENANT-ID>\n")
	lf.Contents += fmt.Sprintf("CLIENT_ID=<APP-ID>\n")
	lf.Contents += fmt.Sprintf("JWT_ASSERTION=<GENERATED-JWT-ASSERTION>\n\n")

	lf.Contents += fmt.Sprintf("curl -X POST \"https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token\" \\\n")
	lf.Contents += fmt.Sprintf("  -H \"Content-Type: application/x-www-form-urlencoded\" \\\n")
	lf.Contents += fmt.Sprintf("  -d \"client_id=$CLIENT_ID\" \\\n")
	lf.Contents += fmt.Sprintf("  -d \"client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\" \\\n")
	lf.Contents += fmt.Sprintf("  -d \"client_assertion=$JWT_ASSERTION\" \\\n")
	lf.Contents += fmt.Sprintf("  -d \"scope=https://management.azure.com/.default\" \\\n")
	lf.Contents += fmt.Sprintf("  -d \"grant_type=client_credentials\"\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 6: Using Key Vault Certificates
	lf.Contents += fmt.Sprintf("## 6. Using Key Vault Certificates\n\n")

	lf.Contents += fmt.Sprintf("If certificates are stored in Azure Key Vault, you can export them (if you have permissions).\n\n")

	lf.Contents += fmt.Sprintf("### Export Certificate from Key Vault (Azure CLI)\n\n")
	lf.Contents += fmt.Sprintf("VAULT_NAME=<KEY-VAULT-NAME>\n")
	lf.Contents += fmt.Sprintf("CERT_NAME=<CERTIFICATE-NAME>\n\n")

	lf.Contents += fmt.Sprintf("# Download certificate (public key only)\n")
	lf.Contents += fmt.Sprintf("az keyvault certificate download \\\n")
	lf.Contents += fmt.Sprintf("  --vault-name $VAULT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --name $CERT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --file certificate.cer\n\n")

	lf.Contents += fmt.Sprintf("# Get certificate as base64-encoded PEM\n")
	lf.Contents += fmt.Sprintf("az keyvault certificate show \\\n")
	lf.Contents += fmt.Sprintf("  --vault-name $VAULT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --name $CERT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query 'cer' -o tsv | base64 -d > certificate.cer\n\n")

	lf.Contents += fmt.Sprintf("# NOTE: Private keys cannot be exported from Key Vault via Azure CLI\n")
	lf.Contents += fmt.Sprintf("# However, if the certificate was imported as a PFX, you may be able to\n")
	lf.Contents += fmt.Sprintf("# retrieve it using the Key Vault Secret API (the certificate is stored as a secret)\n\n")

	lf.Contents += fmt.Sprintf("# Get certificate with private key (if stored as secret)\n")
	lf.Contents += fmt.Sprintf("az keyvault secret show \\\n")
	lf.Contents += fmt.Sprintf("  --vault-name $VAULT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --name $CERT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query 'value' -o tsv | base64 -d > certificate.pfx\n\n")

	lf.Contents += fmt.Sprintf("### Export Certificate from Key Vault (PowerShell)\n\n")
	lf.Contents += fmt.Sprintf("$vaultName = \"<KEY-VAULT-NAME>\"\n")
	lf.Contents += fmt.Sprintf("$certName = \"<CERTIFICATE-NAME>\"\n\n")

	lf.Contents += fmt.Sprintf("# Get certificate (public key)\n")
	lf.Contents += fmt.Sprintf("$cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $certName\n")
	lf.Contents += fmt.Sprintf("$certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)\n")
	lf.Contents += fmt.Sprintf("[System.IO.File]::WriteAllBytes(\"certificate.cer\", $certBytes)\n\n")

	lf.Contents += fmt.Sprintf("# Get certificate with private key (from secret)\n")
	lf.Contents += fmt.Sprintf("$secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $certName\n")
	lf.Contents += fmt.Sprintf("$secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(\n")
	lf.Contents += fmt.Sprintf("    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)\n")
	lf.Contents += fmt.Sprintf(")\n")
	lf.Contents += fmt.Sprintf("$certBytes = [System.Convert]::FromBase64String($secretValueText)\n")
	lf.Contents += fmt.Sprintf("[System.IO.File]::WriteAllBytes(\"certificate.pfx\", $certBytes)\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Summary section
	lf.Contents += fmt.Sprintf("## Summary\n\n")
	lf.Contents += fmt.Sprintf("Certificates provide a powerful method for authenticating to Azure as service principals.\n")
	lf.Contents += fmt.Sprintf("The permissions available depend on the role assignments of the service principal.\n\n")

	lf.Contents += fmt.Sprintf("**Common post-authentication actions:**\n\n")
	lf.Contents += fmt.Sprintf("1. List subscriptions: `az account list` or `Get-AzSubscription`\n")
	lf.Contents += fmt.Sprintf("2. Check permissions: `az role assignment list --assignee <APP-ID>` or `Get-AzRoleAssignment -ObjectId <SP-OBJECT-ID>`\n")
	lf.Contents += fmt.Sprintf("3. Enumerate resources: `az resource list` or `Get-AzResource`\n")
	lf.Contents += fmt.Sprintf("4. Check Azure AD permissions: `az ad app permission list --id <APP-ID>`\n\n")

	lf.Contents += fmt.Sprintf("**Security Considerations:**\n\n")
	lf.Contents += fmt.Sprintf("- Certificate-based authentication is logged in Azure AD sign-in logs\n")
	lf.Contents += fmt.Sprintf("- Service principal activity is logged in Azure Activity Logs\n")
	lf.Contents += fmt.Sprintf("- Certificates may have expiration dates - check EndDateTime\n")
	lf.Contents += fmt.Sprintf("- Some service principals may have MFA or Conditional Access policies\n\n")
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *AccessKeysModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.AccessKeysRows) == 0 {
		logger.InfoM("No Access Keys found", globals.AZ_ACCESSKEYS_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Resource Name",
		"Resource Type",
		"Application ID",
		"Key/Cert Name",
		"Key/Cert Type",
		"Identifier/Thumbprint",
		"Cert Start Time",
		"Cert Expiry",
		"Status",
		"Days Until Expiry",
		"Credential Age",
		"Long-Lived (>365 days)",
		"Permissions/Scope",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.AccessKeysRows, headers,
			"accesskeys", globals.AZ_ACCESSKEYS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.AccessKeysRows, headers,
			"accesskeys", globals.AZ_ACCESSKEYS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := AccessKeysOutput{
		Table: []internal.TableFile{{
			Name:   "accesskeys",
			Header: headers,
			Body:   m.AccessKeysRows,
		}},
		Loot: loot,
	}

	// Determine output scope (single subscription vs tenant-wide consolidation)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart (automatic streaming for large datasets)
	if err := internal.HandleOutputSmart(
		"Azure",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIDs,
		scopeNames,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_ACCESSKEYS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Access Key(s) across %d subscription(s)", len(m.AccessKeysRows), len(m.Subscriptions)), globals.AZ_ACCESSKEYS_MODULE_NAME)
}
