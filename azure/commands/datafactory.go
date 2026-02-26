package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzDataFactoryCommand = &cobra.Command{
	Use:     "datafactory",
	Aliases: []string{"data-factory", "adf"},
	Short:   "Enumerate Azure Data Factory instances",
	Long: `
Enumerate Azure Data Factory for a specific tenant:
  ./cloudfox az datafactory --tenant TENANT_ID

Enumerate Azure Data Factory for a specific subscription:
  ./cloudfox az datafactory --subscription SUBSCRIPTION_ID`,
	Run: ListDataFactory,
}

// ------------------------------
// Module struct
// ------------------------------
type DataFactoryModule struct {
	azinternal.BaseAzureModule

	Subscriptions   []string
	DataFactoryRows [][]string
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type DataFactoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataFactoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataFactoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListDataFactory(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_DATAFACTORY_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &DataFactoryModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		DataFactoryRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"datafactory-commands":        {Name: "datafactory-commands", Contents: ""},
			"datafactory-identities":      {Name: "datafactory-identities", Contents: "# Azure Data Factory Managed Identities\n\n"},
			"datafactory-pipelines":       {Name: "datafactory-pipelines", Contents: "# Azure Data Factory Pipelines\n\n"},
			"datafactory-linked-services": {Name: "datafactory-linked-services", Contents: "# Azure Data Factory Linked Services (Connection Strings)\n\n"},
			"datafactory-datasets":        {Name: "datafactory-datasets", Contents: "# Azure Data Factory Datasets\n\n"},
			"datafactory-triggers":        {Name: "datafactory-triggers", Contents: "# Azure Data Factory Triggers\n\n"},
		},
	}

	module.PrintDataFactory(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *DataFactoryModule) PrintDataFactory(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_DATAFACTORY_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_DATAFACTORY_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *DataFactoryModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups using BaseAzureModule helper
	rgNames := m.ResolveResourceGroups(subID)
	if len(rgNames) == 0 {
		return
	}

	// Create Data Factory client
	dfClient, err := azinternal.GetDataFactoryClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Data Factory client for subscription %s: %v", subID, err), globals.AZ_DATAFACTORY_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rgName := range rgNames {
		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, dfClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *DataFactoryModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, dfClient *armdatafactory.FactoriesClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	// List Data Factories in resource group
	pager := dfClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list Data Factories in %s/%s: %v", subID, rgName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, factory := range page.Value {
			m.processFactory(ctx, subID, subName, rgName, region, factory, dfClient, logger)
		}
	}
}

// ------------------------------
// Process single Data Factory
// ------------------------------
func (m *DataFactoryModule) processFactory(ctx context.Context, subID, subName, rgName, region string, factory *armdatafactory.Factory, dfClient *armdatafactory.FactoriesClient, logger internal.Logger) {
	if factory == nil || factory.Name == nil {
		return
	}

	factoryName := *factory.Name

	// Extract factory properties
	provisioningState := "N/A"
	if factory.Properties != nil && factory.Properties.ProvisioningState != nil {
		provisioningState = *factory.Properties.ProvisioningState
	}

	createTime := "N/A"
	if factory.Properties != nil && factory.Properties.CreateTime != nil {
		createTime = factory.Properties.CreateTime.Format("2006-01-02 15:04:05")
	}

	version := "N/A"
	if factory.Properties != nil && factory.Properties.Version != nil {
		version = *factory.Properties.Version
	}

	// Public/Private access
	publicNetworkAccess := "Enabled"
	if factory.Properties != nil && factory.Properties.PublicNetworkAccess != nil {
		publicNetworkAccess = string(*factory.Properties.PublicNetworkAccess)
	}

	// Encryption settings (Customer Managed Key)
	cmkEnabled := "Disabled"
	keyVaultURL := "N/A"
	keyName := "N/A"
	if factory.Properties != nil && factory.Properties.Encryption != nil {
		cmkEnabled = "Enabled"
		if factory.Properties.Encryption.VaultBaseURL != nil {
			keyVaultURL = *factory.Properties.Encryption.VaultBaseURL
		}
		if factory.Properties.Encryption.KeyName != nil {
			keyName = *factory.Properties.Encryption.KeyName
		}
	}

	// Managed identity
	systemAssignedID := "N/A"
	userAssignedIDs := "N/A"
	if factory.Identity != nil {
		if factory.Identity.Type != nil {
			idType := string(*factory.Identity.Type)
			if strings.Contains(idType, "SystemAssigned") && factory.Identity.PrincipalID != nil {
				systemAssignedID = *factory.Identity.PrincipalID
			}
		}
		if factory.Identity.UserAssignedIdentities != nil && len(factory.Identity.UserAssignedIdentities) > 0 {
			uaIDs := []string{}
			for uaID := range factory.Identity.UserAssignedIdentities {
				uaIDs = append(uaIDs, azinternal.ExtractResourceName(uaID))
			}
			userAssignedIDs = strings.Join(uaIDs, ", ")
		}
	}

	// Git integration
	gitIntegration := "Disabled"
	gitRepoType := "N/A"
	if factory.Properties != nil && factory.Properties.RepoConfiguration != nil {
		gitIntegration = "Enabled"
		// Try to determine if it's GitHub or Azure DevOps
		repoConfig := factory.Properties.RepoConfiguration
		switch repoConfig.(type) {
		case *armdatafactory.FactoryGitHubConfiguration:
			gitRepoType = "GitHub"
		case *armdatafactory.FactoryVSTSConfiguration:
			gitRepoType = "Azure DevOps"
		default:
			gitRepoType = "Unknown"
		}
	}

	// Purview integration
	purviewIntegration := "Disabled"
	purviewResourceID := "N/A"
	if factory.Properties != nil && factory.Properties.PurviewConfiguration != nil && factory.Properties.PurviewConfiguration.PurviewResourceID != nil {
		purviewIntegration = "Enabled"
		purviewResourceID = *factory.Properties.PurviewConfiguration.PurviewResourceID
	}

	// EntraID Centralized Auth - Data Factory uses AAD authentication by default
	entraIDAuth := "Enabled" // Data Factory always uses Azure AD for authentication

	// Construct management endpoint
	// Format: {factoryName}.{region}.datafactory.azure.net
	managementEndpoint := "N/A"
	if factoryName != "" && region != "" {
		managementEndpoint = fmt.Sprintf("%s.%s.datafactory.azure.net", factoryName, region)
	}

	// ==================== ENUMERATE PIPELINES ====================
	pipelineCount := 0
	pipelines := m.enumeratePipelines(ctx, subID, rgName, factoryName, logger)
	pipelineCount = len(pipelines)

	// ==================== ENUMERATE LINKED SERVICES ====================
	linkedServiceCount := 0
	linkedServices := m.enumerateLinkedServices(ctx, subID, rgName, factoryName, logger)
	linkedServiceCount = len(linkedServices)

	// ==================== ENUMERATE DATASETS ====================
	datasetCount := 0
	datasets := m.enumerateDatasets(ctx, subID, rgName, factoryName, logger)
	datasetCount = len(datasets)

	// ==================== ENUMERATE TRIGGERS ====================
	triggerCount := 0
	triggers := m.enumerateTriggers(ctx, subID, rgName, factoryName, logger)
	triggerCount = len(triggers)

	// ==================== ENUMERATE INTEGRATION RUNTIMES ====================
	integrationRuntimeType := m.getIntegrationRuntimeTypes(ctx, subID, rgName, factoryName, logger)

	// ==================== SECURITY RECOMMENDATIONS ====================
	securityRecommendations := m.generateSecurityRecommendations(
		publicNetworkAccess, cmkEnabled, gitIntegration, linkedServiceCount, systemAssignedID,
	)

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		factoryName,
		managementEndpoint,
		provisioningState,
		createTime,
		version,
		publicNetworkAccess,
		cmkEnabled,
		keyVaultURL,
		keyName,
		gitIntegration,
		gitRepoType,
		purviewIntegration,
		entraIDAuth,
		systemAssignedID,
		userAssignedIDs,
		// NEW COLUMNS
		fmt.Sprintf("%d", pipelineCount),
		fmt.Sprintf("%d", linkedServiceCount),
		fmt.Sprintf("%d", datasetCount),
		fmt.Sprintf("%d", triggerCount),
		integrationRuntimeType,
		securityRecommendations,
	}

	m.mu.Lock()
	m.DataFactoryRows = append(m.DataFactoryRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate loot
	m.generateLoot(subID, subName, rgName, factoryName, managementEndpoint, publicNetworkAccess, systemAssignedID, userAssignedIDs, gitIntegration, gitRepoType, purviewResourceID, pipelines, linkedServices, datasets, triggers)
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *DataFactoryModule) generateLoot(subID, subName, rgName, factoryName, managementEndpoint, publicNetworkAccess, systemAssignedID, userAssignedIDs, gitIntegration, gitRepoType, purviewResourceID string, pipelines, linkedServices, datasets, triggers []map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Azure CLI commands
	m.LootMap["datafactory-commands"].Contents += fmt.Sprintf("# Data Factory: %s (Resource Group: %s)\n", factoryName, rgName)
	m.LootMap["datafactory-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["datafactory-commands"].Contents += fmt.Sprintf("az datafactory show --name %s --resource-group %s\n", factoryName, rgName)
	m.LootMap["datafactory-commands"].Contents += fmt.Sprintf("az datafactory pipeline list --factory-name %s --resource-group %s -o table\n", factoryName, rgName)
	m.LootMap["datafactory-commands"].Contents += fmt.Sprintf("az datafactory linked-service list --factory-name %s --resource-group %s -o table\n", factoryName, rgName)
	m.LootMap["datafactory-commands"].Contents += fmt.Sprintf("az datafactory dataset list --factory-name %s --resource-group %s -o table\n", factoryName, rgName)
	m.LootMap["datafactory-commands"].Contents += fmt.Sprintf("az datafactory trigger list --factory-name %s --resource-group %s -o table\n\n", factoryName, rgName)

	// Managed identities for identity tracking
	if systemAssignedID != "N/A" || userAssignedIDs != "N/A" {
		m.LootMap["datafactory-identities"].Contents += fmt.Sprintf("# Factory: %s/%s\n", rgName, factoryName)
		m.LootMap["datafactory-identities"].Contents += fmt.Sprintf("Subscription: %s\n", subName)
		if systemAssignedID != "N/A" {
			m.LootMap["datafactory-identities"].Contents += fmt.Sprintf("System Assigned Identity: %s\n", systemAssignedID)
		}
		if userAssignedIDs != "N/A" {
			m.LootMap["datafactory-identities"].Contents += fmt.Sprintf("User Assigned Identities: %s\n", userAssignedIDs)
		}
		m.LootMap["datafactory-identities"].Contents += "\n"
	}

	// ==================== PIPELINES LOOT ====================
	if len(pipelines) > 0 {
		m.LootMap["datafactory-pipelines"].Contents += fmt.Sprintf("## Data Factory: %s/%s\n", rgName, factoryName)
		m.LootMap["datafactory-pipelines"].Contents += fmt.Sprintf("Subscription: %s (%s)\n", subName, subID)
		m.LootMap["datafactory-pipelines"].Contents += fmt.Sprintf("Pipeline Count: %d\n\n", len(pipelines))

		for _, pipeline := range pipelines {
			pipelineName := "unknown"
			if name, ok := pipeline["name"].(string); ok {
				pipelineName = name
			}

			m.LootMap["datafactory-pipelines"].Contents += fmt.Sprintf("### Pipeline: %s\n", pipelineName)

			// Extract activities if available
			if props, ok := pipeline["properties"].(map[string]interface{}); ok {
				if activities, ok := props["activities"].([]interface{}); ok {
					m.LootMap["datafactory-pipelines"].Contents += fmt.Sprintf("Activities: %d\n", len(activities))
					for _, activity := range activities {
						if actMap, ok := activity.(map[string]interface{}); ok {
							if actName, ok := actMap["name"].(string); ok {
								actType := "N/A"
								if actTypeVal, ok := actMap["type"].(string); ok {
									actType = actTypeVal
								}
								m.LootMap["datafactory-pipelines"].Contents += fmt.Sprintf("  - %s (Type: %s)\n", actName, actType)
							}
						}
					}
				}

				// Scan pipeline parameters for secrets
				if parameters, ok := props["parameters"].(map[string]interface{}); ok && len(parameters) > 0 {
					m.LootMap["datafactory-pipelines"].Contents += "Parameters:\n"
					for paramName := range parameters {
						m.LootMap["datafactory-pipelines"].Contents += fmt.Sprintf("  - %s\n", paramName)
					}
				}
			}

			m.LootMap["datafactory-pipelines"].Contents += "\n"
		}
		m.LootMap["datafactory-pipelines"].Contents += "---\n\n"
	}

	// ==================== LINKED SERVICES LOOT ====================
	if len(linkedServices) > 0 {
		m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("## Data Factory: %s/%s\n", rgName, factoryName)
		m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("Subscription: %s (%s)\n", subName, subID)
		m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("Linked Service Count: %d\n\n", len(linkedServices))

		for _, linkedService := range linkedServices {
			lsName := "unknown"
			if name, ok := linkedService["name"].(string); ok {
				lsName = name
			}

			lsType := "unknown"
			if props, ok := linkedService["properties"].(map[string]interface{}); ok {
				if lsTypeVal, ok := props["type"].(string); ok {
					lsType = lsTypeVal
				}
			}

			m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("### Linked Service: %s\n", lsName)
			m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("Type: %s\n", lsType)

			// Scan for connection strings and secrets
			if props, ok := linkedService["properties"].(map[string]interface{}); ok {
				if typeProps, ok := props["typeProperties"].(map[string]interface{}); ok {
					// Check for connection string
					if connStr, ok := typeProps["connectionString"].(string); ok {
						// Scan for secrets in connection string
						secretMatches := azinternal.ScanScriptContent(connStr, fmt.Sprintf("%s/%s [%s]", rgName, factoryName, lsName), "connection-string")
						if len(secretMatches) > 0 {
							m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("⚠️ Connection String (DETECTED SECRETS):\n%s\n\n", connStr)
							m.LootMap["datafactory-linked-services"].Contents += "Detected Secrets:\n"
							for _, match := range secretMatches {
								m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("  - %s: %s (Severity: %s)\n", match.Pattern, match.Match, match.Severity)
							}
						} else {
							m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("Connection String: %s\n", connStr)
						}
					}

					// Check for other sensitive properties
					sensitiveKeys := []string{"password", "accountKey", "servicePrincipalKey", "accessToken", "apiKey", "sasToken"}
					for _, key := range sensitiveKeys {
						if val, ok := typeProps[key]; ok {
							m.LootMap["datafactory-linked-services"].Contents += fmt.Sprintf("⚠️ %s: %v (SECURITY-SENSITIVE)\n", key, val)
						}
					}
				}
			}

			m.LootMap["datafactory-linked-services"].Contents += "\n"
		}
		m.LootMap["datafactory-linked-services"].Contents += "---\n\n"
	}

	// ==================== DATASETS LOOT ====================
	if len(datasets) > 0 {
		m.LootMap["datafactory-datasets"].Contents += fmt.Sprintf("## Data Factory: %s/%s\n", rgName, factoryName)
		m.LootMap["datafactory-datasets"].Contents += fmt.Sprintf("Subscription: %s (%s)\n", subName, subID)
		m.LootMap["datafactory-datasets"].Contents += fmt.Sprintf("Dataset Count: %d\n\n", len(datasets))

		for _, dataset := range datasets {
			dsName := "unknown"
			if name, ok := dataset["name"].(string); ok {
				dsName = name
			}

			dsType := "unknown"
			linkedServiceName := "N/A"
			if props, ok := dataset["properties"].(map[string]interface{}); ok {
				if dsTypeVal, ok := props["type"].(string); ok {
					dsType = dsTypeVal
				}
				if linkedService, ok := props["linkedServiceName"].(map[string]interface{}); ok {
					if refName, ok := linkedService["referenceName"].(string); ok {
						linkedServiceName = refName
					}
				}
			}

			m.LootMap["datafactory-datasets"].Contents += fmt.Sprintf("### Dataset: %s\n", dsName)
			m.LootMap["datafactory-datasets"].Contents += fmt.Sprintf("Type: %s\n", dsType)
			m.LootMap["datafactory-datasets"].Contents += fmt.Sprintf("Linked Service: %s\n\n", linkedServiceName)
		}
		m.LootMap["datafactory-datasets"].Contents += "---\n\n"
	}

	// ==================== TRIGGERS LOOT ====================
	if len(triggers) > 0 {
		m.LootMap["datafactory-triggers"].Contents += fmt.Sprintf("## Data Factory: %s/%s\n", rgName, factoryName)
		m.LootMap["datafactory-triggers"].Contents += fmt.Sprintf("Subscription: %s (%s)\n", subName, subID)
		m.LootMap["datafactory-triggers"].Contents += fmt.Sprintf("Trigger Count: %d\n\n", len(triggers))

		for _, trigger := range triggers {
			triggerName := "unknown"
			if name, ok := trigger["name"].(string); ok {
				triggerName = name
			}

			triggerType := "unknown"
			runtimeState := "N/A"
			if props, ok := trigger["properties"].(map[string]interface{}); ok {
				if triggerTypeVal, ok := props["type"].(string); ok {
					triggerType = triggerTypeVal
				}
				if runtimeStateVal, ok := props["runtimeState"].(string); ok {
					runtimeState = runtimeStateVal
				}
			}

			m.LootMap["datafactory-triggers"].Contents += fmt.Sprintf("### Trigger: %s\n", triggerName)
			m.LootMap["datafactory-triggers"].Contents += fmt.Sprintf("Type: %s\n", triggerType)
			m.LootMap["datafactory-triggers"].Contents += fmt.Sprintf("Runtime State: %s\n\n", runtimeState)
		}
		m.LootMap["datafactory-triggers"].Contents += "---\n\n"
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *DataFactoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.DataFactoryRows) == 0 {
		logger.InfoM("No Azure Data Factory instances found", globals.AZ_DATAFACTORY_MODULE_NAME)
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
		"Factory Name",
		"Management Endpoint",
		"Provisioning State",
		"Create Time",
		"Version",
		"Public Network Access",
		"CMK Enabled",
		"Key Vault URL",
		"Key Name",
		"Git Integration",
		"Git Repo Type",
		"Purview Integration",
		"EntraID Centralized Auth",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
		// NEW COLUMNS
		"Pipeline Count",
		"Linked Service Count",
		"Dataset Count",
		"Trigger Count",
		"Integration Runtime Type",
		"Security Recommendations",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.DataFactoryRows, headers,
			"datafactory", globals.AZ_DATAFACTORY_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.DataFactoryRows, headers,
			"datafactory", globals.AZ_DATAFACTORY_MODULE_NAME,
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
	output := DataFactoryOutput{
		Table: []internal.TableFile{{
			Name:   "datafactory",
			Header: headers,
			Body:   m.DataFactoryRows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_DATAFACTORY_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d Azure Data Factory instances across %d subscriptions", len(m.DataFactoryRows), len(m.Subscriptions)), globals.AZ_DATAFACTORY_MODULE_NAME)
}

// ==================== HELPER FUNCTIONS FOR PIPELINES/LINKED SERVICES ====================

// enumeratePipelines fetches all pipelines for a Data Factory
func (m *DataFactoryModule) enumeratePipelines(ctx context.Context, subID, rgName, factoryName string, logger internal.Logger) []map[string]interface{} {
	pipelineClient, err := azinternal.GetDataFactoryPipelinesClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Pipelines client for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
		}
		return nil
	}

	pipelines := []map[string]interface{}{}
	pager := pipelineClient.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list pipelines for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
			}
			break
		}

		for _, pipeline := range page.Value {
			pipelineMap := make(map[string]interface{})
			if pipeline.Name != nil {
				pipelineMap["name"] = *pipeline.Name
			}
			if pipeline.Properties != nil {
				propsMap := make(map[string]interface{})
				if pipeline.Properties.Activities != nil {
					propsMap["activities"] = pipeline.Properties.Activities
				}
				if pipeline.Properties.Parameters != nil {
					propsMap["parameters"] = pipeline.Properties.Parameters
				}
				pipelineMap["properties"] = propsMap
			}
			pipelines = append(pipelines, pipelineMap)
		}
	}
	return pipelines
}

// enumerateLinkedServices fetches all linked services for a Data Factory
func (m *DataFactoryModule) enumerateLinkedServices(ctx context.Context, subID, rgName, factoryName string, logger internal.Logger) []map[string]interface{} {
	linkedServiceClient, err := azinternal.GetDataFactoryLinkedServicesClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create LinkedServices client for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
		}
		return nil
	}

	linkedServices := []map[string]interface{}{}
	pager := linkedServiceClient.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list linked services for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
			}
			break
		}

		for _, linkedService := range page.Value {
			lsMap := make(map[string]interface{})
			if linkedService.Name != nil {
				lsMap["name"] = *linkedService.Name
			}
			if linkedService.Properties != nil {
				propsMap := make(map[string]interface{})

				// Get the type of linked service
				lsType := fmt.Sprintf("%T", linkedService.Properties)
				propsMap["type"] = strings.TrimPrefix(lsType, "*armdatafactory.")

				// Try to extract connection string or other sensitive properties
				// This is a simplified approach - in reality, each linked service type has different properties
				typePropsMap := make(map[string]interface{})

				// For Azure SQL Database
				if sqlLS, ok := linkedService.Properties.(*armdatafactory.AzureSQLDatabaseLinkedService); ok {
					if sqlLS.TypeProperties != nil && sqlLS.TypeProperties.ConnectionString != nil {
						if connStr, ok := sqlLS.TypeProperties.ConnectionString.(string); ok {
							typePropsMap["connectionString"] = connStr
						}
					}
				}

				// For Azure Blob Storage
				if blobLS, ok := linkedService.Properties.(*armdatafactory.AzureBlobStorageLinkedService); ok {
					if blobLS.TypeProperties != nil && blobLS.TypeProperties.ConnectionString != nil {
						if connStr, ok := blobLS.TypeProperties.ConnectionString.(string); ok {
							typePropsMap["connectionString"] = connStr
						}
					}
				}

				propsMap["typeProperties"] = typePropsMap
				lsMap["properties"] = propsMap
			}
			linkedServices = append(linkedServices, lsMap)
		}
	}
	return linkedServices
}

// enumerateDatasets fetches all datasets for a Data Factory
func (m *DataFactoryModule) enumerateDatasets(ctx context.Context, subID, rgName, factoryName string, logger internal.Logger) []map[string]interface{} {
	datasetClient, err := azinternal.GetDataFactoryDatasetsClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Datasets client for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
		}
		return nil
	}

	datasets := []map[string]interface{}{}
	pager := datasetClient.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list datasets for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
			}
			break
		}

		for _, dataset := range page.Value {
			dsMap := make(map[string]interface{})
			if dataset.Name != nil {
				dsMap["name"] = *dataset.Name
			}
			if dataset.Properties != nil {
				propsMap := make(map[string]interface{})
				dsType := fmt.Sprintf("%T", dataset.Properties)
				propsMap["type"] = strings.TrimPrefix(dsType, "*armdatafactory.")

				if dataset.Properties.GetDataset() != nil && dataset.Properties.GetDataset().LinkedServiceName != nil {
					lsMap := make(map[string]interface{})
					if dataset.Properties.GetDataset().LinkedServiceName.ReferenceName != nil {
						lsMap["referenceName"] = *dataset.Properties.GetDataset().LinkedServiceName.ReferenceName
					}
					propsMap["linkedServiceName"] = lsMap
				}
				dsMap["properties"] = propsMap
			}
			datasets = append(datasets, dsMap)
		}
	}
	return datasets
}

// enumerateTriggers fetches all triggers for a Data Factory
func (m *DataFactoryModule) enumerateTriggers(ctx context.Context, subID, rgName, factoryName string, logger internal.Logger) []map[string]interface{} {
	triggerClient, err := azinternal.GetDataFactoryTriggersClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Triggers client for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
		}
		return nil
	}

	triggers := []map[string]interface{}{}
	pager := triggerClient.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list triggers for %s: %v", factoryName, err), globals.AZ_DATAFACTORY_MODULE_NAME)
			}
			break
		}

		for _, trigger := range page.Value {
			triggerMap := make(map[string]interface{})
			if trigger.Name != nil {
				triggerMap["name"] = *trigger.Name
			}
			if trigger.Properties != nil {
				propsMap := make(map[string]interface{})
				triggerType := fmt.Sprintf("%T", trigger.Properties)
				propsMap["type"] = strings.TrimPrefix(triggerType, "*armdatafactory.")

				if trigger.Properties.GetTrigger() != nil && trigger.Properties.GetTrigger().RuntimeState != nil {
					propsMap["runtimeState"] = string(*trigger.Properties.GetTrigger().RuntimeState)
				}
				triggerMap["properties"] = propsMap
			}
			triggers = append(triggers, triggerMap)
		}
	}
	return triggers
}

// getIntegrationRuntimeTypes fetches integration runtime types
func (m *DataFactoryModule) getIntegrationRuntimeTypes(ctx context.Context, subID, rgName, factoryName string, logger internal.Logger) string {
	irClient, err := azinternal.GetDataFactoryIntegrationRuntimesClient(m.Session, subID)
	if err != nil {
		return "N/A"
	}

	irTypes := []string{}
	pager := irClient.NewListByFactoryPager(rgName, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, ir := range page.Value {
			if ir.Properties != nil {
				irType := fmt.Sprintf("%T", ir.Properties)
				irType = strings.TrimPrefix(irType, "*armdatafactory.")
				irType = strings.TrimSuffix(irType, "IntegrationRuntime")
				if !contains(irTypes, irType) {
					irTypes = append(irTypes, irType)
				}
			}
		}
	}

	if len(irTypes) == 0 {
		return "N/A"
	}
	return strings.Join(irTypes, ", ")
}

// generateSecurityRecommendations generates security recommendations
func (m *DataFactoryModule) generateSecurityRecommendations(publicNetworkAccess, cmkEnabled, gitIntegration string, linkedServiceCount int, systemAssignedID string) string {
	recommendations := []string{}

	if publicNetworkAccess == "Enabled" {
		recommendations = append(recommendations, "Public network access enabled")
	}

	if cmkEnabled == "Disabled" {
		recommendations = append(recommendations, "CMK encryption disabled")
	}

	if gitIntegration == "Disabled" {
		recommendations = append(recommendations, "No Git integration (IaC best practice)")
	}

	if linkedServiceCount > 0 && systemAssignedID == "N/A" {
		recommendations = append(recommendations, "No managed identity (use MI for linked services)")
	}

	if len(recommendations) == 0 {
		return "No recommendations"
	}

	return strings.Join(recommendations, "; ")
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
