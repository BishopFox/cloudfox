package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzSynapseCommand = &cobra.Command{
	Use:     "synapse",
	Aliases: []string{"synapse-analytics"},
	Short:   "Enumerate Azure Synapse Analytics workspaces with comprehensive security analysis",
	Long: `
Enumerate Azure Synapse Analytics for a specific tenant:
  ./cloudfox az synapse --tenant TENANT_ID

Enumerate Synapse for a specific subscription:
  ./cloudfox az synapse --subscription SUBSCRIPTION_ID

ENHANCED FEATURES (requires Synapse workspace authentication):
  - Pipeline enumeration and activity analysis
  - Linked service credential and connection string analysis
  - Integration runtime security analysis
  - SQL/Spark pool configuration review
  - Comprehensive REST API examples for manual analysis

NOTE: This module enumerates workspaces, pools via Azure ARM. To access pipelines,
      linked services, and integration runtimes, use the generated loot files with
      Synapse workspace authentication (Azure AD token or SQL authentication).`,
	Run: ListSynapse,
}

// ------------------------------
// Module struct
// ------------------------------
type SynapseModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions []string
	SynapseRows   [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

type SynapseInfo struct {
	SubscriptionID      string
	SubscriptionName    string
	ResourceGroup       string
	Region              string
	WorkspaceName       string
	ResourceType        string // Workspace, SQL Pool, Spark Pool
	ResourceName        string
	Endpoint            string
	PublicPrivate       string
	SystemAssignedID    string
	UserAssignedIDs     string
	SystemAssignedRoles string
	UserAssignedRoles   string
}

// ------------------------------
// Output struct
// ------------------------------
type SynapseOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SynapseOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SynapseOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListSynapse(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_SYNAPSE_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &SynapseModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		SynapseRows:     [][]string{},
		LootMap: map[string]*internal.LootFile{
			"synapse-commands":             {Name: "synapse-commands", Contents: ""},
			"synapse-connection-strings":   {Name: "synapse-connection-strings", Contents: ""},
			"synapse-rest-api":             {Name: "synapse-rest-api", Contents: "# Synapse REST API Examples\n\n"},
			"synapse-pipelines":            {Name: "synapse-pipelines", Contents: "# Synapse Pipeline Analysis\n\n"},
			"synapse-linked-services":      {Name: "synapse-linked-services", Contents: "# Synapse Linked Service Credential Analysis\n\n"},
			"synapse-integration-runtimes": {Name: "synapse-integration-runtimes", Contents: "# Synapse Integration Runtime Security Analysis\n\n"},
		},
	}

	module.PrintSynapse(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *SynapseModule) PrintSynapse(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_SYNAPSE_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_SYNAPSE_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *SynapseModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_SYNAPSE_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	workspaceClient, err := armsynapse.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Synapse workspace client: %v", err), globals.AZ_SYNAPSE_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	sqlPoolClient, err := armsynapse.NewSQLPoolsClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create SQL pool client: %v", err), globals.AZ_SYNAPSE_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	sparkPoolClient, err := armsynapse.NewBigDataPoolsClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Spark pool client: %v", err), globals.AZ_SYNAPSE_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	resourceGroups := m.ResolveResourceGroups(subID)

	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, workspaceClient, sqlPoolClient, sparkPoolClient, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *SynapseModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, workspaceClient *armsynapse.WorkspacesClient, sqlPoolClient *armsynapse.SQLPoolsClient, sparkPoolClient *armsynapse.BigDataPoolsClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	for _, r := range rgs {
		if r.Name != nil && *r.Name == rgName && r.Location != nil {
			region = *r.Location
			break
		}
	}

	// List workspaces
	pager := workspaceClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list Synapse workspaces in RG %s: %v", rgName, err), globals.AZ_SYNAPSE_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, workspace := range page.Value {
			m.processWorkspace(ctx, workspace, subID, subName, rgName, region, sqlPoolClient, sparkPoolClient, logger)
		}
	}
}

// ------------------------------
// Process single workspace
// ------------------------------
func (m *SynapseModule) processWorkspace(ctx context.Context, workspace *armsynapse.Workspace, subID, subName, rgName, region string, sqlPoolClient *armsynapse.SQLPoolsClient, sparkPoolClient *armsynapse.BigDataPoolsClient, logger internal.Logger) {
	workspaceName := azinternal.SafeStringPtr(workspace.Name)
	workspaceEndpoint := "N/A"
	sqlEndpoint := "N/A"
	sqlOnDemandEndpoint := "N/A"
	devEndpoint := "N/A"
	publicPrivate := "Unknown"

	if workspace.Properties != nil {
		if workspace.Properties.ConnectivityEndpoints != nil {
			if workspace.Properties.ConnectivityEndpoints["web"] != nil {
				workspaceEndpoint = *workspace.Properties.ConnectivityEndpoints["web"]
			}
			if workspace.Properties.ConnectivityEndpoints["sql"] != nil {
				sqlEndpoint = *workspace.Properties.ConnectivityEndpoints["sql"]
			}
			if workspace.Properties.ConnectivityEndpoints["sqlOnDemand"] != nil {
				sqlOnDemandEndpoint = *workspace.Properties.ConnectivityEndpoints["sqlOnDemand"]
			}
			if workspace.Properties.ConnectivityEndpoints["dev"] != nil {
				devEndpoint = *workspace.Properties.ConnectivityEndpoints["dev"]
			}
		}

		// Determine public/private
		if workspace.Properties.PublicNetworkAccess != nil {
			if *workspace.Properties.PublicNetworkAccess == armsynapse.WorkspacePublicNetworkAccessEnabled {
				publicPrivate = "Public"
			} else {
				publicPrivate = "Private"
			}
		}
	}

	// Check for EntraID Centralized Auth (Azure AD-only authentication)
	entraIDAuth := "Disabled"
	if workspace.Properties != nil && workspace.Properties.AzureADOnlyAuthentication != nil {
		if *workspace.Properties.AzureADOnlyAuthentication {
			entraIDAuth = "Enabled"
		}
	}

	// Extract managed identity information
	var systemAssignedIDs []string
	var userAssignedIDs []string

	if workspace.Identity != nil {
		if workspace.Identity.PrincipalID != nil {
			principalID := *workspace.Identity.PrincipalID
			systemAssignedIDs = append(systemAssignedIDs, principalID)
		}

		if workspace.Identity.UserAssignedIdentities != nil {
			for uaID := range workspace.Identity.UserAssignedIdentities {
				userAssignedIDs = append(userAssignedIDs, uaID)
			}
		}
	}

	// Format identity fields
	sysID := "N/A"
	if len(systemAssignedIDs) > 0 {
		sysID = strings.Join(systemAssignedIDs, "\n")
	}
	userIDs := "N/A"
	if len(userAssignedIDs) > 0 {
		userIDs = strings.Join(userAssignedIDs, "\n")
	}

	// Add workspace row
	workspaceRow := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		workspaceName,
		"Workspace",
		workspaceName,
		workspaceEndpoint,
		publicPrivate,
		entraIDAuth,
		sysID,
		userIDs,
	}

	m.mu.Lock()
	m.SynapseRows = append(m.SynapseRows, workspaceRow)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate workspace loot
	m.generateWorkspaceLoot(subID, rgName, workspaceName, workspaceEndpoint, sqlEndpoint, sqlOnDemandEndpoint, devEndpoint)

	// Enumerate SQL Pools (Dedicated)
	m.enumerateSQLPools(ctx, subID, subName, rgName, region, workspaceName, entraIDAuth, sqlPoolClient, logger)

	// Enumerate Spark Pools
	m.enumerateSparkPools(ctx, subID, subName, rgName, region, workspaceName, entraIDAuth, sparkPoolClient, logger)
}

// ------------------------------
// Enumerate SQL Pools
// ------------------------------
func (m *SynapseModule) enumerateSQLPools(ctx context.Context, subID, subName, rgName, region, workspaceName, entraIDAuth string, sqlPoolClient *armsynapse.SQLPoolsClient, logger internal.Logger) {
	pager := sqlPoolClient.NewListByWorkspacePager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, pool := range page.Value {
			poolName := azinternal.SafeStringPtr(pool.Name)
			endpoint := fmt.Sprintf("%s.sql.azuresynapse.net", workspaceName)
			publicPrivate := "Public" // SQL pools use workspace network settings

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				region,
				workspaceName,
				"Dedicated SQL Pool",
				poolName,
				endpoint,
				publicPrivate,
				entraIDAuth, // SQL pools inherit workspace auth settings
				"N/A",       // SQL pools inherit workspace identity
				"N/A",
			}

			m.mu.Lock()
			m.SynapseRows = append(m.SynapseRows, row)
			m.mu.Unlock()
			m.CommandCounter.Total++

			// Generate SQL pool loot
			m.generateSQLPoolLoot(subID, rgName, workspaceName, poolName, endpoint)
		}
	}
}

// ------------------------------
// Enumerate Spark Pools
// ------------------------------
func (m *SynapseModule) enumerateSparkPools(ctx context.Context, subID, subName, rgName, region, workspaceName, entraIDAuth string, sparkPoolClient *armsynapse.BigDataPoolsClient, logger internal.Logger) {
	pager := sparkPoolClient.NewListByWorkspacePager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, pool := range page.Value {
			poolName := azinternal.SafeStringPtr(pool.Name)
			endpoint := fmt.Sprintf("%s.dev.azuresynapse.net", workspaceName)
			publicPrivate := "Public" // Spark pools use workspace network settings

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				region,
				workspaceName,
				"Spark Pool",
				poolName,
				endpoint,
				publicPrivate,
				entraIDAuth, // Spark pools inherit workspace auth settings
				"N/A",       // Spark pools inherit workspace identity
				"N/A",
			}

			m.mu.Lock()
			m.SynapseRows = append(m.SynapseRows, row)
			m.mu.Unlock()
			m.CommandCounter.Total++

			// Generate Spark pool loot
			m.generateSparkPoolLoot(subID, rgName, workspaceName, poolName, endpoint)
		}
	}
}

// ------------------------------
// Generate workspace loot
// ------------------------------
func (m *SynapseModule) generateWorkspaceLoot(subID, rgName, workspaceName, workspaceEndpoint, sqlEndpoint, sqlOnDemandEndpoint, devEndpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["synapse-commands"].Contents += fmt.Sprintf(
		"## Synapse Workspace: %s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Get workspace details\n"+
			"az synapse workspace show \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# List SQL pools\n"+
			"az synapse sql pool list \\\n"+
			"  --resource-group %s \\\n"+
			"  --workspace-name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# List Spark pools\n"+
			"az synapse spark pool list \\\n"+
			"  --resource-group %s \\\n"+
			"  --workspace-name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# Get workspace firewall rules\n"+
			"az synapse workspace firewall-rule list \\\n"+
			"  --resource-group %s \\\n"+
			"  --workspace-name %s\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"\n"+
			"# Get workspace\n"+
			"Get-AzSynapseWorkspace -ResourceGroupName %s -Name %s\n"+
			"\n"+
			"# List SQL pools\n"+
			"Get-AzSynapseSqlPool -ResourceGroupName %s -WorkspaceName %s\n"+
			"\n"+
			"# List Spark pools\n"+
			"Get-AzSynapseSparkPool -ResourceGroupName %s -WorkspaceName %s\n\n",
		workspaceName, rgName,
		subID,
		rgName, workspaceName,
		rgName, workspaceName,
		rgName, workspaceName,
		rgName, workspaceName,
		subID,
		rgName, workspaceName,
		rgName, workspaceName,
		rgName, workspaceName,
	)

	m.LootMap["synapse-connection-strings"].Contents += fmt.Sprintf(
		"## Synapse Workspace: %s\n"+
			"Workspace Endpoint: %s\n"+
			"SQL Endpoint: %s\n"+
			"SQL On-Demand Endpoint (Serverless): %s\n"+
			"Dev Endpoint: %s\n"+
			"\n"+
			"# SQL Connection String (Dedicated Pool - use pool name as database)\n"+
			"Server=%s;Database=<POOL_NAME>;Authentication=Active Directory Integrated;\n"+
			"\n"+
			"# SQL On-Demand Connection String (Serverless)\n"+
			"Server=%s;Database=master;Authentication=Active Directory Integrated;\n"+
			"\n",
		workspaceName,
		workspaceEndpoint,
		sqlEndpoint,
		sqlOnDemandEndpoint,
		devEndpoint,
		sqlEndpoint,
		sqlOnDemandEndpoint,
	)

	// Add comprehensive REST API documentation
	m.LootMap["synapse-rest-api"].Contents += fmt.Sprintf(
		"## Workspace: %s (%s)\n\n"+
			"### Authentication\n"+
			"# Get Azure AD token for Synapse (use dev endpoint)\n"+
			"export SYNAPSE_TOKEN=$(az account get-access-token --resource https://dev.azuresynapse.net --query accessToken -o tsv)\n\n"+
			"### Core API Endpoints\n\n"+
			"# List all pipelines\n"+
			"curl -X GET %s/pipelines?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# Get pipeline definition\n"+
			"curl -X GET %s/pipelines/<PIPELINE_NAME>?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# List all linked services\n"+
			"curl -X GET %s/linkedservices?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# Get linked service definition\n"+
			"curl -X GET %s/linkedservices/<LINKED_SERVICE_NAME>?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# List all integration runtimes\n"+
			"curl -X GET %s/integrationRuntimes?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# List all datasets\n"+
			"curl -X GET %s/datasets?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# List all triggers\n"+
			"curl -X GET %s/triggers?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# List all notebooks\n"+
			"curl -X GET %s/notebooks?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n"+
			"# List SQL scripts\n"+
			"curl -X GET %s/sqlScripts?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\"\n\n",
		workspaceName, workspaceEndpoint,
		workspaceEndpoint, workspaceEndpoint, workspaceEndpoint, workspaceEndpoint,
		workspaceEndpoint, workspaceEndpoint, workspaceEndpoint, workspaceEndpoint, workspaceEndpoint,
	)

	// Add pipeline enumeration and analysis guidance
	m.LootMap["synapse-pipelines"].Contents += fmt.Sprintf(
		"## Workspace: %s\n\n"+
			"### Enumerate Pipelines\n"+
			"# List all pipelines using Azure CLI\n"+
			"az synapse pipeline list \\\n"+
			"  --workspace-name %s \\\n"+
			"  --output table\n\n"+
			"# Get pipeline definition\n"+
			"az synapse pipeline show \\\n"+
			"  --workspace-name %s \\\n"+
			"  --name <PIPELINE_NAME> \\\n"+
			"  --output json | jq .\n\n"+
			"### REST API Method\n"+
			"curl -X GET %s/pipelines?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\" | jq .\n\n"+
			"# Get specific pipeline\n"+
			"curl -X GET %s/pipelines/<PIPELINE_NAME>?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\" | jq .\n\n"+
			"### Security Analysis - Pipeline Activities\n"+
			"# Check for:\n"+
			"# 1. Copy activities with embedded credentials\n"+
			"# 2. Web activities with API keys in headers\n"+
			"# 3. Script activities with hardcoded secrets\n"+
			"# 4. Custom activities with credential parameters\n"+
			"# 5. Parameters exposed in pipeline definitions\n\n"+
			"# Example: Extract all Copy activity sources/sinks\n"+
			"az synapse pipeline list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.activities[].type == \"Copy\") | \\\n"+
			"  {name, activities: [.properties.activities[] | select(.type == \"Copy\") | \\\n"+
			"  {name, source: .typeProperties.source, sink: .typeProperties.sink}]}'\n\n"+
			"# Example: Find Web activities (potential API key exposure)\n"+
			"az synapse pipeline list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.activities[].type == \"WebActivity\") | \\\n"+
			"  {name, activities: [.properties.activities[] | select(.type == \"WebActivity\") | \\\n"+
			"  {name, url: .typeProperties.url, method: .typeProperties.method, headers: .typeProperties.headers}]}'\n\n"+
			"# Example: Extract pipeline parameters (potential secret exposure)\n"+
			"az synapse pipeline list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | {name, parameters: .properties.parameters}'\n\n"+
			"### Secret Scanning Patterns\n"+
			"# Scan pipeline definitions for secrets\n"+
			"# Export all pipelines and scan for:\n\n"+
			"# Connection strings\n"+
			"jq -r '.. | select(type==\"string\") | select(test(\"DefaultEndpointsProtocol|AccountKey=\"))' pipelines.json\n\n"+
			"# API keys\n"+
			"jq -r '.. | select(type==\"string\") | select(test(\"api[_-]?key|apikey\"; \"i\"))' pipelines.json\n\n"+
			"# Passwords\n"+
			"jq -r '.. | select(type==\"string\") | select(test(\"password|pwd=\"; \"i\"))' pipelines.json\n\n"+
			"# SAS tokens\n"+
			"jq -r '.. | select(type==\"string\") | select(test(\"sig=\"))' pipelines.json\n\n",
		workspaceName,
		workspaceName, workspaceName,
		workspaceEndpoint, workspaceEndpoint,
		workspaceName, workspaceName, workspaceName,
	)

	// Add linked service credential analysis
	m.LootMap["synapse-linked-services"].Contents += fmt.Sprintf(
		"## Workspace: %s\n\n"+
			"### Enumerate Linked Services\n"+
			"# List all linked services using Azure CLI\n"+
			"az synapse linked-service list \\\n"+
			"  --workspace-name %s \\\n"+
			"  --output table\n\n"+
			"# Get linked service definition\n"+
			"az synapse linked-service show \\\n"+
			"  --workspace-name %s \\\n"+
			"  --name <LINKED_SERVICE_NAME> \\\n"+
			"  --output json | jq .\n\n"+
			"### REST API Method\n"+
			"curl -X GET %s/linkedservices?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\" | jq .\n\n"+
			"# Get specific linked service\n"+
			"curl -X GET %s/linkedservices/<LINKED_SERVICE_NAME>?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\" | jq .\n\n"+
			"### Security Analysis - Credential Types\n"+
			"# Check for:\n"+
			"# 1. Linked services using connection strings (less secure)\n"+
			"# 2. Linked services using managed identity (more secure)\n"+
			"# 3. Linked services with Key Vault references (most secure)\n"+
			"# 4. Linked services with embedded passwords\n"+
			"# 5. SQL authentication vs Azure AD authentication\n\n"+
			"# Example: Identify connection string-based linked services\n"+
			"az synapse linked-service list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.typeProperties.connectionString != null) | \\\n"+
			"  {name, type: .properties.type, connectionString: .properties.typeProperties.connectionString}'\n\n"+
			"# Example: Identify managed identity-based linked services (SECURE)\n"+
			"az synapse linked-service list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.typeProperties.authenticationType == \"MSI\" or \\\n"+
			"  .properties.typeProperties.servicePrincipalCredentialType == \"ManagedIdentity\") | \\\n"+
			"  {name, type: .properties.type, auth: \"Managed Identity\"}'\n\n"+
			"# Example: Identify Key Vault-referenced secrets (SECURE)\n"+
			"az synapse linked-service list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.typeProperties | .. | .secretName? != null) | \\\n"+
			"  {name, type: .properties.type, secretReference: \"Azure Key Vault\"}'\n\n"+
			"# Example: Identify SQL authentication (LESS SECURE)\n"+
			"az synapse linked-service list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.type == \"AzureSqlDatabase\" and \\\n"+
			"  (.properties.typeProperties.userName != null or .properties.typeProperties.password != null)) | \\\n"+
			"  {name, type: .properties.type, auth: \"SQL Authentication\", risk: \"HIGH\"}'\n\n"+
			"### Common Linked Service Types\n"+
			"# AzureSqlDatabase - SQL Server connections\n"+
			"# AzureBlobStorage - Blob storage connections\n"+
			"# AzureDataLakeStore - Data Lake Gen1\n"+
			"# AzureDataLakeStorage - Data Lake Gen2\n"+
			"# AzureKeyVault - Key Vault references\n"+
			"# AzureDatabricks - Databricks integration\n"+
			"# CosmosDb - Cosmos DB connections\n"+
			"# Rest - REST API endpoints\n\n"+
			"# Extract all linked service types\n"+
			"az synapse linked-service list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | {name, type: .properties.type}' | sort -u\n\n",
		workspaceName,
		workspaceName, workspaceName,
		workspaceEndpoint, workspaceEndpoint,
		workspaceName, workspaceName, workspaceName, workspaceName, workspaceName,
	)

	// Add integration runtime security analysis
	m.LootMap["synapse-integration-runtimes"].Contents += fmt.Sprintf(
		"## Workspace: %s\n\n"+
			"### Enumerate Integration Runtimes\n"+
			"# List all integration runtimes using Azure CLI\n"+
			"az synapse integration-runtime list \\\n"+
			"  --workspace-name %s \\\n"+
			"  --output table\n\n"+
			"# Get integration runtime details\n"+
			"az synapse integration-runtime show \\\n"+
			"  --workspace-name %s \\\n"+
			"  --name <IR_NAME> \\\n"+
			"  --output json | jq .\n\n"+
			"### REST API Method\n"+
			"curl -X GET %s/integrationRuntimes?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\" | jq .\n\n"+
			"# Get specific integration runtime\n"+
			"curl -X GET %s/integrationRuntimes/<IR_NAME>?api-version=2020-12-01 \\\n"+
			"  -H \"Authorization: Bearer $SYNAPSE_TOKEN\" | jq .\n\n"+
			"### Security Analysis - Integration Runtime Types\n"+
			"# Check for:\n"+
			"# 1. Azure Integration Runtime (managed by Microsoft)\n"+
			"# 2. Self-hosted Integration Runtime (customer network access)\n"+
			"# 3. Azure-SSIS Integration Runtime (SQL Server package execution)\n\n"+
			"# Self-hosted IRs are HIGH RISK:\n"+
			"# - Run on customer infrastructure\n"+
			"# - Have network access to on-premises resources\n"+
			"# - Can be compromised for lateral movement\n"+
			"# - May have overprivileged service accounts\n\n"+
			"# Example: Identify self-hosted integration runtimes (HIGH RISK)\n"+
			"az synapse integration-runtime list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.type == \"SelfHosted\") | \\\n"+
			"  {name, type: .properties.type, risk: \"HIGH - Customer Network Access\"}'\n\n"+
			"# Example: Identify Azure integration runtimes (LOWER RISK)\n"+
			"az synapse integration-runtime list --workspace-name %s --output json | \\\n"+
			"  jq -r '.[] | select(.properties.type == \"Managed\") | \\\n"+
			"  {name, type: .properties.type, risk: \"MEDIUM - Azure Managed\"}'\n\n"+
			"# Example: Get self-hosted IR connection status\n"+
			"az synapse integration-runtime show --workspace-name %s --name <IR_NAME> --output json | \\\n"+
			"  jq '{name, state: .properties.state, version: .properties.version}'\n\n"+
			"### Attack Scenarios\n"+
			"# 1. Self-Hosted IR Compromise:\n"+
			"#    - Gain access to on-premises network\n"+
			"#    - Pivot to internal resources\n"+
			"#    - Exfiltrate data through Synapse pipelines\n"+
			"\n"+
			"# 2. Linked Service Credential Theft:\n"+
			"#    - Extract credentials from linked services\n"+
			"#    - Access databases, storage accounts, APIs\n"+
			"#    - Use for lateral movement\n"+
			"\n"+
			"# 3. Pipeline Manipulation:\n"+
			"#    - Inject malicious activities\n"+
			"#    - Schedule data exfiltration\n"+
			"#    - Abuse pipeline permissions\n\n",
		workspaceName,
		workspaceName, workspaceName,
		workspaceEndpoint, workspaceEndpoint,
		workspaceName, workspaceName, workspaceName,
	)
}

// ------------------------------
// Generate SQL pool loot
// ------------------------------
func (m *SynapseModule) generateSQLPoolLoot(subID, rgName, workspaceName, poolName, endpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["synapse-commands"].Contents += fmt.Sprintf(
		"## SQL Pool: %s/%s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Get SQL pool details\n"+
			"az synapse sql pool show \\\n"+
			"  --resource-group %s \\\n"+
			"  --workspace-name %s \\\n"+
			"  --name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# Pause SQL pool (cost saving)\n"+
			"az synapse sql pool pause \\\n"+
			"  --resource-group %s \\\n"+
			"  --workspace-name %s \\\n"+
			"  --name %s\n"+
			"\n"+
			"# Connect using sqlcmd (if installed)\n"+
			"sqlcmd -S %s -d %s -G\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"\n"+
			"# Get SQL pool\n"+
			"Get-AzSynapseSqlPool -ResourceGroupName %s -WorkspaceName %s -Name %s\n\n",
		workspaceName, poolName, rgName,
		subID,
		rgName, workspaceName, poolName,
		rgName, workspaceName, poolName,
		endpoint, poolName,
		subID,
		rgName, workspaceName, poolName,
	)
}

// ------------------------------
// Generate Spark pool loot
// ------------------------------
func (m *SynapseModule) generateSparkPoolLoot(subID, rgName, workspaceName, poolName, endpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["synapse-commands"].Contents += fmt.Sprintf(
		"## Spark Pool: %s/%s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Get Spark pool details\n"+
			"az synapse spark pool show \\\n"+
			"  --resource-group %s \\\n"+
			"  --workspace-name %s \\\n"+
			"  --name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# List Spark pool applications\n"+
			"az synapse spark session list \\\n"+
			"  --workspace-name %s \\\n"+
			"  --spark-pool-name %s\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"\n"+
			"# Get Spark pool\n"+
			"Get-AzSynapseSparkPool -ResourceGroupName %s -WorkspaceName %s -Name %s\n\n",
		workspaceName, poolName, rgName,
		subID,
		rgName, workspaceName, poolName,
		workspaceName, poolName,
		subID,
		rgName, workspaceName, poolName,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *SynapseModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.SynapseRows) == 0 {
		logger.InfoM("No Synapse workspaces found", globals.AZ_SYNAPSE_MODULE_NAME)
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
		"Workspace Name",
		"Resource Type",
		"Resource Name",
		"Endpoint",
		"Public/Private",
		"EntraID Centralized Auth",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.SynapseRows, headers,
			"synapse", globals.AZ_SYNAPSE_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.SynapseRows, headers,
			"synapse", globals.AZ_SYNAPSE_MODULE_NAME,
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
	output := SynapseOutput{
		Table: []internal.TableFile{{
			Name:   "synapse",
			Header: headers,
			Body:   m.SynapseRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_SYNAPSE_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Synapse resources across %d subscription(s)", len(m.SynapseRows), len(m.Subscriptions)), globals.AZ_SYNAPSE_MODULE_NAME)
}
