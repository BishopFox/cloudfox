package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzDatabricksCommand = &cobra.Command{
	Use:     "databricks",
	Aliases: []string{"adb"},
	Short:   "Enumerate Azure Databricks workspaces with security analysis",
	Long: `
Enumerate Azure Databricks for a specific tenant:
  ./cloudfox az databricks --tenant TENANT_ID

Enumerate Databricks for a specific subscription:
  ./cloudfox az databricks --subscription SUBSCRIPTION_ID

ENHANCED FEATURES (requires Databricks workspace authentication):
  - Notebook enumeration and secret scanning patterns
  - Secret scope and ACL analysis
  - Job configuration security review
  - Cluster security analysis (init scripts, env vars, spark configs)
  - Comprehensive REST API examples for manual analysis

NOTE: This module enumerates workspaces via Azure ARM. To access notebooks,
      secrets, jobs, and clusters, use the generated loot files with Databricks
      workspace authentication (Azure AD token or Personal Access Token).`,
	Run: ListDatabricks,
}

// ------------------------------
// Module struct
// ------------------------------
type DatabricksModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions  []string
	DatabricksRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

type DatabricksInfo struct {
	SubscriptionID         string
	SubscriptionName       string
	ResourceGroup          string
	Region                 string
	WorkspaceName          string
	WorkspaceURL           string
	WorkspaceID            string
	ManagedResourceGroup   string
	PublicPrivate          string
	SKU                    string
	DiskEncryptionIdentity string
	StorageAccountIdentity string
	SystemAssignedID       string
	UserAssignedID         string
}

// ------------------------------
// Output struct
// ------------------------------
type DatabricksOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DatabricksOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DatabricksOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListDatabricks(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_DATABRICKS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &DatabricksModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		DatabricksRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"databricks-commands":           {Name: "databricks-commands", Contents: ""},
			"databricks-connection-strings": {Name: "databricks-connection-strings", Contents: ""},
			"databricks-rest-api":           {Name: "databricks-rest-api", Contents: "# Databricks REST API Examples\n\n"},
			"databricks-notebooks":          {Name: "databricks-notebooks", Contents: "# Databricks Notebook Enumeration and Secret Scanning\n\n"},
			"databricks-secrets":            {Name: "databricks-secrets", Contents: "# Databricks Secret Scope Analysis\n\n"},
			"databricks-jobs":               {Name: "databricks-jobs", Contents: "# Databricks Job Configuration Analysis\n\n"},
			"databricks-clusters":           {Name: "databricks-clusters", Contents: "# Databricks Cluster Security Analysis\n\n"},
		},
	}

	module.PrintDatabricks(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *DatabricksModule) PrintDatabricks(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_DATABRICKS_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_DATABRICKS_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *DatabricksModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_DATABRICKS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	workspaceClient, err := armdatabricks.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Databricks workspace client: %v", err), globals.AZ_DATABRICKS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	resourceGroups := m.ResolveResourceGroups(subID)

	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, workspaceClient, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *DatabricksModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, workspaceClient *armdatabricks.WorkspacesClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
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
			logger.ErrorM(fmt.Sprintf("Failed to list Databricks workspaces in RG %s: %v", rgName, err), globals.AZ_DATABRICKS_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, workspace := range page.Value {
			m.processWorkspace(ctx, workspace, subID, subName, rgName, region, logger)
		}
	}
}

// ------------------------------
// Process single workspace
// ------------------------------
func (m *DatabricksModule) processWorkspace(ctx context.Context, workspace *armdatabricks.Workspace, subID, subName, rgName, region string, logger internal.Logger) {
	workspaceName := azinternal.SafeStringPtr(workspace.Name)
	workspaceURL := "N/A"
	workspaceID := "N/A"
	managedResourceGroup := "N/A"
	publicPrivate := "Unknown"
	sku := "N/A"

	if workspace.Properties != nil {
		// Get workspace URL
		if workspace.Properties.WorkspaceURL != nil {
			workspaceURL = fmt.Sprintf("https://%s", *workspace.Properties.WorkspaceURL)
		}

		// Get workspace ID
		if workspace.Properties.WorkspaceID != nil {
			workspaceID = *workspace.Properties.WorkspaceID
		}

		// Get managed resource group
		if workspace.Properties.ManagedResourceGroupID != nil {
			managedResourceGroup = *workspace.Properties.ManagedResourceGroupID
		}

		// Determine public/private based on public network access
		if workspace.Properties.PublicNetworkAccess != nil {
			if *workspace.Properties.PublicNetworkAccess == armdatabricks.PublicNetworkAccessEnabled {
				publicPrivate = "Public"
			} else {
				publicPrivate = "Private"
			}
		} else {
			// Default to Public if not specified
			publicPrivate = "Public"
		}
	}

	// Get SKU
	if workspace.SKU != nil && workspace.SKU.Name != nil {
		sku = *workspace.SKU.Name
	}

	// Databricks workspaces use managed identities for specific purposes (disk encryption, storage)
	// but don't have general-purpose system/user assigned identities like other Azure resources
	diskEncryptionIdentity := "N/A"
	storageAccountIdentity := "N/A"

	if workspace.Properties != nil {
		if workspace.Properties.ManagedDiskIdentity != nil && workspace.Properties.ManagedDiskIdentity.PrincipalID != nil {
			diskEncryptionIdentity = *workspace.Properties.ManagedDiskIdentity.PrincipalID
		}
		if workspace.Properties.StorageAccountIdentity != nil && workspace.Properties.StorageAccountIdentity.PrincipalID != nil {
			storageAccountIdentity = *workspace.Properties.StorageAccountIdentity.PrincipalID
		}
	}

	// Standard managed identity columns (Databricks doesn't support these, only specialized identities above)
	systemAssignedID := "N/A"
	userAssignedID := "N/A"

	// Add workspace row
	workspaceRow := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		workspaceName,
		workspaceURL,
		workspaceID,
		managedResourceGroup,
		publicPrivate,
		sku,
		diskEncryptionIdentity,
		storageAccountIdentity,
		systemAssignedID,
		userAssignedID,
	}

	m.mu.Lock()
	m.DatabricksRows = append(m.DatabricksRows, workspaceRow)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate workspace loot
	m.generateWorkspaceLoot(subID, rgName, workspaceName, workspaceURL, workspaceID, managedResourceGroup)
}

// ------------------------------
// Generate workspace loot
// ------------------------------
func (m *DatabricksModule) generateWorkspaceLoot(subID, rgName, workspaceName, workspaceURL, workspaceID, managedResourceGroup string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["databricks-commands"].Contents += fmt.Sprintf(
		"## Databricks Workspace: %s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Get workspace details\n"+
			"az databricks workspace show \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# List clusters (requires Databricks CLI and authentication)\n"+
			"# Install: pip install databricks-cli\n"+
			"# Configure: databricks configure --aad-token\n"+
			"databricks clusters list --output JSON\n"+
			"\n"+
			"# List notebooks\n"+
			"databricks workspace ls / --absolute\n"+
			"\n"+
			"# List secrets\n"+
			"databricks secrets list-scopes\n"+
			"\n"+
			"# List jobs\n"+
			"databricks jobs list\n"+
			"\n"+
			"# Export workspace content\n"+
			"databricks workspace export_dir / ./databricks-export --format SOURCE\n"+
			"\n"+
			"# List users and service principals\n"+
			"databricks workspace list-users\n"+
			"\n"+
			"# List tokens (requires admin)\n"+
			"databricks tokens list\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"\n"+
			"# Get workspace\n"+
			"Get-AzDatabricksWorkspace -ResourceGroupName %s -Name %s\n"+
			"\n"+
			"# Get workspace access connector (if exists)\n"+
			"Get-AzDatabricksAccessConnector -ResourceGroupName %s\n"+
			"\n"+
			"# Access Databricks API directly\n"+
			"# Get Azure AD token\n"+
			"$token = (Get-AzAccessToken -ResourceUrl 2ff814a6-3304-4ab8-85cb-cd0e6f879c1d).Token\n"+
			"$headers = @{ Authorization = \"Bearer $token\" }\n"+
			"$apiUrl = \"%s/api/2.0/clusters/list\"\n"+
			"Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get\n\n",
		workspaceName, rgName,
		subID,
		rgName, workspaceName,
		subID,
		rgName, workspaceName,
		rgName,
		workspaceURL,
	)

	m.LootMap["databricks-connection-strings"].Contents += fmt.Sprintf(
		"## Databricks Workspace: %s\n"+
			"Workspace URL: %s\n"+
			"Workspace ID: %s\n"+
			"Managed Resource Group: %s\n"+
			"\n"+
			"# Connection Methods:\n"+
			"# 1. Azure AD Authentication (Recommended)\n"+
			"#    - Use Azure AD token for API access\n"+
			"#    - Resource ID: 2ff814a6-3304-4ab8-85cb-cd0e6f879c1d\n"+
			"\n"+
			"# 2. Personal Access Token (PAT)\n"+
			"#    - Generate in Workspace UI: User Settings > Access Tokens\n"+
			"#    - Use with Databricks CLI or API\n"+
			"\n"+
			"# 3. Service Principal Authentication\n"+
			"#    - Create service principal with workspace access\n"+
			"#    - Use client ID and secret for automation\n"+
			"\n"+
			"# Databricks CLI Configuration:\n"+
			"export DATABRICKS_HOST=\"%s\"\n"+
			"export DATABRICKS_AAD_TOKEN=\"$(az account get-access-token --resource 2ff814a6-3304-4ab8-85cb-cd0e6f879c1d --query accessToken -o tsv)\"\n"+
			"\n"+
			"# Python SDK Connection:\n"+
			"# from databricks.sdk import WorkspaceClient\n"+
			"# w = WorkspaceClient(host=\"%s\", azure_workspace_resource_id=\"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Databricks/workspaces/%s\")\n"+
			"\n"+
			"# REST API Example:\n"+
			"curl -H \"Authorization: Bearer <AAD-TOKEN>\" \\\n"+
			"     %s/api/2.0/clusters/list\n\n",
		workspaceName,
		workspaceURL,
		workspaceID,
		managedResourceGroup,
		workspaceURL,
		workspaceURL,
		subID, rgName, workspaceName,
		workspaceURL,
	)

	// Add comprehensive REST API documentation
	m.LootMap["databricks-rest-api"].Contents += fmt.Sprintf(
		"## Workspace: %s (%s)\n\n"+
			"### Authentication\n"+
			"# Get Azure AD token for Databricks\n"+
			"export DATABRICKS_TOKEN=$(az account get-access-token --resource 2ff814a6-3304-4ab8-85cb-cd0e6f879c1d --query accessToken -o tsv)\n\n"+
			"### Core API Endpoints\n\n"+
			"# List all clusters\n"+
			"curl -X GET %s/api/2.0/clusters/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\"\n\n"+
			"# List all jobs\n"+
			"curl -X GET %s/api/2.0/jobs/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\"\n\n"+
			"# List workspace contents\n"+
			"curl -X GET %s/api/2.0/workspace/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"path\": \"/\"}'\n\n"+
			"# List secret scopes\n"+
			"curl -X GET %s/api/2.0/secrets/scopes/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\"\n\n"+
			"# List users\n"+
			"curl -X GET %s/api/2.0/preview/scim/v2/Users \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\"\n\n"+
			"# List service principals\n"+
			"curl -X GET %s/api/2.0/preview/scim/v2/ServicePrincipals \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\"\n\n"+
			"# List cluster policies\n"+
			"curl -X GET %s/api/2.0/policies/clusters/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\"\n\n",
		workspaceName, workspaceURL,
		workspaceURL, workspaceURL, workspaceURL, workspaceURL, workspaceURL, workspaceURL, workspaceURL,
	)

	// Add notebook enumeration and secret scanning guidance
	m.LootMap["databricks-notebooks"].Contents += fmt.Sprintf(
		"## Workspace: %s\n\n"+
			"### Enumerate Notebooks\n"+
			"# List all notebooks recursively\n"+
			"databricks workspace list / --absolute --profile WORKSPACE_PROFILE\n\n"+
			"# Export all notebooks for analysis\n"+
			"databricks workspace export_dir / ./notebooks-export --format SOURCE --profile WORKSPACE_PROFILE\n\n"+
			"### Secret Scanning Patterns\n"+
			"# Scan exported notebooks for secrets\n"+
			"# Common patterns to search for:\n\n"+
			"# Azure Storage Account Keys\n"+
			"grep -r \"DefaultEndpointsProtocol=https;AccountName=\" ./notebooks-export/\n"+
			"grep -r \"AccountKey=\" ./notebooks-export/\n\n"+
			"# Azure Service Principal Credentials\n"+
			"grep -r \"client_secret\" ./notebooks-export/\n"+
			"grep -r \"tenant_id\" ./notebooks-export/\n"+
			"grep -r \"client_id\" ./notebooks-export/\n\n"+
			"# Database Connection Strings\n"+
			"grep -r \"jdbc:\" ./notebooks-export/\n"+
			"grep -r \"Password=\" ./notebooks-export/\n"+
			"grep -r \"PWD=\" ./notebooks-export/\n\n"+
			"# API Keys\n"+
			"grep -r \"api_key\" ./notebooks-export/\n"+
			"grep -r \"apikey\" ./notebooks-export/\n"+
			"grep -r \"api-key\" ./notebooks-export/\n\n"+
			"# AWS Credentials\n"+
			"grep -r \"aws_access_key_id\" ./notebooks-export/\n"+
			"grep -r \"aws_secret_access_key\" ./notebooks-export/\n\n"+
			"# Generic Secrets\n"+
			"grep -r \"password\" ./notebooks-export/ -i\n"+
			"grep -r \"secret\" ./notebooks-export/ -i\n"+
			"grep -r \"token\" ./notebooks-export/ -i\n\n"+
			"### REST API Method\n"+
			"curl -X GET %s/api/2.0/workspace/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"path\": \"/\"}' | jq .\n\n"+
			"# Export specific notebook\n"+
			"curl -X GET %s/api/2.0/workspace/export \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"path\": \"/Users/user@example.com/notebook\", \"format\": \"SOURCE\"}' | jq -r .content | base64 -d\n\n",
		workspaceName,
		workspaceURL, workspaceURL,
	)

	// Add secret scope analysis
	m.LootMap["databricks-secrets"].Contents += fmt.Sprintf(
		"## Workspace: %s\n\n"+
			"### List Secret Scopes\n"+
			"databricks secrets list-scopes --profile WORKSPACE_PROFILE\n\n"+
			"### List Secrets in Scope\n"+
			"# Note: Secret values cannot be retrieved via API (only metadata)\n"+
			"databricks secrets list --scope <SCOPE_NAME> --profile WORKSPACE_PROFILE\n\n"+
			"### Create Secret Scope (if authorized)\n"+
			"databricks secrets create-scope --scope test-scope --profile WORKSPACE_PROFILE\n\n"+
			"### REST API Method\n"+
			"# List all secret scopes\n"+
			"curl -X GET %s/api/2.0/secrets/scopes/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" | jq .\n\n"+
			"# List secrets in scope\n"+
			"curl -X GET %s/api/2.0/secrets/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"scope\": \"<SCOPE_NAME>\"}' | jq .\n\n"+
			"### Security Analysis\n"+
			"# Check for:\n"+
			"# 1. Azure Key Vault-backed scopes (more secure)\n"+
			"# 2. Databricks-backed scopes (secrets stored in Databricks)\n"+
			"# 3. Scope ACLs - who has READ/WRITE/MANAGE permissions\n\n"+
			"# List ACLs for scope\n"+
			"databricks secrets list-acls --scope <SCOPE_NAME> --profile WORKSPACE_PROFILE\n\n"+
			"curl -X GET %s/api/2.0/secrets/acls/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"scope\": \"<SCOPE_NAME>\"}' | jq .\n\n",
		workspaceName,
		workspaceURL, workspaceURL, workspaceURL,
	)

	// Add job configuration analysis
	m.LootMap["databricks-jobs"].Contents += fmt.Sprintf(
		"## Workspace: %s\n\n"+
			"### List All Jobs\n"+
			"databricks jobs list --profile WORKSPACE_PROFILE --output JSON | jq .\n\n"+
			"### Get Job Details\n"+
			"databricks jobs get --job-id <JOB_ID> --profile WORKSPACE_PROFILE --output JSON | jq .\n\n"+
			"### REST API Method\n"+
			"# List all jobs\n"+
			"curl -X GET %s/api/2.0/jobs/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" | jq .\n\n"+
			"# Get job details\n"+
			"curl -X GET %s/api/2.0/jobs/get \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"job_id\": <JOB_ID>}' | jq .\n\n"+
			"# List job runs\n"+
			"curl -X GET %s/api/2.0/jobs/runs/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"job_id\": <JOB_ID>, \"limit\": 25}' | jq .\n\n"+
			"### Security Analysis\n"+
			"# Check for:\n"+
			"# 1. Jobs with secrets in parameters (hardcoded credentials)\n"+
			"# 2. Jobs running with overprivileged service principals\n"+
			"# 3. Jobs with notebook tasks - extract and scan notebook paths\n"+
			"# 4. Jobs with jar/python tasks - check for embedded credentials\n"+
			"# 5. Job clusters with insecure configurations\n\n"+
			"# Example: Extract all notebook paths from jobs\n"+
			"databricks jobs list --output JSON | jq -r '.jobs[].settings.tasks[]?.notebook_task?.notebook_path' | sort -u\n\n"+
			"# Example: Check for environment variables in job configs\n"+
			"databricks jobs list --output JSON | jq '.jobs[].settings.tasks[]?.spark_env_vars'\n\n",
		workspaceName,
		workspaceURL, workspaceURL, workspaceURL,
	)

	// Add cluster security analysis
	m.LootMap["databricks-clusters"].Contents += fmt.Sprintf(
		"## Workspace: %s\n\n"+
			"### List All Clusters\n"+
			"databricks clusters list --profile WORKSPACE_PROFILE --output JSON | jq .\n\n"+
			"### Get Cluster Details\n"+
			"databricks clusters get --cluster-id <CLUSTER_ID> --profile WORKSPACE_PROFILE --output JSON | jq .\n\n"+
			"### REST API Method\n"+
			"# List all clusters\n"+
			"curl -X GET %s/api/2.0/clusters/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" | jq .\n\n"+
			"# Get cluster details\n"+
			"curl -X GET %s/api/2.0/clusters/get \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" \\\n"+
			"  -d '{\"cluster_id\": \"<CLUSTER_ID>\"}' | jq .\n\n"+
			"# List cluster policies\n"+
			"curl -X GET %s/api/2.0/policies/clusters/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" | jq .\n\n"+
			"### Security Analysis\n"+
			"# Check for:\n"+
			"# 1. Init scripts (potential for privilege escalation)\n"+
			"# 2. Environment variables with secrets\n"+
			"# 3. Spark configurations with credentials\n"+
			"# 4. Instance profiles / managed identities\n"+
			"# 5. Public IP addresses on clusters\n"+
			"# 6. Autoscaling configurations\n\n"+
			"# Example: Extract init scripts from all clusters\n"+
			"databricks clusters list --output JSON | jq -r '.clusters[]? | select(.init_scripts != null) | {cluster_name, init_scripts}'\n\n"+
			"# Example: Check for environment variables\n"+
			"databricks clusters list --output JSON | jq '.clusters[]?.spark_env_vars'\n\n"+
			"# Example: Check for Spark configurations\n"+
			"databricks clusters list --output JSON | jq '.clusters[]?.spark_conf'\n\n"+
			"# Example: Check cluster policies\n"+
			"curl -X GET %s/api/2.0/policies/clusters/list \\\n"+
			"  -H \"Authorization: Bearer $DATABRICKS_TOKEN\" | jq -r '.policies[] | {name, policy_family_id, definition}'\n\n",
		workspaceName,
		workspaceURL, workspaceURL, workspaceURL, workspaceURL,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *DatabricksModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.DatabricksRows) == 0 {
		logger.InfoM("No Databricks workspaces found", globals.AZ_DATABRICKS_MODULE_NAME)
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
		"Workspace URL",
		"Workspace ID",
		"Managed Resource Group",
		"Public/Private",
		"SKU",
		"Disk Encryption Identity",
		"Storage Account Identity",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.DatabricksRows, headers,
			"databricks", globals.AZ_DATABRICKS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.DatabricksRows, headers,
			"databricks", globals.AZ_DATABRICKS_MODULE_NAME,
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
	output := DatabricksOutput{
		Table: []internal.TableFile{{
			Name:   "databricks",
			Header: headers,
			Body:   m.DatabricksRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DATABRICKS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Databricks workspace(s) across %d subscription(s)", len(m.DatabricksRows), len(m.Subscriptions)), globals.AZ_DATABRICKS_MODULE_NAME)
}
