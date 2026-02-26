package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzDeploymentsCommand = &cobra.Command{
	Use:     "deployments",
	Aliases: []string{"deploy"},
	Short:   "Enumerate Azure Deployments",
	Long: `
Enumerate Azure Deployments for a specific tenant:
./cloudfox az deploy --tenant TENANT_ID

Enumerate Azure Deployments for a specific subscription:
./cloudfox az deploy --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListDeployments,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type DeploymentsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions  []string
	DeploymentRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type DeploymentsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DeploymentsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DeploymentsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListDeployments(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_DEPLOYMENTS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &DeploymentsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		DeploymentRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"deployment-commands":                      {Name: "deployment-commands", Contents: ""},
			"deployment-data":                          {Name: "deployment-data", Contents: ""},
			"deployment-secrets":                       {Name: "deployment-secrets", Contents: ""},
			"deployment-uami-templates":                {Name: "deployment-uami-templates", Contents: ""},
			"deployment-uami-identities":               {Name: "deployment-uami-identities", Contents: ""},
			"deployment-parameter-extraction-commands": {Name: "deployment-parameter-extraction-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDeployments(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *DeploymentsModule) PrintDeployments(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_DEPLOYMENTS_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_DEPLOYMENTS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_DEPLOYMENTS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating deployments for %d subscription(s)", len(m.Subscriptions)), globals.AZ_DEPLOYMENTS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_DEPLOYMENTS_MODULE_NAME, m.processSubscription)
	}

	// Generate parameter extraction commands
	m.generateParameterExtractionLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *DeploymentsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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

	// ==================== USER-ASSIGNED MANAGED IDENTITY ENUMERATION ====================
	// Enumerate UAMIs and check permissions (Invoke-AzUADeploymentScript functionality)
	m.enumerateUAMIs(ctx, subID, subName, logger)
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *DeploymentsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region for this resource group using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)
	if region == "" {
		region = "N/A"
	}

	// Get deployments for this resource group
	deployments, client, err := GetDeploymentsPerResourceGroup(m.Session, subID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list deployments for RG %s: %v", rgName, err), globals.AZ_DEPLOYMENTS_MODULE_NAME)
		}
		return
	}

	// Process each deployment concurrently
	var deploymentWg sync.WaitGroup
	for _, d := range deployments {
		d := d
		deploymentWg.Add(1)
		go m.processDeployment(ctx, subID, subName, rgName, region, d, client, &deploymentWg)
	}

	// Wait for all deployments in this resource group to finish
	deploymentWg.Wait()
}

// ------------------------------
// Process single deployment
// ------------------------------
func (m *DeploymentsModule) processDeployment(ctx context.Context, subID, subName, rgName, region string, d *armresources.DeploymentExtended, client *armresources.DeploymentsClient, wg *sync.WaitGroup) {
	defer wg.Done()

	deploymentName := azinternal.SafeStringPtr(d.Name)

	// Thread-safe append - table row
	m.mu.Lock()
	m.DeploymentRows = append(m.DeploymentRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		deploymentName,
	})

	// Loot: commands
	m.LootMap["deployment-commands"].Contents += fmt.Sprintf(
		"## Resource Group: %s\n"+
			"# CLI:\n"+
			"az account set --subscription %s\n"+
			"az deployment group show --resource-group %s --name %s\n"+
			"# PowerShell:\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"Get-AzResourceGroupDeployment -ResourceGroupName %s -Name %s\n\n",
		rgName, subID, rgName, deploymentName, subID, rgName, deploymentName,
	)
	m.mu.Unlock()

	// Loot: templates & secrets
	var templateContent string
	var secretsContent string

	if d.Name != nil {
		timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		exportResp, err := client.ExportTemplate(timeoutCtx, rgName, *d.Name, nil)
		if err == nil && exportResp.Template != nil {
			bytes, _ := json.MarshalIndent(exportResp.Template, "", "  ")
			templateContent = string(bytes)
		}
	}

	if d.Properties != nil {
		if d.Properties.Parameters != nil {
			paramBytes, _ := json.MarshalIndent(d.Properties.Parameters, "", "  ")
			secretsContent += fmt.Sprintf("### Parameters for deployment %s\n%s\n\n", deploymentName, string(paramBytes))
		}
		if d.Properties.Outputs != nil {
			outBytes, _ := json.MarshalIndent(d.Properties.Outputs, "", "  ")
			secretsContent += fmt.Sprintf("### Outputs for deployment %s\n%s\n\n", deploymentName, string(outBytes))
		}
	}

	if templateContent != "" {
		m.mu.Lock()
		m.LootMap["deployment-data"].Contents += fmt.Sprintf(
			"## Resource Group: %s, Deployment: %s\n%s\n\n",
			rgName, deploymentName, templateContent,
		)
		m.mu.Unlock()
	}

	if secretsContent != "" {
		m.mu.Lock()
		m.LootMap["deployment-secrets"].Contents += fmt.Sprintf(
			"## Resource Group: %s, Deployment: %s\n%s\n",
			rgName, deploymentName, secretsContent,
		)
		m.mu.Unlock()
	}
}

// ------------------------------
// Enumerate User-Assigned Managed Identities (Invoke-AzUADeploymentScript)
// ------------------------------
func (m *DeploymentsModule) enumerateUAMIs(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get all UAMIs in subscription
	uamis, err := azinternal.GetUserAssignedIdentities(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate UAMIs for subscription %s: %v", subID, err), globals.AZ_DEPLOYMENTS_MODULE_NAME)
		}
		return
	}

	if len(uamis) == 0 {
		return
	}

	// Check permissions and get role assignments for each UAMI
	var accessibleUAMIs []azinternal.UserAssignedIdentity
	for i := range uamis {
		uami := &uamis[i]

		// Check if we have assign permissions
		hasAccess, err := azinternal.CheckUAMIAssignPermissions(m.Session, uami.ID)
		if err == nil {
			uami.HasAssignAccess = hasAccess
		}

		// Only enumerate roles if we have access
		if uami.HasAssignAccess && uami.PrincipalID != "" {
			// Get role assignments across all subscriptions
			roles, err := azinternal.GetUAMIRoleAssignments(m.Session, uami.PrincipalID, m.Subscriptions)
			if err == nil {
				uami.RoleAssignments = roles
			}
			accessibleUAMIs = append(accessibleUAMIs, *uami)
		}
	}

	if len(accessibleUAMIs) == 0 {
		return
	}

	// Generate loot files
	m.mu.Lock()
	defer m.mu.Unlock()

	// Document accessible UAMIs with their roles
	m.LootMap["deployment-uami-identities"].Contents += fmt.Sprintf("\n"+
		"================================================================================\n"+
		"USER-ASSIGNED MANAGED IDENTITIES - SUBSCRIPTION: %s (%s)\n"+
		"================================================================================\n\n", subName, subID)

	m.LootMap["deployment-uami-identities"].Contents += fmt.Sprintf(
		"Total UAMIs in subscription: %d\n"+
			"UAMIs you have assign/use permissions on: %d\n\n",
		len(uamis), len(accessibleUAMIs))

	for _, uami := range accessibleUAMIs {
		m.LootMap["deployment-uami-identities"].Contents += fmt.Sprintf(
			"## Managed Identity: %s\n"+
				"# Resource Group: %s\n"+
				"# Principal ID: %s\n"+
				"# Client ID: %s\n"+
				"# Location: %s\n"+
				"# Resource ID: %s\n"+
				"# Has Assign Access: %v\n\n",
			uami.Name, uami.ResourceGroup, uami.PrincipalID,
			uami.ClientID, uami.Location, uami.ID, uami.HasAssignAccess)

		// Document role assignments
		if len(uami.RoleAssignments) > 0 {
			m.LootMap["deployment-uami-identities"].Contents += "# Role Assignments:\n"
			for _, role := range uami.RoleAssignments {
				m.LootMap["deployment-uami-identities"].Contents += fmt.Sprintf(
					"#   - %s @ %s (Subscription: %s)\n",
					role.RoleDefinitionName, role.Scope, role.SubscriptionID)
			}
			m.LootMap["deployment-uami-identities"].Contents += "\n"
		} else {
			m.LootMap["deployment-uami-identities"].Contents += "# Role Assignments: None found\n\n"
		}

		// Generate deployment template for this UAMI
		template := azinternal.GenerateUAMIDeploymentTemplate(
			uami.Name,
			uami.ResourceGroup,
			uami.SubscriptionID,
			"https://management.azure.com/",
		)

		m.LootMap["deployment-uami-templates"].Contents += fmt.Sprintf(
			"\n"+
				"================================================================================\n"+
				"DEPLOYMENT TEMPLATE FOR UAMI: %s\n"+
				"================================================================================\n\n"+
				"# This ARM template creates a Deployment Script that uses the UAMI to extract\n"+
				"# an access token. This is an OFFENSIVE technique for privilege escalation.\n"+
				"#\n"+
				"# USAGE:\n"+
				"# 1. Save this template to a file (e.g., uami-%s-template.json)\n"+
				"# 2. Deploy to a resource group where you have deployment permissions:\n"+
				"#    az deployment group create --resource-group <rg-name> --template-file uami-%s-template.json\n"+
				"# 3. Retrieve the output (access token):\n"+
				"#    az deployment group show --resource-group <rg-name> --name <deployment-name> --query properties.outputs.result.value -o tsv\n"+
				"#\n"+
				"# NOTE: The deployment script will be automatically cleaned up after execution.\n"+
				"# The deployment itself should be manually deleted to avoid detection:\n"+
				"#    az deployment group delete --resource-group <rg-name> --name <deployment-name>\n\n"+
				"%s\n\n",
			uami.Name, uami.Name, uami.Name, template)
	}
}

// ------------------------------
// Generate parameter extraction commands
// ------------------------------
func (m *DeploymentsModule) generateParameterExtractionLoot() {
	lf := m.LootMap["deployment-parameter-extraction-commands"]

	// Only generate if we have deployments
	if len(m.DeploymentRows) == 0 {
		return
	}

	// Generate comprehensive parameter extraction and deployment manipulation guide
	lf.Contents += fmt.Sprintf("# Azure Deployment Parameter Extraction & Manipulation Guide\n\n")
	lf.Contents += fmt.Sprintf("This guide provides commands to extract sensitive parameters from deployments,\n")
	lf.Contents += fmt.Sprintf("export deployment operation logs, and re-run deployments with modified parameters.\n\n")

	lf.Contents += fmt.Sprintf("## Table of Contents\n")
	lf.Contents += fmt.Sprintf("1. Extract Deployment Parameters\n")
	lf.Contents += fmt.Sprintf("2. Export Deployment Operations Log\n")
	lf.Contents += fmt.Sprintf("3. Extract Sensitive Data (Database Passwords, Connection Strings)\n")
	lf.Contents += fmt.Sprintf("4. Re-run Deployment with Modified Parameters\n")
	lf.Contents += fmt.Sprintf("5. Validate Template and Parameters\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 1: Extract Deployment Parameters
	lf.Contents += fmt.Sprintf("## 1. Extract Deployment Parameters\n\n")

	lf.Contents += fmt.Sprintf("### Azure CLI: Show deployment with parameters\n\n")
	lf.Contents += fmt.Sprintf("SUBSCRIPTION_ID=<SUBSCRIPTION-ID>\n")
	lf.Contents += fmt.Sprintf("RESOURCE_GROUP=<RESOURCE-GROUP-NAME>\n")
	lf.Contents += fmt.Sprintf("DEPLOYMENT_NAME=<DEPLOYMENT-NAME>\n\n")

	lf.Contents += fmt.Sprintf("# Set subscription context\n")
	lf.Contents += fmt.Sprintf("az account set --subscription $SUBSCRIPTION_ID\n\n")

	lf.Contents += fmt.Sprintf("# Show deployment details (includes parameters and outputs)\n")
	lf.Contents += fmt.Sprintf("az deployment group show \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME\n\n")

	lf.Contents += fmt.Sprintf("# Extract only parameters\n")
	lf.Contents += fmt.Sprintf("az deployment group show \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query 'properties.parameters' -o json\n\n")

	lf.Contents += fmt.Sprintf("# Extract only outputs\n")
	lf.Contents += fmt.Sprintf("az deployment group show \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query 'properties.outputs' -o json\n\n")

	lf.Contents += fmt.Sprintf("# Export template used in deployment\n")
	lf.Contents += fmt.Sprintf("az deployment group export \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME > deployment-template.json\n\n")

	lf.Contents += fmt.Sprintf("### PowerShell: Show deployment with parameters\n\n")
	lf.Contents += fmt.Sprintf("$subscriptionId = \"<SUBSCRIPTION-ID>\"\n")
	lf.Contents += fmt.Sprintf("$resourceGroup = \"<RESOURCE-GROUP-NAME>\"\n")
	lf.Contents += fmt.Sprintf("$deploymentName = \"<DEPLOYMENT-NAME>\"\n\n")

	lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId $subscriptionId\n\n")

	lf.Contents += fmt.Sprintf("# Get deployment details\n")
	lf.Contents += fmt.Sprintf("$deployment = Get-AzResourceGroupDeployment `\n")
	lf.Contents += fmt.Sprintf("  -ResourceGroupName $resourceGroup `\n")
	lf.Contents += fmt.Sprintf("  -Name $deploymentName\n\n")

	lf.Contents += fmt.Sprintf("# View parameters\n")
	lf.Contents += fmt.Sprintf("$deployment.Parameters | ConvertTo-Json -Depth 10\n\n")

	lf.Contents += fmt.Sprintf("# View outputs\n")
	lf.Contents += fmt.Sprintf("$deployment.Outputs | ConvertTo-Json -Depth 10\n\n")

	lf.Contents += fmt.Sprintf("# Export template\n")
	lf.Contents += fmt.Sprintf("$template = (Get-AzResourceGroupDeployment `\n")
	lf.Contents += fmt.Sprintf("  -ResourceGroupName $resourceGroup `\n")
	lf.Contents += fmt.Sprintf("  -Name $deploymentName).TemplateContent\n")
	lf.Contents += fmt.Sprintf("$template | ConvertTo-Json -Depth 100 | Out-File deployment-template.json\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 2: Export Deployment Operations Log
	lf.Contents += fmt.Sprintf("## 2. Export Deployment Operations Log\n\n")

	lf.Contents += fmt.Sprintf("Deployment operations contain detailed logs of all resource creations,\n")
	lf.Contents += fmt.Sprintf("including error messages that may contain sensitive information.\n\n")

	lf.Contents += fmt.Sprintf("### Azure CLI: List deployment operations\n\n")
	lf.Contents += fmt.Sprintf("# List all operations for a deployment\n")
	lf.Contents += fmt.Sprintf("az deployment operation group list \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME\n\n")

	lf.Contents += fmt.Sprintf("# Export operations to JSON file\n")
	lf.Contents += fmt.Sprintf("az deployment operation group list \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  -o json > deployment-operations.json\n\n")

	lf.Contents += fmt.Sprintf("# Show specific operation details\n")
	lf.Contents += fmt.Sprintf("az deployment operation group show \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --operation-id <OPERATION-ID>\n\n")

	lf.Contents += fmt.Sprintf("# Filter operations by status code (e.g., failed operations)\n")
	lf.Contents += fmt.Sprintf("az deployment operation group list \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query \"[?properties.statusCode=='Conflict' || properties.statusCode=='BadRequest']\"\n\n")

	lf.Contents += fmt.Sprintf("### PowerShell: List deployment operations\n\n")
	lf.Contents += fmt.Sprintf("# Get all deployment operations\n")
	lf.Contents += fmt.Sprintf("$operations = Get-AzResourceGroupDeploymentOperation `\n")
	lf.Contents += fmt.Sprintf("  -ResourceGroupName $resourceGroup `\n")
	lf.Contents += fmt.Sprintf("  -DeploymentName $deploymentName\n\n")

	lf.Contents += fmt.Sprintf("# Export to JSON\n")
	lf.Contents += fmt.Sprintf("$operations | ConvertTo-Json -Depth 100 | Out-File deployment-operations.json\n\n")

	lf.Contents += fmt.Sprintf("# View failed operations\n")
	lf.Contents += fmt.Sprintf("$operations | Where-Object { $_.Properties.StatusCode -ne 'OK' } | Format-List\n\n")

	lf.Contents += fmt.Sprintf("# View operation status messages (may contain sensitive data)\n")
	lf.Contents += fmt.Sprintf("$operations | Select-Object @{N='Operation';E={$_.Properties.TargetResource.ResourceName}}, `\n")
	lf.Contents += fmt.Sprintf("  @{N='Status';E={$_.Properties.StatusCode}}, `\n")
	lf.Contents += fmt.Sprintf("  @{N='Message';E={$_.Properties.StatusMessage}}\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 3: Extract Sensitive Data
	lf.Contents += fmt.Sprintf("## 3. Extract Sensitive Data (Database Passwords, Connection Strings)\n\n")

	lf.Contents += fmt.Sprintf("Deployments often contain sensitive parameters like database passwords,\n")
	lf.Contents += fmt.Sprintf("connection strings, API keys, and other credentials.\n\n")

	lf.Contents += fmt.Sprintf("### Common sensitive parameter names to search for:\n\n")
	lf.Contents += fmt.Sprintf("# Azure CLI: Search for sensitive parameters\n")
	lf.Contents += fmt.Sprintf("DEPLOYMENT_PARAMS=$(az deployment group show \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query 'properties.parameters' -o json)\n\n")

	lf.Contents += fmt.Sprintf("# Extract database administrator password\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.administratorLoginPassword.value'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.sqlAdministratorPassword.value'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.databasePassword.value'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.dbPassword.value'\n\n")

	lf.Contents += fmt.Sprintf("# Extract connection strings\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.connectionString.value'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.storageConnectionString.value'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.serviceBusConnectionString.value'\n\n")

	lf.Contents += fmt.Sprintf("# Extract API keys and secrets\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.apiKey.value'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.secret.value'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r '.clientSecret.value'\n\n")

	lf.Contents += fmt.Sprintf("# Search for any parameter containing 'password', 'secret', or 'key'\n")
	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_PARAMS | jq -r 'to_entries | .[] | select(.key | test(\"(?i)(password|secret|key|token)\")) | \"\\(.key): \\(.value.value)\"'\n\n")

	lf.Contents += fmt.Sprintf("# Extract from outputs (sometimes secrets are in outputs too)\n")
	lf.Contents += fmt.Sprintf("DEPLOYMENT_OUTPUTS=$(az deployment group show \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query 'properties.outputs' -o json)\n\n")

	lf.Contents += fmt.Sprintf("echo $DEPLOYMENT_OUTPUTS | jq -r 'to_entries | .[] | select(.key | test(\"(?i)(password|secret|key|token|connection)\")) | \"\\(.key): \\(.value.value)\"'\n\n")

	lf.Contents += fmt.Sprintf("### PowerShell: Search for sensitive parameters\n\n")
	lf.Contents += fmt.Sprintf("# Extract database passwords\n")
	lf.Contents += fmt.Sprintf("$deployment.Parameters.administratorLoginPassword.Value\n")
	lf.Contents += fmt.Sprintf("$deployment.Parameters.sqlAdministratorPassword.Value\n")
	lf.Contents += fmt.Sprintf("$deployment.Parameters.databasePassword.Value\n\n")

	lf.Contents += fmt.Sprintf("# Search all parameters for sensitive data\n")
	lf.Contents += fmt.Sprintf("$deployment.Parameters.GetEnumerator() | Where-Object { \n")
	lf.Contents += fmt.Sprintf("  $_.Key -match '(password|secret|key|token|connection)' \n")
	lf.Contents += fmt.Sprintf("} | Select-Object Key, @{N='Value';E={$_.Value.Value}}\n\n")

	lf.Contents += fmt.Sprintf("# Search outputs for sensitive data\n")
	lf.Contents += fmt.Sprintf("$deployment.Outputs.GetEnumerator() | Where-Object { \n")
	lf.Contents += fmt.Sprintf("  $_.Key -match '(password|secret|key|token|connection)' \n")
	lf.Contents += fmt.Sprintf("} | Select-Object Key, @{N='Value';E={$_.Value.Value}}\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 4: Re-run Deployment with Modified Parameters
	lf.Contents += fmt.Sprintf("## 4. Re-run Deployment with Modified Parameters\n\n")

	lf.Contents += fmt.Sprintf("You can re-run a deployment with modified parameters to:\n")
	lf.Contents += fmt.Sprintf("- Change resource configurations\n")
	lf.Contents += fmt.Sprintf("- Reset passwords to known values\n")
	lf.Contents += fmt.Sprintf("- Modify security settings\n\n")

	lf.Contents += fmt.Sprintf("### Azure CLI: Re-run deployment\n\n")
	lf.Contents += fmt.Sprintf("# Step 1: Export current template and parameters\n")
	lf.Contents += fmt.Sprintf("az deployment group export \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME > template.json\n\n")

	lf.Contents += fmt.Sprintf("az deployment group show \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name $DEPLOYMENT_NAME \\\n")
	lf.Contents += fmt.Sprintf("  --query 'properties.parameters' > parameters.json\n\n")

	lf.Contents += fmt.Sprintf("# Step 2: Modify parameters.json with your desired changes\n")
	lf.Contents += fmt.Sprintf("# Example: Change database administrator password\n")
	lf.Contents += fmt.Sprintf("# Edit parameters.json and modify:\n")
	lf.Contents += fmt.Sprintf("#   \"administratorLoginPassword\": { \"value\": \"NewPassword123!\" }\n\n")

	lf.Contents += fmt.Sprintf("# Step 3: Re-run the deployment with modified parameters\n")
	lf.Contents += fmt.Sprintf("az deployment group create \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name \"${DEPLOYMENT_NAME}-modified\" \\\n")
	lf.Contents += fmt.Sprintf("  --template-file template.json \\\n")
	lf.Contents += fmt.Sprintf("  --parameters @parameters.json\n\n")

	lf.Contents += fmt.Sprintf("# Alternative: Specify parameters inline\n")
	lf.Contents += fmt.Sprintf("az deployment group create \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --name \"${DEPLOYMENT_NAME}-modified\" \\\n")
	lf.Contents += fmt.Sprintf("  --template-file template.json \\\n")
	lf.Contents += fmt.Sprintf("  --parameters administratorLoginPassword=\"NewPassword123!\"\n\n")

	lf.Contents += fmt.Sprintf("### PowerShell: Re-run deployment\n\n")
	lf.Contents += fmt.Sprintf("# Step 1: Export template\n")
	lf.Contents += fmt.Sprintf("$template = (Get-AzResourceGroupDeployment `\n")
	lf.Contents += fmt.Sprintf("  -ResourceGroupName $resourceGroup `\n")
	lf.Contents += fmt.Sprintf("  -Name $deploymentName).TemplateContent\n")
	lf.Contents += fmt.Sprintf("$template | ConvertTo-Json -Depth 100 | Out-File template.json\n\n")

	lf.Contents += fmt.Sprintf("# Step 2: Create modified parameters\n")
	lf.Contents += fmt.Sprintf("$params = @{\n")
	lf.Contents += fmt.Sprintf("  administratorLoginPassword = \"NewPassword123!\"\n")
	lf.Contents += fmt.Sprintf("  # ... other parameters ...\n")
	lf.Contents += fmt.Sprintf("}\n\n")

	lf.Contents += fmt.Sprintf("# Step 3: Re-run deployment\n")
	lf.Contents += fmt.Sprintf("New-AzResourceGroupDeployment `\n")
	lf.Contents += fmt.Sprintf("  -ResourceGroupName $resourceGroup `\n")
	lf.Contents += fmt.Sprintf("  -Name \"$deploymentName-modified\" `\n")
	lf.Contents += fmt.Sprintf("  -TemplateFile template.json `\n")
	lf.Contents += fmt.Sprintf("  -TemplateParameterObject $params\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 5: Validate Template and Parameters
	lf.Contents += fmt.Sprintf("## 5. Validate Template and Parameters\n\n")

	lf.Contents += fmt.Sprintf("Before re-running a deployment, validate the template and parameters.\n\n")

	lf.Contents += fmt.Sprintf("### Azure CLI: Validate deployment\n\n")
	lf.Contents += fmt.Sprintf("az deployment group validate \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --template-file template.json \\\n")
	lf.Contents += fmt.Sprintf("  --parameters @parameters.json\n\n")

	lf.Contents += fmt.Sprintf("# What-if analysis (preview changes without deploying)\n")
	lf.Contents += fmt.Sprintf("az deployment group what-if \\\n")
	lf.Contents += fmt.Sprintf("  --resource-group $RESOURCE_GROUP \\\n")
	lf.Contents += fmt.Sprintf("  --template-file template.json \\\n")
	lf.Contents += fmt.Sprintf("  --parameters @parameters.json\n\n")

	lf.Contents += fmt.Sprintf("### PowerShell: Validate deployment\n\n")
	lf.Contents += fmt.Sprintf("Test-AzResourceGroupDeployment `\n")
	lf.Contents += fmt.Sprintf("  -ResourceGroupName $resourceGroup `\n")
	lf.Contents += fmt.Sprintf("  -TemplateFile template.json `\n")
	lf.Contents += fmt.Sprintf("  -TemplateParameterObject $params\n\n")

	lf.Contents += fmt.Sprintf("# What-if analysis\n")
	lf.Contents += fmt.Sprintf("New-AzResourceGroupDeployment `\n")
	lf.Contents += fmt.Sprintf("  -ResourceGroupName $resourceGroup `\n")
	lf.Contents += fmt.Sprintf("  -TemplateFile template.json `\n")
	lf.Contents += fmt.Sprintf("  -TemplateParameterObject $params `\n")
	lf.Contents += fmt.Sprintf("  -WhatIf\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Summary
	lf.Contents += fmt.Sprintf("## Summary\n\n")
	lf.Contents += fmt.Sprintf("Deployment parameters and outputs often contain sensitive information:\n")
	lf.Contents += fmt.Sprintf("- Database passwords and connection strings\n")
	lf.Contents += fmt.Sprintf("- Storage account keys\n")
	lf.Contents += fmt.Sprintf("- API keys and secrets\n")
	lf.Contents += fmt.Sprintf("- Service principal credentials\n")
	lf.Contents += fmt.Sprintf("- Certificate passwords\n\n")

	lf.Contents += fmt.Sprintf("**Security Considerations:**\n\n")
	lf.Contents += fmt.Sprintf("- Deployment operations are logged in Azure Activity Logs\n")
	lf.Contents += fmt.Sprintf("- Re-running deployments may trigger alerts\n")
	lf.Contents += fmt.Sprintf("- Parameter values are stored in deployment history (up to 200 deployments)\n")
	lf.Contents += fmt.Sprintf("- Use Azure Policy to prevent storing secrets in deployment parameters\n")
	lf.Contents += fmt.Sprintf("- Prefer Azure Key Vault references for sensitive parameters\n\n")
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *DeploymentsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.DeploymentRows) == 0 {
		logger.InfoM("No Deployments found", globals.AZ_DEPLOYMENTS_MODULE_NAME)
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
		"Deployment Name",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.DeploymentRows, headers,
			"deployments", globals.AZ_DEPLOYMENTS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.DeploymentRows, headers,
			"deployments", globals.AZ_DEPLOYMENTS_MODULE_NAME,
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
	output := DeploymentsOutput{
		Table: []internal.TableFile{{
			Name:   "deployments",
			Header: headers,
			Body:   m.DeploymentRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DEPLOYMENTS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Deployment(s) across %d subscription(s)", len(m.DeploymentRows), len(m.Subscriptions)), globals.AZ_DEPLOYMENTS_MODULE_NAME)
}

// ------------------------------
// Helper function
// ------------------------------

// GetDeploymentsPerResourceGroup returns a slice of deployments for a given subscription and resource group
func GetDeploymentsPerResourceGroup(session *azinternal.SafeSession, subscriptionID, resourceGroupName string) ([]*armresources.DeploymentExtended, *armresources.DeploymentsClient, error) {
	ctx := context.Background()
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	client, err := armresources.NewDeploymentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create deployments client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(resourceGroupName, nil)
	deployments := []*armresources.DeploymentExtended{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get deployments page: %w", err)
		}
		for _, d := range page.Value {
			deployments = append(deployments, d)
		}
	}

	return deployments, client, nil
}
