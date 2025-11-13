package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzFunctionsCommand = &cobra.Command{
	Use:     "functions",
	Aliases: []string{"funcs"},
	Short:   "Enumerate Azure Functions",
	Long: `
Enumerate Azure Functions for a specific tenant:
./cloudfox az functions --tenant TENANT_ID

Enumerate Azure Functions for a specific subscription:
./cloudfox az functions --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListFunctions,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type FunctionsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	FunctionRows  [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type FunctionsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FunctionsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FunctionsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListFunctions(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_FUNCTIONS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &FunctionsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		FunctionRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"functions-settings":      {Name: "functions-settings", Contents: ""},
			"functions-download":      {Name: "functions-download", Contents: ""},
			"functions-keys-commands": {Name: "functions-keys-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintFunctions(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *FunctionsModule) PrintFunctions(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_FUNCTIONS_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_FUNCTIONS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_FUNCTIONS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Functions for %d subscription(s)", len(m.Subscriptions)), globals.AZ_FUNCTIONS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_FUNCTIONS_MODULE_NAME, m.processSubscription)
	}

	// Generate function keys extraction commands
	m.generateFunctionKeysLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *FunctionsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *FunctionsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	funcApps, err := azinternal.GetFunctionAppsPerResourceGroup(m.Session, subID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list function apps in %s/%s: %v", subID, rgName, err), globals.AZ_FUNCTIONS_MODULE_NAME)
		}
		return
	}

	// Check which apps have Easy Auth enabled (works for function apps too)
	authConfigs := azinternal.GetWebAppAuthConfigs(m.Session, subID, funcApps)

	// Create a map of app names with Easy Auth enabled for quick lookup
	authEnabledApps := make(map[string]bool)
	for _, config := range authConfigs {
		authEnabledApps[config.AppName] = true
	}

	for _, app := range funcApps {
		if app == nil || app.Name == nil {
			continue
		}

		appName := *app.Name
		region := *app.Location
		privateIPs, publicIPs, vnetName, subnetName := azinternal.GetFunctionAppNetworkInfo(subID, rgName, app)

		// --- Security Settings ---
		httpsOnly := "No"
		minTlsVersion := "N/A"

		// EntraID Centralized Auth (Easy Auth / App Service Authentication)
		authEnabled := "Disabled"
		if authEnabledApps[appName] {
			authEnabled = "Enabled"
		}

		if app.Properties != nil {
			// HTTPS Only
			if app.Properties.HTTPSOnly != nil && *app.Properties.HTTPSOnly {
				httpsOnly = "Yes"
			}

			// Minimum TLS Version
			if app.Properties.SiteConfig != nil && app.Properties.SiteConfig.MinTLSVersion != nil {
				minTlsVersion = string(*app.Properties.SiteConfig.MinTLSVersion)
			}
		}

		// --- App Service Plan (SKU) ---
		appServicePlan := "N/A"
		if app.Properties != nil && app.Properties.ServerFarmID != nil {
			// Extract plan name from resource ID: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/serverfarms/{planName}
			serverFarmID := *app.Properties.ServerFarmID
			parts := strings.Split(serverFarmID, "/")
			if len(parts) > 0 {
				appServicePlan = parts[len(parts)-1] // Last part is the plan name
			}
		}

		// --- Tags ---
		tags := "N/A"
		if app.Tags != nil && len(app.Tags) > 0 {
			var tagPairs []string
			for k, v := range app.Tags {
				if v != nil {
					tagPairs = append(tagPairs, fmt.Sprintf("%s:%s", k, *v))
				} else {
					tagPairs = append(tagPairs, k)
				}
			}
			if len(tagPairs) > 0 {
				tags = strings.Join(tagPairs, ", ")
			}
		}

		// --- Runtime Version ---
		runtime := "N/A"
		if app.Properties != nil && app.Properties.SiteConfig != nil {
			// Linux runtime stack (e.g., "NODE|14-lts", "PYTHON|3.9", "DOTNETCORE|6.0")
			if app.Properties.SiteConfig.LinuxFxVersion != nil && *app.Properties.SiteConfig.LinuxFxVersion != "" {
				runtime = *app.Properties.SiteConfig.LinuxFxVersion
			} else if app.Properties.SiteConfig.WindowsFxVersion != nil && *app.Properties.SiteConfig.WindowsFxVersion != "" {
				// Windows runtime stack
				runtime = *app.Properties.SiteConfig.WindowsFxVersion
			} else if app.Properties.SiteConfig.JavaVersion != nil && *app.Properties.SiteConfig.JavaVersion != "" {
				// Java version
				runtime = fmt.Sprintf("Java|%s", *app.Properties.SiteConfig.JavaVersion)
			} else if app.Properties.SiteConfig.NodeVersion != nil && *app.Properties.SiteConfig.NodeVersion != "" {
				// Node version
				runtime = fmt.Sprintf("Node|%s", *app.Properties.SiteConfig.NodeVersion)
			} else if app.Properties.SiteConfig.PythonVersion != nil && *app.Properties.SiteConfig.PythonVersion != "" {
				// Python version
				runtime = fmt.Sprintf("Python|%s", *app.Properties.SiteConfig.PythonVersion)
			}
		}

		// Determine managed identities
		systemAssignedID := "N/A"
		userAssignedID := "N/A"

		if app.Identity != nil {
			// System Assigned Identity ID
			if app.Identity.PrincipalID != nil {
				systemAssignedID = *app.Identity.PrincipalID
			}

			// User Assigned Identity IDs
			if app.Identity.UserAssignedIdentities != nil && len(app.Identity.UserAssignedIdentities) > 0 {
				var userAssignedIDs []string
				for _, v := range app.Identity.UserAssignedIdentities {
					if v != nil && v.PrincipalID != nil {
						userAssignedIDs = append(userAssignedIDs, *v.PrincipalID)
					}
				}
				if len(userAssignedIDs) > 0 {
					userAssignedID = strings.Join(userAssignedIDs, "\n")
				}
			}
		}

		// Build single row per function app
		row := []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			region,
			appName,
			appServicePlan,
			runtime,
			tags,
			strings.Join(privateIPs, ","),
			strings.Join(publicIPs, ","),
			vnetName,
			subnetName,
			httpsOnly,
			minTlsVersion,
			authEnabled,
			systemAssignedID,
			userAssignedID,
		}

		// Thread-safe append - lock protects both FunctionRows and LootMap updates
		m.mu.Lock()
		m.FunctionRows = append(m.FunctionRows, row)

		// Loot: extract AppSettings and ConnectionStrings
		if app.Properties.SiteConfig != nil {
			for _, cs := range app.Properties.SiteConfig.ConnectionStrings {
				m.LootMap["functions-settings"].Contents += fmt.Sprintf(
					"Subscription: %s\nResourceGroup: %s\nFunctionApp: %s\nConnection String Name: %s\nValue: %s\n\n",
					subID, rgName, appName, azinternal.SafeStringPtr(cs.Name), azinternal.SafeStringPtr(cs.ConnectionString),
				)
			}
			for _, setting := range app.Properties.SiteConfig.AppSettings {
				m.LootMap["functions-settings"].Contents += fmt.Sprintf(
					"Subscription: %s\nResourceGroup: %s\nFunctionApp: %s\nApp Setting: %s = %s\n\n",
					subID, rgName, appName, azinternal.SafeStringPtr(setting.Name), azinternal.SafeStringPtr(setting.Value),
				)
			}
		}

		// Loot: commands to download function code
		m.LootMap["functions-download"].Contents += fmt.Sprintf(
			"## Download Function App Code: %s\n"+
				"# Az CLI:\n"+
				"az account set --subscription %s\n"+
				"az functionapp deployment list-publishing-profiles --name %s --resource-group %s --query '[?publishMethod==`Zip`].{FTP: ftpUrl,User: userName,Pass: userPWD}' -o json\n"+
				"\n"+
				"## PowerShell equivalent\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzFunctionAppPublishingProfile -ResourceGroupName %s -Name %s -OutputFile %s-profile.json\n\n",
			appName, subID, appName, rgName, subID, rgName, appName, appName,
		)
		m.mu.Unlock()
	}
}

// ------------------------------
// Generate function keys extraction commands
// ------------------------------
func (m *FunctionsModule) generateFunctionKeysLoot() {
	// Extract unique function apps
	type FunctionAppInfo struct {
		SubscriptionID, SubscriptionName, ResourceGroup, Region, AppName string
	}

	uniqueFunctionApps := make(map[string]FunctionAppInfo)

	for _, row := range m.FunctionRows {
		if len(row) < 7 { // Updated for tenant columns
			continue
		}

		subID := row[2]   // Shifted by +2 for tenant columns
		subName := row[3] // Shifted by +2 for tenant columns
		rgName := row[4]  // Shifted by +2 for tenant columns
		region := row[5]  // Shifted by +2 for tenant columns
		appName := row[6] // Shifted by +2 for tenant columns

		key := subID + "/" + rgName + "/" + appName
		uniqueFunctionApps[key] = FunctionAppInfo{
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			Region:           region,
			AppName:          appName,
		}
	}

	if len(uniqueFunctionApps) == 0 {
		return
	}

	lf := m.LootMap["functions-keys-commands"]
	lf.Contents += "# Function App Keys Extraction Commands\n"
	lf.Contents += "# NOTE: Function keys provide direct access to invoke functions without authentication.\n"
	lf.Contents += "# Key types:\n"
	lf.Contents += "#   - Master/Host keys: Access to ALL functions in the app (highest privilege)\n"
	lf.Contents += "#   - Function-level keys: Access to specific functions only\n"
	lf.Contents += "#   - System keys: Special internal keys\n\n"

	for _, app := range uniqueFunctionApps {
		lf.Contents += fmt.Sprintf("## Function App: %s (Subscription: %s, RG: %s)\n", app.AppName, app.SubscriptionID, app.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", app.SubscriptionID)

		// List all host keys (master keys)
		lf.Contents += fmt.Sprintf("# Step 1: List host/master keys (access to ALL functions)\n")
		lf.Contents += fmt.Sprintf("az functionapp keys list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  -o json | jq\n\n")

		lf.Contents += fmt.Sprintf("# Get master key value\n")
		lf.Contents += fmt.Sprintf("MASTER_KEY=$(az functionapp keys list --resource-group %s --name %s --query 'masterKey' -o tsv)\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("echo \"Master Key: $MASTER_KEY\"\n\n")

		lf.Contents += fmt.Sprintf("# Get default host key value\n")
		lf.Contents += fmt.Sprintf("DEFAULT_KEY=$(az functionapp keys list --resource-group %s --name %s --query 'functionKeys.default' -o tsv)\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("echo \"Default Host Key: $DEFAULT_KEY\"\n\n")

		// List all functions in the app
		lf.Contents += fmt.Sprintf("# Step 2: List all functions in the function app\n")
		lf.Contents += fmt.Sprintf("az functionapp function list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --query '[].name' \\\n")
		lf.Contents += fmt.Sprintf("  -o table\n\n")

		// List function-level keys
		lf.Contents += fmt.Sprintf("# Step 3: List function-level keys for each function\n")
		lf.Contents += fmt.Sprintf("# First, get all function names\n")
		lf.Contents += fmt.Sprintf("FUNCTIONS=$(az functionapp function list --resource-group %s --name %s --query '[].name' -o tsv)\n\n", app.ResourceGroup, app.AppName)

		lf.Contents += fmt.Sprintf("# Loop through each function and get its keys\n")
		lf.Contents += fmt.Sprintf("for FUNC_NAME in $FUNCTIONS; do\n")
		lf.Contents += fmt.Sprintf("  echo \"Function: $FUNC_NAME\"\n")
		lf.Contents += fmt.Sprintf("  az functionapp function keys list \\\n")
		lf.Contents += fmt.Sprintf("    --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("    --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("    --function-name \"$FUNC_NAME\" \\\n")
		lf.Contents += fmt.Sprintf("    -o json | jq\n")
		lf.Contents += fmt.Sprintf("done\n\n")

		// Show a specific function's keys
		lf.Contents += fmt.Sprintf("# Get keys for a specific function (replace <FUNCTION-NAME>)\n")
		lf.Contents += fmt.Sprintf("az functionapp function keys list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --function-name <FUNCTION-NAME> \\\n")
		lf.Contents += fmt.Sprintf("  -o json | jq\n\n")

		// Create new function key
		lf.Contents += fmt.Sprintf("# Step 4: Create new host key (for persistence)\n")
		lf.Contents += fmt.Sprintf("az functionapp keys set \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --key-type functionKeys \\\n")
		lf.Contents += fmt.Sprintf("  --key-name \"backup-key\" \\\n")
		lf.Contents += fmt.Sprintf("  --key-value \"<RANDOM-KEY-VALUE>\"\n\n")

		// Create function-level key
		lf.Contents += fmt.Sprintf("# Create new function-level key\n")
		lf.Contents += fmt.Sprintf("az functionapp function keys set \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --function-name <FUNCTION-NAME> \\\n")
		lf.Contents += fmt.Sprintf("  --key-name \"backup-key\" \\\n")
		lf.Contents += fmt.Sprintf("  --key-value \"<RANDOM-KEY-VALUE>\"\n\n")

		// Delete key (cleanup)
		lf.Contents += fmt.Sprintf("# Step 5: Delete a key (cleanup)\n")
		lf.Contents += fmt.Sprintf("az functionapp keys delete \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --key-type functionKeys \\\n")
		lf.Contents += fmt.Sprintf("  --key-name \"backup-key\"\n\n")

		// HTTP request examples
		lf.Contents += fmt.Sprintf("# Step 6: Example HTTP requests using function keys\n")
		lf.Contents += fmt.Sprintf("# Get the function app URL\n")
		lf.Contents += fmt.Sprintf("APP_URL=$(az functionapp show --resource-group %s --name %s --query 'defaultHostName' -o tsv)\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("echo \"Function App URL: https://$APP_URL\"\n\n")

		lf.Contents += fmt.Sprintf("# Invoke function using master key (works for ALL functions)\n")
		lf.Contents += fmt.Sprintf("curl \"https://$APP_URL/api/<FUNCTION-NAME>?code=$MASTER_KEY\"\n\n")

		lf.Contents += fmt.Sprintf("# Invoke function using host key\n")
		lf.Contents += fmt.Sprintf("curl \"https://$APP_URL/api/<FUNCTION-NAME>?code=$DEFAULT_KEY\"\n\n")

		lf.Contents += fmt.Sprintf("# Invoke function with POST data\n")
		lf.Contents += fmt.Sprintf("curl -X POST \"https://$APP_URL/api/<FUNCTION-NAME>?code=$MASTER_KEY\" \\\n")
		lf.Contents += fmt.Sprintf("  -H \"Content-Type: application/json\" \\\n")
		lf.Contents += fmt.Sprintf("  -d '{\"name\":\"test\"}'\n\n")

		// Alternative: use x-functions-key header
		lf.Contents += fmt.Sprintf("# Invoke using key in header (alternative to query parameter)\n")
		lf.Contents += fmt.Sprintf("curl \"https://$APP_URL/api/<FUNCTION-NAME>\" \\\n")
		lf.Contents += fmt.Sprintf("  -H \"x-functions-key: $MASTER_KEY\"\n\n")

		// List all function URLs
		lf.Contents += fmt.Sprintf("# Get all function trigger URLs with keys\n")
		lf.Contents += fmt.Sprintf("for FUNC_NAME in $FUNCTIONS; do\n")
		lf.Contents += fmt.Sprintf("  echo \"https://$APP_URL/api/$FUNC_NAME?code=$MASTER_KEY\"\n")
		lf.Contents += fmt.Sprintf("done\n\n")

		// PowerShell equivalents
		lf.Contents += fmt.Sprintf("## PowerShell Equivalents\n")
		lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n\n", app.SubscriptionID)

		lf.Contents += fmt.Sprintf("# List all host keys\n")
		lf.Contents += fmt.Sprintf("$keys = Invoke-AzResourceAction -ResourceType 'Microsoft.Web/sites/host' -ResourceName '%s/default' -ResourceGroupName %s -Action listkeys -ApiVersion '2022-03-01' -Force\n", app.AppName, app.ResourceGroup)
		lf.Contents += fmt.Sprintf("$keys | ConvertTo-Json\n\n")

		lf.Contents += fmt.Sprintf("# Get master key\n")
		lf.Contents += fmt.Sprintf("$masterKey = $keys.masterKey\n")
		lf.Contents += fmt.Sprintf("Write-Host \"Master Key: $masterKey\"\n\n")

		lf.Contents += fmt.Sprintf("# List all functions\n")
		lf.Contents += fmt.Sprintf("$functions = Get-AzFunctionApp -ResourceGroupName %s -Name %s | Get-AzFunctionAppFunction\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("$functions | Format-Table Name\n\n")

		lf.Contents += fmt.Sprintf("# Get function-level keys for a specific function\n")
		lf.Contents += fmt.Sprintf("$functionKeys = Invoke-AzResourceAction -ResourceType 'Microsoft.Web/sites/functions' -ResourceName '%s/<FUNCTION-NAME>' -ResourceGroupName %s -Action listkeys -ApiVersion '2022-03-01' -Force\n", app.AppName, app.ResourceGroup)
		lf.Contents += fmt.Sprintf("$functionKeys | ConvertTo-Json\n\n")

		lf.Contents += fmt.Sprintf("# Invoke function using PowerShell\n")
		lf.Contents += fmt.Sprintf("$appUrl = (Get-AzFunctionApp -ResourceGroupName %s -Name %s).DefaultHostName\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("Invoke-RestMethod -Uri \"https://$appUrl/api/<FUNCTION-NAME>?code=$masterKey\" -Method Get\n\n")

		lf.Contents += fmt.Sprintf("# Invoke with POST\n")
		lf.Contents += fmt.Sprintf("$body = @{ name = 'test' } | ConvertTo-Json\n")
		lf.Contents += fmt.Sprintf("Invoke-RestMethod -Uri \"https://$appUrl/api/<FUNCTION-NAME>?code=$masterKey\" -Method Post -Body $body -ContentType 'application/json'\n\n")

		lf.Contents += fmt.Sprintf("---\n\n")
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *FunctionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.FunctionRows) == 0 {
		logger.InfoM("No Functions found", globals.AZ_FUNCTIONS_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"FunctionApp Name",
		"App Service Plan",
		"Runtime",
		"Tags",
		"Private IPs",
		"Public IPs",
		"VNet Name",
		"Subnet",
		"HTTPS Only",
		"Min TLS Version",
		"EntraID Centralized Auth",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.FunctionRows,
			headers,
			"functions",
			globals.AZ_FUNCTIONS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.FunctionRows, headers,
			"functions", globals.AZ_FUNCTIONS_MODULE_NAME,
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
	output := FunctionsOutput{
		Table: []internal.TableFile{{
			Name:   "functions",
			Header: headers,
			Body:   m.FunctionRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_FUNCTIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Function App(s) across %d subscription(s)", len(m.FunctionRows), len(m.Subscriptions)), globals.AZ_FUNCTIONS_MODULE_NAME)
}
