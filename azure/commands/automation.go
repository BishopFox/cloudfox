package commands

import (
	"context"
	"encoding/json"
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
var AzAutomationCommand = &cobra.Command{
	Use:     "automation",
	Aliases: []string{"auto"},
	Short:   "Enumerate Azure Automation (Runbooks, Accounts, Variables, Schedules, Assets)",
	Long: `
Enumerate Azure Automation resources for a specific tenant:
./cloudfox az automation --tenant TENANT_ID

Enumerate Azure Automation resources for a specific subscription:
./cloudfox az automation --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListAutomation,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type AutomationModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions  []string
	AutomationRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type AutomationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AutomationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AutomationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListAutomation(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_AUTOMATION_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &AutomationModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		AutomationRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"automation-variables":              {Name: "automation-variables", Contents: ""},
			"automation-commands":               {Name: "automation-commands", Contents: ""},
			"automation-runbooks":               {Name: "automation-runbooks", Contents: ""},
			"automation-schedules":              {Name: "automation-schedules", Contents: ""},
			"automation-assets":                 {Name: "automation-assets", Contents: ""},
			"automation-connections":            {Name: "automation-connections", Contents: ""},
			"automation-scope-runbooks":         {Name: "automation-scope-runbooks", Contents: ""},
			"automation-hybrid-workers":         {Name: "automation-hybrid-workers", Contents: ""},
			"automation-hybrid-cert-extraction": {Name: "automation-hybrid-cert-extraction", Contents: ""},
			"automation-hybrid-jrds-extraction": {Name: "automation-hybrid-jrds-extraction", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintAutomation(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *AutomationModule) PrintAutomation(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_AUTOMATION_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			// Save current tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Set tenant context for this iteration
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_AUTOMATION_MODULE_NAME, m.processSubscription)

			// Restore original tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Use the centralized subscription enumeration orchestrator
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_AUTOMATION_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *AutomationModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// ==================== HYBRID WORKER ENUMERATION ====================
	// Enumerate Hybrid Worker VMs for this subscription
	hybridWorkerVMs, _ := azinternal.GetVMsWithHybridWorkerExtension(ctx, m.Session, subID, resourceGroups)

	// Generate loot for Hybrid Workers
	if len(hybridWorkerVMs) > 0 {
		go m.generateHybridWorkerLoot(subID, subName, hybridWorkerVMs)
	}

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		if rgName == "" {
			continue
		}
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *AutomationModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)
	if region == "" {
		region = "N/A"
	}

	// Get Automation Accounts in RG
	automationAccounts, _ := azinternal.GetAutomationAccountsPerResourceGroup(ctx, m.Session, subID, rgName)

	// If none, add a placeholder row
	if len(automationAccounts) == 0 {
		m.mu.Lock()
		m.AutomationRows = append(m.AutomationRows, []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			region,
			"N/A", // Automation Account
			"N/A", // Resource Name
			"N/A", // Resource Type
			"0",   // Runbook Count
			"N/A", // Last Modified
			"N/A", // State / ProvisioningState
			"N/A", // Runbook Type
			"N/A", // System Assigned Identity ID
			"N/A", // User Assigned Identity ID
			"N/A", // Security Recommendations
		})
		m.mu.Unlock()
		return
	}

	// For each automation account
	for _, acc := range automationAccounts {
		accName := azinternal.SafeStringPtr(acc.Name)
		accLocation := azinternal.SafeStringPtr(acc.Location)
		if accLocation == "" {
			accLocation = region
		}

		// Identity handling (system vs user-assigned managed identities)
		userAssignedIDs := []string{}
		systemAssignedIDs := []string{}

		if acc.Identity != nil {
			// System-assigned identity
			if acc.Identity.Type != nil && (*acc.Identity.Type == "SystemAssigned" || *acc.Identity.Type == "SystemAssigned, UserAssigned") {
				if acc.Identity.PrincipalID != nil {
					principalID := *acc.Identity.PrincipalID
					systemAssignedIDs = append(systemAssignedIDs, principalID)
				}
			}

			// User-assigned identities
			if acc.Identity.UserAssignedIdentities != nil {
				for uaID := range acc.Identity.UserAssignedIdentities {
					userAssignedIDs = append(userAssignedIDs, uaID)
				}
			}
		}

		// Format identity fields
		systemIDsStr := "N/A"
		if len(systemAssignedIDs) > 0 {
			systemIDsStr = strings.Join(systemAssignedIDs, ", ")
		}

		userIDsStr := "N/A"
		if len(userAssignedIDs) > 0 {
			userIDsStr = strings.Join(userAssignedIDs, ", ")
		}

		// Enumerate runbooks, variables, schedules, assets
		runbooks, _ := azinternal.GetRunbooksForAutomationAccount(ctx, m.Session, subID, rgName, accName)
		variables, _ := azinternal.GetAutomationVariables(ctx, m.Session, subID, rgName, accName)
		schedules, _ := azinternal.GetAutomationSchedules(ctx, m.Session, subID, rgName, accName)
		assets, _ := azinternal.GetAutomationAssets(ctx, m.Session, subID, rgName, accName)

		runbookCount := 0
		if runbooks != nil {
			runbookCount = len(runbooks)
		}

		// Runbook last modified handling
		lastModified := "N/A"
		if len(runbooks) > 0 {
			var latest time.Time
			for _, rb := range runbooks {
				if rb.Properties != nil && rb.Properties.LastModifiedTime != nil {
					if t := *rb.Properties.LastModifiedTime; t.After(latest) {
						latest = t
					}
				}
			}
			if !latest.IsZero() {
				lastModified = latest.Format(time.RFC3339)
			}
		}

		state := azinternal.SafeStringPtr(acc.Properties.State)

		// Generate security recommendations for automation account
		hasSystemIdentity := len(systemAssignedIDs) > 0
		hasUserIdentity := len(userAssignedIDs) > 0
		accountRecommendations := m.generateAccountSecurityRecommendations(variables, 0, hasSystemIdentity, hasUserIdentity)

		// Thread-safe append - main account row
		m.mu.Lock()
		m.AutomationRows = append(m.AutomationRows, []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			accLocation,
			accName,             // Automation Account
			accName,             // Resource Name (account-level)
			"AutomationAccount", // Resource Type
			fmt.Sprintf("%d", runbookCount),
			lastModified,
			state,
			"N/A",
			systemIDsStr,
			userIDsStr,
			accountRecommendations, // NEW: security recommendations
		})

		// Add per-runbook rows with more detail
		if runbooks != nil {
			for _, rb := range runbooks {
				rbName := azinternal.SafeString(rb.Name)
				rbType := "Runbook"
				rbState := "N/A"
				rbLastModified := "N/A"
				rbRunbookType := "N/A"

				// State
				if rb.Properties != nil && rb.Properties.State != nil {
					rbState = string(*rb.Properties.State)
				}

				// Last modified safely
				if rb.Properties != nil && rb.Properties.LastModifiedTime != nil {
					rbLastModified = (*rb.Properties.LastModifiedTime).Format(time.RFC3339)
				}

				if rb.Properties != nil && rb.Properties.RunbookType != nil {
					rbRunbookType = string(*rb.Properties.RunbookType)
				}

				// Generate security recommendations for this runbook (scan for secrets)
				// Note: This may be slow for large numbers of runbooks, but provides valuable security insights
				runbookRecommendations := m.generateRunbookSecurityRecommendations(ctx, subID, rgName, accName, rbName)

				m.AutomationRows = append(m.AutomationRows, []string{
					m.TenantName, // NEW: for multi-tenant support
					m.TenantID,   // NEW: for multi-tenant support
					subID,
					subName,
					rgName,
					accLocation,
					accName,
					rbName,
					rbType,
					"1",
					rbLastModified,
					rbState,
					rbRunbookType,
					systemIDsStr,
					userIDsStr,
					runbookRecommendations, // NEW: security recommendations
				})
			}
		}
		m.mu.Unlock()

		// ==================== CONNECTION SCOPE ENUMERATION ====================
		// Get automation connections
		connections, _ := azinternal.GetAutomationConnections(ctx, m.Session, subID, rgName, accName)

		// Generate scope enumeration runbook script
		scopeRunbookScript := azinternal.GenerateScopeEnumerationRunbook(accName, connections, acc)

		// Document identity scope results (without executing runbook)
		scopeResults, _ := azinternal.EnumerateIdentityScope(ctx, m.Session, subID, rgName, accName, acc)

		// Loot generation (goroutine per automation account)
		go m.generateLoot(ctx, subID, subName, rgName, accName, variables, runbooks, schedules, assets, connections, scopeRunbookScript, scopeResults)
	}
}

// ------------------------------
// Loot generation (per automation account)
// ------------------------------
func (m *AutomationModule) generateLoot(ctx context.Context, subID, subName, rgName, accName string, variables []azinternal.AutomationVariable, runbooks []azinternal.Runbook, schedules []azinternal.AutomationSchedule, assets []azinternal.AutomationAsset, connections []azinternal.AutomationConnection, scopeRunbookScript string, scopeResults []azinternal.ConnectionScopeResult) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// -------- automation-commands (all commands in ONE file) --------
	if lf, ok := m.LootMap["automation-commands"]; ok {
		lf.Contents += fmt.Sprintf("## Automation Account: %s (Resource Group: %s)\n", accName, rgName)
		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
		lf.Contents += fmt.Sprintf("\n## List automation accounts\n")
		lf.Contents += fmt.Sprintf("az automation account list --resource-group %s --query \"[].{name:name,location:location}\" -o table\n\n", rgName)

		// Runbooks commands with actual names
		for _, rb := range runbooks {
			rbName := azinternal.SafeString(rb.Name)
			lf.Contents += fmt.Sprintf("## List runbooks for account\n")
			lf.Contents += fmt.Sprintf("az automation runbook list --automation-account-name %s --resource-group %s -o table\n\n", accName, rgName)
			lf.Contents += fmt.Sprintf("## Download runbook content\n")
			lf.Contents += fmt.Sprintf("az automation runbook show --automation-account-name %s --name %s --resource-group %s -o json\n\n", accName, rbName, rgName)
			lf.Contents += fmt.Sprintf("## Download published runbook\n")
			lf.Contents += fmt.Sprintf("url=$(az automation runbook show --automation-account-name %s --name %s --resource-group %s --query \"properties.publishContentLink.uri\" -o tsv)\n", accName, rbName, rgName)
			lf.Contents += fmt.Sprintf("outfile=\"%s.ps1\"\n", rbName)
			lf.Contents += "curl -sSL \"$url\" -o \"$outfile\"\n\n"
			lf.Contents += fmt.Sprintf("## Download draft runbook\n")
			lf.Contents += fmt.Sprintf("url=$(az automation runbook show --automation-account-name %s --name %s --resource-group %s --query \"draft.contentLink.uri\" -o tsv)\n", accName, rbName, rgName)
			lf.Contents += fmt.Sprintf("outfile=\"%s-draft.ps1\"\n", rbName)
			lf.Contents += "curl -sSL \"$url\" -o \"$outfile\"\n\n"

			lf.Contents += fmt.Sprintf("## PowerShell equivalents\n")
			lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n", subID)
			lf.Contents += fmt.Sprintf("Get-AzAutomationRunbook -AutomationAccountName %s -Name %s -ResourceGroupName %s | Export-Clixml -Path %s-%s-clixml\n\n", accName, rbName, rgName, accName, rbName)
			lf.Contents += fmt.Sprintf("## Download published runbook (PowerShell)\n")
			lf.Contents += fmt.Sprintf("$url = (Get-AzAutomationRunbook -AutomationAccountName %s -Name %s -ResourceGroupName %s).PublishContentLink.Uri\n", accName, rbName, rgName)
			lf.Contents += fmt.Sprintf("$outfile = \"%s.ps1\"\n", rbName)
			lf.Contents += "if ($url) { Invoke-WebRequest -Uri $url -OutFile $outfile }\n\n"
			lf.Contents += fmt.Sprintf("## Download draft runbook (PowerShell)\n")
			lf.Contents += fmt.Sprintf("$url = (Get-AzAutomationRunbook -AutomationAccountName %s -Name %s -ResourceGroupName %s).Draft.ContentLink.Uri\n", accName, rbName, rgName)
			lf.Contents += fmt.Sprintf("$outfile = \"%s-draft.ps1\"\n", rbName)
			lf.Contents += "if ($url) { Invoke-WebRequest -Uri $url -OutFile $outfile }\n\n"
		}

		// Variables commands
		for _, v := range variables {
			varName := azinternal.SafeStringPtr(v.Name)
			lf.Contents += fmt.Sprintf("## Variable: %s\n", varName)
			lf.Contents += fmt.Sprintf("az automation variable show --automation-account-name %s --resource-group %s --name %s -o json\n\n", accName, rgName, varName)
		}

		// Schedules commands
		for _, s := range schedules {
			schedName := azinternal.SafeStringPtr(s.Name)
			lf.Contents += fmt.Sprintf("## Schedule: %s\n", schedName)
			lf.Contents += fmt.Sprintf("az automation schedule show --automation-account-name %s --resource-group %s --name %s -o json\n\n", accName, rgName, schedName)
		}

		// Assets commands
		for _, a := range assets {
			assetName := azinternal.SafeStringPtr(a.Name)
			lf.Contents += fmt.Sprintf("## Asset: %s (Type: %s)\n\n", assetName, azinternal.SafeStringPtr(a.Type))
		}
	}

	// -------- Separate loot files for actual contents --------
	if lf, ok := m.LootMap["automation-variables"]; ok {
		for _, v := range variables {
			varName := azinternal.SafeStringPtr(v.Name)
			lf.Contents += fmt.Sprintf("Variable: %s\nValue: %s\nEncrypted: %v\nDescription: %s\n\n", varName, azinternal.SafeStringPtr(v.Properties.Value), v.Properties.IsEncrypted, azinternal.SafeStringPtr(v.Properties.Description))
		}
	}

	// -------------------- Runbooks --------------------
	if lf, ok := m.LootMap["automation-runbooks"]; ok && runbooks != nil {
		lf.Contents += fmt.Sprintf("\n" + strings.Repeat("=", 80) + "\n")
		lf.Contents += fmt.Sprintf("AUTOMATION ACCOUNT: %s\n", accName)
		lf.Contents += fmt.Sprintf("RESOURCE GROUP: %s\n", rgName)
		lf.Contents += fmt.Sprintf("SUBSCRIPTION: %s (%s)\n", subName, subID)
		lf.Contents += fmt.Sprintf(strings.Repeat("=", 80) + "\n\n")

		for _, rb := range runbooks {
			rbName := azinternal.SafeString(rb.Name)

			// Header for this runbook
			lf.Contents += fmt.Sprintf("\n" + strings.Repeat("-", 80) + "\n")
			lf.Contents += fmt.Sprintf("RUNBOOK: %s\n", rbName)
			lf.Contents += fmt.Sprintf(strings.Repeat("-", 80) + "\n\n")

			// 1) Serialize metadata as JSON (your local Runbook struct)
			lf.Contents += fmt.Sprintf("### Runbook Metadata ###\n")
			rbJSON, err := json.MarshalIndent(rb, "", "  ")
			if err != nil {
				lf.Contents += fmt.Sprintf("Failed to marshal runbook metadata %s: %v\n\n", rbName, err)
			} else {
				lf.Contents += string(rbJSON) + "\n\n"
			}

			// 2) Attempt to download the actual runbook script using REST API
			lf.Contents += fmt.Sprintf("### Runbook Script Content ###\n")
			script, err := azinternal.FetchRunbookScript(ctx, m.Session, subID, rgName, accName, rbName)
			if err != nil {
				lf.Contents += fmt.Sprintf("ERROR: Failed to download runbook script for %s: %v\n\n", rbName, err)
			} else {
				// Include the actual script with clear boundaries
				lf.Contents += fmt.Sprintf("# File: %s-%s.ps1\n", accName, rbName)
				lf.Contents += fmt.Sprintf("# Automation Account: %s\n", accName)
				lf.Contents += fmt.Sprintf("# Resource Group: %s\n", rgName)
				lf.Contents += fmt.Sprintf("# Subscription: %s\n\n", subID)
				lf.Contents += "# BEGIN SCRIPT CONTENT\n"
				lf.Contents += strings.Repeat("#", 80) + "\n\n"
				lf.Contents += script + "\n\n"
				lf.Contents += strings.Repeat("#", 80) + "\n"
				lf.Contents += "# END SCRIPT CONTENT\n\n"
			}
		}

		lf.Contents += fmt.Sprintf("\n" + strings.Repeat("=", 80) + "\n")
		lf.Contents += fmt.Sprintf("END OF AUTOMATION ACCOUNT: %s\n", accName)
		lf.Contents += fmt.Sprintf(strings.Repeat("=", 80) + "\n\n")
	}

	// -------------------- Schedules --------------------
	if lf, ok := m.LootMap["automation-schedules"]; ok && schedules != nil {
		lf.Contents += fmt.Sprintf("## Schedules for Automation Account %s (Resource Group: %s)\n", accName, rgName)
		schedJSON, err := json.MarshalIndent(schedules, "", "  ")
		if err != nil {
			schedJSON = []byte(fmt.Sprintf("Failed to marshal schedules: %v", err))
		}
		lf.Contents += string(schedJSON) + "\n\n"
	}

	// -------------------- Assets --------------------
	if lf, ok := m.LootMap["automation-assets"]; ok && assets != nil {
		lf.Contents += fmt.Sprintf("## Assets for Automation Account %s (Resource Group: %s)\n", accName, rgName)
		assetsJSON, err := json.MarshalIndent(assets, "", "  ")
		if err != nil {
			assetsJSON = []byte(fmt.Sprintf("Failed to marshal assets: %v", err))
		}
		lf.Contents += string(assetsJSON) + "\n\n"
	}

	// ==================== AUTOMATION CONNECTIONS (GET-AZAUTOMATIONCONNECTIONSCOPE) ====================
	if lf, ok := m.LootMap["automation-connections"]; ok && connections != nil && len(connections) > 0 {
		lf.Contents += fmt.Sprintf("\n" + strings.Repeat("=", 80) + "\n")
		lf.Contents += fmt.Sprintf("AUTOMATION ACCOUNT: %s\n", accName)
		lf.Contents += fmt.Sprintf("RESOURCE GROUP: %s\n", rgName)
		lf.Contents += fmt.Sprintf("SUBSCRIPTION: %s (%s)\n", subName, subID)
		lf.Contents += fmt.Sprintf(strings.Repeat("=", 80) + "\n\n")

		for _, conn := range connections {
			lf.Contents += fmt.Sprintf("## Connection: %s\n", conn.Name)
			lf.Contents += fmt.Sprintf("# Connection Type: %s\n", conn.ConnectionType)
			if conn.ApplicationID != "" {
				lf.Contents += fmt.Sprintf("# Application ID: %s\n", conn.ApplicationID)
			}
			if conn.CertificateThumbprint != "" {
				lf.Contents += fmt.Sprintf("# Certificate Thumbprint: %s\n", conn.CertificateThumbprint)
			}
			if conn.TenantID != "" {
				lf.Contents += fmt.Sprintf("# Tenant ID: %s\n", conn.TenantID)
			}

			// Add field values
			if len(conn.FieldValues) > 0 {
				lf.Contents += "# Field Values:\n"
				for k, v := range conn.FieldValues {
					lf.Contents += fmt.Sprintf("#   %s: %s\n", k, v)
				}
			}
			lf.Contents += "\n"
		}

		// Document identity scope results
		if len(scopeResults) > 0 {
			lf.Contents += "\n" + strings.Repeat("-", 80) + "\n"
			lf.Contents += "IDENTITY SCOPE SUMMARY (requires runbook execution to determine actual scope)\n"
			lf.Contents += strings.Repeat("-", 80) + "\n\n"

			for _, result := range scopeResults {
				lf.Contents += fmt.Sprintf("## Identity: %s\n", result.IdentityType)
				lf.Contents += fmt.Sprintf("# Automation Account: %s\n", result.AutomationAccountName)
				lf.Contents += fmt.Sprintf("# Tenant ID: %s\n", result.TenantID)
				lf.Contents += fmt.Sprintf("# Role: %s\n", result.RoleDefinitionName)
				lf.Contents += fmt.Sprintf("# Scope: %s\n", result.Scope)
				lf.Contents += "# NOTE: Run the scope enumeration runbook (see automation-scope-runbooks.txt) to determine actual subscriptions and Key Vault access\n\n"
			}
		}
	}

	// ==================== SCOPE ENUMERATION RUNBOOKS ====================
	if lf, ok := m.LootMap["automation-scope-runbooks"]; ok && scopeRunbookScript != "" {
		lf.Contents += fmt.Sprintf("\n" + strings.Repeat("=", 80) + "\n")
		lf.Contents += fmt.Sprintf("SCOPE ENUMERATION RUNBOOK FOR: %s\n", accName)
		lf.Contents += fmt.Sprintf("RESOURCE GROUP: %s\n", rgName)
		lf.Contents += fmt.Sprintf("SUBSCRIPTION: %s (%s)\n", subName, subID)
		lf.Contents += fmt.Sprintf(strings.Repeat("=", 80) + "\n\n")
		lf.Contents += "# This runbook tests what subscriptions and Key Vaults are accessible\n"
		lf.Contents += "# to the automation account's connections and managed identities.\n"
		lf.Contents += "#\n"
		lf.Contents += "# USAGE:\n"
		lf.Contents += "# 1. Save this script to a .ps1 file\n"
		lf.Contents += "# 2. Upload to the Automation Account as a PowerShell runbook:\n"
		lf.Contents += fmt.Sprintf("#    az automation runbook create --automation-account-name %s --resource-group %s --name ScopeEnumeration --type PowerShell --location <region>\n", accName, rgName)
		lf.Contents += fmt.Sprintf("#    az automation runbook update-content --automation-account-name %s --resource-group %s --name ScopeEnumeration --source-path <path-to-script>\n", accName, rgName)
		lf.Contents += fmt.Sprintf("#    az automation runbook publish --automation-account-name %s --resource-group %s --name ScopeEnumeration\n", accName, rgName)
		lf.Contents += "# 3. Execute the runbook:\n"
		lf.Contents += fmt.Sprintf("#    az automation runbook start --automation-account-name %s --resource-group %s --name ScopeEnumeration\n", accName, rgName)
		lf.Contents += "# 4. Check job output:\n"
		lf.Contents += fmt.Sprintf("#    az automation job list --automation-account-name %s --resource-group %s --output table\n", accName, rgName)
		lf.Contents += fmt.Sprintf("#    az automation job output --automation-account-name %s --resource-group %s --job-name <job-id>\n", accName, rgName)
		lf.Contents += "#\n\n"
		lf.Contents += strings.Repeat("#", 80) + "\n"
		lf.Contents += "# BEGIN RUNBOOK SCRIPT\n"
		lf.Contents += strings.Repeat("#", 80) + "\n\n"
		lf.Contents += scopeRunbookScript + "\n"
		lf.Contents += strings.Repeat("#", 80) + "\n"
		lf.Contents += "# END RUNBOOK SCRIPT\n"
		lf.Contents += strings.Repeat("#", 80) + "\n\n"
	}
}

// ------------------------------
// Hybrid Worker loot generation (per subscription)
// ------------------------------
func (m *AutomationModule) generateHybridWorkerLoot(subID, subName string, hybridWorkers []azinternal.HybridWorkerVM) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// ==================== HYBRID WORKERS ====================
	if lf, ok := m.LootMap["automation-hybrid-workers"]; ok && len(hybridWorkers) > 0 {
		lf.Contents += fmt.Sprintf("\n" + strings.Repeat("=", 80) + "\n")
		lf.Contents += fmt.Sprintf("HYBRID WORKER VMS FOR SUBSCRIPTION: %s (%s)\n", subName, subID)
		lf.Contents += fmt.Sprintf(strings.Repeat("=", 80) + "\n\n")

		for _, vm := range hybridWorkers {
			lf.Contents += fmt.Sprintf("## VM: %s\n", vm.VMName)
			lf.Contents += fmt.Sprintf("# Resource Group: %s\n", vm.ResourceGroup)
			lf.Contents += fmt.Sprintf("# Location: %s\n", vm.Location)
			lf.Contents += fmt.Sprintf("# OS Type: %s\n", vm.OSType)
			lf.Contents += fmt.Sprintf("# Extension: %s (Version: %s)\n", vm.ExtensionName, vm.ExtensionVersion)
			lf.Contents += fmt.Sprintf("# Provisioning State: %s\n", vm.ProvisioningState)
			if vm.AutomationAccount != "" {
				lf.Contents += fmt.Sprintf("# Automation Account URL: %s\n", vm.AutomationAccount)
			}
			if vm.HasManagedIdentity {
				lf.Contents += fmt.Sprintf("# Managed Identity: %s\n", vm.IdentityType)
				lf.Contents += fmt.Sprintf("# Principal ID: %s\n", vm.PrincipalID)
			} else {
				lf.Contents += "# No Managed Identity\n"
			}
			lf.Contents += "\n"
		}

		lf.Contents += "\n" + strings.Repeat("-", 80) + "\n"
		lf.Contents += "EXTRACTION NOTES\n"
		lf.Contents += strings.Repeat("-", 80) + "\n\n"
		lf.Contents += "# Hybrid Worker VMs may contain Run As certificates in the local machine certificate store\n"
		lf.Contents += "# These certificates can be extracted using VM Run Command (requires VM Contributor or higher)\n"
		lf.Contents += "# See automation-hybrid-cert-extraction.txt for certificate extraction scripts\n"
		lf.Contents += "#\n"
		lf.Contents += "# VMs with managed identities can also access JRDS endpoints to retrieve additional certificates\n"
		lf.Contents += "# See automation-hybrid-jrds-extraction.txt for JRDS extraction scripts\n\n"
	}

	// ==================== CERTIFICATE EXTRACTION SCRIPTS ====================
	if lf, ok := m.LootMap["automation-hybrid-cert-extraction"]; ok && len(hybridWorkers) > 0 {
		lf.Contents += fmt.Sprintf("# Hybrid Worker Certificate Extraction Scripts\n")
		lf.Contents += fmt.Sprintf("# Subscription: %s (%s)\n\n", subName, subID)
		lf.Contents += strings.Repeat("=", 80) + "\n\n"

		for _, vm := range hybridWorkers {
			script := azinternal.GenerateHybridWorkerCertExtractionScript(vm)
			lf.Contents += script
			lf.Contents += "\n" + strings.Repeat("=", 80) + "\n\n"
		}
	}

	// ==================== JRDS EXTRACTION SCRIPTS ====================
	if lf, ok := m.LootMap["automation-hybrid-jrds-extraction"]; ok && len(hybridWorkers) > 0 {
		lf.Contents += fmt.Sprintf("# Hybrid Worker JRDS Certificate Extraction Scripts\n")
		lf.Contents += fmt.Sprintf("# Subscription: %s (%s)\n\n", subName, subID)
		lf.Contents += strings.Repeat("=", 80) + "\n\n"

		for _, vm := range hybridWorkers {
			// Only generate JRDS scripts for VMs with managed identities
			if vm.HasManagedIdentity {
				script := azinternal.GenerateJRDSExtractionScript(vm)
				lf.Contents += script
				lf.Contents += "\n" + strings.Repeat("=", 80) + "\n\n"
			}
		}

		// Add note if no VMs with managed identities found
		hasAnyManagedIdentity := false
		for _, vm := range hybridWorkers {
			if vm.HasManagedIdentity {
				hasAnyManagedIdentity = true
				break
			}
		}
		if !hasAnyManagedIdentity {
			lf.Contents += "# No Hybrid Worker VMs with managed identities found\n"
			lf.Contents += "# JRDS extraction requires managed identity for IMDS token retrieval\n\n"
		}
	}
}

// ------------------------------
// Generate security recommendations for automation account
// ------------------------------
func (m *AutomationModule) generateAccountSecurityRecommendations(variables []azinternal.AutomationVariable, hybridWorkerCount int, hasSystemIdentity bool, hasUserIdentity bool) string {
	recommendations := []string{}

	// Check for unencrypted variables
	unencryptedVars := 0
	for _, v := range variables {
		if v.Properties.IsEncrypted != nil && !*v.Properties.IsEncrypted {
			unencryptedVars++
		}
	}
	if unencryptedVars > 0 {
		recommendations = append(recommendations, fmt.Sprintf("%d unencrypted variable(s)", unencryptedVars))
	}

	// Check for hybrid worker configuration
	if hybridWorkerCount > 0 {
		recommendations = append(recommendations, "Hybrid workers may contain Run As certificates")
	}

	// Check for managed identity usage
	if hasSystemIdentity || hasUserIdentity {
		recommendations = append(recommendations, "Review managed identity RBAC assignments")
	}

	// Return consolidated recommendations
	if len(recommendations) == 0 {
		return "No security issues detected"
	}
	return strings.Join(recommendations, "; ")
}

// ------------------------------
// Generate security recommendations for individual runbooks
// ------------------------------
func (m *AutomationModule) generateRunbookSecurityRecommendations(ctx context.Context, subID, rgName, accName, rbName string) string {
	recommendations := []string{}

	// Fetch runbook script content to scan for secrets
	script, err := azinternal.FetchRunbookScript(ctx, m.Session, subID, rgName, accName, rbName)
	if err == nil && script != "" {
		// Scan for hardcoded secrets
		secretMatches := azinternal.ScanScriptContent(script, fmt.Sprintf("%s/%s [%s]", rgName, accName, rbName), "runbook-script")
		if len(secretMatches) > 0 {
			criticalCount := 0
			highCount := 0
			for _, match := range secretMatches {
				if match.Severity == "CRITICAL" {
					criticalCount++
				} else if match.Severity == "HIGH" {
					highCount++
				}
			}
			if criticalCount > 0 {
				recommendations = append(recommendations, fmt.Sprintf("%d CRITICAL secret(s) detected", criticalCount))
			}
			if highCount > 0 {
				recommendations = append(recommendations, fmt.Sprintf("%d HIGH secret(s) detected", highCount))
			}
		}
	}

	// Return consolidated recommendations
	if len(recommendations) == 0 {
		return "No secrets detected"
	}
	return strings.Join(recommendations, "; ")
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *AutomationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.AutomationRows) == 0 {
		logger.InfoM("No Automation resources found", globals.AZ_AUTOMATION_MODULE_NAME)
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
		"Automation Account",
		"Resource Name",
		"Resource Type",
		"Runbook Count",
		"Last Modified",
		"State",
		"Runbook Type",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
		"Security Recommendations", // NEW: security recommendations based on configuration
	}

	// Check if we should split output by tenant first, then subscription
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.AutomationRows, headers,
			"automation", globals.AZ_AUTOMATION_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.AutomationRows, headers,
			"automation", globals.AZ_AUTOMATION_MODULE_NAME,
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
	output := AutomationOutput{
		Table: []internal.TableFile{{
			Name:   "automation",
			Header: headers,
			Body:   m.AutomationRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_AUTOMATION_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Automation resource(s) across %d subscription(s)", len(m.AutomationRows), len(m.Subscriptions)), globals.AZ_AUTOMATION_MODULE_NAME)
}
