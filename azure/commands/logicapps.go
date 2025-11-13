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
var AzLogicAppsCommand = &cobra.Command{
	Use:     "logicapps",
	Aliases: []string{"logic"},
	Short:   "Enumerate Azure Logic Apps (workflows, definitions, parameters)",
	Long: `
Enumerate Azure Logic Apps for a specific tenant:
./cloudfox az logicapps --tenant TENANT_ID

Enumerate Azure Logic Apps for a specific subscription:
./cloudfox az logicapps --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListLogicApps,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type LogicAppsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	LogicAppRows  [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type LogicAppsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LogicAppsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LogicAppsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListLogicApps(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_LOGICAPPS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &LogicAppsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		LogicAppRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"logicapps-definitions": {Name: "logicapps-definitions", Contents: ""},
			"logicapps-parameters":  {Name: "logicapps-parameters", Contents: ""},
			"logicapps-secrets":     {Name: "logicapps-secrets", Contents: "# Potential Secrets in Logic Apps\n\n"},
			"logicapps-commands":    {Name: "logicapps-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintLogicApps(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *LogicAppsModule) PrintLogicApps(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_LOGICAPPS_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_LOGICAPPS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_LOGICAPPS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating logic apps for %d subscription(s)", len(m.Subscriptions)), globals.AZ_LOGICAPPS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_LOGICAPPS_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *LogicAppsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

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
func (m *LogicAppsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Enumerate Logic Apps for this resource group
	logicApps, err := azinternal.GetLogicAppsForResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			// Silent failure - not all RGs have Logic Apps
		}
		return
	}

	// Process each Logic App
	for _, app := range logicApps {
		m.mu.Lock()
		m.LogicAppRows = append(m.LogicAppRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			app.Region,
			app.Name,
			app.State,
			app.TriggerType,
			app.ActionCount,
			app.HasParameters,
			app.SystemAssignedID,
			app.UserAssignedIDs,
		})

		// Generate loot - definitions
		if lf, ok := m.LootMap["logicapps-definitions"]; ok {
			lf.Contents += fmt.Sprintf("## Logic App: %s\n", app.Name)
			lf.Contents += fmt.Sprintf("### Metadata\n")
			lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
			lf.Contents += fmt.Sprintf("- **Resource Group**: %s\n", rgName)
			lf.Contents += fmt.Sprintf("- **Region**: %s\n", app.Region)
			lf.Contents += fmt.Sprintf("- **State**: %s\n", app.State)
			lf.Contents += fmt.Sprintf("- **Trigger Type**: %s\n", app.TriggerType)
			lf.Contents += fmt.Sprintf("- **Action Count**: %s\n\n", app.ActionCount)

			if app.Definition != "" {
				lf.Contents += fmt.Sprintf("### Workflow Definition\n```json\n%s\n```\n\n", app.Definition)
			}
		}

		// Generate loot - parameters
		if lf, ok := m.LootMap["logicapps-parameters"]; ok && app.Parameters != "" {
			lf.Contents += fmt.Sprintf("## Logic App: %s\n", app.Name)
			lf.Contents += fmt.Sprintf("### Parameters\n```json\n%s\n```\n\n", app.Parameters)
		}

		// Generate loot - potential secrets
		if lf, ok := m.LootMap["logicapps-secrets"]; ok && app.HasSecrets {
			lf.Contents += fmt.Sprintf("## Logic App: %s\n", app.Name)
			lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
			lf.Contents += fmt.Sprintf("- **Resource Group**: %s\n", rgName)
			lf.Contents += fmt.Sprintf("- **Finding**: Logic App contains actions or parameters that may include credentials\n")
			lf.Contents += fmt.Sprintf("- **Review**: Check the definition file for connection strings, API keys, passwords\n\n")
		}

		// Generate loot - commands
		if lf, ok := m.LootMap["logicapps-commands"]; ok {
			lf.Contents += fmt.Sprintf("## Logic App: %s\n", app.Name)
			lf.Contents += fmt.Sprintf("# Get Logic App details\n")
			lf.Contents += fmt.Sprintf("az logic workflow show --resource-group %s --name %s --subscription %s -o json\n", rgName, app.Name, subID)
			lf.Contents += fmt.Sprintf("# List workflow runs\n")
			lf.Contents += fmt.Sprintf("az logic workflow list-runs --resource-group %s --name %s --subscription %s\n", rgName, app.Name, subID)
			lf.Contents += fmt.Sprintf("# PowerShell\n")
			lf.Contents += fmt.Sprintf("Get-AzLogicApp -ResourceGroupName %s -Name %s\n", rgName, app.Name)
			lf.Contents += fmt.Sprintf("# Export workflow definition\n")
			lf.Contents += fmt.Sprintf("az logic workflow show --resource-group %s --name %s --subscription %s --query definition -o json > %s-definition.json\n\n", rgName, app.Name, subID, app.Name)
		}

		m.mu.Unlock()
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *LogicAppsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.LogicAppRows) == 0 {
		logger.InfoM("No Logic Apps found", globals.AZ_LOGICAPPS_MODULE_NAME)
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
		"State",
		"Trigger Type",
		"Action Count",
		"Has Parameters",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.LogicAppRows, headers,
			"logicapps", globals.AZ_LOGICAPPS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.LogicAppRows, headers,
			"logicapps", globals.AZ_LOGICAPPS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" && lf.Contents != "# Potential Secrets in Logic Apps\n\n" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := LogicAppsOutput{
		Table: []internal.TableFile{{
			Name:   "logicapps",
			Header: headers,
			Body:   m.LogicAppRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_LOGICAPPS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Logic App(s) across %d subscription(s)", len(m.LogicAppRows), len(m.Subscriptions)), globals.AZ_LOGICAPPS_MODULE_NAME)
}
