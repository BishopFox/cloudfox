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
var AzAppConfigurationCommand = &cobra.Command{
	Use:     "app-configuration",
	Aliases: []string{"appconfig", "appconf"},
	Short:   "Enumerate Azure App Configuration stores and access keys",
	Long: `
Enumerate Azure App Configuration stores for a specific tenant:
  ./cloudfox az app-configuration --tenant TENANT_ID

Enumerate Azure App Configuration stores for a specific subscription:
  ./cloudfox az app-configuration --subscription SUBSCRIPTION_ID`,
	Run: ListAppConfiguration,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type AppConfigurationModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions []string
	AppConfigRows [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type AppConfigurationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AppConfigurationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AppConfigurationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListAppConfiguration(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_APP_CONFIGURATION_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &AppConfigurationModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		AppConfigRows:   [][]string{},
		LootMap: map[string]*internal.LootFile{
			"appconfig-commands":       {Name: "appconfig-commands", Contents: ""},
			"appconfig-access-keys":    {Name: "appconfig-access-keys", Contents: ""},
			"appconfig-access-scripts": {Name: "appconfig-access-scripts", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintAppConfiguration(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *AppConfigurationModule) PrintAppConfiguration(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_APP_CONFIGURATION_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_APP_CONFIGURATION_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_APP_CONFIGURATION_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating app configuration stores for %d subscription(s)", len(m.Subscriptions)), globals.AZ_APP_CONFIGURATION_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_APP_CONFIGURATION_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *AppConfigurationModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Get all App Configuration stores
	appConfigStores, err := azinternal.GetAppConfigStores(m.Session, subID, resourceGroups)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get App Configuration stores for subscription %s: %v", subID, err), globals.AZ_APP_CONFIGURATION_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each App Configuration store concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit to 5 concurrent stores

	for _, store := range appConfigStores {
		wg.Add(1)
		go m.processAppConfigStore(ctx, subID, subName, store, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single App Configuration store
// ------------------------------
func (m *AppConfigurationModule) processAppConfigStore(ctx context.Context, subID, subName string, store azinternal.AppConfigStore, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get access keys for this store
	accessKeys, _ := azinternal.GetAppConfigAccessKeys(m.Session, subID, store.ResourceGroup, store.Name)

	// Count read-only vs read-write keys
	readOnlyCount := 0
	readWriteCount := 0
	for _, key := range accessKeys {
		if key.ReadOnly {
			readOnlyCount++
		} else {
			readWriteCount++
		}
	}

	// Thread-safe append - main store row
	m.mu.Lock()
	m.AppConfigRows = append(m.AppConfigRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		store.ResourceGroup,
		store.Location,
		store.Name,
		store.SKUName,
		store.ProvisioningState,
		store.PublicNetworkAccess,
		store.Endpoint,
		fmt.Sprintf("%d RO / %d RW", readOnlyCount, readWriteCount),
		fmt.Sprintf("%d", len(accessKeys)),
		store.PrincipalID,
		store.UserAssignedIDs,
	})

	// Add per-key rows
	for _, key := range accessKeys {
		keyType := "Read-Write"
		if key.ReadOnly {
			keyType = "Read-Only"
		}

		m.AppConfigRows = append(m.AppConfigRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			store.ResourceGroup,
			store.Location,
			store.Name,
			fmt.Sprintf("Key: %s", key.Name),
			keyType,
			"",
			key.ID,
			"",
			key.LastModified,
			"",
			"",
		})
	}
	m.mu.Unlock()

	// Generate loot
	m.generateLoot(subID, subName, store, accessKeys)
}

// ------------------------------
// Generate loot files
// ------------------------------
func (m *AppConfigurationModule) generateLoot(subID, subName string, store azinternal.AppConfigStore, keys []azinternal.AppConfigAccessKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Commands loot
	if lf, ok := m.LootMap["appconfig-commands"]; ok {
		lf.Contents += fmt.Sprintf("## App Configuration Store: %s (Resource Group: %s)\n", store.Name, store.ResourceGroup)
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
		lf.Contents += fmt.Sprintf("# List App Configuration stores\n")
		lf.Contents += fmt.Sprintf("az appconfig list --resource-group %s -o table\n\n", store.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Show App Configuration store details\n")
		lf.Contents += fmt.Sprintf("az appconfig show --name %s --resource-group %s\n\n", store.Name, store.ResourceGroup)
		lf.Contents += fmt.Sprintf("# List access keys\n")
		lf.Contents += fmt.Sprintf("az appconfig credential list --name %s --resource-group %s -o table\n\n", store.Name, store.ResourceGroup)
		lf.Contents += fmt.Sprintf("# List configuration key-values (requires connection string)\n")
		lf.Contents += fmt.Sprintf("# Get connection string first, then:\n")
		lf.Contents += fmt.Sprintf("# az appconfig kv list --connection-string \"<CONNECTION_STRING>\" -o table\n\n")
	}

	// Access keys loot
	if lf, ok := m.LootMap["appconfig-access-keys"]; ok && len(keys) > 0 {
		lf.Contents += fmt.Sprintf("\n## App Configuration Store: %s\n", store.Name)
		lf.Contents += fmt.Sprintf("# Resource Group: %s, Subscription: %s (%s)\n", store.ResourceGroup, subName, subID)
		lf.Contents += fmt.Sprintf("# Endpoint: %s\n\n", store.Endpoint)

		for _, key := range keys {
			keyType := "Read-Write"
			if key.ReadOnly {
				keyType = "Read-Only"
			}

			lf.Contents += fmt.Sprintf("### Access Key: %s (%s)\n", key.Name, keyType)
			lf.Contents += fmt.Sprintf("- **ID**: %s\n", key.ID)
			lf.Contents += fmt.Sprintf("- **Value**: %s\n", key.Value)
			lf.Contents += fmt.Sprintf("- **Connection String**: %s\n", key.ConnectionString)
			lf.Contents += fmt.Sprintf("- **Last Modified**: %s\n", key.LastModified)
			lf.Contents += "\n"
		}
	}

	// Generate access scripts
	if lf, ok := m.LootMap["appconfig-access-scripts"]; ok && len(keys) > 0 {
		script := azinternal.GenerateAppConfigAccessScript(store, keys)
		lf.Contents += script
		lf.Contents += "---\n\n"
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *AppConfigurationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.AppConfigRows) == 0 {
		logger.InfoM("No App Configuration stores found", globals.AZ_APP_CONFIGURATION_MODULE_NAME)
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
		"Store Name",
		"SKU / Key Name",
		"Provisioning State / Key Type",
		"Public Network Access",
		"Endpoint / Key ID",
		"Key Counts (RO/RW)",
		"Total Keys / Last Modified",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.AppConfigRows, headers,
			"app-configuration", globals.AZ_APP_CONFIGURATION_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.AppConfigRows, headers,
			"app-configuration", globals.AZ_APP_CONFIGURATION_MODULE_NAME,
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
	output := AppConfigurationOutput{
		Table: []internal.TableFile{{
			Name:   "app-configuration",
			Header: headers,
			Body:   m.AppConfigRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_APP_CONFIGURATION_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d App Configuration resource(s) across %d subscription(s)", len(m.AppConfigRows), len(m.Subscriptions)), globals.AZ_APP_CONFIGURATION_MODULE_NAME)
}
