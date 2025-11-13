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
var AzBatchCommand = &cobra.Command{
	Use:     "batch",
	Aliases: []string{"bat"},
	Short:   "Enumerate Azure Batch accounts, pools, and applications",
	Long: `
Enumerate Azure Batch accounts for a specific tenant:
  ./cloudfox az batch --tenant TENANT_ID

Enumerate Azure Batch accounts for a specific subscription:
  ./cloudfox az batch --subscription SUBSCRIPTION_ID`,
	Run: ListBatch,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type BatchModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions []string
	BatchRows     [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type BatchOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BatchOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BatchOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListBatch(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_BATCH_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &BatchModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		BatchRows:       [][]string{},
		LootMap: map[string]*internal.LootFile{
			"batch-commands": {Name: "batch-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintBatch(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *BatchModule) PrintBatch(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_BATCH_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_BATCH_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_BATCH_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating batch accounts for %d subscription(s)", len(m.Subscriptions)), globals.AZ_BATCH_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_BATCH_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *BatchModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Get all Batch accounts
	batchAccounts, err := azinternal.GetBatchAccounts(m.Session, subID, resourceGroups)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Batch accounts for subscription %s: %v", subID, err), globals.AZ_BATCH_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each Batch account concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit to 5 concurrent Batch accounts

	for _, account := range batchAccounts {
		wg.Add(1)
		go m.processBatchAccount(ctx, subID, subName, account, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single Batch account
// ------------------------------
func (m *BatchModule) processBatchAccount(ctx context.Context, subID, subName string, account azinternal.BatchAccount, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get pools for this Batch account
	pools, _ := azinternal.GetBatchPools(m.Session, subID, account.ResourceGroup, account.Name)

	// Get applications for this Batch account
	apps, _ := azinternal.GetBatchApplications(m.Session, subID, account.ResourceGroup, account.Name)

	// Thread-safe append - main account row
	m.mu.Lock()
	m.BatchRows = append(m.BatchRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		account.ResourceGroup,
		account.Location,
		account.Name,
		"BatchAccount",
		account.ProvisioningState,
		fmt.Sprintf("%d", account.PoolQuota),
		fmt.Sprintf("%d", len(pools)),
		fmt.Sprintf("%d", len(apps)),
		account.AccountEndpoint,
		account.PublicNetworkAccess,
		account.SystemAssignedID,
		account.UserAssignedIDs,
	})

	// Add per-pool rows
	for _, pool := range pools {
		m.BatchRows = append(m.BatchRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			account.ResourceGroup,
			account.Location,
			account.Name,
			fmt.Sprintf("Pool: %s", pool.Name),
			pool.ProvisioningState,
			pool.VMSize,
			fmt.Sprintf("%d/%d", pool.CurrentDedicatedNodes, pool.TargetDedicatedNodes),
			fmt.Sprintf("%d/%d", pool.CurrentLowPriorityNodes, pool.TargetLowPriorityNodes),
			pool.AllocationState,
			"",
			"",
			"",
		})
	}

	// Add per-application rows
	for _, app := range apps {
		m.BatchRows = append(m.BatchRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			account.ResourceGroup,
			account.Location,
			account.Name,
			fmt.Sprintf("Application: %s", app.Name),
			"",
			"",
			"",
			"",
			app.DisplayName,
			fmt.Sprintf("AllowUpdates: %v", app.AllowUpdates),
			"",
			"",
		})
	}
	m.mu.Unlock()

	// Generate loot
	m.generateLoot(subID, subName, account, pools, apps)
}

// ------------------------------
// Generate loot files
// ------------------------------
func (m *BatchModule) generateLoot(subID, subName string, account azinternal.BatchAccount, pools []azinternal.BatchPool, apps []azinternal.BatchApplication) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Commands loot
	if lf, ok := m.LootMap["batch-commands"]; ok {
		lf.Contents += fmt.Sprintf("## Batch Account: %s (Resource Group: %s)\n", account.Name, account.ResourceGroup)
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
		lf.Contents += fmt.Sprintf("# List Batch accounts\naz batch account list --resource-group %s -o table\n\n", account.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Show Batch account details\naz batch account show --name %s --resource-group %s\n\n", account.Name, account.ResourceGroup)
		lf.Contents += fmt.Sprintf("# List Batch account keys\naz batch account keys list --name %s --resource-group %s\n\n", account.Name, account.ResourceGroup)
		lf.Contents += fmt.Sprintf("# PowerShell equivalent\nGet-AzBatchAccount -AccountName %s -ResourceGroupName %s\n", account.Name, account.ResourceGroup)
		lf.Contents += fmt.Sprintf("Get-AzBatchAccountKey -AccountName %s -ResourceGroupName %s\n\n", account.Name, account.ResourceGroup)
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *BatchModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.BatchRows) == 0 {
		logger.InfoM("No Batch accounts found", globals.AZ_BATCH_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Location",
		"Batch Account",
		"Resource Type",
		"Provisioning State",
		"Pool Quota / VM Size",
		"Pool Count / Dedicated Nodes",
		"Application Count / LowPri Nodes",
		"Account Endpoint / Allocation State",
		"Public Network Access",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.BatchRows, headers,
			"batch", globals.AZ_BATCH_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.BatchRows, headers,
			"batch", globals.AZ_BATCH_MODULE_NAME,
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
	output := BatchOutput{
		Table: []internal.TableFile{{
			Name:   "batch",
			Header: headers,
			Body:   m.BatchRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_BATCH_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Batch resource(s) across %d subscription(s)", len(m.BatchRows), len(m.Subscriptions)), globals.AZ_BATCH_MODULE_NAME)
}
