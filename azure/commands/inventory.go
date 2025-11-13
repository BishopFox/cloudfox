package commands

import (
	"context"
	"fmt"
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
var AzInventoryCommand = &cobra.Command{
	Use:     "inventory",
	Aliases: []string{"inv"},
	Short:   "Enumerate Azure resources",
	Long: `
Enumerate Azure resources for a specific tenant:
./cloudfox az inventory --tenant TENANT_ID

Enumerate Azure resources for a specific subscription:
./cloudfox az inventory --subscription SUBSCRIPTION_ID`,
	Run: ListInventory,
}

// ------------------------------
// Module struct (hybrid AWS/Azure pattern)
// ------------------------------
type InventoryModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	InventoryRows [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type InventoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o InventoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o InventoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListInventory(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_INVENTORY_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &InventoryModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		InventoryRows:   [][]string{},
		LootMap: map[string]*internal.LootFile{
			"inventory-commands": {Name: "inventory-commands", Contents: ""},
		},
	}

	// -------------------- Execute module (processes all subscriptions) --------------------
	module.PrintInventory(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *InventoryModule) PrintInventory(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_INVENTORY_MODULE_NAME)

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
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_INVENTORY_MODULE_NAME, m.processSubscription)

			// Restore original tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// -------------------- Process all subscriptions --------------------
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_INVENTORY_MODULE_NAME, m.processSubscription)
	}

	// -------------------- Write output --------------------
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *InventoryModule) processSubscription(ctx context.Context, subscriptionID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subscriptionID)

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Starting enumeration for subscription %s (%s)", subscriptionID, subName), globals.AZ_INVENTORY_MODULE_NAME)
	}

	// -------------------- Enumerate resource groups --------------------
	resourceGroups := m.ResolveResourceGroups(subscriptionID)

	// -------------------- Process resource groups concurrently --------------------
	var wg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs
	for _, rgName := range resourceGroups {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.processResourceGroup(ctx, subscriptionID, subName, rgName, &wg, rgSemaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *InventoryModule) processResourceGroup(ctx context.Context, subscriptionID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating resources for resource group %s in subscription %s", rgName, subscriptionID), globals.AZ_INVENTORY_MODULE_NAME)
	}

	// Get region for this resource group
	var region string
	if rg := azinternal.GetResourceGroupIDFromName(m.Session, subscriptionID, rgName); rg != nil {
		rgs := azinternal.GetResourceGroupsPerSubscription(m.Session, subscriptionID)
		for _, r := range rgs {
			if r.Name != nil && *r.Name == rgName && r.Location != nil {
				region = *r.Location
				break
			}
		}
	}

	// -------------------- Enumerate resources per RG --------------------
	resClient, err := azinternal.GetARMresourcesClient(m.Session, m.TenantID, subscriptionID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create ARM resources client for subscription %s: %v", subscriptionID, err), globals.AZ_INVENTORY_MODULE_NAME)
		}
		return
	}

	pagerCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	pager := resClient.NewListPager(nil)
	for pager.More() {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Fetching next page for subscription %s, resource group %s...", subscriptionID, rgName), globals.AZ_INVENTORY_MODULE_NAME)
		}

		page, err := pager.NextPage(pagerCtx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list resources for subscription %s, resource group %s: %v", subscriptionID, rgName, err), globals.AZ_INVENTORY_MODULE_NAME)
			}
			break
		}

		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Received %d resources on this page for subscription %s, resource group %s", len(page.Value), subscriptionID, rgName), globals.AZ_INVENTORY_MODULE_NAME)
		}

		for _, r := range page.Value {
			resourceName := azinternal.SafeStringPtr(r.Name)
			resourceRG := azinternal.SafeString(rgName)
			resourceLocation := azinternal.SafeStringPtr(r.Location)
			resourceType := azinternal.SafeStringPtr(r.Type)
			resourceKind := azinternal.SafeStringPtr(r.Kind)

			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing resource: %s (%s) Type=%s", resourceName, resourceLocation, resourceType), globals.AZ_INVENTORY_MODULE_NAME)
			}

			// Thread-safe append
			m.mu.Lock()
			m.InventoryRows = append(m.InventoryRows, []string{
				m.TenantName, // NEW: for multi-tenant support
				m.TenantID,   // NEW: for multi-tenant support
				subscriptionID,
				subName,
				resourceRG,
				region,
				resourceName,
				resourceType,
				resourceKind,
			})

			m.LootMap["inventory-commands"].Contents += fmt.Sprintf(
				"## Resource: %s\n# Type: %s\naz resource show --ids %s\nGet-AzResource -ResourceId %s\n\n",
				resourceName, resourceType, azinternal.SafeStringPtr(r.ID), azinternal.SafeStringPtr(r.ID),
			)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *InventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.InventoryRows) == 0 {
		logger.InfoM("No resources found", globals.AZ_INVENTORY_MODULE_NAME)
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
		"Name",
		"Resource Type",
		"Resource Kind",
	}

	// Check if we should split output by tenant first, then subscription
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.InventoryRows, headers,
			"inventory", globals.AZ_INVENTORY_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.InventoryRows, headers,
			"inventory", globals.AZ_INVENTORY_MODULE_NAME,
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
	output := InventoryOutput{
		Table: []internal.TableFile{{
			Name:   "inventory",
			Header: headers,
			Body:   m.InventoryRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_INVENTORY_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d resource(s) across %d subscription(s)", len(m.InventoryRows), len(m.Subscriptions)), globals.AZ_INVENTORY_MODULE_NAME)
}
