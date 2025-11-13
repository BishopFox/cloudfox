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
var AzDisksCommand = &cobra.Command{
	Use:     "disks",
	Aliases: []string{"disk"},
	Short:   "Enumerate Azure Managed Disks and encryption status",
	Long: `
Enumerate Azure Managed Disks for a specific tenant:
./cloudfox az disks --tenant TENANT_ID

Enumerate Azure Managed Disks for a specific subscription:
./cloudfox az disks --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListDisks,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type DisksModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	DiskRows      [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type DisksOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DisksOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DisksOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListDisks(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_DISKS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &DisksModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		DiskRows:        [][]string{},
		LootMap: map[string]*internal.LootFile{
			"disks-unencrypted": {Name: "disks-unencrypted", Contents: "# Unencrypted Disks (Security Finding)\n\n"},
			"disks-commands":    {Name: "disks-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDisks(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *DisksModule) PrintDisks(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_DISKS_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_DISKS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_DISKS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Disks for %d subscription(s)", len(m.Subscriptions)), globals.AZ_DISKS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_DISKS_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *DisksModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Enumerate disks for this subscription
	disks, err := azinternal.GetDisksForSubscription(ctx, m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate disks: %v", err), globals.AZ_DISKS_MODULE_NAME)
		}
		return
	}

	// Process each disk
	for _, disk := range disks {
		m.mu.Lock()
		m.DiskRows = append(m.DiskRows, []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			disk.ResourceGroup,
			disk.Region,
			disk.Name,
			disk.DiskSizeGB,
			disk.OSType,
			disk.DiskState,
			disk.ManagedBy,
			disk.EncryptionType,
			disk.EncryptionStatus,
		})

		// Add to unencrypted disks loot if not encrypted
		if disk.EncryptionStatus == "Not Encrypted" || disk.EncryptionStatus == "Encryption At Rest Only" {
			lf := m.LootMap["disks-unencrypted"]
			lf.Contents += fmt.Sprintf("## Disk: %s\n", disk.Name)
			lf.Contents += fmt.Sprintf("- **Subscription**: %s (%s)\n", subName, subID)
			lf.Contents += fmt.Sprintf("- **Resource Group**: %s\n", disk.ResourceGroup)
			lf.Contents += fmt.Sprintf("- **Region**: %s\n", disk.Region)
			lf.Contents += fmt.Sprintf("- **Size**: %s GB\n", disk.DiskSizeGB)
			lf.Contents += fmt.Sprintf("- **OS Type**: %s\n", disk.OSType)
			lf.Contents += fmt.Sprintf("- **Attached To**: %s\n", disk.ManagedBy)
			lf.Contents += fmt.Sprintf("- **Encryption Status**: %s\n", disk.EncryptionStatus)
			lf.Contents += fmt.Sprintf("- **Risk**: Data on disk may be readable if exported/copied\n\n")
			lf.Contents += fmt.Sprintf("### Remediation\n")
			lf.Contents += fmt.Sprintf("```bash\n")
			lf.Contents += fmt.Sprintf("# Enable encryption on disk\n")
			lf.Contents += fmt.Sprintf("az disk update --resource-group %s --name %s --encryption-type EncryptionAtRestWithPlatformAndCustomerKeys\n", disk.ResourceGroup, disk.Name)
			lf.Contents += fmt.Sprintf("```\n\n")
		}

		// Generate commands loot
		lf := m.LootMap["disks-commands"]
		lf.Contents += fmt.Sprintf("## Disk: %s\n", disk.Name)
		lf.Contents += fmt.Sprintf("az disk show --name %s --resource-group %s --subscription %s -o json\n", disk.Name, disk.ResourceGroup, subID)
		lf.Contents += fmt.Sprintf("az disk list --resource-group %s --subscription %s -o table\n", disk.ResourceGroup, subID)
		lf.Contents += fmt.Sprintf("# PowerShell\n")
		lf.Contents += fmt.Sprintf("Get-AzDisk -ResourceGroupName %s -DiskName %s\n", disk.ResourceGroup, disk.Name)
		lf.Contents += fmt.Sprintf("# Create snapshot\n")
		lf.Contents += fmt.Sprintf("az snapshot create --resource-group %s --name %s-snapshot --source %s\n\n", disk.ResourceGroup, disk.Name, disk.Name)

		m.mu.Unlock()
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *DisksModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.DiskRows) == 0 {
		logger.InfoM("No disks found", globals.AZ_DISKS_MODULE_NAME)
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
		"Resource Name",
		"Size (GB)",
		"OS Type",
		"Disk State",
		"Attached To",
		"Encryption Type",
		"Encryption Status",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.DiskRows,
			headers,
			"disks",
			globals.AZ_DISKS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.DiskRows, headers,
			"disks", globals.AZ_DISKS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" && lf.Contents != "# Unencrypted Disks (Security Finding)\n\n" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := DisksOutput{
		Table: []internal.TableFile{{
			Name:   "disks",
			Header: headers,
			Body:   m.DiskRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DISKS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	// Count unencrypted disks for summary
	unencryptedCount := 0
	for _, row := range m.DiskRows {
		if len(row) > 10 && (row[10] == "Not Encrypted" || row[10] == "Encryption At Rest Only") {
			unencryptedCount++
		}
	}

	successMsg := fmt.Sprintf("Found %d disk(s) across %d subscription(s)", len(m.DiskRows), len(m.Subscriptions))
	if unencryptedCount > 0 {
		successMsg += fmt.Sprintf(" (%d unencrypted)", unencryptedCount)
	}
	logger.SuccessM(successMsg, globals.AZ_DISKS_MODULE_NAME)
}
