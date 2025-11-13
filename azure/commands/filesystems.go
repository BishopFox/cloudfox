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
var AzFilesystemsCommand = &cobra.Command{
	Use:     "filesystems",
	Aliases: []string{"fs"},
	Short:   "Enumerate Azure Files and NetApp Files",
	Long: `
Enumerate Azure Files and Azure NetApp Files for a specific tenant:
./cloudfox az filesystems --tenant TENANT_ID

Enumerate Azure Filesystems for a specific subscription:
./cloudfox az filesystems --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListFilesystems,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type FilesystemsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions  []string
	FilesystemRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type FilesystemsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FilesystemsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FilesystemsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListFilesystems(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_FILESYSTEMS_MODULE)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &FilesystemsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		FilesystemRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"filesystem-commands":       {Name: "filesystem-commands", Contents: ""},
			"filesystem-mount-commands": {Name: "filesystem-mount-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintFilesystems(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *FilesystemsModule) PrintFilesystems(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_FILESYSTEMS_MODULE)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_FILESYSTEMS_MODULE)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_FILESYSTEMS_MODULE, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Filesystems for %d subscription(s)", len(m.Subscriptions)), globals.AZ_FILESYSTEMS_MODULE)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_FILESYSTEMS_MODULE, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *FilesystemsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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
func (m *FilesystemsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()
	// -------------------- Enumerate Azure Files --------------------
	fileShares := azinternal.ListAzureFileShares(ctx, m.Session, subID, rgName)
	for _, fs := range fileShares {
		m.mu.Lock()
		m.FilesystemRows = append(m.FilesystemRows, []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			fs.Location,
			"Azure Files",
			fs.Name,
			fs.DnsName,
			fs.IP,
			fs.MountTarget,
			fs.AuthPolicy,
		})

		m.LootMap["filesystem-commands"].Contents += fmt.Sprintf(
			"## Resource Group: %s\naz storage share list --resource-group %s\n\n",
			rgName, rgName,
		)

		m.LootMap["filesystem-mount-commands"].Contents += fmt.Sprintf(
			"smbclient //%s/%s -U <storage-account-name>\nmount -t cifs //%s/%s /mnt/%s -o username=<storage-account-name>,password=<storage-account-key>\n\n",
			fs.DnsName, fs.Name, fs.DnsName, fs.Name, fs.Name,
		)
		m.mu.Unlock()
	}

	// -------------------- Enumerate NetApp Files --------------------
	netappVolumes, err := azinternal.ListNetAppFiles(ctx, m.Session, subID, rgName)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing NetApp files for rg %s: %v", rgName, err), globals.AZ_FILESYSTEMS_MODULE)
		}
	} else {
		for _, vol := range netappVolumes {
			name := azinternal.GetNetAppVolumeName(vol)
			region := azinternal.GetNetAppVolumeLocation(vol)
			dnsName := azinternal.GetNetAppVolumeDNS(vol)
			ip := azinternal.GetNetAppVolumeIP(vol)
			mountTarget := azinternal.GetNetAppVolumeMountTarget(vol)
			authPolicy := azinternal.GetNetAppVolumeAuthPolicy(vol)

			m.mu.Lock()
			m.FilesystemRows = append(m.FilesystemRows, []string{
				m.TenantName, // NEW: for multi-tenant support
				m.TenantID,   // NEW: for multi-tenant support
				subID,
				subName,
				rgName,
				region,
				"NetApp Files",
				name,
				dnsName,
				ip,
				mountTarget,
				authPolicy,
			})

			m.LootMap["filesystem-commands"].Contents += fmt.Sprintf(
				"## Resource Group: %s\naz netappfiles volume list --resource-group %s\n\n",
				rgName, rgName,
			)

			// Mount: prefer mountTarget, fall back to IP
			mountHost := mountTarget
			if mountHost == "" || mountHost == "N/A" {
				mountHost = ip
			}
			if mountHost == "" || mountHost == "N/A" {
				m.LootMap["filesystem-mount-commands"].Contents += fmt.Sprintf("# mount target not available for %s (NetApp)\n\n", name)
			} else {
				m.LootMap["filesystem-mount-commands"].Contents += fmt.Sprintf(
					"mount -t nfs %s:/%s /mnt/%s\n\n",
					mountHost, name, name,
				)
			}
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *FilesystemsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.FilesystemRows) == 0 {
		logger.InfoM("No Filesystems found", globals.AZ_FILESYSTEMS_MODULE)
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
		"Service",
		"Name",
		"DNS Name",
		"IP",
		"Mount Target",
		"Auth Policy",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.FilesystemRows,
			headers,
			"filesystems",
			globals.AZ_FILESYSTEMS_MODULE,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.FilesystemRows, headers,
			"filesystems", globals.AZ_FILESYSTEMS_MODULE,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if strings.TrimSpace(lf.Contents) != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := FilesystemsOutput{
		Table: []internal.TableFile{{
			Name:   "filesystems",
			Header: headers,
			Body:   m.FilesystemRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_FILESYSTEMS_MODULE)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Filesystem(s) across %d subscription(s)", len(m.FilesystemRows), len(m.Subscriptions)), globals.AZ_FILESYSTEMS_MODULE)
}
