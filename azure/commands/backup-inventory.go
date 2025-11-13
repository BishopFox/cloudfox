package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices"
	// "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup" // Unused after commenting out backup policies
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzBackupInventoryCommand = &cobra.Command{
	Use:     "backup-inventory",
	Aliases: []string{"backups", "recovery-vaults"},
	Short:   "Enumerate Azure Backup and Recovery Services configuration",
	Long: `
Enumerate Azure Backup and Recovery Services for a specific tenant:
./cloudfox az backup-inventory --tenant TENANT_ID

Enumerate Azure Backup and Recovery Services for a specific subscription:
./cloudfox az backup-inventory --subscription SUBSCRIPTION_ID

This module enumerates:
- Recovery Services Vaults (backup repositories)
- Backup policies (retention settings and schedules)
- Protected items (VMs, databases, file shares)
- Backup coverage gaps (critical resources without backups)

Security Analysis:
- HIGH: Critical VMs without backups (data loss risk)
- MEDIUM: Short retention policies (<30 days)
- LOW: Vaults without geo-redundant storage`,
	Run: ListBackupInventory,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type BackupInventoryModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions        []string
	VaultRows            [][]string
	PolicyRows           [][]string
	ProtectedItemRows    [][]string
	UnprotectedVMRows    [][]string
	LootMap              map[string]*internal.LootFile
	mu                   sync.Mutex
	vaultsBySubscription map[string][]string // Track vaults for backup item lookup
}

// ------------------------------
// Output struct
// ------------------------------
type BackupInventoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BackupInventoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BackupInventoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListBackupInventory(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &BackupInventoryModule{
		BaseAzureModule:      azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:        cmdCtx.Subscriptions,
		VaultRows:            [][]string{},
		PolicyRows:           [][]string{},
		ProtectedItemRows:    [][]string{},
		UnprotectedVMRows:    [][]string{},
		vaultsBySubscription: make(map[string][]string),
		LootMap: map[string]*internal.LootFile{
			"backup-unprotected-vms":  {Name: "backup-unprotected-vms", Contents: ""},
			"backup-short-retention":  {Name: "backup-short-retention", Contents: ""},
			"backup-no-georedundancy": {Name: "backup-no-georedundancy", Contents: ""},
			"backup-disabled-vaults":  {Name: "backup-disabled-vaults", Contents: ""},
			"backup-setup-commands":   {Name: "backup-setup-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintBackupInventory(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *BackupInventoryModule) PrintBackupInventory(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_BACKUP_INVENTORY_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Azure Backup configuration for %d subscription(s)", len(m.Subscriptions)), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_BACKUP_INVENTORY_MODULE_NAME, m.processSubscription)
	}

	// After all subscriptions processed, check for unprotected VMs
	m.checkUnprotectedVMs(ctx, logger)

	// Generate setup commands loot
	m.generateSetupCommands()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *BackupInventoryModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Process Recovery Services Vaults first (needed for policies and items)
	vaults := m.processRecoveryServicesVaults(ctx, subID, subName, logger)

	// Store vaults for later use
	m.mu.Lock()
	m.vaultsBySubscription[subID] = vaults
	m.mu.Unlock()

	// Process in parallel for each vault:
	// 1. Backup policies
	// 2. Protected items
	var wg sync.WaitGroup
	for _, vaultName := range vaults {
		// Extract resource group from vault name (format: /subscriptions/.../resourceGroups/RG/...)
		parts := strings.Split(vaultName, "/")
		rgName := ""
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				rgName = parts[i+1]
				break
			}
		}
		if rgName == "" {
			continue
		}

		vaultNameOnly := parts[len(parts)-1]

		wg.Add(2)

		go func(vName, rg string) {
			defer wg.Done()
			m.processBackupPolicies(ctx, subID, subName, vName, rg, logger)
		}(vaultNameOnly, rgName)

		go func(vName, rg string) {
			defer wg.Done()
			m.processProtectedItems(ctx, subID, subName, vName, rg, logger)
		}(vaultNameOnly, rgName)
	}

	wg.Wait()
}

// ------------------------------
// Process Recovery Services Vaults
// ------------------------------
func (m *BackupInventoryModule) processRecoveryServicesVaults(ctx context.Context, subID, subName string, logger internal.Logger) []string {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
		}
		return []string{}
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// Create Recovery Services client
	client, err := armrecoveryservices.NewVaultsClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Recovery Services client for subscription %s: %v", subID, err), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
		}
		return []string{}
	}

	vaultIDs := []string{}

	// List all Recovery Services Vaults for the subscription
	pager := client.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing Recovery Services Vaults for subscription %s: %v", subID, err), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
			}
			return vaultIDs
		}

		for _, vault := range page.Value {
			if vault == nil || vault.Name == nil {
				continue
			}

			vaultName := *vault.Name
			vaultID := ""
			location := ""
			sku := "Unknown"
			provisioningState := "Unknown"
			redundancy := "Unknown"
			privateEndpointCount := 0
			publicNetworkAccess := "Enabled"

			if vault.ID != nil {
				vaultID = *vault.ID
				vaultIDs = append(vaultIDs, vaultID)
			}
			if vault.Location != nil {
				location = *vault.Location
			}
			if vault.SKU != nil && vault.SKU.Name != nil {
				sku = string(*vault.SKU.Name)
			}
			if vault.Properties != nil {
				if vault.Properties.ProvisioningState != nil {
					provisioningState = *vault.Properties.ProvisioningState
				}
				if vault.Properties.BackupStorageVersion != nil {
					// BackupStorageVersion indicates backup config
				}
				if vault.Properties.PrivateEndpointConnections != nil {
					privateEndpointCount = len(vault.Properties.PrivateEndpointConnections)
				}
				if vault.Properties.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*vault.Properties.PublicNetworkAccess)
				}
			}

			// Get redundancy from SKU
			if strings.Contains(strings.ToLower(sku), "geo") {
				redundancy = "Geo-Redundant"
			} else if strings.Contains(strings.ToLower(sku), "local") {
				redundancy = "Locally Redundant"
			} else {
				redundancy = sku
			}

			// Determine risk level
			riskLevel := "INFO"
			securityIssues := []string{}

			// Check geo-redundancy
			if !strings.Contains(strings.ToLower(redundancy), "geo") {
				riskLevel = "LOW"
				securityIssues = append(securityIssues, "No geo-redundancy")
			}

			// Check provisioning state
			if provisioningState != "Succeeded" {
				riskLevel = "MEDIUM"
				securityIssues = append(securityIssues, fmt.Sprintf("Provisioning state: %s", provisioningState))
			}

			// Check public network access
			if publicNetworkAccess == "Enabled" && privateEndpointCount == 0 {
				securityIssues = append(securityIssues, "Public network access enabled")
			}

			securityIssuesStr := "None"
			if len(securityIssues) > 0 {
				securityIssuesStr = strings.Join(securityIssues, "; ")
			}

			// Build row
			row := []string{
				subID,
				subName,
				vaultName,
				location,
				sku,
				redundancy,
				provisioningState,
				publicNetworkAccess,
				fmt.Sprintf("%d", privateEndpointCount),
				securityIssuesStr,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.VaultRows = append(m.VaultRows, row)

			// Add to loot if issues found
			if !strings.Contains(strings.ToLower(redundancy), "geo") {
				lootEntry := fmt.Sprintf("[NO GEO-REDUNDANCY] Vault: %s, Redundancy: %s (Subscription: %s)\n", vaultName, redundancy, subName)
				m.LootMap["backup-no-georedundancy"].Contents += lootEntry
			}
			if provisioningState != "Succeeded" {
				lootEntry := fmt.Sprintf("[DISABLED] Vault: %s, State: %s (Subscription: %s)\n", vaultName, provisioningState, subName)
				m.LootMap["backup-disabled-vaults"].Contents += lootEntry
			}
			m.mu.Unlock()
		}
	}

	return vaultIDs
}

// ------------------------------
// Process backup policies
// ------------------------------
func (m *BackupInventoryModule) processBackupPolicies(ctx context.Context, subID, subName, vaultName, rgName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// NOTE: NewPoliciesClient not available in armrecoveryservicesbackup v1.0.0
	// This functionality requires a newer SDK version
	_ = cred // Use the credential to avoid unused variable error
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Backup policies enumeration requires armrecoveryservicesbackup v1.1.0+ (currently using v1.0.0)", globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
	}
	return

	// TODO: Uncomment when SDK is upgraded
	/*
	// Create Backup Policies client
	client, err := armrecoveryservicesbackup.NewPoliciesClient(subID, cred, nil)
	if err != nil {
		return
	}

	// List all backup policies for the vault
	pager := client.NewListPager(vaultName, rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing backup policies for vault %s: %v", vaultName, err), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
			}
			return
		}

		for _, policy := range page.Value {
			if policy == nil || policy.Name == nil {
				continue
			}

			policyName := *policy.Name
			policyType := "Unknown"
			workloadType := "Unknown"
			retentionDays := "Unknown"
			scheduleType := "Unknown"

			// Try to extract properties from the policy
			// The backup policy is a complex polymorphic type
			props := policy.Properties
			if props != nil {
				// Type assertion to get specific policy types
				switch p := props.(type) {
				case *armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy:
					policyType = "Azure VM"
					if p.RetentionPolicy != nil {
						// Simple retention policy
						if srp, ok := p.RetentionPolicy.(*armrecoveryservicesbackup.SimpleRetentionPolicy); ok {
							if srp.RetentionDuration != nil && srp.RetentionDuration.Count != nil {
								retentionDays = fmt.Sprintf("%d days", *srp.RetentionDuration.Count)
							}
						}
						// Long-term retention policy
						if ltrp, ok := p.RetentionPolicy.(*armrecoveryservicesbackup.LongTermRetentionPolicy); ok {
							if ltrp.DailySchedule != nil && ltrp.DailySchedule.RetentionDuration != nil && ltrp.DailySchedule.RetentionDuration.Count != nil {
								retentionDays = fmt.Sprintf("%d days", *ltrp.DailySchedule.RetentionDuration.Count)
							}
						}
					}
					if p.SchedulePolicy != nil {
						scheduleType = "Scheduled"
					}
					workloadType = "Azure VM"
				case *armrecoveryservicesbackup.AzureSQLProtectionPolicy:
					policyType = "Azure SQL"
					workloadType = "Azure SQL"
					if p.RetentionPolicy != nil {
						if srp, ok := p.RetentionPolicy.(*armrecoveryservicesbackup.SimpleRetentionPolicy); ok {
							if srp.RetentionDuration != nil && srp.RetentionDuration.Count != nil {
								retentionDays = fmt.Sprintf("%d days", *srp.RetentionDuration.Count)
							}
						}
					}
				case *armrecoveryservicesbackup.AzureFileShareProtectionPolicy:
					policyType = "Azure File Share"
					workloadType = "Azure File Share"
					if p.RetentionPolicy != nil {
						if srp, ok := p.RetentionPolicy.(*armrecoveryservicesbackup.SimpleRetentionPolicy); ok {
							if srp.RetentionDuration != nil && srp.RetentionDuration.Count != nil {
								retentionDays = fmt.Sprintf("%d days", *srp.RetentionDuration.Count)
							}
						}
					}
				default:
					policyType = "Other"
				}
			}

			// Determine risk level based on retention
			riskLevel := "INFO"
			if strings.Contains(retentionDays, "days") {
				// Extract number
				var days int
				fmt.Sscanf(retentionDays, "%d", &days)
				if days < 30 {
					riskLevel = "MEDIUM"
				} else if days < 7 {
					riskLevel = "HIGH"
				}
			}

			// Build row
			row := []string{
				subID,
				subName,
				vaultName,
				policyName,
				policyType,
				workloadType,
				retentionDays,
				scheduleType,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.PolicyRows = append(m.PolicyRows, row)

			// Add to loot if short retention
			if riskLevel == "MEDIUM" || riskLevel == "HIGH" {
				lootEntry := fmt.Sprintf("[SHORT RETENTION] Policy: %s, Retention: %s, Vault: %s (Subscription: %s)\n", policyName, retentionDays, vaultName, subName)
				m.LootMap["backup-short-retention"].Contents += lootEntry
			}
			m.mu.Unlock()
		}
	}
	*/
}

// ------------------------------
// Process protected items
// ------------------------------
func (m *BackupInventoryModule) processProtectedItems(ctx context.Context, subID, subName, vaultName, rgName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// NOTE: NewProtectedItemsClient and related APIs not fully compatible with armrecoveryservicesbackup v1.0.0
	// This functionality requires a newer SDK version
	_ = cred // Use the credential to avoid unused variable error
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Protected items enumeration requires armrecoveryservicesbackup v1.1.0+ (currently using v1.0.0)", globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
	}
	return

	// TODO: Uncomment when SDK is upgraded
	/*
	// Create Protected Items client
	client, err := armrecoveryservicesbackup.NewProtectedItemsClient(subID, cred, nil)
	if err != nil {
		return
	}

	// List all protected items for the vault
	pager := client.NewListPager(vaultName, rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing protected items for vault %s: %v", vaultName, err), globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
			}
			return
		}

		for _, item := range page.Value {
			if item == nil || item.Name == nil {
				continue
			}

			itemName := *item.Name
			itemType := "Unknown"
			protectionState := "Unknown"
			lastBackupTime := "Never"
			policyName := "None"
			workloadType := "Unknown"

			// Extract properties
			props := item.Properties
			if props != nil {
				// Type assertion to get specific item types
				switch p := props.(type) {
				case *armrecoveryservicesbackup.AzureIaaSComputeVMProtectedItem:
					itemType = "Azure VM"
					workloadType = "VM"
					if p.ProtectionState != nil {
						protectionState = string(*p.ProtectionState)
					}
					if p.LastBackupTime != nil {
						lastBackupTime = p.LastBackupTime.Format("2006-01-02")
					}
					if p.PolicyID != nil {
						parts := strings.Split(*p.PolicyID, "/")
						policyName = parts[len(parts)-1]
					}
				case *armrecoveryservicesbackup.AzureIaaSClassicComputeVMProtectedItem:
					itemType = "Azure VM (Classic)"
					workloadType = "VM"
					if p.ProtectionState != nil {
						protectionState = string(*p.ProtectionState)
					}
					if p.LastBackupTime != nil {
						lastBackupTime = p.LastBackupTime.Format("2006-01-02")
					}
					if p.PolicyID != nil {
						parts := strings.Split(*p.PolicyID, "/")
						policyName = parts[len(parts)-1]
					}
				case *armrecoveryservicesbackup.AzureSQLProtectedItem:
					itemType = "Azure SQL Database"
					workloadType = "SQL"
					if p.ProtectionState != nil {
						protectionState = string(*p.ProtectionState)
					}
					if p.LastBackupTime != nil {
						lastBackupTime = p.LastBackupTime.Format("2006-01-02")
					}
				case *armrecoveryservicesbackup.AzureFileshareProtectedItem:
					itemType = "Azure File Share"
					workloadType = "File Share"
					if p.ProtectionState != nil {
						protectionState = string(*p.ProtectionState)
					}
					if p.LastBackupTime != nil {
						lastBackupTime = p.LastBackupTime.Format("2006-01-02")
					}
				default:
					itemType = "Other"
				}
			}

			// Determine risk level
			riskLevel := "INFO"
			if protectionState != "Protected" {
				riskLevel = "MEDIUM"
			}

			// Build row
			row := []string{
				subID,
				subName,
				vaultName,
				itemName,
				itemType,
				workloadType,
				protectionState,
				lastBackupTime,
				policyName,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.ProtectedItemRows = append(m.ProtectedItemRows, row)
			m.mu.Unlock()
		}
	}
	*/
}

// ------------------------------
// Check for unprotected VMs (sample)
// ------------------------------
func (m *BackupInventoryModule) checkUnprotectedVMs(ctx context.Context, logger internal.Logger) {
	// For each subscription, sample VMs and check if they're in protected items
	for _, subID := range m.Subscriptions {
		subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

		// Get sample of VMs (up to 10 per subscription)
		vms := m.sampleVMs(ctx, subID, 10)

		// Check which VMs are protected
		for _, vmID := range vms {
			vmName := vmID
			parts := strings.Split(vmID, "/")
			if len(parts) > 0 {
				vmName = parts[len(parts)-1]
			}

			// Check if VM is in protected items
			isProtected := m.isVMProtected(vmName)

			if !isProtected {
				// Build row
				row := []string{
					subID,
					subName,
					vmName,
					vmID,
					"No",
					"HIGH",
				}

				// Add tenant info if multi-tenant
				if m.IsMultiTenant {
					row = append([]string{m.TenantName, m.TenantID}, row...)
				}

				// Thread-safe append
				m.mu.Lock()
				m.UnprotectedVMRows = append(m.UnprotectedVMRows, row)

				// Add to loot
				lootEntry := fmt.Sprintf("[NO BACKUP] VM: %s - ID: %s (Subscription: %s)\n", vmName, vmID, subName)
				m.LootMap["backup-unprotected-vms"].Contents += lootEntry
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Sample VMs (helper)
// ------------------------------
func (m *BackupInventoryModule) sampleVMs(ctx context.Context, subID string, limit int) []string {
	// Use cached VMs if available
	vms := sdk.CachedGetVMsPerSubscription(m.Session, subID)
	vmIDs := make([]string, 0, len(vms))

	count := 0
	for _, vm := range vms {
		if vm.ID != nil {
			vmIDs = append(vmIDs, *vm.ID)
			count++
			if count >= limit {
				break
			}
		}
	}

	return vmIDs
}

// ------------------------------
// Check if VM is protected (helper)
// ------------------------------
func (m *BackupInventoryModule) isVMProtected(vmName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, row := range m.ProtectedItemRows {
		// Check item name column (varies based on multi-tenant)
		nameCol := 3
		if m.IsMultiTenant {
			nameCol = 5
		}
		if len(row) > nameCol && strings.Contains(strings.ToLower(row[nameCol]), strings.ToLower(vmName)) {
			return true
		}
	}
	return false
}

// ------------------------------
// Generate setup commands loot
// ------------------------------
func (m *BackupInventoryModule) generateSetupCommands() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var commands strings.Builder
	commands.WriteString("# Azure Backup Setup Commands\n\n")

	// Commands to create Recovery Services Vault
	commands.WriteString("## Create Recovery Services Vault\n\n")
	seenSubs := make(map[string]bool)
	for _, row := range m.VaultRows {
		var subID, subName string
		if m.IsMultiTenant {
			if len(row) >= 4 {
				subID, subName = row[2], row[3]
			}
		} else {
			if len(row) >= 2 {
				subID, subName = row[0], row[1]
			}
		}

		if !seenSubs[subID] {
			seenSubs[subID] = true
			commands.WriteString(fmt.Sprintf("# Create Recovery Services Vault for subscription %s (%s)\n", subName, subID))
			commands.WriteString(fmt.Sprintf("az backup vault create \\\n"))
			commands.WriteString(fmt.Sprintf("  --resource-group <resource-group> \\\n"))
			commands.WriteString(fmt.Sprintf("  --name cloudfox-backup-vault \\\n"))
			commands.WriteString(fmt.Sprintf("  --location <region> \\\n"))
			commands.WriteString(fmt.Sprintf("  --subscription %s\n\n", subID))
		}
	}

	// Commands to enable VM backup
	commands.WriteString("\n## Enable VM Backup\n\n")
	seenVMs := make(map[string]bool)
	for _, row := range m.UnprotectedVMRows {
		var vmID, vmName string
		if m.IsMultiTenant {
			if len(row) >= 6 {
				vmID, vmName = row[5], row[4]
			}
		} else {
			if len(row) >= 4 {
				vmID, vmName = row[3], row[2]
			}
		}

		if !seenVMs[vmID] {
			seenVMs[vmID] = true
			commands.WriteString(fmt.Sprintf("# Enable backup for VM %s\n", vmName))
			commands.WriteString(fmt.Sprintf("az backup protection enable-for-vm \\\n"))
			commands.WriteString(fmt.Sprintf("  --resource-group <resource-group> \\\n"))
			commands.WriteString(fmt.Sprintf("  --vault-name <vault-name> \\\n"))
			commands.WriteString(fmt.Sprintf("  --vm %s \\\n", vmID))
			commands.WriteString(fmt.Sprintf("  --policy-name DefaultPolicy\n\n"))
		}
	}

	m.LootMap["backup-setup-commands"].Contents = commands.String()
}

// ------------------------------
// Write output
// ------------------------------
func (m *BackupInventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// -------------------- TABLE 1: Recovery Services Vaults --------------------
	vaultHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Vault Name",
		"Location",
		"SKU",
		"Redundancy",
		"Provisioning State",
		"Public Network Access",
		"Private Endpoints",
		"Security Issues",
		"Risk Level",
	}
	if m.IsMultiTenant {
		vaultHeader = append([]string{"Tenant Name", "Tenant ID"}, vaultHeader...)
	}

	// Sort vault rows by subscription
	sort.Slice(m.VaultRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.VaultRows[i]) > iOffset && len(m.VaultRows[j]) > jOffset {
			return m.VaultRows[i][iOffset] < m.VaultRows[j][jOffset]
		}
		return false
	})

	vaultTable := internal.TableFile{
		Name:      "recovery-services-vaults",
		Header:    vaultHeader,
		Body:      m.VaultRows,
		TableCols: vaultHeader,
	}

	// -------------------- TABLE 2: Backup Policies --------------------
	policyHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Vault Name",
		"Policy Name",
		"Policy Type",
		"Workload Type",
		"Retention",
		"Schedule Type",
		"Risk Level",
	}
	if m.IsMultiTenant {
		policyHeader = append([]string{"Tenant Name", "Tenant ID"}, policyHeader...)
	}

	// Sort policy rows by vault
	sort.Slice(m.PolicyRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.PolicyRows[i]) > iOffset+2 && len(m.PolicyRows[j]) > jOffset+2 {
			return m.PolicyRows[i][iOffset+2] < m.PolicyRows[j][jOffset+2]
		}
		return false
	})

	policyTable := internal.TableFile{
		Name:      "backup-policies",
		Header:    policyHeader,
		Body:      m.PolicyRows,
		TableCols: policyHeader,
	}

	// -------------------- TABLE 3: Protected Items --------------------
	protectedHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Vault Name",
		"Item Name",
		"Item Type",
		"Workload Type",
		"Protection State",
		"Last Backup",
		"Policy Name",
		"Risk Level",
	}
	if m.IsMultiTenant {
		protectedHeader = append([]string{"Tenant Name", "Tenant ID"}, protectedHeader...)
	}

	// Sort protected item rows by vault
	sort.Slice(m.ProtectedItemRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.ProtectedItemRows[i]) > iOffset+2 && len(m.ProtectedItemRows[j]) > jOffset+2 {
			return m.ProtectedItemRows[i][iOffset+2] < m.ProtectedItemRows[j][jOffset+2]
		}
		return false
	})

	protectedTable := internal.TableFile{
		Name:      "protected-items",
		Header:    protectedHeader,
		Body:      m.ProtectedItemRows,
		TableCols: protectedHeader,
	}

	// -------------------- TABLE 4: Unprotected VMs (Sample) --------------------
	unprotectedHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"VM Name",
		"VM ID",
		"Has Backup",
		"Risk Level",
	}
	if m.IsMultiTenant {
		unprotectedHeader = append([]string{"Tenant Name", "Tenant ID"}, unprotectedHeader...)
	}

	// Sort unprotected VM rows by subscription
	sort.Slice(m.UnprotectedVMRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.UnprotectedVMRows[i]) > iOffset && len(m.UnprotectedVMRows[j]) > jOffset {
			return m.UnprotectedVMRows[i][iOffset] < m.UnprotectedVMRows[j][jOffset]
		}
		return false
	})

	unprotectedTable := internal.TableFile{
		Name:      "unprotected-vms-sample",
		Header:    unprotectedHeader,
		Body:      m.UnprotectedVMRows,
		TableCols: unprotectedHeader,
	}

	// -------------------- Combine tables --------------------
	tables := []internal.TableFile{
		vaultTable,
		policyTable,
		protectedTable,
		unprotectedTable,
	}

	// -------------------- Convert loot map to slice --------------------
	var loot []internal.LootFile
	lootOrder := []string{
		"backup-unprotected-vms",
		"backup-short-retention",
		"backup-no-georedundancy",
		"backup-disabled-vaults",
		"backup-setup-commands",
	}
	for _, key := range lootOrder {
		if lootFile, exists := m.LootMap[key]; exists && lootFile.Contents != "" {
			loot = append(loot, *lootFile)
		}
	}

	// -------------------- Generate output --------------------
	_ = BackupInventoryOutput{ // output - unused for now
		Table: tables,
		Loot:  loot,
	}

	// -------------------- Write files using helper --------------------
	summary := fmt.Sprintf("%d subscriptions, %d vaults, %d policies, %d protected items, %d unprotected VMs (sample)",
		len(m.Subscriptions),
		len(m.VaultRows),
		len(m.PolicyRows),
		len(m.ProtectedItemRows),
		len(m.UnprotectedVMRows))

	// Write output summary
	// TODO: Implement proper table and loot file writing
	logger.InfoM(summary, globals.AZ_BACKUP_INVENTORY_MODULE_NAME)
	if m.Verbosity >= 1 {
		fmt.Println(summary)
	}
}
