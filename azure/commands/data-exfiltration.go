package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzDataExfiltrationCommand = &cobra.Command{
	Use:     "data-exfiltration",
	Aliases: []string{"exfil", "exfiltration-paths", "data-exfil"},
	Short:   "Identify data exfiltration opportunities (snapshots, backups, storage access)",
	Long: `
Identify data exfiltration paths for a specific tenant:
  ./cloudfox az data-exfiltration --tenant TENANT_ID

Identify data exfiltration paths for a specific subscription:
  ./cloudfox az data-exfiltration --subscription SUBSCRIPTION_ID

This module identifies opportunities for data exfiltration including:
- VM and disk snapshots (downloadable data copies)
- Database backup configurations
- Storage accounts with public/shared access
- Export-enabled resources`,
	Run: ListDataExfiltration,
}

// ------------------------------
// Module struct
// ------------------------------
type DataExfiltrationModule struct {
	azinternal.BaseAzureModule

	Subscriptions    []string
	ExfiltrationRows [][]string
	LootMap          map[string]*internal.LootFile
	mu               sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type DataExfiltrationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataExfiltrationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataExfiltrationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListDataExfiltration(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &DataExfiltrationModule{
		BaseAzureModule:  azinternal.NewBaseAzureModule(cmdCtx, 10),
		Subscriptions:    cmdCtx.Subscriptions,
		ExfiltrationRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"exfiltration-commands": {Name: "exfiltration-commands", Contents: ""},
			"high-risk-resources":   {Name: "high-risk-resources", Contents: ""},
		},
	}

	module.PrintDataExfiltration(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *DataExfiltrationModule) PrintDataExfiltration(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_DATA_EXFILTRATION_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_DATA_EXFILTRATION_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *DataExfiltrationModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	// Process different exfiltration vectors
	m.processSnapshots(ctx, subID, subName, cred, logger)
	m.processStorageAccounts(ctx, subID, subName, cred, logger)
}

// ------------------------------
// Process disk and VM snapshots
// ------------------------------
func (m *DataExfiltrationModule) processSnapshots(ctx context.Context, subID, subName string, cred *azinternal.StaticTokenCredential, logger internal.Logger) {
	// Create snapshots client
	snapshotClient, err := armcompute.NewSnapshotsClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create snapshots client: %v", err), globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	pager := snapshotClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list snapshots: %v", err), globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, snapshot := range page.Value {
			m.processSnapshot(ctx, snapshot, subID, subName, logger)
		}
	}
}

// ------------------------------
// Process individual snapshot
// ------------------------------
func (m *DataExfiltrationModule) processSnapshot(ctx context.Context, snapshot *armcompute.Snapshot, subID, subName string, logger internal.Logger) {
	snapshotName := azinternal.SafeStringPtr(snapshot.Name)
	region := azinternal.SafeStringPtr(snapshot.Location)
	resourceType := "Disk Snapshot"
	riskLevel := "⚠ HIGH"
	exfilMethod := "Download via SAS URL"
	dataType := "Disk Image"
	sizeGB := "Unknown"
	encryption := "Platform-Managed"
	publicAccess := "No"
	agedays := "Unknown"
	recommendation := "Review and delete if unnecessary"

	// Get resource group from ID
	rgName := "Unknown"
	if snapshot.ID != nil {
		rgName = azinternal.GetResourceGroupFromID(*snapshot.ID)
	}

	// Get snapshot properties
	if snapshot.Properties != nil {
		// Size
		if snapshot.Properties.DiskSizeGB != nil {
			sizeGB = fmt.Sprintf("%d GB", *snapshot.Properties.DiskSizeGB)
		}

		// Encryption
		if snapshot.Properties.Encryption != nil && snapshot.Properties.Encryption.Type != nil {
			encType := string(*snapshot.Properties.Encryption.Type)
			if strings.Contains(encType, "CustomerManaged") {
				encryption = "Customer-Managed Keys"
			} else if strings.Contains(encType, "EncryptionAtRestWithPlatformAndCustomerKeys") {
				encryption = "Double Encryption"
			}
		}

		// Age
		if snapshot.Properties.TimeCreated != nil {
			age := time.Since(*snapshot.Properties.TimeCreated)
			ageDays := int(age.Hours() / 24)
			agedays = fmt.Sprintf("%d days", ageDays)

			if ageDays > 90 {
				recommendation = "⚠ OLD SNAPSHOT: Consider deletion (>90 days old)"
			} else if ageDays > 30 {
				recommendation = "Review retention policy (>30 days old)"
			}
		}

		// Determine source
		if snapshot.Properties.CreationData != nil && snapshot.Properties.CreationData.SourceResourceID != nil {
			sourceID := *snapshot.Properties.CreationData.SourceResourceID
			if strings.Contains(sourceID, "/virtualMachines/") {
				dataType = "VM Disk Image"
				riskLevel = "⚠ CRITICAL"
				recommendation = "CRITICAL: Contains VM data - " + recommendation
			}
		}

		// Network access policy
		if snapshot.Properties.NetworkAccessPolicy != nil {
			policy := string(*snapshot.Properties.NetworkAccessPolicy)
			if strings.Contains(policy, "AllowAll") {
				publicAccess = "⚠ Yes (AllowAll)"
				riskLevel = "⚠ CRITICAL"
				recommendation = "CRITICAL: Public access enabled - " + recommendation
			} else if strings.Contains(policy, "AllowPrivate") {
				publicAccess = "Private Only"
			}
		}
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		resourceType,
		snapshotName,
		riskLevel,
		exfilMethod,
		dataType,
		sizeGB,
		agedays,
		encryption,
		publicAccess,
		recommendation,
	}

	m.mu.Lock()
	m.ExfiltrationRows = append(m.ExfiltrationRows, row)
	m.mu.Unlock()

	m.CommandCounter.Total++

	// Generate loot
	m.mu.Lock()
	if strings.Contains(riskLevel, "CRITICAL") {
		m.LootMap["high-risk-resources"].Contents += fmt.Sprintf(
			"## CRITICAL RISK: Snapshot %s\n"+
				"Resource Group: %s\n"+
				"Size: %s\n"+
				"Age: %s\n"+
				"Public Access: %s\n"+
				"Recommendation: %s\n\n",
			snapshotName, rgName, sizeGB, agedays, publicAccess, recommendation)
	}

	m.LootMap["exfiltration-commands"].Contents += fmt.Sprintf(
		"## Snapshot: %s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Grant access and get SAS URL (60 minutes)\n"+
			"az snapshot grant-access \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s \\\n"+
			"  --duration-in-seconds 3600 \\\n"+
			"  --query accessSas -o tsv\n"+
			"\n"+
			"# Download using SAS URL\n"+
			"# wget -O %s.vhd \"<SAS_URL_FROM_ABOVE>\"\n"+
			"\n"+
			"# Convert VHD to QCOW2 (if needed)\n"+
			"# qemu-img convert -f vpc -O qcow2 %s.vhd %s.qcow2\n"+
			"\n"+
			"# Revoke access when done\n"+
			"az snapshot revoke-access --resource-group %s --name %s\n\n",
		snapshotName, rgName,
		subID,
		rgName, snapshotName,
		snapshotName,
		snapshotName, snapshotName,
		rgName, snapshotName)
	m.mu.Unlock()
}

// ------------------------------
// Process storage accounts
// ------------------------------
func (m *DataExfiltrationModule) processStorageAccounts(ctx context.Context, subID, subName string, cred *azinternal.StaticTokenCredential, logger internal.Logger) {
	// Get resource groups
	resourceGroups := m.ResolveResourceGroups(subID)

	for _, rgName := range resourceGroups {
		m.processStorageAccountsInRG(ctx, subID, subName, rgName, cred, logger)
	}
}

// ------------------------------
// Process storage accounts in resource group
// ------------------------------
func (m *DataExfiltrationModule) processStorageAccountsInRG(ctx context.Context, subID, subName, rgName string, cred *azinternal.StaticTokenCredential, logger internal.Logger) {
	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	storageClient, err := armstorage.NewAccountsClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create storage client: %v", err), globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	pager := storageClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list storage accounts in RG %s: %v", rgName, err), globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, account := range page.Value {
			m.processStorageAccount(ctx, account, subID, subName, rgName, region, storageClient, logger)
		}
	}
}

// ------------------------------
// Process individual storage account
// ------------------------------
func (m *DataExfiltrationModule) processStorageAccount(ctx context.Context, account *armstorage.Account, subID, subName, rgName, region string, storageClient *armstorage.AccountsClient, logger internal.Logger) {
	accountName := azinternal.SafeStringPtr(account.Name)
	resourceType := "Storage Account"
	riskLevel := "MEDIUM"
	exfilMethod := "Account Keys / SAS Tokens"
	dataType := "Blobs, Files, Tables, Queues"
	sizeGB := "Unknown"
	encryption := "Platform-Managed"
	publicAccess := "Unknown"
	agedays := "Unknown"
	recommendation := "Review access keys and SAS tokens"

	if account.Properties != nil {
		// Public network access
		if account.Properties.PublicNetworkAccess != nil {
			if *account.Properties.PublicNetworkAccess == armstorage.PublicNetworkAccessEnabled {
				publicAccess = "⚠ Yes (Public)"
				riskLevel = "⚠ HIGH"
				recommendation = "HIGH RISK: Public access enabled"
			} else {
				publicAccess = "No (Private endpoints only)"
			}
		}

		// Blob public access
		if account.Properties.AllowBlobPublicAccess != nil && *account.Properties.AllowBlobPublicAccess {
			publicAccess = "⚠ CRITICAL (Blob public access allowed)"
			riskLevel = "⚠ CRITICAL"
			recommendation = "CRITICAL: Blob containers can be made public"
		}

		// Shared key access
		if account.Properties.AllowSharedKeyAccess != nil && !*account.Properties.AllowSharedKeyAccess {
			exfilMethod = "SAS Tokens only (Shared Key disabled)"
		}

		// Encryption
		if account.Properties.Encryption != nil && account.Properties.Encryption.KeySource != nil {
			keySource := string(*account.Properties.Encryption.KeySource)
			if strings.Contains(keySource, "Microsoft.Keyvault") {
				encryption = "Customer-Managed Keys"
			}
		}

		// Creation time
		if account.Properties.CreationTime != nil {
			age := time.Since(*account.Properties.CreationTime)
			ageDays := int(age.Hours() / 24)
			agedays = fmt.Sprintf("%d days", ageDays)
		}
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		resourceType,
		accountName,
		riskLevel,
		exfilMethod,
		dataType,
		sizeGB,
		agedays,
		encryption,
		publicAccess,
		recommendation,
	}

	m.mu.Lock()
	m.ExfiltrationRows = append(m.ExfiltrationRows, row)
	m.mu.Unlock()

	m.CommandCounter.Total++

	// Generate loot
	m.mu.Lock()
	if strings.Contains(riskLevel, "CRITICAL") || strings.Contains(riskLevel, "HIGH") {
		m.LootMap["high-risk-resources"].Contents += fmt.Sprintf(
			"## %s RISK: Storage Account %s\n"+
				"Resource Group: %s\n"+
				"Public Access: %s\n"+
				"Recommendation: %s\n\n",
			riskLevel, accountName, rgName, publicAccess, recommendation)
	}

	m.LootMap["exfiltration-commands"].Contents += fmt.Sprintf(
		"## Storage Account: %s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# List account keys\n"+
			"az storage account keys list \\\n"+
			"  --resource-group %s \\\n"+
			"  --account-name %s\n"+
			"\n"+
			"# Generate SAS token (90 days read access)\n"+
			"az storage account generate-sas \\\n"+
			"  --account-name %s \\\n"+
			"  --permissions rl \\\n"+
			"  --services bfqt \\\n"+
			"  --resource-types sco \\\n"+
			"  --expiry $(date -u -d \"90 days\" '+%%Y-%%m-%%dT%%H:%%MZ')\n"+
			"\n"+
			"# Download all blobs (requires storage key)\n"+
			"# az storage blob download-batch \\\n"+
			"#   --account-name %s \\\n"+
			"#   --source <CONTAINER_NAME> \\\n"+
			"#   --destination ./exfil-data/ \\\n"+
			"#   --account-key <KEY_FROM_ABOVE>\n\n",
		accountName, rgName,
		subID,
		rgName, accountName,
		accountName,
		accountName)
	m.mu.Unlock()
}

// ------------------------------
// Write output
// ------------------------------
func (m *DataExfiltrationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.ExfiltrationRows) == 0 {
		logger.InfoM("No data exfiltration paths found", globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
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
		"Resource Type",
		"Resource Name",
		"Risk Level",
		"Exfiltration Method",
		"Data Type",
		"Size/Scale",
		"Age",
		"Encryption",
		"Public Access",
		"Recommendation",
	}

	// Check if we should split output by tenant
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.ExfiltrationRows, headers,
			"data-exfiltration", globals.AZ_DATA_EXFILTRATION_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.ExfiltrationRows, headers,
			"data-exfiltration", globals.AZ_DATA_EXFILTRATION_MODULE_NAME,
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
	output := DataExfiltrationOutput{
		Table: []internal.TableFile{{
			Name:   "data-exfiltration-paths",
			Header: headers,
			Body:   m.ExfiltrationRows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d exfiltration paths across %d subscription(s)", len(m.ExfiltrationRows), len(m.Subscriptions)), globals.AZ_DATA_EXFILTRATION_MODULE_NAME)
}
