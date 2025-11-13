package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzKustoCommand = &cobra.Command{
	Use:     "kusto",
	Aliases: []string{"data-explorer", "adx"},
	Short:   "Enumerate Azure Data Explorer (Kusto) clusters and databases",
	Long: `
Enumerate Azure Data Explorer for a specific tenant:
  ./cloudfox az kusto --tenant TENANT_ID

Enumerate Azure Data Explorer for a specific subscription:
  ./cloudfox az kusto --subscription SUBSCRIPTION_ID`,
	Run: ListKusto,
}

// ------------------------------
// Module struct
// ------------------------------
type KustoModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	KustoRows     [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type KustoOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o KustoOutput) TableFiles() []internal.TableFile { return o.Table }
func (o KustoOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListKusto(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_KUSTO_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &KustoModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		KustoRows:       [][]string{},
		LootMap: map[string]*internal.LootFile{
			"kusto-commands":           {Name: "kusto-commands", Contents: ""},
			"kusto-connection-strings": {Name: "kusto-connection-strings", Contents: "# Azure Data Explorer Connection Strings\n\n"},
		},
	}

	module.PrintKusto(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *KustoModule) PrintKusto(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_KUSTO_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_KUSTO_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *KustoModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create Kusto client
	kustoClient, err := azinternal.GetKustoClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Kusto client for subscription %s: %v", subID, err), globals.AZ_KUSTO_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Create Databases client
	dbClient, err := azinternal.GetKustoDatabasesClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Kusto Databases client for subscription %s: %v", subID, err), globals.AZ_KUSTO_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rg := range rgs {
		if rg.Name == nil {
			continue
		}
		rgName := *rg.Name

		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, kustoClient, dbClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *KustoModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, kustoClient *armkusto.ClustersClient, dbClient *armkusto.DatabasesClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	for _, r := range rgs {
		if r.Name != nil && *r.Name == rgName && r.Location != nil {
			region = *r.Location
			break
		}
	}

	// List Kusto clusters in resource group
	pager := kustoClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list Kusto clusters in %s/%s: %v", subID, rgName, err), globals.AZ_KUSTO_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, cluster := range page.Value {
			m.processCluster(ctx, subID, subName, rgName, region, cluster, dbClient, logger)
		}
	}
}

// ------------------------------
// Process single Kusto cluster
// ------------------------------
func (m *KustoModule) processCluster(ctx context.Context, subID, subName, rgName, region string, cluster *armkusto.Cluster, dbClient *armkusto.DatabasesClient, logger internal.Logger) {
	if cluster == nil || cluster.Name == nil {
		return
	}

	clusterName := *cluster.Name

	// Extract cluster properties
	uri := azinternal.SafeStringPtr(cluster.Properties.URI)
	dataIngestionURI := azinternal.SafeStringPtr(cluster.Properties.DataIngestionURI)
	state := "N/A"
	if cluster.Properties.State != nil {
		state = string(*cluster.Properties.State)
	}

	provisioningState := "N/A"
	if cluster.Properties.ProvisioningState != nil {
		provisioningState = string(*cluster.Properties.ProvisioningState)
	}

	// Public/Private access
	publicNetworkAccess := "Enabled"
	if cluster.Properties != nil && cluster.Properties.PublicNetworkAccess != nil {
		publicNetworkAccess = string(*cluster.Properties.PublicNetworkAccess)
	}

	// Encryption settings
	diskEncryption := "Disabled"
	if cluster.Properties != nil && cluster.Properties.EnableDiskEncryption != nil && *cluster.Properties.EnableDiskEncryption {
		diskEncryption = "Enabled"
	}

	doubleEncryption := "Disabled"
	if cluster.Properties != nil && cluster.Properties.EnableDoubleEncryption != nil && *cluster.Properties.EnableDoubleEncryption {
		doubleEncryption = "Enabled"
	}

	// Managed identity
	systemAssignedID := "N/A"
	userAssignedIDs := "N/A"
	if cluster.Identity != nil {
		if cluster.Identity.Type != nil {
			idType := string(*cluster.Identity.Type)
			if strings.Contains(idType, "SystemAssigned") && cluster.Identity.PrincipalID != nil {
				systemAssignedID = *cluster.Identity.PrincipalID
			}
		}
		if cluster.Identity.UserAssignedIdentities != nil && len(cluster.Identity.UserAssignedIdentities) > 0 {
			uaIDs := []string{}
			for uaID := range cluster.Identity.UserAssignedIdentities {
				uaIDs = append(uaIDs, azinternal.ExtractResourceName(uaID))
			}
			userAssignedIDs = strings.Join(uaIDs, ", ")
		}
	}

	// EntraID Centralized Auth - Kusto uses AAD authentication by default
	entraIDAuth := "Enabled" // Kusto always uses Azure AD for authentication

	// Count databases
	databaseCount := 0
	databaseNames := []string{}
	dbPager := dbClient.NewListByClusterPager(rgName, clusterName, nil)
	for dbPager.More() {
		dbPage, err := dbPager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list databases for cluster %s: %v", clusterName, err), globals.AZ_KUSTO_MODULE_NAME)
			}
			break
		}

		for _, db := range dbPage.Value {
			databaseCount++
			if db.GetDatabase() != nil && db.GetDatabase().Name != nil {
				databaseNames = append(databaseNames, *db.GetDatabase().Name)
			}
		}
	}

	databaseNamesStr := strings.Join(databaseNames, ", ")
	if databaseNamesStr == "" {
		databaseNamesStr = "N/A"
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		clusterName,
		uri,
		dataIngestionURI,
		fmt.Sprintf("%d", databaseCount),
		databaseNamesStr,
		state,
		provisioningState,
		publicNetworkAccess,
		diskEncryption,
		doubleEncryption,
		entraIDAuth,
		systemAssignedID,
		userAssignedIDs,
	}

	m.mu.Lock()
	m.KustoRows = append(m.KustoRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate loot
	m.generateLoot(subID, subName, rgName, clusterName, uri, dataIngestionURI, publicNetworkAccess, databaseNamesStr)
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *KustoModule) generateLoot(subID, subName, rgName, clusterName, uri, dataIngestionURI, publicNetworkAccess, databases string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Azure CLI commands
	m.LootMap["kusto-commands"].Contents += fmt.Sprintf("# Kusto Cluster: %s (Resource Group: %s)\n", clusterName, rgName)
	m.LootMap["kusto-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["kusto-commands"].Contents += fmt.Sprintf("az kusto cluster show --name %s --resource-group %s\n", clusterName, rgName)
	m.LootMap["kusto-commands"].Contents += fmt.Sprintf("az kusto database list --cluster-name %s --resource-group %s -o table\n\n", clusterName, rgName)

	// Connection strings
	if uri != "N/A" && uri != "UNKNOWN" {
		m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("# Cluster: %s/%s\n", rgName, clusterName)
		m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("Cluster URI: %s\n", uri)
		m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("Data Ingestion URI: %s\n", dataIngestionURI)
		m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("Subscription: %s\n", subName)
		m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("Public Network Access: %s\n", publicNetworkAccess)
		if databases != "N/A" {
			m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("Databases: %s\n", databases)
		}
		m.LootMap["kusto-connection-strings"].Contents += "\n# Kusto CLI Connection:\n"
		m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("Kusto.Explorer.exe -uri:%s\n\n", uri)
		m.LootMap["kusto-connection-strings"].Contents += "# Python Connection:\n"
		m.LootMap["kusto-connection-strings"].Contents += "from azure.kusto.data import KustoClient, KustoConnectionStringBuilder\n"
		m.LootMap["kusto-connection-strings"].Contents += fmt.Sprintf("kcsb = KustoConnectionStringBuilder.with_aad_device_authentication(\"%s\")\n", uri)
		m.LootMap["kusto-connection-strings"].Contents += "client = KustoClient(kcsb)\n\n"
	}

}

// ------------------------------
// Write output
// ------------------------------
func (m *KustoModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.KustoRows) == 0 {
		logger.InfoM("No Azure Data Explorer clusters found", globals.AZ_KUSTO_MODULE_NAME)
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
		"Cluster Name",
		"Cluster URI",
		"Data Ingestion URI",
		"Database Count",
		"Databases",
		"State",
		"Provisioning State",
		"Public Network Access",
		"Disk Encryption",
		"Double Encryption",
		"EntraID Centralized Auth",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.KustoRows, headers,
			"kusto", globals.AZ_KUSTO_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.KustoRows, headers,
			"kusto", globals.AZ_KUSTO_MODULE_NAME,
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
	output := KustoOutput{
		Table: []internal.TableFile{{
			Name:   "kusto",
			Header: headers,
			Body:   m.KustoRows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_KUSTO_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d Azure Data Explorer clusters across %d subscriptions", len(m.KustoRows), len(m.Subscriptions)), globals.AZ_KUSTO_MODULE_NAME)
}
