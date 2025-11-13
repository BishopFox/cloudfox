package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mariadb/armmariadb"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql"
	armmysqlflexibleservers "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql"
	armpostgresqlflexibleservers "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// Output struct implementing CloudfoxOutput
type DatabasesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DatabasesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DatabasesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ---------------- Helper Functions ----------------

//func GetDatabasesPerSubscription(ctx context.Context, subID, subName string, lootMap map[string]*internal.LootFile, region string) [][]string {
//	cred := GetCredential()
//	if cred == nil {
//		return nil
//	}
//	var results [][]string
//	rgs := GetResourceGroupsPerSubscription(subID)
//	for _, rg := range rgs {
//		dbRows := getDatabasesPerResourceGroup(ctx, subID, subName, rg, lootMap, region)
//		results = append(results, dbRows...)
//	}
//	return results
//}

func GetDatabasesPerResourceGroup(ctx context.Context, session *SafeSession, subID, subName string, rgName string, lootMap map[string]*internal.LootFile, region string, tenantName string, tenantID string) [][]string {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}

	var body [][]string

	// Ensure loot entries exist
	commLootKey := "database-commands"
	if _, ok := lootMap[commLootKey]; !ok {
		lootMap[commLootKey] = &internal.LootFile{
			Name:     commLootKey,
			Contents: "",
		}
	}
	stringLootKey := "database-strings"
	if _, ok := lootMap[stringLootKey]; !ok {
		lootMap[stringLootKey] = &internal.LootFile{
			Name:     stringLootKey,
			Contents: "",
		}
	}

	// ---------------- SQL Servers ----------------
	sqlServers := GetSQLServers(ctx, session, subID, rgName)
	for _, srv := range sqlServers {
		privateIPs, publicIPs := GetDatabaseServerIPs(ctx, session, subID, SafeStringPtr(srv.ID))

		// Extract Tags from server
		tags := "N/A"
		if srv.Tags != nil && len(srv.Tags) > 0 {
			var tagPairs []string
			for k, v := range srv.Tags {
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

		// List databases on this server
		dbClient, _ := armsql.NewDatabasesClient(subID, cred, nil)
		dbPager := dbClient.NewListByServerPager(rgName, SafeStringPtr(srv.Name), nil)

		for dbPager.More() {
			page, err := dbPager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				dbName := SafeStringPtr(db.Name)
				if dbName == "UNKNOWN" {
					continue
				}

				ddmStatus := CheckDynamicDataMasking(ctx, session, subID, rgName, SafeStringPtr(srv.Name), dbName)

				rbacStatus := IsEntraIDAuthEnabled(ctx, session, subID, rgName, dbName, "SQL", srv)
				sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, srv)

				// Check TDE (Transparent Data Encryption) status
				tdeStatus := CheckTDEStatus(ctx, cred, subID, rgName, SafeStringPtr(srv.Name), dbName)

				// Check if server uses customer-managed keys for encryption
				cmkStatus := "No"
				if srv.Properties != nil && srv.Properties.KeyID != nil && *srv.Properties.KeyID != "" {
					cmkStatus = "Yes"
				}

				// Check Minimum TLS Version
				minTlsVersion := "N/A"
				if srv.Properties != nil && srv.Properties.MinimalTLSVersion != nil {
					minTlsVersion = *srv.Properties.MinimalTLSVersion
				}

				// NEW: Check ATP/Defender for SQL status
				atpStatus := CheckATPDefenderStatus(ctx, session, subID, rgName, SafeStringPtr(srv.Name))

				// NEW: Check Auditing status and retention
				auditingStatus, auditingRetention := CheckAuditingStatus(ctx, session, subID, rgName, SafeStringPtr(srv.Name))

				// NEW: Check Vulnerability Assessment status
				vaStatus := CheckVulnerabilityAssessment(ctx, session, subID, rgName, SafeStringPtr(srv.Name))

				// Extract SKU/Pricing Tier
				sku := "N/A"
				if db.SKU != nil {
					if db.SKU.Name != nil && db.SKU.Tier != nil {
						sku = fmt.Sprintf("%s (%s)", *db.SKU.Name, *db.SKU.Tier)
					} else if db.SKU.Name != nil {
						sku = *db.SKU.Name
					} else if db.SKU.Tier != nil {
						sku = *db.SKU.Tier
					}
				}

				row := []string{
					tenantName,                  // 0: Tenant Name
					tenantID,                    // 1: Tenant ID
					subID,                       // 2: Subscription ID
					subName,                     // 3: Subscription Name
					rgName,                      // 4: Resource Group
					SafeStringPtr(srv.Location), // 5: Region
					fmt.Sprintf("%s.database.windows.net", SafeStringPtr(srv.Name)), // 6: Database Server
					dbName,                         // 7: Database Name
					"SQL Database",                 // 8: DB Type
					sku,                            // 9: SKU/Tier
					tags,                           // 10: Tags
					strings.Join(privateIPs, "\n"), // 11: Private IPs
					strings.Join(publicIPs, "\n"),  // 12: Public IPs
					SafeStringPtr(srv.Properties.AdministratorLogin), // 13: Admin Username
					rbacStatus,                              // 14: EntraID Centralized Auth
					DatabaseExposure(privateIPs, publicIPs), // 15: Public?
					tdeStatus,                               // 16: Encryption/TDE
					cmkStatus,                               // 17: Customer Managed Key
					minTlsVersion,                           // 18: Min TLS Version
					ddmStatus,                               // 19: Dynamic Data Masking
					atpStatus,                               // 20: ATP/Defender for SQL (NEW)
					auditingStatus,                          // 21: Auditing Enabled (NEW)
					auditingRetention,                       // 22: Auditing Retention (NEW)
					vaStatus,                                // 23: Vulnerability Assessment (NEW)
					sysID,                                   // 24: System Assigned Identity ID
					strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
				}

				body = append(body, row)

				lootMap["database-commands"].Contents += fmt.Sprintf(
					"## SQL Server: %s, Database: %s\n"+
						"# Set subscription context\n"+
						"az account set --subscription %s\n"+
						"\n"+
						"# Get connection string\n"+
						"az sql db show-connection-string --server %s --name %s -c ado.net\n"+
						"\n"+
						"## PowerShell equivalent\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"# Connection string retrieval via Get-AzSqlDatabase\n\n",
					SafeStringPtr(srv.Name), dbName,
					subID,
					SafeStringPtr(srv.Name), dbName,
					subID)

				// ---------------- Fetch SQL connection strings ----------------
				connStr := getAzConnectionString(
					"sql", "db", "show-connection-string",
					"--server", SafeStringPtr(srv.Name),
					"--name", dbName,
					"-c", "ado.net", // or "jdbc"/"odbc"
				)
				lootMap["database-strings"].Contents += fmt.Sprintf(
					"## SQL Database: %s (server: %s)\n%s\n\n",
					dbName, SafeStringPtr(srv.Name), connStr,
				)

			}
		}
	}

	// ---------------- SQL Managed Instances ----------------
	sqlManagedInstances := GetSQLManagedInstances(ctx, session, subID, rgName)
	for _, mi := range sqlManagedInstances {
		privateIPs, publicIPs := GetDatabaseServerIPs(ctx, session, subID, SafeStringPtr(mi.ID))

		// Extract Tags from managed instance
		tags := "N/A"
		if mi.Tags != nil && len(mi.Tags) > 0 {
			var tagPairs []string
			for k, v := range mi.Tags {
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

		// List databases on this managed instance
		miDbClient, _ := armsql.NewManagedDatabasesClient(subID, cred, nil)
		miDbPager := miDbClient.NewListByInstancePager(rgName, SafeStringPtr(mi.Name), nil)

		for miDbPager.More() {
			page, err := miDbPager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				dbName := SafeStringPtr(db.Name)
				if dbName == "UNKNOWN" || dbName == "master" {
					continue
				}

				// Managed Instances use system databases, skip them
				if dbName == "model" || dbName == "msdb" || dbName == "tempdb" {
					continue
				}

				// DDM is not supported on Managed Instances the same way as SQL Database
				ddmStatus := "Not Supported on MI"

				// RBAC check for managed instance (note: interface is different)
				rbacStatus := "N/A"
				sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, mi)

				// TDE is always enabled on Managed Instances
				tdeStatus := "Always Enabled"

				// Check if instance uses customer-managed keys for encryption
				cmkStatus := "No"
				if mi.Properties != nil && mi.Properties.KeyID != nil && *mi.Properties.KeyID != "" {
					cmkStatus = "Yes"
				}

				// Check Minimum TLS Version
				minTlsVersion := "N/A"
				if mi.Properties != nil && mi.Properties.MinimalTLSVersion != nil {
					minTlsVersion = *mi.Properties.MinimalTLSVersion
				}

				// NEW: Check ATP/Defender for SQL status (supported on Managed Instance)
				atpStatus := CheckATPDefenderStatus(ctx, session, subID, rgName, SafeStringPtr(mi.Name))

				// NEW: Check Auditing status and retention (supported on Managed Instance)
				auditingStatus, auditingRetention := CheckAuditingStatus(ctx, session, subID, rgName, SafeStringPtr(mi.Name))

				// NEW: Check Vulnerability Assessment status (supported on Managed Instance)
				vaStatus := CheckVulnerabilityAssessment(ctx, session, subID, rgName, SafeStringPtr(mi.Name))

				// Extract SKU/Pricing Tier
				sku := "N/A"
				if mi.SKU != nil {
					if mi.SKU.Name != nil && mi.SKU.Tier != nil {
						sku = fmt.Sprintf("%s (%s)", *mi.SKU.Name, *mi.SKU.Tier)
					} else if mi.SKU.Name != nil {
						sku = *mi.SKU.Name
					} else if mi.SKU.Tier != nil {
						sku = *mi.SKU.Tier
					}
				}

				// Managed Instance endpoint format is different
				miEndpoint := fmt.Sprintf("%s.%s.database.windows.net", SafeStringPtr(mi.Name), SafeStringPtr(mi.Location))

				row := []string{
					tenantName,                     // 0: Tenant Name
					tenantID,                       // 1: Tenant ID
					subID,                          // 2: Subscription ID
					subName,                        // 3: Subscription Name
					rgName,                         // 4: Resource Group
					SafeStringPtr(mi.Location),     // 5: Region
					miEndpoint,                     // 6: Database Server
					dbName,                         // 7: Database Name
					"SQL Managed Instance",         // 8: DB Type
					sku,                            // 9: SKU/Tier
					tags,                           // 10: Tags
					strings.Join(privateIPs, "\n"), // 11: Private IPs
					strings.Join(publicIPs, "\n"),  // 12: Public IPs
					SafeStringPtr(mi.Properties.AdministratorLogin), // 13: Admin Username
					rbacStatus,                              // 14: EntraID Centralized Auth
					DatabaseExposure(privateIPs, publicIPs), // 15: Public?
					tdeStatus,                               // 16: Encryption/TDE
					cmkStatus,                               // 17: Customer Managed Key
					minTlsVersion,                           // 18: Min TLS Version
					ddmStatus,                               // 19: Dynamic Data Masking
					atpStatus,                               // 20: ATP/Defender for SQL (NEW)
					auditingStatus,                          // 21: Auditing Enabled (NEW)
					auditingRetention,                       // 22: Auditing Retention (NEW)
					vaStatus,                                // 23: Vulnerability Assessment (NEW)
					sysID,                                   // 24: System Assigned Identity ID
					strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
				}

				body = append(body, row)

				lootMap["database-commands"].Contents += fmt.Sprintf(
					"## SQL Managed Instance: %s, Database: %s\n"+
						"# Set subscription context\n"+
						"az account set --subscription %s\n"+
						"\n"+
						"# Get connection string for managed instance database\n"+
						"# Endpoint: %s\n"+
						"# Connection string format:\n"+
						"# Server=%s;Database=%s;User Id=%s;Password=<PASSWORD>;\n"+
						"\n"+
						"## PowerShell equivalent\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"# Get managed instance details\n"+
						"Get-AzSqlInstance -ResourceGroupName %s -Name %s\n"+
						"# Get managed database details\n"+
						"Get-AzSqlInstanceDatabase -ResourceGroupName %s -InstanceName %s -Name %s\n\n",
					SafeStringPtr(mi.Name), dbName,
					subID,
					miEndpoint,
					miEndpoint, dbName, SafeStringPtr(mi.Properties.AdministratorLogin),
					subID,
					rgName, SafeStringPtr(mi.Name),
					rgName, SafeStringPtr(mi.Name), dbName)

				// ---------------- Fetch SQL Managed Instance connection strings ----------------
				lootMap["database-strings"].Contents += fmt.Sprintf(
					"## SQL Managed Instance Database: %s (instance: %s)\n"+
						"Server=%s;Database=%s;User Id=%s;Password=<PASSWORD>;Encrypt=true;TrustServerCertificate=false;\n\n",
					dbName, SafeStringPtr(mi.Name),
					miEndpoint, dbName, SafeStringPtr(mi.Properties.AdministratorLogin),
				)

			}
		}
	}

	// ---------------- MySQL Servers ----------------
	mysqlServers := GetMySQLServers(ctx, session, subID, rgName)
	for _, srv := range mysqlServers {
		// Extract Tags from server
		tags := "N/A"
		if srv.Tags != nil && len(srv.Tags) > 0 {
			var tagPairs []string
			for k, v := range srv.Tags {
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

		mysqlClient, _ := armmysql.NewDatabasesClient(subID, cred, nil)
		dbPager := mysqlClient.NewListByServerPager(rgName, SafeStringPtr(srv.Name), nil)
		for dbPager.More() {
			page, err := dbPager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				privateIPs, publicIPs := GetDatabaseServerIPs(ctx, session, subID, SafeStringPtr(srv.ID))
				rbacStatus := IsEntraIDAuthEnabled(ctx, session, subID, rgName, SafeStringPtr(srv.Name), "MySQL", srv)

				sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, srv)

				// MySQL encryption is always on with platform-managed keys
				// Check if server uses customer-managed keys
				cmkStatus := "No"
				if srv.Properties != nil && srv.Properties.InfrastructureEncryption != nil {
					if *srv.Properties.InfrastructureEncryption == armmysql.InfrastructureEncryptionEnabled {
						cmkStatus = "Infrastructure"
					}
				}

				// Check Minimum TLS Version
				minTlsVersion := "N/A"
				if srv.Properties != nil && srv.Properties.MinimalTLSVersion != nil {
					minTlsVersion = string(*srv.Properties.MinimalTLSVersion)
				}

				// Extract SKU/Pricing Tier
				sku := "N/A"
				if srv.SKU != nil {
					if srv.SKU.Name != nil && srv.SKU.Tier != nil {
						sku = fmt.Sprintf("%s (%s)", *srv.SKU.Name, string(*srv.SKU.Tier))
					} else if srv.SKU.Name != nil {
						sku = *srv.SKU.Name
					} else if srv.SKU.Tier != nil {
						sku = string(*srv.SKU.Tier)
					}
				}

				body = append(body, []string{
					tenantName,                  // 0: Tenant Name
					tenantID,                    // 1: Tenant ID
					subID,                       // 2: Subscription ID
					subName,                     // 3: Subscription Name
					rgName,                      // 4: Resource Group
					SafeStringPtr(srv.Location), // 5: Region
					fmt.Sprintf("%s.mysql.database.azure.com", SafeStringPtr(srv.Name)), // 6: Database Server
					SafeStringPtr(db.Name),         // 7: Database Name
					"MySQL Single Server",          // 8: DB Type
					sku,                            // 9: SKU/Tier
					tags,                           // 10: Tags
					strings.Join(privateIPs, "\n"), // 11: Private IPs
					strings.Join(publicIPs, "\n"),  // 12: Public IPs
					SafeStringPtr(srv.Properties.AdministratorLogin), // 13: Admin Username
					rbacStatus,                              // 14: EntraID Centralized Auth
					DatabaseExposure(privateIPs, publicIPs), // 15: Public?
					"Always Enabled",                        // 16: Encryption/TDE (MySQL encryption is always on)
					cmkStatus,                               // 17: Customer Managed Key
					minTlsVersion,                           // 18: Min TLS Version
					"Not Supported",                         // 19: Dynamic Data Masking (not supported on MySQL)
					"Not Supported",                         // 20: ATP/Defender (not available for MySQL)
					"N/A",                                   // 21: Auditing Enabled (basic auditing via server parameters)
					"N/A",                                   // 22: Auditing Retention
					"Not Supported",                         // 23: Vulnerability Assessment (not available for MySQL)
					sysID,                                   // 24: System Assigned Identity ID
					strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
				})

				lootMap["database-commands"].Contents += fmt.Sprintf(
					"## MySQL Server: %s\n"+
						"# Set subscription context\n"+
						"az account set --subscription %s\n"+
						"\n"+
						"# Get server connection string\n"+
						"az mysql server show-connection-string --server %s\n"+
						"\n"+
						"## PowerShell equivalent\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"Get-AzMySqlServer -Name %s -ResourceGroupName %s\n\n",
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name), rgName)

				// ---------------- Fetch connection strings ----------------
				//mysql db show-connection-string --server myserver --name mydb
				connStr := getAzConnectionString(
					"mysql", "db", "show-connection-string",
					"--server", SafeStringPtr(srv.Name),
					"--name", SafeStringPtr(db.Name),
				)
				lootMap["database-strings"].Contents += fmt.Sprintf(
					"## SQL Database: %s (server: %s)\n%s\n\n",
					SafeStringPtr(db.Name), SafeStringPtr(srv.Name), connStr,
				)
			}
		}
	}

	// ---------------- MySQL Flexible Servers ----------------
	mysqlFlexServers := GetMySQLFlexibleServers(ctx, session, subID, rgName)
	for _, srv := range mysqlFlexServers {
		// Extract Tags from server
		tags := "N/A"
		if srv.Tags != nil && len(srv.Tags) > 0 {
			var tagPairs []string
			for k, v := range srv.Tags {
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

		// MySQL Flexible Server uses different database enumeration
		// List databases on this flexible server
		flexDbClient, _ := armmysqlflexibleservers.NewDatabasesClient(subID, cred, nil)
		flexDbPager := flexDbClient.NewListByServerPager(rgName, SafeStringPtr(srv.Name), nil)

		for flexDbPager.More() {
			page, err := flexDbPager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				dbName := SafeStringPtr(db.Name)
				// Skip system databases
				if dbName == "information_schema" || dbName == "mysql" || dbName == "performance_schema" || dbName == "sys" {
					continue
				}

				privateIPs, publicIPs := GetDatabaseServerIPs(ctx, session, subID, SafeStringPtr(srv.ID))

				// RBAC is N/A for flexible servers - uses Azure AD authentication differently
				rbacStatus := "N/A"
				sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, srv)

				// MySQL Flexible Server encryption is always on
				cmkStatus := "No"
				// Flexible servers support customer-managed keys through Azure Key Vault
				if srv.Properties != nil && srv.Properties.DataEncryption != nil && srv.Properties.DataEncryption.PrimaryKeyURI != nil {
					cmkStatus = "Yes"
				}

				// Check Minimum TLS Version for Flexible Server
				minTlsVersion := "N/A"
				// Flexible servers have different property structure

				// Extract SKU/Pricing Tier
				sku := "N/A"
				if srv.SKU != nil {
					if srv.SKU.Name != nil && srv.SKU.Tier != nil {
						sku = fmt.Sprintf("%s (%s)", *srv.SKU.Name, string(*srv.SKU.Tier))
					} else if srv.SKU.Name != nil {
						sku = *srv.SKU.Name
					} else if srv.SKU.Tier != nil {
						sku = string(*srv.SKU.Tier)
					}
				}

				// MySQL Flexible Server endpoint format
				endpoint := fmt.Sprintf("%s.mysql.database.azure.com", SafeStringPtr(srv.Name))

				body = append(body, []string{
					tenantName,                     // 0: Tenant Name
					tenantID,                       // 1: Tenant ID
					subID,                          // 2: Subscription ID
					subName,                        // 3: Subscription Name
					rgName,                         // 4: Resource Group
					SafeStringPtr(srv.Location),    // 5: Region
					endpoint,                       // 6: Database Server
					dbName,                         // 7: Database Name
					"MySQL Flexible Server",        // 8: DB Type
					sku,                            // 9: SKU/Tier
					tags,                           // 10: Tags
					strings.Join(privateIPs, "\n"), // 11: Private IPs
					strings.Join(publicIPs, "\n"),  // 12: Public IPs
					SafeStringPtr(srv.Properties.AdministratorLogin), // 13: Admin Username
					rbacStatus,                              // 14: EntraID Centralized Auth
					DatabaseExposure(privateIPs, publicIPs), // 15: Public?
					"Always Enabled",                        // 16: Encryption/TDE (MySQL encryption is always on)
					cmkStatus,                               // 17: Customer Managed Key
					minTlsVersion,                           // 18: Min TLS Version
					"Not Supported",                         // 19: Dynamic Data Masking (not supported on MySQL)
					"Not Supported",                         // 20: ATP/Defender (not available for MySQL)
					"N/A",                                   // 21: Auditing Enabled
					"N/A",                                   // 22: Auditing Retention
					"Not Supported",                         // 23: Vulnerability Assessment (not available for MySQL)
					sysID,                                   // 24: System Assigned Identity ID
					strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
				})

				lootMap["database-commands"].Contents += fmt.Sprintf(
					"## MySQL Flexible Server: %s, Database: %s\n"+
						"# Set subscription context\n"+
						"az account set --subscription %s\n"+
						"\n"+
						"# Get server connection string\n"+
						"# Endpoint: %s\n"+
						"# Connection string format:\n"+
						"# Server=%s;Database=%s;Uid=%s;Pwd=<PASSWORD>;\n"+
						"\n"+
						"## PowerShell equivalent\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"# Get flexible server details\n"+
						"Get-AzMySqlFlexibleServer -ResourceGroupName %s -Name %s\n"+
						"# Get database details\n"+
						"Get-AzMySqlFlexibleServerDatabase -ResourceGroupName %s -ServerName %s -Name %s\n\n",
					SafeStringPtr(srv.Name), dbName,
					subID,
					endpoint,
					endpoint, dbName, SafeStringPtr(srv.Properties.AdministratorLogin),
					subID,
					rgName, SafeStringPtr(srv.Name),
					rgName, SafeStringPtr(srv.Name), dbName)

				// ---------------- Fetch MySQL Flexible Server connection strings ----------------
				lootMap["database-strings"].Contents += fmt.Sprintf(
					"## MySQL Flexible Server Database: %s (server: %s)\n"+
						"Server=%s;Database=%s;Uid=%s;Pwd=<PASSWORD>;SslMode=Required;\n\n",
					dbName, SafeStringPtr(srv.Name),
					endpoint, dbName, SafeStringPtr(srv.Properties.AdministratorLogin),
				)
			}
		}
	}

	// ---------------- PostgreSQL Servers ----------------
	postgresServers := GetPostgresServers(ctx, session, subID, rgName)
	for _, srv := range postgresServers {
		// Extract Tags from server
		tags := "N/A"
		if srv.Tags != nil && len(srv.Tags) > 0 {
			var tagPairs []string
			for k, v := range srv.Tags {
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

		pgClient, _ := armpostgresql.NewDatabasesClient(subID, cred, nil)
		dbPager := pgClient.NewListByServerPager(rgName, SafeStringPtr(srv.Name), nil)

		for dbPager.More() {
			page, err := dbPager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				dbName := SafeStringPtr(db.Name)
				privateIPs, publicIPs := GetDatabaseServerIPs(ctx, session, subID, SafeStringPtr(srv.ID))
				rbacStatus := IsEntraIDAuthEnabled(ctx, session, subID, rgName, SafeStringPtr(srv.Name), "PostgreSQL", srv)

				sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, srv)

				// PostgreSQL encryption is always on with platform-managed keys
				// Check if server uses customer-managed keys or infrastructure encryption
				cmkStatus := "No"
				if srv.Properties != nil && srv.Properties.InfrastructureEncryption != nil {
					if *srv.Properties.InfrastructureEncryption == armpostgresql.InfrastructureEncryptionEnabled {
						cmkStatus = "Infrastructure"
					}
				}

				// Check Minimum TLS Version
				minTlsVersion := "N/A"
				if srv.Properties != nil && srv.Properties.MinimalTLSVersion != nil {
					minTlsVersion = string(*srv.Properties.MinimalTLSVersion)
				}

				// Extract SKU/Pricing Tier
				sku := "N/A"
				if srv.SKU != nil {
					if srv.SKU.Name != nil && srv.SKU.Tier != nil {
						sku = fmt.Sprintf("%s (%s)", *srv.SKU.Name, string(*srv.SKU.Tier))
					} else if srv.SKU.Name != nil {
						sku = *srv.SKU.Name
					} else if srv.SKU.Tier != nil {
						sku = string(*srv.SKU.Tier)
					}
				}

				body = append(body, []string{
					tenantName,                  // 0: Tenant Name
					tenantID,                    // 1: Tenant ID
					subID,                       // 2: Subscription ID
					subName,                     // 3: Subscription Name
					rgName,                      // 4: Resource Group
					SafeStringPtr(srv.Location), // 5: Region
					fmt.Sprintf("%s.postgres.database.windows.net", SafeStringPtr(srv.Name)), // 6: Database Server
					SafeStringPtr(db.Name),         // 7: Database Name
					"PostgreSQL Single Server",     // 8: DB Type
					sku,                            // 9: SKU/Tier
					tags,                           // 10: Tags
					strings.Join(privateIPs, "\n"), // 11: Private IPs
					strings.Join(publicIPs, "\n"),  // 12: Public IPs
					SafeStringPtr(srv.Properties.AdministratorLogin), // 13: Admin Username
					rbacStatus,                              // 14: EntraID Centralized Auth
					DatabaseExposure(privateIPs, publicIPs), // 15: Public?
					"Always Enabled",                        // 16: Encryption/TDE (PostgreSQL encryption is always on)
					cmkStatus,                               // 17: Customer Managed Key
					minTlsVersion,                           // 18: Min TLS Version
					"Not Supported",                         // 19: Dynamic Data Masking (not supported on PostgreSQL)
					"Not Supported",                         // 20: ATP/Defender (not available for PostgreSQL)
					"N/A",                                   // 21: Auditing Enabled
					"N/A",                                   // 22: Auditing Retention
					"Not Supported",                         // 23: Vulnerability Assessment (not available for PostgreSQL)
					sysID,                                   // 24: System Assigned Identity ID
					strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
				})

				lootMap["database-commands"].Contents += fmt.Sprintf(
					"## PostgreSQL Server: %s\n"+
						"# Set subscription context\n"+
						"az account set --subscription %s\n"+
						"\n"+
						"# Get server connection string\n"+
						"az postgres server show-connection-string --server %s\n"+
						"\n"+
						"## PowerShell equivalent\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"Get-AzPostgreSqlServer -Name %s -ResourceGroupName %s\n\n",
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name), rgName)

				// ---------------- Fetch connection strings ----------------
				//az postgres db show-connection-string --server myserver --name mydb
				connStr := getAzConnectionString(
					"postgres", "db", "show-connection-string",
					"--server", SafeStringPtr(srv.Name),
					"--name", dbName,
				)
				lootMap["database-strings"].Contents += fmt.Sprintf(
					"## SQL Database: %s (server: %s)\n%s\n\n",
					dbName, SafeStringPtr(srv.Name), connStr,
				)
			}
		}
	}

	// ---------------- PostgreSQL Flexible Servers ----------------
	postgresFlexServers := GetPostgreSQLFlexibleServers(ctx, session, subID, rgName)
	for _, srv := range postgresFlexServers {
		// Extract Tags from server
		tags := "N/A"
		if srv.Tags != nil && len(srv.Tags) > 0 {
			var tagPairs []string
			for k, v := range srv.Tags {
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

		pgFlexClient, _ := armpostgresqlflexibleservers.NewDatabasesClient(subID, cred, nil)
		dbPager := pgFlexClient.NewListByServerPager(rgName, SafeStringPtr(srv.Name), nil)

		for dbPager.More() {
			page, err := dbPager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				dbName := SafeStringPtr(db.Name)

				// Skip system databases
				if dbName == "azure_maintenance" || dbName == "azure_sys" || dbName == "postgres" {
					continue
				}

				privateIPs, publicIPs := GetDatabaseServerIPs(ctx, session, subID, SafeStringPtr(srv.ID))
				rbacStatus := IsEntraIDAuthEnabled(ctx, session, subID, rgName, SafeStringPtr(srv.Name), "PostgreSQL", srv)

				sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, srv)

				// PostgreSQL Flexible Server encryption is always on with platform-managed keys
				// Note: Customer-managed keys (CMK) are not currently supported via the SDK properties
				// for PostgreSQL Flexible Server in the same way as MySQL Flexible Server
				cmkStatus := "No"

				// Check Minimum TLS Version
				minTlsVersion := "N/A"
				if srv.Properties != nil && srv.Properties.Network != nil && srv.Properties.Network.PublicNetworkAccess != nil {
					// Flexible server uses different TLS version property
					minTlsVersion = "TLS 1.2" // Default for flexible servers
				}

				// Extract SKU/Pricing Tier
				sku := "N/A"
				if srv.SKU != nil {
					if srv.SKU.Name != nil && srv.SKU.Tier != nil {
						sku = fmt.Sprintf("%s (%s)", *srv.SKU.Name, string(*srv.SKU.Tier))
					} else if srv.SKU.Name != nil {
						sku = *srv.SKU.Name
					} else if srv.SKU.Tier != nil {
						sku = string(*srv.SKU.Tier)
					}
				}

				body = append(body, []string{
					tenantName,                  // 0: Tenant Name
					tenantID,                    // 1: Tenant ID
					subID,                       // 2: Subscription ID
					subName,                     // 3: Subscription Name
					rgName,                      // 4: Resource Group
					SafeStringPtr(srv.Location), // 5: Region
					fmt.Sprintf("%s.postgres.database.azure.com", SafeStringPtr(srv.Name)), // 6: Database Server
					SafeStringPtr(db.Name),         // 7: Database Name
					"PostgreSQL Flexible Server",   // 8: DB Type
					sku,                            // 9: SKU/Tier
					tags,                           // 10: Tags
					strings.Join(privateIPs, "\n"), // 11: Private IPs
					strings.Join(publicIPs, "\n"),  // 12: Public IPs
					SafeStringPtr(srv.Properties.AdministratorLogin), // 13: Admin Username
					rbacStatus,                              // 14: EntraID Centralized Auth
					DatabaseExposure(privateIPs, publicIPs), // 15: Public?
					"Always Enabled",                        // 16: Encryption/TDE (PostgreSQL encryption is always on)
					cmkStatus,                               // 17: Customer Managed Key
					minTlsVersion,                           // 18: Min TLS Version
					"Not Supported",                         // 19: Dynamic Data Masking (not supported on PostgreSQL)
					"Not Supported",                         // 20: ATP/Defender (not available for PostgreSQL)
					"N/A",                                   // 21: Auditing Enabled
					"N/A",                                   // 22: Auditing Retention
					"Not Supported",                         // 23: Vulnerability Assessment (not available for PostgreSQL)
					sysID,                                   // 24: System Assigned Identity ID
					strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
				})

				lootMap["database-commands"].Contents += fmt.Sprintf(
					"## PostgreSQL Flexible Server: %s\n"+
						"# Set subscription context\n"+
						"az account set --subscription %s\n"+
						"\n"+
						"# Get flexible server connection string\n"+
						"az postgres flexible-server show-connection-string --server %s\n"+
						"\n"+
						"## PowerShell equivalent\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"Get-AzPostgreSqlFlexibleServer -Name %s -ResourceGroupName %s\n\n",
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name), rgName)

				// ---------------- Fetch connection strings ----------------
				// az postgres flexible-server db show-connection-string --server myserver --database-name mydb
				connStr := getAzConnectionString(
					"postgres", "flexible-server", "db", "show-connection-string",
					"--server", SafeStringPtr(srv.Name),
					"--database-name", dbName,
				)
				lootMap["database-strings"].Contents += fmt.Sprintf(
					"## PostgreSQL Flexible Server Database: %s (server: %s)\n%s\n\n",
					dbName, SafeStringPtr(srv.Name), connStr,
				)
			}
		}
	}

	// ---------------- MariaDB Servers ----------------
	mariaServers := GetMariaDBServers(ctx, session, subID, rgName)
	for _, srv := range mariaServers {
		// Extract Tags from server
		tags := "N/A"
		if srv.Tags != nil && len(srv.Tags) > 0 {
			var tagPairs []string
			for k, v := range srv.Tags {
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

		mariaClient, _ := armmariadb.NewDatabasesClient(subID, cred, nil)
		dbPager := mariaClient.NewListByServerPager(rgName, SafeStringPtr(srv.Name), nil)

		for dbPager.More() {
			page, err := dbPager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				dbName := SafeStringPtr(db.Name)

				// Skip system databases
				if dbName == "information_schema" || dbName == "mysql" || dbName == "performance_schema" {
					continue
				}

				privateIPs, publicIPs := GetDatabaseServerIPs(ctx, session, subID, SafeStringPtr(srv.ID))
				rbacStatus := IsEntraIDAuthEnabled(ctx, session, subID, rgName, SafeStringPtr(srv.Name), "MariaDB", srv)

				sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, srv)

				// MariaDB encryption is always on with platform-managed keys
				// Check if server uses infrastructure encryption
				cmkStatus := "No"
				if srv.Properties != nil && srv.Properties.MinimalTLSVersion != nil {
					// MariaDB doesn't expose customer-managed key status in the same way
					// Infrastructure encryption would need to be checked separately
					cmkStatus = "No"
				}

				// Check Minimum TLS Version
				minTlsVersion := "N/A"
				if srv.Properties != nil && srv.Properties.MinimalTLSVersion != nil {
					minTlsVersion = string(*srv.Properties.MinimalTLSVersion)
				}

				// Extract SKU/Pricing Tier
				sku := "N/A"
				if srv.SKU != nil {
					if srv.SKU.Name != nil && srv.SKU.Tier != nil {
						sku = fmt.Sprintf("%s (%s)", *srv.SKU.Name, string(*srv.SKU.Tier))
					} else if srv.SKU.Name != nil {
						sku = *srv.SKU.Name
					} else if srv.SKU.Tier != nil {
						sku = string(*srv.SKU.Tier)
					}
				}

				body = append(body, []string{
					tenantName,                  // 0: Tenant Name
					tenantID,                    // 1: Tenant ID
					subID,                       // 2: Subscription ID
					subName,                     // 3: Subscription Name
					rgName,                      // 4: Resource Group
					SafeStringPtr(srv.Location), // 5: Region
					fmt.Sprintf("%s.mariadb.database.azure.com", SafeStringPtr(srv.Name)), // 6: Database Server
					SafeStringPtr(db.Name),         // 7: Database Name
					"MariaDB",                      // 8: DB Type
					sku,                            // 9: SKU/Tier
					tags,                           // 10: Tags
					strings.Join(privateIPs, "\n"), // 11: Private IPs
					strings.Join(publicIPs, "\n"),  // 12: Public IPs
					SafeStringPtr(srv.Properties.AdministratorLogin), // 13: Admin Username
					rbacStatus,                              // 14: EntraID Centralized Auth
					DatabaseExposure(privateIPs, publicIPs), // 15: Public?
					"Always Enabled",                        // 16: Encryption/TDE (MariaDB encryption is always on)
					cmkStatus,                               // 17: Customer Managed Key
					minTlsVersion,                           // 18: Min TLS Version
					"Not Supported",                         // 19: Dynamic Data Masking (not supported on MariaDB)
					"Not Supported",                         // 20: ATP/Defender (not available for MariaDB)
					"N/A",                                   // 21: Auditing Enabled
					"N/A",                                   // 22: Auditing Retention
					"Not Supported",                         // 23: Vulnerability Assessment (not available for MariaDB)
					sysID,                                   // 24: System Assigned Identity ID
					strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
				})

				lootMap["database-commands"].Contents += fmt.Sprintf(
					"## MariaDB Server: %s\n"+
						"# Set subscription context\n"+
						"az account set --subscription %s\n"+
						"\n"+
						"# Get server connection string\n"+
						"az mariadb server show-connection-string --server %s\n"+
						"\n"+
						"## PowerShell equivalent\n"+
						"Set-AzContext -SubscriptionId %s\n"+
						"Get-AzMariaDbServer -Name %s -ResourceGroupName %s\n\n",
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name),
					subID,
					SafeStringPtr(srv.Name), rgName)

				// ---------------- Fetch connection strings ----------------
				//az mariadb db show-connection-string --server myserver --name mydb
				connStr := getAzConnectionString(
					"mariadb", "db", "show-connection-string",
					"--server", SafeStringPtr(srv.Name),
					"--name", dbName,
				)
				lootMap["database-strings"].Contents += fmt.Sprintf(
					"## MariaDB Database: %s (server: %s)\n%s\n\n",
					dbName, SafeStringPtr(srv.Name), connStr,
				)
			}
		}
	}

	// ---------------- CosmosDB Accounts ----------------
	cosmosAccounts := GetCosmosAccounts(ctx, session, subID, rgName)
	for _, acct := range cosmosAccounts {
		var dnsName string
		var dbType string
		privateIPs, publicIPs := GetCosmosDBIPs(ctx, session, acct, subID)
		rbacStatus := IsEntraIDAuthEnabled(ctx, session, subID, rgName, SafeStringPtr(acct.Name), "CosmosDB", acct)
		sysID, userIDs, _, _ := GetManagedIdentities(ctx, session, subID, acct)

		// Extract Tags from CosmosDB account
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

		// CosmosDB encryption is always on
		// Check if using customer-managed keys
		cmkStatus := "No"
		if acct.Properties != nil && acct.Properties.KeyVaultKeyURI != nil && *acct.Properties.KeyVaultKeyURI != "" {
			cmkStatus = "Yes"
		}

		// CosmosDB doesn't expose MinTLS in the API response
		minTlsVersion := "N/A"

		// CosmosDB doesn't use traditional SKUs - uses capacity modes (Provisioned/Serverless)
		sku := "N/A"

		dbType = "CosmosDB"
		if acct.Kind != nil {
			kind := string(*acct.Kind) // DatabaseAccountKind → string
			accountName := ""
			if acct.Name != nil {
				accountName = *acct.Name
			}

			switch strings.ToLower(kind) {
			case "mongodb":
				dbType = "CosmosDB-Mongo"
				dnsName = fmt.Sprintf("%s.mongo.cosmos.azure.com", accountName)
			case "cassandra":
				dbType = "CosmosDB-Cassandra"
				dnsName = fmt.Sprintf("%s.cassandra.cosmos.azure.com", accountName)
			case "gremlin":
				dbType = "CosmosDB-Gremlin"
				dnsName = fmt.Sprintf("%s.gremlin.cosmos.azure.com", accountName)
			case "table":
				dbType = "CosmosDB-Table"
				dnsName = fmt.Sprintf("%s.table.cosmos.azure.com", accountName)
			default:
				dbType = "CosmosDB-SQL"
				dnsName = fmt.Sprintf("%s.documents.azure.com", accountName)
			}
		}

		body = append(body, []string{
			tenantName,                              // 0: Tenant Name
			tenantID,                                // 1: Tenant ID
			subID,                                   // 2: Subscription ID
			subName,                                 // 3: Subscription Name
			rgName,                                  // 4: Resource Group
			SafeStringPtr(acct.Location),            // 5: Region
			dnsName,                                 // 6: Database Server
			SafeStringPtr(acct.Name),                // 7: Database Name
			dbType,                                  // 8: DB Type
			sku,                                     // 9: SKU/Tier
			tags,                                    // 10: Tags
			strings.Join(privateIPs, "\n"),          // 11: Private IPs
			strings.Join(publicIPs, "\n"),           // 12: Public IPs
			"N/A",                                   // 13: Admin Username (not applicable for CosmosDB)
			rbacStatus,                              // 14: EntraID Centralized Auth
			DatabaseExposure(privateIPs, publicIPs), // 15: Public?
			"Always Enabled",                        // 16: Encryption/TDE (CosmosDB encryption is always on)
			cmkStatus,                               // 17: Customer Managed Key
			minTlsVersion,                           // 18: Min TLS Version
			"Not Supported",                         // 19: Dynamic Data Masking (not supported on CosmosDB)
			"Not Supported",                         // 20: ATP/Defender (not available for CosmosDB)
			"N/A",                                   // 21: Auditing Enabled (diagnostic logging available)
			"N/A",                                   // 22: Auditing Retention
			"Not Supported",                         // 23: Vulnerability Assessment (not available for CosmosDB)
			sysID,                                   // 24: System Assigned Identity ID
			strings.Join(userIDs, "\n"),             // 25: User Assigned Identity ID
		})

		lootMap["database-commands"].Contents += fmt.Sprintf(
			"## CosmosDB Account: %s (%s)\n"+
				"# Set subscription context\n"+
				"az account set --subscription %s\n"+
				"\n"+
				"# List connection keys\n"+
				"az cosmosdb keys list --name %s --resource-group %s\n"+
				"\n"+
				"## PowerShell equivalent\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzCosmosDBAccountKey -ResourceGroupName %s -Name %s\n\n",
			SafeStringPtr(acct.Name), dbType,
			subID,
			SafeStringPtr(acct.Name), rgName,
			subID,
			rgName, SafeStringPtr(acct.Name))

		// ---------------- Fetch connection strings ----------------
		//az cosmosdb keys list --name mycosmos --resource-group myrg
		connStr := getAzConnectionString(
			"cosmosdb", "keys", "list",
			"--name", SafeStringPtr(acct.Name),
			"--resource-group", rgName,
		)
		lootMap["database-strings"].Contents += fmt.Sprintf(
			"## SQL Database: %s (server: %s)\n%s\n\n",
			SafeStringPtr(acct.Name), rgName, connStr,
		)
	}

	return body
}

// ---------------- IP Detection ----------------

// GetDatabaseServerIPs returns private/public IPs for SQL/MySQL/Postgres servers.
func GetDatabaseServerIPs(ctx context.Context, session *SafeSession, subscriptionID, resourceID string) ([]string, []string) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return []string{"UNKNOWN"}, []string{"UNKNOWN"}
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return []string{"UNKNOWN"}, []string{"UNKNOWN"}
	}

	var privateIPs, publicIPs []string

	// ---------------- Private IPs ----------------
	peClient, err := armnetwork.NewPrivateEndpointsClient(subscriptionID, cred, nil)
	if err == nil {
		rgName := GetResourceGroupFromID(resourceID)
		pager := peClient.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, pe := range page.Value {
				if pe.Properties == nil {
					continue
				}
				for _, nic := range pe.Properties.NetworkInterfaces {
					if nic.Properties == nil {
						continue
					}
					for _, ipConfig := range nic.Properties.IPConfigurations {
						if ipConfig.Properties != nil && ipConfig.Properties.PrivateIPAddress != nil {
							privateIPs = append(privateIPs, SafeStringPtr(ipConfig.Properties.PrivateIPAddress))
						}
					}
				}
			}
		}
	}

	// ---------------- Public IPs ----------------
	fqdn := ExtractDBFQDN(resourceID)
	if fqdn != "" {
		ips, err := net.LookupIP(fqdn)
		if err != nil || len(ips) == 0 {
			publicIPs = append(publicIPs, "UNKNOWN")
		} else {
			for _, ip := range ips {
				publicIPs = append(publicIPs, ip.String())
			}
		}
	} else {
		publicIPs = append(publicIPs, "UNKNOWN")
	}

	// Ensure non-empty slices
	if len(privateIPs) == 0 {
		privateIPs = []string{"UNKNOWN"}
	}
	if len(publicIPs) == 0 {
		publicIPs = []string{"UNKNOWN"}
	}

	return privateIPs, publicIPs
}

func DatabaseExposure(privateIPs, publicIPs []string) string {
	if len(publicIPs) == 0 {
		return "PrivateOnly"
	}

	// Check if any public IP is wide open
	for _, ip := range publicIPs {
		if ip == "0.0.0.0" || ip == "0.0.0.0/0" {
			return "PublicOpen"
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil && parsedIP.IsGlobalUnicast() {
			// Could optionally refine: check against known private ranges
			return "PublicRestricted"
		}
	}

	return "PublicRestricted"
}

// ---------------- Azure SDK Enumerators ----------------

func GetSQLServers(ctx context.Context, session *SafeSession, subID, rgName string) []*armsql.Server {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}
	client, _ := armsql.NewServersClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armsql.Server
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		servers = append(servers, page.Value...)
	}
	return servers
}

func GetSQLManagedInstances(ctx context.Context, session *SafeSession, subID, rgName string) []*armsql.ManagedInstance {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}
	client, _ := armsql.NewManagedInstancesClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var instances []*armsql.ManagedInstance
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		instances = append(instances, page.Value...)
	}
	return instances
}

func GetMySQLServers(ctx context.Context, session *SafeSession, subID, rgName string) []*armmysql.Server {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}
	client, _ := armmysql.NewServersClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armmysql.Server
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		servers = append(servers, page.Value...)
	}
	return servers
}

func GetMySQLFlexibleServers(ctx context.Context, session *SafeSession, subID, rgName string) []*armmysqlflexibleservers.Server {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}
	client, _ := armmysqlflexibleservers.NewServersClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armmysqlflexibleservers.Server
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		servers = append(servers, page.Value...)
	}
	return servers
}

func GetPostgreSQLFlexibleServers(ctx context.Context, session *SafeSession, subID, rgName string) []*armpostgresqlflexibleservers.Server {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}
	client, _ := armpostgresqlflexibleservers.NewServersClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armpostgresqlflexibleservers.Server
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		servers = append(servers, page.Value...)
	}
	return servers
}

func GetPostgresServers(ctx context.Context, session *SafeSession, subID, rgName string) []*armpostgresql.Server {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}
	client, _ := armpostgresql.NewServersClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armpostgresql.Server
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		servers = append(servers, page.Value...)
	}
	return servers
}

func GetCosmosAccounts(ctx context.Context, session *SafeSession, subID, rgName string) []*armcosmos.DatabaseAccountGetResults {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}

	client, _ := armcosmos.NewDatabaseAccountsClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var accounts []*armcosmos.DatabaseAccountGetResults
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		accounts = append(accounts, page.Value...)
	}
	return accounts
}

func GetMariaDBServers(ctx context.Context, session *SafeSession, subID, rgName string) []*armmariadb.Server {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return nil
	}
	client, _ := armmariadb.NewServersClient(subID, cred, nil)
	pager := client.NewListByResourceGroupPager(rgName, nil)
	var servers []*armmariadb.Server
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}
		servers = append(servers, page.Value...)
	}
	return servers
}

// ---------------- Resource Group & Subscription Helpers ----------------

func ExtractDBFQDN(resourceID string) string {
	// SQL/MySQL/Postgres servers usually follow: <server>.database.windows.net
	name := strings.Split(resourceID, "/")
	if len(name) > 0 {
		return name[len(name)-1] + ".database.windows.net"
	}
	return ""
}

// GetCosmosDBIPs returns private/public IPs for CosmosDB accounts.
func GetCosmosDBIPs(ctx context.Context, session *SafeSession, acct *armcosmos.DatabaseAccountGetResults, subscriptionID string) ([]string, []string) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return []string{"UNKNOWN"}, []string{"UNKNOWN"}
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return []string{"UNKNOWN"}, []string{"UNKNOWN"}
	}

	var privateIPs, publicIPs []string

	// ---------------- Private IPs (via Private Endpoints) ----------------
	if acct.ID != nil {
		peClient, err := armnetwork.NewPrivateEndpointsClient(subscriptionID, cred, nil)
		if err == nil {
			rgName := GetResourceGroupFromID(*acct.ID)
			pager := peClient.NewListPager(rgName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					continue
				}
				for _, pe := range page.Value {
					if pe.Properties == nil || pe.Properties.PrivateLinkServiceConnections == nil {
						continue
					}
					for _, conn := range pe.Properties.PrivateLinkServiceConnections {
						if conn.Properties == nil || conn.Properties.PrivateLinkServiceConnectionState == nil || conn.Properties.PrivateLinkServiceID == nil {
							continue
						}
						if strings.Contains(strings.ToLower(*conn.Properties.PrivateLinkServiceConnectionState.Status), "approved") &&
							strings.Contains(strings.ToLower(*conn.Properties.PrivateLinkServiceID), strings.ToLower(*acct.ID)) {

							for _, nic := range pe.Properties.NetworkInterfaces {
								if nic.Properties == nil || nic.Properties.IPConfigurations == nil {
									continue
								}
								for _, ipConfig := range nic.Properties.IPConfigurations {
									if ipConfig.Properties != nil && ipConfig.Properties.PrivateIPAddress != nil {
										// SafeStringPtr handles nil pointer -> "UNKNOWN"
										privateIPs = append(privateIPs, SafeStringPtr(ipConfig.Properties.PrivateIPAddress))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// ---------------- Public IPs ----------------
	// Try to extract a host from DocumentEndpoint (strip scheme, port, path).
	var host string
	if acct.Properties != nil && acct.Properties.DocumentEndpoint != nil && *acct.Properties.DocumentEndpoint != "" {
		dns := *acct.Properties.DocumentEndpoint
		// Remove scheme if present
		if idx := strings.Index(dns, "://"); idx != -1 {
			dns = dns[idx+3:]
		}
		// Strip path
		if idx := strings.Index(dns, "/"); idx != -1 {
			dns = dns[:idx]
		}
		// Strip port
		if idx := strings.Index(dns, ":"); idx != -1 {
			dns = dns[:idx]
		}
		host = dns
	}

	// If we still don't have a host, try account name + default documents domain
	if host == "" && acct.Name != nil && *acct.Name != "" {
		host = fmt.Sprintf("%s.documents.azure.com", *acct.Name)
	}

	if host != "" {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			publicIPs = append(publicIPs, "UNKNOWN")
		} else {
			for _, ip := range ips {
				if ip.IsGlobalUnicast() {
					publicIPs = append(publicIPs, ip.String())
				}
			}
		}
	} else {
		publicIPs = append(publicIPs, "UNKNOWN")
	}

	// Ensure we always return at least "UNKNOWN" for each slice
	if len(privateIPs) == 0 {
		privateIPs = []string{"UNKNOWN"}
	}
	if len(publicIPs) == 0 {
		publicIPs = []string{"UNKNOWN"}
	}

	return privateIPs, publicIPs
}

func CheckDynamicDataMasking(ctx context.Context, session *SafeSession, subID, rgName, serverName, dbName string) string {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil || token == "" {
		return "Unknown"
	}

	endpoint := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/databases/%s/dataMaskingPolicies/Default?api-version=2021-11-01-preview",
		subID, rgName, serverName, dbName,
	)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	body, err := HTTPRequestWithRetry(ctx, "GET", endpoint, token, nil, config)
	if err != nil {
		return "Error"
	}

	var ddmResp struct {
		Properties struct {
			DataMaskingState *string `json:"dataMaskingState"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(body, &ddmResp); err != nil {
		return "Error"
	}

	if ddmResp.Properties.DataMaskingState != nil {
		return *ddmResp.Properties.DataMaskingState // e.g. "Enabled" or "Disabled"
	}

	return "Unknown"
}

// CallAzureREST executes a raw ARM request and returns the response body
func CallAzureREST(ctx context.Context, session *SafeSession, url string) ([]byte, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, err
	}

	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	return HTTPRequestWithRetry(ctx, "GET", url, token, nil, config)
}

func IsEntraIDAuthEnabled(ctx context.Context, session *SafeSession, subscriptionID, resourceGroup, dbName, dbType string, srv interface{}) string {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return "Unknown"
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return "Unknown"
	}

	switch dbType {
	case "SQL":
		if s, ok := srv.(*armsql.Server); ok && s.Properties != nil {
			// SDK might not expose AzureADAdministrator → fallback to REST
			url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/administrators?api-version=2021-02-01-preview",
				subscriptionID, resourceGroup, dbName)
			body, err := CallAzureREST(ctx, session, url)
			if err == nil {
				var resp struct {
					Value []map[string]interface{} `json:"value"`
				}
				if err := json.Unmarshal(body, &resp); err == nil && len(resp.Value) > 0 {
					return "Enabled"
				}
			}
		}
	case "MySQL":
		if s, ok := srv.(*armmysql.Server); ok && s.Properties != nil {
			url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforMySQL/servers/%s/administrators?api-version=2020-01-01",
				subscriptionID, resourceGroup, dbName)
			body, err := CallAzureREST(ctx, session, url)
			if err == nil {
				var resp struct {
					Value []map[string]interface{} `json:"value"`
				}
				if err := json.Unmarshal(body, &resp); err == nil && len(resp.Value) > 0 {
					return "Enabled"
				}
			}
		}
	case "PostgreSQL":
		if s, ok := srv.(*armpostgresql.Server); ok && s.Properties != nil {
			url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/servers/%s/administrators?api-version=2020-01-01",
				subscriptionID, resourceGroup, dbName)
			body, err := CallAzureREST(ctx, session, url)
			if err == nil {
				var resp struct {
					Value []map[string]interface{} `json:"value"`
				}
				if err := json.Unmarshal(body, &resp); err == nil && len(resp.Value) > 0 {
					return "Enabled"
				}
			}
		}
	case "CosmosDB":
		if c, ok := srv.(*armcosmos.DatabaseAccountGetResults); ok && c.Properties != nil {
			url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DocumentDB/databaseAccounts/%s?api-version=2021-04-15",
				subscriptionID, resourceGroup, dbName)
			body, err := CallAzureREST(ctx, session, url)
			if err == nil {
				var resp struct {
					Properties struct {
						EnableRoleBasedAccessControl *bool `json:"enableRoleBasedAccessControl"`
					} `json:"properties"`
				}
				if err := json.Unmarshal(body, &resp); err == nil && resp.Properties.EnableRoleBasedAccessControl != nil && *resp.Properties.EnableRoleBasedAccessControl {
					return "Enabled"
				}
			}
		}
	}
	return "Disabled"
}

// GetManagedIdentities returns the system-assigned and user-assigned identities for a database resource.
// For MySQL/PostgreSQL, user-assigned identities are fetched via optional ARM REST call.
func GetManagedIdentities(ctx context.Context, session *SafeSession, subscriptionID string, resource interface{}) (systemAssigned string, userAssigned []string, systemRoles []string, userRoles []string) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return
	}

	cred := &StaticTokenCredential{Token: token}

	if cred == nil {
		return
	}

	switch r := resource.(type) {
	case *armsql.Server:
		if r.Identity != nil {
			if r.Identity.Type != nil && strings.Contains(string(*r.Identity.Type), "SystemAssigned") && r.Identity.PrincipalID != nil {
				systemAssigned = *r.Identity.PrincipalID

				// Fetch role assignments for system-assigned identity
				roles, err := GetRoleAssignmentsForPrincipal(ctx, session, systemAssigned, subscriptionID)
				if err == nil {
					systemRoles = roles
				}
			}
			if r.Identity.UserAssignedIdentities != nil {
				for id, uaData := range r.Identity.UserAssignedIdentities {
					userAssigned = append(userAssigned, id)

					// Fetch role assignments if principal ID available
					if uaData.PrincipalID != nil {
						principalID := *uaData.PrincipalID
						roles, err := GetRoleAssignmentsForPrincipal(ctx, session, principalID, subscriptionID)
						if err == nil {
							userRoles = append(userRoles, roles...)
						}
					}
				}
			}
		}

	case *armmysql.Server, *armpostgresql.Server:
		var resourceID string
		if s, ok := r.(*armmysql.Server); ok && s.ID != nil {
			resourceID = *s.ID
			if s.Identity != nil && s.Identity.PrincipalID != nil {
				systemAssigned = *s.Identity.PrincipalID

				// Fetch role assignments for system-assigned identity
				roles, err := GetRoleAssignmentsForPrincipal(ctx, session, systemAssigned, subscriptionID)
				if err == nil {
					systemRoles = roles
				}
			}
		} else if s, ok := r.(*armpostgresql.Server); ok && s.ID != nil {
			resourceID = *s.ID
			if s.Identity != nil && s.Identity.PrincipalID != nil {
				systemAssigned = *s.Identity.PrincipalID

				// Fetch role assignments for system-assigned identity
				roles, err := GetRoleAssignmentsForPrincipal(ctx, session, systemAssigned, subscriptionID)
				if err == nil {
					systemRoles = roles
				}
			}
		}

		// ---------------- Optional REST call for user-assigned identities ----------------
		if resourceID != "" {
			url := fmt.Sprintf("https://management.azure.com%s?api-version=2022-12-01", resourceID)
			body, err := CallAzureREST(ctx, session, url)
			if err == nil {
				var resp struct {
					Identity struct {
						UserAssignedIdentities map[string]struct {
							PrincipalID string `json:"principalId"`
							ClientID    string `json:"clientId"`
						} `json:"userAssignedIdentities"`
					} `json:"identity"`
				}
				if err := json.Unmarshal(body, &resp); err == nil && resp.Identity.UserAssignedIdentities != nil {
					for id, uaData := range resp.Identity.UserAssignedIdentities {
						userAssigned = append(userAssigned, id)

						// Fetch role assignments if principal ID available
						if uaData.PrincipalID != "" {
							roles, err := GetRoleAssignmentsForPrincipal(ctx, session, uaData.PrincipalID, subscriptionID)
							if err == nil {
								userRoles = append(userRoles, roles...)
							}
						}
					}
				}
			}
		}

	case *armcosmos.DatabaseAccountGetResults:
		if r.Identity != nil {
			if r.Identity.Type != nil && strings.Contains(string(*r.Identity.Type), "SystemAssigned") && r.Identity.PrincipalID != nil {
				systemAssigned = *r.Identity.PrincipalID

				// Fetch role assignments for system-assigned identity
				roles, err := GetRoleAssignmentsForPrincipal(ctx, session, systemAssigned, subscriptionID)
				if err == nil {
					systemRoles = roles
				}
			}
			if r.Identity.UserAssignedIdentities != nil {
				for id, uaData := range r.Identity.UserAssignedIdentities {
					userAssigned = append(userAssigned, id)

					// Fetch role assignments if principal ID available
					if uaData.PrincipalID != nil {
						principalID := *uaData.PrincipalID
						roles, err := GetRoleAssignmentsForPrincipal(ctx, session, principalID, subscriptionID)
						if err == nil {
							userRoles = append(userRoles, roles...)
						}
					}
				}
			}
		}
	}

	return
}

// CheckTDEStatus checks if Transparent Data Encryption is enabled for a SQL database
func CheckTDEStatus(ctx context.Context, cred *StaticTokenCredential, subID, rgName, serverName, dbName string) string {
	// Create TDE client
	tdeClient, err := armsql.NewTransparentDataEncryptionsClient(subID, cred, nil)
	if err != nil {
		return "N/A"
	}

	// Get TDE configuration for the database
	tde, err := tdeClient.Get(ctx, rgName, serverName, dbName, armsql.TransparentDataEncryptionNameCurrent, nil)
	if err != nil {
		// If error, TDE might not be configured or accessible
		return "Unknown"
	}

	// Check TDE state
	if tde.Properties != nil && tde.Properties.State != nil {
		if *tde.Properties.State == armsql.TransparentDataEncryptionStateEnabled {
			return "Enabled"
		} else if *tde.Properties.State == armsql.TransparentDataEncryptionStateDisabled {
			return "Disabled"
		}
	}

	return "N/A"
}

// CheckATPDefenderStatus checks if Microsoft Defender for SQL (formerly ATP) is enabled for a SQL database/server
func CheckATPDefenderStatus(ctx context.Context, session *SafeSession, subID, rgName, serverName string) string {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil || token == "" {
		return "Unknown"
	}

	// Check server-level Defender for SQL (new Security API)
	endpoint := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/securityAlertPolicies/Default?api-version=2021-11-01",
		subID, rgName, serverName,
	)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 3
	config.InitialDelay = 1 * time.Second
	config.MaxDelay = 1 * time.Minute

	body, err := HTTPRequestWithRetry(ctx, "GET", endpoint, token, nil, config)
	if err != nil {
		return "Unknown"
	}

	var securityResp struct {
		Properties struct {
			State *string `json:"state"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(body, &securityResp); err != nil {
		return "Error"
	}

	if securityResp.Properties.State != nil {
		state := strings.ToLower(*securityResp.Properties.State)
		if state == "enabled" {
			return "Enabled"
		} else if state == "disabled" {
			return "Disabled"
		}
	}

	return "Disabled"
}

// CheckAuditingStatus checks if auditing is enabled for a SQL database/server and returns status and retention days
func CheckAuditingStatus(ctx context.Context, session *SafeSession, subID, rgName, serverName string) (string, string) {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil || token == "" {
		return "Unknown", "N/A"
	}

	// Check server-level auditing settings
	endpoint := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/auditingSettings/default?api-version=2021-11-01",
		subID, rgName, serverName,
	)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 3
	config.InitialDelay = 1 * time.Second
	config.MaxDelay = 1 * time.Minute

	body, err := HTTPRequestWithRetry(ctx, "GET", endpoint, token, nil, config)
	if err != nil {
		return "Unknown", "N/A"
	}

	var auditResp struct {
		Properties struct {
			State                       *string `json:"state"`
			RetentionDays               *int32  `json:"retentionDays"`
			IsAzureMonitorTargetEnabled *bool   `json:"isAzureMonitorTargetEnabled"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(body, &auditResp); err != nil {
		return "Error", "N/A"
	}

	status := "Disabled"
	retention := "N/A"

	if auditResp.Properties.State != nil {
		state := strings.ToLower(*auditResp.Properties.State)
		if state == "enabled" {
			status = "Enabled"

			// Get retention days if available
			if auditResp.Properties.RetentionDays != nil {
				retentionDays := *auditResp.Properties.RetentionDays
				if retentionDays == 0 {
					retention = "Unlimited"
				} else {
					retention = fmt.Sprintf("%d days", retentionDays)
				}
			}

			// Add indicator if Azure Monitor integration is enabled
			if auditResp.Properties.IsAzureMonitorTargetEnabled != nil && *auditResp.Properties.IsAzureMonitorTargetEnabled {
				status = "Enabled (Azure Monitor)"
			}
		}
	}

	return status, retention
}

// CheckVulnerabilityAssessment checks if Vulnerability Assessment is configured for a SQL server
func CheckVulnerabilityAssessment(ctx context.Context, session *SafeSession, subID, rgName, serverName string) string {
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil || token == "" {
		return "Unknown"
	}

	// Check server-level Vulnerability Assessment settings
	endpoint := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/vulnerabilityAssessments/default?api-version=2021-11-01",
		subID, rgName, serverName,
	)

	config := DefaultRateLimitConfig()
	config.MaxRetries = 3
	config.InitialDelay = 1 * time.Second
	config.MaxDelay = 1 * time.Minute

	body, err := HTTPRequestWithRetry(ctx, "GET", endpoint, token, nil, config)
	if err != nil {
		// 404 means not configured
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "NotFound") {
			return "Not Configured"
		}
		return "Unknown"
	}

	var vaResp struct {
		Properties struct {
			StorageContainerPath *string `json:"storageContainerPath"`
			RecurringScans       *struct {
				IsEnabled *bool `json:"isEnabled"`
			} `json:"recurringScans"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(body, &vaResp); err != nil {
		return "Error"
	}

	// If storage container is configured, VA is enabled
	if vaResp.Properties.StorageContainerPath != nil && *vaResp.Properties.StorageContainerPath != "" {
		// Check if recurring scans are enabled
		if vaResp.Properties.RecurringScans != nil && vaResp.Properties.RecurringScans.IsEnabled != nil {
			if *vaResp.Properties.RecurringScans.IsEnabled {
				return "Enabled (Recurring)"
			}
		}
		return "Enabled"
	}

	return "Not Configured"
}

// helper to run az CLI command and return output
func getAzConnectionString(cmdArgs ...string) string {
	cmd := exec.Command("az", cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Sprintf("ERROR running az command: %v\nOutput: %s", err, out.String())
	}
	return out.String()
}
