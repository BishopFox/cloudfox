package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/gcp/shared"

	FunctionsService "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPFunctionsCommand = &cobra.Command{
	Use:     globals.GCP_FUNCTIONS_MODULE_NAME,
	Aliases: []string{"function", "gcf", "cloud-functions"},
	Short:   "Enumerate GCP Cloud Functions with security analysis",
	Long: `Enumerate GCP Cloud Functions across projects with security-relevant details.

Features:
- Lists all Cloud Functions (Gen 2) accessible to the authenticated user
- Shows security configuration (ingress settings, VPC connector, service account)
- Identifies publicly invokable functions (allUsers/allAuthenticatedUsers)
- Shows runtime, trigger type, and trigger configuration
- Counts environment variables and secret references
- Generates gcloud commands for further enumeration and exploitation

Security Columns:
- Ingress: ALL_TRAFFIC (public), INTERNAL_ONLY, or INTERNAL_AND_GCLB
- Public: Whether allUsers or allAuthenticatedUsers can invoke the function
- ServiceAccount: The identity the function runs as (privilege level)
- VPCConnector: Network connectivity to VPC resources
- Secrets: Count of secret environment variables and volumes

Resource IAM Columns:
- IAM Binding Role: The IAM role granted ON this function (e.g., roles/cloudfunctions.invoker)
- IAM Binding Principal: The principal (user/SA/group) who has that role on this function

Attack Surface:
- Public HTTP functions may be directly exploitable
- Functions with default service account may have excessive permissions
- Functions with VPC connectors can access internal resources
- Event triggers reveal integration points (Pub/Sub, Storage, etc.)

TIP: Run foxmapper first to populate the Attack Paths column with privesc/exfil/lateral movement analysis.`,
	Run: runGCPFunctionsCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type FunctionsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectFunctions map[string][]FunctionsService.FunctionInfo // projectID -> functions
	LootMap          map[string]map[string]*internal.LootFile   // projectID -> loot files
	FoxMapperCache   *gcpinternal.FoxMapperCache                // FoxMapper graph data (preferred)
	mu               sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type FunctionsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FunctionsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FunctionsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPFunctionsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_FUNCTIONS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &FunctionsModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectFunctions: make(map[string][]FunctionsService.FunctionInfo),
		LootMap:          make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *FunctionsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Try to get FoxMapper cache (preferred - graph-based analysis)
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_FUNCTIONS_MODULE_NAME)
	}

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_FUNCTIONS_MODULE_NAME, m.processProject)

	// Get all functions for stats
	allFunctions := m.getAllFunctions()
	if len(allFunctions) == 0 {
		logger.InfoM("No Cloud Functions found", globals.GCP_FUNCTIONS_MODULE_NAME)
		return
	}

	// Count public functions
	publicCount := 0
	for _, fn := range allFunctions {
		if fn.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d function(s), %d PUBLIC", len(allFunctions), publicCount), globals.GCP_FUNCTIONS_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d function(s)", len(allFunctions)), globals.GCP_FUNCTIONS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// getAllFunctions returns all functions from all projects (for statistics)
func (m *FunctionsModule) getAllFunctions() []FunctionsService.FunctionInfo {
	var all []FunctionsService.FunctionInfo
	for _, functions := range m.ProjectFunctions {
		all = append(all, functions...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *FunctionsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud Functions in project: %s", projectID), globals.GCP_FUNCTIONS_MODULE_NAME)
	}

	fs := FunctionsService.New()
	functions, err := fs.Functions(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FUNCTIONS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate functions in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectFunctions[projectID] = functions

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["functions-commands"] = &internal.LootFile{
			Name:     "functions-commands",
			Contents: "# GCP Cloud Functions Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["functions-secrets"] = &internal.LootFile{
			Name:     "functions-secrets",
			Contents: "# Cloud Functions Secret References\n# Generated by CloudFox\n# Secrets used by functions (names only)\n\n",
		}
	}

	for _, fn := range functions {
		m.addFunctionToLoot(projectID, fn)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d function(s) in project %s", len(functions), projectID), globals.GCP_FUNCTIONS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *FunctionsModule) addFunctionToLoot(projectID string, fn FunctionsService.FunctionInfo) {
	commandsLoot := m.LootMap[projectID]["functions-commands"]
	secretsLoot := m.LootMap[projectID]["functions-secrets"]

	if commandsLoot == nil {
		return
	}

	// All commands for this function
	commandsLoot.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# FUNCTION: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Region: %s\n"+
			"# Runtime: %s, Trigger: %s\n"+
			"# Service Account: %s\n"+
			"# Public: %v, Ingress: %s\n",
		fn.Name,
		fn.ProjectID, fn.Region,
		fn.Runtime, fn.TriggerType,
		fn.ServiceAccount,
		fn.IsPublic, fn.IngressSettings,
	)

	if fn.TriggerURL != "" {
		commandsLoot.Contents += fmt.Sprintf("# URL: %s\n", fn.TriggerURL)
	}

	if fn.SourceLocation != "" {
		commandsLoot.Contents += fmt.Sprintf("# Source: %s (%s)\n", fn.SourceLocation, fn.SourceType)
	}

	commandsLoot.Contents += fmt.Sprintf(
		"\n# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe function:\n"+
			"gcloud functions describe %s --region=%s --project=%s --gen2\n"+
			"# Get IAM policy:\n"+
			"gcloud functions get-iam-policy %s --region=%s --project=%s --gen2\n"+
			"# Read logs:\n"+
			"gcloud functions logs read %s --region=%s --project=%s --gen2 --limit=50\n",
		fn.Name, fn.Region, fn.ProjectID,
		fn.Name, fn.Region, fn.ProjectID,
		fn.Name, fn.Region, fn.ProjectID,
	)

	// HTTP invocation commands
	commandsLoot.Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
	if fn.TriggerType == "HTTP" && fn.TriggerURL != "" {
		commandsLoot.Contents += fmt.Sprintf(
			"# Invoke (GET):\n"+
				"curl -s '%s'\n"+
				"# Invoke (POST with auth):\n"+
				"curl -s -X POST '%s' \\\n"+
				"  -H 'Authorization: Bearer $(gcloud auth print-identity-token)' \\\n"+
				"  -H 'Content-Type: application/json' \\\n"+
				"  -d '{\"test\": \"data\"}'\n",
			fn.TriggerURL,
			fn.TriggerURL,
		)
	}

	// Source download command
	if fn.SourceType == "GCS" && fn.SourceLocation != "" {
		commandsLoot.Contents += fmt.Sprintf(
			"# Download source:\n"+
				"gsutil cp %s ./function-source-%s.zip\n",
			fn.SourceLocation, fn.Name,
		)
	}

	commandsLoot.Contents += "\n"

	// Secret references
	if (len(fn.SecretEnvVarNames) > 0 || len(fn.SecretVolumeNames) > 0) && secretsLoot != nil {
		secretsLoot.Contents += fmt.Sprintf(
			"## Function: %s (Project: %s)\n",
			fn.Name, fn.ProjectID,
		)
		if len(fn.SecretEnvVarNames) > 0 {
			secretsLoot.Contents += "## Secret Environment Variables:\n"
			for _, secretName := range fn.SecretEnvVarNames {
				secretsLoot.Contents += fmt.Sprintf("##   - %s\n", secretName)
			}
		}
		if len(fn.SecretVolumeNames) > 0 {
			secretsLoot.Contents += "## Secret Volumes:\n"
			for _, volName := range fn.SecretVolumeNames {
				secretsLoot.Contents += fmt.Sprintf("##   - %s\n", volName)
			}
		}
		secretsLoot.Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *FunctionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *FunctionsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, functions := range m.ProjectFunctions {
		tables := m.buildTablesForProject(projectID, functions)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !isEmptyLootFile(loot.Contents) {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = FunctionsOutput{Table: tables, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_FUNCTIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *FunctionsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allFunctions := m.getAllFunctions()
	tables := m.buildTablesForProject("", allFunctions)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !isEmptyLootFile(loot.Contents) {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := FunctionsOutput{
		Table: tables,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_FUNCTIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// isEmptyLootFile checks if a loot file contains only the header
func isEmptyLootFile(contents string) bool {
	return strings.HasSuffix(contents, "# WARNING: Only use with proper authorization\n\n") ||
		strings.HasSuffix(contents, "# Secrets used by functions (names only)\n\n") ||
		strings.HasSuffix(contents, "# Generated by CloudFox\n\n")
}

// buildTablesForProject builds all tables for a given project's functions
func (m *FunctionsModule) buildTablesForProject(projectID string, functions []FunctionsService.FunctionInfo) []internal.TableFile {
	tableFiles := []internal.TableFile{}

	// Main functions table
	body := m.functionsToTableBody(functions)
	if len(body) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FUNCTIONS_MODULE_NAME,
			Header: m.getTableHeader(),
			Body:   body,
		})
	}

	// Secrets table (env vars and secret refs - matching Cloud Run format)
	secretsHeader := []string{
		"Project", "Name", "Region", "Env Var", "Value/Type", "Source", "Sensitive",
	}

	var secretsBody [][]string
	for _, fn := range functions {
		// Add environment variables from EnvVars (has actual values)
		for _, env := range fn.EnvVars {
			sensitive := isFunctionSensitiveEnvVar(env.Name)
			if env.Source == "direct" {
				secretsBody = append(secretsBody, []string{
					m.GetProjectName(fn.ProjectID),
					fn.Name,
					fn.Region,
					env.Name,
					env.Value,
					"EnvVar",
					sensitive,
				})
			} else {
				// Secret Manager reference
				secretsBody = append(secretsBody, []string{
					m.GetProjectName(fn.ProjectID),
					fn.Name,
					fn.Region,
					env.Name,
					fmt.Sprintf("%s:%s", env.SecretName, env.SecretVersion),
					"SecretManager",
					"Yes",
				})
			}
		}

		// Add secret volumes
		for _, volName := range fn.SecretVolumeNames {
			secretsBody = append(secretsBody, []string{
				m.GetProjectName(fn.ProjectID),
				fn.Name,
				fn.Region,
				volName + " (volume)",
				volName,
				"SecretManager",
				"Yes",
			})
		}
	}

	if len(secretsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FUNCTIONS_MODULE_NAME + "-secrets",
			Header: secretsHeader,
			Body:   secretsBody,
		})
	}

	return tableFiles
}

// isFunctionSensitiveEnvVar checks if an environment variable name indicates sensitive data
func isFunctionSensitiveEnvVar(envName string) string {
	envNameUpper := strings.ToUpper(envName)
	sensitivePatterns := []string{
		"PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY", "API-KEY",
		"TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN", "BEARER", "CREDENTIAL",
		"PRIVATE_KEY", "PRIVATEKEY", "CONNECTION_STRING", "CONN_STR",
		"DATABASE_URL", "DB_PASSWORD", "DB_PASS", "MYSQL_PASSWORD",
		"POSTGRES_PASSWORD", "REDIS_PASSWORD", "MONGODB_URI",
		"AWS_ACCESS_KEY", "AWS_SECRET", "AZURE_KEY", "GCP_KEY",
		"ENCRYPTION_KEY", "SIGNING_KEY", "JWT_SECRET", "SESSION_SECRET",
		"OAUTH", "CLIENT_SECRET",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(envNameUpper, pattern) {
			return "Yes"
		}
	}
	return "No"
}

// getTableHeader returns the functions table header
func (m *FunctionsModule) getTableHeader() []string {
	return []string{
		"Project",
		"Name",
		"Region",
		"Runtime",
		"State",
		"Trigger",
		"URL",
		"Ingress",
		"Public",
		"Service Account",
		"SA Attack Paths",
		"Default SA",
		"VPC Access",
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

// functionsToTableBody converts functions to table body rows
func (m *FunctionsModule) functionsToTableBody(functions []FunctionsService.FunctionInfo) [][]string {
	var body [][]string
	for _, fn := range functions {
		// Format trigger info
		triggerInfo := fn.TriggerType
		if fn.TriggerEventType != "" {
			triggerInfo = fmt.Sprintf("%s (%s)", fn.TriggerType, extractFunctionName(fn.TriggerEventType))
		}

		// Format URL
		url := "-"
		if fn.TriggerURL != "" {
			url = fn.TriggerURL
		}

		// Format state
		state := fn.State
		if state == "" {
			state = "-"
		}

		// Format VPC access (renamed from VPC Connector for consistency with Cloud Run)
		vpcAccess := "-"
		if fn.VPCConnector != "" {
			vpcAccess = extractFunctionName(fn.VPCConnector)
			if fn.VPCEgressSettings != "" {
				vpcAccess += fmt.Sprintf(" (%s)", strings.TrimPrefix(fn.VPCEgressSettings, "VPC_EGRESS_"))
			}
		}

		// Format service account
		serviceAccount := fn.ServiceAccount
		if serviceAccount == "" {
			serviceAccount = "-"
		}

		// Check if using default service account
		defaultSA := "No"
		if strings.Contains(serviceAccount, "@appspot.gserviceaccount.com") ||
			strings.Contains(serviceAccount, "-compute@developer.gserviceaccount.com") {
			defaultSA = "Yes"
		}

		// Check attack paths (privesc/exfil/lateral) for the service account
		attackPaths := "run foxmapper"
		if serviceAccount != "-" {
			attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, serviceAccount)
		} else if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
			attackPaths = "No SA"
		}

		// Format ingress for display (consistent with Cloud Run)
		ingress := formatFunctionIngress(fn.IngressSettings)

		// If function has IAM bindings, create one row per binding (shows IAM Binding Role/Principal)
		if len(fn.IAMBindings) > 0 {
			for _, binding := range fn.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(fn.ProjectID),
					fn.Name,
					fn.Region,
					fn.Runtime,
					state,
					triggerInfo,
					url,
					ingress,
					shared.BoolToYesNo(fn.IsPublic),
					serviceAccount,
					attackPaths,
					defaultSA,
					vpcAccess,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// Function has no IAM bindings - single row
			body = append(body, []string{
				m.GetProjectName(fn.ProjectID),
				fn.Name,
				fn.Region,
				fn.Runtime,
				state,
				triggerInfo,
				url,
				ingress,
				shared.BoolToYesNo(fn.IsPublic),
				serviceAccount,
				attackPaths,
				defaultSA,
				vpcAccess,
				"-",
				"-",
			})
		}
	}
	return body
}

// formatFunctionIngress formats ingress settings for display (consistent with Cloud Run)
func formatFunctionIngress(ingress string) string {
	switch ingress {
	case "ALLOW_ALL":
		return "ALL (Public)"
	case "ALLOW_INTERNAL_ONLY":
		return "INTERNAL"
	case "ALLOW_INTERNAL_AND_GCLB":
		return "INT+LB"
	default:
		return ingress
	}
}

// extractFunctionName extracts just the name from a resource path
func extractFunctionName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
