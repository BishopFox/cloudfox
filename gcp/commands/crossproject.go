package commands

import (
	"context"
	"fmt"
	"strings"

	crossprojectservice "github.com/BishopFox/cloudfox/gcp/services/crossProjectService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCrossProjectCommand = &cobra.Command{
	Use:     globals.GCP_CROSSPROJECT_MODULE_NAME,
	Aliases: []string{"cross-project", "xproject"},
	Short:   "Analyze cross-project access patterns for lateral movement",
	Long: `Analyze cross-project access patterns to identify lateral movement paths and data flows.

This module is designed for penetration testing and identifies:
- Service accounts with access to multiple projects
- Cross-project IAM role bindings
- Potential lateral movement paths between projects
- Cross-project logging sinks (data exfiltration via logs)
- Cross-project Pub/Sub exports (data exfiltration via messages)
- Impersonation targets (which SAs can be impersonated in target projects)

Features:
- Maps cross-project service account access
- Identifies cross-project roles (owner, editor, admin)
- Discovers logging sinks sending logs to other projects
- Discovers Pub/Sub subscriptions exporting to other projects (BQ, GCS, push)
- Generates exploitation commands for lateral movement
- Highlights service accounts spanning trust boundaries
- Shows impersonation targets (run foxmapper first for attack path analysis)

RECOMMENDED: For comprehensive cross-project analysis, use -A to analyze all accessible projects:

  cloudfox gcp crossproject -A

This will:
- Use cached org/folder/project data (auto-populated, refreshes every 24h)
- Analyze cross-project patterns across all accessible projects
- Show "Trust Boundary" column indicating if target is Internal, External, or Unknown

TRUST BOUNDARY COLUMN:
- "Internal" - Target project is within your organization
- "External" - Target project is outside your organization (trust boundary crossing!)
- "Unknown"  - Cannot determine boundary

ALTERNATIVE: Specify projects manually with -l for a project list file:

  cloudfox gcp crossproject -l projects.txt

TIP: Run foxmapper first to populate the Attack Paths column.

WARNING: Requires multiple projects to be specified for effective analysis.
Single project analysis (-p) will have limited results.`,
	Run: runGCPCrossProjectCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CrossProjectModule struct {
	gcpinternal.BaseGCPModule

	CrossBindings        []crossprojectservice.CrossProjectBinding
	CrossProjectSAs      []crossprojectservice.CrossProjectServiceAccount
	LateralMovementPaths []crossprojectservice.LateralMovementPath
	CrossProjectSinks    []crossprojectservice.CrossProjectLoggingSink
	CrossProjectPubSub   []crossprojectservice.CrossProjectPubSubExport
	LootMap              map[string]*internal.LootFile
	FoxMapperCache       *gcpinternal.FoxMapperCache
	OrgCache             *gcpinternal.OrgCache
}

// ------------------------------
// Output Struct
// ------------------------------
type CrossProjectOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CrossProjectOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CrossProjectOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCrossProjectCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CROSSPROJECT_MODULE_NAME)
	if err != nil {
		return
	}

	if len(cmdCtx.ProjectIDs) < 2 {
		cmdCtx.Logger.InfoM("Cross-project analysis works best with multiple projects. Consider using -l to specify a project list.", globals.GCP_CROSSPROJECT_MODULE_NAME)
	}

	module := &CrossProjectModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		CrossBindings:        []crossprojectservice.CrossProjectBinding{},
		CrossProjectSAs:      []crossprojectservice.CrossProjectServiceAccount{},
		LateralMovementPaths: []crossprojectservice.LateralMovementPath{},
		CrossProjectSinks:    []crossprojectservice.CrossProjectLoggingSink{},
		CrossProjectPubSub:   []crossprojectservice.CrossProjectPubSubExport{},
		LootMap:              make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CrossProjectModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get FoxMapper cache for graph-based analysis
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_CROSSPROJECT_MODULE_NAME)
	}

	// Get org cache from context (auto-loaded at startup)
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)

	// If no context cache, try loading from disk cache
	if m.OrgCache == nil || !m.OrgCache.IsPopulated() {
		diskCache, _, err := gcpinternal.LoadOrgCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			m.OrgCache = diskCache
		}
	}

	logger.InfoM(fmt.Sprintf("Analyzing cross-project access patterns across %d project(s)...", len(m.ProjectIDs)), globals.GCP_CROSSPROJECT_MODULE_NAME)

	svc := crossprojectservice.New()

	// Analyze cross-project bindings
	bindings, err := svc.AnalyzeCrossProjectAccess(m.ProjectIDs, m.OrgCache)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not analyze cross-project access")
	} else {
		m.CrossBindings = bindings
	}

	// Get cross-project service accounts
	sas, err := svc.GetCrossProjectServiceAccounts(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not get cross-project service accounts")
	} else {
		m.CrossProjectSAs = sas
	}

	// Find lateral movement paths
	paths, err := svc.FindLateralMovementPaths(m.ProjectIDs, m.OrgCache)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find lateral movement paths")
	} else {
		m.LateralMovementPaths = paths
	}

	// Find cross-project logging sinks
	sinks, err := svc.FindCrossProjectLoggingSinks(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find cross-project logging sinks")
	} else {
		m.CrossProjectSinks = sinks
	}

	// Find cross-project Pub/Sub exports
	pubsubExports, err := svc.FindCrossProjectPubSubExports(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find cross-project Pub/Sub exports")
	} else {
		m.CrossProjectPubSub = pubsubExports
	}

	if len(m.CrossBindings) == 0 && len(m.CrossProjectSAs) == 0 && len(m.LateralMovementPaths) == 0 &&
		len(m.CrossProjectSinks) == 0 && len(m.CrossProjectPubSub) == 0 {
		logger.InfoM("No cross-project access patterns found", globals.GCP_CROSSPROJECT_MODULE_NAME)
		return
	}

	// Add findings to loot
	for _, binding := range m.CrossBindings {
		m.addBindingToLoot(binding)
	}

	for _, sa := range m.CrossProjectSAs {
		m.addServiceAccountToLoot(sa)
	}

	for _, path := range m.LateralMovementPaths {
		m.addLateralMovementToLoot(path)
	}

	for _, sink := range m.CrossProjectSinks {
		m.addLoggingSinkToLoot(sink)
	}

	for _, export := range m.CrossProjectPubSub {
		m.addPubSubExportToLoot(export)
	}

	logger.SuccessM(fmt.Sprintf("Found %d binding(s), %d SA(s), %d lateral path(s), %d logging sink(s), %d pubsub export(s)",
		len(m.CrossBindings), len(m.CrossProjectSAs), len(m.LateralMovementPaths),
		len(m.CrossProjectSinks), len(m.CrossProjectPubSub)), globals.GCP_CROSSPROJECT_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CrossProjectModule) initializeLootFiles() {
	m.LootMap["crossproject-commands"] = &internal.LootFile{
		Name:     "crossproject-commands",
		Contents: "# Cross-Project Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *CrossProjectModule) addBindingToLoot(binding crossprojectservice.CrossProjectBinding) {
	// Only add if there are exploitation commands
	if len(binding.ExploitCommands) > 0 {
		m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# %s -> %s (%s)\n"+
				"# =============================================================================\n",
			m.GetProjectName(binding.SourceProject),
			m.GetProjectName(binding.TargetProject),
			cleanRole(binding.Role),
		)
		m.LootMap["crossproject-commands"].Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
		for _, cmd := range binding.ExploitCommands {
			m.LootMap["crossproject-commands"].Contents += cmd + "\n"
		}
		m.LootMap["crossproject-commands"].Contents += "\n"
	}
}

func (m *CrossProjectModule) addServiceAccountToLoot(sa crossprojectservice.CrossProjectServiceAccount) {
	// Skip - service account cross-project access is covered by bindings and lateral movement paths
	// Adding separate impersonation commands would be redundant
}

func (m *CrossProjectModule) addLateralMovementToLoot(path crossprojectservice.LateralMovementPath) {
	// Only add if there are exploitation commands
	if len(path.ExploitCommands) > 0 {
		// Clean up role names for display
		var cleanedRoles []string
		for _, r := range path.TargetRoles {
			cleanedRoles = append(cleanedRoles, cleanRole(r))
		}

		m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# %s -> %s (%s)\n"+
				"# =============================================================================\n",
			m.GetProjectName(path.SourceProject),
			m.GetProjectName(path.TargetProject),
			strings.Join(cleanedRoles, ", "),
		)
		m.LootMap["crossproject-commands"].Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
		for _, cmd := range path.ExploitCommands {
			m.LootMap["crossproject-commands"].Contents += cmd + "\n"
		}
		m.LootMap["crossproject-commands"].Contents += "\n"
	}
}

func (m *CrossProjectModule) addLoggingSinkToLoot(sink crossprojectservice.CrossProjectLoggingSink) {
	// Logging sinks are data exports, not direct exploitation paths
	// Skip adding to loot - the table output is sufficient
}

func (m *CrossProjectModule) addPubSubExportToLoot(export crossprojectservice.CrossProjectPubSubExport) {
	// Pub/Sub exports are data exports, not direct exploitation paths
	// Skip adding to loot - the table output is sufficient
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CrossProjectModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *CrossProjectModule) getHeader() []string {
	return []string{
		"Source Project",
		"Source Type",
		"Source Principal",
		"Binding Type",
		"Target Project",
		"Target Type",
		"Target Principal",
		"Target Role",
		"Attack Path",
		"Trust Boundary",
	}
}

// getTargetProjectScope returns the scope of the target project relative to the org
func (m *CrossProjectModule) getTargetProjectScope(targetProjectID string) string {
	if m.OrgCache == nil || !m.OrgCache.IsPopulated() {
		return "Unknown"
	}
	return m.OrgCache.GetProjectScope(targetProjectID)
}

// getImpersonationTarget checks if a role grants impersonation capabilities and returns the target
// Returns (targetType, targetPrincipal) - both "-" if no impersonation target found
func (m *CrossProjectModule) getImpersonationTarget(principal, role, targetProject string) (string, string) {
	// Roles that grant impersonation capabilities
	impersonationRoles := map[string]bool{
		"roles/iam.serviceAccountTokenCreator": true,
		"roles/iam.serviceAccountKeyAdmin":     true,
		"iam.serviceAccountTokenCreator":       true,
		"iam.serviceAccountKeyAdmin":           true,
	}

	cleanedRole := cleanRole(role)

	// Check if this is an impersonation role
	if !impersonationRoles[role] && !impersonationRoles[cleanedRole] &&
		!strings.Contains(cleanedRole, "serviceAccountTokenCreator") &&
		!strings.Contains(cleanedRole, "serviceAccountKeyAdmin") {
		return "-", "-"
	}

	// FoxMapper handles impersonation differently via graph edges
	// Since we no longer use AttackPathCache, we rely on FoxMapper or show a generic message

	// No specific targets found in cache - this likely means the role was granted at the
	// project level (not on specific SAs), which means ALL SAs in the target project can be impersonated
	return "Service Account", fmt.Sprintf("All SAs in %s", m.GetProjectName(targetProject))
}

// getPrincipalTypeDisplay returns a human-readable type for the principal
func getPrincipalTypeDisplay(principal string) string {
	if strings.HasPrefix(principal, "serviceAccount:") {
		return "Service Account"
	} else if strings.HasPrefix(principal, "user:") {
		return "User"
	} else if strings.HasPrefix(principal, "group:") {
		return "Group"
	} else if strings.HasPrefix(principal, "domain:") {
		return "Domain"
	}
	return "Unknown"
}

// cleanPrincipal removes common prefixes from principal strings for cleaner display
func cleanPrincipal(principal string) string {
	// Remove serviceAccount:, user:, group: prefixes
	principal = strings.TrimPrefix(principal, "serviceAccount:")
	principal = strings.TrimPrefix(principal, "user:")
	principal = strings.TrimPrefix(principal, "group:")
	principal = strings.TrimPrefix(principal, "domain:")
	return principal
}

// cleanRole extracts just the role name from a full role path
func cleanRole(role string) string {
	// Handle full project paths like "projects/project-id/roles/customRole"
	if strings.Contains(role, "/roles/") {
		parts := strings.Split(role, "/roles/")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	// Handle standard roles like "roles/compute.admin"
	if strings.HasPrefix(role, "roles/") {
		return strings.TrimPrefix(role, "roles/")
	}
	return role
}

// extractCrossProjectResourceName extracts just the resource name from a full resource path
func extractCrossProjectResourceName(path string) string {
	// Handle various path formats
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}

// getAttackPathForTarget returns attack path summary for a principal accessing a target project
func (m *CrossProjectModule) getAttackPathForTarget(targetProject, principal string) string {
	// Clean principal for lookup
	cleanedPrincipal := cleanPrincipal(principal)

	// Check if this is a service account
	if strings.Contains(cleanedPrincipal, "@") && strings.Contains(cleanedPrincipal, ".iam.gserviceaccount.com") {
		return gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, cleanedPrincipal)
	}

	return "-"
}

func (m *CrossProjectModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

// buildTableBodyByTargetProject builds table bodies grouped by target project
// Returns a map of targetProjectID -> [][]string (rows for that target project)
func (m *CrossProjectModule) buildTableBodyByTargetProject() map[string][][]string {
	bodyByProject := make(map[string][][]string)

	// Add cross-project bindings
	for _, binding := range m.CrossBindings {
		principalType := getPrincipalTypeDisplay(binding.Principal)
		principal := cleanPrincipal(binding.Principal)
		role := cleanRole(binding.Role)
		attackPath := m.getAttackPathForTarget(binding.TargetProject, binding.Principal)
		targetType, targetPrincipal := m.getImpersonationTarget(binding.Principal, binding.Role, binding.TargetProject)
		trustBoundary := m.getTargetProjectScope(binding.TargetProject)

		row := []string{
			m.GetProjectName(binding.SourceProject),
			principalType,
			principal,
			"IAM Binding",
			m.GetProjectName(binding.TargetProject),
			targetType,
			targetPrincipal,
			role,
			attackPath,
			trustBoundary,
		}
		bodyByProject[binding.TargetProject] = append(bodyByProject[binding.TargetProject], row)
	}

	// Add cross-project service accounts
	for _, sa := range m.CrossProjectSAs {
		for _, access := range sa.TargetAccess {
			parts := strings.SplitN(access, ": ", 2)
			targetProject := ""
			role := access
			if len(parts) == 2 {
				targetProject = parts[0]
				role = parts[1]
			}

			role = cleanRole(role)
			attackPath := m.getAttackPathForTarget(targetProject, "serviceAccount:"+sa.Email)
			targetType, targetPrincipal := m.getImpersonationTarget(sa.Email, role, targetProject)
			trustBoundary := m.getTargetProjectScope(targetProject)

			row := []string{
				m.GetProjectName(sa.ProjectID),
				"Service Account",
				sa.Email,
				"IAM Binding",
				m.GetProjectName(targetProject),
				targetType,
				targetPrincipal,
				role,
				attackPath,
				trustBoundary,
			}
			bodyByProject[targetProject] = append(bodyByProject[targetProject], row)
		}
	}

	// Add lateral movement paths
	for _, path := range m.LateralMovementPaths {
		for _, role := range path.TargetRoles {
			principalType := getPrincipalTypeDisplay(path.SourcePrincipal)
			principal := cleanPrincipal(path.SourcePrincipal)
			cleanedRole := cleanRole(role)
			attackPath := m.getAttackPathForTarget(path.TargetProject, path.SourcePrincipal)
			targetType, targetPrincipal := m.getImpersonationTarget(path.SourcePrincipal, role, path.TargetProject)
			trustBoundary := m.getTargetProjectScope(path.TargetProject)

			row := []string{
				m.GetProjectName(path.SourceProject),
				principalType,
				principal,
				path.AccessMethod,
				m.GetProjectName(path.TargetProject),
				targetType,
				targetPrincipal,
				cleanedRole,
				attackPath,
				trustBoundary,
			}
			bodyByProject[path.TargetProject] = append(bodyByProject[path.TargetProject], row)
		}
	}

	// Add logging sinks - these are resources, not principals
	for _, sink := range m.CrossProjectSinks {
		dest := sink.DestinationType
		if sink.Filter != "" {
			filter := sink.Filter
			if len(filter) > 30 {
				filter = filter[:27] + "..."
			}
			dest = fmt.Sprintf("%s (%s)", sink.DestinationType, filter)
		}
		trustBoundary := m.getTargetProjectScope(sink.TargetProject)

		row := []string{
			m.GetProjectName(sink.SourceProject),
			"Logging Sink",
			sink.SinkName,
			"Data Export",
			m.GetProjectName(sink.TargetProject),
			"-",
			"-",
			dest,
			"-",
			trustBoundary,
		}
		bodyByProject[sink.TargetProject] = append(bodyByProject[sink.TargetProject], row)
	}

	// Add Pub/Sub exports - these are resources, not principals
	for _, export := range m.CrossProjectPubSub {
		dest := export.ExportType
		if export.ExportDest != "" {
			destName := extractCrossProjectResourceName(export.ExportDest)
			dest = fmt.Sprintf("%s: %s", export.ExportType, destName)
		}
		trustBoundary := m.getTargetProjectScope(export.TargetProject)

		row := []string{
			m.GetProjectName(export.SourceProject),
			"Pub/Sub",
			export.SubscriptionName,
			"Data Export",
			m.GetProjectName(export.TargetProject),
			"-",
			"-",
			dest,
			"-",
			trustBoundary,
		}
		bodyByProject[export.TargetProject] = append(bodyByProject[export.TargetProject], row)
	}

	return bodyByProject
}

func (m *CrossProjectModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// For crossproject, output at project level grouped by TARGET project
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	header := m.getHeader()
	bodyByProject := m.buildTableBodyByTargetProject()
	lootFiles := m.collectLootFiles()

	// Create output for each target project
	for targetProject, body := range bodyByProject {
		if len(body) == 0 {
			continue
		}

		tables := []internal.TableFile{
			{
				Name:   "crossproject",
				Header: header,
				Body:   body,
			},
		}

		output := CrossProjectOutput{
			Table: tables,
			Loot:  lootFiles, // Loot files are shared across all projects
		}

		outputData.ProjectLevelData[targetProject] = output
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *CrossProjectModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getHeader()
	bodyByProject := m.buildTableBodyByTargetProject()
	lootFiles := m.collectLootFiles()

	// Write output for each target project separately
	isFirstProject := true
	for targetProject, body := range bodyByProject {
		if len(body) == 0 {
			continue
		}

		tables := []internal.TableFile{
			{
				Name:   "crossproject",
				Header: header,
				Body:   body,
			},
		}

		// Only include loot files on the first project to avoid duplicate writes
		var projectLoot []internal.LootFile
		if isFirstProject {
			projectLoot = lootFiles
			isFirstProject = false
		}

		output := CrossProjectOutput{
			Table: tables,
			Loot:  projectLoot,
		}

		err := internal.HandleOutputSmart(
			"gcp",
			m.Format,
			m.OutputDirectory,
			m.Verbosity,
			m.WrapTable,
			"project",
			[]string{targetProject},
			[]string{m.GetProjectName(targetProject)},
			m.Account,
			output,
		)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for project %s: %v", targetProject, err), globals.GCP_CROSSPROJECT_MODULE_NAME)
			m.CommandCounter.Error++
		}
	}
}
