package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	cloudbuildservice "github.com/BishopFox/cloudfox/gcp/services/cloudbuildService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudBuildCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDBUILD_MODULE_NAME,
	Aliases: []string{"cb", "build", "builds"},
	Short:   "Enumerate Cloud Build triggers and builds",
	Long: `Enumerate Cloud Build triggers and recent build executions.

Features:
- Lists all build triggers
- Shows trigger source configuration (GitHub, CSR)
- Identifies service accounts used for builds
- Shows recent build executions
- Detects potentially risky trigger configurations`,
	Run: runGCPCloudBuildCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type CloudBuildModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	ProjectTriggers         map[string][]cloudbuildservice.TriggerInfo             // projectID -> triggers
	ProjectBuilds           map[string][]cloudbuildservice.BuildInfo               // projectID -> builds
	ProjectSecurityAnalysis map[string][]cloudbuildservice.TriggerSecurityAnalysis // projectID -> analysis
	LootMap                 map[string]map[string]*internal.LootFile               // projectID -> loot files
	FoxMapperCache          *gcpinternal.FoxMapperCache                            // Cached FoxMapper attack path analysis results
	mu                      sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type CloudBuildOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudBuildOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudBuildOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudBuildCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDBUILD_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudBuildModule{
		BaseGCPModule:           gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectTriggers:         make(map[string][]cloudbuildservice.TriggerInfo),
		ProjectBuilds:           make(map[string][]cloudbuildservice.BuildInfo),
		ProjectSecurityAnalysis: make(map[string][]cloudbuildservice.TriggerSecurityAnalysis),
		LootMap:                 make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudBuildModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get FoxMapper cache from context
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDBUILD_MODULE_NAME, m.processProject)

	allTriggers := m.getAllTriggers()
	allBuilds := m.getAllBuilds()

	if len(allTriggers) == 0 && len(allBuilds) == 0 {
		logger.InfoM("No Cloud Build triggers or builds found", globals.GCP_CLOUDBUILD_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d trigger(s), %d recent build(s)",
		len(allTriggers), len(allBuilds)), globals.GCP_CLOUDBUILD_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *CloudBuildModule) getAllTriggers() []cloudbuildservice.TriggerInfo {
	var all []cloudbuildservice.TriggerInfo
	for _, triggers := range m.ProjectTriggers {
		all = append(all, triggers...)
	}
	return all
}

func (m *CloudBuildModule) getAllBuilds() []cloudbuildservice.BuildInfo {
	var all []cloudbuildservice.BuildInfo
	for _, builds := range m.ProjectBuilds {
		all = append(all, builds...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudBuildModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud Build in project: %s", projectID), globals.GCP_CLOUDBUILD_MODULE_NAME)
	}

	cbSvc := cloudbuildservice.New()

	// Get triggers
	triggers, err := cbSvc.ListTriggers(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDBUILD_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Build triggers in project %s", projectID))
	}

	// Get recent builds
	builds, err := cbSvc.ListBuilds(projectID, 20)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDBUILD_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Build builds in project %s", projectID))
	}

	m.mu.Lock()
	m.ProjectTriggers[projectID] = triggers
	m.ProjectBuilds[projectID] = builds

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["cloudbuild-details"] = &internal.LootFile{
			Name:     "cloudbuild-details",
			Contents: "# Cloud Build Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	var projectAnalysis []cloudbuildservice.TriggerSecurityAnalysis
	for _, trigger := range triggers {
		m.addTriggerToLoot(projectID, trigger)
		// Perform security analysis
		analysis := cbSvc.AnalyzeTriggerForPrivesc(trigger, projectID)
		projectAnalysis = append(projectAnalysis, analysis)
		m.addSecurityAnalysisToLoot(projectID, analysis)
	}
	m.ProjectSecurityAnalysis[projectID] = projectAnalysis

	// Add build step analysis to loot
	for _, build := range builds {
		m.addBuildToLoot(projectID, build)
	}
	m.mu.Unlock()
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CloudBuildModule) addTriggerToLoot(projectID string, trigger cloudbuildservice.TriggerInfo) {
	lootFile := m.LootMap[projectID]["cloudbuild-details"]
	if lootFile == nil {
		return
	}

	// Build flags for special attributes
	var flags []string
	if trigger.PrivescPotential {
		flags = append(flags, "PRIVESC POTENTIAL")
	}
	if trigger.Disabled {
		flags = append(flags, "DISABLED")
	}

	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, "] [") + "]"
	}

	sa := trigger.ServiceAccount
	if sa == "" {
		sa = "(default)"
	}

	branchTag := trigger.BranchName
	if branchTag == "" {
		branchTag = trigger.TagName
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# BUILD TRIGGER: %s%s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n"+
			"# ID: %s\n"+
			"# Source: %s - %s\n"+
			"# Branch/Tag: %s, Config: %s\n"+
			"# Service Account: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe trigger:\n"+
			"gcloud builds triggers describe %s --project=%s\n",
		trigger.Name, flagStr,
		trigger.ProjectID,
		trigger.ID,
		trigger.SourceType, trigger.RepoName,
		branchTag, trigger.Filename,
		sa,
		trigger.ID, trigger.ProjectID,
	)
}

func (m *CloudBuildModule) addSecurityAnalysisToLoot(projectID string, analysis cloudbuildservice.TriggerSecurityAnalysis) {
	lootFile := m.LootMap[projectID]["cloudbuild-details"]
	if lootFile == nil {
		return
	}

	// Add exploitation commands if available
	if len(analysis.ExploitCommands) > 0 {
		lootFile.Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
		for _, cmd := range analysis.ExploitCommands {
			lootFile.Contents += fmt.Sprintf("# %s\n", cmd)
		}
	}
	lootFile.Contents += "\n"
}

func (m *CloudBuildModule) addBuildToLoot(projectID string, build cloudbuildservice.BuildInfo) {
	lootFile := m.LootMap[projectID]["cloudbuild-details"]
	if lootFile == nil {
		return
	}

	buildID := build.ID
	if len(buildID) > 12 {
		buildID = buildID[:12]
	}

	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# BUILD: %s\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Project: %s, Status: %s\n"+
			"# Trigger: %s, Source: %s\n",
		buildID,
		build.ProjectID, build.Status,
		build.TriggerID, build.Source,
	)

	// Log location
	if build.LogsBucket != "" {
		lootFile.Contents += fmt.Sprintf(
			"Logs: gsutil cat %s/log-%s.txt\n",
			build.LogsBucket, build.ID,
		)
	}

	// Secret environment variables
	if len(build.SecretEnvVars) > 0 {
		lootFile.Contents += "Secret Env Vars:\n"
		for _, secret := range build.SecretEnvVars {
			lootFile.Contents += fmt.Sprintf("  - %s\n", secret)
		}
	}

	lootFile.Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudBuildModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Log privesc count
	privescCount := 0
	for _, triggers := range m.ProjectTriggers {
		for _, trigger := range triggers {
			if trigger.PrivescPotential {
				privescCount++
			}
		}
	}
	if privescCount > 0 {
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d trigger(s) with privilege escalation potential!", privescCount), globals.GCP_CLOUDBUILD_MODULE_NAME)
	}

	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *CloudBuildModule) getTriggersHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Source",
		"Repository",
		"Branch/Tag",
		"Config File",
		"Service Account",
		"SA Attack Paths",
		"Disabled",
		"Privesc Potential",
	}
}

func (m *CloudBuildModule) getBuildsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"ID",
		"Status",
		"Trigger",
		"Source",
		"Created",
	}
}

func (m *CloudBuildModule) triggersToTableBody(triggers []cloudbuildservice.TriggerInfo) [][]string {
	var body [][]string
	for _, trigger := range triggers {
		disabled := "No"
		if trigger.Disabled {
			disabled = "Yes"
		}

		privescPotential := "No"
		if trigger.PrivescPotential {
			privescPotential = "Yes"
		}

		branchTag := trigger.BranchName
		if branchTag == "" {
			branchTag = trigger.TagName
		}

		sa := trigger.ServiceAccount
		if sa == "" {
			sa = "(default)"
		}

		// Check attack paths (privesc/exfil/lateral) for the service account
		attackPaths := "run foxmapper"
		if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
			if sa != "(default)" && sa != "" {
				attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, sa)
			} else {
				attackPaths = "No"
			}
		}

		body = append(body, []string{
			m.GetProjectName(trigger.ProjectID),
			trigger.ProjectID,
			trigger.Name,
			trigger.SourceType,
			trigger.RepoName,
			branchTag,
			trigger.Filename,
			sa,
			attackPaths,
			disabled,
			privescPotential,
		})
	}
	return body
}

func (m *CloudBuildModule) buildsToTableBody(builds []cloudbuildservice.BuildInfo) [][]string {
	var body [][]string
	for _, build := range builds {
		buildID := build.ID
		if len(buildID) > 12 {
			buildID = buildID[:12]
		}
		body = append(body, []string{
			m.GetProjectName(build.ProjectID),
			build.ProjectID,
			buildID,
			build.Status,
			build.TriggerID,
			build.Source,
			build.CreateTime,
		})
	}
	return body
}

func (m *CloudBuildModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if triggers, ok := m.ProjectTriggers[projectID]; ok && len(triggers) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "cloudbuild-triggers",
			Header: m.getTriggersHeader(),
			Body:   m.triggersToTableBody(triggers),
		})
	}

	if builds, ok := m.ProjectBuilds[projectID]; ok && len(builds) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "cloudbuild-builds",
			Header: m.getBuildsHeader(),
			Body:   m.buildsToTableBody(builds),
		})
	}

	return tableFiles
}

func (m *CloudBuildModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Get all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectTriggers {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectBuilds {
		projectIDs[projectID] = true
	}

	for projectID := range projectIDs {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = CloudBuildOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CLOUDBUILD_MODULE_NAME)
	}
}

func (m *CloudBuildModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allTriggers := m.getAllTriggers()
	allBuilds := m.getAllBuilds()

	var tables []internal.TableFile

	if len(allTriggers) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cloudbuild-triggers",
			Header: m.getTriggersHeader(),
			Body:   m.triggersToTableBody(allTriggers),
		})
	}

	if len(allBuilds) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cloudbuild-builds",
			Header: m.getBuildsHeader(),
			Body:   m.buildsToTableBody(allBuilds),
		})
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := CloudBuildOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDBUILD_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
