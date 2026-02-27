package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	serviceagentsservice "github.com/BishopFox/cloudfox/gcp/services/serviceAgentsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPServiceAgentsCommand = &cobra.Command{
	Use:     globals.GCP_SERVICEAGENTS_MODULE_NAME,
	Aliases: []string{"agents", "service-accounts-google", "gcp-agents"},
	Short:   "Enumerate Google-managed service agents",
	Long: `Enumerate Google-managed service agents and their permissions.

Service agents are Google-managed service accounts that operate on behalf
of GCP services. Understanding them helps identify:
- Hidden access paths to resources
- Cross-project service agent access
- Overprivileged service agents
- Potential lateral movement via service agent impersonation

Common Service Agents:
- Cloud Build Service Account (@cloudbuild.gserviceaccount.com)
- Compute Engine Service Agent (@compute-system.iam.gserviceaccount.com)
- GKE Service Agent (@container-engine-robot.iam.gserviceaccount.com)
- Cloud Run/Functions (@serverless-robot-prod.iam.gserviceaccount.com)
- Cloud SQL Service Agent (@gcp-sa-cloud-sql.iam.gserviceaccount.com)

Security Considerations:
- Service agents often have broad permissions
- Cross-project agents indicate shared service access
- Cloud Build SA is a common privilege escalation vector
- Default compute SA often has Editor role

TIP: Run foxmapper first to populate the Attack Paths column with privesc/exfil/lateral movement analysis.`,
	Run: runGCPServiceAgentsCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type ServiceAgentsModule struct {
	gcpinternal.BaseGCPModule

	ProjectAgents  map[string][]serviceagentsservice.ServiceAgentInfo // projectID -> agents
	LootMap        map[string]map[string]*internal.LootFile           // projectID -> loot files
	FoxMapperCache *gcpinternal.FoxMapperCache                        // Cached FoxMapper analysis results
	OrgCache       *gcpinternal.OrgCache
	mu             sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type ServiceAgentsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ServiceAgentsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ServiceAgentsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPServiceAgentsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_SERVICEAGENTS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &ServiceAgentsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectAgents: make(map[string][]serviceagentsservice.ServiceAgentInfo),
		LootMap:       make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ServiceAgentsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get FoxMapper cache from context
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)

	// Get OrgCache for project number resolution
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_SERVICEAGENTS_MODULE_NAME, m.processProject)

	allAgents := m.getAllAgents()
	if len(allAgents) == 0 {
		logger.InfoM("No service agents found", globals.GCP_SERVICEAGENTS_MODULE_NAME)
		return
	}

	// Count cross-project agents
	crossProjectCount := 0
	for _, agent := range allAgents {
		if agent.IsCrossProject {
			crossProjectCount++
		}
	}

	if crossProjectCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d service agent(s) (%d cross-project)", len(allAgents), crossProjectCount), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d service agent(s)", len(allAgents)), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// getAllAgents returns all agents from all projects (for statistics)
func (m *ServiceAgentsModule) getAllAgents() []serviceagentsservice.ServiceAgentInfo {
	var all []serviceagentsservice.ServiceAgentInfo
	for _, agents := range m.ProjectAgents {
		all = append(all, agents...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *ServiceAgentsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating service agents in project: %s", projectID), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	}

	svc := serviceagentsservice.New()
	agents, err := svc.GetServiceAgents(projectID, m.OrgCache)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_SERVICEAGENTS_MODULE_NAME,
			fmt.Sprintf("Could not get service agents in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.ProjectAgents[projectID] = agents

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["serviceagents-commands"] = &internal.LootFile{
			Name:     "serviceagents-commands",
			Contents: "# Service Agents Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	for _, agent := range agents {
		m.addAgentToLoot(projectID, agent)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d service agent(s) in project %s", len(agents), projectID), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ServiceAgentsModule) addAgentToLoot(projectID string, agent serviceagentsservice.ServiceAgentInfo) {
	lootFile := m.LootMap[projectID]["serviceagents-commands"]
	if lootFile == nil {
		return
	}

	crossProjectNote := ""
	if agent.IsCrossProject {
		crossProjectNote = " [CROSS-PROJECT from " + agent.SourceProject + "]"
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# SERVICE AGENT: %s%s\n"+
			"# =============================================================================\n"+
			"# Email: %s\n"+
			"# Description: %s\n",
		agent.ServiceName, crossProjectNote,
		agent.Email, agent.Description,
	)

	if agent.IsCrossProject && agent.SourceProject != "" {
		lootFile.Contents += fmt.Sprintf("# Source Project: %s\n", agent.SourceProject)
	}

	if len(agent.Roles) > 0 {
		lootFile.Contents += fmt.Sprintf("# Roles: %s\n", strings.Join(agent.Roles, ", "))
	}

	lootFile.Contents += fmt.Sprintf(`
# === ENUMERATION COMMANDS ===

# List all roles granted to this service agent (clean output for screenshots)
gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains("%s")) | .role'

# Show service agent with its roles (formatted for reporting)
gcloud projects get-iam-policy %s --format=json | jq '[.bindings[] | select(.members[] | contains("%s")) | {role: .role, member: "%s"}]'

# Check what resources this service agent can access (with roles)
gcloud asset search-all-iam-policies --scope=projects/%s --query='policy:%s' --format=json | jq -r '.results[] | {resource: .resource, roles: [.policy.bindings[].role]} | "\(.resource): \(.roles | join(", "))"'

# Check resource-level IAM bindings for this service agent
gcloud asset search-all-iam-policies --scope=projects/%s --query='policy.bindings.members:%s' --format=json | jq -r '.results[] | "\(.resource): \([.policy.bindings[] | select(.members[] | contains("%s")) | .role] | join(", "))"'

`, projectID, agent.Email, projectID, agent.Email, agent.Email, projectID, agent.Email, projectID, agent.Email, agent.Email)

	lootFile.Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ServiceAgentsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getHeader returns the table header
func (m *ServiceAgentsModule) getHeader() []string {
	return []string{
		"Project",
		"Service",
		"Email",
		"Source Project",
		"Cross-Project",
		"Role",
		"Attack Paths",
		"Description",
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *ServiceAgentsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getHeader()

	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, agents := range m.ProjectAgents {
		body := m.agentsToTableBody(agents)
		tables := []internal.TableFile{{
			Name:   globals.GCP_SERVICEAGENTS_MODULE_NAME,
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

		outputData.ProjectLevelData[projectID] = ServiceAgentsOutput{Table: tables, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_SERVICEAGENTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *ServiceAgentsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getHeader()

	allAgents := m.getAllAgents()
	body := m.agentsToTableBody(allAgents)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tables := []internal.TableFile{
		{
			Name:   globals.GCP_SERVICEAGENTS_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	output := ServiceAgentsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SERVICEAGENTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// agentsToTableBody converts agents to table rows
func (m *ServiceAgentsModule) agentsToTableBody(agents []serviceagentsservice.ServiceAgentInfo) [][]string {
	var body [][]string
	for _, agent := range agents {
		crossProject := "No"
		if agent.IsCrossProject {
			crossProject = "Yes"
		}

		// Source project (where the agent originates from)
		sourceProject := "-"
		if agent.SourceProject != "" {
			sourceProject = agent.SourceProject
		}

		// Check attack paths for this service agent
		attackPaths := "run foxmapper"
		if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
			attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, agent.Email)
		}

		// One row per role
		if len(agent.Roles) > 0 {
			for _, role := range agent.Roles {
				body = append(body, []string{
					m.GetProjectName(agent.ProjectID),
					agent.ServiceName,
					agent.Email,
					sourceProject,
					crossProject,
					role,
					attackPaths,
					agent.Description,
				})
			}
		} else {
			// Agent with no roles
			body = append(body, []string{
				m.GetProjectName(agent.ProjectID),
				agent.ServiceName,
				agent.Email,
				sourceProject,
				crossProject,
				"-",
				attackPaths,
				agent.Description,
			})
		}
	}
	return body
}
