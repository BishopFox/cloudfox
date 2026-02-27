package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/gcp/shared"

	GKEService "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPGKECommand = &cobra.Command{
	Use:     globals.GCP_GKE_MODULE_NAME,
	Aliases: []string{"kubernetes", "k8s", "clusters"},
	Short:   "Enumerate GKE clusters with security analysis",
	Long: `Enumerate GKE clusters across projects with comprehensive security analysis.

Features:
- Lists all GKE clusters accessible to the authenticated user
- Analyzes security configuration (private clusters, authorized networks, RBAC)
- Identifies clusters with public API endpoints
- Shows workload identity configuration
- Detects common misconfigurations (legacy ABAC, basic auth, no network policy)
- Enumerates node pools with service accounts and OAuth scopes
- Shows Binary Authorization status
- Shows GKE Autopilot vs Standard mode
- Shows Config Connector and Istio/ASM status
- Shows maintenance window and exclusions
- Generates kubectl and gcloud commands for further analysis

Security Columns:
- Private: Whether the cluster uses private nodes (no public IPs)
- MasterAuth: Master authorized networks enabled
- NetworkPolicy: Kubernetes network policy controller enabled
- WorkloadIdentity: GKE Workload Identity configured
- ShieldedNodes: Shielded GKE nodes enabled
- BinAuth: Binary Authorization enabled
- Autopilot: GKE Autopilot mode (vs Standard)
- Issues: Detected security misconfigurations

Attack Surface:
- Public API servers are accessible from the internet
- Clusters without Workload Identity use node service accounts
- Default service accounts may have excessive permissions
- Legacy ABAC allows broader access than RBAC
- Autopilot clusters have reduced attack surface
- Binary Authorization prevents untrusted container images

TIP: Run 'workload-identity' to enumerate K8s SA -> GCP SA bindings and Workload Identity Federation (external identity pools/providers).`,
	Run: runGCPGKECommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type GKEModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectClusters  map[string][]GKEService.ClusterInfo      // projectID -> clusters
	ProjectNodePools map[string][]GKEService.NodePoolInfo     // projectID -> node pools
	LootMap          map[string]map[string]*internal.LootFile // projectID -> loot files
	FoxMapperCache   *gcpinternal.FoxMapperCache              // FoxMapper graph data (preferred)
	mu               sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type GKEOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o GKEOutput) TableFiles() []internal.TableFile { return o.Table }
func (o GKEOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPGKECommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_GKE_MODULE_NAME)
	if err != nil {
		return
	}

	module := &GKEModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectClusters:  make(map[string][]GKEService.ClusterInfo),
		ProjectNodePools: make(map[string][]GKEService.NodePoolInfo),
		LootMap:          make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *GKEModule) Execute(ctx context.Context, logger internal.Logger) {
	// Try to get FoxMapper cache (preferred - graph-based analysis)
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_GKE_MODULE_NAME)
	}

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_GKE_MODULE_NAME, m.processProject)

	// Get all clusters for stats
	allClusters := m.getAllClusters()
	allNodePools := m.getAllNodePools()
	if len(allClusters) == 0 {
		logger.InfoM("No GKE clusters found", globals.GCP_GKE_MODULE_NAME)
		return
	}

	// Count public clusters
	publicCount := 0
	for _, cluster := range allClusters {
		if !cluster.PrivateCluster && !cluster.MasterAuthorizedOnly {
			publicCount++
		}
	}

	msg := fmt.Sprintf("Found %d cluster(s), %d node pool(s)", len(allClusters), len(allNodePools))
	if publicCount > 0 {
		msg += fmt.Sprintf(" [%d with public API endpoint]", publicCount)
	}
	logger.SuccessM(msg, globals.GCP_GKE_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllClusters returns all clusters from all projects (for statistics)
func (m *GKEModule) getAllClusters() []GKEService.ClusterInfo {
	var all []GKEService.ClusterInfo
	for _, clusters := range m.ProjectClusters {
		all = append(all, clusters...)
	}
	return all
}

// getAllNodePools returns all node pools from all projects (for statistics)
func (m *GKEModule) getAllNodePools() []GKEService.NodePoolInfo {
	var all []GKEService.NodePoolInfo
	for _, nodePools := range m.ProjectNodePools {
		all = append(all, nodePools...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *GKEModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating GKE clusters in project: %s", projectID), globals.GCP_GKE_MODULE_NAME)
	}

	gs := GKEService.New()
	clusters, nodePools, err := gs.Clusters(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_GKE_MODULE_NAME,
			fmt.Sprintf("Could not enumerate GKE clusters in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectClusters[projectID] = clusters
	m.ProjectNodePools[projectID] = nodePools

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["gke-commands"] = &internal.LootFile{
			Name:     "gke-commands",
			Contents: "# GKE Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	for _, cluster := range clusters {
		m.addClusterToLoot(projectID, cluster)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d cluster(s) in project %s", len(clusters), projectID), globals.GCP_GKE_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *GKEModule) addClusterToLoot(projectID string, cluster GKEService.ClusterInfo) {
	lootFile := m.LootMap[projectID]["gke-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# CLUSTER: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Location: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Get detailed cluster configuration and settings\n"+
			"gcloud container clusters describe %s --location=%s --project=%s\n\n"+
			"# Configure kubectl to authenticate to this cluster\n"+
			"gcloud container clusters get-credentials %s --location=%s --project=%s\n\n"+
			"# List all node pools in this cluster\n"+
			"gcloud container node-pools list --cluster=%s --location=%s --project=%s\n\n"+
			"# kubectl commands (after getting credentials):\n\n"+
			"# Show cluster endpoint and services info\n"+
			"kubectl cluster-info\n\n"+
			"# List all nodes with additional details (IP, OS, runtime)\n"+
			"kubectl get nodes -o wide\n\n"+
			"# List all namespaces in the cluster\n"+
			"kubectl get namespaces\n\n"+
			"# === EXPLOIT COMMANDS ===\n\n"+
			"# Check what actions you can perform in the cluster\n"+
			"kubectl auth can-i --list\n\n",
		cluster.Name,
		cluster.ProjectID, cluster.Location,
		cluster.Name, cluster.Location, cluster.ProjectID,
		cluster.Name, cluster.Location, cluster.ProjectID,
		cluster.Name, cluster.Location, cluster.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *GKEModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *GKEModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectClusters {
		projectsWithData[projectID] = true
	}

	// Build project-level outputs
	for projectID := range projectsWithData {
		clusters := m.ProjectClusters[projectID]
		nodePools := m.ProjectNodePools[projectID]

		tables := m.buildTablesForProject(clusters, nodePools)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = GKEOutput{Table: tables, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_GKE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *GKEModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allClusters := m.getAllClusters()
	allNodePools := m.getAllNodePools()

	tables := m.buildTablesForProject(allClusters, allNodePools)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := GKEOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_GKE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// buildTablesForProject builds all tables for given clusters and node pools
func (m *GKEModule) buildTablesForProject(clusters []GKEService.ClusterInfo, nodePools []GKEService.NodePoolInfo) []internal.TableFile {
	tableFiles := []internal.TableFile{}

	// Clusters table - columns grouped by: identity, network/access, cluster-level security
	clusterHeader := []string{
		"Project", "Name", "Location", "Mode", "Status", "Version", "Release Channel",
		"Endpoint", "Private", "Authorized CIDRs",
		"WorkloadID", "NetPolicy", "BinAuth",
	}

	var clusterBody [][]string
	for _, cluster := range clusters {
		clusterMode := "Standard"
		if cluster.Autopilot {
			clusterMode = "Autopilot"
		}
		releaseChannel := cluster.ReleaseChannel
		if releaseChannel == "" || releaseChannel == "UNSPECIFIED" {
			releaseChannel = "-"
		}
		endpoint := cluster.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}

		// Format authorized CIDRs
		authorizedCIDRs := formatAuthorizedCIDRs(cluster)

		clusterBody = append(clusterBody, []string{
			m.GetProjectName(cluster.ProjectID), cluster.Name, cluster.Location,
			clusterMode, cluster.Status, cluster.CurrentMasterVersion, releaseChannel,
			endpoint, shared.BoolToYesNo(cluster.PrivateCluster), authorizedCIDRs,
			shared.BoolToYesNo(cluster.WorkloadIdentity != ""), shared.BoolToYesNo(cluster.NetworkPolicy),
			shared.BoolToYesNo(cluster.BinaryAuthorization),
		})
	}

	if len(clusterBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-clusters",
			Header: clusterHeader,
			Body:   clusterBody,
		})
	}

	// Node pools table - node-level details including hardware security (like instances module)
	nodePoolHeader := []string{
		"Project", "Cluster", "Node Pool", "Machine Type", "Node Count",
		"Auto Upgrade", "Secure Boot", "Integrity", "Preemptible",
		"Service Account", "SA Attack Paths", "SA Scopes", "SA Scope Summary",
	}

	var nodePoolBody [][]string
	for _, np := range nodePools {
		saDisplay := np.ServiceAccount
		if saDisplay == "" {
			saDisplay = "-"
		}

		// Check attack paths (privesc/exfil/lateral) for the service account
		attackPaths := "run foxmapper"
		if saDisplay != "-" {
			attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, saDisplay)
		} else if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
			attackPaths = "No SA"
		}

		// Format actual scopes for display
		scopes := formatGKEScopes(np.OAuthScopes)

		// Get scope summary, default to "Unknown" if empty
		scopeSummary := np.ScopeSummary
		if scopeSummary == "" {
			scopeSummary = "Unknown"
		}

		nodePoolBody = append(nodePoolBody, []string{
			m.GetProjectName(np.ProjectID), np.ClusterName, np.Name,
			np.MachineType, fmt.Sprintf("%d", np.NodeCount),
			shared.BoolToYesNo(np.AutoUpgrade),
			shared.BoolToYesNo(np.SecureBoot), shared.BoolToYesNo(np.IntegrityMonitoring),
			shared.BoolToYesNo(np.Preemptible || np.Spot),
			saDisplay, attackPaths, scopes, scopeSummary,
		})
	}

	if len(nodePoolBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-node-pools",
			Header: nodePoolHeader,
			Body:   nodePoolBody,
		})
	}

	return tableFiles
}

// formatAuthorizedCIDRs formats the authorized CIDRs for display
func formatAuthorizedCIDRs(cluster GKEService.ClusterInfo) string {
	if cluster.PrivateCluster {
		return "Private endpoint"
	}
	if !cluster.MasterAuthorizedOnly {
		return "0.0.0.0/0 (any)"
	}
	if len(cluster.MasterAuthorizedCIDRs) == 0 {
		return "None configured"
	}
	// Check if 0.0.0.0/0 is in the list (effectively public)
	for _, cidr := range cluster.MasterAuthorizedCIDRs {
		if cidr == "0.0.0.0/0" {
			return "0.0.0.0/0 (any)"
		}
	}
	// Show all CIDRs
	return strings.Join(cluster.MasterAuthorizedCIDRs, ", ")
}

// formatGKEScopes formats OAuth scopes for display (extracts short names from URLs)
func formatGKEScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "-"
	}

	var shortScopes []string
	for _, scope := range scopes {
		// Extract the scope name from the URL
		// e.g., "https://www.googleapis.com/auth/cloud-platform" -> "cloud-platform"
		parts := strings.Split(scope, "/")
		if len(parts) > 0 {
			shortScopes = append(shortScopes, parts[len(parts)-1])
		}
	}
	return strings.Join(shortScopes, ", ")
}
