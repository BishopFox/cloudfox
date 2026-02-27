package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gkeservice "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	iam "google.golang.org/api/iam/v1"
)

var GCPWorkloadIdentityCommand = &cobra.Command{
	Use:     globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
	Aliases: []string{"wi", "gke-identity", "workload-id"},
	Short:   "Enumerate GKE Workload Identity (K8s SA -> GCP SA bindings)",
	Long: `Enumerate GKE Workload Identity configurations and K8s-to-GCP service account bindings.

Features:
- Lists GKE clusters with Workload Identity enabled
- Shows Kubernetes service accounts bound to GCP service accounts
- Identifies privilege escalation paths through Workload Identity
- Maps namespace/service account to GCP permissions
- Detects overly permissive bindings

Security Considerations:
- K8s pods with Workload Identity inherit all permissions of the bound GCP SA
- High-privilege GCP SAs bound to K8s SAs are prime escalation targets
- Any pod in the namespace/SA can assume the GCP identity

TIP: Run 'identity-federation' to enumerate external identity federation (GitHub Actions, AWS, GitLab CI, etc.).
TIP: Run 'gke' to see full cluster security configuration and node pool details.
TIP: Run foxmapper first to populate the Attack Paths column with privesc/exfil/lateral movement analysis.`,
	Run: runGCPWorkloadIdentityCommand,
}

// WorkloadIdentityBinding represents a binding between K8s SA and GCP SA
type WorkloadIdentityBinding struct {
	ProjectID         string   `json:"projectId"`
	ClusterName       string   `json:"clusterName"`
	ClusterLocation   string   `json:"clusterLocation"`
	WorkloadPool      string   `json:"workloadPool"`
	KubernetesNS      string   `json:"kubernetesNamespace"`
	KubernetesSA      string   `json:"kubernetesServiceAccount"`
	GCPServiceAccount string   `json:"gcpServiceAccount"`
	GCPSARoles        []string `json:"gcpServiceAccountRoles"`
	IsHighPrivilege   bool     `json:"isHighPrivilege"`
	BindingType       string   `json:"bindingType"` // "workloadIdentityUser" or "other"
}

// ClusterWorkloadIdentity represents a cluster's workload identity configuration
type ClusterWorkloadIdentity struct {
	ProjectID           string `json:"projectId"`
	ClusterName         string `json:"clusterName"`
	Location            string `json:"location"`
	WorkloadPoolEnabled bool   `json:"workloadPoolEnabled"`
	WorkloadPool        string `json:"workloadPool"`
	NodePoolsWithWI     int    `json:"nodePoolsWithWI"`
	TotalNodePools      int    `json:"totalNodePools"`
}

// ------------------------------
// Module Struct
// ------------------------------
type WorkloadIdentityModule struct {
	gcpinternal.BaseGCPModule

	ProjectClusters map[string][]ClusterWorkloadIdentity    // projectID -> clusters
	ProjectBindings map[string][]WorkloadIdentityBinding    // projectID -> bindings
	LootMap         map[string]map[string]*internal.LootFile // projectID -> loot files
	FoxMapperCache  *gcpinternal.FoxMapperCache
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type WorkloadIdentityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o WorkloadIdentityOutput) TableFiles() []internal.TableFile { return o.Table }
func (o WorkloadIdentityOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPWorkloadIdentityCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	if err != nil {
		return
	}

	module := &WorkloadIdentityModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectClusters: make(map[string][]ClusterWorkloadIdentity),
		ProjectBindings: make(map[string][]WorkloadIdentityBinding),
		LootMap:         make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *WorkloadIdentityModule) Execute(ctx context.Context, logger internal.Logger) {
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper cache for attack path analysis", globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME, m.processProject)

	allClusters := m.getAllClusters()
	allBindings := m.getAllBindings()

	if len(allClusters) == 0 {
		logger.InfoM("No GKE clusters found", globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		return
	}

	wiEnabled := 0
	for _, c := range allClusters {
		if c.WorkloadPoolEnabled {
			wiEnabled++
		}
	}
	logger.SuccessM(fmt.Sprintf("Found %d GKE cluster(s) (%d with Workload Identity), %d K8s->GCP binding(s)",
		len(allClusters), wiEnabled, len(allBindings)), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllClusters returns all clusters from all projects
func (m *WorkloadIdentityModule) getAllClusters() []ClusterWorkloadIdentity {
	var all []ClusterWorkloadIdentity
	for _, clusters := range m.ProjectClusters {
		all = append(all, clusters...)
	}
	return all
}

// getAllBindings returns all bindings from all projects
func (m *WorkloadIdentityModule) getAllBindings() []WorkloadIdentityBinding {
	var all []WorkloadIdentityBinding
	for _, bindings := range m.ProjectBindings {
		all = append(all, bindings...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *WorkloadIdentityModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating GKE Workload Identity in project: %s", projectID), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}

	gkeSvc := gkeservice.New()
	clusters, _, err := gkeSvc.Clusters(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate GKE clusters in project %s", projectID))
		return
	}

	var clusterInfos []ClusterWorkloadIdentity
	var bindings []WorkloadIdentityBinding

	for _, cluster := range clusters {
		cwi := ClusterWorkloadIdentity{
			ProjectID:      projectID,
			ClusterName:    cluster.Name,
			Location:       cluster.Location,
			TotalNodePools: cluster.NodePoolCount,
		}

		if cluster.WorkloadIdentity != "" {
			cwi.WorkloadPoolEnabled = true
			cwi.WorkloadPool = cluster.WorkloadIdentity
		}

		if cwi.WorkloadPoolEnabled {
			cwi.NodePoolsWithWI = cwi.TotalNodePools
		}

		clusterInfos = append(clusterInfos, cwi)

		// If Workload Identity is enabled, look for bindings
		if cwi.WorkloadPoolEnabled {
			clusterBindings := m.findWorkloadIdentityBindings(ctx, projectID, cluster.Name, cluster.Location, cwi.WorkloadPool, logger)
			bindings = append(bindings, clusterBindings...)
		}
	}

	m.mu.Lock()
	m.ProjectClusters[projectID] = clusterInfos
	m.ProjectBindings[projectID] = bindings

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["workloadidentity-commands"] = &internal.LootFile{
			Name:     "workloadidentity-commands",
			Contents: "# Workload Identity Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	for _, cwi := range clusterInfos {
		m.addClusterToLoot(projectID, cwi)
	}
	for _, binding := range bindings {
		m.addBindingToLoot(projectID, binding)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d GKE cluster(s), %d K8s binding(s) in project %s",
			len(clusterInfos), len(bindings), projectID), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}
}

// findWorkloadIdentityBindings finds all IAM bindings that grant workloadIdentityUser role
// by querying the IAM policy ON each service account (resource-level, not project-level)
func (m *WorkloadIdentityModule) findWorkloadIdentityBindings(ctx context.Context, projectID, clusterName, location, workloadPool string, logger internal.Logger) []WorkloadIdentityBinding {
	var bindings []WorkloadIdentityBinding

	iamSvc := IAMService.New()
	serviceAccounts, err := iamSvc.ServiceAccountsBasic(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			fmt.Sprintf("Could not list service accounts in project %s", projectID))
		return bindings
	}

	// Get an IAM service client for SA-level policy queries
	iamService, err := iam.NewService(ctx)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			"Could not create IAM service client")
		return bindings
	}

	for _, sa := range serviceAccounts {
		// Get the IAM policy ON the service account resource (not project-level)
		saResource := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, sa.Email)
		policy, err := iamService.Projects.ServiceAccounts.GetIamPolicy(saResource).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			if binding.Role == "roles/iam.workloadIdentityUser" {
				for _, member := range binding.Members {
					if strings.HasPrefix(member, "serviceAccount:") && strings.Contains(member, ".svc.id.goog") {
						ns, ksa := parseWorkloadIdentityMember(member)
						if ns != "" && ksa != "" {
							wib := WorkloadIdentityBinding{
								ProjectID:         projectID,
								ClusterName:       clusterName,
								ClusterLocation:   location,
								WorkloadPool:      workloadPool,
								KubernetesNS:      ns,
								KubernetesSA:      ksa,
								GCPServiceAccount: sa.Email,
								GCPSARoles:        sa.Roles,
								BindingType:       "workloadIdentityUser",
							}
							wib.IsHighPrivilege = isHighPrivilegeServiceAccount(sa)
							bindings = append(bindings, wib)
						}
					}
				}
			}
		}
	}

	return bindings
}

// parseWorkloadIdentityMember parses a workload identity member string
// Format: serviceAccount:[PROJECT_ID].svc.id.goog[NAMESPACE/KSA_NAME]
func parseWorkloadIdentityMember(member string) (namespace, serviceAccount string) {
	member = strings.TrimPrefix(member, "serviceAccount:")

	bracketStart := strings.Index(member, "[")
	bracketEnd := strings.Index(member, "]")

	if bracketStart == -1 || bracketEnd == -1 || bracketEnd <= bracketStart {
		return "", ""
	}

	nsAndSA := member[bracketStart+1 : bracketEnd]
	parts := strings.Split(nsAndSA, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return "", ""
}

// isHighPrivilegeServiceAccount checks if a service account has high-privilege roles
func isHighPrivilegeServiceAccount(sa IAMService.ServiceAccountInfo) bool {
	highPrivRoles := map[string]bool{
		"roles/owner":                           true,
		"roles/editor":                          true,
		"roles/iam.serviceAccountAdmin":         true,
		"roles/iam.serviceAccountKeyAdmin":      true,
		"roles/iam.serviceAccountTokenCreator":  true,
		"roles/resourcemanager.projectIamAdmin": true,
		"roles/compute.admin":                   true,
		"roles/container.admin":                 true,
		"roles/secretmanager.admin":             true,
		"roles/storage.admin":                   true,
	}

	for _, role := range sa.Roles {
		if highPrivRoles[role] {
			return true
		}
	}
	return false
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *WorkloadIdentityModule) addClusterToLoot(projectID string, cwi ClusterWorkloadIdentity) {
	lootFile := m.LootMap[projectID]["workloadidentity-commands"]
	if lootFile == nil {
		return
	}
	if cwi.WorkloadPoolEnabled {
		lootFile.Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# GKE CLUSTER: %s\n"+
				"# =============================================================================\n"+
				"# Location: %s\n"+
				"# Workload Pool: %s\n"+
				"# Node Pools with WI: %d/%d\n\n"+
				"# === ENUMERATION COMMANDS ===\n\n"+
				"# Get cluster credentials:\n"+
				"gcloud container clusters get-credentials %s --zone=%s --project=%s\n\n",
			cwi.ClusterName,
			cwi.Location,
			cwi.WorkloadPool,
			cwi.NodePoolsWithWI,
			cwi.TotalNodePools,
			cwi.ClusterName,
			cwi.Location,
			cwi.ProjectID,
		)
	}
}

func (m *WorkloadIdentityModule) addBindingToLoot(projectID string, binding WorkloadIdentityBinding) {
	lootFile := m.LootMap[projectID]["workloadidentity-commands"]
	if lootFile == nil {
		return
	}
	highPriv := ""
	if binding.IsHighPrivilege {
		highPriv = " [HIGH PRIVILEGE]"
	}

	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# K8s SA BINDING: %s/%s -> %s%s\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Cluster: %s (%s)\n",
		binding.KubernetesNS,
		binding.KubernetesSA,
		binding.GCPServiceAccount,
		highPriv,
		binding.ClusterName,
		binding.ClusterLocation,
	)

	if binding.IsHighPrivilege && len(binding.GCPSARoles) > 0 {
		lootFile.Contents += fmt.Sprintf(
			"# GCP SA Roles: %s\n",
			strings.Join(binding.GCPSARoles, ", "),
		)
	}

	lootFile.Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"# To exploit, create pod with this service account:\n"+
			"# kubectl run exploit-pod --image=google/cloud-sdk:slim --serviceaccount=%s -n %s -- sleep infinity\n"+
			"# kubectl exec -it exploit-pod -n %s -- gcloud auth list\n\n",
		binding.KubernetesSA,
		binding.KubernetesNS,
		binding.KubernetesNS,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *WorkloadIdentityModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *WorkloadIdentityModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID := range m.ProjectClusters {
		tables := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = WorkloadIdentityOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *WorkloadIdentityModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allClusters := m.getAllClusters()
	allBindings := m.getAllBindings()

	tables := m.buildTables(allClusters, allBindings)

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := WorkloadIdentityOutput{
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
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			"Could not write output")
	}
}

// buildTablesForProject builds tables for a specific project
func (m *WorkloadIdentityModule) buildTablesForProject(projectID string) []internal.TableFile {
	clusters := m.ProjectClusters[projectID]
	bindings := m.ProjectBindings[projectID]
	return m.buildTables(clusters, bindings)
}

// buildTables builds all tables from the given data
func (m *WorkloadIdentityModule) buildTables(
	clusters []ClusterWorkloadIdentity,
	bindings []WorkloadIdentityBinding,
) []internal.TableFile {
	var tables []internal.TableFile

	// Clusters table
	clustersHeader := []string{
		"Project",
		"Cluster",
		"Location",
		"Cluster WI Enabled",
		"Workload Pool",
		"Node Pools WI Enabled",
	}

	var clustersBody [][]string
	for _, cwi := range clusters {
		wiEnabled := "No"
		if cwi.WorkloadPoolEnabled {
			wiEnabled = "Yes"
		}
		workloadPool := "-"
		if cwi.WorkloadPool != "" {
			workloadPool = cwi.WorkloadPool
		}

		nodePoolsWI := fmt.Sprintf("%d of %d", cwi.NodePoolsWithWI, cwi.TotalNodePools)

		clustersBody = append(clustersBody, []string{
			m.GetProjectName(cwi.ProjectID),
			cwi.ClusterName,
			cwi.Location,
			wiEnabled,
			workloadPool,
			nodePoolsWI,
		})
	}

	if len(clustersBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "workload-identity-clusters",
			Header: clustersHeader,
			Body:   clustersBody,
		})
	}

	// Bindings table
	bindingsHeader := []string{
		"Project",
		"Cluster",
		"K8s Namespace",
		"K8s Service Account",
		"GCP Service Account",
		"High Privilege SA",
		"SA Attack Paths",
	}

	var bindingsBody [][]string
	for _, binding := range bindings {
		highPriv := "No"
		if binding.IsHighPrivilege {
			highPriv = "Yes"
		}

		attackPaths := gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, binding.GCPServiceAccount)

		bindingsBody = append(bindingsBody, []string{
			m.GetProjectName(binding.ProjectID),
			binding.ClusterName,
			binding.KubernetesNS,
			binding.KubernetesSA,
			binding.GCPServiceAccount,
			highPriv,
			attackPaths,
		})
	}

	if len(bindingsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "workload-identity-bindings",
			Header: bindingsHeader,
			Body:   bindingsBody,
		})
	}

	return tables
}
