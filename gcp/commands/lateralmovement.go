package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
	FunctionsService "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	GKEService "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

// Module name constant
const GCP_LATERALMOVEMENT_MODULE_NAME string = "lateral-movement"

var GCPLateralMovementCommand = &cobra.Command{
	Use:     GCP_LATERALMOVEMENT_MODULE_NAME,
	Aliases: []string{"lateral", "pivot"},
	Short:   "Map lateral movement paths, credential theft vectors, and pivot opportunities",
	Long: `Identify lateral movement opportunities within and across GCP projects.

This module uses FoxMapper graph data for permission-based analysis combined with
direct enumeration of compute resources for token theft vectors.

Features:
- Maps service account impersonation chains (SA → SA → SA)
- Identifies token creator permissions (lateral movement via impersonation)
- Finds cross-project access paths
- Detects VM metadata abuse vectors
- Analyzes credential storage locations (secrets, environment variables)
- Generates exploitation commands for penetration testing

Prerequisites:
- Run 'foxmapper gcp graph create' for permission-based analysis

This module helps identify how an attacker could move laterally after gaining
initial access to a GCP environment.`,
	Run: runGCPLateralMovementCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

// LateralMovementPath represents a lateral movement opportunity
type LateralMovementPath struct {
	Source         string   // Starting point (principal or resource)
	SourceType     string   // Type of source (serviceAccount, user, compute_instance, etc.)
	Target         string   // Target resource/identity
	Method         string   // How the lateral movement is achieved
	Category       string   // Category of lateral movement
	Permissions    []string // Permissions required
	Description    string   // Human-readable description
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM, LOW
	ExploitCommand string   // Command to exploit
	ProjectID      string   // Project where this path exists
}

// ------------------------------
// Module Struct
// ------------------------------
type LateralMovementModule struct {
	gcpinternal.BaseGCPModule

	// Paths from enumeration
	ProjectPaths    map[string][]LateralMovementPath // projectID -> paths
	AllPaths        []LateralMovementPath            // All paths combined

	// FoxMapper findings
	FoxMapperFindings []foxmapperservice.LateralFinding // FoxMapper-based findings
	FoxMapperCache    *gcpinternal.FoxMapperCache

	// OrgCache for ancestry lookups
	OrgCache *gcpinternal.OrgCache

	// Loot
	LootMap map[string]map[string]*internal.LootFile // projectID -> loot files
	mu      sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type LateralMovementOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LateralMovementOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LateralMovementOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPLateralMovementCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_LATERALMOVEMENT_MODULE_NAME)
	if err != nil {
		return
	}

	module := &LateralMovementModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPaths:      make(map[string][]LateralMovementPath),
		AllPaths:          []LateralMovementPath{},
		FoxMapperFindings: []foxmapperservice.LateralFinding{},
		LootMap:           make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LateralMovementModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Mapping lateral movement paths...", GCP_LATERALMOVEMENT_MODULE_NAME)

	// Load OrgCache for ancestry lookups (needed for per-project filtering)
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)
	if m.OrgCache == nil || !m.OrgCache.IsPopulated() {
		diskCache, _, err := gcpinternal.LoadOrgCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			m.OrgCache = diskCache
		}
	}

	// Get FoxMapper cache from context or try to load it
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache == nil || !m.FoxMapperCache.IsPopulated() {
		// Try to load FoxMapper data (org from hierarchy if available)
		orgID := ""
		if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
			orgID = m.Hierarchy.Organizations[0].ID
		}
		m.FoxMapperCache = gcpinternal.TryLoadFoxMapper(orgID, m.ProjectIDs)
	}

	// Process each project for actual token theft vectors
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_LATERALMOVEMENT_MODULE_NAME, m.processProject)

	// Consolidate project paths
	for _, paths := range m.ProjectPaths {
		m.AllPaths = append(m.AllPaths, paths...)
	}

	// Analyze permission-based lateral movement using FoxMapper
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Analyzing permission-based lateral movement using FoxMapper...", GCP_LATERALMOVEMENT_MODULE_NAME)
		svc := m.FoxMapperCache.GetService()
		allFindings := svc.AnalyzeLateral("")

		// Filter findings to only include principals from specified projects
		m.FoxMapperFindings = m.filterFindingsByProjects(allFindings)

		if len(m.FoxMapperFindings) > 0 {
			logger.InfoM(fmt.Sprintf("Found %d permission-based lateral movement techniques", len(m.FoxMapperFindings)), GCP_LATERALMOVEMENT_MODULE_NAME)
		}
	} else {
		logger.InfoM("No FoxMapper data found - skipping permission-based analysis. Run 'foxmapper gcp graph create' for full analysis.", GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	// Check results
	hasResults := len(m.AllPaths) > 0 || len(m.FoxMapperFindings) > 0

	if !hasResults {
		logger.InfoM("No lateral movement paths found", GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	// Count by category for summary
	categoryCounts := make(map[string]int)
	for _, path := range m.AllPaths {
		categoryCounts[path.Category]++
	}

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s) from enumeration", len(m.AllPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)
	if len(m.FoxMapperFindings) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d permission-based lateral movement technique(s)", len(m.FoxMapperFindings)), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// filterFindingsByProjects filters FoxMapper findings to only include principals
// from the specified projects (via -p or -l flags) OR principals without a clear project
func (m *LateralMovementModule) filterFindingsByProjects(findings []foxmapperservice.LateralFinding) []foxmapperservice.LateralFinding {
	// Build a set of specified project IDs for fast lookup
	specifiedProjects := make(map[string]bool)
	for _, projectID := range m.ProjectIDs {
		specifiedProjects[projectID] = true
	}

	var filtered []foxmapperservice.LateralFinding

	for _, finding := range findings {
		var filteredPrincipals []foxmapperservice.PrincipalAccess
		for _, p := range finding.Principals {
			principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)
			// Include if: SA from specified project OR user/group (no project)
			if specifiedProjects[principalProject] || principalProject == "" {
				filteredPrincipals = append(filteredPrincipals, p)
			}
		}

		if len(filteredPrincipals) > 0 {
			filteredFinding := finding
			filteredFinding.Principals = filteredPrincipals
			filtered = append(filtered, filteredFinding)
		}
	}

	return filtered
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LateralMovementModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["lateral-movement-commands"] = &internal.LootFile{
			Name:     "lateral-movement-commands",
			Contents: "# Lateral Movement Exploit Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
}

// getLateralExploitCommand returns specific exploitation commands for a lateral movement permission
func getLateralExploitCommand(permission, principal, project string) string {
	commands := map[string]string{
		// Service Account Impersonation
		"iam.serviceAccounts.getAccessToken": "gcloud auth print-access-token --impersonate-service-account=TARGET_SA",
		"iam.serviceAccountKeys.create":      "gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA",
		"iam.serviceAccounts.signBlob":       "gcloud iam service-accounts sign-blob --iam-account=TARGET_SA input.txt output.sig",
		"iam.serviceAccounts.signJwt":        "# Sign JWT to impersonate SA\ngcloud iam service-accounts sign-jwt --iam-account=TARGET_SA claim.json signed.jwt",
		"iam.serviceAccounts.getOpenIdToken": "gcloud auth print-identity-token --impersonate-service-account=TARGET_SA",
		"iam.serviceAccounts.actAs":          "# actAs allows deploying resources with this SA\ngcloud run deploy SERVICE --service-account=TARGET_SA",

		// Compute Access
		"compute.instances.osLogin":                   "gcloud compute ssh INSTANCE --zone=ZONE --project=PROJECT",
		"compute.instances.setMetadata":               "gcloud compute instances add-metadata INSTANCE --zone=ZONE --metadata=ssh-keys=\"user:$(cat ~/.ssh/id_rsa.pub)\"",
		"compute.projects.setCommonInstanceMetadata":  "gcloud compute project-info add-metadata --metadata=ssh-keys=\"user:$(cat ~/.ssh/id_rsa.pub)\"",
		"compute.instances.getSerialPortOutput":       "gcloud compute instances get-serial-port-output INSTANCE --zone=ZONE",

		// GKE Access
		"container.clusters.getCredentials": "gcloud container clusters get-credentials CLUSTER --zone=ZONE --project=PROJECT",
		"container.pods.exec":               "kubectl exec -it POD -- /bin/sh",
		"container.pods.attach":             "kubectl attach -it POD",

		// Serverless
		"cloudfunctions.functions.create": "gcloud functions deploy FUNC --runtime=python311 --service-account=TARGET_SA --trigger-http",
		"cloudfunctions.functions.update": "gcloud functions deploy FUNC --service-account=TARGET_SA",
		"run.services.create":             "gcloud run deploy SERVICE --image=IMAGE --service-account=TARGET_SA",
		"run.services.update":             "gcloud run services update SERVICE --service-account=TARGET_SA",

		// IAM Policy Modification
		"resourcemanager.projects.setIamPolicy":       "gcloud projects add-iam-policy-binding PROJECT --member=user:ATTACKER --role=roles/owner",
		"resourcemanager.folders.setIamPolicy":        "gcloud resource-manager folders add-iam-policy-binding FOLDER_ID --member=user:ATTACKER --role=roles/owner",
		"resourcemanager.organizations.setIamPolicy":  "gcloud organizations add-iam-policy-binding ORG_ID --member=user:ATTACKER --role=roles/owner",
	}

	cmd, ok := commands[permission]
	if !ok {
		return fmt.Sprintf("# No specific command for %s - check gcloud documentation", permission)
	}

	if project != "" && project != "-" {
		cmd = strings.ReplaceAll(cmd, "PROJECT", project)
	}

	return cmd
}

// generatePlaybookForProject generates a loot file specific to a project
func (m *LateralMovementModule) generatePlaybookForProject(projectID string) *internal.LootFile {
	var sb strings.Builder
	sb.WriteString("# GCP Lateral Movement Commands\n")
	sb.WriteString(fmt.Sprintf("# Project: %s\n", projectID))
	sb.WriteString("# Generated by CloudFox\n")
	sb.WriteString("# WARNING: Only use with proper authorization\n\n")

	// Token theft vectors for this project
	if paths, ok := m.ProjectPaths[projectID]; ok && len(paths) > 0 {
		sb.WriteString("# === TOKEN THEFT VECTORS ===\n\n")

		for _, path := range paths {
			sb.WriteString(fmt.Sprintf("# =============================================================================\n"+
				"# %s -> %s\n"+
				"# =============================================================================\n", path.Source, path.Target))
			sb.WriteString(fmt.Sprintf("# Method: %s\n", path.Method))
			sb.WriteString(fmt.Sprintf("# Category: %s\n", path.Category))
			if path.ExploitCommand != "" {
				sb.WriteString(path.ExploitCommand)
				sb.WriteString("\n\n")
			}
		}
	}

	// Permission-based findings - filter to this project's principals + users/groups
	if len(m.FoxMapperFindings) > 0 {
		hasFindings := false

		for _, finding := range m.FoxMapperFindings {
			var relevantPrincipals []foxmapperservice.PrincipalAccess

			for _, p := range finding.Principals {
				principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)
				if principalProject == projectID || principalProject == "" {
					relevantPrincipals = append(relevantPrincipals, p)
				}
			}

			if len(relevantPrincipals) == 0 {
				continue
			}

			if !hasFindings {
				sb.WriteString("# === PERMISSION-BASED LATERAL MOVEMENT ===\n\n")
				hasFindings = true
			}

			sb.WriteString(fmt.Sprintf("# =============================================================================\n"+
				"# %s (%s)\n"+
				"# =============================================================================\n", finding.Permission, finding.Category))
			sb.WriteString(fmt.Sprintf("# %s\n\n", finding.Description))

			for _, p := range relevantPrincipals {
				project := extractProjectFromPrincipal(p.Principal, m.OrgCache)
				if project == "" {
					project = projectID
				}

				principalType := p.MemberType
				if principalType == "" {
					if p.IsServiceAccount {
						principalType = "serviceAccount"
					} else {
						principalType = "user"
					}
				}

				sb.WriteString(fmt.Sprintf("# %s (%s)\n", p.Principal, principalType))

				if p.IsServiceAccount {
					sb.WriteString(fmt.Sprintf("# Impersonate first:\ngcloud config set auth/impersonate_service_account %s\n\n", p.Principal))
				}

				cmd := getLateralExploitCommand(finding.Permission, p.Principal, project)
				sb.WriteString(cmd)
				sb.WriteString("\n\n")

				if p.IsServiceAccount {
					sb.WriteString("# Reset impersonation when done:\n# gcloud config unset auth/impersonate_service_account\n\n")
				}
			}
		}
	}

	contents := sb.String()
	if contents == fmt.Sprintf("# GCP Lateral Movement Commands\n# Project: %s\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n", projectID) {
		return nil
	}

	return &internal.LootFile{
		Name:     "lateral-movement-commands",
		Contents: contents,
	}
}

func (m *LateralMovementModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing lateral movement paths in project: %s", projectID), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	// 1. Find impersonation chains
	m.findImpersonationChains(ctx, projectID, logger)

	// 2. Find token theft vectors (compute instances, functions, etc.)
	m.findTokenTheftVectors(ctx, projectID, logger)
}

// findImpersonationChains finds service account impersonation paths
func (m *LateralMovementModule) findImpersonationChains(ctx context.Context, projectID string, logger internal.Logger) {
	iamService := IAMService.New()

	// Get all service accounts (without keys - not needed for impersonation analysis)
	serviceAccounts, err := iamService.ServiceAccountsBasic(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
			fmt.Sprintf("Could not get service accounts in project %s", projectID))
		return
	}

	// For each SA, check who can impersonate it
	for _, sa := range serviceAccounts {
		impersonationInfo, err := iamService.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
		if err != nil {
			continue
		}

		// Token creators can impersonate
		for _, creator := range impersonationInfo.TokenCreators {
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			riskLevel := "HIGH"
			if impersonationInfo.RiskLevel == "CRITICAL" {
				riskLevel = "CRITICAL"
			}

			path := LateralMovementPath{
				Source:      creator,
				SourceType:  shared.GetPrincipalType(creator),
				Target:      sa.Email,
				Method:      "Impersonate (Get Token)",
				Category:    "Service Account Impersonation",
				Permissions: []string{"iam.serviceAccounts.getAccessToken"},
				Description: fmt.Sprintf("%s can impersonate %s", creator, sa.Email),
				RiskLevel:   riskLevel,
				ExploitCommand: fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", sa.Email),
				ProjectID:   projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}

		// Key creators can create persistent access
		for _, creator := range impersonationInfo.KeyCreators {
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			path := LateralMovementPath{
				Source:      creator,
				SourceType:  shared.GetPrincipalType(creator),
				Target:      sa.Email,
				Method:      "Create Key",
				Category:    "Service Account Key Creation",
				Permissions: []string{"iam.serviceAccountKeys.create"},
				Description: fmt.Sprintf("%s can create keys for %s", creator, sa.Email),
				RiskLevel:   "CRITICAL",
				ExploitCommand: fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", sa.Email),
				ProjectID:   projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}
}

// findTokenTheftVectors finds compute resources where tokens can be stolen
func (m *LateralMovementModule) findTokenTheftVectors(ctx context.Context, projectID string, logger internal.Logger) {
	// Find Compute Engine instances with service accounts
	m.findComputeInstanceVectors(ctx, projectID, logger)

	// Find Cloud Functions with service accounts
	m.findCloudFunctionVectors(ctx, projectID, logger)

	// Find Cloud Run services with service accounts
	m.findCloudRunVectors(ctx, projectID, logger)

	// Find GKE clusters with node service accounts
	m.findGKEVectors(ctx, projectID, logger)
}

// findComputeInstanceVectors finds compute instances where tokens can be stolen via metadata server
func (m *LateralMovementModule) findComputeInstanceVectors(ctx context.Context, projectID string, logger internal.Logger) {
	computeService := ComputeEngineService.New()

	instances, err := computeService.Instances(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get compute instances in project %s", projectID))
		}
		return
	}

	for _, instance := range instances {
		if len(instance.ServiceAccounts) == 0 {
			continue
		}

		for _, sa := range instance.ServiceAccounts {
			if sa.Email == "" {
				continue
			}

			path := LateralMovementPath{
				Source:      instance.Name,
				SourceType:  "compute_instance",
				Target:      sa.Email,
				Method:      "Steal Token (Metadata)",
				Category:    "Compute Instance Token Theft",
				Permissions: []string{"compute.instances.get", "compute.instances.osLogin"},
				Description: fmt.Sprintf("Access to instance %s allows stealing token for %s", instance.Name, sa.Email),
				RiskLevel:   "HIGH",
				ExploitCommand: fmt.Sprintf(`# SSH into instance and steal token
gcloud compute ssh %s --zone=%s --project=%s --command='curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'`,
					instance.Name, instance.Zone, projectID),
				ProjectID: projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}
}

// findCloudFunctionVectors finds Cloud Functions where tokens can be stolen
func (m *LateralMovementModule) findCloudFunctionVectors(ctx context.Context, projectID string, logger internal.Logger) {
	functionsService := FunctionsService.New()

	functions, err := functionsService.Functions(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get Cloud Functions in project %s", projectID))
		}
		return
	}

	for _, fn := range functions {
		if fn.ServiceAccount == "" {
			continue
		}

		exploitCmd := fmt.Sprintf(`# Deploy function with target SA to steal token
# Requires: cloudfunctions.functions.create + iam.serviceAccounts.actAs
gcloud functions deploy token-theft-poc \
    --gen2 --runtime=python311 --region=%s \
    --entry-point=steal_token --trigger-http --allow-unauthenticated \
    --service-account=%s --project=%s`,
			fn.Region, fn.ServiceAccount, projectID)

		path := LateralMovementPath{
			Source:      fn.Name,
			SourceType:  "cloud_function",
			Target:      fn.ServiceAccount,
			Method:      "Steal Token (Function)",
			Category:    "Cloud Function Token Theft",
			Permissions: []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"},
			Description: fmt.Sprintf("Cloud Function %s runs with SA %s", fn.Name, fn.ServiceAccount),
			RiskLevel:   "HIGH",
			ExploitCommand: exploitCmd,
			ProjectID:   projectID,
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// findCloudRunVectors finds Cloud Run services where tokens can be stolen
func (m *LateralMovementModule) findCloudRunVectors(ctx context.Context, projectID string, logger internal.Logger) {
	cloudRunService := CloudRunService.New()

	services, err := cloudRunService.Services(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get Cloud Run services in project %s", projectID))
		}
		return
	}

	for _, svc := range services {
		if svc.ServiceAccount == "" {
			continue
		}

		exploitCmd := fmt.Sprintf(`# Deploy Cloud Run service with target SA to steal token
# Requires: run.services.create + iam.serviceAccounts.actAs
gcloud run deploy token-theft-poc \
    --image gcr.io/%s/token-theft-poc \
    --region=%s --service-account=%s \
    --allow-unauthenticated --project=%s`,
			projectID, svc.Region, svc.ServiceAccount, projectID)

		path := LateralMovementPath{
			Source:      svc.Name,
			SourceType:  "cloud_run",
			Target:      svc.ServiceAccount,
			Method:      "Steal Token (Container)",
			Category:    "Cloud Run Token Theft",
			Permissions: []string{"run.services.create", "iam.serviceAccounts.actAs"},
			Description: fmt.Sprintf("Cloud Run service %s runs with SA %s", svc.Name, svc.ServiceAccount),
			RiskLevel:   "HIGH",
			ExploitCommand: exploitCmd,
			ProjectID:   projectID,
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// findGKEVectors finds GKE clusters/node pools where tokens can be stolen
func (m *LateralMovementModule) findGKEVectors(ctx context.Context, projectID string, logger internal.Logger) {
	gkeService := GKEService.New()

	clusters, nodePools, err := gkeService.Clusters(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get GKE clusters in project %s", projectID))
		}
		return
	}

	// Track cluster SAs to avoid duplicates in node pools
	clusterSAs := make(map[string]string)

	for _, cluster := range clusters {
		if cluster.NodeServiceAccount != "" {
			clusterSAs[cluster.Name] = cluster.NodeServiceAccount

			var exploitCmd string
			if cluster.WorkloadIdentity != "" {
				exploitCmd = fmt.Sprintf(`# Cluster uses Workload Identity - tokens are pod-specific
gcloud container clusters get-credentials %s --location=%s --project=%s
kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
					cluster.Name, cluster.Location, projectID)
			} else {
				exploitCmd = fmt.Sprintf(`# Cluster uses node SA - all pods can access node SA
gcloud container clusters get-credentials %s --location=%s --project=%s
kubectl exec -it <pod> -- curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"`,
					cluster.Name, cluster.Location, projectID)
			}

			path := LateralMovementPath{
				Source:      cluster.Name,
				SourceType:  "gke_cluster",
				Target:      cluster.NodeServiceAccount,
				Method:      "Steal Token (Pod)",
				Category:    "GKE Cluster Token Theft",
				Permissions: []string{"container.clusters.getCredentials", "container.pods.exec"},
				Description: fmt.Sprintf("GKE cluster %s uses node SA %s", cluster.Name, cluster.NodeServiceAccount),
				RiskLevel:   "HIGH",
				ExploitCommand: exploitCmd,
				ProjectID:   projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}

	// Process node pools with different SAs than their cluster
	for _, np := range nodePools {
		clusterSA := clusterSAs[np.ClusterName]
		if np.ServiceAccount == "" || np.ServiceAccount == clusterSA {
			continue
		}

		exploitCmd := fmt.Sprintf(`# Node pool %s uses specific SA
gcloud container clusters get-credentials %s --location=%s --project=%s
# Exec into pod running on this node pool and steal token`,
			np.Name, np.ClusterName, np.Location, projectID)

		path := LateralMovementPath{
			Source:      fmt.Sprintf("%s/%s", np.ClusterName, np.Name),
			SourceType:  "gke_nodepool",
			Target:      np.ServiceAccount,
			Method:      "Steal Token (Pod)",
			Category:    "GKE Node Pool Token Theft",
			Permissions: []string{"container.clusters.getCredentials", "container.pods.exec"},
			Description: fmt.Sprintf("GKE node pool %s/%s uses SA %s", np.ClusterName, np.Name, np.ServiceAccount),
			RiskLevel:   "HIGH",
			ExploitCommand: exploitCmd,
			ProjectID:   projectID,
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LateralMovementModule) addPathToLoot(path LateralMovementPath, projectID string) {
	lootFile := m.LootMap[projectID]["lateral-movement-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# %s -> %s\n"+
			"# =============================================================================\n"+
			"# Method: %s\n"+
			"# Category: %s\n"+
			"# Source: %s (%s)\n"+
			"# Target: %s\n"+
			"# Permissions: %s\n"+
			"%s\n\n",
		path.Source, path.Target,
		path.Method,
		path.Category,
		path.Source, path.SourceType,
		path.Target,
		strings.Join(path.Permissions, ", "),
		path.ExploitCommand,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LateralMovementModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *LateralMovementModule) getHeader() []string {
	return []string{
		"Project",
		"Source",
		"Source Type",
		"Target",
		"Method",
		"Category",
		"Risk Level",
	}
}

func (m *LateralMovementModule) getFoxMapperHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Principal Type",
		"Principal",
		"Category",
		"Permission",
		"Description",
	}
}

func (m *LateralMovementModule) pathsToTableBody(paths []LateralMovementPath) [][]string {
	var body [][]string
	for _, path := range paths {
		body = append(body, []string{
			m.GetProjectName(path.ProjectID),
			path.Source,
			path.SourceType,
			path.Target,
			path.Method,
			path.Category,
			path.RiskLevel,
		})
	}
	return body
}

// foxMapperFindingsForProject returns findings for a specific project
// Includes: SAs from that project + users/groups (which can access any project)
// Also filters by scope: only org/folder/project findings in the project's hierarchy
func (m *LateralMovementModule) foxMapperFindingsForProject(projectID string) [][]string {
	var body [][]string

	// Get ancestor folders and org for filtering
	var ancestorFolders []string
	var projectOrgID string
	if m.OrgCache != nil && m.OrgCache.IsPopulated() {
		ancestorFolders = m.OrgCache.GetProjectAncestorFolders(projectID)
		projectOrgID = m.OrgCache.GetProjectOrgID(projectID)
	}
	ancestorFolderSet := make(map[string]bool)
	for _, f := range ancestorFolders {
		ancestorFolderSet[f] = true
	}

	for _, f := range m.FoxMapperFindings {
		for _, p := range f.Principals {
			principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)

			// Include if: SA from this project OR user/group (no project)
			if principalProject != projectID && principalProject != "" {
				continue
			}

			// Filter by scope hierarchy
			if !m.scopeMatchesProject(p.ScopeType, p.ScopeID, projectID, projectOrgID, ancestorFolderSet) {
				continue
			}

			principalType := p.MemberType
			if principalType == "" {
				if p.IsServiceAccount {
					principalType = "serviceAccount"
				} else {
					principalType = "user"
				}
			}

			scopeType := p.ScopeType
			if scopeType == "" {
				scopeType = "-"
			}
			scopeID := p.ScopeID
			if scopeID == "" {
				scopeID = "-"
			}

			body = append(body, []string{
				scopeType,
				scopeID,
				principalType,
				p.Principal,
				f.Category,
				f.Permission,
				f.Description,
			})
		}
	}
	return body
}

// foxMapperFindingsToTableBody returns all findings (for flat output)
func (m *LateralMovementModule) foxMapperFindingsToTableBody() [][]string {
	var body [][]string
	for _, f := range m.FoxMapperFindings {
		for _, p := range f.Principals {
			principalType := p.MemberType
			if principalType == "" {
				if p.IsServiceAccount {
					principalType = "serviceAccount"
				} else {
					principalType = "user"
				}
			}

			scopeType := p.ScopeType
			if scopeType == "" {
				scopeType = "-"
			}
			scopeID := p.ScopeID
			if scopeID == "" {
				scopeID = "-"
			}

			body = append(body, []string{
				scopeType,
				scopeID,
				principalType,
				p.Principal,
				f.Category,
				f.Permission,
				f.Description,
			})
		}
	}
	return body
}

func (m *LateralMovementModule) buildTablesForProject(projectID string) []internal.TableFile {
	// No longer outputting the old lateral-movement table
	// All findings are now in lateral-movement-permissions
	return []internal.TableFile{}
}

// scopeMatchesProject checks if a scope (org/folder/project) is in the hierarchy for a project
func (m *LateralMovementModule) scopeMatchesProject(scopeType, scopeID, projectID, projectOrgID string, ancestorFolderSet map[string]bool) bool {
	if scopeType == "" || scopeID == "" {
		// No scope info - include by default
		return true
	}

	switch scopeType {
	case "project":
		return scopeID == projectID
	case "organization":
		if projectOrgID != "" {
			return scopeID == projectOrgID
		}
		// No org info - include by default
		return true
	case "folder":
		if len(ancestorFolderSet) > 0 {
			return ancestorFolderSet[scopeID]
		}
		// No folder info - include by default
		return true
	case "resource":
		// Resource-level - include by default
		return true
	default:
		return true
	}
}

func (m *LateralMovementModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		FolderLevelData:  make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Process each specified project
	for _, projectID := range m.ProjectIDs {
		var tableFiles []internal.TableFile

		// Add FoxMapper findings table for this project (the only table now)
		foxMapperBody := m.foxMapperFindingsForProject(projectID)
		if len(foxMapperBody) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "lateral-movement-permissions",
				Header: m.getFoxMapperHeader(),
				Body:   foxMapperBody,
			})
		}

		// Add project-specific playbook (only one loot file per project)
		var lootFiles []internal.LootFile
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil && playbook.Contents != "" {
			lootFiles = append(lootFiles, *playbook)
		}

		// Always add all specified projects to output
		outputData.ProjectLevelData[projectID] = LateralMovementOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
	}
}

func (m *LateralMovementModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := []internal.TableFile{}

	// Only output the permissions table (not the old lateral-movement table)
	if len(m.FoxMapperFindings) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-movement-permissions",
			Header: m.getFoxMapperHeader(),
			Body:   m.foxMapperFindingsToTableBody(),
		})
	}

	// Add per-project playbooks
	var lootFiles []internal.LootFile
	for _, projectID := range m.ProjectIDs {
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil && playbook.Contents != "" {
			playbook.Name = fmt.Sprintf("lateral-movement-commands-%s", projectID)
			lootFiles = append(lootFiles, *playbook)
		}
	}

	output := LateralMovementOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
