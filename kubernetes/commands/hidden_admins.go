package commands

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	attackpathservice "github.com/BishopFox/cloudfox/kubernetes/services/attackpathService"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
)

var HiddenAdminsCmd = &cobra.Command{
	Use:   "hidden-admins",
	Short: "Enumerate entities with IAM/RBAC escalation permissions",
	Long: `
Identify hidden administrators with IAM/RBAC escalation capabilities. This includes:
  - Membership in system:masters group
  - Cluster-admin or admin role bindings
  - RBAC modification (create/update Roles, ClusterRoles, RoleBindings, ClusterRoleBindings)
  - Impersonation rights (users, groups, service accounts)
  - Certificate approval (CSR approval - create new cluster identities)
  - RBAC aggregation roles (dynamically expandable permissions)

For other privilege escalation paths (secrets, pod creation, exec, webhooks, nodes),
use the 'privesc' command.

Outputs detailed findings and attack paths:
  cloudfox kubernetes hidden-admins`,
	Run: ListHiddenAdmins,
}

type HiddenAdminFinding struct {
	Namespace      string
	Entity         string
	EntityType     string
	Scope          string
	DangerousPerms string
	Source         string
	CloudIAM       string // AWS/GCP/Azure IAM role
	ActivePods     int    // Number of pods using this SA
	IsDefault      bool   // Is this the default SA?
	IsWildcard     bool   // Wildcard group binding
}

type AttackPath struct {
	StartEntity string
	EntityType  string
	Steps       []string
	EndGoal     string
	Feasibility string // "Immediate", "Requires-Enum", "Complex"
}

type HiddenAdminsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

// Built-in dangerous roles
var dangerousBuiltInRoles = map[string]bool{
	"cluster-admin":                           true,
	"admin":                                   true,
	"edit":                                    true,
	"system:masters":                          true,
	"system:controller:deployment-controller": true,
	"system:controller:replicaset-controller": true,
	"system:controller:daemon-set-controller": true,
	"system:controller:job-controller":        true,
	"system:node":                             true,
	"system:node-proxier":                     true,
	"system:kube-controller-manager":          true,
	"system:kube-scheduler":                   true,
}

func (h HiddenAdminsOutput) TableFiles() []internal.TableFile {
	return h.Table
}

// appendUniqueHA appends a string to a slice only if it doesn't already exist (hidden-admins specific)
func appendUniqueHA(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}


// isIAMRelatedRule checks if a rule grants IAM/RBAC escalation permissions
// This is specific to hidden-admins and excludes privesc paths like pod creation, secrets, etc.
// Uses the centralized attackpathService for detection.
func isIAMRelatedRule(rule rbacv1.PolicyRule) bool {
	return attackpathservice.IsHiddenAdminRule(rule)
}

// getIAMRiskDescription returns a human-readable description of IAM/RBAC risks
// Uses the centralized attackpathService for detection.
func getIAMRiskDescription(rule rbacv1.PolicyRule) string {
	return attackpathservice.GetHiddenAdminRiskDescription(rule)
}

func (h HiddenAdminsOutput) LootFiles() []internal.LootFile {
	return h.Loot
}

func (h HiddenAdminFinding) ToTableRow() []string {
	cloudIAM := h.CloudIAM
	if cloudIAM == "" {
		cloudIAM = "<NONE>"
	}

	activePods := fmt.Sprintf("%d", h.ActivePods)
	if h.ActivePods == 0 && h.EntityType != "ServiceAccount" {
		activePods = "N/A"
	}

	flags := ""
	if h.IsDefault {
		flags = "DEFAULT-SA"
	}
	if h.IsWildcard {
		if flags != "" {
			flags += ", "
		}
		flags += "WILDCARD"
	}
	if flags == "" {
		flags = "-"
	}

	return []string{
		h.Namespace,
		h.Entity,
		h.EntityType,
		h.Scope,
		h.DangerousPerms,
		cloudIAM,
		activePods,
		flags,
		h.Source,
	}
}

func (h HiddenAdminFinding) Loot() string {
	return fmt.Sprintf(
		"[Hidden Admin Detection]\nNamespace: %s\nEntity: %s (%s)\nScope: %s\nSource: %s\nDangerous Permissions: %s\n",
		h.Namespace,
		h.Entity,
		h.EntityType,
		h.Scope,
		h.Source,
		h.DangerousPerms,
	)
}

func ListHiddenAdmins(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating hidden admin permissions for %s", globals.ClusterName), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Use centralized attackpathService for hidden admin analysis
	attackPathSvc := attackpathservice.NewWithClientset(clientset)
	attackPathSvc.SetModuleName(globals.K8S_HIDDEN_ADMINS_MODULE_NAME)

	hiddenAdminData, err := attackPathSvc.AnalyzeHiddenAdmins(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error analyzing hidden admins: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}

	headers := []string{"Namespace", "Entity", "Type", "Scope", "Dangerous Permissions", "Cloud IAM", "Active Pods", "Flags", "Source"}
	var tableRows [][]string

	// Loot builder
	loot := shared.NewLootBuilder()

	// Track entities by IAM/RBAC permission type (focused on identity/access control)
	type PermissionTracking struct {
		ClusterAdmin        []string // Bound to cluster-admin or system:masters
		RBACModification    []string // Can create/update roles/bindings
		Impersonation       []string // Can impersonate users/groups/SAs
		CertificateApproval []string // Can approve CSRs (create new identities)
		AggregationRoles    []string // Uses RBAC aggregation
	}
	permTracking := &PermissionTracking{}

	// Also track legacy attack paths for backwards compatibility
	var attackPaths []AttackPath

	// Query all ServiceAccounts to detect cloud IAM annotations using cache
	serviceAccountCloudIAM := make(map[string]map[string]string) // namespace -> sa name -> cloud IAM
	serviceAccountPodCount := make(map[string]map[string]int)    // namespace -> sa name -> pod count

	logger.InfoM("Scanning ServiceAccounts for cloud IAM annotations...", globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	serviceAccounts, err := sdk.GetServiceAccounts(ctx, clientset)
	if err == nil {
		for _, sa := range serviceAccounts {
			if serviceAccountCloudIAM[sa.Namespace] == nil {
				serviceAccountCloudIAM[sa.Namespace] = make(map[string]string)
			}
			if serviceAccountPodCount[sa.Namespace] == nil {
				serviceAccountPodCount[sa.Namespace] = make(map[string]int)
			}

			// Check for AWS IRSA (IAM Roles for ServiceAccounts)
			if roleARN, ok := sa.Annotations["eks.amazonaws.com/role-arn"]; ok {
				serviceAccountCloudIAM[sa.Namespace][sa.Name] = fmt.Sprintf("AWS: %s", roleARN)
			}

			// Check for GCP Workload Identity
			if gcpSA, ok := sa.Annotations["iam.gke.io/gcp-service-account"]; ok {
				serviceAccountCloudIAM[sa.Namespace][sa.Name] = fmt.Sprintf("GCP: %s", gcpSA)
			}

			// Check for Azure Pod Identity
			if azureID, ok := sa.Annotations["azure.workload.identity/client-id"]; ok {
				serviceAccountCloudIAM[sa.Namespace][sa.Name] = fmt.Sprintf("Azure: %s", azureID)
			}
		}
	}

	// Count active pods per ServiceAccount using cache
	logger.InfoM("Counting active pods per ServiceAccount...", globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	allPods, err := sdk.GetPods(ctx, clientset)
	if err == nil {
		for _, pod := range allPods {
			saName := pod.Spec.ServiceAccountName
			if saName == "" {
				saName = "default"
			}
			if serviceAccountPodCount[pod.Namespace] == nil {
				serviceAccountPodCount[pod.Namespace] = make(map[string]int)
			}
			serviceAccountPodCount[pod.Namespace][saName]++
		}
	}

	// ClusterRoles using cache
	clusterRoles, err := sdk.GetClusterRoles(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching ClusterRoles: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}

	// Map of ClusterRole name -> dangerous permissions findings
	dangerousClusterRoles := make(map[string][]string)

	for _, role := range clusterRoles {
		var findings []string

		// Check if this is a built-in dangerous role
		if _, isBuiltInDangerous := dangerousBuiltInRoles[role.Name]; isBuiltInDangerous {
			findings = append(findings, fmt.Sprintf("Built-in dangerous role: %s", role.Name))
		}

		if role.Name == "cluster-admin" {
			findings = append(findings, "cluster-admin role (full cluster control)")
			permTracking.ClusterAdmin = append(permTracking.ClusterAdmin, fmt.Sprintf("ClusterRole/%s", role.Name))
		}
		if strings.Contains(role.Name, "system:masters") {
			findings = append(findings, "member of system:masters group")
			permTracking.ClusterAdmin = append(permTracking.ClusterAdmin, fmt.Sprintf("ClusterRole/%s", role.Name))
		}
		if role.AggregationRule != nil && role.AggregationRule.ClusterRoleSelectors != nil && len(role.AggregationRule.ClusterRoleSelectors) > 0 {
			findings = append(findings, "RBAC Aggregation role")
			permTracking.AggregationRoles = appendUniqueHA(permTracking.AggregationRoles, fmt.Sprintf("ClusterRole/%s", role.Name))
		}
		if role.Rules != nil {
			for _, rule := range role.Rules {
				// Only check for IAM/RBAC related rules, not privesc paths
				if isIAMRelatedRule(rule) {
					riskDesc := getIAMRiskDescription(rule)
					if riskDesc != "" {
						findings = append(findings, riskDesc)
					}

					// Track IAM/RBAC-related permissions
					entityRef := fmt.Sprintf("ClusterRole/%s", role.Name)
					for _, res := range rule.Resources {
						resLower := strings.ToLower(res)
						for _, verb := range rule.Verbs {
							verbLower := strings.ToLower(verb)
							// RBAC modification
							if strings.Contains(resLower, "role") || strings.Contains(resLower, "rolebinding") || strings.Contains(resLower, "clusterrole") {
								if verbLower == "create" || verbLower == "update" || verbLower == "patch" || verbLower == "*" || verbLower == "bind" || verbLower == "escalate" {
									permTracking.RBACModification = appendUniqueHA(permTracking.RBACModification, entityRef)
								}
							}
							// Certificate approval (identity creation)
							if strings.Contains(resLower, "certificatesigningrequests") {
								if verbLower == "create" || verbLower == "update" || verbLower == "approve" || verbLower == "*" {
									permTracking.CertificateApproval = appendUniqueHA(permTracking.CertificateApproval, entityRef)
								}
							}
						}
						// Impersonation
						for _, verb := range rule.Verbs {
							if strings.ToLower(verb) == "impersonate" {
								permTracking.Impersonation = appendUniqueHA(permTracking.Impersonation, entityRef)
							}
						}
					}
				}
			}
		}
		if len(findings) > 0 {
			// Store findings for lookup when processing bindings
			dangerousClusterRoles[role.Name] = findings

			row := HiddenAdminFinding{
				Namespace:      "<cluster>",
				Entity:         role.Name,
				EntityType:     "ClusterRole",
				Scope:          "cluster",
				DangerousPerms: strings.Join(findings, "; "),
				Source:         "ClusterRole definition",
			}
			tableRows = append(tableRows, row.ToTableRow())
		}
	}

	// ClusterRoleBindings using cache
	crbs, err := sdk.GetClusterRoleBindings(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching ClusterRoleBindings: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}
	for _, binding := range crbs {
		if binding.Subjects != nil {
			for _, subject := range binding.Subjects {
				ns := subject.Namespace
				if ns == "" {
					ns = "<cluster>"
				}
				role := binding.RoleRef.Name
				isWildcard := false
				isDefault := false
				cloudIAM := ""
				activePods := 0
				isDangerous := false

				// Detect wildcard group bindings
				if subject.Kind == "Group" {
					if subject.Name == "system:serviceaccounts" {
						isWildcard = true
						isDangerous = true
						// Create attack path for wildcard binding
						attackPaths = append(attackPaths, AttackPath{
							StartEntity: "system:serviceaccounts (ALL ServiceAccounts)",
							EntityType:  "Group",
							Steps: []string{
								"ANY ServiceAccount in ANY namespace can authenticate",
								fmt.Sprintf("Bound to ClusterRole: %s", role),
								"Full cluster-wide access through group membership",
							},
							EndGoal:     "Cluster-wide privilege escalation via any ServiceAccount",
							Feasibility: "Immediate",
						})
					} else if strings.HasPrefix(subject.Name, "system:serviceaccounts:") {
						isWildcard = true
						isDangerous = true
						wildcardNS := strings.TrimPrefix(subject.Name, "system:serviceaccounts:")
						// Create attack path for namespace wildcard binding
						attackPaths = append(attackPaths, AttackPath{
							StartEntity: fmt.Sprintf("system:serviceaccounts:%s (ALL SAs in %s)", wildcardNS, wildcardNS),
							EntityType:  "Group",
							Steps: []string{
								fmt.Sprintf("ANY ServiceAccount in namespace '%s' can authenticate", wildcardNS),
								fmt.Sprintf("Bound to ClusterRole: %s", role),
								"Namespace-wide access to cluster-level permissions",
							},
							EndGoal:     fmt.Sprintf("Privilege escalation via any ServiceAccount in %s", wildcardNS),
							Feasibility: "Immediate",
						})
					}
				}

				// Detect default ServiceAccount elevations
				if subject.Kind == "ServiceAccount" && subject.Name == "default" {
					isDefault = true
					isDangerous = true
					// Create attack path for default SA elevation
					attackPaths = append(attackPaths, AttackPath{
						StartEntity: fmt.Sprintf("default ServiceAccount (%s)", ns),
						EntityType:  "ServiceAccount",
						Steps: []string{
							"Default ServiceAccount has elevated permissions",
							fmt.Sprintf("Bound to ClusterRole: %s", role),
							"All pods without explicit SA use this account",
						},
						EndGoal:     "Privilege escalation through implicit ServiceAccount",
						Feasibility: "Immediate",
					})
				}

				// Get cloud IAM and pod count for ServiceAccounts
				if subject.Kind == "ServiceAccount" && ns != "<cluster>" {
					if saCloudIAM, ok := serviceAccountCloudIAM[ns][subject.Name]; ok {
						cloudIAM = saCloudIAM
						// Create attack path for cloud IAM crosswalk
						attackPaths = append(attackPaths, AttackPath{
							StartEntity: fmt.Sprintf("%s/%s", ns, subject.Name),
							EntityType:  "ServiceAccount",
							Steps: []string{
								fmt.Sprintf("K8s: Bound to ClusterRole %s", role),
								fmt.Sprintf("Cloud: %s", cloudIAM),
								"Compromise pod → K8s cluster access + Cloud IAM access",
							},
							EndGoal:     "Multi-cloud privilege escalation (K8s + Cloud Provider)",
							Feasibility: "Requires-Enum",
						})
					}
					if podCount, ok := serviceAccountPodCount[ns][subject.Name]; ok {
						activePods = podCount
					}
				}

				// Check built-in dangerous roles
				if _, isDangerousRole := dangerousBuiltInRoles[role]; isDangerousRole {
					isDangerous = true
				}

				if role == "cluster-admin" || role == "system:masters" || role == "admin" || role == "edit" {
					isDangerous = true
				}

				if isDangerous {
					// Track entity with their bound role for playbook
					entityRef := fmt.Sprintf("%s:%s/%s", subject.Kind, ns, subject.Name)
					if role == "cluster-admin" || role == "system:masters" {
						permTracking.ClusterAdmin = appendUniqueHA(permTracking.ClusterAdmin, entityRef)
					}
					if role == "admin" || role == "edit" {
						permTracking.RBACModification = appendUniqueHA(permTracking.RBACModification, entityRef)
					}

					// Get actual dangerous permissions from the ClusterRole
					dangerousPerms := fmt.Sprintf("bound to ClusterRole %s", role)
					if roleFindings, ok := dangerousClusterRoles[role]; ok {
						dangerousPerms = strings.Join(roleFindings, "; ")
					}

					row := HiddenAdminFinding{
						Namespace:      ns,
						Entity:         subject.Name,
						EntityType:     subject.Kind,
						Scope:          "cluster",
						DangerousPerms: dangerousPerms,
						Source:         fmt.Sprintf("ClusterRoleBinding %s", binding.Name),
						CloudIAM:       cloudIAM,
						ActivePods:     activePods,
						IsDefault:      isDefault,
						IsWildcard:     isWildcard,
					}
					tableRows = append(tableRows, row.ToTableRow())
				}
			}
		}
	}

	// Roles & RoleBindings using cache
	allRoles, err := sdk.GetRoles(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching Roles: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	}

	allRoleBindings, err := sdk.GetRoleBindings(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching RoleBindings: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	}

	// Process roles grouped by namespace
	dangerousRolesInNS := make(map[string]map[string][]string) // namespace -> roleName -> []findings
	for _, role := range allRoles {
		ns := role.Namespace
		if dangerousRolesInNS[ns] == nil {
			dangerousRolesInNS[ns] = make(map[string][]string)
		}

		var findings []string

		if role.Rules != nil {
			for _, rule := range role.Rules {
				// Only check for IAM/RBAC related rules, not privesc paths
				if isIAMRelatedRule(rule) {
					riskDesc := getIAMRiskDescription(rule)
					if riskDesc != "" {
						findings = append(findings, riskDesc)
					}
				}
			}
		}
		if len(findings) > 0 {
			dangerousRolesInNS[ns][role.Name] = findings
			row := HiddenAdminFinding{
				Namespace:      ns,
				Entity:         role.Name,
				EntityType:     "Role",
				Scope:          "namespace",
				DangerousPerms: strings.Join(findings, "; "),
				Source:         fmt.Sprintf("Role definition (%s)", role.Name),
			}
			tableRows = append(tableRows, row.ToTableRow())
		}
	}

	// Process RoleBindings
	for _, binding := range allRoleBindings {
		ns := binding.Namespace
		if binding.Subjects != nil {
			// Check if the role being bound is dangerous
			roleName := binding.RoleRef.Name
			var isDangerousBinding bool
			var bindingPerms string

			// Check if it's a dangerous namespaced role
			if dangerousRolesInNS[ns] != nil {
				if findings, ok := dangerousRolesInNS[ns][roleName]; ok {
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to Role %s with: %s", roleName, strings.Join(findings, "; "))
				}
			}

			// Check if it's binding to a ClusterRole (which might be cluster-admin or other dangerous ClusterRole)
			if binding.RoleRef.Kind == "ClusterRole" {
				// First check if this ClusterRole has known dangerous permissions
				if roleFindings, ok := dangerousClusterRoles[roleName]; ok {
					isDangerousBinding = true
					bindingPerms = strings.Join(roleFindings, "; ")
				} else if roleName == "cluster-admin" || strings.Contains(roleName, "system:masters") || roleName == "admin" || roleName == "edit" {
					// Fallback for built-in dangerous roles not in our map
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
				}
			}

			// Only add subjects if this is a dangerous binding
			if isDangerousBinding {
				for _, subject := range binding.Subjects {
					cloudIAM := ""
					activePods := 0
					isDefault := false

					// Detect default ServiceAccount in namespace bindings
					if subject.Kind == "ServiceAccount" && subject.Name == "default" {
						isDefault = true
					}

					// Get cloud IAM and pod count for ServiceAccounts
					if subject.Kind == "ServiceAccount" {
						if saCloudIAM, ok := serviceAccountCloudIAM[ns][subject.Name]; ok {
							cloudIAM = saCloudIAM
						}
						if podCount, ok := serviceAccountPodCount[ns][subject.Name]; ok {
							activePods = podCount
						}
					}

					row := HiddenAdminFinding{
						Namespace:      ns,
						Entity:         subject.Name,
						EntityType:     subject.Kind,
						Scope:          "namespace",
						DangerousPerms: bindingPerms,
						Source:         fmt.Sprintf("RoleBinding %s", binding.Name),
						CloudIAM:       cloudIAM,
						ActivePods:     activePods,
						IsDefault:      isDefault,
						IsWildcard:     false,
					}
					tableRows = append(tableRows, row.ToTableRow())
				}
			}
		}
	}

	// Build a map of dangerous service accounts with their cloud IAM and permissions
	type dangerousSAInfo struct {
		CloudIAM    string
		Permissions string
	}
	dangerousSAs := make(map[string]map[string]dangerousSAInfo) // namespace -> sa -> info
	for _, row := range tableRows {
		if len(row) >= 6 {
			ns := row[0]
			entity := row[1]
			entityType := row[2]
			perms := row[4]
			cloudIAM := row[5]

			if entityType == "ServiceAccount" {
				if dangerousSAs[ns] == nil {
					dangerousSAs[ns] = make(map[string]dangerousSAInfo)
				}
				dangerousSAs[ns][entity] = dangerousSAInfo{CloudIAM: cloudIAM, Permissions: perms}
			}
		}
	}

	// Build hidden-admin-location table rows
	var locationRows [][]string

	// ============================================
	// LOOT FILE 1: Hidden-Admin-Exec
	// Combines pod mapping and cloud IAM with specific exec commands
	// ============================================
	lootExecSection := loot.Section("Hidden-Admins-Exec").SetHeader(`#####################################
##### Hidden Admins Exec Commands
#####################################
#
# Direct exec commands to compromise pods running
# with dangerous ServiceAccounts
#`)

	if globals.KubeContext != "" {
		lootExecSection.Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	// Query pods to find which ones use dangerous SAs
	if len(dangerousSAs) > 0 {
		for _, pod := range allPods {
			ns := pod.Namespace
			if _, exists := dangerousSAs[ns]; !exists {
				continue
			}

			saName := pod.Spec.ServiceAccountName
			if saName == "" {
				saName = "default"
			}

			if saInfo, found := dangerousSAs[ns][saName]; found {
				// Add to location table
				locationRows = append(locationRows, []string{
					ns,
					saName,
					saInfo.Permissions,
					saInfo.CloudIAM,
					pod.Name,
					pod.Spec.NodeName,
				})

				lootExecSection.AddBlank()
				lootExecSection.Addf("## %s/%s (SA: %s)", ns, pod.Name, saName)
				lootExecSection.Addf("# Node: %s | Permissions: %s", pod.Spec.NodeName, saInfo.Permissions)

				if saInfo.CloudIAM != "" && saInfo.CloudIAM != "<NONE>" {
					lootExecSection.Addf("# Cloud IAM: %s", saInfo.CloudIAM)
				}

				lootExecSection.Addf("kubectl exec -it %s -n %s -- /bin/sh", pod.Name, ns)
				lootExecSection.Add("cat /var/run/secrets/kubernetes.io/serviceaccount/token")

				// Add cloud-specific commands
				if strings.HasPrefix(saInfo.CloudIAM, "AWS:") {
					lootExecSection.Add("aws sts get-caller-identity && aws s3 ls")
				} else if strings.HasPrefix(saInfo.CloudIAM, "GCP:") {
					lootExecSection.Add("gcloud auth list && gcloud projects list")
				} else if strings.HasPrefix(saInfo.CloudIAM, "Azure:") {
					lootExecSection.Add("az account show && az resource list")
				}
			}
		}
	}

	if len(locationRows) == 0 {
		lootExecSection.AddBlank()
		lootExecSection.Add("# No pods found running with dangerous ServiceAccounts")
	}

	// ============================================
	// LOOT FILE 2: Attack-Path-Chains (entity-specific)
	// ============================================
	lootAttackPathsSection := loot.Section("Hidden-Admins-Attack-Path-Chains").SetHeader(`#####################################
##### Hidden Admins Attack Path Chains
#####################################
#
# Entity-specific privilege escalation paths
#`)

	if len(attackPaths) > 0 {
		for i, path := range attackPaths {
			lootAttackPathsSection.AddBlank()
			lootAttackPathsSection.Addf("## Path %d: %s", i+1, path.StartEntity)
			lootAttackPathsSection.Addf("# Type: %s | Feasibility: %s", path.EntityType, path.Feasibility)
			for stepNum, step := range path.Steps {
				lootAttackPathsSection.Addf("#   %d. %s", stepNum+1, step)
			}
			lootAttackPathsSection.Addf("# Goal: %s", path.EndGoal)
		}
	} else {
		lootAttackPathsSection.AddBlank()
		lootAttackPathsSection.Add("# No specific attack paths detected")
	}

	// ============================================
	// LOOT FILE 3: Privilege-Escalation-Playbook
	// Organized by permission type with specific entities
	// ============================================
	lootPlaybookSection := loot.Section("Hidden-Admins-Playbook").SetHeader(`#####################################
##### Hidden Admins Playbook
#####################################
#
# Exploitation techniques organized by permission type
# with specific entities that have these permissions
#`)

	if globals.KubeContext != "" {
		lootPlaybookSection.Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	// cluster-admin / system:masters
	lootPlaybookSection.Add(`
##############################################
## CLUSTER-ADMIN / SYSTEM:MASTERS
##############################################
# Full cluster control - no escalation needed`)
	if len(permTracking.ClusterAdmin) > 0 {
		lootPlaybookSection.Add("# Entities with this permission:")
		for _, entity := range permTracking.ClusterAdmin {
			lootPlaybookSection.Addf("#   - %s", entity)
		}
	} else {
		lootPlaybookSection.Add("# No entities found with cluster-admin")
	}

	// RBAC Modification
	lootPlaybookSection.Add(`
##############################################
## RBAC MODIFICATION
##############################################
# Can create/update roles and bindings`)
	if len(permTracking.RBACModification) > 0 {
		lootPlaybookSection.Add("# Entities with this permission:")
		for _, entity := range permTracking.RBACModification {
			lootPlaybookSection.Addf("#   - %s", entity)
		}
		lootPlaybookSection.Add(`
# Escalate to cluster-admin:
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=NAMESPACE:SA_NAME

# Or create custom role:
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pwn-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
EOF`)
	} else {
		lootPlaybookSection.Add("# No entities found with RBAC modification permissions")
	}

	// Impersonation
	lootPlaybookSection.Add(`
##############################################
## IMPERSONATION
##############################################
# Can impersonate users/groups/SAs`)
	if len(permTracking.Impersonation) > 0 {
		lootPlaybookSection.Add("# Entities with this permission:")
		for _, entity := range permTracking.Impersonation {
			lootPlaybookSection.Addf("#   - %s", entity)
		}
		lootPlaybookSection.Add(`
# Test impersonation:
kubectl auth can-i --list --as=system:serviceaccount:kube-system:default

# Impersonate and act:
kubectl --as=system:serviceaccount:kube-system:default get secrets -A
kubectl --as=cluster-admin create clusterrolebinding pwn --clusterrole=cluster-admin --user=YOUR_USER`)
	} else {
		lootPlaybookSection.Add("# No entities found with impersonation permissions")
	}

	// Certificate Approval
	lootPlaybookSection.Add(`
##############################################
## CERTIFICATE APPROVAL
##############################################
# Can approve CSRs - create new cluster identities`)
	if len(permTracking.CertificateApproval) > 0 {
		lootPlaybookSection.Add("# Entities with this permission:")
		for _, entity := range permTracking.CertificateApproval {
			lootPlaybookSection.Addf("#   - %s", entity)
		}
		lootPlaybookSection.Add(`
# Create and approve CSR for system:masters:
openssl genrsa -out pwn.key 2048
openssl req -new -key pwn.key -out pwn.csr -subj "/CN=pwn/O=system:masters"
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: pwn-csr
spec:
  request: $(cat pwn.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages: ["client auth"]
EOF
kubectl certificate approve pwn-csr
kubectl get csr pwn-csr -o jsonpath='{.status.certificate}' | base64 -d > pwn.crt`)
	} else {
		lootPlaybookSection.Add("# No entities found with certificate approval permissions")
	}

	// Aggregation Roles
	lootPlaybookSection.Add(`
##############################################
## RBAC AGGREGATION ROLES
##############################################
# Uses RBAC aggregation - permissions can be dynamically expanded`)
	if len(permTracking.AggregationRoles) > 0 {
		lootPlaybookSection.Add("# Entities with this permission:")
		for _, entity := range permTracking.AggregationRoles {
			lootPlaybookSection.Addf("#   - %s", entity)
		}
		lootPlaybookSection.Add(`
# Aggregation roles can have their permissions expanded by creating
# new ClusterRoles with matching labels. If you can create ClusterRoles:

# Check aggregation selectors:
kubectl get clusterrole ROLE_NAME -o yaml | grep -A10 aggregationRule

# Create ClusterRole that matches aggregation selector to inject permissions:
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: inject-permissions
  labels:
    # Match the aggregation selector labels
    rbac.authorization.k8s.io/aggregate-to-admin: "true"
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
EOF`)
	} else {
		lootPlaybookSection.Add("# No aggregation roles found")
	}

	// ============================================
	// LOOT FILE 4: Centralized Playbook from attackpathService
	// ============================================
	if hiddenAdminData != nil && len(hiddenAdminData.AllFindings) > 0 {
		clusterHeader := fmt.Sprintf("Cluster: %s", globals.ClusterName)
		if centralizedPlaybook := attackpathservice.GenerateHiddenAdminsPlaybook(hiddenAdminData, clusterHeader); centralizedPlaybook != "" {
			loot.Section("Hidden-Admins-Centralized-Playbook").SetHeader("").Add(centralizedPlaybook)
		}
	}

	// Output section
	table := internal.TableFile{
		Name:   "Hidden-Admins",
		Header: headers,
		Body:   tableRows,
	}

	// Hidden admin location table - shows where dangerous SAs are running
	locationTable := internal.TableFile{
		Name:   "Hidden-Admin-Location",
		Header: []string{"Namespace", "ServiceAccount", "Permissions", "Cloud IAM", "Pod Name", "Node Name"},
		Body:   locationRows,
	}

	// Build tables list
	tables := []internal.TableFile{table}
	if len(locationRows) > 0 {
		tables = append(tables, locationTable)
	}

	// Build all loot files
	lootFiles := loot.Build()

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Hidden-Admins",
		globals.ClusterName,
		"results",
		HiddenAdminsOutput{
			Table: tables,
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}

	if len(tableRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d hidden admin findings found", len(tableRows)), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	} else {
		logger.InfoM("No hidden admin findings found, skipping output file creation", globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_HIDDEN_ADMINS_MODULE_NAME), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
}
