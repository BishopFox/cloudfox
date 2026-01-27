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
	v1 "k8s.io/api/core/v1"
)

var TaintsTolerationsCmd = &cobra.Command{
	Use:     "taints-tolerates",
	Aliases: []string{"tt"},
	Short:   "Analyzes taint-toleration mismatches and security bypasses",
	Long: `
Analyzes taint-toleration relationships with comprehensive security analysis:
  - Shows which node taints each pod tolerates
  - Identifies taints not tolerated by any pod (isolation gaps)
  - Detects unauthorized pod access (app pods on master nodes)
  - Identifies overly permissive tolerations (wildcards, bypasses)
  - Detects compliance violations (pods breaking isolation)
  - Risk scoring for dangerous taint-toleration combinations
  - Remediation guidance for security issues

  cloudfox kubernetes taints-tolerates`,
	Run: ListTaintsTolerations,
}

type TaintsTolerationsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t TaintsTolerationsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t TaintsTolerationsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type PodTaintMatch struct {
	Namespace           string
	PodName             string
	NodeName            string
	ToleratedTaints     []string
	UntoleratedTaints   []string
	IsPrivileged        bool
	HostAccess          string
	UnauthorizedAccess  bool
	ComplianceViolation string
	WildcardBypass      bool
	RiskLevel           string
	RiskScore           int
	SecurityIssues      []string
}

// helper to check if a toleration matches a taint (improved version)
func ttToleratesTaint(tol v1.Toleration, taint v1.Taint) bool {
	// Wildcard toleration: empty key + Exists operator = tolerates ALL taints
	if tol.Key == "" && tol.Operator == v1.TolerationOpExists {
		return true
	}

	// Key must match
	if tol.Key != taint.Key {
		return false
	}

	// Effect must match (or toleration has empty effect which matches all effects for that key)
	if tol.Effect != taint.Effect && tol.Effect != v1.TaintEffect("") {
		return false
	}

	switch tol.Operator {
	case v1.TolerationOpExists:
		// Key exists, value ignored
		return true
	case v1.TolerationOpEqual, "":
		// Operator Equal or default, key and value must match
		return tol.Value == taint.Value
	default:
		return false
	}
}

func ListTaintsTolerations(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating taint-toleration mappings for %s", globals.ClusterName), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all nodes using cache
	nodes, err := sdk.GetNodes(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "nodes", "", err, globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME, true)
		return
	}

	nodeTaints := map[string][]v1.Taint{}
	nodeRoles := map[string]string{}
	nodeComplianceZones := map[string]string{}

	for _, node := range nodes {
		nodeTaints[node.Name] = node.Spec.Taints
		nodeRoles[node.Name] = detectNodeRoleTT(node.Labels)
		nodeComplianceZones[node.Name] = detectComplianceZoneTT(node.Labels, node.Spec.Taints)
	}

	headersPods := []string{
		"Namespace",
		"PodName",
		"NodeName",
		"Node Role",
		"ToleratedTaints",
		"UntoleratedTaints",
		"Issues",
	}
	var outputRowsPods [][]string

	loot := shared.NewLootBuilder()

	loot.Section("PodTolerations-info")

	loot.Section("Unauthorized-Access").SetHeader(`#####################################
##### Unauthorized Node Access
#####################################
# Pods accessing nodes they shouldn't
# App pods on master nodes, etc.

`)

	loot.Section("Compliance-Violations").SetHeader(`#####################################
##### Compliance Violations
#####################################
# Pods bypassing compliance zone isolation
# PCI, HIPAA, or other regulated environments

`)

	loot.Section("Wildcard-Bypasses").SetHeader(`#####################################
##### Wildcard Toleration Bypasses
#####################################
# Pods with wildcard tolerations bypassing all taints
# Can schedule anywhere including sensitive nodes

`)

	loot.Section("Remediation-Guide").SetHeader(`#####################################
##### Remediation Guidance
#####################################
# Step-by-step fixes for taint-toleration issues

`)

	allTaintsSet := map[string]struct{}{}
	taintTolerated := map[string]bool{}
	var podMatches []PodTaintMatch

	riskCounts := shared.NewRiskCounts()

	// Get all pods using cache
	allPods, err := sdk.GetPods(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "pods", "", err, globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME, true)
		return
	}

	for _, pod := range allPods {
			nodeName := pod.Spec.NodeName
			if nodeName == "" {
				continue
			}

			podMatch := PodTaintMatch{
				Namespace: pod.Namespace,
				PodName:   pod.Name,
				NodeName:  nodeName,
			}

			// Analyze pod security context
			podMatch.IsPrivileged = isPodPrivileged(&pod)
			podMatch.HostAccess = getHostAccessString(&pod)

			taints := nodeTaints[nodeName]
			var toleratedTaints []string
			var untoleratedTaints []string

			for _, taint := range taints {
				taintKey := fmt.Sprintf("%s:%s=%s", taint.Key, taint.Effect, taint.Value)
				allTaintsSet[taintKey] = struct{}{}

				if ttToleratesAnyTaint(pod.Spec.Tolerations, taint) {
					toleratedTaints = append(toleratedTaints, taintKey)
					taintTolerated[taintKey] = true
				} else {
					untoleratedTaints = append(untoleratedTaints, taintKey)
					if _, seen := taintTolerated[taintKey]; !seen {
						taintTolerated[taintKey] = false
					}
				}
			}

			podMatch.ToleratedTaints = toleratedTaints
			podMatch.UntoleratedTaints = untoleratedTaints

			// Detect security issues
			podMatch.WildcardBypass = hasWildcardToleration(pod.Spec.Tolerations)
			podMatch.UnauthorizedAccess = detectUnauthorizedAccess(&pod, nodeRoles[nodeName], pod.Spec.Tolerations)
			podMatch.ComplianceViolation = detectComplianceViolationTT(&pod, nodeComplianceZones[nodeName])

			// Calculate risk
			podMatch.RiskLevel, podMatch.RiskScore = calculateTaintTolerationRisk(&podMatch, nodeRoles[nodeName])
			podMatch.SecurityIssues = generateTaintTolerationIssues(&podMatch, nodeRoles[nodeName])

			riskCounts.Add(podMatch.RiskLevel)
			podMatches = append(podMatches, podMatch)

			toleratedStr := "<NONE>"
			if len(toleratedTaints) > 0 {
				toleratedStr = strings.Join(toleratedTaints, "\n")
			}

			untoleratedStr := "<NONE>"
			if len(untoleratedTaints) > 0 {
				untoleratedStr = strings.Join(untoleratedTaints, "\n")
			}

			row := []string{
				k8sinternal.NonEmpty(pod.Namespace),
				k8sinternal.NonEmpty(pod.Name),
				k8sinternal.NonEmpty(nodeName),
				nodeRoles[nodeName],
				toleratedStr,
				untoleratedStr,
				fmt.Sprintf("%d", len(podMatch.SecurityIssues)),
			}
			outputRowsPods = append(outputRowsPods, row)

			loot.Section("PodTolerations-info").Addf("### [%s] Namespace: %s | Pod: %s | Node: %s (%s)",
				podMatch.RiskLevel, pod.Namespace, pod.Name, nodeName, nodeRoles[nodeName])
			loot.Section("PodTolerations-info").Addf("# Tolerated: %d | Untolerated: %d | Issues: %d",
				len(toleratedTaints), len(untoleratedTaints), len(podMatch.SecurityIssues))
			if len(toleratedTaints) > 0 {
				loot.Section("PodTolerations-info").Add("# Tolerated Taints:")
				for _, t := range toleratedTaints {
					loot.Section("PodTolerations-info").Addf("#   - %s", t)
				}
			}
			if len(untoleratedTaints) > 0 {
				loot.Section("PodTolerations-info").Add("# Untolerated Taints:")
				for _, t := range untoleratedTaints {
					loot.Section("PodTolerations-info").Addf("#   - %s", t)
				}
			}
			if len(podMatch.SecurityIssues) > 0 {
				loot.Section("PodTolerations-info").Add("# Security Issues:")
				for _, issue := range podMatch.SecurityIssues {
					loot.Section("PodTolerations-info").Addf("#   - %s", issue)
				}
			}
			loot.Section("PodTolerations-info").Add("")

			// Loot: Unauthorized access
			if podMatch.UnauthorizedAccess {
				loot.Section("Unauthorized-Access").Add("")
				loot.Section("Unauthorized-Access").Addf("### [%s] %s/%s on %s (%s)", podMatch.RiskLevel, pod.Namespace, pod.Name, nodeName, nodeRoles[nodeName])
				loot.Section("Unauthorized-Access").Addf("# Privileged: %v | HostAccess: %s", podMatch.IsPrivileged, podMatch.HostAccess)
				if len(podMatch.SecurityIssues) > 0 {
					loot.Section("Unauthorized-Access").Add("# Issues:")
					for _, issue := range podMatch.SecurityIssues {
						loot.Section("Unauthorized-Access").Addf("#   - %s", issue)
					}
				}
				loot.Section("Unauthorized-Access").Addf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace)
				loot.Section("Unauthorized-Access").Add("")
			}

			// Loot: Compliance violations
			if podMatch.ComplianceViolation != "" {
				loot.Section("Compliance-Violations").Add("")
				loot.Section("Compliance-Violations").Addf("### [%s] %s/%s - %s Zone Violation", shared.RiskCritical, pod.Namespace, pod.Name, podMatch.ComplianceViolation)
				loot.Section("Compliance-Violations").Addf("# Node: %s | Compliance Zone: %s", nodeName, podMatch.ComplianceViolation)
				loot.Section("Compliance-Violations").Addf("# Pod bypassing %s compliance isolation", podMatch.ComplianceViolation)
				loot.Section("Compliance-Violations").Addf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace)
				loot.Section("Compliance-Violations").Add("")
			}

			// Loot: Wildcard bypasses
			if podMatch.WildcardBypass {
				loot.Section("Wildcard-Bypasses").Add("")
				loot.Section("Wildcard-Bypasses").Addf("### [%s] %s/%s", podMatch.RiskLevel, pod.Namespace, pod.Name)
				loot.Section("Wildcard-Bypasses").Addf("# Node: %s (%s) | Privileged: %v", nodeName, nodeRoles[nodeName], podMatch.IsPrivileged)
				loot.Section("Wildcard-Bypasses").Add("# WARNING: Wildcard toleration can bypass ALL taints")
				if len(podMatch.SecurityIssues) > 0 {
					loot.Section("Wildcard-Bypasses").Add("# Issues:")
					for _, issue := range podMatch.SecurityIssues {
						loot.Section("Wildcard-Bypasses").Addf("#   - %s", issue)
					}
				}
				loot.Section("Wildcard-Bypasses").Addf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace)
				loot.Section("Wildcard-Bypasses").Add("")
			}

			// Loot: Remediation
			if len(podMatch.SecurityIssues) > 0 {
				loot.Section("Remediation-Guide").Add("")
				loot.Section("Remediation-Guide").Addf("### %s/%s - %d Issues", pod.Namespace, pod.Name, len(podMatch.SecurityIssues))
				for i, issue := range podMatch.SecurityIssues {
					loot.Section("Remediation-Guide").Addf("# %d. %s", i+1, issue)
				}
				loot.Section("Remediation-Guide").Add("# Remediation steps:")
				if podMatch.UnauthorizedAccess {
					loot.Section("Remediation-Guide").Addf("#   - Remove tolerations allowing access to %s nodes", nodeRoles[nodeName])
				}
				if podMatch.WildcardBypass {
					loot.Section("Remediation-Guide").Add("#   - Replace wildcard toleration with specific tolerations")
				}
				if podMatch.ComplianceViolation != "" {
					loot.Section("Remediation-Guide").Addf("#   - Add %s compliance zone taint to prevent unauthorized access", podMatch.ComplianceViolation)
				}
				loot.Section("Remediation-Guide").Addf("#   kubectl edit pod %s -n %s", pod.Name, pod.Namespace)
				loot.Section("Remediation-Guide").Add("")
			}
	}

	// Build pod toleration table and loot
	podsTable := internal.TableFile{
		Name:   "PodTolerations",
		Header: headersPods,
		Body:   outputRowsPods,
	}

	// Add summary
	if riskCounts.Critical > 0 || riskCounts.High > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d pod-taint combinations with critical risks
# HIGH: %d pod-taint combinations with high risks
# MEDIUM: %d pod-taint combinations with medium risks
# LOW: %d pod-taint combinations with low risks
#
# Focus on CRITICAL and HIGH risk combinations for security review.
`, riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low)
		loot.Section("PodTolerations-info").SetSummary(summary)
	}

	// Unmatched taints (not tolerated by any pod)
	headersTaints := []string{"Taint"}
	var outputRowsTaints [][]string

	loot.Section("UnmatchedTaints-info").SetHeader(`#####################################
##### Taints Not Tolerated by Any Pod
#####################################
# These taints may indicate:
#   - Overly restrictive isolation (no pods can use these nodes)
#   - Orphaned/unused nodes
#   - Missing workload deployments

`)

	for taint := range allTaintsSet {
		if tolerated, ok := taintTolerated[taint]; !ok || !tolerated {
			riskLevel := assessUntoleratedTaintRisk(taint)
			outputRowsTaints = append(outputRowsTaints, []string{taint})
			loot.Section("UnmatchedTaints-info").Addf("# [%s] %s", riskLevel, taint)
		}
	}
	if len(outputRowsTaints) == 0 {
		outputRowsTaints = append(outputRowsTaints, []string{"<NONE>"})
		loot.Section("UnmatchedTaints-info").Add("# All taints are tolerated by at least one pod")
	}

	taintsTable := internal.TableFile{
		Name:   "UnmatchedTaints",
		Header: headersTaints,
		Body:   outputRowsTaints,
	}

	// Build all loot files
	lootFiles := loot.Build()

	// Output handling
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Taints-Tolerations",
		globals.ClusterName,
		"results",
		TaintsTolerationsOutput{
			Table: []internal.TableFile{podsTable, taintsTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
		return
	}

	if len(outputRowsPods) > 0 {
		logger.InfoM(fmt.Sprintf("%d pod tolerations found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRowsPods),
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
			globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
	} else {
		logger.InfoM("No pod tolerations found, skipping output file creation", globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

// Helper to check if pod tolerations tolerate a taint
func ttToleratesAnyTaint(tolerations []v1.Toleration, taint v1.Taint) bool {
	for _, tol := range tolerations {
		if ttToleratesTaint(tol, taint) {
			return true
		}
	}
	return false
}

func detectNodeRoleTT(labels map[string]string) string {
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		return "master"
	}
	if _, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
		return "control-plane"
	}
	for key := range labels {
		if strings.Contains(key, "node-role.kubernetes.io/") {
			parts := strings.Split(key, "/")
			if len(parts) == 2 {
				return parts[1]
			}
		}
	}
	return "worker"
}

func detectComplianceZoneTT(labels map[string]string, taints []v1.Taint) string {
	for key, value := range labels {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "compliance") || strings.Contains(lowerKey, "pci") || strings.Contains(lowerKey, "hipaa") {
			return value
		}
	}
	for _, taint := range taints {
		lowerKey := strings.ToLower(taint.Key)
		if strings.Contains(lowerKey, "pci") {
			return "PCI"
		}
		if strings.Contains(lowerKey, "hipaa") {
			return "HIPAA"
		}
	}
	return ""
}

func isPodPrivileged(pod *v1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return true
		}
	}
	for _, container := range pod.Spec.InitContainers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

func getHostAccessString(pod *v1.Pod) string {
	var access []string
	if pod.Spec.HostNetwork {
		access = append(access, "Net")
	}
	if pod.Spec.HostPID {
		access = append(access, "PID")
	}
	if pod.Spec.HostIPC {
		access = append(access, "IPC")
	}
	if len(access) == 0 {
		return "None"
	}
	return strings.Join(access, ",")
}

func hasWildcardToleration(tolerations []v1.Toleration) bool {
	for _, tol := range tolerations {
		if tol.Key == "" && tol.Operator == v1.TolerationOpExists {
			return true
		}
	}
	return false
}

func detectUnauthorizedAccess(pod *v1.Pod, nodeRole string, tolerations []v1.Toleration) bool {
	// Non-system pods on master/control-plane nodes
	if (nodeRole == "master" || nodeRole == "control-plane") &&
		!strings.HasPrefix(pod.Namespace, "kube-") &&
		pod.Namespace != "kube-system" {
		return true
	}

	// Wildcard toleration = can access anywhere
	if hasWildcardToleration(tolerations) {
		return true
	}

	return false
}

func detectComplianceViolationTT(pod *v1.Pod, complianceZone string) string {
	if complianceZone == "" {
		return ""
	}

	// Non-compliant namespaces accessing compliance zones
	if !strings.Contains(strings.ToLower(pod.Namespace), strings.ToLower(complianceZone)) {
		return complianceZone
	}

	return ""
}

func calculateTaintTolerationRisk(match *PodTaintMatch, nodeRole string) (string, int) {
	score := 0

	// Unauthorized access to sensitive nodes
	if match.UnauthorizedAccess {
		score += 50
	}

	// Compliance violations are critical
	if match.ComplianceViolation != "" {
		score += 60
	}

	// Wildcard bypass
	if match.WildcardBypass {
		score += 40
	}

	// Privileged pods with dangerous tolerations
	if match.IsPrivileged {
		score += 20
		if match.UnauthorizedAccess || match.WildcardBypass {
			score += 20
		}
	}

	// Host access
	if match.HostAccess != "None" {
		score += 15
	}

	// Master/control-plane access
	if nodeRole == "master" || nodeRole == "control-plane" {
		score += 30
	}

	// Determine risk level
	if score >= 70 {
		return shared.RiskCritical, ttMin(score, 100)
	} else if score >= 40 {
		return shared.RiskHigh, score
	} else if score >= 20 {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
}

func generateTaintTolerationIssues(match *PodTaintMatch, nodeRole string) []string {
	var issues []string

	if match.UnauthorizedAccess {
		issues = append(issues, fmt.Sprintf("UNAUTHORIZED: Pod accessing %s node", nodeRole))
	}

	if match.ComplianceViolation != "" {
		issues = append(issues, fmt.Sprintf("COMPLIANCE VIOLATION: Bypassing %s zone isolation", match.ComplianceViolation))
	}

	if match.WildcardBypass {
		issues = append(issues, "WILDCARD BYPASS: Can schedule on ANY node including master/GPU/compliance zones")
	}

	if match.IsPrivileged && (match.UnauthorizedAccess || match.WildcardBypass) {
		issues = append(issues, "PRIVILEGE ESCALATION: Privileged pod + dangerous node access")
	}

	if match.IsPrivileged {
		issues = append(issues, "Privileged container - full host access")
	}

	if match.HostAccess != "None" {
		issues = append(issues, fmt.Sprintf("Host access: %s", match.HostAccess))
	}

	if len(match.UntoleratedTaints) > 0 && !match.WildcardBypass {
		issues = append(issues, fmt.Sprintf("%d taints not tolerated - may cause scheduling issues", len(match.UntoleratedTaints)))
	}

	return issues
}

func assessUntoleratedTaintRisk(taint string) string {
	lowerTaint := strings.ToLower(taint)

	// Critical taints that should have pods tolerating them
	if strings.Contains(lowerTaint, "master") ||
		strings.Contains(lowerTaint, "control-plane") ||
		strings.Contains(lowerTaint, "pci") ||
		strings.Contains(lowerTaint, "hipaa") {
		return shared.RiskMedium
	}

	// GPU or specialized hardware
	if strings.Contains(lowerTaint, "gpu") ||
		strings.Contains(lowerTaint, "nvidia") {
		return shared.RiskLow
	}

	return shared.RiskLow
}

func ttMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
