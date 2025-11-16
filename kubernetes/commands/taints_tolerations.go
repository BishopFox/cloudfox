package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating taint-toleration mappings for %s", globals.ClusterName), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing nodes: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
		return
	}

	nodeTaints := map[string][]v1.Taint{}
	nodeRoles := map[string]string{}
	nodeComplianceZones := map[string]string{}

	for _, node := range nodes.Items {
		nodeTaints[node.Name] = node.Spec.Taints
		nodeRoles[node.Name] = detectNodeRoleTT(node.Labels)
		nodeComplianceZones[node.Name] = detectComplianceZoneTT(node.Labels, node.Spec.Taints)
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
		return
	}

	headersPods := []string{
		"Risk",
		"Score",
		"Namespace",
		"PodName",
		"NodeName",
		"Node Role",
		"ToleratedTaints",
		"UntoleratedTaints",
		"Issues",
	}
	var outputRowsPods [][]string
	var lootContentsPods []string
	var lootUnauthorizedAccess []string
	var lootComplianceViolations []string
	var lootWildcardBypasses []string
	var lootRemediation []string

	lootUnauthorizedAccess = append(lootUnauthorizedAccess, `#####################################
##### Unauthorized Node Access
#####################################
# Pods accessing nodes they shouldn't
# App pods on master nodes, etc.

`)

	lootComplianceViolations = append(lootComplianceViolations, `#####################################
##### Compliance Violations
#####################################
# Pods bypassing compliance zone isolation
# PCI, HIPAA, or other regulated environments

`)

	lootWildcardBypasses = append(lootWildcardBypasses, `#####################################
##### Wildcard Toleration Bypasses
#####################################
# Pods with wildcard tolerations bypassing all taints
# Can schedule anywhere including sensitive nodes

`)

	lootRemediation = append(lootRemediation, `#####################################
##### Remediation Guidance
#####################################
# Step-by-step fixes for taint-toleration issues

`)

	allTaintsSet := map[string]struct{}{}
	taintTolerated := map[string]bool{}
	var podMatches []PodTaintMatch

	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing pods in namespace: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
			continue
		}

		for _, pod := range pods.Items {
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

			riskCounts[podMatch.RiskLevel]++
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
				podMatch.RiskLevel,
				fmt.Sprintf("%d", podMatch.RiskScore),
				k8sinternal.NonEmpty(pod.Namespace),
				k8sinternal.NonEmpty(pod.Name),
				k8sinternal.NonEmpty(nodeName),
				nodeRoles[nodeName],
				toleratedStr,
				untoleratedStr,
				fmt.Sprintf("%d", len(podMatch.SecurityIssues)),
			}
			outputRowsPods = append(outputRowsPods, row)

			lootContentsPods = append(lootContentsPods,
				fmt.Sprintf("### [%s] Namespace: %s | Pod: %s | Node: %s (%s)",
					podMatch.RiskLevel, pod.Namespace, pod.Name, nodeName, nodeRoles[nodeName]),
				fmt.Sprintf("# Tolerated: %d | Untolerated: %d | Issues: %d",
					len(toleratedTaints), len(untoleratedTaints), len(podMatch.SecurityIssues)),
			)
			if len(toleratedTaints) > 0 {
				lootContentsPods = append(lootContentsPods, "# Tolerated Taints:")
				for _, t := range toleratedTaints {
					lootContentsPods = append(lootContentsPods, fmt.Sprintf("#   - %s", t))
				}
			}
			if len(untoleratedTaints) > 0 {
				lootContentsPods = append(lootContentsPods, "# Untolerated Taints:")
				for _, t := range untoleratedTaints {
					lootContentsPods = append(lootContentsPods, fmt.Sprintf("#   - %s", t))
				}
			}
			if len(podMatch.SecurityIssues) > 0 {
				lootContentsPods = append(lootContentsPods, "# Security Issues:")
				for _, issue := range podMatch.SecurityIssues {
					lootContentsPods = append(lootContentsPods, fmt.Sprintf("#   - %s", issue))
				}
			}
			lootContentsPods = append(lootContentsPods, "")

			// Loot: Unauthorized access
			if podMatch.UnauthorizedAccess {
				lootUnauthorizedAccess = append(lootUnauthorizedAccess,
					fmt.Sprintf("\n### [%s] %s/%s on %s (%s)", podMatch.RiskLevel, pod.Namespace, pod.Name, nodeName, nodeRoles[nodeName]),
					fmt.Sprintf("# Privileged: %v | HostAccess: %s", podMatch.IsPrivileged, podMatch.HostAccess),
				)
				if len(podMatch.SecurityIssues) > 0 {
					lootUnauthorizedAccess = append(lootUnauthorizedAccess, "# Issues:")
					for _, issue := range podMatch.SecurityIssues {
						lootUnauthorizedAccess = append(lootUnauthorizedAccess, fmt.Sprintf("#   - %s", issue))
					}
				}
				lootUnauthorizedAccess = append(lootUnauthorizedAccess,
					fmt.Sprintf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace),
					"")
			}

			// Loot: Compliance violations
			if podMatch.ComplianceViolation != "" {
				lootComplianceViolations = append(lootComplianceViolations,
					fmt.Sprintf("\n### [CRITICAL] %s/%s - %s Zone Violation", pod.Namespace, pod.Name, podMatch.ComplianceViolation),
					fmt.Sprintf("# Node: %s | Compliance Zone: %s", nodeName, podMatch.ComplianceViolation),
					fmt.Sprintf("# Pod bypassing %s compliance isolation", podMatch.ComplianceViolation),
					fmt.Sprintf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace),
					"")
			}

			// Loot: Wildcard bypasses
			if podMatch.WildcardBypass {
				lootWildcardBypasses = append(lootWildcardBypasses,
					fmt.Sprintf("\n### [%s] %s/%s", podMatch.RiskLevel, pod.Namespace, pod.Name),
					fmt.Sprintf("# Node: %s (%s) | Privileged: %v", nodeName, nodeRoles[nodeName], podMatch.IsPrivileged),
					"# WARNING: Wildcard toleration can bypass ALL taints",
				)
				if len(podMatch.SecurityIssues) > 0 {
					lootWildcardBypasses = append(lootWildcardBypasses, "# Issues:")
					for _, issue := range podMatch.SecurityIssues {
						lootWildcardBypasses = append(lootWildcardBypasses, fmt.Sprintf("#   - %s", issue))
					}
				}
				lootWildcardBypasses = append(lootWildcardBypasses,
					fmt.Sprintf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace),
					"")
			}

			// Loot: Remediation
			if len(podMatch.SecurityIssues) > 0 {
				lootRemediation = append(lootRemediation,
					fmt.Sprintf("\n### %s/%s - %d Issues", pod.Namespace, pod.Name, len(podMatch.SecurityIssues)),
				)
				for i, issue := range podMatch.SecurityIssues {
					lootRemediation = append(lootRemediation, fmt.Sprintf("# %d. %s", i+1, issue))
				}
				lootRemediation = append(lootRemediation, "# Remediation steps:")
				if podMatch.UnauthorizedAccess {
					lootRemediation = append(lootRemediation, fmt.Sprintf("#   - Remove tolerations allowing access to %s nodes", nodeRoles[nodeName]))
				}
				if podMatch.WildcardBypass {
					lootRemediation = append(lootRemediation, "#   - Replace wildcard toleration with specific tolerations")
				}
				if podMatch.ComplianceViolation != "" {
					lootRemediation = append(lootRemediation, fmt.Sprintf("#   - Add %s compliance zone taint to prevent unauthorized access", podMatch.ComplianceViolation))
				}
				lootRemediation = append(lootRemediation,
					fmt.Sprintf("#   kubectl edit pod %s -n %s", pod.Name, pod.Namespace),
					"")
			}
		}
	}

	// Build pod toleration table and loot
	podsTable := internal.TableFile{
		Name:   "PodTolerations",
		Header: headersPods,
		Body:   outputRowsPods,
	}

	// Add summary
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d pod-taint combinations with critical risks
# HIGH: %d pod-taint combinations with high risks
# MEDIUM: %d pod-taint combinations with medium risks
# LOW: %d pod-taint combinations with low risks
#
# Focus on CRITICAL and HIGH risk combinations for security review.
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])
		lootContentsPods = append([]string{summary}, lootContentsPods...)
	}

	podsLoot := internal.LootFile{
		Name:     "PodTolerations-info",
		Contents: strings.Join(lootContentsPods, "\n"),
	}

	// Unmatched taints (not tolerated by any pod)
	headersTaints := []string{"Taint", "Risk"}
	var outputRowsTaints [][]string
	var lootContentsTaints []string
	lootContentsTaints = append(lootContentsTaints, `#####################################
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
			outputRowsTaints = append(outputRowsTaints, []string{taint, riskLevel})
			lootContentsTaints = append(lootContentsTaints, fmt.Sprintf("# [%s] %s", riskLevel, taint))
		}
	}
	if len(outputRowsTaints) == 0 {
		outputRowsTaints = append(outputRowsTaints, []string{"<NONE>", "LOW"})
		lootContentsTaints = append(lootContentsTaints, "# All taints are tolerated by at least one pod")
	}

	taintsTable := internal.TableFile{
		Name:   "UnmatchedTaints",
		Header: headersTaints,
		Body:   outputRowsTaints,
	}
	taintsLoot := internal.LootFile{
		Name:     "UnmatchedTaints-info",
		Contents: strings.Join(lootContentsTaints, "\n"),
	}

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
			Loot: []internal.LootFile{
				podsLoot,
				taintsLoot,
				{Name: "Unauthorized-Access", Contents: strings.Join(lootUnauthorizedAccess, "\n")},
				{Name: "Compliance-Violations", Contents: strings.Join(lootComplianceViolations, "\n")},
				{Name: "Wildcard-Bypasses", Contents: strings.Join(lootWildcardBypasses, "\n")},
				{Name: "Remediation-Guide", Contents: strings.Join(lootRemediation, "\n")},
			},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_TAINTS_TOLERATIONS_MODULE_NAME)
		return
	}

	if len(outputRowsPods) > 0 {
		logger.InfoM(fmt.Sprintf("%d pod tolerations found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRowsPods),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
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
		return "CRITICAL", ttMin(score, 100)
	} else if score >= 40 {
		return "HIGH", score
	} else if score >= 20 {
		return "MEDIUM", score
	}
	return "LOW", score
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
		return "MEDIUM"
	}

	// GPU or specialized hardware
	if strings.Contains(lowerTaint, "gpu") ||
		strings.Contains(lowerTaint, "nvidia") {
		return "LOW"
	}

	return "LOW"
}

func ttMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
