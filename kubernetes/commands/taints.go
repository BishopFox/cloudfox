package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var TaintsCmd = &cobra.Command{
	Use:     "taints",
	Aliases: []string{},
	Short:   "List all cluster Node Taints with security analysis",
	Long: `
List all cluster Node Taints with comprehensive security analysis including:
  - Critical taint detection (master nodes, GPU, compliance zones)
  - Node role categorization
  - Risk scoring for sensitive node taints
  - Wildcard toleration examples for bypass scenarios
  - Node label correlation for context
  - Grouping by taint effect (NoSchedule, NoExecute, PreferNoSchedule)

  cloudfox kubernetes taints`,
	Run: ListTaints,
}

type TaintsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t TaintsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t TaintsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type NodeTaintInfo struct {
	NodeName        string
	NodeRole        string
	IsMaster        bool
	IsGPU           bool
	ComplianceZone  string
	Taints          []corev1.Taint
	CriticalTaints  []string
	RiskLevel       string
	RiskScore       int
	SecurityIssues  []string
	NodeLabels      map[string]string
}

// Critical taint patterns that indicate security-sensitive nodes
var criticalTaintPatterns = []string{
	"node-role.kubernetes.io/master",
	"node-role.kubernetes.io/control-plane",
	"CriticalAddonsOnly",
	"dedicated=master",
	"dedicated=admin",
	"compliance-zone",
	"pci-compliant",
	"hipaa-compliant",
	"security-zone",
}

// GPU and specialized hardware patterns
var gpuTaintPatterns = []string{
	"nvidia.com/gpu",
	"amd.com/gpu",
	"gpu",
	"accelerator",
}

func ListTaints(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating node taints for %s", globals.ClusterName), globals.K8S_TAINTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	loot := shared.NewLootBuilder()
	loot.Section("Taint-Enum").SetHeader(`#####################################
##### Enumerate Taint Information
#####################################

`)
	if globals.KubeContext != "" {
		loot.Section("Taint-Enum").Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	loot.Section("Pod-YAMLs").SetHeader(`#####################################
##### Pod YAMLs for Tolerations
#####################################
# Example pods that tolerate specific taints
# Use these for testing or bypass scenarios

`)

	loot.Section("Wildcard-Bypass-YAMLs").SetHeader(`#####################################
##### Wildcard Toleration Examples
#####################################
# WARNING: These pods can bypass ALL taints
# Use for security testing only

`)

	loot.Section("Critical-Taints").SetHeader(`#####################################
##### Critical/Sensitive Node Taints
#####################################
# Taints on security-sensitive nodes
# Master nodes, GPU nodes, compliance zones

`)

	loot.Section("Taints-By-Effect").SetHeader(`#####################################
##### Taints Grouped by Effect
#####################################

`)

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "nodes", "", err, globals.K8S_TAINTS_MODULE_NAME, true)
		return
	}

	var tableRows [][]string
	var nodeInfos []NodeTaintInfo
	taintsByEffect := map[string][]string{
		"NoSchedule":       {},
		"NoExecute":        {},
		"PreferNoSchedule": {},
	}

	riskCounts := shared.NewRiskCounts()

	for _, node := range nodes.Items {
		nodeInfo := NodeTaintInfo{
			NodeName:   node.Name,
			NodeLabels: node.Labels,
			Taints:     node.Spec.Taints,
		}

		// Detect node role
		nodeInfo.NodeRole = detectNodeRole(node.Labels)
		nodeInfo.IsMaster = isMasterNode(node.Labels, node.Spec.Taints)
		nodeInfo.IsGPU = isGPUNode(node.Labels, node.Spec.Taints)
		nodeInfo.ComplianceZone = detectComplianceZone(node.Labels, node.Spec.Taints)

		// Analyze taints for security issues
		nodeInfo.CriticalTaints = detectCriticalTaints(node.Spec.Taints)
		nodeInfo.RiskLevel, nodeInfo.RiskScore = calculateTaintRiskScore(&nodeInfo)
		nodeInfo.SecurityIssues = generateTaintSecurityIssues(&nodeInfo)

		riskCounts.Add(nodeInfo.RiskLevel)
		nodeInfos = append(nodeInfos, nodeInfo)

		// Table rows
		if len(node.Spec.Taints) == 0 {
			tableRows = append(tableRows, []string{
				nodeInfo.NodeName,
				nodeInfo.NodeRole,
				"<NONE>",
				"<NONE>",
				"<NONE>",
				"<NONE>",
			})
			continue
		}

		var tolerations []corev1.Toleration
		for _, taint := range node.Spec.Taints {
			timeAdded := "<NONE>"
			if taint.TimeAdded != nil {
				timeAdded = taint.TimeAdded.String()
			}

			tableRows = append(tableRows, []string{
				nodeInfo.NodeName,
				nodeInfo.NodeRole,
				k8sinternal.NonEmpty(taint.Key),
				k8sinternal.NonEmpty(taint.Value),
				k8sinternal.NonEmpty(string(taint.Effect)),
				timeAdded,
			})

			tolerations = append(tolerations, corev1.Toleration{
				Key:      taint.Key,
				Operator: corev1.TolerationOpEqual,
				Value:    taint.Value,
				Effect:   taint.Effect,
			})

			// Group by effect
			effectKey := string(taint.Effect)
			taintStr := fmt.Sprintf("Node: %s | Key: %s | Value: %s", node.Name, taint.Key, taint.Value)
			taintsByEffect[effectKey] = append(taintsByEffect[effectKey], taintStr)
		}

		// Loot file 1: kubectl + jq command
		lootCmd := fmt.Sprintf(
			"kubectl get node %s -o json | jq '.spec.taints[] | {nodeName: \"%s\", key: .key, value: .value, effect: .effect}'",
			nodeInfo.NodeName,
			nodeInfo.NodeName,
		)
		loot.Section("Taint-Enum").Add(lootCmd)

		// Loot file 2: example Pod YAML with exact tolerations
		pod := corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("tolerate-%s", nodeInfo.NodeName),
			},
			Spec: corev1.PodSpec{
				NodeName:    nodeInfo.NodeName,
				Tolerations: tolerations,
				Containers: []corev1.Container{
					{
						Name:    "alpine",
						Image:   "alpine:latest",
						Command: []string{"sh", "-c", "sleep 3600"},
					},
				},
			},
		}

		yamlData, err := yaml.Marshal(pod)
		if err == nil {
			loot.Section("Pod-YAMLs").Addf("# --- POD YAML for node: %s (Role: %s, Risk: %s) ---\n%s",
				nodeInfo.NodeName, nodeInfo.NodeRole, nodeInfo.RiskLevel, string(yamlData))
			loot.Section("Pod-YAMLs").Add("# Apply with: kubectl create -f <filename>.yaml\n")
		} else {
			logger.ErrorM(fmt.Sprintf("Error marshaling YAML for node %s: %v", nodeInfo.NodeName, err), globals.K8S_TAINTS_MODULE_NAME)
		}

		// Loot file 3: Wildcard toleration examples (bypass scenarios)
		if nodeInfo.IsMaster || len(nodeInfo.CriticalTaints) > 0 {
			wildcardPod := corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("bypass-%s", nodeInfo.NodeName),
				},
				Spec: corev1.PodSpec{
					NodeName: nodeInfo.NodeName,
					Tolerations: []corev1.Toleration{
						{
							Key:      "",
							Operator: corev1.TolerationOpExists,
							Effect:   "",
						},
					},
					Containers: []corev1.Container{
						{
							Name:    "alpine",
							Image:   "alpine:latest",
							Command: []string{"sh", "-c", "sleep 3600"},
						},
					},
				},
			}

			wildcardYAML, err := yaml.Marshal(wildcardPod)
			if err == nil {
				loot.Section("Wildcard-Bypass-YAMLs").Addf("# --- WILDCARD BYPASS for node: %s (Role: %s) ---", nodeInfo.NodeName, nodeInfo.NodeRole)
				loot.Section("Wildcard-Bypass-YAMLs").Addf("# WARNING: Tolerates ALL taints with operator: Exists\n%s", string(wildcardYAML))
				loot.Section("Wildcard-Bypass-YAMLs").Add("# Apply with: kubectl create -f <filename>.yaml\n")
			}
		}

		// Loot file 4: Critical taints
		if len(nodeInfo.CriticalTaints) > 0 {
			loot.Section("Critical-Taints").Addf("\n### Node: %s (Role: %s, Risk: %s)", nodeInfo.NodeName, nodeInfo.NodeRole, nodeInfo.RiskLevel)
			for _, ct := range nodeInfo.CriticalTaints {
				loot.Section("Critical-Taints").Addf("# - %s", ct)
			}
			if len(nodeInfo.SecurityIssues) > 0 {
				loot.Section("Critical-Taints").Add("# Security Issues:")
				for _, issue := range nodeInfo.SecurityIssues {
					loot.Section("Critical-Taints").Addf("#   - %s", issue)
				}
			}
			if nodeInfo.ComplianceZone != "" {
				loot.Section("Critical-Taints").Addf("# Compliance Zone: %s", nodeInfo.ComplianceZone)
			}
			loot.Section("Critical-Taints").Add("")
		}
	}

	// Loot file 5: Taints grouped by effect
	for effect, taints := range taintsByEffect {
		if len(taints) > 0 {
			loot.Section("Taints-By-Effect").Addf("\n### %s (Count: %d)", effect, len(taints))
			for _, t := range taints {
				loot.Section("Taints-By-Effect").Addf("# %s", t)
			}
			loot.Section("Taints-By-Effect").Add("")
		}
	}

	// Sort table rows by node name
	sort.SliceStable(tableRows, func(i, j int) bool {
		return tableRows[i][0] < tableRows[j][0]
	})

	headers := []string{
		"Node Name",
		"Node Role",
		"Taint Key",
		"Taint Value",
		"Taint Effect",
		"Time Added",
	}
	table := internal.TableFile{
		Name:   "Taints",
		Header: headers,
		Body:   tableRows,
	}

	// Add summary to critical taints
	if riskCounts.Critical > 0 || riskCounts.High > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d nodes with critical taints
# HIGH: %d nodes with high-risk taints
# MEDIUM: %d nodes with medium-risk taints
# LOW: %d nodes with low/no taints
#
# Focus on CRITICAL and HIGH risk nodes for security review.
`, riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low)
		loot.Section("Critical-Taints").SetSummary(summary)
	}

	// Create loot files
	lootFiles := loot.Build()

	// Pass loot files in the output
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Taints",
		globals.ClusterName,
		"results",
		TaintsOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_TAINTS_MODULE_NAME)
		return
	}

	if len(tableRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d node taints found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(tableRows),
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
			globals.K8S_TAINTS_MODULE_NAME)
	} else {
		logger.InfoM("No node taints found, skipping output file creation", globals.K8S_TAINTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_TAINTS_MODULE_NAME), globals.K8S_TAINTS_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

func detectNodeRole(labels map[string]string) string {
	// Check for common role labels
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		return "master"
	}
	if _, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
		return "control-plane"
	}
	if role, ok := labels["kubernetes.io/role"]; ok {
		return role
	}
	if role, ok := labels["node-role.kubernetes.io/worker"]; ok {
		if role == "true" || role == "" {
			return "worker"
		}
	}

	// Check for specialized roles
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

func isMasterNode(labels map[string]string, taints []corev1.Taint) bool {
	// Check labels
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		return true
	}
	if _, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
		return true
	}

	// Check taints
	for _, taint := range taints {
		if strings.Contains(taint.Key, "master") || strings.Contains(taint.Key, "control-plane") {
			return true
		}
	}

	return false
}

func isGPUNode(labels map[string]string, taints []corev1.Taint) bool {
	// Check labels
	for key := range labels {
		if strings.Contains(strings.ToLower(key), "gpu") ||
			strings.Contains(strings.ToLower(key), "nvidia") ||
			strings.Contains(strings.ToLower(key), "accelerator") {
			return true
		}
	}

	// Check taints
	for _, taint := range taints {
		for _, pattern := range gpuTaintPatterns {
			if strings.Contains(strings.ToLower(taint.Key), strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}

func detectComplianceZone(labels map[string]string, taints []corev1.Taint) string {
	// Check labels
	for key, value := range labels {
		lowerKey := strings.ToLower(key)
		lowerValue := strings.ToLower(value)
		if strings.Contains(lowerKey, "compliance") || strings.Contains(lowerKey, "pci") || strings.Contains(lowerKey, "hipaa") {
			return value
		}
		if strings.Contains(lowerValue, "pci") {
			return "PCI"
		}
		if strings.Contains(lowerValue, "hipaa") {
			return "HIPAA"
		}
	}

	// Check taints
	for _, taint := range taints {
		lowerKey := strings.ToLower(taint.Key)
		if strings.Contains(lowerKey, "pci") {
			return "PCI"
		}
		if strings.Contains(lowerKey, "hipaa") {
			return "HIPAA"
		}
		if strings.Contains(lowerKey, "compliance") {
			return taint.Value
		}
	}

	return ""
}

func detectCriticalTaints(taints []corev1.Taint) []string {
	var critical []string

	for _, taint := range taints {
		if isCriticalTaint(taint) {
			critical = append(critical, fmt.Sprintf("%s=%s:%s", taint.Key, taint.Value, taint.Effect))
		}
	}

	return critical
}

func isCriticalTaint(taint corev1.Taint) bool {
	lowerKey := strings.ToLower(taint.Key)

	for _, pattern := range criticalTaintPatterns {
		if strings.Contains(lowerKey, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

func calculateTaintRiskScore(nodeInfo *NodeTaintInfo) (string, int) {
	score := 0

	// Master nodes are high risk
	if nodeInfo.IsMaster {
		score += 50
	}

	// Critical taints
	if len(nodeInfo.CriticalTaints) > 0 {
		score += len(nodeInfo.CriticalTaints) * 20
	}

	// GPU nodes are medium risk (expensive, specialized)
	if nodeInfo.IsGPU {
		score += 25
	}

	// Compliance zones are high risk
	if nodeInfo.ComplianceZone != "" {
		score += 40
	}

	// Number of taints (more taints = more restrictions = higher value node)
	if len(nodeInfo.Taints) > 3 {
		score += 15
	}

	// Determine risk level
	if score >= 70 {
		return shared.RiskCritical, taintsMin(score, 100)
	} else if score >= 40 {
		return shared.RiskHigh, score
	} else if score >= 20 {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
}

func generateTaintSecurityIssues(nodeInfo *NodeTaintInfo) []string {
	var issues []string

	if nodeInfo.IsMaster {
		issues = append(issues, "Master/control-plane node - unauthorized access = cluster compromise")
	}

	if nodeInfo.IsGPU {
		issues = append(issues, "GPU node - expensive resource, potential for crypto mining abuse")
	}

	if nodeInfo.ComplianceZone != "" {
		issues = append(issues, fmt.Sprintf("Compliance zone (%s) - unauthorized pods violate compliance", nodeInfo.ComplianceZone))
	}

	if len(nodeInfo.CriticalTaints) > 0 {
		issues = append(issues, fmt.Sprintf("%d critical taints - pods with wildcard tolerations can bypass", len(nodeInfo.CriticalTaints)))
	}

	// Check for NoExecute taints (will evict running pods)
	for _, taint := range nodeInfo.Taints {
		if taint.Effect == corev1.TaintEffectNoExecute {
			issues = append(issues, fmt.Sprintf("NoExecute taint '%s' - will evict non-tolerating pods", taint.Key))
		}
	}

	return issues
}

func taintsMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
