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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var TolerationsCmd = &cobra.Command{
	Use:     "tolerations",
	Aliases: []string{"tol"},
	Short:   "List all cluster Pod Tolerations with security analysis",
	Long: `
List all cluster Pod Tolerations with comprehensive security analysis including:
  - Wildcard toleration detection (can schedule anywhere)
  - Master node access detection (pods tolerating control-plane taints)
  - Privilege escalation detection (tolerations + privileged containers)
  - Compliance zone bypass detection (PCI/HIPAA isolation bypass)
  - Infinite/long tolerationSeconds detection
  - Pod security context correlation
  - Risk scoring for dangerous toleration patterns

  cloudfox kubernetes tolerations`,
	Run: ListTolerations,
}

type TolerationsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t TolerationsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t TolerationsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type PodTolerationInfo struct {
	Namespace              string
	PodName                string
	Tolerations            []corev1.Toleration
	WildcardTolerations    []string
	MasterNodeAccess       bool
	ComplianceBypass       string
	IsPrivileged           bool
	HostNetwork            bool
	HostPID                bool
	HostIPC                bool
	ServiceAccount         string
	RiskLevel              string
	RiskScore              int
	SecurityIssues         []string
	PrivilegeEscalation    bool
	InfiniteTolerationSecs bool
}

func ListTolerations(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating pod tolerations for %s", globals.ClusterName), globals.K8S_TOLERATIONS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### Enumerate Toleration Information
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	var lootPodYAMLs []string
	lootPodYAMLs = append(lootPodYAMLs, `#####################################
##### Pod YAMLs for Tolerations
#####################################

`)

	var lootWildcardTolerations []string
	lootWildcardTolerations = append(lootWildcardTolerations, `#####################################
##### Wildcard Tolerations (Security Risk)
#####################################
# Pods with wildcard tolerations can schedule ANYWHERE
# Including master nodes, GPU nodes, compliance zones

`)

	var lootPrivilegeEscalation []string
	lootPrivilegeEscalation = append(lootPrivilegeEscalation, `#####################################
##### Privilege Escalation Risks
#####################################
# Pods with dangerous tolerations + privileged security context
# Can access sensitive nodes with elevated privileges

`)

	var lootComplianceBypass []string
	lootComplianceBypass = append(lootComplianceBypass, `#####################################
##### Compliance Zone Bypass
#####################################
# Pods that can bypass compliance zone isolation
# PCI, HIPAA, or other regulated environments

`)

	var lootMasterAccess []string
	lootMasterAccess = append(lootMasterAccess, `#####################################
##### Master/Control-Plane Access
#####################################
# Pods tolerating master node taints
# Unauthorized access = cluster compromise

`)

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_TOLERATIONS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk",
		"Score",
		"Namespace",
		"Pod Name",
		"Toleration Key",
		"Operator",
		"Value",
		"Effect",
		"Toleration Seconds",
		"Privileged",
		"Host Access",
	}

	var outputRows [][]string
	var podInfos []PodTolerationInfo

	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing pods in namespace: %v", err), globals.K8S_TOLERATIONS_MODULE_NAME)
			continue
		}

		for _, pod := range pods.Items {
			podInfo := PodTolerationInfo{
				Namespace:      pod.Namespace,
				PodName:        pod.Name,
				Tolerations:    pod.Spec.Tolerations,
				ServiceAccount: pod.Spec.ServiceAccountName,
			}

			// Analyze pod security context
			podInfo.HostNetwork = pod.Spec.HostNetwork
			podInfo.HostPID = pod.Spec.HostPID
			podInfo.HostIPC = pod.Spec.HostIPC

			// Check for privileged containers
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil &&
					container.SecurityContext.Privileged != nil &&
					*container.SecurityContext.Privileged {
					podInfo.IsPrivileged = true
					break
				}
			}
			if !podInfo.IsPrivileged {
				for _, container := range pod.Spec.InitContainers {
					if container.SecurityContext != nil &&
						container.SecurityContext.Privileged != nil &&
						*container.SecurityContext.Privileged {
						podInfo.IsPrivileged = true
						break
					}
				}
			}

			// Analyze tolerations
			podInfo.WildcardTolerations = detectWildcardTolerations(pod.Spec.Tolerations)
			podInfo.MasterNodeAccess = detectMasterNodeAccess(pod.Spec.Tolerations)
			podInfo.ComplianceBypass = detectComplianceBypass(pod.Spec.Tolerations)
			podInfo.InfiniteTolerationSecs = detectInfiniteToleration(pod.Spec.Tolerations)

			// Detect privilege escalation
			if (podInfo.IsPrivileged || podInfo.HostNetwork || podInfo.HostPID) &&
				(podInfo.MasterNodeAccess || len(podInfo.WildcardTolerations) > 0) {
				podInfo.PrivilegeEscalation = true
			}

			// Calculate risk
			podInfo.RiskLevel, podInfo.RiskScore = calculateTolerationRiskScore(&podInfo)
			podInfo.SecurityIssues = generateTolerationSecurityIssues(&podInfo)

			riskCounts[podInfo.RiskLevel]++
			podInfos = append(podInfos, podInfo)

			// Add kubectl/jq command for this pod
			lootEnum = append(lootEnum,
				fmt.Sprintf("kubectl get pod %s -n %s -o json | jq '.spec.tolerations[] | {Key:.key, Operator:.operator, Value:.value, Effect:.effect, TolerationSeconds:.tolerationSeconds}' \n",
					pod.Name, pod.Namespace),
			)

			if len(pod.Spec.Tolerations) == 0 {
				hostAccess := formatHostAccess(&podInfo)
				row := []string{
					podInfo.RiskLevel,
					fmt.Sprintf("%d", podInfo.RiskScore),
					k8sinternal.NonEmpty(pod.Namespace),
					k8sinternal.NonEmpty(pod.Name),
					"<NONE>",
					"<NONE>",
					"<NONE>",
					"<NONE>",
					"<NONE>",
					fmt.Sprintf("%v", podInfo.IsPrivileged),
					hostAccess,
				}
				outputRows = append(outputRows, row)
			} else {
				for _, tol := range pod.Spec.Tolerations {
					seconds := "<NONE>"
					if tol.TolerationSeconds != nil {
						if *tol.TolerationSeconds == 0 {
							seconds = "0 (Infinite)"
						} else {
							seconds = fmt.Sprintf("%d", *tol.TolerationSeconds)
						}
					}

					hostAccess := formatHostAccess(&podInfo)
					row := []string{
						podInfo.RiskLevel,
						fmt.Sprintf("%d", podInfo.RiskScore),
						k8sinternal.NonEmpty(pod.Namespace),
						k8sinternal.NonEmpty(pod.Name),
						k8sinternal.NonEmpty(tol.Key),
						k8sinternal.NonEmpty(string(tol.Operator)),
						k8sinternal.NonEmpty(tol.Value),
						k8sinternal.NonEmpty(string(tol.Effect)),
						seconds,
						fmt.Sprintf("%v", podInfo.IsPrivileged),
						hostAccess,
					}
					outputRows = append(outputRows, row)
				}
			}

			// Generate example pod YAML using pod tolerations and node selector if present
			examplePod := corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("example-%s", pod.Name),
				},
				Spec: corev1.PodSpec{
					Tolerations: pod.Spec.Tolerations,
					Containers: []corev1.Container{
						{
							Name:    "alpine",
							Image:   "alpine:latest",
							Command: []string{"sh", "-c", "sleep 3600"},
						},
					},
				},
			}

			var nodeSelectorComment string
			if len(pod.Spec.NodeSelector) > 0 {
				examplePod.Spec.NodeSelector = pod.Spec.NodeSelector
				nodeSelectorComment = fmt.Sprintf("# NodeSelector applied: %v", pod.Spec.NodeSelector)
			}

			yamlData, err := yaml.Marshal(examplePod)
			if err == nil {
				var commentLines []string
				commentLines = append(commentLines, fmt.Sprintf("# Example pod with alpine container sleeping 3600s (Risk: %s)", podInfo.RiskLevel))
				if nodeSelectorComment != "" {
					commentLines = append(commentLines, nodeSelectorComment)
				}
				if len(podInfo.SecurityIssues) > 0 {
					commentLines = append(commentLines, fmt.Sprintf("# Security Issues: %d", len(podInfo.SecurityIssues)))
				}
				lootPodYAMLs = append(lootPodYAMLs,
					fmt.Sprintf("%s\n# --- Pod YAML for %s/%s\n%s", strings.Join(commentLines, "\n"), pod.Namespace, pod.Name, string(yamlData)),
					fmt.Sprintf("# Apply with: kubectl create -f <filename>.yaml\n"),
				)
			} else {
				logger.ErrorM(fmt.Sprintf("Error marshaling pod YAML for %s/%s: %v", pod.Namespace, pod.Name, err), globals.K8S_TOLERATIONS_MODULE_NAME)
			}

			// Loot: Wildcard tolerations
			if len(podInfo.WildcardTolerations) > 0 {
				lootWildcardTolerations = append(lootWildcardTolerations,
					fmt.Sprintf("\n### [%s] %s/%s (Score: %d)", podInfo.RiskLevel, pod.Namespace, pod.Name, podInfo.RiskScore),
					fmt.Sprintf("# Wildcard Tolerations: %s", strings.Join(podInfo.WildcardTolerations, ", ")),
				)
				if podInfo.IsPrivileged {
					lootWildcardTolerations = append(lootWildcardTolerations, "# WARNING: Privileged pod with wildcard tolerations")
				}
				if len(podInfo.SecurityIssues) > 0 {
					lootWildcardTolerations = append(lootWildcardTolerations, "# Security Issues:")
					for _, issue := range podInfo.SecurityIssues {
						lootWildcardTolerations = append(lootWildcardTolerations, fmt.Sprintf("#   - %s", issue))
					}
				}
				lootWildcardTolerations = append(lootWildcardTolerations, "")
			}

			// Loot: Privilege escalation
			if podInfo.PrivilegeEscalation {
				lootPrivilegeEscalation = append(lootPrivilegeEscalation,
					fmt.Sprintf("\n### [CRITICAL] %s/%s", pod.Namespace, pod.Name),
					fmt.Sprintf("# Privileged: %v | HostNetwork: %v | HostPID: %v | HostIPC: %v",
						podInfo.IsPrivileged, podInfo.HostNetwork, podInfo.HostPID, podInfo.HostIPC),
					fmt.Sprintf("# Master Access: %v | Wildcard Tolerations: %d",
						podInfo.MasterNodeAccess, len(podInfo.WildcardTolerations)),
				)
				if len(podInfo.SecurityIssues) > 0 {
					lootPrivilegeEscalation = append(lootPrivilegeEscalation, "# Security Issues:")
					for _, issue := range podInfo.SecurityIssues {
						lootPrivilegeEscalation = append(lootPrivilegeEscalation, fmt.Sprintf("#   - %s", issue))
					}
				}
				lootPrivilegeEscalation = append(lootPrivilegeEscalation,
					fmt.Sprintf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace),
					"")
			}

			// Loot: Compliance bypass
			if podInfo.ComplianceBypass != "" {
				lootComplianceBypass = append(lootComplianceBypass,
					fmt.Sprintf("\n### [%s] %s/%s - %s Bypass", podInfo.RiskLevel, pod.Namespace, pod.Name, podInfo.ComplianceBypass),
					fmt.Sprintf("# Can access %s compliance zone", podInfo.ComplianceBypass),
					fmt.Sprintf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace),
					"")
			}

			// Loot: Master access
			if podInfo.MasterNodeAccess {
				lootMasterAccess = append(lootMasterAccess,
					fmt.Sprintf("\n### [%s] %s/%s (Score: %d)", podInfo.RiskLevel, pod.Namespace, pod.Name, podInfo.RiskScore),
					fmt.Sprintf("# Tolerates master/control-plane taints"),
					fmt.Sprintf("# Privileged: %v | ServiceAccount: %s", podInfo.IsPrivileged, podInfo.ServiceAccount),
				)
				if len(podInfo.SecurityIssues) > 0 {
					lootMasterAccess = append(lootMasterAccess, "# Security Issues:")
					for _, issue := range podInfo.SecurityIssues {
						lootMasterAccess = append(lootMasterAccess, fmt.Sprintf("#   - %s", issue))
					}
				}
				lootMasterAccess = append(lootMasterAccess,
					fmt.Sprintf("kubectl get pod %s -n %s -o yaml", pod.Name, pod.Namespace),
					"")
			}
		}
	}

	table := internal.TableFile{
		Name:   "Tolerations",
		Header: headers,
		Body:   outputRows,
	}

	// Add summary
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d pods with critical toleration risks
# HIGH: %d pods with high-risk tolerations
# MEDIUM: %d pods with medium-risk tolerations
# LOW: %d pods with low/no risk tolerations
#
# Focus on CRITICAL and HIGH risk pods for security review.
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])
		lootWildcardTolerations = append([]string{summary}, lootWildcardTolerations...)
	}

	loot1 := internal.LootFile{
		Name:     "Tolerations-Enum",
		Contents: strings.Join(k8sinternal.Unique(lootEnum), "\n"),
	}

	loot2 := internal.LootFile{
		Name:     "Pod-YAMLs",
		Contents: strings.Join(lootPodYAMLs, "\n"),
	}

	loot3 := internal.LootFile{
		Name:     "Wildcard-Tolerations",
		Contents: strings.Join(lootWildcardTolerations, "\n"),
	}

	loot4 := internal.LootFile{
		Name:     "Privilege-Escalation",
		Contents: strings.Join(lootPrivilegeEscalation, "\n"),
	}

	loot5 := internal.LootFile{
		Name:     "Compliance-Bypass",
		Contents: strings.Join(lootComplianceBypass, "\n"),
	}

	loot6 := internal.LootFile{
		Name:     "Master-Access",
		Contents: strings.Join(lootMasterAccess, "\n"),
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Tolerations",
		globals.ClusterName,
		"results",
		TolerationsOutput{
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{loot1, loot2, loot3, loot4, loot5, loot6},
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_TOLERATIONS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d pod tolerations found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_TOLERATIONS_MODULE_NAME)
	} else {
		logger.InfoM("No pod tolerations found, skipping output file creation", globals.K8S_TOLERATIONS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_TOLERATIONS_MODULE_NAME), globals.K8S_TOLERATIONS_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

func detectWildcardTolerations(tolerations []corev1.Toleration) []string {
	var wildcards []string

	for _, tol := range tolerations {
		// Empty key with Exists operator = tolerate ALL taints
		if tol.Key == "" && tol.Operator == corev1.TolerationOpExists {
			wildcards = append(wildcards, "key=\"\" operator=Exists (tolerates ALL taints)")
		}
		// Exists operator without specific value
		if tol.Operator == corev1.TolerationOpExists && tol.Key != "" && tol.Effect == "" {
			wildcards = append(wildcards, fmt.Sprintf("key=%s operator=Exists effect=\"\" (tolerates all effects)", tol.Key))
		}
	}

	return wildcards
}

func detectMasterNodeAccess(tolerations []corev1.Toleration) bool {
	masterTaintPatterns := []string{
		"node-role.kubernetes.io/master",
		"node-role.kubernetes.io/control-plane",
		"CriticalAddonsOnly",
		"dedicated=master",
	}

	for _, tol := range tolerations {
		// Wildcard toleration
		if tol.Key == "" && tol.Operator == corev1.TolerationOpExists {
			return true
		}

		// Check for master-specific tolerations
		lowerKey := strings.ToLower(tol.Key)
		for _, pattern := range masterTaintPatterns {
			if strings.Contains(lowerKey, strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}

func detectComplianceBypass(tolerations []corev1.Toleration) string {
	compliancePatterns := map[string]string{
		"pci":        "PCI",
		"hipaa":      "HIPAA",
		"compliance": "Compliance",
	}

	for _, tol := range tolerations {
		// Wildcard toleration can bypass any compliance zone
		if tol.Key == "" && tol.Operator == corev1.TolerationOpExists {
			return "ALL (wildcard)"
		}

		lowerKey := strings.ToLower(tol.Key)
		for pattern, zone := range compliancePatterns {
			if strings.Contains(lowerKey, pattern) {
				return zone
			}
		}
	}

	return ""
}

func detectInfiniteToleration(tolerations []corev1.Toleration) bool {
	for _, tol := range tolerations {
		if tol.TolerationSeconds != nil && *tol.TolerationSeconds == 0 {
			return true
		}
		// nil TolerationSeconds = infinite for NoExecute taints
		if tol.TolerationSeconds == nil && tol.Effect == corev1.TaintEffectNoExecute {
			return true
		}
	}
	return false
}

func calculateTolerationRiskScore(podInfo *PodTolerationInfo) (string, int) {
	score := 0

	// Wildcard tolerations are very high risk
	if len(podInfo.WildcardTolerations) > 0 {
		score += 50
	}

	// Master node access
	if podInfo.MasterNodeAccess {
		score += 40
	}

	// Compliance bypass
	if podInfo.ComplianceBypass != "" {
		score += 35
	}

	// Privileged containers with dangerous tolerations
	if podInfo.IsPrivileged {
		score += 20
		if podInfo.MasterNodeAccess || len(podInfo.WildcardTolerations) > 0 {
			score += 20 // Extra penalty for privilege escalation
		}
	}

	// Host access
	if podInfo.HostNetwork {
		score += 15
	}
	if podInfo.HostPID || podInfo.HostIPC {
		score += 15
	}

	// Infinite toleration seconds
	if podInfo.InfiniteTolerationSecs {
		score += 10
	}

	// Determine risk level
	if score >= 70 {
		return "CRITICAL", tolerationsMin(score, 100)
	} else if score >= 40 {
		return "HIGH", score
	} else if score >= 20 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func generateTolerationSecurityIssues(podInfo *PodTolerationInfo) []string {
	var issues []string

	if len(podInfo.WildcardTolerations) > 0 {
		issues = append(issues, "Wildcard tolerations - can schedule on ANY node including master/GPU/compliance zones")
	}

	if podInfo.MasterNodeAccess {
		issues = append(issues, "Can access master/control-plane nodes - cluster compromise risk")
	}

	if podInfo.ComplianceBypass != "" {
		issues = append(issues, fmt.Sprintf("Can bypass %s compliance zone isolation", podInfo.ComplianceBypass))
	}

	if podInfo.PrivilegeEscalation {
		issues = append(issues, "PRIVILEGE ESCALATION: Privileged pod + dangerous tolerations")
	}

	if podInfo.IsPrivileged {
		issues = append(issues, "Privileged container - full host access")
	}

	if podInfo.HostNetwork {
		issues = append(issues, "HostNetwork=true - can access node network stack")
	}

	if podInfo.HostPID {
		issues = append(issues, "HostPID=true - can see all host processes")
	}

	if podInfo.HostIPC {
		issues = append(issues, "HostIPC=true - can access host IPC")
	}

	if podInfo.InfiniteTolerationSecs {
		issues = append(issues, "Infinite tolerationSeconds - survives node evictions")
	}

	return issues
}

func formatHostAccess(podInfo *PodTolerationInfo) string {
	var access []string
	if podInfo.HostNetwork {
		access = append(access, "Net")
	}
	if podInfo.HostPID {
		access = append(access, "PID")
	}
	if podInfo.HostIPC {
		access = append(access, "IPC")
	}
	if len(access) == 0 {
		return "None"
	}
	return strings.Join(access, ",")
}

func tolerationsMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
