package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var PriorityClassesCmd = &cobra.Command{
	Use:     "priorityclasses",
	Aliases: []string{"pc", "priorities"},
	Short:   "Enumerate PriorityClasses and pod priorities with security analysis",
	Long: `
Enumerate PriorityClasses with comprehensive security analysis including:
  - Non-system pods with system-level priority (preemption abuse)
  - Privilege escalation via high-priority pods
  - Availability impact (critical workloads at risk of preemption)
  - Default PriorityClass gaps
  - PriorityClass creation permissions (RBAC analysis)
  - Preemption policy risks
  - Pod priority distribution analysis
  - Risk scoring based on misuse potential

  cloudfox kubernetes priorityclasses`,
	Run: ListPriorityClasses,
}

type PriorityClassesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PriorityClassesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t PriorityClassesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type PriorityClassAnalysis struct {
	Name                string
	Value               int32
	GlobalDefault       bool
	PreemptionPolicy    string
	Description         string
	IsSystemClass       bool
	RiskLevel           string
	RiskScore           int
	SecurityIssues      []string
	PodsUsingClass      int
	SystemPodsUsingIt   int
	UserPodsUsingIt     int
	NamespacesUsingIt   []string
}

type PodPriorityAnalysis struct {
	Namespace        string
	PodName          string
	PriorityClass    string
	PriorityValue    int32
	PreemptionPolicy string
	IsPrivileged     bool
	HostNetwork      bool
	IsSystemPod      bool
	RiskLevel        string
	RiskScore        int
	SecurityIssues   []string
	CanPreempt       bool
	VulnerableToPreempt bool
}

// System priority ranges
const (
	SystemCriticalPriority = 2000000000 // k8s system-cluster-critical
	SystemNodeCritical     = 2000001000 // k8s system-node-critical
	HighPriorityThreshold  = 1000000    // User pods above this are suspicious
)

func ListPriorityClasses(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating priority classes for %s", globals.ClusterName), globals.K8S_PRIORITYCLASSES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	var lootEnum []string
	lootEnum = append(lootEnum, `#####################################
##### PriorityClass Enumeration
#####################################

`)
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	var lootAbuse []string
	lootAbuse = append(lootAbuse, `#####################################
##### Priority Abuse Detection
#####################################
# User pods with system-level priorities
# Can preempt critical system components

`)

	var lootPreemptionRisks []string
	lootPreemptionRisks = append(lootPreemptionRisks, `#####################################
##### Preemption Risk Analysis
#####################################
# Pods vulnerable to preemption
# Availability impact assessment

`)

	var lootPrivilegeEscalation []string
	lootPrivilegeEscalation = append(lootPrivilegeEscalation, `#####################################
##### Privilege Escalation via Priority
#####################################
# High-priority privileged pods
# Can disrupt cluster and evict workloads

`)

	var lootDefaultClass []string
	lootDefaultClass = append(lootDefaultClass, `#####################################
##### Default PriorityClass Analysis
#####################################
# Global default priority class configuration

`)

	var lootRemediation []string
	lootRemediation = append(lootRemediation, `#####################################
##### Remediation Guidance
#####################################

`)

	// Get all PriorityClasses
	priorityClasses, err := clientset.SchedulingV1().PriorityClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing priority classes: %v", err), globals.K8S_PRIORITYCLASSES_MODULE_NAME)
		return
	}

	// Get all pods for usage analysis
	allPods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Warning: Could not list pods: %v", err), globals.K8S_PRIORITYCLASSES_MODULE_NAME)
		allPods = &corev1.PodList{}
	}

	// Build priority class usage map
	pcUsage := make(map[string][]corev1.Pod)
	defaultPriorityPods := []corev1.Pod{}

	for _, pod := range allPods.Items {
		if pod.Spec.PriorityClassName != "" {
			pcUsage[pod.Spec.PriorityClassName] = append(pcUsage[pod.Spec.PriorityClassName], pod)
		} else {
			defaultPriorityPods = append(defaultPriorityPods, pod)
		}
	}

	headers := []string{
		"Risk",
		"Score",
		"PriorityClass",
		"Priority Value",
		"Global Default",
		"Preemption Policy",
		"Pods Using It",
		"System Pods",
		"User Pods",
		"Issues",
	}

	var outputRows [][]string
	var pcAnalyses []PriorityClassAnalysis

	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	var globalDefaultPC string

	for _, pc := range priorityClasses.Items {
		analysis := PriorityClassAnalysis{
			Name:             pc.Name,
			Value:            pc.Value,
			GlobalDefault:    pc.GlobalDefault,
			PreemptionPolicy: string(*pc.PreemptionPolicy),
			Description:      pc.Description,
			IsSystemClass:    isSystemPriorityClass(pc.Name, pc.Value),
		}

		if pc.GlobalDefault {
			globalDefaultPC = pc.Name
		}

		// Analyze pods using this priority class
		pods := pcUsage[pc.Name]
		analysis.PodsUsingClass = len(pods)

		for _, pod := range pods {
			if isSystemPod(pod.Namespace, pod.Name) {
				analysis.SystemPodsUsingIt++
			} else {
				analysis.UserPodsUsingIt++
			}

			if !containsString(analysis.NamespacesUsingIt, pod.Namespace) {
				analysis.NamespacesUsingIt = append(analysis.NamespacesUsingIt, pod.Namespace)
			}
		}

		// Security analysis
		analysis.SecurityIssues = analyzePriorityClassSecurity(&analysis, pods)
		analysis.RiskLevel, analysis.RiskScore = calculatePriorityClassRisk(&analysis)

		riskCounts[analysis.RiskLevel]++
		pcAnalyses = append(pcAnalyses, analysis)

		outputRows = append(outputRows, []string{
			analysis.RiskLevel,
			fmt.Sprintf("%d", analysis.RiskScore),
			pc.Name,
			fmt.Sprintf("%d", pc.Value),
			fmt.Sprintf("%v", pc.GlobalDefault),
			analysis.PreemptionPolicy,
			fmt.Sprintf("%d", analysis.PodsUsingClass),
			fmt.Sprintf("%d", analysis.SystemPodsUsingIt),
			fmt.Sprintf("%d", analysis.UserPodsUsingIt),
			fmt.Sprintf("%d", len(analysis.SecurityIssues)),
		})

		// Loot generation
		lootEnum = append(lootEnum, fmt.Sprintf("\n# [%s] PriorityClass: %s", analysis.RiskLevel, pc.Name))
		lootEnum = append(lootEnum, fmt.Sprintf("# Value: %d | Global Default: %v | Pods: %d", pc.Value, pc.GlobalDefault, analysis.PodsUsingClass))
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl get priorityclass %s -o yaml", pc.Name))
		lootEnum = append(lootEnum, "")

		// Loot: Priority abuse
		if analysis.UserPodsUsingIt > 0 && analysis.IsSystemClass {
			lootAbuse = append(lootAbuse, fmt.Sprintf("\n### [CRITICAL] %s - User pods with system priority", pc.Name))
			lootAbuse = append(lootAbuse, fmt.Sprintf("# Priority Value: %d (System-level)", pc.Value))
			lootAbuse = append(lootAbuse, fmt.Sprintf("# User Pods: %d | Namespaces: %s", analysis.UserPodsUsingIt, strings.Join(analysis.NamespacesUsingIt, ", ")))
			lootAbuse = append(lootAbuse, "# These pods can preempt system components!")
			lootAbuse = append(lootAbuse, fmt.Sprintf("kubectl get pods --all-namespaces --field-selector spec.priorityClassName=%s", pc.Name))
			lootAbuse = append(lootAbuse, "")
		}

		// Loot: Privilege escalation
		for _, pod := range pods {
			if isPodPrivilegedPC(&pod) && !isSystemPod(pod.Namespace, pod.Name) {
				if !strings.Contains(strings.Join(lootPrivilegeEscalation, "\n"), pod.Namespace+"/"+pod.Name) {
					lootPrivilegeEscalation = append(lootPrivilegeEscalation, fmt.Sprintf("\n### [CRITICAL] %s/%s", pod.Namespace, pod.Name))
					lootPrivilegeEscalation = append(lootPrivilegeEscalation, fmt.Sprintf("# PriorityClass: %s (Value: %d)", pc.Name, pc.Value))
					lootPrivilegeEscalation = append(lootPrivilegeEscalation, fmt.Sprintf("# Privileged: %v | HostNetwork: %v", isPodPrivilegedPC(&pod), pod.Spec.HostNetwork))
					lootPrivilegeEscalation = append(lootPrivilegeEscalation, "# Can preempt other workloads + has elevated host access")
					lootPrivilegeEscalation = append(lootPrivilegeEscalation, "")
				}
			}
		}
	}

	// Analyze pods without explicit priority class (using default)
	if len(defaultPriorityPods) > 0 {
		lootDefaultClass = append(lootDefaultClass, fmt.Sprintf("\n# Global Default PriorityClass: %s", globalDefaultPC))
		if globalDefaultPC == "" {
			lootDefaultClass = append(lootDefaultClass, "# WARNING: No global default - pods get priority 0")
		}
		lootDefaultClass = append(lootDefaultClass, fmt.Sprintf("# Pods without explicit priority: %d", len(defaultPriorityPods)))

		systemCount := 0
		userCount := 0
		for _, pod := range defaultPriorityPods {
			if isSystemPod(pod.Namespace, pod.Name) {
				systemCount++
			} else {
				userCount++
			}
		}
		lootDefaultClass = append(lootDefaultClass, fmt.Sprintf("# System pods: %d | User pods: %d", systemCount, userCount))
		lootDefaultClass = append(lootDefaultClass, "")
	}

	// Detailed pod priority analysis
	podHeaders := []string{
		"Risk",
		"Score",
		"Namespace",
		"Pod",
		"Priority Class",
		"Priority Value",
		"Privileged",
		"HostNetwork",
		"Can Preempt",
		"Issues",
	}

	var podRows [][]string
	var podAnalyses []PodPriorityAnalysis

	for _, pod := range allPods.Items {
		if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
			continue
		}

		podAnalysis := PodPriorityAnalysis{
			Namespace:     pod.Namespace,
			PodName:       pod.Name,
			PriorityClass: pod.Spec.PriorityClassName,
			IsSystemPod:   isSystemPod(pod.Namespace, pod.Name),
			IsPrivileged:  isPodPrivilegedPC(&pod),
			HostNetwork:   pod.Spec.HostNetwork,
		}

		if pod.Spec.Priority != nil {
			podAnalysis.PriorityValue = *pod.Spec.Priority
		}

		if pod.Spec.PreemptionPolicy != nil {
			podAnalysis.PreemptionPolicy = string(*pod.Spec.PreemptionPolicy)
		}

		// Can this pod preempt others?
		if podAnalysis.PriorityValue > 0 && podAnalysis.PreemptionPolicy != "Never" {
			podAnalysis.CanPreempt = true
		}

		// Is this pod vulnerable to preemption?
		if podAnalysis.PriorityValue < HighPriorityThreshold {
			podAnalysis.VulnerableToPreempt = true
		}

		// Security analysis
		podAnalysis.SecurityIssues = analyzePodPrioritySecurity(&podAnalysis)
		podAnalysis.RiskLevel, podAnalysis.RiskScore = calculatePodPriorityRisk(&podAnalysis)

		if podAnalysis.RiskLevel == "CRITICAL" || podAnalysis.RiskLevel == "HIGH" || len(podAnalysis.SecurityIssues) > 0 {
			podAnalyses = append(podAnalyses, podAnalysis)

			podRows = append(podRows, []string{
				podAnalysis.RiskLevel,
				fmt.Sprintf("%d", podAnalysis.RiskScore),
				pod.Namespace,
				pod.Name,
				podAnalysis.PriorityClass,
				fmt.Sprintf("%d", podAnalysis.PriorityValue),
				fmt.Sprintf("%v", podAnalysis.IsPrivileged),
				fmt.Sprintf("%v", podAnalysis.HostNetwork),
				fmt.Sprintf("%v", podAnalysis.CanPreempt),
				fmt.Sprintf("%d", len(podAnalysis.SecurityIssues)),
			})

			// Loot: Preemption risks
			if podAnalysis.VulnerableToPreempt && !podAnalysis.IsSystemPod {
				lootPreemptionRisks = append(lootPreemptionRisks, fmt.Sprintf("\n### [%s] %s/%s", podAnalysis.RiskLevel, pod.Namespace, pod.Name))
				lootPreemptionRisks = append(lootPreemptionRisks, fmt.Sprintf("# Priority: %d (< %d threshold)", podAnalysis.PriorityValue, HighPriorityThreshold))
				lootPreemptionRisks = append(lootPreemptionRisks, "# Risk: Can be preempted by higher-priority pods")
				lootPreemptionRisks = append(lootPreemptionRisks, "# Impact: Service disruption, downtime")
				lootPreemptionRisks = append(lootPreemptionRisks, "")
			}
		}
	}

	// Sort pod rows by risk score descending
	sort.SliceStable(podRows, func(i, j int) bool {
		return podRows[i][1] > podRows[j][1]
	})

	// Remediation guidance
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		lootRemediation = append(lootRemediation, "## Critical Issues")
		lootRemediation = append(lootRemediation, "")

		for _, analysis := range pcAnalyses {
			if analysis.RiskLevel == "CRITICAL" && len(analysis.SecurityIssues) > 0 {
				lootRemediation = append(lootRemediation, fmt.Sprintf("### PriorityClass: %s", analysis.Name))
				for _, issue := range analysis.SecurityIssues {
					lootRemediation = append(lootRemediation, fmt.Sprintf("# Issue: %s", issue))
				}

				if analysis.UserPodsUsingIt > 0 && analysis.IsSystemClass {
					lootRemediation = append(lootRemediation, "# Remediation:")
					lootRemediation = append(lootRemediation, "#   1. Identify user pods using system priority:")
					lootRemediation = append(lootRemediation, fmt.Sprintf("#      kubectl get pods --all-namespaces --field-selector spec.priorityClassName=%s", analysis.Name))
					lootRemediation = append(lootRemediation, "#   2. Create appropriate user-level PriorityClass (value < 1000000)")
					lootRemediation = append(lootRemediation, "#   3. Update pod specs to use user-level priority")
					lootRemediation = append(lootRemediation, "#   4. Consider PodSecurity admission to block system priorities")
				}
				lootRemediation = append(lootRemediation, "")
			}
		}
	}

	// Add summary
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d priority classes with critical risks
# HIGH: %d priority classes with high risks
# MEDIUM: %d priority classes with medium risks
# LOW: %d priority classes with low/acceptable config
#
# Total pods analyzed: %d
# Pods at risk of preemption: %d
#
# Focus on CRITICAL and HIGH risk priority classes for immediate remediation.
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"], len(allPods.Items), len(podAnalyses))
		lootAbuse = append([]string{summary}, lootAbuse...)
	}

	table1 := internal.TableFile{
		Name:   "PriorityClasses",
		Header: headers,
		Body:   outputRows,
	}

	table2 := internal.TableFile{
		Name:   "Pod-Priorities",
		Header: podHeaders,
		Body:   podRows,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "PriorityClass-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "Priority-Abuse",
			Contents: strings.Join(lootAbuse, "\n"),
		},
		{
			Name:     "Preemption-Risks",
			Contents: strings.Join(lootPreemptionRisks, "\n"),
		},
		{
			Name:     "Privilege-Escalation",
			Contents: strings.Join(lootPrivilegeEscalation, "\n"),
		},
		{
			Name:     "Default-PriorityClass",
			Contents: strings.Join(lootDefaultClass, "\n"),
		},
		{
			Name:     "Remediation-Guide",
			Contents: strings.Join(lootRemediation, "\n"),
		},
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"PriorityClasses",
		globals.ClusterName,
		"results",
		PriorityClassesOutput{
			Table: []internal.TableFile{table1, table2},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PRIORITYCLASSES_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d priority classes found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_PRIORITYCLASSES_MODULE_NAME)
	} else {
		logger.InfoM("No priority classes found", globals.K8S_PRIORITYCLASSES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PRIORITYCLASSES_MODULE_NAME), globals.K8S_PRIORITYCLASSES_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

func isSystemPriorityClass(name string, value int32) bool {
	// System priority classes
	systemClasses := map[string]bool{
		"system-cluster-critical": true,
		"system-node-critical":    true,
	}

	if systemClasses[name] {
		return true
	}

	// System priority range (2 billion+)
	if value >= SystemCriticalPriority {
		return true
	}

	return false
}

func isSystemPod(namespace, name string) bool {
	systemNamespaces := []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
	}

	for _, ns := range systemNamespaces {
		if namespace == ns {
			return true
		}
	}

	return strings.HasPrefix(namespace, "kube-")
}

func isPodPrivilegedPC(pod *corev1.Pod) bool {
	// Check containers
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return true
		}
	}

	// Check init containers
	for _, container := range pod.Spec.InitContainers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return true
		}
	}

	return false
}

func analyzePriorityClassSecurity(analysis *PriorityClassAnalysis, pods []corev1.Pod) []string {
	var issues []string

	// Critical: User pods with system-level priority
	if analysis.UserPodsUsingIt > 0 && analysis.IsSystemClass {
		issues = append(issues, fmt.Sprintf("CRITICAL: %d user pods using system-level priority (can preempt system components)", analysis.UserPodsUsingIt))
	}

	// High: System priority class with high user pod count
	if analysis.IsSystemClass && analysis.UserPodsUsingIt > 5 {
		issues = append(issues, fmt.Sprintf("HIGH: Excessive user pods (%d) with system priority", analysis.UserPodsUsingIt))
	}

	// Medium: Very high priority for user class
	if !analysis.IsSystemClass && analysis.Value > HighPriorityThreshold {
		issues = append(issues, fmt.Sprintf("MEDIUM: User priority class with suspiciously high value (%d)", analysis.Value))
	}

	// Check for privileged pods with high priority
	privCount := 0
	for _, pod := range pods {
		if isPodPrivilegedPC(&pod) && !isSystemPod(pod.Namespace, pod.Name) {
			privCount++
		}
	}

	if privCount > 0 && analysis.Value > HighPriorityThreshold {
		issues = append(issues, fmt.Sprintf("HIGH: %d privileged pods with high priority (privilege escalation risk)", privCount))
	}

	return issues
}

func calculatePriorityClassRisk(analysis *PriorityClassAnalysis) (string, int) {
	score := 0

	// User pods with system priority = critical
	if analysis.UserPodsUsingIt > 0 && analysis.IsSystemClass {
		score += 70
	}

	// High user pod count with system priority
	if analysis.IsSystemClass && analysis.UserPodsUsingIt > 5 {
		score += 20
	}

	// Suspicious user priority value
	if !analysis.IsSystemClass && analysis.Value > HighPriorityThreshold {
		score += 30
	}

	// Global default with high priority
	if analysis.GlobalDefault && analysis.Value > HighPriorityThreshold {
		score += 25
	}

	// Determine risk level
	if score >= 70 {
		return "CRITICAL", pcMin(score, 100)
	} else if score >= 40 {
		return "HIGH", score
	} else if score >= 20 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func analyzePodPrioritySecurity(analysis *PodPriorityAnalysis) []string {
	var issues []string

	// Critical: Non-system pod with system priority
	if !analysis.IsSystemPod && analysis.PriorityValue >= SystemCriticalPriority {
		issues = append(issues, "CRITICAL: User pod with system-level priority")
	}

	// High: Privileged pod with high priority
	if analysis.IsPrivileged && analysis.PriorityValue > HighPriorityThreshold && !analysis.IsSystemPod {
		issues = append(issues, "HIGH: Privileged pod with high priority (can disrupt cluster)")
	}

	// High: HostNetwork + high priority
	if analysis.HostNetwork && analysis.PriorityValue > HighPriorityThreshold && !analysis.IsSystemPod {
		issues = append(issues, "HIGH: HostNetwork pod with high priority")
	}

	// Medium: Can preempt others
	if analysis.CanPreempt && analysis.PriorityValue > HighPriorityThreshold {
		issues = append(issues, "MEDIUM: Can preempt lower-priority workloads")
	}

	return issues
}

func calculatePodPriorityRisk(analysis *PodPriorityAnalysis) (string, int) {
	score := 0

	// User pod with system priority
	if !analysis.IsSystemPod && analysis.PriorityValue >= SystemCriticalPriority {
		score += 80
	}

	// Privileged + high priority
	if analysis.IsPrivileged && analysis.PriorityValue > HighPriorityThreshold && !analysis.IsSystemPod {
		score += 40
	}

	// HostNetwork + high priority
	if analysis.HostNetwork && analysis.PriorityValue > HighPriorityThreshold {
		score += 30
	}

	// Can preempt
	if analysis.CanPreempt && analysis.PriorityValue > HighPriorityThreshold {
		score += 20
	}

	// Determine risk level
	if score >= 70 {
		return "CRITICAL", pcMin(score, 100)
	} else if score >= 40 {
		return "HIGH", score
	} else if score >= 20 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func pcMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
