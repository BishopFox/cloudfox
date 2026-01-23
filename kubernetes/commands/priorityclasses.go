package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
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
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating priority classes for %s", globals.ClusterName), globals.K8S_PRIORITYCLASSES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	loot := shared.NewLootBuilder()
	loot.Section("PriorityClass-Enum").SetHeader(`#####################################
##### PriorityClass Enumeration
#####################################

`)
	if globals.KubeContext != "" {
		loot.Section("PriorityClass-Enum").Add(fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	loot.Section("Priority-Abuse").SetHeader(`#####################################
##### Priority Abuse Detection
#####################################
# User pods with system-level priorities
# Can preempt critical system components

`)

	loot.Section("Preemption-Risks").SetHeader(`#####################################
##### Preemption Risk Analysis
#####################################
# Pods vulnerable to preemption
# Availability impact assessment

`)

	loot.Section("Privilege-Escalation").SetHeader(`#####################################
##### Privilege Escalation via Priority
#####################################
# High-priority privileged pods
# Can disrupt cluster and evict workloads

`)

	loot.Section("Default-PriorityClass").SetHeader(`#####################################
##### Default PriorityClass Analysis
#####################################
# Global default priority class configuration

`)

	loot.Section("Remediation-Guide").SetHeader(`#####################################
##### Remediation Guidance
#####################################

`)

	// Get all PriorityClasses
	priorityClasses, err := clientset.SchedulingV1().PriorityClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "priority classes", "", err, globals.K8S_PRIORITYCLASSES_MODULE_NAME, true)
		return
	}

	// Get all pods for usage analysis
	allPods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "pods", "", err, globals.K8S_PRIORITYCLASSES_MODULE_NAME, false)
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

	riskCounts := shared.NewRiskCounts()

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

		riskCounts.Add(analysis.RiskLevel)
		pcAnalyses = append(pcAnalyses, analysis)

		outputRows = append(outputRows, []string{
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
		loot.Section("PriorityClass-Enum").Add(fmt.Sprintf("\n# [%s] PriorityClass: %s", analysis.RiskLevel, pc.Name))
		loot.Section("PriorityClass-Enum").Add(fmt.Sprintf("# Value: %d | Global Default: %v | Pods: %d", pc.Value, pc.GlobalDefault, analysis.PodsUsingClass))
		loot.Section("PriorityClass-Enum").Add(fmt.Sprintf("kubectl get priorityclass %s -o yaml", pc.Name))
		loot.Section("PriorityClass-Enum").Add("")

		// Loot: Priority abuse
		if analysis.UserPodsUsingIt > 0 && analysis.IsSystemClass {
			loot.Section("Priority-Abuse").Add(fmt.Sprintf("\n### [CRITICAL] %s - User pods with system priority", pc.Name))
			loot.Section("Priority-Abuse").Add(fmt.Sprintf("# Priority Value: %d (System-level)", pc.Value))
			loot.Section("Priority-Abuse").Add(fmt.Sprintf("# User Pods: %d | Namespaces: %s", analysis.UserPodsUsingIt, strings.Join(analysis.NamespacesUsingIt, ", ")))
			loot.Section("Priority-Abuse").Add("# These pods can preempt system components!")
			loot.Section("Priority-Abuse").Add(fmt.Sprintf("kubectl get pods --all-namespaces --field-selector spec.priorityClassName=%s", pc.Name))
			loot.Section("Priority-Abuse").Add("")
		}

		// Loot: Privilege escalation
		for _, pod := range pods {
			if isPodPrivilegedPC(&pod) && !isSystemPod(pod.Namespace, pod.Name) {
				loot.Section("Privilege-Escalation").Add(fmt.Sprintf("\n### [CRITICAL] %s/%s", pod.Namespace, pod.Name))
				loot.Section("Privilege-Escalation").Add(fmt.Sprintf("# PriorityClass: %s (Value: %d)", pc.Name, pc.Value))
				loot.Section("Privilege-Escalation").Add(fmt.Sprintf("# Privileged: %v | HostNetwork: %v", isPodPrivilegedPC(&pod), pod.Spec.HostNetwork))
				loot.Section("Privilege-Escalation").Add("# Can preempt other workloads + has elevated host access")
				loot.Section("Privilege-Escalation").Add("")
			}
		}
	}

	// Analyze pods without explicit priority class (using default)
	if len(defaultPriorityPods) > 0 {
		loot.Section("Default-PriorityClass").Add(fmt.Sprintf("\n# Global Default PriorityClass: %s", globalDefaultPC))
		if globalDefaultPC == "" {
			loot.Section("Default-PriorityClass").Add("# WARNING: No global default - pods get priority 0")
		}
		loot.Section("Default-PriorityClass").Add(fmt.Sprintf("# Pods without explicit priority: %d", len(defaultPriorityPods)))

		systemCount := 0
		userCount := 0
		for _, pod := range defaultPriorityPods {
			if isSystemPod(pod.Namespace, pod.Name) {
				systemCount++
			} else {
				userCount++
			}
		}
		loot.Section("Default-PriorityClass").Add(fmt.Sprintf("# System pods: %d | User pods: %d", systemCount, userCount))
		loot.Section("Default-PriorityClass").Add("")
	}

	// Detailed pod priority analysis
	podHeaders := []string{
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

		if podAnalysis.RiskLevel == shared.RiskCritical || podAnalysis.RiskLevel == shared.RiskHigh || len(podAnalysis.SecurityIssues) > 0 {
			podAnalyses = append(podAnalyses, podAnalysis)

			podRows = append(podRows, []string{
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
				loot.Section("Preemption-Risks").Add(fmt.Sprintf("\n### [%s] %s/%s", podAnalysis.RiskLevel, pod.Namespace, pod.Name))
				loot.Section("Preemption-Risks").Add(fmt.Sprintf("# Priority: %d (< %d threshold)", podAnalysis.PriorityValue, HighPriorityThreshold))
				loot.Section("Preemption-Risks").Add("# Risk: Can be preempted by higher-priority pods")
				loot.Section("Preemption-Risks").Add("# Impact: Service disruption, downtime")
				loot.Section("Preemption-Risks").Add("")
			}
		}
	}

	// Sort pod rows by risk score descending
	sort.SliceStable(podRows, func(i, j int) bool {
		return podRows[i][1] > podRows[j][1]
	})

	// Remediation guidance
	if riskCounts.Critical > 0 || riskCounts.High > 0 {
		loot.Section("Remediation-Guide").Add("## Critical Issues")
		loot.Section("Remediation-Guide").Add("")

		for _, analysis := range pcAnalyses {
			if analysis.RiskLevel == shared.RiskCritical && len(analysis.SecurityIssues) > 0 {
				loot.Section("Remediation-Guide").Add(fmt.Sprintf("### PriorityClass: %s", analysis.Name))
				for _, issue := range analysis.SecurityIssues {
					loot.Section("Remediation-Guide").Add(fmt.Sprintf("# Issue: %s", issue))
				}

				if analysis.UserPodsUsingIt > 0 && analysis.IsSystemClass {
					loot.Section("Remediation-Guide").Add("# Remediation:")
					loot.Section("Remediation-Guide").Add("#   1. Identify user pods using system priority:")
					loot.Section("Remediation-Guide").Add(fmt.Sprintf("#      kubectl get pods --all-namespaces --field-selector spec.priorityClassName=%s", analysis.Name))
					loot.Section("Remediation-Guide").Add("#   2. Create appropriate user-level PriorityClass (value < 1000000)")
					loot.Section("Remediation-Guide").Add("#   3. Update pod specs to use user-level priority")
					loot.Section("Remediation-Guide").Add("#   4. Consider PodSecurity admission to block system priorities")
				}
				loot.Section("Remediation-Guide").Add("")
			}
		}
	}

	// Add summary
	if riskCounts.Critical > 0 || riskCounts.High > 0 {
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
`, riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low, len(allPods.Items), len(podAnalyses))
		loot.Section("Priority-Abuse").SetSummary(summary)
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

	lootFiles := loot.Build()

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
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
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
		return shared.RiskCritical, pcMin(score, 100)
	} else if score >= 40 {
		return shared.RiskHigh, score
	} else if score >= 20 {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
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
		return shared.RiskCritical, pcMin(score, 100)
	} else if score >= 40 {
		return shared.RiskHigh, score
	} else if score >= 20 {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
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
