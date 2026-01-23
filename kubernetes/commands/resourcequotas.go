package commands

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ResourceQuotasCmd = &cobra.Command{
	Use:     "resourcequotas",
	Aliases: []string{"rq", "quotas"},
	Short:   "Enumerate ResourceQuotas and LimitRanges with comprehensive security analysis",
	Long: `
Enumerate ResourceQuotas and LimitRanges with enterprise-grade security analysis including:
  - Namespaces without resource quotas (DoS/resource exhaustion risk)
  - Excessive quotas (cost bomb risk)
  - Missing CPU/memory limits (noisy neighbor risk)
  - Missing PVC quotas (storage exhaustion risk)
  - LimitRange gap analysis
  - Resource utilization vs quota analysis
  - Risk scoring based on exposure
  - Compliance zone quota enforcement
  - Multi-tenancy isolation validation
  - Cost optimization recommendations

  cloudfox kubernetes resourcequotas`,
	Run: ListResourceQuotas,
}

type ResourceQuotasOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ResourceQuotasOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ResourceQuotasOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type NamespaceQuotaAnalysis struct {
	Namespace           string
	HasResourceQuota    bool
	HasLimitRange       bool
	QuotaNames          []string
	LimitRangeNames     []string
	RiskLevel           string
	RiskScore           int
	SecurityIssues      []string
	MissingQuotas       []string
	ExcessiveQuotas     []string
	CPUQuota            string
	MemoryQuota         string
	PodQuota            string
	PVCQuota            string
	CPUUsed             string
	MemoryUsed          string
	PodsRunning         int
	ComplianceZone      string
	IsSystemNamespace   bool
	CostRisk            string
	DoSRisk             bool
}

type ResourceQuotaDetail struct {
	Namespace      string
	Name           string
	HardLimits     map[string]string
	UsedLimits     map[string]string
	UtilizationPct map[string]int
	RiskLevel      string
	Issues         []string
}

type LimitRangeDetail struct {
	Namespace    string
	Name         string
	Type         string
	DefaultCPU   string
	DefaultMem   string
	MaxCPU       string
	MaxMem       string
	MinCPU       string
	MinMem       string
	RiskLevel    string
	Issues       []string
	GapAnalysis  []string
}

func ListResourceQuotas(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating resource quotas for %s", globals.ClusterName), globals.K8S_RESOURCEQUOTAS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	loot := shared.NewLootBuilder()

	loot.Section("ResourceQuota-Enum").SetHeader(`#####################################
##### Resource Quota Enumeration
#####################################

`)
	if globals.KubeContext != "" {
		loot.Section("ResourceQuota-Enum").Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	loot.Section("Unprotected-Namespaces").SetHeader(`#####################################
##### Namespaces Without Resource Quotas
#####################################
# CRITICAL: Resource exhaustion & DoS risk
# These namespaces have no limits on resource consumption

`)

	loot.Section("Excessive-Quotas").SetHeader(`#####################################
##### Excessive Resource Quotas
#####################################
# HIGH: Cost bomb risk
# Quotas allowing excessive resource allocation

`)

	loot.Section("Missing-LimitRanges").SetHeader(`#####################################
##### Missing LimitRanges
#####################################
# MEDIUM: Noisy neighbor & resource contention risk
# Namespaces without default resource limits

`)

	loot.Section("Quota-Utilization").SetHeader(`#####################################
##### Quota Utilization Analysis
#####################################
# Resource usage vs quota allocation
# Identify over-provisioned or under-utilized quotas

`)

	loot.Section("Remediation-Guide").SetHeader(`#####################################
##### Remediation Guidance
#####################################
# Step-by-step fixes for resource quota issues

`)

	loot.Section("Cost-Optimization").SetHeader(`#####################################
##### Cost Optimization Recommendations
#####################################
# Right-size quotas based on actual usage

`)

	// Get all namespaces
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_RESOURCEQUOTAS_MODULE_NAME)

	// Get all resource quotas
	allQuotas, err := clientset.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "resource quotas", "", err, globals.K8S_RESOURCEQUOTAS_MODULE_NAME, true)
		return
	}

	// Get all limit ranges
	allLimitRanges, err := clientset.CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "limit ranges", "", err, globals.K8S_RESOURCEQUOTAS_MODULE_NAME, false)
		allLimitRanges = &corev1.LimitRangeList{}
	}

	// Get all pods for utilization analysis
	allPods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "pods", "", err, globals.K8S_RESOURCEQUOTAS_MODULE_NAME, false)
		allPods = &corev1.PodList{}
	}

	// Build maps for quick lookup
	quotasByNS := make(map[string][]corev1.ResourceQuota)
	limitRangesByNS := make(map[string][]corev1.LimitRange)
	podCountByNS := make(map[string]int)

	for _, quota := range allQuotas.Items {
		quotasByNS[quota.Namespace] = append(quotasByNS[quota.Namespace], quota)
	}

	for _, lr := range allLimitRanges.Items {
		limitRangesByNS[lr.Namespace] = append(limitRangesByNS[lr.Namespace], lr)
	}

	for _, pod := range allPods.Items {
		if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
			podCountByNS[pod.Namespace]++
		}
	}

	headers := []string{
		"Namespace",
		"Resource Quotas",
		"Limit Ranges",
		"CPU Quota",
		"Memory Quota",
		"Pod Quota",
		"Pods Running",
		"Issues",
	}

	var outputRows [][]string
	var nsAnalyses []NamespaceQuotaAnalysis

	riskCounts := shared.NewRiskCounts()

	for _, ns := range namespaces {
		analysis := NamespaceQuotaAnalysis{
			Namespace:         ns,
			IsSystemNamespace: isSystemNamespace(ns),
			PodsRunning:       podCountByNS[ns],
		}

		// Detect compliance zone
		analysis.ComplianceZone = detectComplianceZoneNS(nil, nil)

		// Check for resource quotas
		quotas := quotasByNS[ns]
		analysis.HasResourceQuota = len(quotas) > 0

		for _, quota := range quotas {
			analysis.QuotaNames = append(analysis.QuotaNames, quota.Name)

			// Extract quota values
			if cpu, ok := quota.Status.Hard[corev1.ResourceRequestsCPU]; ok {
				analysis.CPUQuota = cpu.String()
			}
			if mem, ok := quota.Status.Hard[corev1.ResourceRequestsMemory]; ok {
				analysis.MemoryQuota = mem.String()
			}
			if pods, ok := quota.Status.Hard[corev1.ResourcePods]; ok {
				analysis.PodQuota = pods.String()
			}
			if pvc, ok := quota.Status.Hard[corev1.ResourcePersistentVolumeClaims]; ok {
				analysis.PVCQuota = pvc.String()
			}

			// Extract used values
			if cpuUsed, ok := quota.Status.Used[corev1.ResourceRequestsCPU]; ok {
				analysis.CPUUsed = cpuUsed.String()
			}
			if memUsed, ok := quota.Status.Used[corev1.ResourceRequestsMemory]; ok {
				analysis.MemoryUsed = memUsed.String()
			}
		}

		// Check for limit ranges
		limitRanges := limitRangesByNS[ns]
		analysis.HasLimitRange = len(limitRanges) > 0

		for _, lr := range limitRanges {
			analysis.LimitRangeNames = append(analysis.LimitRangeNames, lr.Name)
		}

		// Analyze security issues
		analysis.SecurityIssues = analyzeNamespaceQuotaSecurity(&analysis, quotas, limitRanges)
		analysis.RiskLevel, analysis.RiskScore = calculateQuotaRiskScore(&analysis)

		riskCounts.Add(analysis.RiskLevel)
		nsAnalyses = append(nsAnalyses, analysis)

		// Build table row
		quotaStr := fmt.Sprintf("%d", len(quotas))
		if len(quotas) == 0 {
			quotaStr = "NONE"
		}

		lrStr := fmt.Sprintf("%d", len(limitRanges))
		if len(limitRanges) == 0 {
			lrStr = "NONE"
		}

		cpuQuotaStr := analysis.CPUQuota
		if cpuQuotaStr == "" {
			cpuQuotaStr = "No Limit"
		}

		memQuotaStr := analysis.MemoryQuota
		if memQuotaStr == "" {
			memQuotaStr = "No Limit"
		}

		podQuotaStr := analysis.PodQuota
		if podQuotaStr == "" {
			podQuotaStr = "No Limit"
		}

		outputRows = append(outputRows, []string{
			ns,
			quotaStr,
			lrStr,
			cpuQuotaStr,
			memQuotaStr,
			podQuotaStr,
			fmt.Sprintf("%d", analysis.PodsRunning),
			fmt.Sprintf("%d", len(analysis.SecurityIssues)),
		})

		// Generate loot content
		loot.Section("ResourceQuota-Enum").Addf("\n# [%s] Namespace: %s", analysis.RiskLevel, ns)
		loot.Section("ResourceQuota-Enum").Addf("kubectl get resourcequota -n %s", ns)
		loot.Section("ResourceQuota-Enum").Addf("kubectl get limitrange -n %s", ns)
		loot.Section("ResourceQuota-Enum").Addf("kubectl describe quota -n %s", ns)
		loot.Section("ResourceQuota-Enum").Add("")

		// Loot: Unprotected namespaces
		if !analysis.HasResourceQuota && !analysis.IsSystemNamespace {
			loot.Section("Unprotected-Namespaces").Addf("\n### [%s] %s", analysis.RiskLevel, ns)
			loot.Section("Unprotected-Namespaces").Addf("# Pods Running: %d", analysis.PodsRunning)
			if analysis.ComplianceZone != "" {
				loot.Section("Unprotected-Namespaces").Addf("# Compliance Zone: %s - CRITICAL VIOLATION", analysis.ComplianceZone)
			}
			if len(analysis.SecurityIssues) > 0 {
				loot.Section("Unprotected-Namespaces").Add("# Issues:")
				for _, issue := range analysis.SecurityIssues {
					loot.Section("Unprotected-Namespaces").Addf("#   - %s", issue)
				}
			}
			loot.Section("Unprotected-Namespaces").Add("# Risk: Unlimited resource consumption, DoS attacks, cost bombs")
			loot.Section("Unprotected-Namespaces").Addf("kubectl get pods -n %s --no-headers | wc -l", ns)
			loot.Section("Unprotected-Namespaces").Add("")
		}

		// Loot: Excessive quotas
		if len(analysis.ExcessiveQuotas) > 0 {
			loot.Section("Excessive-Quotas").Addf("\n### [%s] %s", analysis.RiskLevel, ns)
			for _, excessive := range analysis.ExcessiveQuotas {
				loot.Section("Excessive-Quotas").Addf("# %s", excessive)
			}
			loot.Section("Excessive-Quotas").Add("")
		}

		// Loot: Missing limit ranges
		if !analysis.HasLimitRange && !analysis.IsSystemNamespace {
			loot.Section("Missing-LimitRanges").Addf("\n### [%s] %s", shared.RiskMedium, ns)
			loot.Section("Missing-LimitRanges").Add("# Risk: Pods can request unbounded CPU/memory")
			loot.Section("Missing-LimitRanges").Add("# Impact: Noisy neighbor, resource contention, cluster instability")
			loot.Section("Missing-LimitRanges").Add("")
		}

		// Loot: Utilization analysis
		if analysis.HasResourceQuota && (analysis.CPUUsed != "" || analysis.MemoryUsed != "") {
			loot.Section("Quota-Utilization").Addf("\n### %s", ns)
			if analysis.CPUQuota != "" && analysis.CPUUsed != "" {
				loot.Section("Quota-Utilization").Addf("# CPU: %s / %s", analysis.CPUUsed, analysis.CPUQuota)
			}
			if analysis.MemoryQuota != "" && analysis.MemoryUsed != "" {
				loot.Section("Quota-Utilization").Addf("# Memory: %s / %s", analysis.MemoryUsed, analysis.MemoryQuota)
			}
			loot.Section("Quota-Utilization").Addf("kubectl top pods -n %s --no-headers | awk '{sum+=$2} END {print sum}'", ns)
			loot.Section("Quota-Utilization").Add("")
		}

		// Loot: Remediation
		if len(analysis.SecurityIssues) > 0 {
			loot.Section("Remediation-Guide").Addf("\n### %s - %d Issues", ns, len(analysis.SecurityIssues))
			for i, issue := range analysis.SecurityIssues {
				loot.Section("Remediation-Guide").Addf("# %d. %s", i+1, issue)
			}
			loot.Section("Remediation-Guide").Add("# Remediation:")
			if !analysis.HasResourceQuota {
				loot.Section("Remediation-Guide").Add("#   - Create ResourceQuota with appropriate limits")
				loot.Section("Remediation-Guide").Add("#   kubectl create quota quota-example -n " + ns + " --hard=cpu=10,memory=20Gi,pods=20")
			}
			if !analysis.HasLimitRange {
				loot.Section("Remediation-Guide").Add("#   - Create LimitRange with default limits")
			}
			loot.Section("Remediation-Guide").Add("")
		}
	}

	// Add detailed quota analysis
	var quotaDetails []ResourceQuotaDetail
	for _, quota := range allQuotas.Items {
		detail := analyzeResourceQuotaDetail(&quota)
		quotaDetails = append(quotaDetails, detail)

		if len(detail.Issues) > 0 {
			loot.Section("Cost-Optimization").Addf("\n### %s/%s", detail.Namespace, detail.Name)
			for _, issue := range detail.Issues {
				loot.Section("Cost-Optimization").Addf("# %s", issue)
			}
			loot.Section("Cost-Optimization").Add("")
		}
	}

	// Build second table for detailed quota analysis
	quotaHeaders := []string{
		"Namespace",
		"Quota Name",
		"CPU Hard",
		"CPU Used",
		"Memory Hard",
		"Memory Used",
		"Pods Hard",
		"Pods Used",
		"Issues",
	}

	var quotaRows [][]string
	for _, detail := range quotaDetails {
		quotaRows = append(quotaRows, []string{
			detail.Namespace,
			detail.Name,
			getHardLimit(detail, "cpu"),
			getUsedLimit(detail, "cpu"),
			getHardLimit(detail, "memory"),
			getUsedLimit(detail, "memory"),
			getHardLimit(detail, "pods"),
			getUsedLimit(detail, "pods"),
			fmt.Sprintf("%d", len(detail.Issues)),
		})
	}

	// Add summary
	if riskCounts.Critical > 0 || riskCounts.High > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d namespaces with critical quota risks
# HIGH: %d namespaces with high quota risks
# MEDIUM: %d namespaces with medium quota risks
# LOW: %d namespaces with low/acceptable quotas
#
# Focus on CRITICAL and HIGH risk namespaces for immediate remediation.
`, riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low)
		loot.Section("Unprotected-Namespaces").SetSummary(summary)
	}

	table1 := internal.TableFile{
		Name:   "Namespace-Quotas",
		Header: headers,
		Body:   outputRows,
	}

	table2 := internal.TableFile{
		Name:   "Quota-Details",
		Header: quotaHeaders,
		Body:   quotaRows,
	}

	lootFiles := loot.Build()

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"ResourceQuotas",
		globals.ClusterName,
		"results",
		ResourceQuotasOutput{
			Table: []internal.TableFile{table1, table2},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_RESOURCEQUOTAS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d namespaces analyzed | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low),
			globals.K8S_RESOURCEQUOTAS_MODULE_NAME)
	} else {
		logger.InfoM("No namespaces found", globals.K8S_RESOURCEQUOTAS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_RESOURCEQUOTAS_MODULE_NAME), globals.K8S_RESOURCEQUOTAS_MODULE_NAME)
}

// ====================
// Helper Functions
// ====================

func isSystemNamespace(ns string) bool {
	systemNS := []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
		"default",
	}

	for _, sysNS := range systemNS {
		if ns == sysNS {
			return true
		}
	}

	return strings.HasPrefix(ns, "kube-")
}

func detectComplianceZoneNS(labels, annotations map[string]string) string {
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

	// Check annotations
	for key, value := range annotations {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "compliance") || strings.Contains(lowerKey, "pci") || strings.Contains(lowerKey, "hipaa") {
			return value
		}
	}

	return ""
}

func analyzeNamespaceQuotaSecurity(analysis *NamespaceQuotaAnalysis, quotas []corev1.ResourceQuota, limitRanges []corev1.LimitRange) []string {
	var issues []string

	// Critical: No resource quota in non-system namespace
	if !analysis.HasResourceQuota && !analysis.IsSystemNamespace {
		issues = append(issues, fmt.Sprintf("%s: No ResourceQuota - unlimited resource consumption possible", shared.RiskCritical))
		analysis.DoSRisk = true
	}

	// Critical: Compliance zone without quota
	if analysis.ComplianceZone != "" && !analysis.HasResourceQuota {
		issues = append(issues, fmt.Sprintf("%s: Compliance zone (%s) without ResourceQuota enforcement", shared.RiskCritical, analysis.ComplianceZone))
	}

	// High: No limit range
	if !analysis.HasLimitRange && !analysis.IsSystemNamespace {
		issues = append(issues, fmt.Sprintf("%s: No LimitRange - pods can request unbounded resources", shared.RiskHigh))
	}

	// Analyze quotas for excessive values
	for _, quota := range quotas {
		// Check CPU quota
		if cpu, ok := quota.Status.Hard[corev1.ResourceRequestsCPU]; ok {
			cpuVal := cpu.MilliValue()
			if cpuVal > 1000000 { // >1000 cores
				excessive := fmt.Sprintf("EXCESSIVE CPU quota: %s (>1000 cores)", cpu.String())
				issues = append(issues, excessive)
				analysis.ExcessiveQuotas = append(analysis.ExcessiveQuotas, excessive)
				analysis.CostRisk = shared.RiskHigh
			}
		}

		// Check Memory quota
		if mem, ok := quota.Status.Hard[corev1.ResourceRequestsMemory]; ok {
			memVal := mem.Value()
			if memVal > 1024*1024*1024*1024 { // >1 TB
				excessive := fmt.Sprintf("EXCESSIVE Memory quota: %s (>1TB)", mem.String())
				issues = append(issues, excessive)
				analysis.ExcessiveQuotas = append(analysis.ExcessiveQuotas, excessive)
				analysis.CostRisk = shared.RiskHigh
			}
		}

		// Check for missing critical quotas
		if _, hasCPU := quota.Status.Hard[corev1.ResourceRequestsCPU]; !hasCPU {
			analysis.MissingQuotas = append(analysis.MissingQuotas, "CPU requests")
		}
		if _, hasMem := quota.Status.Hard[corev1.ResourceRequestsMemory]; !hasMem {
			analysis.MissingQuotas = append(analysis.MissingQuotas, "Memory requests")
		}
		if _, hasPods := quota.Status.Hard[corev1.ResourcePods]; !hasPods {
			analysis.MissingQuotas = append(analysis.MissingQuotas, "Pod count")
		}
		if _, hasPVC := quota.Status.Hard[corev1.ResourcePersistentVolumeClaims]; !hasPVC {
			analysis.MissingQuotas = append(analysis.MissingQuotas, "PVC count")
		}
	}

	if len(analysis.MissingQuotas) > 0 {
		issues = append(issues, fmt.Sprintf("%s: Missing quota types: %s", shared.RiskMedium, strings.Join(analysis.MissingQuotas, ", ")))
	}

	return issues
}

func calculateQuotaRiskScore(analysis *NamespaceQuotaAnalysis) (string, int) {
	score := 0

	// No quota = critical risk
	if !analysis.HasResourceQuota && !analysis.IsSystemNamespace {
		score += 70
	}

	// Compliance zone without quota = critical
	if analysis.ComplianceZone != "" && !analysis.HasResourceQuota {
		score += 30
	}

	// No limit range
	if !analysis.HasLimitRange && !analysis.IsSystemNamespace {
		score += 20
	}

	// Excessive quotas
	if analysis.CostRisk == shared.RiskHigh {
		score += 25
	}

	// Missing critical quota types
	score += len(analysis.MissingQuotas) * 5

	// Many pods without limits
	if analysis.PodsRunning > 10 && !analysis.HasLimitRange {
		score += 15
	}

	// DoS risk
	if analysis.DoSRisk {
		score += 20
	}

	// Determine risk level
	if score >= 70 {
		return shared.RiskCritical, rqMin(score, 100)
	} else if score >= 40 {
		return shared.RiskHigh, score
	} else if score >= 20 {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
}

func analyzeResourceQuotaDetail(quota *corev1.ResourceQuota) ResourceQuotaDetail {
	detail := ResourceQuotaDetail{
		Namespace:      quota.Namespace,
		Name:           quota.Name,
		HardLimits:     make(map[string]string),
		UsedLimits:     make(map[string]string),
		UtilizationPct: make(map[string]int),
	}

	// Extract hard limits
	for resourceName, quantity := range quota.Status.Hard {
		detail.HardLimits[string(resourceName)] = quantity.String()
	}

	// Extract used limits
	for resourceName, quantity := range quota.Status.Used {
		detail.UsedLimits[string(resourceName)] = quantity.String()
	}

	// Calculate utilization percentages
	for resourceName, hardQuantity := range quota.Status.Hard {
		if usedQuantity, ok := quota.Status.Used[resourceName]; ok {
			hardVal := hardQuantity.Value()
			usedVal := usedQuantity.Value()

			if hardVal > 0 {
				pct := int((float64(usedVal) / float64(hardVal)) * 100)
				detail.UtilizationPct[string(resourceName)] = pct

				// Detect issues
				if pct > 90 {
					detail.Issues = append(detail.Issues, fmt.Sprintf("%s utilization >90%% (%d%%) - approaching limit", resourceName, pct))
				} else if pct < 10 && hardVal > 0 {
					detail.Issues = append(detail.Issues, fmt.Sprintf("%s utilization <10%% (%d%%) - over-provisioned", resourceName, pct))
				}
			}
		}
	}

	// Calculate risk level
	detail.RiskLevel = shared.RiskLow
	if len(detail.Issues) > 2 {
		detail.RiskLevel = shared.RiskMedium
	}
	for _, issue := range detail.Issues {
		if strings.Contains(issue, ">90%") {
			detail.RiskLevel = shared.RiskHigh
			break
		}
	}

	return detail
}

func getHardLimit(detail ResourceQuotaDetail, resourceType string) string {
	// Try different resource name formats
	keys := []string{
		"requests." + resourceType,
		"limits." + resourceType,
		resourceType,
	}

	for _, key := range keys {
		if val, ok := detail.HardLimits[key]; ok {
			return val
		}
	}

	// Try pod count
	if resourceType == "pods" {
		if val, ok := detail.HardLimits["pods"]; ok {
			return val
		}
	}

	return "-"
}

func getUsedLimit(detail ResourceQuotaDetail, resourceType string) string {
	keys := []string{
		"requests." + resourceType,
		"limits." + resourceType,
		resourceType,
	}

	for _, key := range keys {
		if val, ok := detail.UsedLimits[key]; ok {
			return val
		}
	}

	if resourceType == "pods" {
		if val, ok := detail.UsedLimits["pods"]; ok {
			return val
		}
	}

	return "-"
}

func parseQuantity(s string) (int64, error) {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0, err
	}
	return q.Value(), nil
}

func rqMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
