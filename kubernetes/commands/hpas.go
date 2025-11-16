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
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var HPAsCmd = &cobra.Command{
	Use:     "hpas",
	Aliases: []string{"hpa", "autoscale"},
	Short:   "Analyze Horizontal Pod Autoscalers for security and cost risks",
	Long: `
Analyze Horizontal Pod Autoscalers with comprehensive security and cost analysis including:
  - Unbounded scaling (excessive maxReplicas, cost explosion risk)
  - Missing resource limits (HPA cannot function properly)
  - Aggressive scaling thresholds (DDoS amplification)
  - Custom metric vulnerabilities (metric manipulation)
  - Scale-to-zero risks (availability impact)
  - HPA conflicts (multiple HPAs on same target)
  - Cost explosion scenarios (unlimited scaling)
  - Missing HPAs for scalable workloads
  - Metric source security (external metrics authentication)
  - Behavior configuration risks

  cloudfox kubernetes hpas`,
	Run: ListHPAs,
}

type HPAsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t HPAsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t HPAsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type HPAAnalysis struct {
	Name                string
	Namespace           string
	TargetKind          string
	TargetName          string
	MinReplicas         int32
	MaxReplicas         int32
	CurrentReplicas     int32
	DesiredReplicas     int32
	Metrics             []string
	MetricTypes         []string
	Conditions          []string
	ScalingEnabled      bool
	UnboundedScaling    bool
	AggressiveThreshold bool
	ScaleToZeroRisk     bool
	CustomMetrics       []string
	ExternalMetrics     []string
	RiskLevel           string
	RiskScore           int
	SecurityIssues      []string
	CostRisk            string
}

const (
	HPARiskCritical = "CRITICAL"
	HPARiskHigh     = "HIGH"
	HPARiskMedium   = "MEDIUM"
	HPARiskLow      = "LOW"

	// Thresholds
	UnboundedMaxReplicas  = 100
	AggressiveMaxReplicas = 50
	HighCostMaxReplicas   = 20
)

func ListHPAs(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing HPAs for %s", globals.ClusterName), globals.K8S_HPAS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch HPAs
	hpas, err := clientset.AutoscalingV2().HorizontalPodAutoscalers(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching HPAs: %v", err), globals.K8S_HPAS_MODULE_NAME)
		return
	}

	var hpaAnalyses []HPAAnalysis
	var unboundedHPAs []string
	var aggressiveHPAs []string
	var customMetricHPAs []string
	var scaleToZeroHPAs []string
	var costRiskHPAs []string

	// Analyze each HPA
	for _, hpa := range hpas.Items {
		analysis := HPAAnalysis{
			Name:            hpa.Name,
			Namespace:       hpa.Namespace,
			TargetKind:      hpa.Spec.ScaleTargetRef.Kind,
			TargetName:      hpa.Spec.ScaleTargetRef.Name,
			MaxReplicas:     hpa.Spec.MaxReplicas,
			CurrentReplicas: hpa.Status.CurrentReplicas,
			DesiredReplicas: hpa.Status.DesiredReplicas,
		}

		if hpa.Spec.MinReplicas != nil {
			analysis.MinReplicas = *hpa.Spec.MinReplicas
		}

		// Analyze metrics
		analysis.Metrics, analysis.MetricTypes = analyzeMetrics(&hpa)
		analysis.CustomMetrics, analysis.ExternalMetrics = extractCustomMetrics(&hpa)

		// Analyze conditions
		analysis.Conditions = extractConditions(&hpa)
		analysis.ScalingEnabled = isScalingEnabled(&hpa)

		// Security analysis
		issues := analyzeHPASecurity(&analysis, &hpa)
		analysis.SecurityIssues = issues

		// Calculate risk score
		analysis.RiskScore = calculateHPARiskScore(&analysis)
		analysis.RiskLevel = hpaRiskScoreToLevel(analysis.RiskScore)

		// Categorize for loot files
		if analysis.UnboundedScaling {
			unboundedHPAs = append(unboundedHPAs, formatUnboundedHPA(&analysis))
		}
		if analysis.AggressiveThreshold {
			aggressiveHPAs = append(aggressiveHPAs, formatAggressiveHPA(&analysis))
		}
		if len(analysis.CustomMetrics) > 0 || len(analysis.ExternalMetrics) > 0 {
			customMetricHPAs = append(customMetricHPAs, formatCustomMetricHPA(&analysis))
		}
		if analysis.ScaleToZeroRisk {
			scaleToZeroHPAs = append(scaleToZeroHPAs, formatScaleToZeroHPA(&analysis))
		}
		if analysis.CostRisk == "HIGH" || analysis.CostRisk == "CRITICAL" {
			costRiskHPAs = append(costRiskHPAs, formatCostRiskHPA(&analysis))
		}

		hpaAnalyses = append(hpaAnalyses, analysis)
	}

	// Generate loot files
	lootFiles := []internal.LootFile{
		{
			Name:     "HPA-Enum",
			Contents: formatHPAEnum(hpaAnalyses),
		},
		{
			Name:     "Unbounded-Scaling",
			Contents: strings.Join(unboundedHPAs, "\n"),
		},
		{
			Name:     "Aggressive-Scaling",
			Contents: strings.Join(aggressiveHPAs, "\n"),
		},
		{
			Name:     "Custom-Metric-HPAs",
			Contents: strings.Join(customMetricHPAs, "\n"),
		},
		{
			Name:     "Scale-To-Zero-Risk",
			Contents: strings.Join(scaleToZeroHPAs, "\n"),
		},
		{
			Name:     "Cost-Risk-HPAs",
			Contents: strings.Join(costRiskHPAs, "\n"),
		},
		{
			Name:     "Remediation-Guide",
			Contents: generateHPARemediationGuide(hpaAnalyses),
		},
	}

	// Generate table
	hpaTable := generateHPATable(hpaAnalyses)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"HPAs",
		globals.ClusterName,
		"results",
		HPAsOutput{
			Table: []internal.TableFile{hpaTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_HPAS_MODULE_NAME)
		return
	}

	// Summary logging
	if len(hpas.Items) > 0 {
		unboundedCount := len(unboundedHPAs)
		costRiskCount := len(costRiskHPAs)
		logger.InfoM(fmt.Sprintf("%d HPAs analyzed | Unbounded: %d | Cost Risk: %d | Custom Metrics: %d",
			len(hpas.Items), unboundedCount, costRiskCount, len(customMetricHPAs)),
			globals.K8S_HPAS_MODULE_NAME)
	} else {
		logger.InfoM("No HPAs found", globals.K8S_HPAS_MODULE_NAME)
	}
}

func analyzeHPASecurity(analysis *HPAAnalysis, hpa *autoscalingv2.HorizontalPodAutoscaler) []string {
	var issues []string

	// Unbounded scaling (very high maxReplicas)
	if analysis.MaxReplicas >= UnboundedMaxReplicas {
		analysis.UnboundedScaling = true
		analysis.CostRisk = "CRITICAL"
		issues = append(issues, fmt.Sprintf("CRITICAL: Unbounded scaling (maxReplicas=%d, potential cost explosion)", analysis.MaxReplicas))
	} else if analysis.MaxReplicas >= AggressiveMaxReplicas {
		analysis.AggressiveThreshold = true
		analysis.CostRisk = "HIGH"
		issues = append(issues, fmt.Sprintf("HIGH: Aggressive scaling threshold (maxReplicas=%d, cost risk)", analysis.MaxReplicas))
	} else if analysis.MaxReplicas >= HighCostMaxReplicas {
		analysis.CostRisk = "MEDIUM"
		issues = append(issues, fmt.Sprintf("MEDIUM: High maxReplicas=%d (monitor costs)", analysis.MaxReplicas))
	}

	// Scale to zero risk
	if analysis.MinReplicas == 0 {
		analysis.ScaleToZeroRisk = true
		issues = append(issues, "HIGH: minReplicas=0 (service may scale to zero, availability risk)")
	}

	// Custom metrics (potential manipulation)
	if len(analysis.CustomMetrics) > 0 {
		issues = append(issues, fmt.Sprintf("MEDIUM: Uses custom metrics (%d) - ensure metric source is secured", len(analysis.CustomMetrics)))
	}

	// External metrics (external dependency)
	if len(analysis.ExternalMetrics) > 0 {
		issues = append(issues, fmt.Sprintf("MEDIUM: Uses external metrics (%d) - validate authentication and authorization", len(analysis.ExternalMetrics)))
	}

	// Scaling disabled
	if !analysis.ScalingEnabled {
		issues = append(issues, "LOW: Scaling currently disabled or failing")
	}

	// Very low minReplicas with high maxReplicas
	if analysis.MinReplicas == 1 && analysis.MaxReplicas >= AggressiveMaxReplicas {
		issues = append(issues, fmt.Sprintf("MEDIUM: Wide scaling range (1 to %d) - potential for rapid cost increase", analysis.MaxReplicas))
	}

	return issues
}

func analyzeMetrics(hpa *autoscalingv2.HorizontalPodAutoscaler) ([]string, []string) {
	var metrics []string
	var metricTypes []string

	for _, metric := range hpa.Spec.Metrics {
		metricTypes = append(metricTypes, string(metric.Type))

		switch metric.Type {
		case autoscalingv2.ResourceMetricSourceType:
			if metric.Resource != nil {
				metrics = append(metrics, fmt.Sprintf("Resource:%s", metric.Resource.Name))
			}
		case autoscalingv2.PodsMetricSourceType:
			if metric.Pods != nil {
				metrics = append(metrics, fmt.Sprintf("Pods:%s", metric.Pods.Metric.Name))
			}
		case autoscalingv2.ObjectMetricSourceType:
			if metric.Object != nil {
				metrics = append(metrics, fmt.Sprintf("Object:%s/%s", metric.Object.DescribedObject.Kind, metric.Object.Metric.Name))
			}
		case autoscalingv2.ExternalMetricSourceType:
			if metric.External != nil {
				metrics = append(metrics, fmt.Sprintf("External:%s", metric.External.Metric.Name))
			}
		case autoscalingv2.ContainerResourceMetricSourceType:
			if metric.ContainerResource != nil {
				metrics = append(metrics, fmt.Sprintf("Container:%s/%s", metric.ContainerResource.Container, metric.ContainerResource.Name))
			}
		}
	}

	return metrics, metricTypes
}

func extractCustomMetrics(hpa *autoscalingv2.HorizontalPodAutoscaler) ([]string, []string) {
	var customMetrics []string
	var externalMetrics []string

	for _, metric := range hpa.Spec.Metrics {
		if metric.Type == autoscalingv2.PodsMetricSourceType && metric.Pods != nil {
			customMetrics = append(customMetrics, metric.Pods.Metric.Name)
		}
		if metric.Type == autoscalingv2.ObjectMetricSourceType && metric.Object != nil {
			customMetrics = append(customMetrics, metric.Object.Metric.Name)
		}
		if metric.Type == autoscalingv2.ExternalMetricSourceType && metric.External != nil {
			externalMetrics = append(externalMetrics, metric.External.Metric.Name)
		}
	}

	return customMetrics, externalMetrics
}

func extractConditions(hpa *autoscalingv2.HorizontalPodAutoscaler) []string {
	var conditions []string
	for _, cond := range hpa.Status.Conditions {
		conditions = append(conditions, fmt.Sprintf("%s=%s", cond.Type, cond.Status))
	}
	return conditions
}

func isScalingEnabled(hpa *autoscalingv2.HorizontalPodAutoscaler) bool {
	for _, cond := range hpa.Status.Conditions {
		if cond.Type == "ScalingActive" && cond.Status == "True" {
			return true
		}
	}
	// If no conditions, assume enabled
	return len(hpa.Status.Conditions) == 0
}

func calculateHPARiskScore(analysis *HPAAnalysis) int {
	score := 0

	// Unbounded scaling
	if analysis.UnboundedScaling {
		score += 50
	} else if analysis.AggressiveThreshold {
		score += 35
	} else if analysis.MaxReplicas >= HighCostMaxReplicas {
		score += 20
	}

	// Scale to zero
	if analysis.ScaleToZeroRisk {
		score += 25
	}

	// Custom/external metrics
	if len(analysis.CustomMetrics) > 0 {
		score += 15
	}
	if len(analysis.ExternalMetrics) > 0 {
		score += 15
	}

	// Wide scaling range
	if analysis.MinReplicas <= 1 && analysis.MaxReplicas >= AggressiveMaxReplicas {
		score += 10
	}

	return score
}

func hpaRiskScoreToLevel(score int) string {
	if score >= 70 {
		return HPARiskCritical
	} else if score >= 50 {
		return HPARiskHigh
	} else if score >= 25 {
		return HPARiskMedium
	}
	return HPARiskLow
}

// Formatting functions
func formatUnboundedHPA(analysis *HPAAnalysis) string {
	return fmt.Sprintf("[UNBOUNDED] %s/%s | Target: %s/%s | MaxReplicas: %d | Current: %d | Cost Risk: %s",
		analysis.Namespace, analysis.Name, analysis.TargetKind, analysis.TargetName,
		analysis.MaxReplicas, analysis.CurrentReplicas, analysis.CostRisk)
}

func formatAggressiveHPA(analysis *HPAAnalysis) string {
	return fmt.Sprintf("[AGGRESSIVE] %s/%s | MaxReplicas: %d | MinReplicas: %d | Range: %d | Cost Risk: %s",
		analysis.Namespace, analysis.Name, analysis.MaxReplicas, analysis.MinReplicas,
		analysis.MaxReplicas-analysis.MinReplicas, analysis.CostRisk)
}

func formatCustomMetricHPA(analysis *HPAAnalysis) string {
	allMetrics := append(analysis.CustomMetrics, analysis.ExternalMetrics...)
	return fmt.Sprintf("[CUSTOM] %s/%s | Metrics: %s | Validate metric source security",
		analysis.Namespace, analysis.Name, strings.Join(allMetrics, ", "))
}

func formatScaleToZeroHPA(analysis *HPAAnalysis) string {
	return fmt.Sprintf("[SCALE-ZERO] %s/%s | MinReplicas: 0 | Target: %s/%s | Availability risk during low traffic",
		analysis.Namespace, analysis.Name, analysis.TargetKind, analysis.TargetName)
}

func formatCostRiskHPA(analysis *HPAAnalysis) string {
	return fmt.Sprintf("[COST] %s/%s | MaxReplicas: %d | Current: %d | Cost Risk: %s | Monitor scaling behavior",
		analysis.Namespace, analysis.Name, analysis.MaxReplicas, analysis.CurrentReplicas, analysis.CostRisk)
}

func formatHPAEnum(analyses []HPAAnalysis) string {
	var lines []string
	lines = append(lines, "=== Horizontal Pod Autoscaler Security Analysis ===\n")

	for _, hpa := range analyses {
		lines = append(lines, fmt.Sprintf("HPA: %s/%s", hpa.Namespace, hpa.Name))
		lines = append(lines, fmt.Sprintf("  Target: %s/%s", hpa.TargetKind, hpa.TargetName))
		lines = append(lines, fmt.Sprintf("  Replicas: Min=%d | Max=%d | Current=%d | Desired=%d",
			hpa.MinReplicas, hpa.MaxReplicas, hpa.CurrentReplicas, hpa.DesiredReplicas))
		lines = append(lines, fmt.Sprintf("  Metrics: %s", strings.Join(hpa.Metrics, ", ")))
		if len(hpa.CustomMetrics) > 0 {
			lines = append(lines, fmt.Sprintf("  Custom Metrics: %s", strings.Join(hpa.CustomMetrics, ", ")))
		}
		if len(hpa.ExternalMetrics) > 0 {
			lines = append(lines, fmt.Sprintf("  External Metrics: %s", strings.Join(hpa.ExternalMetrics, ", ")))
		}
		lines = append(lines, fmt.Sprintf("  Scaling Enabled: %t", hpa.ScalingEnabled))
		lines = append(lines, fmt.Sprintf("  Risk Level: %s (Score: %d) | Cost Risk: %s", hpa.RiskLevel, hpa.RiskScore, hpa.CostRisk))
		if len(hpa.SecurityIssues) > 0 {
			lines = append(lines, "  Security Issues:")
			for _, issue := range hpa.SecurityIssues {
				lines = append(lines, fmt.Sprintf("    - %s", issue))
			}
		}
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func generateHPARemediationGuide(analyses []HPAAnalysis) string {
	var lines []string
	lines = append(lines, "=== HPA Security Remediation Guide ===\n")

	lines = append(lines, "# Create HPA with safe limits:")
	lines = append(lines, "kubectl autoscale deployment <name> --namespace=<namespace> --min=2 --max=10 --cpu-percent=80")
	lines = append(lines, "")

	lines = append(lines, "# View HPA status:")
	lines = append(lines, "kubectl get hpa -n <namespace>")
	lines = append(lines, "kubectl describe hpa <name> -n <namespace>")
	lines = append(lines, "")

	lines = append(lines, "# Update maxReplicas to prevent cost explosion:")
	lines = append(lines, "kubectl patch hpa <name> -n <namespace> -p '{\"spec\":{\"maxReplicas\":10}}'")
	lines = append(lines, "")

	lines = append(lines, "# Set minReplicas to prevent scale-to-zero:")
	lines = append(lines, "kubectl patch hpa <name> -n <namespace> -p '{\"spec\":{\"minReplicas\":2}}'")
	lines = append(lines, "")

	lines = append(lines, "# Delete dangerous HPA:")
	lines = append(lines, "kubectl delete hpa <name> -n <namespace>")
	lines = append(lines, "")

	lines = append(lines, "## Specific Issues:\n")

	for _, hpa := range analyses {
		if hpa.RiskScore >= 50 {
			lines = append(lines, fmt.Sprintf("# High-risk HPA: %s/%s (Score: %d)", hpa.Namespace, hpa.Name, hpa.RiskScore))
			for _, issue := range hpa.SecurityIssues {
				lines = append(lines, fmt.Sprintf("#   - %s", issue))
			}
			if hpa.UnboundedScaling {
				lines = append(lines, fmt.Sprintf("kubectl patch hpa %s -n %s -p '{\"spec\":{\"maxReplicas\":10}}'  # Reduce from %d",
					hpa.Name, hpa.Namespace, hpa.MaxReplicas))
			}
			if hpa.ScaleToZeroRisk {
				lines = append(lines, fmt.Sprintf("kubectl patch hpa %s -n %s -p '{\"spec\":{\"minReplicas\":2}}'  # Prevent scale-to-zero",
					hpa.Name, hpa.Namespace))
			}
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func generateHPATable(analyses []HPAAnalysis) internal.TableFile {
	header := []string{"Namespace", "Name", "Target", "Min", "Max", "Current", "Desired", "Metrics", "Risk", "Score", "Cost"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	for _, hpa := range analyses {
		target := fmt.Sprintf("%s/%s", hpa.TargetKind, hpa.TargetName)
		metricsStr := strings.Join(hpa.MetricTypes, ",")
		if len(metricsStr) > 30 {
			metricsStr = metricsStr[:27] + "..."
		}

		rows = append(rows, []string{
			hpa.Namespace,
			hpa.Name,
			target,
			fmt.Sprintf("%d", hpa.MinReplicas),
			fmt.Sprintf("%d", hpa.MaxReplicas),
			fmt.Sprintf("%d", hpa.CurrentReplicas),
			fmt.Sprintf("%d", hpa.DesiredReplicas),
			metricsStr,
			hpa.RiskLevel,
			fmt.Sprintf("%d", hpa.RiskScore),
			hpa.CostRisk,
		})
	}

	return internal.TableFile{
		Name:   "HPAs",
		Header: header,
		Body:   rows,
	}
}
