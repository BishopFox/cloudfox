package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
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
	// Thresholds
	UnboundedMaxReplicas  = 100
	AggressiveMaxReplicas = 50
	HighCostMaxReplicas   = 20
)

func ListHPAs(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing HPAs for %s", globals.ClusterName), globals.K8S_HPAS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch HPAs from cache
	allHPAs, err := sdk.GetHorizontalPodAutoscalers(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching HPAs: %v", err), globals.K8S_HPAS_MODULE_NAME)
		return
	}

	// Filter by target namespace if specified
	targetNS := shared.GetNamespaceOrAll()
	var hpasList []autoscalingv2.HorizontalPodAutoscaler
	if targetNS == "" {
		hpasList = allHPAs
	} else {
		for _, hpa := range allHPAs {
			if hpa.Namespace == targetNS {
				hpasList = append(hpasList, hpa)
			}
		}
	}

	var hpaAnalyses []HPAAnalysis
	loot := shared.NewLootBuilder()

	// Analyze each HPA
	for _, hpa := range hpasList {
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

		hpaAnalyses = append(hpaAnalyses, analysis)
	}

	// Generate consolidated HPA-Commands section
	loot.Section("HPA-Commands").Add(generateHPACommands(hpaAnalyses))

	// Build loot files
	lootFiles := loot.Build()

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
	if len(hpasList) > 0 {
		unboundedCount := 0
		zeroRiskCount := 0
		customMetricCount := 0
		for _, hpa := range hpaAnalyses {
			if hpa.UnboundedScaling {
				unboundedCount++
			}
			if hpa.ScaleToZeroRisk {
				zeroRiskCount++
			}
			if len(hpa.CustomMetrics) > 0 || len(hpa.ExternalMetrics) > 0 {
				customMetricCount++
			}
		}
		logger.InfoM(fmt.Sprintf("%d HPAs analyzed | Unbounded: %d | Zero-Risk: %d | Custom Metrics: %d",
			len(hpasList), unboundedCount, zeroRiskCount, customMetricCount),
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
		analysis.CostRisk = shared.RiskCritical
		issues = append(issues, fmt.Sprintf("CRITICAL: Unbounded scaling (maxReplicas=%d, potential cost explosion)", analysis.MaxReplicas))
	} else if analysis.MaxReplicas >= AggressiveMaxReplicas {
		analysis.AggressiveThreshold = true
		analysis.CostRisk = shared.RiskHigh
		issues = append(issues, fmt.Sprintf("HIGH: Aggressive scaling threshold (maxReplicas=%d, cost risk)", analysis.MaxReplicas))
	} else if analysis.MaxReplicas >= HighCostMaxReplicas {
		analysis.CostRisk = shared.RiskMedium
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
		return shared.RiskCritical
	} else if score >= 50 {
		return shared.RiskHigh
	} else if score >= 25 {
		return shared.RiskMedium
	}
	return shared.RiskLow
}

func generateHPACommands(analyses []HPAAnalysis) string {
	var lines []string

	lines = append(lines, "# ===========================================")
	lines = append(lines, "# HPA Enumeration Commands")
	lines = append(lines, "# ===========================================")
	lines = append(lines, "")

	lines = append(lines, "# List all HPAs:")
	lines = append(lines, "kubectl get hpa -A")
	lines = append(lines, "")

	lines = append(lines, "# View HPA details:")
	lines = append(lines, "kubectl describe hpa <name> -n <namespace>")
	lines = append(lines, "")

	lines = append(lines, "# Watch HPA scaling in real-time:")
	lines = append(lines, "kubectl get hpa -A --watch")
	lines = append(lines, "")

	lines = append(lines, "# Get HPA metrics status:")
	lines = append(lines, "kubectl get hpa -A -o wide")
	lines = append(lines, "")

	lines = append(lines, "# ===========================================")
	lines = append(lines, "# Remediation Commands")
	lines = append(lines, "# ===========================================")
	lines = append(lines, "")

	lines = append(lines, "# Create HPA with safe limits:")
	lines = append(lines, "kubectl autoscale deployment <name> -n <namespace> --min=2 --max=10 --cpu-percent=80")
	lines = append(lines, "")

	lines = append(lines, "# Update maxReplicas to prevent unbounded scaling:")
	lines = append(lines, "kubectl patch hpa <name> -n <namespace> -p '{\"spec\":{\"maxReplicas\":10}}'")
	lines = append(lines, "")

	lines = append(lines, "# Set minReplicas to prevent scale-to-zero:")
	lines = append(lines, "kubectl patch hpa <name> -n <namespace> -p '{\"spec\":{\"minReplicas\":2}}'")
	lines = append(lines, "")

	lines = append(lines, "# Delete HPA:")
	lines = append(lines, "kubectl delete hpa <name> -n <namespace>")
	lines = append(lines, "")

	// Add specific remediation for high-risk HPAs
	var highRiskHPAs []HPAAnalysis
	for _, hpa := range analyses {
		if hpa.UnboundedScaling || hpa.ScaleToZeroRisk || len(hpa.CustomMetrics) > 0 || len(hpa.ExternalMetrics) > 0 {
			highRiskHPAs = append(highRiskHPAs, hpa)
		}
	}

	if len(highRiskHPAs) > 0 {
		lines = append(lines, "# ===========================================")
		lines = append(lines, "# Flagged HPAs - Specific Remediation")
		lines = append(lines, "# ===========================================")
		lines = append(lines, "")

		for _, hpa := range highRiskHPAs {
			var flags []string
			if hpa.UnboundedScaling {
				flags = append(flags, "Unbounded")
			}
			if hpa.ScaleToZeroRisk {
				flags = append(flags, "Zero-Risk")
			}
			if len(hpa.CustomMetrics) > 0 {
				flags = append(flags, "Custom")
			}
			if len(hpa.ExternalMetrics) > 0 {
				flags = append(flags, "External")
			}

			lines = append(lines, fmt.Sprintf("# %s/%s [%s]", hpa.Namespace, hpa.Name, strings.Join(flags, ", ")))
			lines = append(lines, fmt.Sprintf("# Target: %s/%s | Min: %d | Max: %d", hpa.TargetKind, hpa.TargetName, hpa.MinReplicas, hpa.MaxReplicas))

			if hpa.UnboundedScaling {
				lines = append(lines, fmt.Sprintf("kubectl patch hpa %s -n %s -p '{\"spec\":{\"maxReplicas\":10}}'", hpa.Name, hpa.Namespace))
			}
			if hpa.ScaleToZeroRisk {
				lines = append(lines, fmt.Sprintf("kubectl patch hpa %s -n %s -p '{\"spec\":{\"minReplicas\":2}}'", hpa.Name, hpa.Namespace))
			}
			if len(hpa.CustomMetrics) > 0 || len(hpa.ExternalMetrics) > 0 {
				lines = append(lines, fmt.Sprintf("kubectl describe hpa %s -n %s  # Verify metric source security", hpa.Name, hpa.Namespace))
			}
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func generateHPATable(analyses []HPAAnalysis) internal.TableFile {
	header := []string{"Namespace", "Name", "Target", "Min", "Max", "Current", "Desired", "Metrics", "Flags"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	for _, hpa := range analyses {
		target := fmt.Sprintf("%s/%s", hpa.TargetKind, hpa.TargetName)
		metricsStr := strings.Join(hpa.MetricTypes, ",")

		// Build flags
		var flags []string
		if hpa.UnboundedScaling {
			flags = append(flags, "Unbounded")
		}
		if hpa.ScaleToZeroRisk {
			flags = append(flags, "Zero-Risk")
		}
		if len(hpa.CustomMetrics) > 0 {
			flags = append(flags, "Custom")
		}
		if len(hpa.ExternalMetrics) > 0 {
			flags = append(flags, "External")
		}
		flagsStr := strings.Join(flags, ",")

		rows = append(rows, []string{
			hpa.Namespace,
			hpa.Name,
			target,
			fmt.Sprintf("%d", hpa.MinReplicas),
			fmt.Sprintf("%d", hpa.MaxReplicas),
			fmt.Sprintf("%d", hpa.CurrentReplicas),
			fmt.Sprintf("%d", hpa.DesiredReplicas),
			metricsStr,
			flagsStr,
		})
	}

	return internal.TableFile{
		Name:   "HPAs",
		Header: header,
		Body:   rows,
	}
}
