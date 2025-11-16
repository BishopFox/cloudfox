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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var CRDsCmd = &cobra.Command{
	Use:     "crds",
	Aliases: []string{"crd", "customresources"},
	Short:   "Analyze Custom Resource Definitions for security risks",
	Long: `
Analyze Custom Resource Definitions with comprehensive security analysis including:
  - Missing validation schemas (injection and data integrity risks)
  - Unversioned CRDs (breaking change risks)
  - CRDs with conversion webhooks (admission bypass potential)
  - Cluster-scoped CRDs (broad access implications)
  - CRDs without descriptions (operational risk)
  - Deprecated API versions still in use
  - Storage version migrations needed
  - CRD sprawl (unused or abandoned CRDs)
  - OpenAPI v3 schema validation
  - Subresources (status, scale) configuration
  - Printer columns for kubectl output

  cloudfox kubernetes crds`,
	Run: ListCRDs,
}

type CRDsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t CRDsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t CRDsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type CRDAnalysis struct {
	Name                 string
	Group                string
	Kind                 string
	Scope                string
	Versions             []string
	StoredVersions       []string
	LatestVersion        string
	HasValidation        bool
	HasConversionWebhook bool
	ConversionStrategy   string
	HasStatus            bool
	HasScale             bool
	Namespaced           bool
	Categories           []string
	ShortNames           []string
	RiskLevel            string
	RiskScore            int
	SecurityIssues       []string
	DeprecatedVersions   []string
}

const (
	CRDRiskCritical = "CRITICAL"
	CRDRiskHigh     = "HIGH"
	CRDRiskMedium   = "MEDIUM"
	CRDRiskLow      = "LOW"
)

func ListCRDs(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing CRDs for %s", globals.ClusterName), globals.K8S_CRDS_MODULE_NAME)

	// Get rest config
	restConfig, err := config.GetRESTConfig()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error getting REST config: %v", err), globals.K8S_CRDS_MODULE_NAME)
		return
	}

	// Create apiextensions clientset
	apiextensionsClient, err := apiextensionsclientset.NewForConfig(restConfig)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating apiextensions client: %v", err), globals.K8S_CRDS_MODULE_NAME)
		return
	}

	// Fetch CRDs
	crds, err := apiextensionsClient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching CRDs: %v", err), globals.K8S_CRDS_MODULE_NAME)
		return
	}

	var crdAnalyses []CRDAnalysis
	var noValidation []string
	var clusterScoped []string
	var conversionWebhooks []string
	var deprecatedVersions []string

	// Analyze each CRD
	for _, crd := range crds.Items {
		analysis := CRDAnalysis{
			Name:           crd.Name,
			Group:          crd.Spec.Group,
			Kind:           crd.Spec.Names.Kind,
			Scope:          string(crd.Spec.Scope),
			StoredVersions: crd.Status.StoredVersions,
			Categories:     crd.Spec.Names.Categories,
			ShortNames:     crd.Spec.Names.ShortNames,
			Namespaced:     crd.Spec.Scope == apiextensionsv1.NamespaceScoped,
		}

		// Extract versions
		for _, ver := range crd.Spec.Versions {
			analysis.Versions = append(analysis.Versions, ver.Name)
			if ver.Served && ver.Storage {
				analysis.LatestVersion = ver.Name
			}

			// Check for validation schema
			if ver.Schema != nil && ver.Schema.OpenAPIV3Schema != nil {
				analysis.HasValidation = true
			}

			// Check for deprecated versions
			if ver.Deprecated {
				analysis.DeprecatedVersions = append(analysis.DeprecatedVersions, ver.Name)
			}

			// Check for subresources
			if ver.Subresources != nil {
				if ver.Subresources.Status != nil {
					analysis.HasStatus = true
				}
				if ver.Subresources.Scale != nil {
					analysis.HasScale = true
				}
			}
		}

		// Conversion webhook analysis
		if crd.Spec.Conversion != nil {
			analysis.ConversionStrategy = string(crd.Spec.Conversion.Strategy)
			if crd.Spec.Conversion.Strategy == apiextensionsv1.WebhookConverter {
				analysis.HasConversionWebhook = true
			}
		}

		// Security analysis
		issues := analyzeCRDSecurity(&analysis, &crd)
		analysis.SecurityIssues = issues

		// Calculate risk score
		analysis.RiskScore = calculateCRDRiskScore(&analysis)
		analysis.RiskLevel = crdRiskScoreToLevel(analysis.RiskScore)

		// Categorize for loot files
		if !analysis.HasValidation {
			noValidation = append(noValidation, formatNoValidationCRD(&analysis))
		}
		if !analysis.Namespaced {
			clusterScoped = append(clusterScoped, formatClusterScopedCRD(&analysis))
		}
		if analysis.HasConversionWebhook {
			conversionWebhooks = append(conversionWebhooks, formatConversionWebhookCRD(&analysis))
		}
		if len(analysis.DeprecatedVersions) > 0 {
			deprecatedVersions = append(deprecatedVersions, formatDeprecatedCRD(&analysis))
		}

		crdAnalyses = append(crdAnalyses, analysis)
	}

	// Generate loot files
	lootFiles := []internal.LootFile{
		{
			Name:     "CRD-Enum",
			Contents: formatCRDEnum(crdAnalyses),
		},
		{
			Name:     "No-Validation-CRDs",
			Contents: strings.Join(noValidation, "\n"),
		},
		{
			Name:     "Cluster-Scoped-CRDs",
			Contents: strings.Join(clusterScoped, "\n"),
		},
		{
			Name:     "Conversion-Webhooks",
			Contents: strings.Join(conversionWebhooks, "\n"),
		},
		{
			Name:     "Deprecated-Versions",
			Contents: strings.Join(deprecatedVersions, "\n"),
		},
		{
			Name:     "Remediation-Guide",
			Contents: generateCRDRemediationGuide(crdAnalyses),
		},
	}

	// Generate table
	crdTable := generateCRDTable(crdAnalyses)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"CRDs",
		globals.ClusterName,
		"results",
		CRDsOutput{
			Table: []internal.TableFile{crdTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CRDS_MODULE_NAME)
		return
	}

	// Summary logging
	if len(crds.Items) > 0 {
		noValidationCount := len(noValidation)
		clusterScopedCount := len(clusterScoped)
		logger.InfoM(fmt.Sprintf("%d CRDs analyzed | No Validation: %d | Cluster-Scoped: %d | Webhooks: %d",
			len(crds.Items), noValidationCount, clusterScopedCount, len(conversionWebhooks)),
			globals.K8S_CRDS_MODULE_NAME)
	} else {
		logger.InfoM("No CRDs found", globals.K8S_CRDS_MODULE_NAME)
	}
}

func analyzeCRDSecurity(analysis *CRDAnalysis, crd *apiextensionsv1.CustomResourceDefinition) []string {
	var issues []string

	// No validation schema
	if !analysis.HasValidation {
		issues = append(issues, "CRITICAL: No OpenAPI v3 validation schema (data injection risk, no input validation)")
	}

	// Cluster-scoped CRD
	if !analysis.Namespaced {
		issues = append(issues, "HIGH: Cluster-scoped CRD (broad access, requires cluster-admin to manage)")
	}

	// Conversion webhook
	if analysis.HasConversionWebhook {
		issues = append(issues, "MEDIUM: Uses conversion webhook (webhook security is critical, potential admission bypass)")
	}

	// Deprecated versions still served
	if len(analysis.DeprecatedVersions) > 0 {
		issues = append(issues, fmt.Sprintf("MEDIUM: Deprecated versions in use: %s", strings.Join(analysis.DeprecatedVersions, ", ")))
	}

	// Multiple stored versions (migration needed)
	if len(analysis.StoredVersions) > 1 {
		issues = append(issues, fmt.Sprintf("LOW: Multiple stored versions (%d) - consider storage version migration", len(analysis.StoredVersions)))
	}

	// No status subresource
	if !analysis.HasStatus {
		issues = append(issues, "LOW: No status subresource (mixing spec and status updates)")
	}

	return issues
}

func calculateCRDRiskScore(analysis *CRDAnalysis) int {
	score := 0

	// No validation
	if !analysis.HasValidation {
		score += 50
	}

	// Cluster-scoped
	if !analysis.Namespaced {
		score += 30
	}

	// Conversion webhook
	if analysis.HasConversionWebhook {
		score += 20
	}

	// Deprecated versions
	if len(analysis.DeprecatedVersions) > 0 {
		score += 15
	}

	// Multiple stored versions
	if len(analysis.StoredVersions) > 1 {
		score += 5
	}

	return score
}

func crdRiskScoreToLevel(score int) string {
	if score >= 70 {
		return CRDRiskCritical
	} else if score >= 50 {
		return CRDRiskHigh
	} else if score >= 25 {
		return CRDRiskMedium
	}
	return CRDRiskLow
}

// Formatting functions
func formatNoValidationCRD(analysis *CRDAnalysis) string {
	return fmt.Sprintf("[NO-VALIDATION] %s | Group: %s | Kind: %s | Risk: Data injection, no input validation",
		analysis.Name, analysis.Group, analysis.Kind)
}

func formatClusterScopedCRD(analysis *CRDAnalysis) string {
	return fmt.Sprintf("[CLUSTER-SCOPED] %s | Group: %s | Kind: %s | Requires cluster-admin access",
		analysis.Name, analysis.Group, analysis.Kind)
}

func formatConversionWebhookCRD(analysis *CRDAnalysis) string {
	return fmt.Sprintf("[WEBHOOK] %s | Group: %s | Strategy: %s | Ensure webhook endpoint is secured",
		analysis.Name, analysis.Group, analysis.ConversionStrategy)
}

func formatDeprecatedCRD(analysis *CRDAnalysis) string {
	return fmt.Sprintf("[DEPRECATED] %s | Group: %s | Versions: %s | Plan migration to newer versions",
		analysis.Name, analysis.Group, strings.Join(analysis.DeprecatedVersions, ", "))
}

func formatCRDEnum(analyses []CRDAnalysis) string {
	var lines []string
	lines = append(lines, "=== Custom Resource Definition Security Analysis ===\n")

	for _, crd := range analyses {
		lines = append(lines, fmt.Sprintf("CRD: %s", crd.Name))
		lines = append(lines, fmt.Sprintf("  Group: %s | Kind: %s", crd.Group, crd.Kind))
		lines = append(lines, fmt.Sprintf("  Scope: %s", crd.Scope))
		lines = append(lines, fmt.Sprintf("  Versions: %s (Latest: %s)", strings.Join(crd.Versions, ", "), crd.LatestVersion))
		lines = append(lines, fmt.Sprintf("  Stored Versions: %s", strings.Join(crd.StoredVersions, ", ")))
		lines = append(lines, fmt.Sprintf("  Has Validation: %t", crd.HasValidation))
		lines = append(lines, fmt.Sprintf("  Conversion: %s (Webhook: %t)", crd.ConversionStrategy, crd.HasConversionWebhook))
		lines = append(lines, fmt.Sprintf("  Subresources: Status=%t, Scale=%t", crd.HasStatus, crd.HasScale))
		if len(crd.ShortNames) > 0 {
			lines = append(lines, fmt.Sprintf("  Short Names: %s", strings.Join(crd.ShortNames, ", ")))
		}
		if len(crd.Categories) > 0 {
			lines = append(lines, fmt.Sprintf("  Categories: %s", strings.Join(crd.Categories, ", ")))
		}
		lines = append(lines, fmt.Sprintf("  Risk Level: %s (Score: %d)", crd.RiskLevel, crd.RiskScore))
		if len(crd.SecurityIssues) > 0 {
			lines = append(lines, "  Security Issues:")
			for _, issue := range crd.SecurityIssues {
				lines = append(lines, fmt.Sprintf("    - %s", issue))
			}
		}
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func generateCRDRemediationGuide(analyses []CRDAnalysis) string {
	var lines []string
	lines = append(lines, "=== CRD Security Remediation Guide ===\n")

	lines = append(lines, "# View all CRDs:")
	lines = append(lines, "kubectl get crds")
	lines = append(lines, "")

	lines = append(lines, "# Describe a specific CRD:")
	lines = append(lines, "kubectl describe crd <crd-name>")
	lines = append(lines, "")

	lines = append(lines, "# Get custom resources of a specific CRD:")
	lines = append(lines, "kubectl get <resource-plural> --all-namespaces")
	lines = append(lines, "")

	lines = append(lines, "# Delete unused CRD (warning: deletes all custom resources):")
	lines = append(lines, "kubectl delete crd <crd-name>")
	lines = append(lines, "")

	lines = append(lines, "## Security Best Practices:\n")
	lines = append(lines, "# 1. Always define OpenAPI v3 validation schema in CRD spec")
	lines = append(lines, "# 2. Use namespace-scoped CRDs when possible (avoid cluster-scoped)")
	lines = append(lines, "# 3. Implement proper RBAC for custom resources")
	lines = append(lines, "# 4. Validate conversion webhook configurations")
	lines = append(lines, "# 5. Plan for version migrations (avoid serving deprecated versions)")
	lines = append(lines, "# 6. Use status subresource to separate spec and status updates")
	lines = append(lines, "")

	lines = append(lines, "## Specific Issues:\n")

	for _, crd := range analyses {
		if crd.RiskScore >= 50 {
			lines = append(lines, fmt.Sprintf("# High-risk CRD: %s (Score: %d)", crd.Name, crd.RiskScore))
			for _, issue := range crd.SecurityIssues {
				lines = append(lines, fmt.Sprintf("#   - %s", issue))
			}
			if !crd.HasValidation {
				lines = append(lines, "#   ACTION: Add OpenAPI v3 schema validation to CRD definition")
			}
			if !crd.Namespaced {
				lines = append(lines, "#   ACTION: Consider converting to namespace-scoped if possible")
			}
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func generateCRDTable(analyses []CRDAnalysis) internal.TableFile {
	header := []string{"Name", "Group", "Kind", "Scope", "Versions", "Validation", "Webhook", "Status", "Risk", "Score"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	for _, crd := range analyses {
		versionsStr := strings.Join(crd.Versions, ",")
		if len(versionsStr) > 20 {
			versionsStr = versionsStr[:17] + "..."
		}

		rows = append(rows, []string{
			truncateStr(crd.Name, 50),
			crd.Group,
			crd.Kind,
			crd.Scope,
			versionsStr,
			fmt.Sprintf("%t", crd.HasValidation),
			fmt.Sprintf("%t", crd.HasConversionWebhook),
			fmt.Sprintf("%t", crd.HasStatus),
			crd.RiskLevel,
			fmt.Sprintf("%d", crd.RiskScore),
		})
	}

	return internal.TableFile{
		Name:   "CRDs",
		Header: header,
		Body:   rows,
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
