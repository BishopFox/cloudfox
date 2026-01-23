package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	attackpathservice "github.com/BishopFox/cloudfox/kubernetes/services/attackpathService"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
)

var DataExfiltrationCmd = &cobra.Command{
	Use:     "data-exfiltration",
	Aliases: []string{"exfil", "de", "data-exfil"},
	Short:   "Identify data exfiltration paths in Kubernetes",
	Long: `Analyze Kubernetes RBAC and resources to identify data exfiltration opportunities.

This module examines permissions that allow reading sensitive data from the cluster
that could be exfiltrated to external destinations.

Detected data exfiltration vectors include:

Secrets:
- Read secrets (credentials, API keys, TLS certificates)
- List secrets cluster-wide or namespace-scoped
- Full wildcard access to secrets

ConfigMaps:
- Read configmaps (often contain sensitive configuration)
- List configmaps for sensitive data discovery

Logs:
- Pod logs access (may contain sensitive data, credentials in error messages)

Data Extraction:
- Pod exec (extract files and data from containers)
- PersistentVolumeClaim access (access data volumes)

Token Exfiltration:
- ServiceAccount token generation (for external use)

Custom Resources:
- Read custom resources (may contain sensitive application data)

Usage:
  cloudfox kubernetes data-exfiltration`,
	Run: runDataExfiltrationCommand,
}

type DataExfiltrationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataExfiltrationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataExfiltrationOutput) LootFiles() []internal.LootFile   { return o.Loot }

type DataExfiltrationModule struct {
	// All paths from combined analysis
	AllPaths       []attackpathservice.AttackPath
	ClusterPaths   []attackpathservice.AttackPath
	NamespacePaths map[string][]attackpathservice.AttackPath
	Namespaces     []string
}

func runDataExfiltrationCommand(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	// Validate authentication first
	if err := sdk.ValidateAuth(ctx); err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed:\n%v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Analyzing data exfiltration paths for %s", globals.ClusterName), globals.K8S_DATA_EXFIL_MODULE_NAME)

	// Initialize attack path service
	svc, err := attackpathservice.New()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to initialize attack path service: %v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}
	svc.SetModuleName(globals.K8S_DATA_EXFIL_MODULE_NAME)

	// Run analysis
	result, err := svc.CombinedAnalysis(ctx, "exfil")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to analyze data exfiltration: %v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	module := &DataExfiltrationModule{
		AllPaths:       result.AllPaths,
		ClusterPaths:   result.ClusterPaths,
		NamespacePaths: result.NamespacePaths,
		Namespaces:     result.Namespaces,
	}

	if len(module.AllPaths) == 0 {
		logger.InfoM("No data exfiltration paths found", globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	// Count by scope and risk
	clusterCount := len(module.ClusterPaths)
	namespaceCount := len(module.AllPaths) - clusterCount
	riskCounts := countExfilRiskLevels(module.AllPaths)

	logger.SuccessM(fmt.Sprintf("Found %d data exfiltration path(s): %d cluster-level, %d namespace-level",
		len(module.AllPaths), clusterCount, namespaceCount), globals.K8S_DATA_EXFIL_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_DATA_EXFIL_MODULE_NAME)

	// Generate output
	tables := module.buildExfilTables()
	loot := module.generateExfilLoot()

	output := DataExfiltrationOutput{
		Table: tables,
		Loot:  loot,
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"data-exfiltration",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.K8S_DATA_EXFIL_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DATA_EXFIL_MODULE_NAME), globals.K8S_DATA_EXFIL_MODULE_NAME)
}

func (m *DataExfiltrationModule) buildExfilTables() []internal.TableFile {
	headers := []string{
		"Risk Level",
		"Scope",
		"Principal",
		"Principal Type",
		"Method",
		"Target Resource",
		"Permissions",
		"Role",
		"Binding",
		"Description",
	}

	var body [][]string

	// Sort by risk level (CRITICAL first)
	sortedPaths := make([]attackpathservice.AttackPath, len(m.AllPaths))
	copy(sortedPaths, m.AllPaths)
	sort.Slice(sortedPaths, func(i, j int) bool {
		return shared.RiskLevelValue(sortedPaths[i].RiskLevel) > shared.RiskLevelValue(sortedPaths[j].RiskLevel)
	})

	for _, path := range sortedPaths {
		scope := path.ScopeName
		if path.ScopeType == "cluster" {
			scope = "cluster-wide"
		}

		body = append(body, []string{
			path.RiskLevel,
			scope,
			path.Principal,
			path.PrincipalType,
			path.Method,
			path.TargetResource,
			strings.Join(path.Permissions, ", "),
			path.RoleName,
			path.BindingName,
			path.Description,
		})
	}

	return []internal.TableFile{
		{
			Name:   "DataExfiltration",
			Header: headers,
			Body:   body,
		},
	}
}

func (m *DataExfiltrationModule) generateExfilLoot() []internal.LootFile {
	var lootContent []string

	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "##### Kubernetes Data Exfiltration Commands")
	lootContent = append(lootContent, "##### Generated by CloudFox")
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "")

	riskCounts := countExfilRiskLevels(m.AllPaths)
	lootContent = append(lootContent, fmt.Sprintf("# Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low))
	lootContent = append(lootContent, "")

	// Section: Secrets
	secretPaths := filterExfilByCategory(m.AllPaths, "Secrets")
	if len(secretPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### SECRETS - Extract credentials, API keys, certificates")
		lootContent = append(lootContent, "")
		for _, path := range secretPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# Role: %s via %s", path.RoleName, path.BindingName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}

		// Add additional secret extraction commands
		lootContent = append(lootContent, "# Additional secret extraction commands:")
		lootContent = append(lootContent, "# Decode all secrets in a namespace:")
		lootContent = append(lootContent, "kubectl get secrets -n <namespace> -o json | jq '.items[].data | map_values(@base64d)'")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Find TLS certificates:")
		lootContent = append(lootContent, "kubectl get secrets -A --field-selector type=kubernetes.io/tls -o wide")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Find docker registry credentials:")
		lootContent = append(lootContent, "kubectl get secrets -A --field-selector type=kubernetes.io/dockerconfigjson -o json | jq '.items[].data[\".dockerconfigjson\"]' -r | base64 -d")
		lootContent = append(lootContent, "")
	}

	// Section: ConfigMaps
	configmapPaths := filterExfilByCategory(m.AllPaths, "ConfigMaps")
	if len(configmapPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### CONFIGMAPS - Extract configuration data")
		lootContent = append(lootContent, "")
		for _, path := range configmapPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Section: Logs
	logPaths := filterExfilByCategory(m.AllPaths, "Logs")
	if len(logPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### LOGS - Extract pod logs (may contain sensitive data)")
		lootContent = append(lootContent, "")
		for _, path := range logPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}

		// Add additional log extraction commands
		lootContent = append(lootContent, "# Search logs for sensitive patterns:")
		lootContent = append(lootContent, "kubectl logs <pod> | grep -iE '(password|secret|token|key|credential)'")
		lootContent = append(lootContent, "")
	}

	// Section: Data Extraction via Exec
	execPaths := filterExfilByCategory(m.AllPaths, "Data Extraction")
	if len(execPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### DATA EXTRACTION - Extract files from containers")
		lootContent = append(lootContent, "")
		for _, path := range execPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}

		// Add additional data extraction commands
		lootContent = append(lootContent, "# Extract files via kubectl cp:")
		lootContent = append(lootContent, "kubectl cp <namespace>/<pod>:/path/to/file ./extracted-file")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Extract environment variables:")
		lootContent = append(lootContent, "kubectl exec <pod> -n <namespace> -- env | grep -iE '(password|secret|token|key|credential|database|api)'")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# Extract SA token from running pod:")
		lootContent = append(lootContent, "kubectl exec <pod> -n <namespace> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token")
		lootContent = append(lootContent, "")
	}

	// Section: Token Exfiltration
	tokenPaths := filterExfilByCategory(m.AllPaths, "Token Exfil")
	if len(tokenPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### TOKEN EXFILTRATION - Generate SA tokens for external use")
		lootContent = append(lootContent, "")
		for _, path := range tokenPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Section: Storage
	storagePaths := filterExfilByCategory(m.AllPaths, "Storage")
	if len(storagePaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### STORAGE - Access persistent volume data")
		lootContent = append(lootContent, "")
		for _, path := range storagePaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s (%s) - %s", path.RiskLevel, path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Group by namespace for targeted exfiltration
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### GROUPED BY NAMESPACE")
	lootContent = append(lootContent, "")

	for namespace, paths := range m.NamespacePaths {
		if len(paths) > 0 {
			lootContent = append(lootContent, fmt.Sprintf("## Namespace: %s (%d paths)", namespace, len(paths)))

			// Group by category within namespace
			secretsInNs := filterExfilByCategory(paths, "Secrets")
			if len(secretsInNs) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# Secrets access: %d principals", len(secretsInNs)))
				lootContent = append(lootContent, fmt.Sprintf("kubectl get secrets -n %s -o yaml", namespace))
			}

			configmapsInNs := filterExfilByCategory(paths, "ConfigMaps")
			if len(configmapsInNs) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# ConfigMaps access: %d principals", len(configmapsInNs)))
				lootContent = append(lootContent, fmt.Sprintf("kubectl get configmaps -n %s -o yaml", namespace))
			}

			lootContent = append(lootContent, "")
		}
	}

	// Summary of high-value targets
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### HIGH-VALUE TARGETS")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Cluster-wide secret access is most dangerous:")
	clusterSecretPaths := filterExfilByCategory(m.ClusterPaths, "Secrets")
	if len(clusterSecretPaths) > 0 {
		lootContent = append(lootContent, fmt.Sprintf("# Found %d principals with cluster-wide secret access", len(clusterSecretPaths)))
		for _, path := range clusterSecretPaths {
			lootContent = append(lootContent, fmt.Sprintf("# - %s (%s) via %s", path.Principal, path.PrincipalType, path.RoleName))
		}
	} else {
		lootContent = append(lootContent, "# No cluster-wide secret access found")
	}
	lootContent = append(lootContent, "")

	return []internal.LootFile{
		{
			Name:     "DataExfiltration-Commands",
			Contents: strings.Join(lootContent, "\n"),
		},
	}
}

// Helper functions

func countExfilRiskLevels(paths []attackpathservice.AttackPath) *shared.RiskCounts {
	counts := shared.NewRiskCounts()
	for _, path := range paths {
		counts.Add(path.RiskLevel)
	}
	return counts
}

func filterExfilByCategory(paths []attackpathservice.AttackPath, category string) []attackpathservice.AttackPath {
	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if path.Category == category {
			filtered = append(filtered, path)
		}
	}
	return filtered
}
