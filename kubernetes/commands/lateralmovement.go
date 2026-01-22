package commands

import (
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	attackpathservice "github.com/BishopFox/cloudfox/kubernetes/services/attackpathService"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
)

var LateralMovementCmd = &cobra.Command{
	Use:     "lateral-movement",
	Aliases: []string{"lm", "lateral"},
	Short:   "Identify lateral movement paths in Kubernetes",
	Long: `Analyze Kubernetes RBAC and resources to identify lateral movement opportunities.

This module examines permissions that allow movement between pods, namespaces,
and nodes within the cluster.

Detected lateral movement vectors include:

Pod Access:
- Pod exec (execute commands in containers)
- Pod attach (attach to running containers)
- Pod port-forward (tunnel to pod ports)

Token/Credential Theft:
- Secret access (SA tokens, TLS certs, credentials)
- ServiceAccount token generation
- ConfigMap access (often contains service credentials)

Service Discovery:
- Service enumeration
- Endpoint discovery (direct pod IP access)
- Namespace enumeration

Network Access:
- Network policy modification/deletion
- Ingress modification (traffic redirection)

Node Access:
- Kubelet API proxy access
- Node proxy access

Usage:
  cloudfox kubernetes lateral-movement`,
	Run: runLateralMovementCommand,
}

type LateralMovementOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LateralMovementOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LateralMovementOutput) LootFiles() []internal.LootFile   { return o.Loot }

type LateralMovementModule struct {
	// All paths from combined analysis
	AllPaths       []attackpathservice.AttackPath
	ClusterPaths   []attackpathservice.AttackPath
	NamespacePaths map[string][]attackpathservice.AttackPath
	Namespaces     []string
}

func runLateralMovementCommand(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	// Validate authentication first
	if err := sdk.ValidateAuth(ctx); err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed:\n%v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Analyzing lateral movement paths for %s", globals.ClusterName), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)

	// Initialize attack path service
	svc, err := attackpathservice.New()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to initialize attack path service: %v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}
	svc.SetModuleName(globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)

	// Run analysis
	result, err := svc.CombinedAnalysis(ctx, "lateral")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to analyze lateral movement: %v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	module := &LateralMovementModule{
		AllPaths:       result.AllPaths,
		ClusterPaths:   result.ClusterPaths,
		NamespacePaths: result.NamespacePaths,
		Namespaces:     result.Namespaces,
	}

	if len(module.AllPaths) == 0 {
		logger.InfoM("No lateral movement paths found", globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	// Count by scope and risk
	clusterCount := len(module.ClusterPaths)
	namespaceCount := len(module.AllPaths) - clusterCount
	riskCounts := countLateralRiskLevels(module.AllPaths)

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s): %d cluster-level, %d namespace-level",
		len(module.AllPaths), clusterCount, namespaceCount), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)

	// Generate output
	tables := module.buildLateralTables()
	loot := module.generateLateralLoot()

	output := LateralMovementOutput{
		Table: tables,
		Loot:  loot,
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Lateral-Movement",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_LATERAL_MOVEMENT_MODULE_NAME), globals.K8S_LATERAL_MOVEMENT_MODULE_NAME)
}

func (m *LateralMovementModule) buildLateralTables() []internal.TableFile {
	headers := []string{
		"Principal",
		"Principal Type",
		"Scope",
		"Role",
		"Role Binding",
		"Method",
		"Target Resource",
		"Permissions",
		"Description",
	}

	var body [][]string

	for _, path := range m.AllPaths {
		scope := path.ScopeName
		if path.ScopeType == "cluster" {
			scope = "cluster-wide"
		}

		body = append(body, []string{
			path.Principal,
			path.PrincipalType,
			scope,
			path.RoleName,
			path.BindingName,
			path.Method,
			path.TargetResource,
			strings.Join(path.Permissions, ", "),
			path.Description,
		})
	}

	return []internal.TableFile{
		{
			Name:   "LateralMovement",
			Header: headers,
			Body:   body,
		},
	}
}

func (m *LateralMovementModule) generateLateralLoot() []internal.LootFile {
	var lootContent []string

	lootContent = append(lootContent, "# ===========================================")
	lootContent = append(lootContent, "# Lateral Movement Commands")
	lootContent = append(lootContent, "# ===========================================")

	// Section: Pod Access
	podAccessPaths := filterByCategory(m.AllPaths, "Pod Access")
	if len(podAccessPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# POD ACCESS - Execute/attach to containers")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range podAccessPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s via %s", path.Principal, path.PrincipalType, path.ScopeName, path.RoleName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Token/Credential Theft
	tokenPaths := filterByCategory(m.AllPaths, "Token Theft")
	if len(tokenPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# TOKEN THEFT - Steal SA tokens and credentials")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range tokenPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s via %s", path.Principal, path.PrincipalType, path.ScopeName, path.RoleName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Service Discovery
	discoveryPaths := filterByMultipleCategories(m.AllPaths, []string{"Service Discovery", "Namespace Discovery", "Pod Discovery"})
	if len(discoveryPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# SERVICE DISCOVERY - Find lateral movement targets")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range discoveryPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s", path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Network Access
	networkPaths := filterByCategory(m.AllPaths, "Network")
	if len(networkPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# NETWORK - Bypass network policies")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range networkPaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s", path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# %s", path.Description))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	// Section: Node Access
	nodePaths := filterByCategory(m.AllPaths, "Node Access")
	if len(nodePaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "# -------------------------------------------")
		lootContent = append(lootContent, "# NODE ACCESS - Access kubelet and node resources")
		lootContent = append(lootContent, "# -------------------------------------------")
		for _, path := range nodePaths {
			lootContent = append(lootContent, "")
			lootContent = append(lootContent, fmt.Sprintf("# %s (%s) - %s", path.Principal, path.PrincipalType, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
	}

	return []internal.LootFile{
		{
			Name:     "LateralMovement-Commands",
			Contents: strings.Join(lootContent, "\n"),
		},
	}
}

// Helper functions

func countLateralRiskLevels(paths []attackpathservice.AttackPath) *shared.RiskCounts {
	counts := shared.NewRiskCounts()
	for _, path := range paths {
		counts.Add(path.RiskLevel)
	}
	return counts
}

func filterByCategory(paths []attackpathservice.AttackPath, category string) []attackpathservice.AttackPath {
	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if path.Category == category {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func filterByMultipleCategories(paths []attackpathservice.AttackPath, categories []string) []attackpathservice.AttackPath {
	categorySet := make(map[string]bool)
	for _, c := range categories {
		categorySet[c] = true
	}

	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if categorySet[path.Category] {
			filtered = append(filtered, path)
		}
	}
	return filtered
}
