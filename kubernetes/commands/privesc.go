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

var PrivescCmd = &cobra.Command{
	Use:     "privesc",
	Aliases: []string{"pe", "escalate", "priv"},
	Short:   "Identify privilege escalation paths in Kubernetes RBAC",
	Long: `Analyze Kubernetes RBAC to identify privilege escalation opportunities.

This module examines ClusterRoleBindings and RoleBindings to find principals
with dangerous permissions that could be used to escalate privileges.

Detected privilege escalation methods (30+) include:

RBAC Escalation:
- Cluster-admin equivalent (wildcard verbs/resources)
- ClusterRoleBinding/RoleBinding creation
- Bind/Escalate verbs (bypass RBAC restrictions)
- Role/ClusterRole modification

Impersonation:
- User impersonation (including system:admin)
- Group impersonation (including system:masters)
- ServiceAccount impersonation

Pod-Based Escalation:
- Create pods with privileged security context
- Create pods with hostPath, hostPID, hostNetwork
- Exec into existing pods
- Create workloads (Deployments, DaemonSets, Jobs) with elevated SAs

Token/Credential Theft:
- ServiceAccount token generation
- Secret access (SA tokens, TLS certs)

Node Access:
- Node creation/modification
- Kubelet API proxy access

Webhook Abuse:
- Mutating webhook creation (inject malicious content)
- Validating webhook creation (intercept/block requests)

Usage:
  cloudfox kubernetes privesc`,
	Run: runPrivescCommand,
}

type PrivescOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivescOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivescOutput) LootFiles() []internal.LootFile   { return o.Loot }

type PrivescModule struct {
	// All paths from combined analysis
	AllPaths       []attackpathservice.AttackPath
	ClusterPaths   []attackpathservice.AttackPath
	NamespacePaths map[string][]attackpathservice.AttackPath
	Namespaces     []string

	// Loot
	LootContent string
}

func runPrivescCommand(cmd *cobra.Command, args []string) {
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
		logger.ErrorM(fmt.Sprintf("Authentication failed:\n%v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Analyzing privilege escalation paths for %s", globals.ClusterName), globals.K8S_PRIVESC_MODULE_NAME)

	// Initialize attack path service
	svc, err := attackpathservice.New()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to initialize attack path service: %v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}
	svc.SetModuleName(globals.K8S_PRIVESC_MODULE_NAME)

	// Run analysis
	result, err := svc.CombinedAnalysis(ctx, "privesc")
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to analyze privilege escalation: %v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	module := &PrivescModule{
		AllPaths:       result.AllPaths,
		ClusterPaths:   result.ClusterPaths,
		NamespacePaths: result.NamespacePaths,
		Namespaces:     result.Namespaces,
	}

	if len(module.AllPaths) == 0 {
		logger.InfoM("No privilege escalation paths found", globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	// Count by scope and risk
	clusterCount := len(module.ClusterPaths)
	namespaceCount := len(module.AllPaths) - clusterCount
	riskCounts := countRiskLevels(module.AllPaths)

	logger.SuccessM(fmt.Sprintf("Found %d privilege escalation path(s): %d cluster-level, %d namespace-level",
		len(module.AllPaths), clusterCount, namespaceCount), globals.K8S_PRIVESC_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_PRIVESC_MODULE_NAME)

	// Generate output
	tables := module.buildTables()
	loot := module.generateLoot()

	output := PrivescOutput{
		Table: tables,
		Loot:  loot,
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"privesc",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.K8S_PRIVESC_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PRIVESC_MODULE_NAME), globals.K8S_PRIVESC_MODULE_NAME)
}

func (m *PrivescModule) buildTables() []internal.TableFile {
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
			Name:   "Privesc",
			Header: headers,
			Body:   body,
		},
	}
}

func (m *PrivescModule) generateLoot() []internal.LootFile {
	var lootContent []string

	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "##### Kubernetes Privilege Escalation Commands")
	lootContent = append(lootContent, "##### Generated by CloudFox")
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "")

	riskCounts := countRiskLevels(m.AllPaths)
	lootContent = append(lootContent, fmt.Sprintf("# Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low))
	lootContent = append(lootContent, "")

	// Group paths by risk level
	criticalPaths := filterByRisk(m.AllPaths, shared.RiskCritical)
	highPaths := filterByRisk(m.AllPaths, shared.RiskHigh)

	// CRITICAL section
	if len(criticalPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### CRITICAL - Immediate privilege escalation paths")
		lootContent = append(lootContent, "")
		for _, path := range criticalPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] Principal: %s (%s)", path.RiskLevel, path.Principal, path.PrincipalType))
			lootContent = append(lootContent, fmt.Sprintf("# Method: %s", path.Method))
			lootContent = append(lootContent, fmt.Sprintf("# Scope: %s", path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# Role: %s via %s", path.RoleName, path.BindingName))
			lootContent = append(lootContent, fmt.Sprintf("# Description: %s", path.Description))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// HIGH section
	if len(highPaths) > 0 {
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, "### HIGH - Significant privilege escalation paths")
		lootContent = append(lootContent, "")
		for _, path := range highPaths {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] Principal: %s (%s)", path.RiskLevel, path.Principal, path.PrincipalType))
			lootContent = append(lootContent, fmt.Sprintf("# Method: %s", path.Method))
			lootContent = append(lootContent, fmt.Sprintf("# Scope: %s", path.ScopeName))
			lootContent = append(lootContent, fmt.Sprintf("# Role: %s via %s", path.RoleName, path.BindingName))
			lootContent = append(lootContent, fmt.Sprintf("# Description: %s", path.Description))
			lootContent = append(lootContent, path.ExploitCommand)
			lootContent = append(lootContent, "")
		}
	}

	// Group by method for easy exploitation
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### GROUPED BY METHOD")
	lootContent = append(lootContent, "")

	methodGroups := groupByMethod(m.AllPaths)
	for method, paths := range methodGroups {
		lootContent = append(lootContent, fmt.Sprintf("## %s (%d paths)", method, len(paths)))
		for _, path := range paths {
			lootContent = append(lootContent, fmt.Sprintf("# %s - %s (%s)", path.Principal, path.RoleName, path.ScopeName))
			lootContent = append(lootContent, path.ExploitCommand)
		}
		lootContent = append(lootContent, "")
	}

	return []internal.LootFile{
		{
			Name:     "Privesc-Loot",
			Contents: strings.Join(lootContent, "\n"),
		},
	}
}

// Helper functions

func countRiskLevels(paths []attackpathservice.AttackPath) *shared.RiskCounts {
	counts := shared.NewRiskCounts()
	for _, path := range paths {
		counts.Add(path.RiskLevel)
	}
	return counts
}

func filterByRisk(paths []attackpathservice.AttackPath, riskLevel string) []attackpathservice.AttackPath {
	var filtered []attackpathservice.AttackPath
	for _, path := range paths {
		if path.RiskLevel == riskLevel {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func groupByMethod(paths []attackpathservice.AttackPath) map[string][]attackpathservice.AttackPath {
	groups := make(map[string][]attackpathservice.AttackPath)
	for _, path := range paths {
		groups[path.Method] = append(groups[path.Method], path)
	}
	return groups
}
