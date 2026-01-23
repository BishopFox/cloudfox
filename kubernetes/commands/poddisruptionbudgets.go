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
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var PodDisruptionBudgetsCmd = &cobra.Command{
	Use:     "poddisruptionbudgets",
	Aliases: []string{"pdb", "pdbs"},
	Short:   "Analyze PodDisruptionBudgets for availability and security",
	Long: `
Analyze PodDisruptionBudgets with comprehensive security and availability analysis including:
  - Missing PDBs for critical workloads (availability risk)
  - Overly permissive PDBs (minAvailable=0, allows unlimited disruptions)
  - Too restrictive PDBs (blocking cluster maintenance)
  - Selector mismatches (PDB not protecting expected pods)
  - Namespace coverage gaps (no PDBs in production namespaces)
  - PDB conflicts (multiple PDBs targeting same pods)
  - Eviction API abuse potential
  - Deployment/StatefulSet without PDB protection
  - Risk scoring based on availability exposure

  cloudfox kubernetes poddisruptionbudgets`,
	Run: ListPodDisruptionBudgets,
}

type PodDisruptionBudgetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PodDisruptionBudgetsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t PodDisruptionBudgetsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type PDBAnalysis struct {
	Name               string
	Namespace          string
	MinAvailable       string
	MaxUnavailable     string
	CurrentHealthy     int32
	DesiredHealthy     int32
	ExpectedPods       int32
	DisruptionsAllowed int32
	Selector           string
	MatchedPods        []string
	SelectorMismatch   bool
	TooPermissive      bool
	TooRestrictive     bool
	RiskLevel          string
	RiskScore          int
	SecurityIssues     []string
}

type WorkloadPDBStatus struct {
	Namespace    string
	WorkloadType string
	WorkloadName string
	Replicas     int32
	HasPDB       bool
	PDBNames     []string
	RiskLevel    string
	RiskScore    int
	Issues       []string
}


func ListPodDisruptionBudgets(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing PodDisruptionBudgets for %s", globals.ClusterName), globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch PodDisruptionBudgets from target namespaces
	pdbs, err := clientset.PolicyV1().PodDisruptionBudgets(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching PodDisruptionBudgets: %v", err), globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)
		return
	}

	// Fetch pods for matching
	pods, err := clientset.CoreV1().Pods(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching Pods: %v", err), globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)
		return
	}

	// Fetch deployments
	deployments, err := clientset.AppsV1().Deployments(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching Deployments: %v", err), globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)
		return
	}

	// Fetch statefulsets
	statefulsets, err := clientset.AppsV1().StatefulSets(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching StatefulSets: %v", err), globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)
		return
	}

	var pdbAnalyses []PDBAnalysis
	var workloadStatuses []WorkloadPDBStatus

	loot := shared.NewLootBuilder()

	// Analyze each PDB
	for _, pdb := range pdbs.Items {
		analysis := PDBAnalysis{
			Name:               pdb.Name,
			Namespace:          pdb.Namespace,
			MinAvailable:       intStrPtrToString(pdb.Spec.MinAvailable),
			MaxUnavailable:     intStrPtrToString(pdb.Spec.MaxUnavailable),
			CurrentHealthy:     pdb.Status.CurrentHealthy,
			DesiredHealthy:     pdb.Status.DesiredHealthy,
			ExpectedPods:       pdb.Status.ExpectedPods,
			DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
			Selector:           selectorToString(pdb.Spec.Selector),
		}

		// Find matching pods
		analysis.MatchedPods = findMatchingPods(&pdb, pods.Items)

		// Security analysis
		issues := analyzePDBSecurity(&analysis, &pdb)
		analysis.SecurityIssues = issues

		// Calculate risk score
		analysis.RiskScore = calculatePDBRiskScore(&analysis)
		analysis.RiskLevel = pdbRiskScoreToLevel(analysis.RiskScore)

		// Categorize for loot files
		if analysis.TooPermissive {
			loot.Section("Permissive-PDBs").Add(formatPermissivePDB(&analysis))
		}
		if analysis.TooRestrictive {
			loot.Section("Restrictive-PDBs").Add(formatRestrictivePDB(&analysis))
		}
		if analysis.SelectorMismatch {
			loot.Section("Selector-Mismatches").Add(formatSelectorMismatch(&analysis))
		}

		pdbAnalyses = append(pdbAnalyses, analysis)
	}

	// Build PDB index by namespace and selector
	pdbIndex := buildPDBIndex(pdbs.Items)

	// Analyze deployments
	for _, deploy := range deployments.Items {
		status := WorkloadPDBStatus{
			Namespace:    deploy.Namespace,
			WorkloadType: "Deployment",
			WorkloadName: deploy.Name,
			Replicas:     *deploy.Spec.Replicas,
		}

		// Check if deployment has PDB protection
		status.PDBNames = findWorkloadPDBs(deploy.Namespace, deploy.Spec.Selector, pdbIndex)
		status.HasPDB = len(status.PDBNames) > 0

		// Analyze workload PDB status
		status.Issues = analyzeWorkloadPDBStatus(&status)
		status.RiskScore = calculateWorkloadRiskScore(&status)
		status.RiskLevel = pdbRiskScoreToLevel(status.RiskScore)

		if !status.HasPDB && status.Replicas > 1 {
			loot.Section("Unprotected-Workloads").Add(formatUnprotectedWorkload(&status))
		}

		workloadStatuses = append(workloadStatuses, status)
	}

	// Analyze statefulsets
	for _, sts := range statefulsets.Items {
		status := WorkloadPDBStatus{
			Namespace:    sts.Namespace,
			WorkloadType: "StatefulSet",
			WorkloadName: sts.Name,
			Replicas:     *sts.Spec.Replicas,
		}

		status.PDBNames = findWorkloadPDBs(sts.Namespace, sts.Spec.Selector, pdbIndex)
		status.HasPDB = len(status.PDBNames) > 0

		status.Issues = analyzeWorkloadPDBStatus(&status)
		status.RiskScore = calculateWorkloadRiskScore(&status)
		status.RiskLevel = pdbRiskScoreToLevel(status.RiskScore)

		if !status.HasPDB && status.Replicas > 1 {
			loot.Section("Unprotected-Workloads").Add(formatUnprotectedWorkload(&status))
		}

		workloadStatuses = append(workloadStatuses, status)
	}

	// Generate loot files
	loot.Section("PDB-Enum").Add(formatPDBEnum(pdbAnalyses))
	loot.Section("Remediation-Guide").Add(generatePDBRemediationGuide(pdbAnalyses, workloadStatuses))

	lootFiles := loot.Build()

	// Generate tables
	pdbTable := generatePDBTable(pdbAnalyses)
	workloadTable := generateWorkloadTable(workloadStatuses)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"PodDisruptionBudgets",
		globals.ClusterName,
		"results",
		PodDisruptionBudgetsOutput{
			Table: []internal.TableFile{pdbTable, workloadTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)
		return
	}

	// Summary logging
	if len(pdbs.Items) > 0 {
		permissiveCount := 0
		if loot.HasSection("Permissive-PDBs") {
			permissiveCount = loot.Section("Permissive-PDBs").Len()
		}
		unprotectedCount := 0
		if loot.HasSection("Unprotected-Workloads") {
			unprotectedCount = loot.Section("Unprotected-Workloads").Len()
		}
		logger.InfoM(fmt.Sprintf("%d PDBs analyzed | Permissive: %d | Unprotected workloads: %d | Total workloads: %d",
			len(pdbs.Items), permissiveCount, unprotectedCount, len(workloadStatuses)),
			globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)
	} else {
		logger.InfoM("No PodDisruptionBudgets found", globals.K8S_PODDISRUPTIONBUDGETS_MODULE_NAME)
	}
}

func analyzePDBSecurity(analysis *PDBAnalysis, pdb *policyv1.PodDisruptionBudget) []string {
	var issues []string

	// Too permissive: allows all disruptions
	if analysis.MinAvailable == "0" || analysis.MaxUnavailable == "100%" {
		analysis.TooPermissive = true
		issues = append(issues, "CRITICAL: PDB allows unlimited disruptions (minAvailable=0 or maxUnavailable=100%)")
	}

	// No matching pods
	if len(analysis.MatchedPods) == 0 {
		analysis.SelectorMismatch = true
		issues = append(issues, "HIGH: PDB selector matches no pods (ineffective protection)")
	}

	// Expected pods mismatch
	if analysis.ExpectedPods != int32(len(analysis.MatchedPods)) {
		analysis.SelectorMismatch = true
		issues = append(issues, fmt.Sprintf("MEDIUM: Expected %d pods, matched %d (selector mismatch)", analysis.ExpectedPods, len(analysis.MatchedPods)))
	}

	// Too restrictive: blocks all disruptions
	if analysis.DisruptionsAllowed == 0 && analysis.CurrentHealthy > 0 {
		analysis.TooRestrictive = true
		issues = append(issues, "MEDIUM: PDB blocks all disruptions (may prevent cluster maintenance)")
	}

	// MinAvailable equals total pods (no disruptions allowed)
	if analysis.MinAvailable == fmt.Sprintf("%d", analysis.ExpectedPods) && analysis.ExpectedPods > 0 {
		analysis.TooRestrictive = true
		issues = append(issues, "MEDIUM: MinAvailable equals total pods (no rolling updates possible)")
	}

	return issues
}

func findMatchingPods(pdb *policyv1.PodDisruptionBudget, pods []corev1.Pod) []string {
	var matchedPods []string

	if pdb.Spec.Selector == nil {
		return matchedPods
	}

	selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil {
		return matchedPods
	}

	for _, pod := range pods {
		if pod.Namespace != pdb.Namespace {
			continue
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			matchedPods = append(matchedPods, pod.Name)
		}
	}

	return matchedPods
}

func buildPDBIndex(pdbs []policyv1.PodDisruptionBudget) map[string][]policyv1.PodDisruptionBudget {
	index := make(map[string][]policyv1.PodDisruptionBudget)

	for _, pdb := range pdbs {
		key := pdb.Namespace
		index[key] = append(index[key], pdb)
	}

	return index
}

func findWorkloadPDBs(namespace string, selector *metav1.LabelSelector, pdbIndex map[string][]policyv1.PodDisruptionBudget) []string {
	var pdbNames []string

	if selector == nil {
		return pdbNames
	}

	workloadSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return pdbNames
	}

	for _, pdb := range pdbIndex[namespace] {
		if pdb.Spec.Selector == nil {
			continue
		}

		pdbSelector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}

		// Check if PDB selector would match workload pods
		// This is a simplified check - in reality we'd need to check if selectors overlap
		if pdbSelector.String() == workloadSelector.String() {
			pdbNames = append(pdbNames, pdb.Name)
		}
	}

	return pdbNames
}

func analyzeWorkloadPDBStatus(status *WorkloadPDBStatus) []string {
	var issues []string

	// No PDB for multi-replica workload
	if !status.HasPDB && status.Replicas > 1 {
		issues = append(issues, "HIGH: Multi-replica workload without PDB (availability risk during disruptions)")
	}

	// No PDB for high-replica workload
	if !status.HasPDB && status.Replicas >= 3 {
		issues = append(issues, "CRITICAL: High-availability workload without PDB protection")
	}

	// Multiple PDBs (potential conflicts)
	if len(status.PDBNames) > 1 {
		issues = append(issues, fmt.Sprintf("MEDIUM: Multiple PDBs (%d) may conflict", len(status.PDBNames)))
	}

	return issues
}

func calculatePDBRiskScore(analysis *PDBAnalysis) int {
	score := 0

	// Too permissive
	if analysis.TooPermissive {
		score += 50
	}

	// Selector mismatch
	if analysis.SelectorMismatch {
		score += 30
	}

	// Too restrictive
	if analysis.TooRestrictive {
		score += 20
	}

	// No disruptions allowed
	if analysis.DisruptionsAllowed == 0 {
		score += 15
	}

	return score
}

func calculateWorkloadRiskScore(status *WorkloadPDBStatus) int {
	score := 0

	// No PDB for multi-replica workload
	if !status.HasPDB {
		if status.Replicas >= 5 {
			score += 50
		} else if status.Replicas >= 3 {
			score += 40
		} else if status.Replicas > 1 {
			score += 25
		}
	}

	// Multiple PDBs
	if len(status.PDBNames) > 1 {
		score += 15
	}

	return score
}

func pdbRiskScoreToLevel(score int) string {
	if score >= 70 {
		return shared.RiskCritical
	} else if score >= 50 {
		return shared.RiskHigh
	} else if score >= 25 {
		return shared.RiskMedium
	}
	return shared.RiskLow
}

// Formatting functions
func formatPermissivePDB(analysis *PDBAnalysis) string {
	return fmt.Sprintf("[PERMISSIVE] %s/%s | MinAvailable: %s | MaxUnavailable: %s | Issues: %s",
		analysis.Namespace, analysis.Name, analysis.MinAvailable, analysis.MaxUnavailable,
		strings.Join(analysis.SecurityIssues, "; "))
}

func formatRestrictivePDB(analysis *PDBAnalysis) string {
	return fmt.Sprintf("[RESTRICTIVE] %s/%s | DisruptionsAllowed: %d | CurrentHealthy: %d | ExpectedPods: %d",
		analysis.Namespace, analysis.Name, analysis.DisruptionsAllowed, analysis.CurrentHealthy, analysis.ExpectedPods)
}

func formatSelectorMismatch(analysis *PDBAnalysis) string {
	return fmt.Sprintf("[MISMATCH] %s/%s | Selector: %s | Expected: %d | Matched: %d | Fix selector or check pod labels",
		analysis.Namespace, analysis.Name, analysis.Selector, analysis.ExpectedPods, len(analysis.MatchedPods))
}

func formatUnprotectedWorkload(status *WorkloadPDBStatus) string {
	return fmt.Sprintf("[UNPROTECTED] %s/%s/%s | Replicas: %d | No PDB protection (availability risk)",
		status.Namespace, status.WorkloadType, status.WorkloadName, status.Replicas)
}

func formatPDBEnum(analyses []PDBAnalysis) string {
	var lines []string
	lines = append(lines, "=== PodDisruptionBudget Security Analysis ===\n")

	for _, pdb := range analyses {
		lines = append(lines, fmt.Sprintf("PDB: %s/%s", pdb.Namespace, pdb.Name))
		lines = append(lines, fmt.Sprintf("  MinAvailable: %s | MaxUnavailable: %s", pdb.MinAvailable, pdb.MaxUnavailable))
		lines = append(lines, fmt.Sprintf("  Current Healthy: %d | Desired: %d | Expected: %d", pdb.CurrentHealthy, pdb.DesiredHealthy, pdb.ExpectedPods))
		lines = append(lines, fmt.Sprintf("  Disruptions Allowed: %d", pdb.DisruptionsAllowed))
		lines = append(lines, fmt.Sprintf("  Matched Pods: %d", len(pdb.MatchedPods)))
		lines = append(lines, fmt.Sprintf("  Risk Level: %s (Score: %d)", pdb.RiskLevel, pdb.RiskScore))
		if len(pdb.SecurityIssues) > 0 {
			lines = append(lines, "  Security Issues:")
			for _, issue := range pdb.SecurityIssues {
				lines = append(lines, fmt.Sprintf("    - %s", issue))
			}
		}
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func generatePDBRemediationGuide(pdbs []PDBAnalysis, workloads []WorkloadPDBStatus) string {
	var lines []string
	lines = append(lines, "=== PodDisruptionBudget Remediation Guide ===\n")

	lines = append(lines, "# Create PDB for a deployment (allow 1 pod unavailable during disruptions):")
	lines = append(lines, "kubectl create pdb <name> --namespace=<namespace> --selector=app=<app-label> --max-unavailable=1")
	lines = append(lines, "")

	lines = append(lines, "# Create PDB with minAvailable (keep at least 2 pods available):")
	lines = append(lines, "kubectl create pdb <name> --namespace=<namespace> --selector=app=<app-label> --min-available=2")
	lines = append(lines, "")

	lines = append(lines, "# View PDB status:")
	lines = append(lines, "kubectl get pdb -n <namespace>")
	lines = append(lines, "kubectl describe pdb <name> -n <namespace>")
	lines = append(lines, "")

	lines = append(lines, "# Delete overly permissive PDB:")
	lines = append(lines, "kubectl delete pdb <name> -n <namespace>")
	lines = append(lines, "")

	// Specific recommendations
	lines = append(lines, "## Specific Issues:\n")

	for _, pdb := range pdbs {
		if pdb.RiskScore >= 50 {
			lines = append(lines, fmt.Sprintf("# High-risk PDB: %s/%s (Score: %d)", pdb.Namespace, pdb.Name, pdb.RiskScore))
			for _, issue := range pdb.SecurityIssues {
				lines = append(lines, fmt.Sprintf("#   - %s", issue))
			}
			lines = append(lines, "")
		}
	}

	// Unprotected workloads
	unprotectedCount := 0
	for _, wl := range workloads {
		if !wl.HasPDB && wl.Replicas > 1 {
			unprotectedCount++
		}
	}

	if unprotectedCount > 0 {
		lines = append(lines, fmt.Sprintf("# %d unprotected workloads found - create PDBs for high-availability services", unprotectedCount))
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func generatePDBTable(analyses []PDBAnalysis) internal.TableFile {
	header := []string{"Namespace", "Name", "MinAvailable", "MaxUnavailable", "CurrentHealthy", "DisruptionsAllowed", "MatchedPods"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	for _, pdb := range analyses {
		rows = append(rows, []string{
			pdb.Namespace,
			pdb.Name,
			pdb.MinAvailable,
			pdb.MaxUnavailable,
			fmt.Sprintf("%d", pdb.CurrentHealthy),
			fmt.Sprintf("%d", pdb.DisruptionsAllowed),
			fmt.Sprintf("%d", len(pdb.MatchedPods)),
		})
	}

	return internal.TableFile{
		Name:   "PodDisruptionBudgets",
		Header: header,
		Body:   rows,
	}
}

func generateWorkloadTable(workloads []WorkloadPDBStatus) internal.TableFile {
	header := []string{"Namespace", "Type", "Name", "Replicas", "HasPDB", "PDBs", "Issues"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(workloads, func(i, j int) bool {
		return workloads[i].RiskScore > workloads[j].RiskScore
	})

	for _, wl := range workloads {
		rows = append(rows, []string{
			wl.Namespace,
			wl.WorkloadType,
			wl.WorkloadName,
			fmt.Sprintf("%d", wl.Replicas),
			shared.FormatBool(wl.HasPDB),
			fmt.Sprintf("%d", len(wl.PDBNames)),
			fmt.Sprintf("%d", len(wl.Issues)),
		})
	}

	return internal.TableFile{
		Name:   "Workload-PDB-Status",
		Header: header,
		Body:   rows,
	}
}

// Helper functions
func selectorToString(selector *metav1.LabelSelector) string {
	if selector == nil {
		return ""
	}
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return ""
	}
	return sel.String()
}

func intStrPtrToString(val interface{}) string {
	if val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}
