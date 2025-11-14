package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var PodSecurityCmd = &cobra.Command{
	Use:     "pod-security",
	Aliases: []string{"psa"},
	Short:   "Analyze Pod Security Policies, Standards, and admission controls with security assessment",
	Long: `
Analyze all cluster Pod Security configurations including:
  - Pod Security Standards (PSS) - enforce/warn/audit levels
  - Pod Security Policies (PSP) - deprecated but still in use
  - Admission webhooks (mutating/validating)
  - Policy engines (Gatekeeper, Kyverno)
  - Policy gaps, bypasses, and conflicts
  - Security risk assessment

  cloudfox kubernetes pod-security`,
	Run: ListPodSecurity,
}

type PodSecurityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PodSecurityOutput) TableFiles() []internal.TableFile { return t.Table }
func (t PodSecurityOutput) LootFiles() []internal.LootFile   { return t.Loot }

// PolicyFinding represents comprehensive policy security analysis for a namespace
type PolicyFinding struct {
	// Basic Info
	Namespace string
	Age       string

	// Security Analysis
	RiskLevel      string
	SecurityIssues []string

	// Pod Security Standards (PSS)
	PSSEnabled        bool
	PSSEnforceLevel   string
	PSSEnforceVersion string
	PSSWarnLevel      string
	PSSWarnVersion    string
	PSSAuditLevel     string
	PSSAuditVersion   string
	PSSExemptions     []string

	// Pod Security Policy (PSP - deprecated)
	PSPEnabled           bool
	PSPCount             int
	PSPNames             []string
	ClusterHasPSP        bool
	PSPDeprecationRisk   string
	PSPAllowsPrivileged  bool
	PSPAllowsHostNetwork bool
	PSPAllowsHostPID     bool
	PSPAllowsHostIPC     bool
	PSPAllowsHostPath    bool
	PSPDangerousCaps     []string
	PSPAllowsRunAsRoot   bool

	// Admission Control Webhooks
	MutatingWebhooks   []WebhookInfo
	ValidatingWebhooks []WebhookInfo
	WebhookCount       int
	WebhookBypassRisk  string

	// Dynamic Policy Engines
	GatekeeperPolicies []string
	KyvernoPolicies    []string
	PolicyEngineCount  int

	// Policy Gaps
	NoEnforcement       bool
	WeakEnforcement     bool
	PolicyGaps          []string
	EnforcementCoverage string

	// Policy Conflicts
	HasConflicts    bool
	ConflictDetails []string
	ConflictRisk    string

	// Policy Bypass Techniques
	BypassTechniques []string
	BypassRisk       string

	// Attack Vectors
	AllowsPrivilegeEscalation bool
	EscalationPaths           []string

	// Recommendations
	Recommendations []string
}

// WebhookInfo represents webhook configuration details
type WebhookInfo struct {
	Name              string
	Type              string // mutating or validating
	FailurePolicy     string
	MatchPolicy       string
	SideEffects       string
	TimeoutSeconds    int32
	NamespaceSelector string
	HasExclusions     bool
	BypassRisk        string
	SecurityIssues    []string
}

// PSPAnalysis represents Pod Security Policy analysis
type PSPAnalysis struct {
	Name                string
	RiskLevel           string
	AllowsPrivileged    bool
	AllowsHostNetwork   bool
	AllowsHostPID       bool
	AllowsHostIPC       bool
	AllowsHostPath      bool
	AllowedHostPaths    []string
	AllowedCapabilities []string
	AllowsRunAsRoot     bool
	RunAsUserRule       string
	SELinuxRule         string
	FSGroupRule         string
	SecurityIssues      []string
	DeprecationWarning  string
}

// PSSAnalysis represents Pod Security Standards analysis
type PSSAnalysis struct {
	EnforceLevel    string
	EnforceVersion  string
	WarnLevel       string
	WarnVersion     string
	AuditLevel      string
	AuditVersion    string
	IsExempt        bool
	ExemptReason    string
	NoEnforcement   bool
	WeakEnforcement bool
	RiskLevel       string
	SecurityIssues  []string
}

// PolicyEscalationPath represents privilege escalation via policy misconfiguration
type PolicyEscalationPath struct {
	Type      string
	Policy    string
	Steps     []string
	EndResult string
	RiskLevel string
}

func ListPodSecurity(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Analyzing pod security policies for %s", globals.ClusterName), globals.K8S_POD_SECURITY_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Detect cluster-wide PSP
	clusterHasPSP := false
	pspAnalyses := analyzePSPs(ctx, dynClient)
	if len(pspAnalyses) > 0 {
		clusterHasPSP = true
	}

	// Get namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_POD_SECURITY_MODULE_NAME)
		return
	}

	// Analyze webhooks
	mutatingWebhooks := analyzeWebhooks(ctx, dynClient, "mutatingwebhookconfigurations")
	validatingWebhooks := analyzeWebhooks(ctx, dynClient, "validatingwebhookconfigurations")

	// Analyze dynamic policies
	gatekeeperPolicies := analyzeDynamicPolicies(ctx, dynClient, "gatekeeper")
	kyvernoPolicies := analyzeDynamicPolicies(ctx, dynClient, "kyverno")

	// Process each namespace
	var findings []PolicyFinding

	for _, ns := range namespaces.Items {
		finding := PolicyFinding{
			Namespace:     ns.Name,
			ClusterHasPSP: clusterHasPSP,
		}

		// Calculate age
		age := time.Since(ns.CreationTimestamp.Time)
		finding.Age = formatDuration(age)

		// PSS Analysis
		pssAnalysis := analyzePodSecurityStandards(ns)
		finding.PSSEnabled = !pssAnalysis.NoEnforcement
		finding.PSSEnforceLevel = pssAnalysis.EnforceLevel
		finding.PSSEnforceVersion = pssAnalysis.EnforceVersion
		finding.PSSWarnLevel = pssAnalysis.WarnLevel
		finding.PSSWarnVersion = pssAnalysis.WarnVersion
		finding.PSSAuditLevel = pssAnalysis.AuditLevel
		finding.PSSAuditVersion = pssAnalysis.AuditVersion
		finding.NoEnforcement = pssAnalysis.NoEnforcement
		finding.WeakEnforcement = pssAnalysis.WeakEnforcement
		finding.SecurityIssues = append(finding.SecurityIssues, pssAnalysis.SecurityIssues...)

		// PSP Analysis
		if clusterHasPSP {
			finding.PSPEnabled = true
			finding.PSPCount = len(pspAnalyses)
			for _, psp := range pspAnalyses {
				finding.PSPNames = append(finding.PSPNames, psp.Name)
				if psp.AllowsPrivileged {
					finding.PSPAllowsPrivileged = true
				}
				if psp.AllowsHostNetwork {
					finding.PSPAllowsHostNetwork = true
				}
				if psp.AllowsHostPID {
					finding.PSPAllowsHostPID = true
				}
				if psp.AllowsHostIPC {
					finding.PSPAllowsHostIPC = true
				}
				if psp.AllowsHostPath {
					finding.PSPAllowsHostPath = true
				}
				finding.PSPDangerousCaps = append(finding.PSPDangerousCaps, psp.AllowedCapabilities...)
				if psp.AllowsRunAsRoot {
					finding.PSPAllowsRunAsRoot = true
				}
			}
			finding.PSPDeprecationRisk = "HIGH"
			finding.SecurityIssues = append(finding.SecurityIssues,
				"PSP is deprecated since Kubernetes 1.21 and removed in 1.25 - migrate to PSS")
		}

		// Webhook Analysis
		finding.MutatingWebhooks = filterWebhooksForNamespace(mutatingWebhooks, ns.Name, ns.Labels)
		finding.ValidatingWebhooks = filterWebhooksForNamespace(validatingWebhooks, ns.Name, ns.Labels)
		finding.WebhookCount = len(finding.MutatingWebhooks) + len(finding.ValidatingWebhooks)

		for _, wh := range finding.MutatingWebhooks {
			finding.SecurityIssues = append(finding.SecurityIssues, wh.SecurityIssues...)
			if wh.BypassRisk == "HIGH" {
				finding.WebhookBypassRisk = "HIGH"
			}
		}
		for _, wh := range finding.ValidatingWebhooks {
			finding.SecurityIssues = append(finding.SecurityIssues, wh.SecurityIssues...)
			if wh.BypassRisk == "HIGH" {
				finding.WebhookBypassRisk = "HIGH"
			}
		}

		// Dynamic Policy Analysis
		finding.GatekeeperPolicies = gatekeeperPolicies[ns.Name]
		finding.KyvernoPolicies = kyvernoPolicies[ns.Name]
		finding.PolicyEngineCount = len(finding.GatekeeperPolicies) + len(finding.KyvernoPolicies)

		// Policy Gap Detection
		finding.PolicyGaps = detectPolicyGaps(finding)
		if finding.NoEnforcement {
			finding.EnforcementCoverage = "None"
		} else if finding.WeakEnforcement {
			finding.EnforcementCoverage = "Weak"
		} else {
			finding.EnforcementCoverage = "Strong"
		}

		// Policy Conflict Detection
		finding.ConflictDetails = detectPolicyConflicts(finding)
		finding.HasConflicts = len(finding.ConflictDetails) > 0
		if finding.HasConflicts {
			finding.ConflictRisk = "MEDIUM"
		}

		// Policy Bypass Detection
		finding.BypassTechniques = detectPolicyBypass(finding)
		if len(finding.BypassTechniques) > 0 {
			finding.BypassRisk = "HIGH"
		}

		// Escalation Path Detection
		finding.EscalationPaths = detectPolicyEscalationPaths(finding, pspAnalyses)
		finding.AllowsPrivilegeEscalation = len(finding.EscalationPaths) > 0

		// Risk Scoring
		finding.RiskLevel, _ = calculatePolicyRiskScore(finding)

		// Recommendations
		finding.Recommendations = generatePolicyRecommendations(finding)

		findings = append(findings, finding)
	}

	// Generate output
	headers := []string{
		"Risk Level",
		"Namespace",
		"PSS Enforce",
		"PSS Warn/Audit",
		"PSP Status",
		"Webhooks",
		"Policy Engines",
		"No Enforcement",
		"Weak Enforcement",
		"Policy Gaps",
		"Conflicts",
		"Bypass Techniques",
		"Escalation Paths",
		"Security Issues",
		"Coverage",
		"Age",
		"Recommendations",
	}

	var outputRows [][]string
	var lootEnum []string
	var lootNoEnforcement []string
	var lootWeakPolicies []string
	var lootPSP []string
	var lootPSS []string
	var lootWebhooks []string
	var lootBypasses []string
	var lootEscalation []string
	var lootConflicts []string
	var lootGaps []string
	var lootAttackPaths []string
	var lootRemediation []string

	// Initialize loot headers
	lootEnum = append(lootEnum,
		"#####################################",
		"##### Pod Security Policy Enumeration",
		"#####################################",
		"#",
		"# Enumerate all pod security configurations",
		"#",
	)

	lootNoEnforcement = append(lootNoEnforcement,
		"#####################################",
		"##### Namespaces with No Enforcement",
		"#####################################",
		"#",
		"# CRITICAL: These namespaces accept any pod configuration",
		"# Deploy privileged pods for container escape",
		"#",
	)

	lootWeakPolicies = append(lootWeakPolicies,
		"#####################################",
		"##### Weak Policy Configurations",
		"#####################################",
		"#",
		"# PSS 'privileged' level or permissive PSP configurations",
		"# Allows dangerous pod configurations",
		"#",
	)

	lootPSP = append(lootPSP,
		"#####################################",
		"##### Pod Security Policy Analysis",
		"#####################################",
		"#",
		"# PSP is DEPRECATED (removed in Kubernetes 1.25)",
		"# Analyze existing PSPs for security issues",
		"#",
	)

	lootPSS = append(lootPSS,
		"#####################################",
		"##### Pod Security Standards Analysis",
		"#####################################",
		"#",
		"# PSS enforce/warn/audit level analysis",
		"#",
	)

	lootWebhooks = append(lootWebhooks,
		"#####################################",
		"##### Admission Webhook Analysis",
		"#####################################",
		"#",
		"# Webhook security configuration and bypass risks",
		"#",
	)

	lootBypasses = append(lootBypasses,
		"#####################################",
		"##### Policy Bypass Techniques",
		"#####################################",
		"#",
		"# Methods to bypass pod security controls",
		"#",
	)

	lootEscalation = append(lootEscalation,
		"#####################################",
		"##### Privilege Escalation via Policy",
		"#####################################",
		"#",
		"# Policy misconfigurations leading to privilege escalation",
		"#",
	)

	lootConflicts = append(lootConflicts,
		"#####################################",
		"##### Policy Conflicts",
		"#####################################",
		"#",
		"# Conflicting or overlapping policy configurations",
		"#",
	)

	lootGaps = append(lootGaps,
		"#####################################",
		"##### Policy Coverage Gaps",
		"#####################################",
		"#",
		"# Missing or incomplete policy enforcement",
		"#",
	)

	lootAttackPaths = append(lootAttackPaths,
		"#####################################",
		"##### Complete Attack Paths",
		"#####################################",
		"#",
		"# End-to-end attack chains via policy misconfiguration",
		"#",
	)

	lootRemediation = append(lootRemediation,
		"#####################################",
		"##### Remediation Recommendations",
		"#####################################",
		"#",
		"# Security hardening recommendations",
		"#",
	)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, finding := range findings {
		// Generate table row
		pssEnforce := finding.PSSEnforceLevel
		if pssEnforce == "" {
			pssEnforce = "<NONE>"
		}

		pssOther := ""
		if finding.PSSWarnLevel != "" || finding.PSSAuditLevel != "" {
			modes := []string{}
			if finding.PSSWarnLevel != "" {
				modes = append(modes, "warn:"+finding.PSSWarnLevel)
			}
			if finding.PSSAuditLevel != "" {
				modes = append(modes, "audit:"+finding.PSSAuditLevel)
			}
			pssOther = strings.Join(modes, ",")
		} else {
			pssOther = "<NONE>"
		}

		pspStatus := "Disabled"
		if finding.ClusterHasPSP {
			pspStatus = fmt.Sprintf("%d PSPs", finding.PSPCount)
		}

		outputRows = append(outputRows, []string{
			finding.RiskLevel,
			finding.Namespace,
			pssEnforce,
			pssOther,
			pspStatus,
			fmt.Sprintf("%d", finding.WebhookCount),
			fmt.Sprintf("%d", finding.PolicyEngineCount),
			fmt.Sprintf("%t", finding.NoEnforcement),
			fmt.Sprintf("%t", finding.WeakEnforcement),
			fmt.Sprintf("%d", len(finding.PolicyGaps)),
			fmt.Sprintf("%d", len(finding.ConflictDetails)),
			fmt.Sprintf("%d", len(finding.BypassTechniques)),
			fmt.Sprintf("%d", len(finding.EscalationPaths)),
			fmt.Sprintf("%d", len(finding.SecurityIssues)),
			finding.EnforcementCoverage,
			finding.Age,
			fmt.Sprintf("%d", len(finding.Recommendations)),
		})

		// Generate loot content
		generatePolicyLoot(&finding, &lootEnum, &lootNoEnforcement, &lootWeakPolicies,
			&lootPSS, &lootBypasses, &lootEscalation, &lootConflicts, &lootGaps,
			&lootAttackPaths, &lootRemediation)
	}

	// PSP-specific loot
	for _, psp := range pspAnalyses {
		lootPSP = append(lootPSP, fmt.Sprintf("\n# PSP: %s (Risk: %s)", psp.Name, psp.RiskLevel))
		lootPSP = append(lootPSP, fmt.Sprintf("kubectl get psp %s -o yaml", psp.Name))
		lootPSP = append(lootPSP, "")
		lootPSP = append(lootPSP, "# Security Configuration:")
		lootPSP = append(lootPSP, fmt.Sprintf("#   Privileged: %t", psp.AllowsPrivileged))
		lootPSP = append(lootPSP, fmt.Sprintf("#   HostNetwork: %t", psp.AllowsHostNetwork))
		lootPSP = append(lootPSP, fmt.Sprintf("#   HostPID: %t", psp.AllowsHostPID))
		lootPSP = append(lootPSP, fmt.Sprintf("#   HostIPC: %t", psp.AllowsHostIPC))
		lootPSP = append(lootPSP, fmt.Sprintf("#   HostPath: %t", psp.AllowsHostPath))
		if len(psp.AllowedCapabilities) > 0 {
			lootPSP = append(lootPSP, fmt.Sprintf("#   Dangerous Capabilities: %s", strings.Join(psp.AllowedCapabilities, ", ")))
		}
		lootPSP = append(lootPSP, "")
		lootPSP = append(lootPSP, "# Security Issues:")
		for _, issue := range psp.SecurityIssues {
			lootPSP = append(lootPSP, "#   - "+issue)
		}
		lootPSP = append(lootPSP, "")
		lootPSP = append(lootPSP, "# Check which service accounts can use this PSP:")
		lootPSP = append(lootPSP, fmt.Sprintf("kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name==\"%s\") | {name: .metadata.name, subjects: .subjects}'", psp.Name))
		lootPSP = append(lootPSP, "")
	}

	// Webhook-specific loot
	for _, wh := range mutatingWebhooks {
		lootWebhooks = append(lootWebhooks, fmt.Sprintf("\n# Mutating Webhook: %s", wh.Name))
		lootWebhooks = append(lootWebhooks, fmt.Sprintf("kubectl get mutatingwebhookconfiguration %s -o yaml", wh.Name))
		lootWebhooks = append(lootWebhooks, fmt.Sprintf("# Failure Policy: %s", wh.FailurePolicy))
		if wh.FailurePolicy == "Ignore" {
			lootWebhooks = append(lootWebhooks, "# BYPASS RISK: Webhook failures won't block pods")
		}
		lootWebhooks = append(lootWebhooks, "")
	}

	for _, wh := range validatingWebhooks {
		lootWebhooks = append(lootWebhooks, fmt.Sprintf("\n# Validating Webhook: %s", wh.Name))
		lootWebhooks = append(lootWebhooks, fmt.Sprintf("kubectl get validatingwebhookconfiguration %s -o yaml", wh.Name))
		lootWebhooks = append(lootWebhooks, fmt.Sprintf("# Failure Policy: %s", wh.FailurePolicy))
		if wh.FailurePolicy == "Ignore" {
			lootWebhooks = append(lootWebhooks, "# BYPASS RISK: Webhook failures won't block pods")
		}
		lootWebhooks = append(lootWebhooks, "")
	}

	// Sort by risk level
	sort.SliceStable(outputRows, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		return riskOrder[outputRows[i][0]] < riskOrder[outputRows[j][0]]
	})

	table := internal.TableFile{
		Name:   "Pod-Security",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{Name: "Pod-Security-Enum", Contents: strings.Join(lootEnum, "\n")},
		{Name: "Pod-Security-No-Enforcement", Contents: strings.Join(lootNoEnforcement, "\n")},
		{Name: "Pod-Security-Weak-Policies", Contents: strings.Join(lootWeakPolicies, "\n")},
		{Name: "Pod-Security-PSP-Analysis", Contents: strings.Join(lootPSP, "\n")},
		{Name: "Pod-Security-PSS-Analysis", Contents: strings.Join(lootPSS, "\n")},
		{Name: "Pod-Security-Webhooks", Contents: strings.Join(lootWebhooks, "\n")},
		{Name: "Pod-Security-Bypasses", Contents: strings.Join(lootBypasses, "\n")},
		{Name: "Pod-Security-Escalation", Contents: strings.Join(lootEscalation, "\n")},
		{Name: "Pod-Security-Conflicts", Contents: strings.Join(lootConflicts, "\n")},
		{Name: "Pod-Security-Gaps", Contents: strings.Join(lootGaps, "\n")},
		{Name: "Pod-Security-Attack-Paths", Contents: strings.Join(lootAttackPaths, "\n")},
		{Name: "Pod-Security-Remediation", Contents: strings.Join(lootRemediation, "\n")},
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Pod-Security",
		globals.ClusterName,
		"results",
		PodSecurityOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_POD_SECURITY_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		criticalCount := 0
		highCount := 0
		for _, row := range outputRows {
			if row[0] == "CRITICAL" {
				criticalCount++
			} else if row[0] == "HIGH" {
				highCount++
			}
		}
		logger.InfoM(fmt.Sprintf("%d namespaces analyzed (%d CRITICAL, %d HIGH risk)", len(outputRows), criticalCount, highCount), globals.K8S_POD_SECURITY_MODULE_NAME)
	} else {
		logger.InfoM("No pod security configurations found", globals.K8S_POD_SECURITY_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_POD_SECURITY_MODULE_NAME), globals.K8S_POD_SECURITY_MODULE_NAME)
}

// analyzePodSecurityStandards analyzes PSS labels and annotations
func analyzePodSecurityStandards(ns corev1.Namespace) PSSAnalysis {
	analysis := PSSAnalysis{}

	// Check enforce mode
	if enforce, exists := ns.Labels["pod-security.kubernetes.io/enforce"]; exists {
		analysis.EnforceLevel = enforce
		if version, exists := ns.Labels["pod-security.kubernetes.io/enforce-version"]; exists {
			analysis.EnforceVersion = version
		}
	}

	// Check warn mode
	if warn, exists := ns.Labels["pod-security.kubernetes.io/warn"]; exists {
		analysis.WarnLevel = warn
		if version, exists := ns.Labels["pod-security.kubernetes.io/warn-version"]; exists {
			analysis.WarnVersion = version
		}
	}

	// Check audit mode
	if audit, exists := ns.Labels["pod-security.kubernetes.io/audit"]; exists {
		analysis.AuditLevel = audit
		if version, exists := ns.Labels["pod-security.kubernetes.io/audit-version"]; exists {
			analysis.AuditVersion = version
		}
	}

	// Check for exemptions
	if exempt, exists := ns.Labels["pod-security.kubernetes.io/exempt"]; exists {
		analysis.IsExempt = true
		analysis.ExemptReason = exempt
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("Namespace is exempt from PSS: %s", exempt))
	}

	// Risk assessment
	if analysis.EnforceLevel == "" {
		analysis.NoEnforcement = true
		analysis.RiskLevel = "CRITICAL"
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"No PSS enforcement - accepts all pod configurations")
	} else {
		switch analysis.EnforceLevel {
		case "privileged":
			analysis.WeakEnforcement = true
			analysis.RiskLevel = "CRITICAL"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"PSS enforce level 'privileged' - no restrictions (equivalent to no enforcement)")
		case "baseline":
			analysis.RiskLevel = "MEDIUM"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"PSS baseline allows some risky configurations (hostNetwork with restrictions, unsafe sysctls)")
		case "restricted":
			analysis.RiskLevel = "LOW"
		default:
			analysis.RiskLevel = "MEDIUM"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				fmt.Sprintf("Unknown PSS level: %s", analysis.EnforceLevel))
		}
	}

	// Check for warn/audit only (no enforcement)
	if analysis.EnforceLevel == "" && (analysis.WarnLevel != "" || analysis.AuditLevel != "") {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"PSS warn/audit mode only - pods not blocked, only logged")
	}

	return analysis
}

// analyzePSPs analyzes Pod Security Policies
func analyzePSPs(ctx context.Context, dynClient dynamic.Interface) []PSPAnalysis {
	var analyses []PSPAnalysis

	pspGVR := schema.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"}
	pspList, err := dynClient.Resource(pspGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return analyses
	}

	for _, psp := range pspList.Items {
		analysis := PSPAnalysis{
			Name:               psp.GetName(),
			RiskLevel:          "LOW",
			DeprecationWarning: "PSP is deprecated since Kubernetes 1.21 and removed in 1.25",
		}

		spec, found, _ := unstructured.NestedMap(psp.Object, "spec")
		if !found {
			continue
		}

		// Check privileged
		if privileged, _, _ := unstructured.NestedBool(spec, "privileged"); privileged {
			analysis.AllowsPrivileged = true
			analysis.RiskLevel = "CRITICAL"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows privileged containers (full node compromise)")
		}

		// Check hostNetwork
		if hostNetwork, _, _ := unstructured.NestedBool(spec, "hostNetwork"); hostNetwork {
			analysis.AllowsHostNetwork = true
			if analysis.RiskLevel != "CRITICAL" {
				analysis.RiskLevel = "HIGH"
			}
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows host network access (network sniffing, service impersonation)")
		}

		// Check hostPID
		if hostPID, _, _ := unstructured.NestedBool(spec, "hostPID"); hostPID {
			analysis.AllowsHostPID = true
			if analysis.RiskLevel != "CRITICAL" {
				analysis.RiskLevel = "HIGH"
			}
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows host PID namespace (process inspection, signal injection)")
		}

		// Check hostIPC
		if hostIPC, _, _ := unstructured.NestedBool(spec, "hostIPC"); hostIPC {
			analysis.AllowsHostIPC = true
			if analysis.RiskLevel != "CRITICAL" {
				analysis.RiskLevel = "HIGH"
			}
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows host IPC namespace (shared memory access)")
		}

		// Check allowedCapabilities
		caps, _, _ := unstructured.NestedStringSlice(spec, "allowedCapabilities")
		dangerousCaps := map[string]string{
			"SYS_ADMIN":       "Full system administration",
			"NET_ADMIN":       "Network administration",
			"SYS_PTRACE":      "Process tracing",
			"SYS_MODULE":      "Load kernel modules",
			"DAC_READ_SEARCH": "Bypass file read permission checks",
			"DAC_OVERRIDE":    "Bypass file write permission checks",
		}

		for _, cap := range caps {
			if cap == "*" {
				analysis.AllowedCapabilities = append(analysis.AllowedCapabilities, "ALL")
				analysis.RiskLevel = "CRITICAL"
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					"Allows ALL capabilities (complete privilege escalation)")
				break
			}
			if desc, exists := dangerousCaps[cap]; exists {
				analysis.AllowedCapabilities = append(analysis.AllowedCapabilities, cap)
				analysis.RiskLevel = "CRITICAL"
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					fmt.Sprintf("Allows dangerous capability %s: %s", cap, desc))
			}
		}

		// Check allowedHostPaths
		hostPaths, found, _ := unstructured.NestedSlice(spec, "allowedHostPaths")
		if found && len(hostPaths) > 0 {
			analysis.AllowsHostPath = true
			for _, hp := range hostPaths {
				if hpMap, ok := hp.(map[string]interface{}); ok {
					if pathPrefix, ok := hpMap["pathPrefix"].(string); ok {
						analysis.AllowedHostPaths = append(analysis.AllowedHostPaths, pathPrefix)
						if pathPrefix == "/" || strings.HasPrefix(pathPrefix, "/var/lib/kubelet") {
							analysis.RiskLevel = "CRITICAL"
							analysis.SecurityIssues = append(analysis.SecurityIssues,
								fmt.Sprintf("Allows dangerous hostPath: %s", pathPrefix))
						}
					}
				}
			}
		}

		// Check runAsUser
		runAsUser, found, _ := unstructured.NestedMap(spec, "runAsUser")
		if found {
			if rule, ok := runAsUser["rule"].(string); ok {
				analysis.RunAsUserRule = rule
				if rule == "RunAsAny" {
					analysis.AllowsRunAsRoot = true
					if analysis.RiskLevel == "LOW" {
						analysis.RiskLevel = "MEDIUM"
					}
					analysis.SecurityIssues = append(analysis.SecurityIssues,
						"Allows running as any user including root")
				}
			}
		}

		analyses = append(analyses, analysis)
	}

	return analyses
}

// analyzeWebhooks analyzes admission webhooks
func analyzeWebhooks(ctx context.Context, dynClient dynamic.Interface, resourceType string) []WebhookInfo {
	var webhooks []WebhookInfo

	gvr := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: resourceType,
	}

	webhookList, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return webhooks
	}

	whType := "validating"
	if resourceType == "mutatingwebhookconfigurations" {
		whType = "mutating"
	}

	for _, wh := range webhookList.Items {
		whks, found := wh.Object["webhooks"].([]interface{})
		if !found {
			continue
		}

		for _, w := range whks {
			wMap := w.(map[string]interface{})

			// Check if targets pods
			rules, ok := wMap["rules"].([]interface{})
			if !ok {
				continue
			}

			targetsPods := false
			for _, r := range rules {
				rMap := r.(map[string]interface{})
				resources, _ := rMap["resources"].([]interface{})
				for _, res := range resources {
					if resStr, ok := res.(string); ok && resStr == "pods" {
						targetsPods = true
					}
				}
			}

			if !targetsPods {
				continue
			}

			info := WebhookInfo{
				Name: wh.GetName(),
				Type: whType,
			}

			// Check failure policy
			if failurePolicy, ok := wMap["failurePolicy"].(string); ok {
				info.FailurePolicy = failurePolicy
				if failurePolicy == "Ignore" {
					info.BypassRisk = "HIGH"
					info.SecurityIssues = append(info.SecurityIssues,
						"Failure policy 'Ignore' - webhook failures don't block pods")
				}
			}

			// Check side effects
			if sideEffects, ok := wMap["sideEffects"].(string); ok {
				info.SideEffects = sideEffects
			}

			// Check timeout
			if timeout, ok := wMap["timeoutSeconds"].(int64); ok {
				info.TimeoutSeconds = int32(timeout)
				if timeout > 10 {
					info.SecurityIssues = append(info.SecurityIssues,
						fmt.Sprintf("Long timeout (%ds) - performance impact", timeout))
				}
			}

			// Check namespace selector
			if nsSelector, ok := wMap["namespaceSelector"].(map[string]interface{}); ok {
				if len(nsSelector) > 0 {
					info.NamespaceSelector = "configured"
					info.HasExclusions = true
					info.SecurityIssues = append(info.SecurityIssues,
						"Namespace selector configured - some namespaces may be excluded")
				}
			}

			webhooks = append(webhooks, info)
		}
	}

	return webhooks
}

// filterWebhooksForNamespace determines which webhooks apply to a namespace
func filterWebhooksForNamespace(webhooks []WebhookInfo, nsName string, nsLabels map[string]string) []WebhookInfo {
	var applicable []WebhookInfo

	for _, wh := range webhooks {
		// If webhook has no namespace selector, it applies to all namespaces
		if wh.NamespaceSelector == "" {
			applicable = append(applicable, wh)
		}
		// TODO: Implement actual namespace selector matching logic
	}

	return applicable
}

// analyzeDynamicPolicies analyzes Gatekeeper/Kyverno policies
func analyzeDynamicPolicies(ctx context.Context, dynClient dynamic.Interface, policyType string) map[string][]string {
	policies := make(map[string][]string)

	crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	crdList, err := dynClient.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policies
	}

	for _, crd := range crdList.Items {
		crdName := crd.GetName()
		if !strings.Contains(strings.ToLower(crdName), policyType) {
			continue
		}

		// Simplified: mark as cluster-wide
		policies["<cluster-wide>"] = append(policies["<cluster-wide>"], crdName)
	}

	return policies
}

// detectPolicyGaps detects missing or incomplete policy enforcement
func detectPolicyGaps(finding PolicyFinding) []string {
	var gaps []string

	if finding.NoEnforcement {
		gaps = append(gaps, "No pod security enforcement configured")
	}

	if finding.WeakEnforcement {
		gaps = append(gaps, "Weak enforcement (privileged level allows all configurations)")
	}

	if !finding.PSSEnabled && !finding.PSPEnabled && finding.WebhookCount == 0 && finding.PolicyEngineCount == 0 {
		gaps = append(gaps, "No pod security controls of any kind")
	}

	if finding.PSSEnforceLevel == "" && finding.PSSWarnLevel == "" && finding.PSSAuditLevel == "" {
		gaps = append(gaps, "No PSS labels configured (enforce/warn/audit)")
	}

	if finding.PSSEnforceLevel == "" && finding.PSSWarnLevel != "" {
		gaps = append(gaps, "PSS warn mode only - pods not blocked")
	}

	return gaps
}

// detectPolicyConflicts detects conflicting policy configurations
func detectPolicyConflicts(finding PolicyFinding) []string {
	var conflicts []string

	// PSS + PSP conflict
	if finding.PSSEnabled && finding.PSPEnabled {
		conflicts = append(conflicts, "Both PSS and PSP enabled - PSP is deprecated, prefer PSS")
	}

	// Multiple policy engines
	if finding.PolicyEngineCount > 1 {
		conflicts = append(conflicts, fmt.Sprintf("Multiple policy engines (%d) - may have overlapping rules", finding.PolicyEngineCount))
	}

	// PSS privileged with webhooks
	if finding.PSSEnforceLevel == "privileged" && finding.WebhookCount > 0 {
		conflicts = append(conflicts, "PSS privileged level with webhooks - PSS allows all, webhooks may try to restrict")
	}

	return conflicts
}

// detectPolicyBypass detects policy bypass techniques
func detectPolicyBypass(finding PolicyFinding) []string {
	var bypasses []string

	if finding.NoEnforcement {
		bypasses = append(bypasses, "No enforcement - deploy any pod configuration")
	}

	if finding.PSSEnforceLevel == "privileged" {
		bypasses = append(bypasses, "PSS privileged level - effectively no restrictions")
	}

	if finding.WebhookBypassRisk == "HIGH" {
		bypasses = append(bypasses, "Webhook has 'Ignore' failure policy - trigger failure to bypass")
	}

	if finding.PSPEnabled {
		bypasses = append(bypasses, "PSP can be bypassed by using unbound service accounts")
	}

	return bypasses
}

// detectPolicyEscalationPaths detects privilege escalation via policy misconfig
func detectPolicyEscalationPaths(finding PolicyFinding, pspAnalyses []PSPAnalysis) []string {
	var paths []string

	if finding.NoEnforcement {
		paths = append(paths, "No enforcement → deploy privileged pod → container escape")
	}

	if finding.PSSEnforceLevel == "privileged" {
		paths = append(paths, "PSS privileged level → deploy pod with dangerous capabilities → escalate")
	}

	for _, psp := range pspAnalyses {
		if psp.AllowsPrivileged {
			paths = append(paths, fmt.Sprintf("PSP %s allows privileged → container escape", psp.Name))
		}
		if len(psp.AllowedCapabilities) > 0 {
			paths = append(paths, fmt.Sprintf("PSP %s allows dangerous capabilities → capability abuse", psp.Name))
		}
		if psp.AllowsHostPath {
			paths = append(paths, fmt.Sprintf("PSP %s allows hostPath → host filesystem access", psp.Name))
		}
	}

	return paths
}

// calculatePolicyRiskScore calculates policy configuration risk score
func calculatePolicyRiskScore(finding PolicyFinding) (string, int) {
	score := 0

	// No enforcement = CRITICAL
	if finding.NoEnforcement {
		return "CRITICAL", 100
	}

	// PSS privileged level = CRITICAL
	if finding.PSSEnforceLevel == "privileged" {
		return "CRITICAL", 95
	}

	// PSP allows privileged
	if finding.PSPAllowsPrivileged {
		score += 80
	}

	// PSP dangerous capabilities
	if len(finding.PSPDangerousCaps) > 0 {
		score += 60
	}

	// PSP allows hostPath
	if finding.PSPAllowsHostPath {
		score += 50
	}

	// Webhook bypass risk
	if finding.WebhookBypassRisk == "HIGH" {
		score += 40
	}

	// Weak enforcement (baseline)
	if finding.PSSEnforceLevel == "baseline" {
		score += 30
	}

	// Policy gaps
	score += len(finding.PolicyGaps) * 10

	// Policy conflicts
	score += len(finding.ConflictDetails) * 5

	// Bypass techniques
	score += len(finding.BypassTechniques) * 15

	// PSP deprecation risk
	if finding.PSPEnabled {
		score += 20
	}

	// Determine risk level
	if score >= 80 {
		return "CRITICAL", score
	} else if score >= 50 {
		return "HIGH", score
	} else if score >= 25 {
		return "MEDIUM", score
	}
	return "LOW", score
}

// generatePolicyRecommendations generates policy security recommendations
func generatePolicyRecommendations(finding PolicyFinding) []string {
	var recommendations []string

	if finding.NoEnforcement {
		recommendations = append(recommendations,
			"CRITICAL: Enable Pod Security Standards with 'restricted' level",
			"kubectl label namespace "+finding.Namespace+" pod-security.kubernetes.io/enforce=restricted")
	}

	if finding.PSSEnforceLevel == "privileged" {
		recommendations = append(recommendations,
			"Upgrade PSS enforce level from 'privileged' to 'baseline' or 'restricted'")
	}

	if finding.PSSEnforceLevel == "baseline" {
		recommendations = append(recommendations,
			"Consider upgrading PSS enforce level from 'baseline' to 'restricted' for stronger security")
	}

	if finding.PSPEnabled {
		recommendations = append(recommendations,
			"Migrate from deprecated PSP to Pod Security Standards",
			"PSP will be removed in Kubernetes 1.25")
	}

	if finding.WebhookBypassRisk == "HIGH" {
		recommendations = append(recommendations,
			"Change webhook failurePolicy from 'Ignore' to 'Fail'",
			"Ensure webhook has proper monitoring and alerting")
	}

	if len(finding.ConflictDetails) > 0 {
		recommendations = append(recommendations,
			"Resolve policy conflicts (PSS/PSP/webhooks)",
			"Use single consistent policy framework")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Policy configuration is secure")
	}

	return recommendations
}

// generatePolicyLoot generates loot content for all policy categories
func generatePolicyLoot(finding *PolicyFinding, lootEnum, lootNoEnforcement, lootWeakPolicies,
	lootPSS, lootBypasses, lootEscalation, lootConflicts, lootGaps, lootAttackPaths,
	lootRemediation *[]string) {

	// Enumeration
	*lootEnum = append(*lootEnum, fmt.Sprintf("\n# Namespace: %s (Risk: %s)", finding.Namespace, finding.RiskLevel))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get ns %s --show-labels", finding.Namespace))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get ns %s -o yaml", finding.Namespace))
	*lootEnum = append(*lootEnum, "")

	// No enforcement
	if finding.NoEnforcement {
		*lootNoEnforcement = append(*lootNoEnforcement, fmt.Sprintf("\n# Namespace: %s", finding.Namespace))
		*lootNoEnforcement = append(*lootNoEnforcement, "# CRITICAL: No pod security enforcement")
		*lootNoEnforcement = append(*lootNoEnforcement, "# Deploy privileged pod for container escape:")
		*lootNoEnforcement = append(*lootNoEnforcement, `cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-escape
  namespace: `+finding.Namespace+`
spec:
  containers:
  - name: escape
    image: alpine
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF`)
		*lootNoEnforcement = append(*lootNoEnforcement, fmt.Sprintf("kubectl exec -it privileged-escape -n %s -- sh", finding.Namespace))
		*lootNoEnforcement = append(*lootNoEnforcement, "# Inside container: access /host for full node filesystem")
		*lootNoEnforcement = append(*lootNoEnforcement, "")
	}

	// Weak policies
	if finding.WeakEnforcement {
		*lootWeakPolicies = append(*lootWeakPolicies, fmt.Sprintf("\n# Namespace: %s", finding.Namespace))
		*lootWeakPolicies = append(*lootWeakPolicies, fmt.Sprintf("# PSS enforce level: %s (WEAK)", finding.PSSEnforceLevel))
		*lootWeakPolicies = append(*lootWeakPolicies, "# Privileged level allows all dangerous configurations")
		*lootWeakPolicies = append(*lootWeakPolicies, "")
	}

	// PSS analysis
	if finding.PSSEnabled {
		*lootPSS = append(*lootPSS, fmt.Sprintf("\n# Namespace: %s", finding.Namespace))
		*lootPSS = append(*lootPSS, fmt.Sprintf("# Enforce: %s (version: %s)", finding.PSSEnforceLevel, finding.PSSEnforceVersion))
		if finding.PSSWarnLevel != "" {
			*lootPSS = append(*lootPSS, fmt.Sprintf("# Warn: %s (version: %s)", finding.PSSWarnLevel, finding.PSSWarnVersion))
		}
		if finding.PSSAuditLevel != "" {
			*lootPSS = append(*lootPSS, fmt.Sprintf("# Audit: %s (version: %s)", finding.PSSAuditLevel, finding.PSSAuditVersion))
		}
		*lootPSS = append(*lootPSS, "")
	}

	// Bypasses
	if len(finding.BypassTechniques) > 0 {
		*lootBypasses = append(*lootBypasses, fmt.Sprintf("\n# Namespace: %s", finding.Namespace))
		*lootBypasses = append(*lootBypasses, "# Bypass Techniques:")
		for _, bypass := range finding.BypassTechniques {
			*lootBypasses = append(*lootBypasses, "# - "+bypass)
		}
		*lootBypasses = append(*lootBypasses, "")
	}

	// Escalation paths
	if len(finding.EscalationPaths) > 0 {
		*lootEscalation = append(*lootEscalation, fmt.Sprintf("\n# Namespace: %s", finding.Namespace))
		*lootEscalation = append(*lootEscalation, "# Escalation Paths:")
		for _, path := range finding.EscalationPaths {
			*lootEscalation = append(*lootEscalation, "# - "+path)
		}
		*lootEscalation = append(*lootEscalation, "")
	}

	// Conflicts
	if len(finding.ConflictDetails) > 0 {
		*lootConflicts = append(*lootConflicts, fmt.Sprintf("\n# Namespace: %s", finding.Namespace))
		*lootConflicts = append(*lootConflicts, "# Policy Conflicts:")
		for _, conflict := range finding.ConflictDetails {
			*lootConflicts = append(*lootConflicts, "# - "+conflict)
		}
		*lootConflicts = append(*lootConflicts, "")
	}

	// Gaps
	if len(finding.PolicyGaps) > 0 {
		*lootGaps = append(*lootGaps, fmt.Sprintf("\n# Namespace: %s", finding.Namespace))
		*lootGaps = append(*lootGaps, "# Policy Gaps:")
		for _, gap := range finding.PolicyGaps {
			*lootGaps = append(*lootGaps, "# - "+gap)
		}
		*lootGaps = append(*lootGaps, "")
	}

	// Attack paths
	if len(finding.EscalationPaths) > 0 || len(finding.BypassTechniques) > 0 {
		*lootAttackPaths = append(*lootAttackPaths, fmt.Sprintf("\n# Namespace: %s - Risk: %s", finding.Namespace, finding.RiskLevel))
		*lootAttackPaths = append(*lootAttackPaths, "# Complete Attack Chain:")
		if finding.NoEnforcement {
			*lootAttackPaths = append(*lootAttackPaths,
				"1. No policy enforcement in namespace",
				"2. Deploy privileged pod with hostPath: /",
				"3. Exec into pod and access /host",
				"4. Read /host/etc/shadow, /host/root/.kube/config",
				"5. Access kubelet certs at /host/var/lib/kubelet/pki",
				"6. Authenticate to API server as node",
				"7. Escalate to cluster-admin",
			)
		}
		*lootAttackPaths = append(*lootAttackPaths, "")
	}

	// Remediation
	if len(finding.Recommendations) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n# Namespace: %s - Risk: %s", finding.Namespace, finding.RiskLevel))
		*lootRemediation = append(*lootRemediation, "# Recommendations:")
		for _, rec := range finding.Recommendations {
			*lootRemediation = append(*lootRemediation, "# "+rec)
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}

// formatDuration formats a duration into human-readable string
func formatDuration(d time.Duration) string {
	if d.Hours() > 24*365 {
		years := int(d.Hours() / 24 / 365)
		return fmt.Sprintf("%dy", years)
	}
	if d.Hours() > 24*30 {
		months := int(d.Hours() / 24 / 30)
		return fmt.Sprintf("%dmo", months)
	}
	if d.Hours() > 24 {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	}
	if d.Hours() > 1 {
		hours := int(d.Hours())
		return fmt.Sprintf("%dh", hours)
	}
	if d.Minutes() > 1 {
		minutes := int(d.Minutes())
		return fmt.Sprintf("%dm", minutes)
	}
	return "< 1m"
}
