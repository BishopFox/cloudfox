package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const K8S_AUDIT_ADMISSION_MODULE_NAME = "audit-admission"

var AuditAdmissionCmd = &cobra.Command{
	Use:     "audit-admission",
	Aliases: []string{"runtime-detection", "security-monitoring"},
	Short:   "Analyze runtime security monitoring and audit configurations",
	Long: `
Analyze all cluster runtime security monitoring configurations including:

Runtime Security Tools:
  - Falco (DaemonSet, FalcoRules)
  - Tetragon (TracingPolicy CRDs)
  - KubeArmor (KubeArmorPolicy CRDs)
  - Tracee (Aqua)
  - Sysdig Secure Runtime
  - CrowdStrike Falcon
  - Aqua Security, Prisma Cloud, NeuVector, StackRox/RHACS

Kubernetes Audit:
  - Audit Policy analysis
  - Coverage gap analysis
  - Detection bypass vectors

Cloud-Specific Logging/Monitoring (in-cluster detection):
  Detects cloud logging agents from DaemonSets and pods.
  No --cloud-provider flag required - reads pods/daemonsets directly.

  AWS:
    - AWS CloudWatch Agent / Fluent Bit for CloudWatch
    - AWS GuardDuty EKS Runtime Monitoring

  GCP:
    - Google Cloud Logging agent (fluentd/fluent-bit stackdriver)
    - GKE Cloud Operations integration

  Azure:
    - Azure Monitor Container Insights
    - OMSAgent for Azure Log Analytics
    - Azure Defender for Containers

Examples:
  cloudfox kubernetes audit-admission
  cloudfox kubernetes audit-admission --detailed`,
	Run: ListAuditAdmission,
}

type AuditAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t AuditAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t AuditAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// AuditAdmissionFinding represents audit/detection coverage for a namespace
type AuditAdmissionFinding struct {
	Namespace string

	// Detection Tools Present
	FalcoActive     bool
	TetragonActive  bool
	KubeArmorActive bool
	TraceeActive    bool
	SysdigActive    bool

	// Policy Counts
	FalcoRules        int
	TetragonPolicies  int
	KubeArmorPolicies int
	TraceeRules       int
	SysdigPolicies    int

	// Coverage Analysis
	HasRuntimeDetection bool
	DetectionTools      []string
	CoverageLevel       string // full, partial, none
	MonitoredPods       int
	UnmonitoredPods     int

	// Risk Analysis

	SecurityIssues []string
	BypassVectors  []string
}

// FalcoInfo represents Falco deployment status
type FalcoInfo struct {
	Name             string
	Namespace        string
	Status           string
	PodsRunning      int
	TotalPods        int
	DriverType       string // module, ebpf, modern_ebpf
	OutputChannels   []string
	RulesCount       int
	CustomRulesCount int

	SecurityIssues   []string
	ImageVerified    bool // True if Falco image was verified
}

// FalcoRuleInfo represents a Falco rule
type FalcoRuleInfo struct {
	Name           string
	Namespace      string
	Source         string // default, custom, falcosidekick
	Priority       string // emergency, alert, critical, error, warning, notice, info, debug
	Enabled        bool
	Output         string
	Tags           []string
	Condition      string

}

// TetragonInfo represents Tetragon deployment status
type TetragonInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Policies      int

	ImageVerified bool // True if Tetragon image was verified
}

// TracingPolicyInfo represents a Tetragon TracingPolicy
type TracingPolicyInfo struct {
	Name         string
	Namespace    string
	IsCluster    bool
	Selectors    []string
	Kprobes      int
	Tracepoints  int
	UprobesCount int
	Actions      []string

}

// KubeArmorInfo represents KubeArmor deployment status
type KubeArmorInfo struct {
	Name           string
	Namespace      string
	Status         string
	PodsRunning    int
	TotalPods      int
	Policies       int
	HostPolicies   int
	DefaultPosture string // audit, block

	ImageVerified  bool // True if KubeArmor image was verified
}

// KubeArmorPolicyInfo represents a KubeArmor policy
type KubeArmorPolicyInfo struct {
	Name       string
	Namespace  string
	IsHost     bool
	Selector   string
	Action     string // Audit, Allow, Block
	FileRules  int
	ProcRules  int
	NetRules   int
	CapRules   int
	SyscallRules int

}

// TraceeInfo represents Tracee deployment status
type TraceeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Policies      int

	ImageVerified bool // True if Tracee image was verified
}

// SysdigInfo represents Sysdig Secure Runtime status
type SysdigInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Policies      int

	ImageVerified bool // True if Sysdig agent image was verified
}

// K8sAuditPolicyInfo represents Kubernetes API server audit policy status
type K8sAuditPolicyInfo struct {
	Detected        bool
	PolicySource    string // configmap, file, unknown
	AuditLevel      string // None, Metadata, Request, RequestResponse
	LogBackend      string // log, webhook, dynamic
	LogDestination  string
	PolicyRules     int
	OmitStages      []string

}

// PrismaCloudInfo represents Prisma Cloud/Twistlock status
type PrismaCloudInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Defenders     int

	ImageVerified bool // True if Prisma Cloud defender image was verified
}

// AquaInfo represents Aqua Security platform status
type AquaInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Enforcers     int

	ImageVerified bool // True if Aqua enforcer image was verified
}

// StackRoxInfo represents StackRox/Red Hat ACS status
type StackRoxInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	CentralActive bool
	SensorActive  bool

	ImageVerified bool // True if StackRox image was verified
}

// NeuVectorInfo represents NeuVector runtime security status
type NeuVectorInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Controllers   int
	Enforcers     int

	ImageVerified bool // True if NeuVector image was verified
}

// CrowdStrikeInfo represents CrowdStrike Falcon runtime security status
type CrowdStrikeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int

	ImageVerified bool // True if CrowdStrike Falcon image was verified
}

// KubescapeRuntimeInfo represents Kubescape runtime security status
type KubescapeRuntimeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int

	ImageVerified bool // True if Kubescape image was verified
}

// DeepfenceInfo represents Deepfence ThreatMapper status
type DeepfenceInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int

	ImageVerified bool // True if Deepfence image was verified
}

// WizRuntimeInfo represents Wiz Runtime Sensor status
type WizRuntimeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int

	ImageVerified bool // True if Wiz sensor image was verified
}

// LaceworkInfo represents Lacework agent status
type LaceworkInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int

	ImageVerified bool // True if Lacework agent image was verified
}

// AuditLogDestinationInfo represents where audit logs are sent
type AuditLogDestinationInfo struct {
	Type        string // file, webhook, fluentd, elasticsearch, cloudwatch, stackdriver, azure-monitor, splunk, siem
	Name        string
	Namespace   string
	Status      string
	Destination string
	PodsRunning int
	TotalPods   int
	Configured  bool

}

// verifyAuditEngineImage checks if an image matches known patterns for the specified engine
// Now uses the shared admission SDK for centralized engine detection
func verifyAuditEngineImage(image string, engine string) bool {
	return admission.VerifyControllerImage(image, engine)
}

func ListAuditAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

	logger.InfoM(fmt.Sprintf("Analyzing audit/detection for %s", globals.ClusterName), K8S_AUDIT_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Pre-fetch all DaemonSets, Deployments, Pods, and ConfigMaps once (cached)
	logger.InfoM("Pre-fetching resources for audit analysis...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	allDaemonSets, err := sdk.GetDaemonSets(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to fetch DaemonSets: %v", err), K8S_AUDIT_ADMISSION_MODULE_NAME)
		allDaemonSets = []appsv1.DaemonSet{}
	}
	allDeployments, err := sdk.GetDeployments(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to fetch Deployments: %v", err), K8S_AUDIT_ADMISSION_MODULE_NAME)
		allDeployments = []appsv1.Deployment{}
	}
	allPods, err := sdk.GetPods(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to fetch Pods: %v", err), K8S_AUDIT_ADMISSION_MODULE_NAME)
		allPods = []corev1.Pod{}
	}
	allConfigMaps, err := sdk.GetConfigMaps(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to fetch ConfigMaps: %v", err), K8S_AUDIT_ADMISSION_MODULE_NAME)
		allConfigMaps = []corev1.ConfigMap{}
	}

	// Analyze Falco
	logger.InfoM("Analyzing Falco...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	falco, falcoRules := analyzeFalco(ctx, allDaemonSets, allPods, allConfigMaps, dynClient)

	// Analyze Tetragon
	logger.InfoM("Analyzing Tetragon...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	tetragon, tracingPolicies := analyzeTetragon(ctx, allDaemonSets, allPods, dynClient)

	// Analyze KubeArmor
	logger.InfoM("Analyzing KubeArmor...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	kubearmor, kubeArmorPolicies := analyzeKubeArmor(ctx, allDaemonSets, allPods, dynClient)

	// Analyze Tracee
	logger.InfoM("Analyzing Tracee...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	tracee := analyzeTracee(ctx, allDaemonSets, allPods, dynClient)

	// Analyze Sysdig
	logger.InfoM("Analyzing Sysdig...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	sysdig := analyzeSysdig(ctx, allDaemonSets, allPods, dynClient)

	// Analyze Kubernetes Audit Policy
	logger.InfoM("Analyzing Kubernetes Audit Policy...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	k8sAuditPolicy := analyzeK8sAuditPolicy(ctx, allPods, allConfigMaps)

	// Analyze Prisma Cloud
	logger.InfoM("Analyzing Prisma Cloud...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	prismaCloud := auditAnalyzePrismaCloud(allDaemonSets)

	// Analyze Aqua Security
	logger.InfoM("Analyzing Aqua Security...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	aquaSecurity := auditAnalyzeAquaSecurity(allDaemonSets)

	// Analyze StackRox/Red Hat ACS
	logger.InfoM("Analyzing StackRox/Red Hat ACS...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	stackrox := auditAnalyzeStackRox(allDaemonSets, allDeployments)

	// Analyze NeuVector
	logger.InfoM("Analyzing NeuVector...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	neuvector := auditAnalyzeNeuVector(allDaemonSets, allDeployments)

	// Analyze CrowdStrike Falcon
	logger.InfoM("Analyzing CrowdStrike Falcon...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	crowdstrike := auditAnalyzeCrowdStrike(allDaemonSets, allPods)

	// Analyze Kubescape Runtime
	logger.InfoM("Analyzing Kubescape Runtime...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	kubescape := auditAnalyzeKubescape(allDaemonSets, allPods)

	// Analyze Deepfence
	logger.InfoM("Analyzing Deepfence ThreatMapper...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	deepfence := auditAnalyzeDeepfence(allDaemonSets, allPods)

	// Analyze Wiz Runtime
	logger.InfoM("Analyzing Wiz Runtime Sensor...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	wizRuntime := auditAnalyzeWiz(allDaemonSets, allPods)

	// Analyze Lacework
	logger.InfoM("Analyzing Lacework...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	lacework := auditAnalyzeLacework(allDaemonSets, allPods)

	// Analyze Audit Log Destinations
	logger.InfoM("Analyzing audit log destinations...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	auditLogDestinations := analyzeAuditLogDestinations(allDaemonSets, allPods)

	// Analyze Cloud-Specific Logging
	logger.InfoM("Analyzing AWS CloudWatch...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	awsCloudWatch := analyzeAWSCloudWatch(allDaemonSets, allPods)
	if awsCloudWatch.Name != "" {
		logger.InfoM(fmt.Sprintf("Found %s: %s (%d/%d pods)", awsCloudWatch.Name, awsCloudWatch.Status, awsCloudWatch.PodsRunning, awsCloudWatch.TotalPods), K8S_AUDIT_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing GCP Cloud Logging...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	gcpCloudLogging := analyzeGCPCloudLogging(allDaemonSets, allPods)
	if gcpCloudLogging.Name != "" {
		logger.InfoM(fmt.Sprintf("Found %s: %s (%d/%d pods)", gcpCloudLogging.Name, gcpCloudLogging.Status, gcpCloudLogging.PodsRunning, gcpCloudLogging.TotalPods), K8S_AUDIT_ADMISSION_MODULE_NAME)
	}

	logger.InfoM("Analyzing Azure Monitor...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	azureMonitor := analyzeAzureMonitor(allDaemonSets, allPods)
	if azureMonitor.Name != "" {
		logger.InfoM(fmt.Sprintf("Found %s: %s (%d/%d pods)", azureMonitor.Name, azureMonitor.Status, azureMonitor.PodsRunning, azureMonitor.TotalPods), K8S_AUDIT_ADMISSION_MODULE_NAME)
	}

	// Build findings per namespace
	findings := buildAuditAdmissionFindings(allPods, falco, tetragon, kubearmor, tracee, sysdig, prismaCloud, aquaSecurity, stackrox, neuvector, crowdstrike, kubescape, deepfence, wizRuntime, lacework, kubeArmorPolicies)

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Falco",
		"Tetragon",
		"KubeArmor",
		"Tracee",
		"Sysdig",
		"Coverage",
		"Detection Tools",
		"Issues",
	}

	falcoHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Driver Type",
		"Rules Count",
		"Custom Rules",
		"Output Channels",
		"Issues",
	}

	// Uniform header for detailed policy tables (consistent across all admission modules)
	uniformPolicyHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Target",
		"Monitoring",
		"Rules",
		"Details",
		"Issues",
	}

	tetragonHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Policies",
		"Issues",
	}

	kubeArmorHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Policies",
		"Host Policies",
		"Default Posture",
		"Issues",
	}

	// Use uniform headers for detailed policy tables
	falcoRulesHeader := uniformPolicyHeader
	tracingPolicyHeader := uniformPolicyHeader
	kubeArmorPolicyHeader := uniformPolicyHeader

	auditLogDestHeader := []string{
		"Type",
		"Name",
		"Namespace",
		"Status",
		"Destination",
		"Pods Running",
		"Issues",
	}

	var summaryRows [][]string
	var policyOverviewRows [][]string
	var falcoRows [][]string
	var falcoRulesRows [][]string
	var tetragonRows [][]string
	var tracingPolicyRows [][]string
	var kubeArmorRows [][]string
	var kubeArmorPolicyRows [][]string
	var auditLogDestRows [][]string

	// Uniform header for policy overview table
	policyOverviewHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Tool",
		"Target",
		"Status",
		"Details",
		"Issues",
	}

	loot := shared.NewLootBuilder()

	// Build summary rows
	for _, finding := range findings {
		falcoStatus := "No"
		if finding.FalcoActive {
			falcoStatus = fmt.Sprintf("Yes (%d rules)", finding.FalcoRules)
		}

		tetragonStatus := "No"
		if finding.TetragonActive {
			tetragonStatus = fmt.Sprintf("Yes (%d policies)", finding.TetragonPolicies)
		}

		kubeArmorStatus := "No"
		if finding.KubeArmorActive {
			kubeArmorStatus = fmt.Sprintf("Yes (%d policies)", finding.KubeArmorPolicies)
		}

		traceeStatus := "No"
		if finding.TraceeActive {
			traceeStatus = "Yes"
		}

		sysdigStatus := "No"
		if finding.SysdigActive {
			sysdigStatus = "Yes"
		}

		detectionTools := "-"
		if len(finding.DetectionTools) > 0 {
			detectionTools = strings.Join(finding.DetectionTools, ", ")
		}

		issues := "-"
		if len(finding.SecurityIssues) > 0 {
			if len(finding.SecurityIssues) > 2 {
				issues = strings.Join(finding.SecurityIssues[:2], "; ") + fmt.Sprintf(" (+%d)", len(finding.SecurityIssues)-2)
			} else {
				issues = strings.Join(finding.SecurityIssues, "; ")
			}
		}

		summaryRows = append(summaryRows, []string{
			finding.Namespace,
			falcoStatus,
			tetragonStatus,
			kubeArmorStatus,
			traceeStatus,
			sysdigStatus,
			finding.CoverageLevel,
			detectionTools,
			issues,
		})
	}

	// Build Falco rows
	if falco.Name != "" {
		outputChannels := "-"
		if len(falco.OutputChannels) > 0 {
			outputChannels = strings.Join(falco.OutputChannels, ", ")
		}

		// Detect issues
		var falcoIssues []string
		if falco.Status != "Running" && falco.Status != "Healthy" {
			falcoIssues = append(falcoIssues, "Not running")
		}
		if falco.PodsRunning < falco.TotalPods {
			falcoIssues = append(falcoIssues, "Not all pods running")
		}
		if falco.RulesCount == 0 {
			falcoIssues = append(falcoIssues, "No rules loaded")
		}
		if len(falco.OutputChannels) == 0 {
			falcoIssues = append(falcoIssues, "No output channels")
		}
		issuesStr := "<NONE>"
		if len(falcoIssues) > 0 {
			issuesStr = strings.Join(falcoIssues, "; ")
		}

		falcoRows = append(falcoRows, []string{
			falco.Namespace,
			falco.Status,
			fmt.Sprintf("%d/%d", falco.PodsRunning, falco.TotalPods),
			falco.DriverType,
			fmt.Sprintf("%d", falco.RulesCount),
			fmt.Sprintf("%d", falco.CustomRulesCount),
			outputChannels,
			issuesStr,
		})
	}

	// Build Falco Rules rows (uniform schema: Namespace, Name, Scope, Target, Monitoring, Rules, Details, Issues)
	for _, rule := range falcoRules {
		enabled := "Disabled"
		if rule.Enabled {
			enabled = "Enabled"
		}

		tags := "-"
		if len(rule.Tags) > 0 {
			if len(rule.Tags) > 3 {
				tags = strings.Join(rule.Tags[:3], ", ") + "..."
			} else {
				tags = strings.Join(rule.Tags, ", ")
			}
		}

		// Detect issues
		var ruleIssues []string
		if !rule.Enabled {
			ruleIssues = append(ruleIssues, "Rule disabled")
		}
		if rule.Priority == "DEBUG" || rule.Priority == "INFORMATIONAL" {
			ruleIssues = append(ruleIssues, "Low priority")
		}
		ruleIssuesStr := "<NONE>"
		if len(ruleIssues) > 0 {
			ruleIssuesStr = strings.Join(ruleIssues, "; ")
		}

		// Build uniform row
		rulesDesc := fmt.Sprintf("Priority: %s, Source: %s", rule.Priority, rule.Source)
		details := fmt.Sprintf("Status: %s, Tags: %s", enabled, tags)

		falcoRulesRows = append(falcoRulesRows, []string{
			rule.Namespace,
			rule.Name,
			"Namespace",
			"All pods",
			"Syscall monitoring",
			rulesDesc,
			details,
			ruleIssuesStr,
		})
	}

	// Build Tetragon rows
	if tetragon.Name != "" {
		// Detect issues
		var tetragonIssues []string
		if tetragon.Status != "Running" && tetragon.Status != "Healthy" {
			tetragonIssues = append(tetragonIssues, "Not running")
		}
		if tetragon.PodsRunning < tetragon.TotalPods {
			tetragonIssues = append(tetragonIssues, "Not all pods running")
		}
		if tetragon.Policies == 0 {
			tetragonIssues = append(tetragonIssues, "No policies")
		}
		issuesStr := "<NONE>"
		if len(tetragonIssues) > 0 {
			issuesStr = strings.Join(tetragonIssues, "; ")
		}

		tetragonRows = append(tetragonRows, []string{
			tetragon.Namespace,
			tetragon.Status,
			fmt.Sprintf("%d/%d", tetragon.PodsRunning, tetragon.TotalPods),
			fmt.Sprintf("%d", tetragon.Policies),
			issuesStr,
		})
	}

	// Build TracingPolicy rows (uniform schema: Namespace, Name, Scope, Target, Monitoring, Rules, Details, Issues)
	for _, tp := range tracingPolicies {
		scope := "Namespace"
		ns := tp.Namespace
		if tp.IsCluster {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		target := "All pods"
		if len(tp.Selectors) > 0 {
			if len(tp.Selectors) > 2 {
				target = strings.Join(tp.Selectors[:2], ", ") + "..."
			} else {
				target = strings.Join(tp.Selectors, ", ")
			}
		}

		actions := "-"
		if len(tp.Actions) > 0 {
			actions = strings.Join(tp.Actions, ", ")
		}

		// Detect issues
		var tpIssues []string
		if tp.Kprobes == 0 && tp.Tracepoints == 0 {
			tpIssues = append(tpIssues, "No kprobes or tracepoints")
		}
		if len(tp.Selectors) == 0 {
			tpIssues = append(tpIssues, "No selectors")
		}
		tpIssuesStr := "<NONE>"
		if len(tpIssues) > 0 {
			tpIssuesStr = strings.Join(tpIssues, "; ")
		}

		// Build monitoring type description
		var monitoringTypes []string
		if tp.Kprobes > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("Kprobes (%d)", tp.Kprobes))
		}
		if tp.Tracepoints > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("Tracepoints (%d)", tp.Tracepoints))
		}
		if tp.UprobesCount > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("Uprobes (%d)", tp.UprobesCount))
		}
		monitoring := "None"
		if len(monitoringTypes) > 0 {
			monitoring = strings.Join(monitoringTypes, ", ")
		}

		rulesDesc := fmt.Sprintf("Actions: %s", actions)
		details := fmt.Sprintf("Tetragon TracingPolicy")

		tracingPolicyRows = append(tracingPolicyRows, []string{
			ns,
			tp.Name,
			scope,
			target,
			monitoring,
			rulesDesc,
			details,
			tpIssuesStr,
		})
	}

	// Build KubeArmor rows
	if kubearmor.Name != "" {
		// Detect issues
		var kaIssues []string
		if kubearmor.Status != "Running" && kubearmor.Status != "Healthy" {
			kaIssues = append(kaIssues, "Not running")
		}
		if kubearmor.PodsRunning < kubearmor.TotalPods {
			kaIssues = append(kaIssues, "Not all pods running")
		}
		if kubearmor.Policies == 0 {
			kaIssues = append(kaIssues, "No policies")
		}
		if kubearmor.DefaultPosture == "allow" || kubearmor.DefaultPosture == "audit" {
			kaIssues = append(kaIssues, "Permissive posture")
		}
		issuesStr := "<NONE>"
		if len(kaIssues) > 0 {
			issuesStr = strings.Join(kaIssues, "; ")
		}

		kubeArmorRows = append(kubeArmorRows, []string{
			kubearmor.Namespace,
			kubearmor.Status,
			fmt.Sprintf("%d/%d", kubearmor.PodsRunning, kubearmor.TotalPods),
			fmt.Sprintf("%d", kubearmor.Policies),
			fmt.Sprintf("%d", kubearmor.HostPolicies),
			kubearmor.DefaultPosture,
			issuesStr,
		})
	}

	// Build KubeArmor Policy rows (uniform schema: Namespace, Name, Scope, Target, Monitoring, Rules, Details, Issues)
	for _, kp := range kubeArmorPolicies {
		policyType := "Pod"
		scope := "Namespace"
		if kp.IsHost {
			policyType = "Host"
			scope = "Host"
		}

		// Detect issues
		var kpIssues []string
		if kp.Action == "Allow" || kp.Action == "Audit" {
			kpIssues = append(kpIssues, "Permissive action")
		}
		if kp.FileRules == 0 && kp.ProcRules == 0 && kp.NetRules == 0 {
			kpIssues = append(kpIssues, "No rules defined")
		}
		kpIssuesStr := "<NONE>"
		if len(kpIssues) > 0 {
			kpIssuesStr = strings.Join(kpIssues, "; ")
		}

		// Build monitoring type description
		var monitoringTypes []string
		if kp.FileRules > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("File (%d)", kp.FileRules))
		}
		if kp.ProcRules > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("Process (%d)", kp.ProcRules))
		}
		if kp.NetRules > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("Network (%d)", kp.NetRules))
		}
		if kp.CapRules > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("Capabilities (%d)", kp.CapRules))
		}
		if kp.SyscallRules > 0 {
			monitoringTypes = append(monitoringTypes, fmt.Sprintf("Syscalls (%d)", kp.SyscallRules))
		}
		monitoring := "None"
		if len(monitoringTypes) > 0 {
			monitoring = strings.Join(monitoringTypes, ", ")
		}

		target := kp.Selector
		if target == "" {
			target = "All pods"
		}

		rulesDesc := fmt.Sprintf("Action: %s", kp.Action)
		details := fmt.Sprintf("Type: %s, KubeArmor Policy", policyType)

		kubeArmorPolicyRows = append(kubeArmorPolicyRows, []string{
			kp.Namespace,
			kp.Name,
			scope,
			target,
			monitoring,
			rulesDesc,
			details,
			kpIssuesStr,
		})
	}

	// Build audit log destination rows
	for _, dest := range auditLogDestinations {
		podsRunning := "-"
		if dest.PodsRunning > 0 || dest.TotalPods > 0 {
			podsRunning = fmt.Sprintf("%d/%d", dest.PodsRunning, dest.TotalPods)
		}

		destination := "-"
		if dest.Destination != "" {
			destination = dest.Destination
		}

		// Detect issues
		var destIssues []string
		if dest.Status != "Running" && dest.Status != "Healthy" && dest.Status != "Ready" {
			destIssues = append(destIssues, "Not running")
		}
		if dest.PodsRunning < dest.TotalPods && dest.TotalPods > 0 {
			destIssues = append(destIssues, "Not all pods running")
		}
		if dest.Destination == "" || dest.Destination == "-" {
			destIssues = append(destIssues, "No destination configured")
		}
		destIssuesStr := "<NONE>"
		if len(destIssues) > 0 {
			destIssuesStr = strings.Join(destIssues, "; ")
		}

		auditLogDestRows = append(auditLogDestRows, []string{
			dest.Type,
			dest.Name,
			dest.Namespace,
			dest.Status,
			destination,
			podsRunning,
			destIssuesStr,
		})
	}

	// Build Policy Overview rows - unified view of all runtime security policies
	// Add Falco Rules to overview
	for _, rule := range falcoRules {
		var issues []string
		if !rule.Enabled {
			issues = append(issues, "Rule disabled")
		}
		if rule.Priority == "DEBUG" || rule.Priority == "INFORMATIONAL" {
			issues = append(issues, "Low priority")
		}
		issuesStr := "<NONE>"
		if len(issues) > 0 {
			issuesStr = strings.Join(issues, "; ")
		}

		status := "Enabled"
		if !rule.Enabled {
			status = "Disabled"
		}

		tags := "-"
		if len(rule.Tags) > 0 {
			if len(rule.Tags) > 3 {
				tags = strings.Join(rule.Tags[:3], ", ") + "..."
			} else {
				tags = strings.Join(rule.Tags, ", ")
			}
		}

		details := fmt.Sprintf("Source: %s, Priority: %s, Tags: %s", rule.Source, rule.Priority, tags)

		policyOverviewRows = append(policyOverviewRows, []string{
			rule.Namespace,
			rule.Name,
			"Namespace",
			"Falco",
			"All pods",
			status,
			details,
			issuesStr,
		})
	}

	// Add Tetragon TracingPolicies to overview
	for _, tp := range tracingPolicies {
		scope := "Namespace"
		ns := tp.Namespace
		if tp.IsCluster {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		var issues []string
		if tp.Kprobes == 0 && tp.Tracepoints == 0 {
			issues = append(issues, "No kprobes or tracepoints")
		}
		if len(tp.Selectors) == 0 {
			issues = append(issues, "No selectors")
		}
		issuesStr := "<NONE>"
		if len(issues) > 0 {
			issuesStr = strings.Join(issues, "; ")
		}

		target := "All pods"
		if len(tp.Selectors) > 0 {
			if len(tp.Selectors) > 2 {
				target = strings.Join(tp.Selectors[:2], ", ") + "..."
			} else {
				target = strings.Join(tp.Selectors, ", ")
			}
		}

		actions := "-"
		if len(tp.Actions) > 0 {
			actions = strings.Join(tp.Actions, ", ")
		}

		details := fmt.Sprintf("Kprobes: %d, Tracepoints: %d, Actions: %s", tp.Kprobes, tp.Tracepoints, actions)

		policyOverviewRows = append(policyOverviewRows, []string{
			ns,
			tp.Name,
			scope,
			"Tetragon",
			target,
			"Active",
			details,
			issuesStr,
		})
	}

	// Add KubeArmor Policies to overview
	for _, kp := range kubeArmorPolicies {
		var issues []string
		if kp.Action == "Allow" || kp.Action == "Audit" {
			issues = append(issues, "Permissive action")
		}
		if kp.FileRules == 0 && kp.ProcRules == 0 && kp.NetRules == 0 {
			issues = append(issues, "No rules defined")
		}
		issuesStr := "<NONE>"
		if len(issues) > 0 {
			issuesStr = strings.Join(issues, "; ")
		}

		policyType := "Pod"
		if kp.IsHost {
			policyType = "Host"
		}

		details := fmt.Sprintf("Type: %s, Action: %s, File: %d, Proc: %d, Net: %d",
			policyType, kp.Action, kp.FileRules, kp.ProcRules, kp.NetRules)

		policyOverviewRows = append(policyOverviewRows, []string{
			kp.Namespace,
			kp.Name,
			"Namespace",
			"KubeArmor",
			kp.Selector,
			"Active",
			details,
			issuesStr,
		})
	}

	// Sort overview rows by namespace, then tool, then name
	sort.SliceStable(policyOverviewRows, func(i, j int) bool {
		if policyOverviewRows[i][0] != policyOverviewRows[j][0] {
			return policyOverviewRows[i][0] < policyOverviewRows[j][0]
		}
		if policyOverviewRows[i][3] != policyOverviewRows[j][3] {
			return policyOverviewRows[i][3] < policyOverviewRows[j][3]
		}
		return policyOverviewRows[i][1] < policyOverviewRows[j][1]
	})

	// Generate loot
	generateAuditAdmissionLoot(loot, findings, falco, falcoRules, tetragon, tracingPolicies, kubearmor, kubeArmorPolicies, tracee, sysdig, k8sAuditPolicy, prismaCloud, aquaSecurity, stackrox, neuvector, auditLogDestinations)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Audit-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	// Add unified policy overview table (always shown)
	if len(policyOverviewRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-Policy-Overview",
			Header: policyOverviewHeader,
			Body:   policyOverviewRows,
		})
	}

	if len(falcoRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-Falco",
			Header: falcoHeader,
			Body:   falcoRows,
		})
	}

	if len(falcoRulesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-Falco-Rules",
			Header: falcoRulesHeader,
			Body:   falcoRulesRows,
		})
	}

	if len(tetragonRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-Tetragon",
			Header: tetragonHeader,
			Body:   tetragonRows,
		})
	}

	if len(tracingPolicyRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-TracingPolicies",
			Header: tracingPolicyHeader,
			Body:   tracingPolicyRows,
		})
	}

	if len(kubeArmorRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-KubeArmor",
			Header: kubeArmorHeader,
			Body:   kubeArmorRows,
		})
	}

	if len(kubeArmorPolicyRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-KubeArmor-Policies",
			Header: kubeArmorPolicyHeader,
			Body:   kubeArmorPolicyRows,
		})
	}

	if len(auditLogDestRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Audit-Admission-Log-Destinations",
			Header: auditLogDestHeader,
			Body:   auditLogDestRows,
		})
	}

	output := AuditAdmissionOutput{
		Table: tables,
		Loot:  loot.Build(),
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"Audit-Admission",
		globals.ClusterName,
		"results",
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_AUDIT_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// Falco Analysis
// ============================================================================

func analyzeFalco(ctx context.Context, allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod, allConfigMaps []corev1.ConfigMap, dynClient dynamic.Interface) (FalcoInfo, []FalcoRuleInfo) {
	info := FalcoInfo{}
	var rules []FalcoRuleInfo

	// Check for Falco DaemonSet in pre-fetched data
	namespaces := map[string]bool{"falco": true, "falco-system": true, "security": true, "kube-system": true}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		nameLC := strings.ToLower(ds.Name)
		if strings.Contains(nameLC, "falco") && !strings.Contains(nameLC, "sidekick") && !strings.Contains(nameLC, "exporter") {
			info.Name = "Falco"
			info.Namespace = ds.Namespace
			info.TotalPods = int(ds.Status.DesiredNumberScheduled)
			info.PodsRunning = int(ds.Status.NumberReady)

			// Analyze driver type from container args and verify image
			for _, container := range ds.Spec.Template.Spec.Containers {
				// Verify by image
				if verifyAuditEngineImage(container.Image, "falco") {
					info.ImageVerified = true
				}

				for _, arg := range container.Args {
					if strings.Contains(arg, "modern_ebpf") || strings.Contains(arg, "modern-bpf") {
						info.DriverType = "modern_ebpf"
					} else if strings.Contains(arg, "ebpf") {
						info.DriverType = "ebpf"
					}
				}
				for _, env := range container.Env {
					if env.Name == "FALCO_BPF_PROBE" || env.Name == "FALCO_DRIVER_NAME" {
						if strings.Contains(env.Value, "modern") {
							info.DriverType = "modern_ebpf"
						} else if strings.Contains(env.Value, "ebpf") {
							info.DriverType = "ebpf"
						}
					}
				}
			}
			if info.DriverType == "" {
				info.DriverType = "kernel_module"
			}
			break
		}
	}

	// Also check via pods with labels if DaemonSet not found
	if info.Name == "" {
		labelSelectors := map[string]string{
			"app":                     "falco",
			"app.kubernetes.io/name":  "falco",
		}
		for _, pod := range allPods {
			if !namespaces[pod.Namespace] {
				continue
			}
			for labelKey, labelVal := range labelSelectors {
				if pod.Labels[labelKey] == labelVal {
					if info.Name == "" {
						info.Name = "Falco"
						info.Namespace = pod.Namespace
						info.DriverType = "unknown"
					}
					info.TotalPods++
					if pod.Status.Phase == corev1.PodRunning {
						info.PodsRunning++
					}
					// Verify by image
					for _, container := range pod.Spec.Containers {
						if verifyAuditEngineImage(container.Image, "falco") {
							info.ImageVerified = true
							break
						}
					}
					break
				}
			}
		}
	}

	if info.Name == "" {
		return info, rules
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
	} else {
		info.Status = "active"
	}

	// Check for Falcosidekick (output channels) from pre-fetched pods
	for _, pod := range allPods {
		if pod.Namespace == info.Namespace && pod.Labels["app.kubernetes.io/name"] == "falcosidekick" {
			info.OutputChannels = append(info.OutputChannels, "falcosidekick")
			break
		}
	}

	// Check for FalcoRules CRD (if using falco-operator)
	falcoRulesGVR := schema.GroupVersionResource{
		Group:    "falco.org",
		Version:  "v1alpha1",
		Resource: "falcorules",
	}

	rulesList, err := dynClient.Resource(falcoRulesGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, r := range rulesList.Items {
			rule := parseFalcoRule(r.Object)
			rules = append(rules, rule)
			info.RulesCount++
			if rule.Source == "custom" {
				info.CustomRulesCount++
			}
		}
	}

	// Check ConfigMaps for rules from pre-fetched data
	for _, cm := range allConfigMaps {
		if cm.Namespace == info.Namespace && strings.Contains(cm.Name, "falco") && strings.Contains(cm.Name, "rules") {
			// Count rules in ConfigMap
			for key, data := range cm.Data {
				if strings.HasSuffix(key, ".yaml") || strings.HasSuffix(key, ".yml") {
					// Simple heuristic: count "- rule:" occurrences
					ruleCount := strings.Count(data, "- rule:")
					info.RulesCount += ruleCount
					if strings.Contains(cm.Name, "custom") {
						info.CustomRulesCount += ruleCount
					}
				}
			}
		}
	}

	return info, rules
}

func parseFalcoRule(obj map[string]interface{}) FalcoRuleInfo {
	rule := FalcoRuleInfo{
		Enabled: true,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		rule.Name, _ = metadata["name"].(string)
		rule.Namespace, _ = metadata["namespace"].(string)

		if labels, ok := metadata["labels"].(map[string]interface{}); ok {
			if source, ok := labels["source"].(string); ok {
				rule.Source = source
			}
		}
	}

	if rule.Source == "" {
		rule.Source = "custom"
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if priority, ok := spec["priority"].(string); ok {
			rule.Priority = priority
		}
		if enabled, ok := spec["enabled"].(bool); ok {
			rule.Enabled = enabled
		}
		if output, ok := spec["output"].(string); ok {
			rule.Output = output
		}
		if condition, ok := spec["condition"].(string); ok {
			rule.Condition = condition
		}
		if tags, ok := spec["tags"].([]interface{}); ok {
			for _, tag := range tags {
				if tagStr, ok := tag.(string); ok {
					rule.Tags = append(rule.Tags, tagStr)
				}
			}
		}
	}

	if !rule.Enabled {
	}

	return rule
}

// ============================================================================
// Tetragon Analysis
// ============================================================================

func analyzeTetragon(ctx context.Context, allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod, dynClient dynamic.Interface) (TetragonInfo, []TracingPolicyInfo) {
	info := TetragonInfo{}
	var policies []TracingPolicyInfo

	// Check for Tetragon DaemonSet in pre-fetched data
	namespaces := map[string]bool{"kube-system": true, "tetragon": true, "cilium": true}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "tetragon") {
			info.Name = "Tetragon"
			info.Namespace = ds.Namespace
			info.TotalPods = int(ds.Status.DesiredNumberScheduled)
			info.PodsRunning = int(ds.Status.NumberReady)
			// Verify by image
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "tetragon") {
					info.ImageVerified = true
					break
				}
			}
			break
		}
	}

	// Also check via pods with labels if DaemonSet not found
	if info.Name == "" {
		for _, pod := range allPods {
			if !namespaces[pod.Namespace] {
				continue
			}
			if pod.Labels["app.kubernetes.io/name"] == "tetragon" || pod.Labels["k8s-app"] == "tetragon" {
				if info.Name == "" {
					info.Name = "Tetragon"
					info.Namespace = pod.Namespace
				}
				info.TotalPods++
				if pod.Status.Phase == corev1.PodRunning {
					info.PodsRunning++
				}
				// Verify by image
				for _, container := range pod.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "tetragon") {
						info.ImageVerified = true
						break
					}
				}
			}
		}
	}

	if info.Name == "" {
		return info, policies
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
	} else {
		info.Status = "active"
	}

	// Check for TracingPolicy CRDs
	tracingPolicyGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v1alpha1",
		Resource: "tracingpolicies",
	}

	tpList, err := dynClient.Resource(tracingPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, tp := range tpList.Items {
			policy := parseTracingPolicy(tp.Object, false)
			policies = append(policies, policy)
			info.Policies++
		}
	}

	// Check for TracingPolicyNamespaced
	tracingPolicyNSGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v1alpha1",
		Resource: "tracingpoliciesnamespaced",
	}

	tpNSList, err := dynClient.Resource(tracingPolicyNSGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, tp := range tpNSList.Items {
			policy := parseTracingPolicy(tp.Object, false)
			policies = append(policies, policy)
			info.Policies++
		}
	}

	return info, policies
}

func parseTracingPolicy(obj map[string]interface{}, isCluster bool) TracingPolicyInfo {
	policy := TracingPolicyInfo{
		IsCluster: isCluster,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		policy.Name, _ = metadata["name"].(string)
		policy.Namespace, _ = metadata["namespace"].(string)
		if policy.Namespace == "" {
			policy.IsCluster = true
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Parse selectors
		if selectors, ok := spec["selectors"].([]interface{}); ok {
			for _, sel := range selectors {
				if selMap, ok := sel.(map[string]interface{}); ok {
					if matchLabels, ok := selMap["matchLabels"].(map[string]interface{}); ok {
						for k, v := range matchLabels {
							policy.Selectors = append(policy.Selectors, fmt.Sprintf("%s=%v", k, v))
						}
					}
				}
			}
		}

		// Count kprobes
		if kprobes, ok := spec["kprobes"].([]interface{}); ok {
			policy.Kprobes = len(kprobes)
			for _, kp := range kprobes {
				if kpMap, ok := kp.(map[string]interface{}); ok {
					if selectors, ok := kpMap["selectors"].([]interface{}); ok {
						for _, sel := range selectors {
							if selMap, ok := sel.(map[string]interface{}); ok {
								if actions, ok := selMap["matchActions"].([]interface{}); ok {
									for _, action := range actions {
										if actionMap, ok := action.(map[string]interface{}); ok {
											if actionType, ok := actionMap["action"].(string); ok {
												if !auditAdmissionContainsString(policy.Actions, actionType) {
													policy.Actions = append(policy.Actions, actionType)
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Count tracepoints
		if tracepoints, ok := spec["tracepoints"].([]interface{}); ok {
			policy.Tracepoints = len(tracepoints)
		}

		// Count uprobes
		if uprobes, ok := spec["uprobes"].([]interface{}); ok {
			policy.UprobesCount = len(uprobes)
		}
	}

	if policy.Kprobes == 0 && policy.Tracepoints == 0 && policy.UprobesCount == 0 {
	}

	return policy
}

// ============================================================================
// KubeArmor Analysis
// ============================================================================

func analyzeKubeArmor(ctx context.Context, allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod, dynClient dynamic.Interface) (KubeArmorInfo, []KubeArmorPolicyInfo) {
	info := KubeArmorInfo{}
	var policies []KubeArmorPolicyInfo

	// Check for KubeArmor DaemonSet in pre-fetched data
	namespaces := map[string]bool{"kubearmor": true, "kube-system": true, "security": true}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "kubearmor") {
			info.Name = "KubeArmor"
			info.Namespace = ds.Namespace
			info.TotalPods = int(ds.Status.DesiredNumberScheduled)
			info.PodsRunning = int(ds.Status.NumberReady)
			// Verify by image
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "kubearmor") {
					info.ImageVerified = true
					break
				}
			}
			break
		}
	}

	// Also check via pods with labels if DaemonSet not found
	if info.Name == "" {
		for _, pod := range allPods {
			if !namespaces[pod.Namespace] {
				continue
			}
			if pod.Labels["kubearmor-app"] == "kubearmor" || pod.Labels["app.kubernetes.io/name"] == "kubearmor" {
				if info.Name == "" {
					info.Name = "KubeArmor"
					info.Namespace = pod.Namespace
				}
				info.TotalPods++
				if pod.Status.Phase == corev1.PodRunning {
					info.PodsRunning++
				}
				// Verify by image
				for _, container := range pod.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "kubearmor") {
						info.ImageVerified = true
						break
					}
				}
			}
		}
	}

	if info.Name == "" {
		return info, policies
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
	} else {
		info.Status = "active"
	}

	info.DefaultPosture = "audit" // Default

	// Check for KubeArmorPolicy CRDs
	kubeArmorPolicyGVR := schema.GroupVersionResource{
		Group:    "security.kubearmor.com",
		Version:  "v1",
		Resource: "kubearmorpolicies",
	}

	kapList, err := dynClient.Resource(kubeArmorPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, kap := range kapList.Items {
			policy := parseKubeArmorPolicy(kap.Object, false)
			policies = append(policies, policy)
			info.Policies++
		}
	}

	// Check for KubeArmorHostPolicy CRDs
	kubeArmorHostPolicyGVR := schema.GroupVersionResource{
		Group:    "security.kubearmor.com",
		Version:  "v1",
		Resource: "kubearmorhostpolicies",
	}

	kahpList, err := dynClient.Resource(kubeArmorHostPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, kahp := range kahpList.Items {
			policy := parseKubeArmorPolicy(kahp.Object, true)
			policies = append(policies, policy)
			info.HostPolicies++
		}
	}

	// Note: Default posture check from ConfigMap is skipped - would require passing allConfigMaps
	// The default posture is set to "audit" above which is the KubeArmor default

	if info.DefaultPosture == "audit" {
	}

	return info, policies
}

func parseKubeArmorPolicy(obj map[string]interface{}, isHost bool) KubeArmorPolicyInfo {
	policy := KubeArmorPolicyInfo{
		IsHost: isHost,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		policy.Name, _ = metadata["name"].(string)
		policy.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		// Parse selector
		if selector, ok := spec["selector"].(map[string]interface{}); ok {
			if matchLabels, ok := selector["matchLabels"].(map[string]interface{}); ok {
				var labels []string
				for k, v := range matchLabels {
					labels = append(labels, fmt.Sprintf("%s=%v", k, v))
				}
				policy.Selector = strings.Join(labels, ", ")
			}
		}

		// Default action
		if action, ok := spec["action"].(string); ok {
			policy.Action = action
		} else {
			policy.Action = "Audit"
		}

		// Count rules
		if file, ok := spec["file"].(map[string]interface{}); ok {
			if matchPaths, ok := file["matchPaths"].([]interface{}); ok {
				policy.FileRules += len(matchPaths)
			}
			if matchDirectories, ok := file["matchDirectories"].([]interface{}); ok {
				policy.FileRules += len(matchDirectories)
			}
			if matchPatterns, ok := file["matchPatterns"].([]interface{}); ok {
				policy.FileRules += len(matchPatterns)
			}
		}

		if process, ok := spec["process"].(map[string]interface{}); ok {
			if matchPaths, ok := process["matchPaths"].([]interface{}); ok {
				policy.ProcRules += len(matchPaths)
			}
			if matchDirectories, ok := process["matchDirectories"].([]interface{}); ok {
				policy.ProcRules += len(matchDirectories)
			}
			if matchPatterns, ok := process["matchPatterns"].([]interface{}); ok {
				policy.ProcRules += len(matchPatterns)
			}
		}

		if network, ok := spec["network"].(map[string]interface{}); ok {
			if matchProtocols, ok := network["matchProtocols"].([]interface{}); ok {
				policy.NetRules += len(matchProtocols)
			}
		}

		if capabilities, ok := spec["capabilities"].(map[string]interface{}); ok {
			if matchCapabilities, ok := capabilities["matchCapabilities"].([]interface{}); ok {
				policy.CapRules += len(matchCapabilities)
			}
		}

		if syscalls, ok := spec["syscalls"].(map[string]interface{}); ok {
			if matchSyscalls, ok := syscalls["matchSyscalls"].([]interface{}); ok {
				policy.SyscallRules += len(matchSyscalls)
			}
		}
	}

	if policy.Action == "Audit" {
	}

	return policy
}

// ============================================================================
// Tracee Analysis
// ============================================================================

func analyzeTracee(ctx context.Context, allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod, dynClient dynamic.Interface) TraceeInfo {
	info := TraceeInfo{}

	// Check for Tracee DaemonSet in pre-fetched data
	namespaces := map[string]bool{"tracee": true, "tracee-system": true, "aqua": true, "kube-system": true}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "tracee") {
			info.Name = "Tracee"
			info.Namespace = ds.Namespace
			info.TotalPods = int(ds.Status.DesiredNumberScheduled)
			info.PodsRunning = int(ds.Status.NumberReady)
			// Verify by image
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "tracee") {
					info.ImageVerified = true
					break
				}
			}
			break
		}
	}

	// Also check via pods with labels if DaemonSet not found
	if info.Name == "" {
		for _, pod := range allPods {
			if !namespaces[pod.Namespace] {
				continue
			}
			if pod.Labels["app.kubernetes.io/name"] == "tracee" || pod.Labels["app"] == "tracee" {
				if info.Name == "" {
					info.Name = "Tracee"
					info.Namespace = pod.Namespace
				}
				info.TotalPods++
				if pod.Status.Phase == corev1.PodRunning {
					info.PodsRunning++
				}
				// Verify by image
				for _, container := range pod.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "tracee") {
						info.ImageVerified = true
						break
					}
				}
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// Sysdig Analysis
// ============================================================================

func analyzeSysdig(ctx context.Context, allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod, dynClient dynamic.Interface) SysdigInfo {
	info := SysdigInfo{}

	// Check for Sysdig Agent DaemonSet in pre-fetched data
	namespaces := map[string]bool{"sysdig": true, "sysdig-agent": true, "kube-system": true}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "sysdig") {
			info.Name = "Sysdig"
			info.Namespace = ds.Namespace
			info.TotalPods = int(ds.Status.DesiredNumberScheduled)
			info.PodsRunning = int(ds.Status.NumberReady)
			// Verify by image
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "sysdig") {
					info.ImageVerified = true
					break
				}
			}
			break
		}
	}

	// Also check via pods with labels if DaemonSet not found
	if info.Name == "" {
		for _, pod := range allPods {
			if !namespaces[pod.Namespace] {
				continue
			}
			if pod.Labels["app"] == "sysdig-agent" || pod.Labels["app.kubernetes.io/name"] == "sysdig-agent" {
				if info.Name == "" {
					info.Name = "Sysdig"
					info.Namespace = pod.Namespace
				}
				info.TotalPods++
				if pod.Status.Phase == corev1.PodRunning {
					info.PodsRunning++
				}
				// Verify by image
				for _, container := range pod.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "sysdig") {
						info.ImageVerified = true
						break
					}
				}
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// Kubernetes Audit Policy Analysis
// ============================================================================

func analyzeK8sAuditPolicy(ctx context.Context, allPods []corev1.Pod, allConfigMaps []corev1.ConfigMap) K8sAuditPolicyInfo {
	info := K8sAuditPolicyInfo{}

	// Check for audit policy ConfigMap from pre-fetched data
	auditConfigMapNames := map[string]bool{
		"audit-policy":                  true,
		"kube-apiserver-audit-policy":   true,
		"audit":                         true,
	}

	for _, cm := range allConfigMaps {
		if cm.Namespace == "kube-system" && auditConfigMapNames[cm.Name] {
			info.Detected = true
			info.PolicySource = "configmap"

			// Parse audit policy
			for key, data := range cm.Data {
				if strings.Contains(key, "yaml") || strings.Contains(key, "policy") {
					// Count rules
					info.PolicyRules = strings.Count(data, "- level:")

					// Detect audit level
					if strings.Contains(data, "level: RequestResponse") {
						info.AuditLevel = "RequestResponse"
					} else if strings.Contains(data, "level: Request") {
						info.AuditLevel = "Request"
					} else if strings.Contains(data, "level: Metadata") {
						info.AuditLevel = "Metadata"
					} else if strings.Contains(data, "level: None") {
						info.AuditLevel = "None"
					}

					// Check for omitStages
					if strings.Contains(data, "omitStages:") {
						if strings.Contains(data, "RequestReceived") {
							info.OmitStages = append(info.OmitStages, "RequestReceived")
						}
						if strings.Contains(data, "ResponseStarted") {
							info.OmitStages = append(info.OmitStages, "ResponseStarted")
						}
						if strings.Contains(data, "ResponseComplete") {
							info.OmitStages = append(info.OmitStages, "ResponseComplete")
						}
						if strings.Contains(data, "Panic") {
							info.OmitStages = append(info.OmitStages, "Panic")
						}
					}
				}
			}
			break
		}
	}

	// Check kube-apiserver pod for audit flags from pre-fetched pods
	for _, pod := range allPods {
		if pod.Namespace == "kube-system" && pod.Labels["component"] == "kube-apiserver" {
			for _, container := range pod.Spec.Containers {
				for _, arg := range container.Command {
					if strings.Contains(arg, "--audit-policy-file") {
						info.Detected = true
						if info.PolicySource == "" {
							info.PolicySource = "file"
						}
					}
					if strings.Contains(arg, "--audit-log-path") {
						info.LogBackend = "log"
						parts := strings.Split(arg, "=")
						if len(parts) > 1 {
							info.LogDestination = parts[1]
						}
					}
					if strings.Contains(arg, "--audit-webhook-config-file") {
						info.LogBackend = "webhook"
					}
					if strings.Contains(arg, "--audit-dynamic-configuration") {
						info.LogBackend = "dynamic"
					}
				}
			}
		}
	}

	// Assess risk
	if !info.Detected {
	} else if info.AuditLevel == "None" || info.AuditLevel == "" {
	} else if len(info.OmitStages) > 0 {
	}

	return info
}

// ============================================================================
// Prisma Cloud/Twistlock Analysis
// ============================================================================

func auditAnalyzePrismaCloud(allDaemonSets []appsv1.DaemonSet) PrismaCloudInfo {
	info := PrismaCloudInfo{}

	// Check for Prisma Cloud Defender DaemonSet in pre-fetched data
	namespaces := map[string]bool{"twistlock": true, "prisma-cloud": true, "pcc": true}
	imagePatterns := []string{"twistlock", "prismacloud", "registry.twistlock.com"}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		// Verify by image name to reduce false positives
		for _, container := range ds.Spec.Template.Spec.Containers {
			for _, pattern := range imagePatterns {
				if strings.Contains(strings.ToLower(container.Image), pattern) {
					info.Name = "Prisma Cloud"
					info.Namespace = ds.Namespace
					info.TotalPods = int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning = int(ds.Status.NumberReady)
					info.Defenders = info.PodsRunning
					info.ImageVerified = true
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// Aqua Security Analysis
// ============================================================================

func auditAnalyzeAquaSecurity(allDaemonSets []appsv1.DaemonSet) AquaInfo {
	info := AquaInfo{}

	// Check for Aqua Enforcer DaemonSet in pre-fetched data
	namespaces := map[string]bool{"aqua": true, "aqua-security": true, "kube-system": true}
	imagePatterns := []string{"aquasec", "aqua-enforcer", "registry.aquasec.com"}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		// Verify by image name to reduce false positives
		for _, container := range ds.Spec.Template.Spec.Containers {
			for _, pattern := range imagePatterns {
				if strings.Contains(strings.ToLower(container.Image), pattern) {
					info.Name = "Aqua Security"
					info.Namespace = ds.Namespace
					info.TotalPods = int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning = int(ds.Status.NumberReady)
					info.Enforcers = info.PodsRunning
					info.ImageVerified = true
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// StackRox/Red Hat ACS Analysis
// ============================================================================

func auditAnalyzeStackRox(allDaemonSets []appsv1.DaemonSet, allDeployments []appsv1.Deployment) StackRoxInfo {
	info := StackRoxInfo{}

	// Check for StackRox/RHACS deployment in pre-fetched data
	namespaces := map[string]bool{"stackrox": true, "rhacs-operator": true, "rhacs": true, "acs": true}
	imagePatterns := []string{
		"stackrox",
		"advanced-cluster-security",
		"rhacs",
		"registry.redhat.io/advanced-cluster-security",
	}

	// Check for Central
	for _, dep := range allDeployments {
		if !namespaces[dep.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(dep.Name), "central") {
			// Verify by image
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, pattern := range imagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						info.Name = "StackRox/ACS"
						info.Namespace = dep.Namespace
						info.CentralActive = dep.Status.ReadyReplicas > 0
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	// Check for Sensor (daemonset or deployment)
	if info.Name != "" {
		// Check DaemonSets for collector
		for _, ds := range allDaemonSets {
			if ds.Namespace != info.Namespace {
				continue
			}
			if strings.Contains(strings.ToLower(ds.Name), "collector") ||
				strings.Contains(strings.ToLower(ds.Name), "sensor") {
				info.SensorActive = ds.Status.NumberReady > 0
				info.TotalPods += int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning += int(ds.Status.NumberReady)
			}
		}

		// Check Deployments for sensor
		for _, dep := range allDeployments {
			if dep.Namespace != info.Namespace {
				continue
			}
			if strings.Contains(strings.ToLower(dep.Name), "sensor") {
				info.SensorActive = dep.Status.ReadyReplicas > 0
				info.TotalPods += int(dep.Status.Replicas)
				info.PodsRunning += int(dep.Status.ReadyReplicas)
			}
		}

		// Set status
		if info.CentralActive && info.SensorActive {
			info.Status = "active"
		} else if info.CentralActive || info.SensorActive {
			info.Status = "degraded"
			if !info.CentralActive {
			} else {
			}
		} else {
			info.Status = "not-running"
		}
	}

	return info
}

// ============================================================================
// NeuVector Analysis
// ============================================================================

func auditAnalyzeNeuVector(allDaemonSets []appsv1.DaemonSet, allDeployments []appsv1.Deployment) NeuVectorInfo {
	info := NeuVectorInfo{}

	// Check for NeuVector deployment in pre-fetched data
	namespaces := map[string]bool{"neuvector": true, "nv-system": true, "kube-system": true}
	imagePatterns := []string{
		"neuvector/controller",
		"neuvector/enforcer",
		"neuvector/manager",
		"docker.io/neuvector",
	}

	for _, dep := range allDeployments {
		if !namespaces[dep.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(dep.Name), "neuvector") &&
			strings.Contains(strings.ToLower(dep.Name), "controller") {
			// Verify by image
			for _, container := range dep.Spec.Template.Spec.Containers {
				for _, pattern := range imagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						info.Name = "NeuVector"
						info.Namespace = dep.Namespace
						info.Controllers = int(dep.Status.ReadyReplicas)
						info.ImageVerified = true
						break
					}
				}
				if info.ImageVerified {
					break
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Check for enforcer DaemonSet
	for _, ds := range allDaemonSets {
		if ds.Namespace != info.Namespace {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "neuvector") &&
			strings.Contains(strings.ToLower(ds.Name), "enforcer") {
			info.Enforcers = int(ds.Status.NumberReady)
			info.TotalPods = int(ds.Status.DesiredNumberScheduled)
			info.PodsRunning = int(ds.Status.NumberReady)
			break
		}
	}

	// Set status
	if info.Controllers > 0 && info.Enforcers > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else if info.Controllers > 0 {
		info.Status = "degraded"
	} else {
		info.Status = "not-running"
	}

	return info
}

// ============================================================================
// CrowdStrike Falcon Analysis
// ============================================================================

func auditAnalyzeCrowdStrike(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) CrowdStrikeInfo {
	info := CrowdStrikeInfo{}

	// Check for CrowdStrike Falcon using SDK expected namespaces
	expectedNs := admission.GetExpectedNamespaces("crowdstrike")
	namespaces := make(map[string]bool)
	if len(expectedNs) == 0 {
		namespaces = map[string]bool{"falcon-system": true, "crowdstrike": true, "kube-system": true}
	} else {
		for _, ns := range expectedNs {
			namespaces[ns] = true
		}
	}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "falcon") {
			// Verify by image using SDK
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "crowdstrike") {
					info.Name = "CrowdStrike Falcon"
					info.Namespace = ds.Namespace
					info.TotalPods = int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning = int(ds.Status.NumberReady)
					info.ImageVerified = true
					break
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}

// ============================================================================
// Kubescape Runtime Analysis
// ============================================================================

func auditAnalyzeKubescape(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) KubescapeRuntimeInfo {
	info := KubescapeRuntimeInfo{}

	// Check for Kubescape using SDK expected namespaces
	expectedNs := admission.GetExpectedNamespaces("kubescape-runtime")
	namespaces := make(map[string]bool)
	if len(expectedNs) == 0 {
		namespaces = map[string]bool{"kubescape": true, "armo-system": true, "kube-system": true}
	} else {
		for _, ns := range expectedNs {
			namespaces[ns] = true
		}
	}

	// Check for node-agent DaemonSet
	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "kubescape") ||
			strings.Contains(strings.ToLower(ds.Name), "node-agent") {
			// Verify by image using SDK
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "kubescape-runtime") {
					info.Name = "Kubescape"
					info.Namespace = ds.Namespace
					info.TotalPods = int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning = int(ds.Status.NumberReady)
					info.ImageVerified = true
					break
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}

// ============================================================================
// Deepfence ThreatMapper Analysis
// ============================================================================

func auditAnalyzeDeepfence(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) DeepfenceInfo {
	info := DeepfenceInfo{}

	// Check for Deepfence using SDK expected namespaces
	expectedNs := admission.GetExpectedNamespaces("deepfence")
	namespaces := make(map[string]bool)
	if len(expectedNs) == 0 {
		namespaces = map[string]bool{"deepfence": true, "kube-system": true}
	} else {
		for _, ns := range expectedNs {
			namespaces[ns] = true
		}
	}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "deepfence") {
			// Verify by image using SDK
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "deepfence") {
					info.Name = "Deepfence ThreatMapper"
					info.Namespace = ds.Namespace
					info.TotalPods = int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning = int(ds.Status.NumberReady)
					info.ImageVerified = true
					break
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}

// ============================================================================
// Wiz Runtime Sensor Analysis
// ============================================================================

func auditAnalyzeWiz(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) WizRuntimeInfo {
	info := WizRuntimeInfo{}

	// Check for Wiz using SDK expected namespaces
	expectedNs := admission.GetExpectedNamespaces("wiz-runtime")
	namespaces := make(map[string]bool)
	if len(expectedNs) == 0 {
		namespaces = map[string]bool{"wiz": true, "kube-system": true}
	} else {
		for _, ns := range expectedNs {
			namespaces[ns] = true
		}
	}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "wiz") {
			// Verify by image using SDK
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "wiz-runtime") {
					info.Name = "Wiz Runtime Sensor"
					info.Namespace = ds.Namespace
					info.TotalPods = int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning = int(ds.Status.NumberReady)
					info.ImageVerified = true
					break
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}

// ============================================================================
// Lacework Analysis
// ============================================================================

func auditAnalyzeLacework(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) LaceworkInfo {
	info := LaceworkInfo{}

	// Check for Lacework using SDK expected namespaces
	expectedNs := admission.GetExpectedNamespaces("lacework")
	namespaces := make(map[string]bool)
	if len(expectedNs) == 0 {
		namespaces = map[string]bool{"lacework": true, "kube-system": true}
	} else {
		for _, ns := range expectedNs {
			namespaces[ns] = true
		}
	}

	for _, ds := range allDaemonSets {
		if !namespaces[ds.Namespace] {
			continue
		}
		if strings.Contains(strings.ToLower(ds.Name), "lacework") {
			// Verify by image using SDK
			for _, container := range ds.Spec.Template.Spec.Containers {
				if verifyAuditEngineImage(container.Image, "lacework") {
					info.Name = "Lacework"
					info.Namespace = ds.Namespace
					info.TotalPods = int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning = int(ds.Status.NumberReady)
					info.ImageVerified = true
					break
				}
			}
			if info.ImageVerified {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}

// ============================================================================
// Build Findings
// ============================================================================

func buildAuditAdmissionFindings(allPods []corev1.Pod,
	falco FalcoInfo, tetragon TetragonInfo, kubearmor KubeArmorInfo,
	tracee TraceeInfo, sysdig SysdigInfo,
	prismaCloud PrismaCloudInfo, aquaSecurity AquaInfo,
	stackrox StackRoxInfo, neuvector NeuVectorInfo,
	crowdstrike CrowdStrikeInfo, kubescape KubescapeRuntimeInfo,
	deepfence DeepfenceInfo, wizRuntime WizRuntimeInfo, lacework LaceworkInfo,
	kubeArmorPolicies []KubeArmorPolicyInfo) []AuditAdmissionFinding {

	// Initialize findings per namespace
	namespaceData := make(map[string]*AuditAdmissionFinding)
	for _, ns := range globals.K8sNamespaces {
		namespaceData[ns] = &AuditAdmissionFinding{
			Namespace: ns,
		}
	}

	// Count pods per namespace for coverage metrics from pre-fetched pods
	podCountsByNS := make(map[string]int)
	for _, pod := range allPods {
		if pod.Status.Phase == corev1.PodRunning {
			podCountsByNS[pod.Namespace]++
		}
	}
	for ns, finding := range namespaceData {
		finding.UnmonitoredPods = podCountsByNS[ns] // Will be adjusted below if detection is active
	}

	// Cluster-wide detection tools
	clusterTools := []string{}

	if falco.Status == "active" {
		clusterTools = append(clusterTools, "Falco")
		for _, finding := range namespaceData {
			finding.FalcoActive = true
			finding.FalcoRules = falco.RulesCount
		}
	}

	if tetragon.Status == "active" {
		clusterTools = append(clusterTools, "Tetragon")
		for _, finding := range namespaceData {
			finding.TetragonActive = true
			finding.TetragonPolicies = tetragon.Policies
		}
	}

	if kubearmor.Status == "active" {
		clusterTools = append(clusterTools, "KubeArmor")
		// Count policies per namespace
		nsPolicyCounts := make(map[string]int)
		for _, kp := range kubeArmorPolicies {
			if !kp.IsHost {
				nsPolicyCounts[kp.Namespace]++
			}
		}
		for ns, finding := range namespaceData {
			finding.KubeArmorActive = true
			finding.KubeArmorPolicies = nsPolicyCounts[ns]
		}
	}

	if tracee.Status == "active" {
		clusterTools = append(clusterTools, "Tracee")
		for _, finding := range namespaceData {
			finding.TraceeActive = true
		}
	}

	if sysdig.Status == "active" {
		clusterTools = append(clusterTools, "Sysdig")
		for _, finding := range namespaceData {
			finding.SysdigActive = true
		}
	}

	if prismaCloud.Status == "active" {
		clusterTools = append(clusterTools, "Prisma Cloud")
	}

	if aquaSecurity.Status == "active" {
		clusterTools = append(clusterTools, "Aqua Security")
	}

	if stackrox.Status == "active" {
		clusterTools = append(clusterTools, "StackRox/ACS")
	}

	if neuvector.Status == "active" {
		clusterTools = append(clusterTools, "NeuVector")
	}

	if crowdstrike.Status == "active" {
		clusterTools = append(clusterTools, "CrowdStrike Falcon")
	}

	if kubescape.Status == "active" {
		clusterTools = append(clusterTools, "Kubescape")
	}

	if deepfence.Status == "active" {
		clusterTools = append(clusterTools, "Deepfence")
	}

	if wizRuntime.Status == "active" {
		clusterTools = append(clusterTools, "Wiz Runtime")
	}

	if lacework.Status == "active" {
		clusterTools = append(clusterTools, "Lacework")
	}

	// Build findings list
	var findings []AuditAdmissionFinding
	for _, finding := range namespaceData {
		finding.DetectionTools = clusterTools
		finding.HasRuntimeDetection = len(clusterTools) > 0

		// Determine coverage level
		if len(clusterTools) >= 2 {
			finding.CoverageLevel = "Full"
		} else if len(clusterTools) == 1 {
			finding.CoverageLevel = "Partial"
		} else {
			finding.CoverageLevel = "None"
		}

		// Set pod monitoring counts based on detection coverage
		// Cluster-wide tools (Falco, Tetragon, Tracee, Sysdig, Prisma, Aqua) monitor all pods
		if finding.HasRuntimeDetection {
			finding.MonitoredPods = finding.UnmonitoredPods
			finding.UnmonitoredPods = 0
		}
		// Note: UnmonitoredPods was already set to total running pods earlier

		// Calculate risk level
		if !finding.HasRuntimeDetection {
			finding.SecurityIssues = append(finding.SecurityIssues, "No runtime detection")
		} else if finding.CoverageLevel == "Partial" {
		} else {
		}

		// Add tool-specific issues
		if finding.FalcoActive && falco.Status == "degraded" {
			finding.SecurityIssues = append(finding.SecurityIssues, "Falco degraded")
		}
		if finding.TetragonActive && tetragon.Status == "degraded" {
			finding.SecurityIssues = append(finding.SecurityIssues, "Tetragon degraded")
		}
		if finding.KubeArmorActive && kubearmor.DefaultPosture == "audit" {
			finding.SecurityIssues = append(finding.SecurityIssues, "KubeArmor audit-only")
		}

		findings = append(findings, *finding)
	}

	// Sort by namespace
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Namespace < findings[j].Namespace
	})

	return findings
}

func auditAdmissionContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// ============================================================================
// Loot Generation
// ============================================================================

func generateAuditAdmissionLoot(loot *shared.LootBuilder,
	findings []AuditAdmissionFinding,
	falco FalcoInfo, falcoRules []FalcoRuleInfo,
	tetragon TetragonInfo, tracingPolicies []TracingPolicyInfo,
	kubearmor KubeArmorInfo, kubeArmorPolicies []KubeArmorPolicyInfo,
	tracee TraceeInfo, sysdig SysdigInfo,
	k8sAuditPolicy K8sAuditPolicyInfo, prismaCloud PrismaCloudInfo, aquaSecurity AquaInfo,
	stackrox StackRoxInfo, neuvector NeuVectorInfo,
	auditLogDestinations []AuditLogDestinationInfo) {

	// Summary
	loot.Section("Summary").Add("# Runtime Detection Summary")
	loot.Section("Summary").Add("#")

	activeTools := 0
	if falco.Status == "active" {
		activeTools++
		loot.Section("Summary").Add(fmt.Sprintf("# Falco: ACTIVE (%d rules, driver: %s)", falco.RulesCount, falco.DriverType))
	} else if falco.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Falco: %s", falco.Status))
	}

	if tetragon.Status == "active" {
		activeTools++
		loot.Section("Summary").Add(fmt.Sprintf("# Tetragon: ACTIVE (%d policies)", tetragon.Policies))
	} else if tetragon.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Tetragon: %s", tetragon.Status))
	}

	if kubearmor.Status == "active" {
		activeTools++
		loot.Section("Summary").Add(fmt.Sprintf("# KubeArmor: ACTIVE (%d policies, %d host policies, default: %s)", kubearmor.Policies, kubearmor.HostPolicies, kubearmor.DefaultPosture))
	} else if kubearmor.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# KubeArmor: %s", kubearmor.Status))
	}

	if tracee.Status == "active" {
		activeTools++
		loot.Section("Summary").Add("# Tracee: ACTIVE")
	} else if tracee.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Tracee: %s", tracee.Status))
	}

	if sysdig.Status == "active" {
		activeTools++
		loot.Section("Summary").Add("# Sysdig: ACTIVE")
	} else if sysdig.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Sysdig: %s", sysdig.Status))
	}

	if prismaCloud.Status == "active" {
		activeTools++
		loot.Section("Summary").Add(fmt.Sprintf("# Prisma Cloud: ACTIVE (%d defenders)", prismaCloud.Defenders))
	} else if prismaCloud.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Prisma Cloud: %s", prismaCloud.Status))
	}

	if aquaSecurity.Status == "active" {
		activeTools++
		loot.Section("Summary").Add(fmt.Sprintf("# Aqua Security: ACTIVE (%d enforcers)", aquaSecurity.Enforcers))
	} else if aquaSecurity.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# Aqua Security: %s", aquaSecurity.Status))
	}

	if stackrox.Status == "active" {
		activeTools++
		loot.Section("Summary").Add(fmt.Sprintf("# StackRox/ACS: ACTIVE (central: %v, sensor: %v)", stackrox.CentralActive, stackrox.SensorActive))
	} else if stackrox.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# StackRox/ACS: %s", stackrox.Status))
	}

	if neuvector.Status == "active" {
		activeTools++
		loot.Section("Summary").Add(fmt.Sprintf("# NeuVector: ACTIVE (%d controllers, %d enforcers)", neuvector.Controllers, neuvector.Enforcers))
	} else if neuvector.Name != "" {
		loot.Section("Summary").Add(fmt.Sprintf("# NeuVector: %s", neuvector.Status))
	}

	// Kubernetes Audit Policy
	loot.Section("Summary").Add("#")
	if k8sAuditPolicy.Detected {
		loot.Section("Summary").Add(fmt.Sprintf("# K8s Audit Policy: DETECTED (level: %s, backend: %s, rules: %d)", k8sAuditPolicy.AuditLevel, k8sAuditPolicy.LogBackend, k8sAuditPolicy.PolicyRules))
	} else {
		loot.Section("Summary").Add("# K8s Audit Policy: NOT DETECTED")
	}

	if activeTools == 0 {
		loot.Section("Summary").Add("#")
		loot.Section("Summary").Add("# WARNING: No runtime detection tools found!")
		loot.Section("Summary").Add("# Cluster has NO visibility into runtime threats")
	}

	loot.Section("Summary").Add("#")

	// Bypass vectors
	loot.Section("BypassVectors").Add("# Detection Bypass Vectors")
	loot.Section("BypassVectors").Add("#")

	if falco.Status == "degraded" {
		loot.Section("BypassVectors").Add("# Falco: degraded - partial or no coverage")
	}
	if tetragon.Status == "degraded" {
		loot.Section("BypassVectors").Add("# Tetragon: degraded - partial or no coverage")
	}
	if kubearmor.DefaultPosture == "audit" {
		loot.Section("BypassVectors").Add("# KubeArmor: Default posture is audit - violations logged but not blocked")
	}

	// Recommendations
	loot.Section("Recommendations").Add("# Recommendations")
	loot.Section("Recommendations").Add("#")

	if activeTools == 0 {
		loot.Section("Recommendations").Add("# 1. Deploy runtime detection (recommended: Falco or Tetragon)")
		loot.Section("Recommendations").Add("#    Falco: helm install falco falcosecurity/falco -n falco --create-namespace")
		loot.Section("Recommendations").Add("#    Tetragon: helm install tetragon cilium/tetragon -n kube-system")
	}

	if kubearmor.Status == "active" && kubearmor.DefaultPosture == "audit" {
		loot.Section("Recommendations").Add("# 2. Consider switching KubeArmor to block mode for production")
	}

	// Commands
	loot.Section("Commands").Add("# Useful Commands")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check Falco logs:")
	loot.Section("Commands").Add("kubectl logs -l app=falco -n falco --tail=100")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check Tetragon events:")
	loot.Section("Commands").Add("kubectl logs -l app.kubernetes.io/name=tetragon -n kube-system -c export-stdout --tail=100")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check KubeArmor alerts:")
	loot.Section("Commands").Add("kubectl logs -l kubearmor-app=kubearmor -n kubearmor --tail=100 | grep -i alert")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List Tetragon policies:")
	loot.Section("Commands").Add("kubectl get tracingpolicies")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List KubeArmor policies:")
	loot.Section("Commands").Add("kubectl get kubearmorpolicies -A")
}

// ============================================================================
// Audit Log Destination Analysis
// ============================================================================

func analyzeAuditLogDestinations(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) []AuditLogDestinationInfo {
	var destinations []AuditLogDestinationInfo

	// 1. Check for Fluentd/Fluent Bit (common log forwarders) from pre-fetched DaemonSets
	fluentNamespaces := map[string]bool{"logging": true, "fluentd": true, "fluent-bit": true, "kube-system": true, "monitoring": true}
	fluentImagePatterns := []string{"fluentd", "fluent-bit", "fluent/"}

	for _, ds := range allDaemonSets {
		if !fluentNamespaces[ds.Namespace] {
			continue
		}

		for _, container := range ds.Spec.Template.Spec.Containers {
			matched := false
			for _, pattern := range fluentImagePatterns {
				if strings.Contains(strings.ToLower(container.Image), pattern) {
					destInfo := AuditLogDestinationInfo{
						Type:        "Fluentd/FluentBit",
						Name:        ds.Name,
						Namespace:   ds.Namespace,
						Status:      "active",
						Destination: "configured",
						TotalPods:   int(ds.Status.DesiredNumberScheduled),
						PodsRunning: int(ds.Status.NumberReady),
						Configured:  true,
					}

					if destInfo.PodsRunning < destInfo.TotalPods {
						destInfo.Status = "degraded"
					}

					// Check for audit log volume mounts
					for _, vol := range ds.Spec.Template.Spec.Volumes {
						if vol.HostPath != nil {
							if strings.Contains(vol.HostPath.Path, "audit") ||
								strings.Contains(vol.HostPath.Path, "/var/log/kube-apiserver") {
								destInfo.Destination = "audit-logs: " + vol.HostPath.Path
							}
						}
					}

					destinations = append(destinations, destInfo)
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}

	// 2. Check for Splunk forwarder from pre-fetched DaemonSets
	splunkNamespaces := map[string]bool{"splunk": true, "logging": true, "monitoring": true, "kube-system": true}
	for _, ds := range allDaemonSets {
		if !splunkNamespaces[ds.Namespace] {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			if strings.Contains(strings.ToLower(container.Image), "splunk") {
				destInfo := AuditLogDestinationInfo{
					Type:        "Splunk",
					Name:        ds.Name,
					Namespace:   ds.Namespace,
					Status:      "active",
					Destination: "splunk forwarder",
					TotalPods:   int(ds.Status.DesiredNumberScheduled),
					PodsRunning: int(ds.Status.NumberReady),
					Configured:  true,
				}

				if destInfo.PodsRunning < destInfo.TotalPods {
					destInfo.Status = "degraded"
				}

				destinations = append(destinations, destInfo)
				break
			}
		}
	}

	// 3. Check for cloud provider logging integrations - AWS CloudWatch
	cwNamespaces := map[string]bool{"amazon-cloudwatch": true, "aws-observability": true, "kube-system": true}
	for _, ds := range allDaemonSets {
		if !cwNamespaces[ds.Namespace] {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			if strings.Contains(strings.ToLower(container.Image), "cloudwatch") ||
				strings.Contains(strings.ToLower(ds.Name), "cloudwatch") {
				destInfo := AuditLogDestinationInfo{
					Type:        "CloudWatch",
					Name:        ds.Name,
					Namespace:   ds.Namespace,
					Status:      "active",
					Destination: "AWS CloudWatch Logs",
					TotalPods:   int(ds.Status.DesiredNumberScheduled),
					PodsRunning: int(ds.Status.NumberReady),
					Configured:  true,
				}

				if destInfo.PodsRunning < destInfo.TotalPods {
					destInfo.Status = "degraded"
				}

				destinations = append(destinations, destInfo)
				break
			}
		}
	}

	// 4. Check for Vector (Datadog/generic log collector)
	vectorNamespaces := map[string]bool{"vector": true, "logging": true, "monitoring": true, "datadog": true}
	for _, ds := range allDaemonSets {
		if !vectorNamespaces[ds.Namespace] {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			if strings.Contains(strings.ToLower(container.Image), "vector") ||
				strings.Contains(strings.ToLower(container.Image), "timberio/vector") {
				destInfo := AuditLogDestinationInfo{
					Type:        "Vector",
					Name:        ds.Name,
					Namespace:   ds.Namespace,
					Status:      "active",
					Destination: "vector pipeline",
					TotalPods:   int(ds.Status.DesiredNumberScheduled),
					PodsRunning: int(ds.Status.NumberReady),
					Configured:  true,
				}

				if destInfo.PodsRunning < destInfo.TotalPods {
					destInfo.Status = "degraded"
				}

				destinations = append(destinations, destInfo)
				break
			}
		}
	}

	// 5. Check for Datadog agent
	datadogNamespaces := map[string]bool{"datadog": true, "monitoring": true, "kube-system": true}
	for _, ds := range allDaemonSets {
		if !datadogNamespaces[ds.Namespace] {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			if strings.Contains(strings.ToLower(container.Image), "datadog") {
				destInfo := AuditLogDestinationInfo{
					Type:        "Datadog",
					Name:        ds.Name,
					Namespace:   ds.Namespace,
					Status:      "active",
					Destination: "Datadog platform",
					TotalPods:   int(ds.Status.DesiredNumberScheduled),
					PodsRunning: int(ds.Status.NumberReady),
					Configured:  true,
				}

				if destInfo.PodsRunning < destInfo.TotalPods {
					destInfo.Status = "degraded"
				}

				destinations = append(destinations, destInfo)
				break
			}
		}
	}

	// 6. Check kube-apiserver for audit webhook configuration from pre-fetched pods
	for _, pod := range allPods {
		if pod.Namespace == "kube-system" && pod.Labels["component"] == "kube-apiserver" {
			for _, container := range pod.Spec.Containers {
				for _, arg := range container.Command {
					if strings.Contains(arg, "--audit-webhook-config-file") {
						destinations = append(destinations, AuditLogDestinationInfo{
							Type:        "Webhook",
							Name:        "kube-apiserver",
							Namespace:   "kube-system",
							Status:      "active",
							Destination: "audit webhook",
							Configured:  true,
						})
					}
				}
			}
		}
	}

	// If no destinations found, add a warning
	if len(destinations) == 0 {
		destinations = append(destinations, AuditLogDestinationInfo{
			Type:       "None",
			Name:       "No audit log forwarding detected",
			Namespace:  "-",
			Status:     "not-configured",
		})
	}

	return destinations
}

// ============================================================================
// Cloud-Specific Logging Analysis
// ============================================================================

// AWSCloudWatchInfo represents AWS CloudWatch agent detection
type AWSCloudWatchInfo struct {
	Name           string
	Namespace      string
	Status         string
	PodsRunning    int
	TotalPods      int
	LogGroups      []string
	FluentBitUsed  bool
	ImageVerified  bool
}

// GCPCloudLoggingInfo represents GCP Cloud Logging agent detection
type GCPCloudLoggingInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	FluentdUsed   bool
	FluentBitUsed bool
	ImageVerified bool
}

// AzureMonitorInfo represents Azure Monitor Container Insights detection
type AzureMonitorInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	OMSAgentUsed  bool
	AMALogsUsed   bool
	ImageVerified bool
}

// analyzeAWSCloudWatch detects AWS CloudWatch agent and Fluent Bit for CloudWatch
func analyzeAWSCloudWatch(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) AWSCloudWatchInfo {
	info := AWSCloudWatchInfo{}

	// Check for CloudWatch agent or Fluent Bit for CloudWatch
	cloudwatchNs := map[string]bool{"amazon-cloudwatch": true, "kube-system": true, "logging": true, "aws-observability": true}

	for _, ds := range allDaemonSets {
		if !cloudwatchNs[ds.Namespace] {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			imageLower := strings.ToLower(container.Image)
			if strings.Contains(imageLower, "cloudwatch-agent") ||
				strings.Contains(imageLower, "amazon/cloudwatch") {
				info.Name = "AWS CloudWatch Agent"
				info.Namespace = ds.Namespace
				info.TotalPods = int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning = int(ds.Status.NumberReady)
				info.ImageVerified = verifyAuditEngineImage(container.Image, "aws-cloudwatch")
				break
			}
			if strings.Contains(imageLower, "aws-for-fluent-bit") ||
				(strings.Contains(imageLower, "fluent-bit") && strings.Contains(imageLower, "aws")) {
				info.Name = "AWS Fluent Bit"
				info.Namespace = ds.Namespace
				info.TotalPods = int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning = int(ds.Status.NumberReady)
				info.FluentBitUsed = true
				info.ImageVerified = verifyAuditEngineImage(container.Image, "aws-cloudwatch")
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}

// analyzeGCPCloudLogging detects GCP Cloud Logging agents
func analyzeGCPCloudLogging(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) GCPCloudLoggingInfo {
	info := GCPCloudLoggingInfo{}

	// Check for GCP logging agents
	gkeNs := map[string]bool{"kube-system": true, "gke-system": true}

	for _, ds := range allDaemonSets {
		if !gkeNs[ds.Namespace] {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			imageLower := strings.ToLower(container.Image)
			if strings.Contains(imageLower, "stackdriver-logging") ||
				strings.Contains(imageLower, "fluentd-gcp") ||
				strings.Contains(imageLower, "gke-logging") {
				info.Name = "GCP Cloud Logging"
				info.Namespace = ds.Namespace
				info.TotalPods = int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning = int(ds.Status.NumberReady)
				info.FluentdUsed = strings.Contains(imageLower, "fluentd")
				info.ImageVerified = verifyAuditEngineImage(container.Image, "gcp-cloud-logging")
				break
			}
			if strings.Contains(imageLower, "fluent-bit-gke") {
				info.Name = "GCP Cloud Logging (Fluent Bit)"
				info.Namespace = ds.Namespace
				info.TotalPods = int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning = int(ds.Status.NumberReady)
				info.FluentBitUsed = true
				info.ImageVerified = verifyAuditEngineImage(container.Image, "gcp-cloud-logging")
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}

// analyzeAzureMonitor detects Azure Monitor Container Insights
func analyzeAzureMonitor(allDaemonSets []appsv1.DaemonSet, allPods []corev1.Pod) AzureMonitorInfo {
	info := AzureMonitorInfo{}

	// Check for Azure Monitor agents
	aksNs := map[string]bool{"kube-system": true, "azure-monitor": true}

	for _, ds := range allDaemonSets {
		if !aksNs[ds.Namespace] {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			imageLower := strings.ToLower(container.Image)
			if strings.Contains(imageLower, "omsagent") ||
				strings.Contains(imageLower, "oms-agent") {
				info.Name = "Azure Monitor (OMS Agent)"
				info.Namespace = ds.Namespace
				info.TotalPods = int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning = int(ds.Status.NumberReady)
				info.OMSAgentUsed = true
				info.ImageVerified = verifyAuditEngineImage(container.Image, "azure-monitor")
				break
			}
			if strings.Contains(imageLower, "ama-logs") ||
				strings.Contains(imageLower, "azure-monitor-agent") {
				info.Name = "Azure Monitor Agent"
				info.Namespace = ds.Namespace
				info.TotalPods = int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning = int(ds.Status.NumberReady)
				info.AMALogsUsed = true
				info.ImageVerified = verifyAuditEngineImage(container.Image, "azure-monitor")
				break
			}
		}
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
		}
	} else {
		info.Status = "not-running"
	}

	return info
}
