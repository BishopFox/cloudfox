package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_AUDIT_ADMISSION_MODULE_NAME = "audit-admission"

var AuditAdmissionCmd = &cobra.Command{
	Use:     "audit-admission",
	Aliases: []string{"runtime-detection", "security-monitoring"},
	Short:   "Analyze runtime security monitoring and audit configurations",
	Long: `
Analyze all cluster runtime security monitoring configurations including:
  - Falco (DaemonSet, FalcoRules)
  - Tetragon (TracingPolicy CRDs)
  - KubeArmor (KubeArmorPolicy CRDs)
  - Tracee (Aqua)
  - Sysdig Secure Runtime
  - Kubernetes Audit Policy
  - Coverage gap analysis
  - Detection bypass vectors

  cloudfox kubernetes audit-admission`,
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
	RiskLevel      string
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
	BypassRisk       string
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
	BypassRisk     string
}

// TetragonInfo represents Tetragon deployment status
type TetragonInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Policies      int
	BypassRisk    string
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
	BypassRisk   string
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
	BypassRisk     string
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
	BypassRisk string
}

// TraceeInfo represents Tracee deployment status
type TraceeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Policies      int
	BypassRisk    string
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
	BypassRisk    string
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
	BypassRisk      string
}

// PrismaCloudInfo represents Prisma Cloud/Twistlock status
type PrismaCloudInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Defenders     int
	BypassRisk    string
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
	BypassRisk    string
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
	BypassRisk    string
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
	BypassRisk    string
	ImageVerified bool // True if NeuVector image was verified
}

// CrowdStrikeInfo represents CrowdStrike Falcon runtime security status
type CrowdStrikeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	BypassRisk    string
	ImageVerified bool // True if CrowdStrike Falcon image was verified
}

// KubescapeRuntimeInfo represents Kubescape runtime security status
type KubescapeRuntimeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	BypassRisk    string
	ImageVerified bool // True if Kubescape image was verified
}

// DeepfenceInfo represents Deepfence ThreatMapper status
type DeepfenceInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	BypassRisk    string
	ImageVerified bool // True if Deepfence image was verified
}

// WizRuntimeInfo represents Wiz Runtime Sensor status
type WizRuntimeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	BypassRisk    string
	ImageVerified bool // True if Wiz sensor image was verified
}

// LaceworkInfo represents Lacework agent status
type LaceworkInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	BypassRisk    string
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
	BypassRisk  string
}

// verifyAuditEngineImage checks if an image matches known patterns for the specified engine
// Now uses the shared admission SDK for centralized engine detection
func verifyAuditEngineImage(image string, engine string) bool {
	return VerifyControllerImage(image, engine)
}

func ListAuditAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

	logger.InfoM(fmt.Sprintf("Analyzing audit/detection for %s", globals.ClusterName), K8S_AUDIT_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Analyze Falco
	logger.InfoM("Analyzing Falco...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	falco, falcoRules := analyzeFalco(ctx, clientset, dynClient)

	// Analyze Tetragon
	logger.InfoM("Analyzing Tetragon...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	tetragon, tracingPolicies := analyzeTetragon(ctx, clientset, dynClient)

	// Analyze KubeArmor
	logger.InfoM("Analyzing KubeArmor...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	kubearmor, kubeArmorPolicies := analyzeKubeArmor(ctx, clientset, dynClient)

	// Analyze Tracee
	logger.InfoM("Analyzing Tracee...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	tracee := analyzeTracee(ctx, clientset, dynClient)

	// Analyze Sysdig
	logger.InfoM("Analyzing Sysdig...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	sysdig := analyzeSysdig(ctx, clientset, dynClient)

	// Analyze Kubernetes Audit Policy
	logger.InfoM("Analyzing Kubernetes Audit Policy...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	k8sAuditPolicy := analyzeK8sAuditPolicy(ctx, clientset)

	// Analyze Prisma Cloud
	logger.InfoM("Analyzing Prisma Cloud...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	prismaCloud := auditAnalyzePrismaCloud(ctx, clientset)

	// Analyze Aqua Security
	logger.InfoM("Analyzing Aqua Security...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	aquaSecurity := auditAnalyzeAquaSecurity(ctx, clientset)

	// Analyze StackRox/Red Hat ACS
	logger.InfoM("Analyzing StackRox/Red Hat ACS...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	stackrox := auditAnalyzeStackRox(ctx, clientset)

	// Analyze NeuVector
	logger.InfoM("Analyzing NeuVector...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	neuvector := auditAnalyzeNeuVector(ctx, clientset)

	// Analyze CrowdStrike Falcon
	logger.InfoM("Analyzing CrowdStrike Falcon...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	crowdstrike := auditAnalyzeCrowdStrike(ctx, clientset)

	// Analyze Kubescape Runtime
	logger.InfoM("Analyzing Kubescape Runtime...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	kubescape := auditAnalyzeKubescape(ctx, clientset)

	// Analyze Deepfence
	logger.InfoM("Analyzing Deepfence ThreatMapper...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	deepfence := auditAnalyzeDeepfence(ctx, clientset)

	// Analyze Wiz Runtime
	logger.InfoM("Analyzing Wiz Runtime Sensor...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	wizRuntime := auditAnalyzeWiz(ctx, clientset)

	// Analyze Lacework
	logger.InfoM("Analyzing Lacework...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	lacework := auditAnalyzeLacework(ctx, clientset)

	// Analyze Audit Log Destinations
	logger.InfoM("Analyzing audit log destinations...", K8S_AUDIT_ADMISSION_MODULE_NAME)
	auditLogDestinations := analyzeAuditLogDestinations(ctx, clientset)

	// Build findings per namespace
	findings := buildAuditAdmissionFindings(ctx, clientset, falco, tetragon, kubearmor, tracee, sysdig, prismaCloud, aquaSecurity, stackrox, neuvector, crowdstrike, kubescape, deepfence, wizRuntime, lacework, kubeArmorPolicies)

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
		"Risk Level",
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
		"Bypass Risk",
	}

	falcoRulesHeader := []string{
		"Name",
		"Namespace",
		"Source",
		"Priority",
		"Enabled",
		"Tags",
		"Bypass Risk",
	}

	tetragonHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Policies",
		"Bypass Risk",
	}

	tracingPolicyHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"Selectors",
		"Kprobes",
		"Tracepoints",
		"Actions",
		"Bypass Risk",
	}

	kubeArmorHeader := []string{
		"Namespace",
		"Status",
		"Pods Running",
		"Policies",
		"Host Policies",
		"Default Posture",
		"Bypass Risk",
	}

	kubeArmorPolicyHeader := []string{
		"Name",
		"Namespace",
		"Type",
		"Selector",
		"Action",
		"File Rules",
		"Process Rules",
		"Network Rules",
		"Bypass Risk",
	}

	auditLogDestHeader := []string{
		"Type",
		"Name",
		"Namespace",
		"Status",
		"Destination",
		"Pods Running",
		"Bypass Risk",
	}

	var summaryRows [][]string
	var falcoRows [][]string
	var falcoRulesRows [][]string
	var tetragonRows [][]string
	var tracingPolicyRows [][]string
	var kubeArmorRows [][]string
	var kubeArmorPolicyRows [][]string
	var auditLogDestRows [][]string

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
			finding.RiskLevel,
			issues,
		})
	}

	// Build Falco rows
	if falco.Name != "" {
		outputChannels := "-"
		if len(falco.OutputChannels) > 0 {
			outputChannels = strings.Join(falco.OutputChannels, ", ")
		}

		falcoRows = append(falcoRows, []string{
			falco.Namespace,
			falco.Status,
			fmt.Sprintf("%d/%d", falco.PodsRunning, falco.TotalPods),
			falco.DriverType,
			fmt.Sprintf("%d", falco.RulesCount),
			fmt.Sprintf("%d", falco.CustomRulesCount),
			outputChannels,
			falco.BypassRisk,
		})
	}

	// Build Falco Rules rows
	for _, rule := range falcoRules {
		enabled := "No"
		if rule.Enabled {
			enabled = "Yes"
		}

		tags := "-"
		if len(rule.Tags) > 0 {
			if len(rule.Tags) > 3 {
				tags = strings.Join(rule.Tags[:3], ", ") + "..."
			} else {
				tags = strings.Join(rule.Tags, ", ")
			}
		}

		falcoRulesRows = append(falcoRulesRows, []string{
			rule.Name,
			rule.Namespace,
			rule.Source,
			rule.Priority,
			enabled,
			tags,
			rule.BypassRisk,
		})
	}

	// Build Tetragon rows
	if tetragon.Name != "" {
		tetragonRows = append(tetragonRows, []string{
			tetragon.Namespace,
			tetragon.Status,
			fmt.Sprintf("%d/%d", tetragon.PodsRunning, tetragon.TotalPods),
			fmt.Sprintf("%d", tetragon.Policies),
			tetragon.BypassRisk,
		})
	}

	// Build TracingPolicy rows
	for _, tp := range tracingPolicies {
		scope := "Namespace"
		ns := tp.Namespace
		if tp.IsCluster {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		selectors := "-"
		if len(tp.Selectors) > 0 {
			if len(tp.Selectors) > 2 {
				selectors = strings.Join(tp.Selectors[:2], ", ") + "..."
			} else {
				selectors = strings.Join(tp.Selectors, ", ")
			}
		}

		actions := "-"
		if len(tp.Actions) > 0 {
			actions = strings.Join(tp.Actions, ", ")
		}

		tracingPolicyRows = append(tracingPolicyRows, []string{
			tp.Name,
			ns,
			scope,
			selectors,
			fmt.Sprintf("%d", tp.Kprobes),
			fmt.Sprintf("%d", tp.Tracepoints),
			actions,
			tp.BypassRisk,
		})
	}

	// Build KubeArmor rows
	if kubearmor.Name != "" {
		kubeArmorRows = append(kubeArmorRows, []string{
			kubearmor.Namespace,
			kubearmor.Status,
			fmt.Sprintf("%d/%d", kubearmor.PodsRunning, kubearmor.TotalPods),
			fmt.Sprintf("%d", kubearmor.Policies),
			fmt.Sprintf("%d", kubearmor.HostPolicies),
			kubearmor.DefaultPosture,
			kubearmor.BypassRisk,
		})
	}

	// Build KubeArmor Policy rows
	for _, kp := range kubeArmorPolicies {
		policyType := "Pod"
		if kp.IsHost {
			policyType = "Host"
		}

		kubeArmorPolicyRows = append(kubeArmorPolicyRows, []string{
			kp.Name,
			kp.Namespace,
			policyType,
			kp.Selector,
			kp.Action,
			fmt.Sprintf("%d", kp.FileRules),
			fmt.Sprintf("%d", kp.ProcRules),
			fmt.Sprintf("%d", kp.NetRules),
			kp.BypassRisk,
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

		bypassRisk := "-"
		if dest.BypassRisk != "" {
			bypassRisk = dest.BypassRisk
		}

		auditLogDestRows = append(auditLogDestRows, []string{
			dest.Type,
			dest.Name,
			dest.Namespace,
			dest.Status,
			destination,
			podsRunning,
			bypassRisk,
		})
	}

	// Generate loot
	generateAuditAdmissionLoot(loot, findings, falco, falcoRules, tetragon, tracingPolicies, kubearmor, kubeArmorPolicies, tracee, sysdig, k8sAuditPolicy, prismaCloud, aquaSecurity, stackrox, neuvector, auditLogDestinations)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Audit-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

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

	err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"Audit-Admission",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_AUDIT_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// Falco Analysis
// ============================================================================

func analyzeFalco(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (FalcoInfo, []FalcoRuleInfo) {
	info := FalcoInfo{}
	var rules []FalcoRuleInfo

	// Check for Falco DaemonSet
	namespaces := []string{"falco", "falco-system", "security", "kube-system"}
	labelSelectors := []string{
		"app=falco",
		"app.kubernetes.io/name=falco",
	}

	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			nameLC := strings.ToLower(ds.Name)
			if strings.Contains(nameLC, "falco") && !strings.Contains(nameLC, "sidekick") && !strings.Contains(nameLC, "exporter") {
				info.Name = "Falco"
				info.Namespace = ns
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
		if info.Name != "" {
			break
		}
	}

	// Also check via label selectors
	if info.Name == "" {
		for _, ns := range namespaces {
			for _, selector := range labelSelectors {
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
				if err == nil && len(pods.Items) > 0 {
					info.Name = "Falco"
					info.Namespace = ns
					info.TotalPods = len(pods.Items)
					for _, pod := range pods.Items {
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
					}
					info.DriverType = "unknown"
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
	}

	if info.Name == "" {
		return info, rules
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
		info.BypassRisk = "Falco pods not running - no runtime detection"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
		info.BypassRisk = fmt.Sprintf("Only %d/%d Falco pods running", info.PodsRunning, info.TotalPods)
	} else {
		info.Status = "active"
	}

	// Check for Falcosidekick (output channels)
	sidekickPods, err := clientset.CoreV1().Pods(info.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=falcosidekick",
	})
	if err == nil && len(sidekickPods.Items) > 0 {
		info.OutputChannels = append(info.OutputChannels, "falcosidekick")
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

	// Check ConfigMaps for rules
	configMaps, err := clientset.CoreV1().ConfigMaps(info.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "falco") && strings.Contains(cm.Name, "rules") {
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
		rule.BypassRisk = "Rule disabled"
	}

	return rule
}

// ============================================================================
// Tetragon Analysis
// ============================================================================

func analyzeTetragon(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (TetragonInfo, []TracingPolicyInfo) {
	info := TetragonInfo{}
	var policies []TracingPolicyInfo

	// Check for Tetragon DaemonSet
	namespaces := []string{"kube-system", "tetragon", "cilium"}
	labelSelectors := []string{
		"app.kubernetes.io/name=tetragon",
		"k8s-app=tetragon",
	}

	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "tetragon") {
				info.Name = "Tetragon"
				info.Namespace = ns
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
		if info.Name != "" {
			break
		}
	}

	// Also check via label selectors
	if info.Name == "" {
		for _, ns := range namespaces {
			for _, selector := range labelSelectors {
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
				if err == nil && len(pods.Items) > 0 {
					info.Name = "Tetragon"
					info.Namespace = ns
					info.TotalPods = len(pods.Items)
					for _, pod := range pods.Items {
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
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
	}

	if info.Name == "" {
		return info, policies
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
		info.BypassRisk = "Tetragon pods not running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
		info.BypassRisk = fmt.Sprintf("Only %d/%d Tetragon pods running", info.PodsRunning, info.TotalPods)
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
		policy.BypassRisk = "No probes defined"
	}

	return policy
}

// ============================================================================
// KubeArmor Analysis
// ============================================================================

func analyzeKubeArmor(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (KubeArmorInfo, []KubeArmorPolicyInfo) {
	info := KubeArmorInfo{}
	var policies []KubeArmorPolicyInfo

	// Check for KubeArmor DaemonSet
	namespaces := []string{"kubearmor", "kube-system", "security"}
	labelSelectors := []string{
		"kubearmor-app=kubearmor",
		"app.kubernetes.io/name=kubearmor",
	}

	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "kubearmor") {
				info.Name = "KubeArmor"
				info.Namespace = ns
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
		if info.Name != "" {
			break
		}
	}

	// Also check via label selectors
	if info.Name == "" {
		for _, ns := range namespaces {
			for _, selector := range labelSelectors {
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
				if err == nil && len(pods.Items) > 0 {
					info.Name = "KubeArmor"
					info.Namespace = ns
					info.TotalPods = len(pods.Items)
					for _, pod := range pods.Items {
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
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
	}

	if info.Name == "" {
		return info, policies
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
		info.BypassRisk = "KubeArmor pods not running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
		info.BypassRisk = fmt.Sprintf("Only %d/%d KubeArmor pods running", info.PodsRunning, info.TotalPods)
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

	// Check default posture from ConfigMap
	cm, err := clientset.CoreV1().ConfigMaps(info.Namespace).Get(ctx, "kubearmor-config", metav1.GetOptions{})
	if err == nil {
		if posture, ok := cm.Data["defaultFilePosture"]; ok {
			info.DefaultPosture = posture
		}
	}

	if info.DefaultPosture == "audit" {
		info.BypassRisk = "Default posture is audit - violations are logged but not blocked"
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
		policy.BypassRisk = "Audit-only - violations not blocked"
	}

	return policy
}

// ============================================================================
// Tracee Analysis
// ============================================================================

func analyzeTracee(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) TraceeInfo {
	info := TraceeInfo{}

	// Check for Tracee DaemonSet
	namespaces := []string{"tracee", "tracee-system", "aqua", "kube-system"}
	labelSelectors := []string{
		"app.kubernetes.io/name=tracee",
		"app=tracee",
	}

	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "tracee") {
				info.Name = "Tracee"
				info.Namespace = ns
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
		if info.Name != "" {
			break
		}
	}

	// Also check via label selectors
	if info.Name == "" {
		for _, ns := range namespaces {
			for _, selector := range labelSelectors {
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
				if err == nil && len(pods.Items) > 0 {
					info.Name = "Tracee"
					info.Namespace = ns
					info.TotalPods = len(pods.Items)
					for _, pod := range pods.Items {
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
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
		info.BypassRisk = "Tracee pods not running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
		info.BypassRisk = fmt.Sprintf("Only %d/%d Tracee pods running", info.PodsRunning, info.TotalPods)
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// Sysdig Analysis
// ============================================================================

func analyzeSysdig(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) SysdigInfo {
	info := SysdigInfo{}

	// Check for Sysdig Agent DaemonSet
	namespaces := []string{"sysdig", "sysdig-agent", "kube-system"}
	labelSelectors := []string{
		"app=sysdig-agent",
		"app.kubernetes.io/name=sysdig-agent",
	}

	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "sysdig") {
				info.Name = "Sysdig"
				info.Namespace = ns
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
		if info.Name != "" {
			break
		}
	}

	// Also check via label selectors
	if info.Name == "" {
		for _, ns := range namespaces {
			for _, selector := range labelSelectors {
				pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
				if err == nil && len(pods.Items) > 0 {
					info.Name = "Sysdig"
					info.Namespace = ns
					info.TotalPods = len(pods.Items)
					for _, pod := range pods.Items {
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
					break
				}
			}
			if info.Name != "" {
				break
			}
		}
	}

	if info.Name == "" {
		return info
	}

	// Set status
	if info.PodsRunning == 0 {
		info.Status = "not-running"
		info.BypassRisk = "Sysdig pods not running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
		info.BypassRisk = fmt.Sprintf("Only %d/%d Sysdig pods running", info.PodsRunning, info.TotalPods)
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// Kubernetes Audit Policy Analysis
// ============================================================================

func analyzeK8sAuditPolicy(ctx context.Context, clientset kubernetes.Interface) K8sAuditPolicyInfo {
	info := K8sAuditPolicyInfo{}

	// Check for audit policy ConfigMap (common in managed clusters)
	auditConfigMaps := []struct {
		namespace string
		name      string
	}{
		{"kube-system", "audit-policy"},
		{"kube-system", "kube-apiserver-audit-policy"},
		{"kube-system", "audit"},
	}

	for _, cm := range auditConfigMaps {
		configMap, err := clientset.CoreV1().ConfigMaps(cm.namespace).Get(ctx, cm.name, metav1.GetOptions{})
		if err == nil {
			info.Detected = true
			info.PolicySource = "configmap"

			// Parse audit policy
			for key, data := range configMap.Data {
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
						info.BypassRisk = "Audit level None - no audit logging"
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

	// Check kube-apiserver pod for audit flags (if accessible)
	pods, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err == nil && len(pods.Items) > 0 {
		for _, pod := range pods.Items {
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
		info.BypassRisk = "No audit policy detected"
	} else if info.AuditLevel == "None" || info.AuditLevel == "" {
		info.BypassRisk = "Audit logging may not capture events"
	} else if len(info.OmitStages) > 0 {
		info.BypassRisk = fmt.Sprintf("Omitting stages: %s", strings.Join(info.OmitStages, ", "))
	}

	return info
}

// ============================================================================
// Prisma Cloud/Twistlock Analysis
// ============================================================================

func auditAnalyzePrismaCloud(ctx context.Context, clientset kubernetes.Interface) PrismaCloudInfo {
	info := PrismaCloudInfo{}

	// Check for Prisma Cloud Defender DaemonSet
	namespaces := []string{"twistlock", "prisma-cloud", "pcc"}
	imagePatterns := []string{"twistlock", "prismacloud", "registry.twistlock.com"}

	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			// Verify by image name to reduce false positives
			for _, container := range ds.Spec.Template.Spec.Containers {
				for _, pattern := range imagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						info.Name = "Prisma Cloud"
						info.Namespace = ns
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
		info.BypassRisk = "Prisma Cloud defenders not running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
		info.BypassRisk = fmt.Sprintf("Only %d/%d defenders running", info.PodsRunning, info.TotalPods)
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// Aqua Security Analysis
// ============================================================================

func auditAnalyzeAquaSecurity(ctx context.Context, clientset kubernetes.Interface) AquaInfo {
	info := AquaInfo{}

	// Check for Aqua Enforcer DaemonSet
	namespaces := []string{"aqua", "aqua-security", "kube-system"}
	imagePatterns := []string{"aquasec", "aqua-enforcer", "registry.aquasec.com"}

	for _, ns := range namespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			// Verify by image name to reduce false positives
			for _, container := range ds.Spec.Template.Spec.Containers {
				for _, pattern := range imagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						info.Name = "Aqua Security"
						info.Namespace = ns
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
		info.BypassRisk = "Aqua enforcers not running"
	} else if info.PodsRunning < info.TotalPods {
		info.Status = "degraded"
		info.BypassRisk = fmt.Sprintf("Only %d/%d enforcers running", info.PodsRunning, info.TotalPods)
	} else {
		info.Status = "active"
	}

	return info
}

// ============================================================================
// StackRox/Red Hat ACS Analysis
// ============================================================================

func auditAnalyzeStackRox(ctx context.Context, clientset kubernetes.Interface) StackRoxInfo {
	info := StackRoxInfo{}

	// Check for StackRox/RHACS deployment
	namespaces := []string{"stackrox", "rhacs-operator", "rhacs", "acs"}
	imagePatterns := []string{
		"stackrox",
		"advanced-cluster-security",
		"rhacs",
		"registry.redhat.io/advanced-cluster-security",
	}

	// Check for Central
	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "central") {
				// Verify by image
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, pattern := range imagePatterns {
						if strings.Contains(strings.ToLower(container.Image), pattern) {
							info.Name = "StackRox/ACS"
							info.Namespace = ns
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
		if info.Name != "" {
			break
		}
	}

	// Check for Sensor (daemonset or deployment)
	if info.Name != "" {
		// Check DaemonSets for collector
		daemonSets, err := clientset.AppsV1().DaemonSets(info.Namespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ds := range daemonSets.Items {
				if strings.Contains(strings.ToLower(ds.Name), "collector") ||
					strings.Contains(strings.ToLower(ds.Name), "sensor") {
					info.SensorActive = ds.Status.NumberReady > 0
					info.TotalPods += int(ds.Status.DesiredNumberScheduled)
					info.PodsRunning += int(ds.Status.NumberReady)
				}
			}
		}

		// Check Deployments for sensor
		deployments, err := clientset.AppsV1().Deployments(info.Namespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				if strings.Contains(strings.ToLower(dep.Name), "sensor") {
					info.SensorActive = dep.Status.ReadyReplicas > 0
					info.TotalPods += int(dep.Status.Replicas)
					info.PodsRunning += int(dep.Status.ReadyReplicas)
				}
			}
		}

		// Set status
		if info.CentralActive && info.SensorActive {
			info.Status = "active"
		} else if info.CentralActive || info.SensorActive {
			info.Status = "degraded"
			if !info.CentralActive {
				info.BypassRisk = "Central not running - no policy enforcement"
			} else {
				info.BypassRisk = "Sensor not running - no runtime visibility"
			}
		} else {
			info.Status = "not-running"
			info.BypassRisk = "StackRox components not running"
		}
	}

	return info
}

// ============================================================================
// NeuVector Analysis
// ============================================================================

func auditAnalyzeNeuVector(ctx context.Context, clientset kubernetes.Interface) NeuVectorInfo {
	info := NeuVectorInfo{}

	// Check for NeuVector deployment
	namespaces := []string{"neuvector", "nv-system", "kube-system"}
	imagePatterns := []string{
		"neuvector/controller",
		"neuvector/enforcer",
		"neuvector/manager",
		"docker.io/neuvector",
	}

	for _, ns := range namespaces {
		// Check for controller deployment
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, dep := range deployments.Items {
			if strings.Contains(strings.ToLower(dep.Name), "neuvector") &&
				strings.Contains(strings.ToLower(dep.Name), "controller") {
				// Verify by image
				for _, container := range dep.Spec.Template.Spec.Containers {
					for _, pattern := range imagePatterns {
						if strings.Contains(strings.ToLower(container.Image), pattern) {
							info.Name = "NeuVector"
							info.Namespace = ns
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
		if info.Name != "" {
			break
		}
	}

	if info.Name == "" {
		return info
	}

	// Check for enforcer DaemonSet
	daemonSets, err := clientset.AppsV1().DaemonSets(info.Namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "neuvector") &&
				strings.Contains(strings.ToLower(ds.Name), "enforcer") {
				info.Enforcers = int(ds.Status.NumberReady)
				info.TotalPods = int(ds.Status.DesiredNumberScheduled)
				info.PodsRunning = int(ds.Status.NumberReady)
				break
			}
		}
	}

	// Set status
	if info.Controllers > 0 && info.Enforcers > 0 {
		info.Status = "active"
		if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
			info.BypassRisk = fmt.Sprintf("Only %d/%d enforcers running", info.PodsRunning, info.TotalPods)
		}
	} else if info.Controllers > 0 {
		info.Status = "degraded"
		info.BypassRisk = "Enforcers not running - no runtime protection"
	} else {
		info.Status = "not-running"
		info.BypassRisk = "NeuVector components not running"
	}

	return info
}

// ============================================================================
// CrowdStrike Falcon Analysis
// ============================================================================

func auditAnalyzeCrowdStrike(ctx context.Context, clientset kubernetes.Interface) CrowdStrikeInfo {
	info := CrowdStrikeInfo{}

	// Check for CrowdStrike Falcon using SDK expected namespaces
	namespaces := GetExpectedNamespaces("crowdstrike")
	if len(namespaces) == 0 {
		namespaces = []string{"falcon-system", "crowdstrike", "kube-system"}
	}

	for _, ns := range namespaces {
		// Check for Falcon sensor DaemonSet
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "falcon") {
				// Verify by image using SDK
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "crowdstrike") {
						info.Name = "CrowdStrike Falcon"
						info.Namespace = ns
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
			info.BypassRisk = fmt.Sprintf("Only %d/%d Falcon sensors running", info.PodsRunning, info.TotalPods)
		}
	} else {
		info.Status = "not-running"
		info.BypassRisk = "CrowdStrike Falcon sensors not running"
	}

	return info
}

// ============================================================================
// Kubescape Runtime Analysis
// ============================================================================

func auditAnalyzeKubescape(ctx context.Context, clientset kubernetes.Interface) KubescapeRuntimeInfo {
	info := KubescapeRuntimeInfo{}

	// Check for Kubescape using SDK expected namespaces
	namespaces := GetExpectedNamespaces("kubescape-runtime")
	if len(namespaces) == 0 {
		namespaces = []string{"kubescape", "armo-system", "kube-system"}
	}

	for _, ns := range namespaces {
		// Check for Kubescape deployment or DaemonSet
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				if strings.Contains(strings.ToLower(dep.Name), "kubescape") ||
					strings.Contains(strings.ToLower(dep.Name), "operator") {
					// Verify by image using SDK
					for _, container := range dep.Spec.Template.Spec.Containers {
						if verifyAuditEngineImage(container.Image, "kubescape-runtime") {
							info.Name = "Kubescape"
							info.Namespace = ns
							info.TotalPods = int(dep.Status.Replicas)
							info.PodsRunning = int(dep.Status.ReadyReplicas)
							info.ImageVerified = true
							break
						}
					}
					if info.ImageVerified {
						break
					}
				}
			}
		}
		if info.Name != "" {
			break
		}

		// Also check for node-agent DaemonSet
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ds := range daemonSets.Items {
				if strings.Contains(strings.ToLower(ds.Name), "kubescape") ||
					strings.Contains(strings.ToLower(ds.Name), "node-agent") {
					// Verify by image using SDK
					for _, container := range ds.Spec.Template.Spec.Containers {
						if verifyAuditEngineImage(container.Image, "kubescape-runtime") {
							info.Name = "Kubescape"
							info.Namespace = ns
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
			info.BypassRisk = fmt.Sprintf("Only %d/%d Kubescape pods running", info.PodsRunning, info.TotalPods)
		}
	} else {
		info.Status = "not-running"
		info.BypassRisk = "Kubescape not running"
	}

	return info
}

// ============================================================================
// Deepfence ThreatMapper Analysis
// ============================================================================

func auditAnalyzeDeepfence(ctx context.Context, clientset kubernetes.Interface) DeepfenceInfo {
	info := DeepfenceInfo{}

	// Check for Deepfence using SDK expected namespaces
	namespaces := GetExpectedNamespaces("deepfence")
	if len(namespaces) == 0 {
		namespaces = []string{"deepfence", "kube-system"}
	}

	for _, ns := range namespaces {
		// Check for Deepfence agent DaemonSet
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "deepfence") {
				// Verify by image using SDK
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "deepfence") {
						info.Name = "Deepfence ThreatMapper"
						info.Namespace = ns
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
			info.BypassRisk = fmt.Sprintf("Only %d/%d Deepfence agents running", info.PodsRunning, info.TotalPods)
		}
	} else {
		info.Status = "not-running"
		info.BypassRisk = "Deepfence agents not running"
	}

	return info
}

// ============================================================================
// Wiz Runtime Sensor Analysis
// ============================================================================

func auditAnalyzeWiz(ctx context.Context, clientset kubernetes.Interface) WizRuntimeInfo {
	info := WizRuntimeInfo{}

	// Check for Wiz using SDK expected namespaces
	namespaces := GetExpectedNamespaces("wiz-runtime")
	if len(namespaces) == 0 {
		namespaces = []string{"wiz", "kube-system"}
	}

	for _, ns := range namespaces {
		// Check for Wiz sensor DaemonSet
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "wiz") {
				// Verify by image using SDK
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "wiz-runtime") {
						info.Name = "Wiz Runtime Sensor"
						info.Namespace = ns
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
		if info.Name != "" {
			break
		}

		// Also check deployments
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, dep := range deployments.Items {
				if strings.Contains(strings.ToLower(dep.Name), "wiz") {
					// Verify by image using SDK
					for _, container := range dep.Spec.Template.Spec.Containers {
						if verifyAuditEngineImage(container.Image, "wiz-runtime") {
							info.Name = "Wiz Runtime Sensor"
							info.Namespace = ns
							info.TotalPods = int(dep.Status.Replicas)
							info.PodsRunning = int(dep.Status.ReadyReplicas)
							info.ImageVerified = true
							break
						}
					}
					if info.ImageVerified {
						break
					}
				}
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
			info.BypassRisk = fmt.Sprintf("Only %d/%d Wiz sensors running", info.PodsRunning, info.TotalPods)
		}
	} else {
		info.Status = "not-running"
		info.BypassRisk = "Wiz sensors not running"
	}

	return info
}

// ============================================================================
// Lacework Analysis
// ============================================================================

func auditAnalyzeLacework(ctx context.Context, clientset kubernetes.Interface) LaceworkInfo {
	info := LaceworkInfo{}

	// Check for Lacework using SDK expected namespaces
	namespaces := GetExpectedNamespaces("lacework")
	if len(namespaces) == 0 {
		namespaces = []string{"lacework", "kube-system"}
	}

	for _, ns := range namespaces {
		// Check for Lacework agent DaemonSet
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			if strings.Contains(strings.ToLower(ds.Name), "lacework") {
				// Verify by image using SDK
				for _, container := range ds.Spec.Template.Spec.Containers {
					if verifyAuditEngineImage(container.Image, "lacework") {
						info.Name = "Lacework"
						info.Namespace = ns
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
			info.BypassRisk = fmt.Sprintf("Only %d/%d Lacework agents running", info.PodsRunning, info.TotalPods)
		}
	} else {
		info.Status = "not-running"
		info.BypassRisk = "Lacework agents not running"
	}

	return info
}

// ============================================================================
// Build Findings
// ============================================================================

func buildAuditAdmissionFindings(ctx context.Context, clientset kubernetes.Interface,
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

	// Count pods per namespace for coverage metrics
	for ns, finding := range namespaceData {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			// Count running pods (not monitoring system pods)
			runningPods := 0
			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning {
					runningPods++
				}
			}
			finding.UnmonitoredPods = runningPods // Will be adjusted below if detection is active
		}
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
			finding.RiskLevel = "CRITICAL"
			finding.SecurityIssues = append(finding.SecurityIssues, "No runtime detection")
		} else if finding.CoverageLevel == "Partial" {
			finding.RiskLevel = "MEDIUM"
		} else {
			finding.RiskLevel = "LOW"
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
		loot.Section("BypassVectors").Add(fmt.Sprintf("# Falco: %s", falco.BypassRisk))
	}
	if tetragon.Status == "degraded" {
		loot.Section("BypassVectors").Add(fmt.Sprintf("# Tetragon: %s", tetragon.BypassRisk))
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

func analyzeAuditLogDestinations(ctx context.Context, clientset kubernetes.Interface) []AuditLogDestinationInfo {
	var destinations []AuditLogDestinationInfo

	// 1. Check for Fluentd/Fluent Bit (common log forwarders)
	fluentNamespaces := []string{"logging", "fluentd", "fluent-bit", "kube-system", "monitoring"}
	fluentImagePatterns := []string{"fluentd", "fluent-bit", "fluent/"}

	for _, ns := range fluentNamespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			for _, container := range ds.Spec.Template.Spec.Containers {
				for _, pattern := range fluentImagePatterns {
					if strings.Contains(strings.ToLower(container.Image), pattern) {
						destInfo := AuditLogDestinationInfo{
							Type:        "Fluentd/FluentBit",
							Name:        ds.Name,
							Namespace:   ns,
							Status:      "active",
							Destination: "configured",
							TotalPods:   int(ds.Status.DesiredNumberScheduled),
							PodsRunning: int(ds.Status.NumberReady),
							Configured:  true,
						}

						if destInfo.PodsRunning < destInfo.TotalPods {
							destInfo.Status = "degraded"
							destInfo.BypassRisk = fmt.Sprintf("Only %d/%d pods running", destInfo.PodsRunning, destInfo.TotalPods)
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
						break
					}
				}
			}
		}
	}

	// 2. Check for Elasticsearch (common SIEM destination)
	esNamespaces := []string{"logging", "elasticsearch", "elastic-system", "monitoring"}
	for _, ns := range esNamespaces {
		statefulSets, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, sts := range statefulSets.Items {
			if strings.Contains(strings.ToLower(sts.Name), "elasticsearch") ||
				strings.Contains(strings.ToLower(sts.Name), "elastic") {
				// Verify by checking image
				isElastic := false
				for _, container := range sts.Spec.Template.Spec.Containers {
					if strings.Contains(strings.ToLower(container.Image), "elasticsearch") ||
						strings.Contains(strings.ToLower(container.Image), "elastic") {
						isElastic = true
						break
					}
				}

				if isElastic {
					destInfo := AuditLogDestinationInfo{
						Type:        "Elasticsearch",
						Name:        sts.Name,
						Namespace:   ns,
						Status:      "active",
						Destination: "elasticsearch cluster",
						TotalPods:   int(*sts.Spec.Replicas),
						PodsRunning: int(sts.Status.ReadyReplicas),
						Configured:  true,
					}

					if destInfo.PodsRunning < destInfo.TotalPods {
						destInfo.Status = "degraded"
						destInfo.BypassRisk = fmt.Sprintf("Only %d/%d replicas ready", destInfo.PodsRunning, destInfo.TotalPods)
					}

					destinations = append(destinations, destInfo)
				}
			}
		}
	}

	// 3. Check for Loki (Grafana logging)
	lokiNamespaces := []string{"loki", "grafana-loki", "monitoring", "logging"}
	for _, ns := range lokiNamespaces {
		statefulSets, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, sts := range statefulSets.Items {
			if strings.Contains(strings.ToLower(sts.Name), "loki") {
				// Verify by image
				isLoki := false
				for _, container := range sts.Spec.Template.Spec.Containers {
					if strings.Contains(strings.ToLower(container.Image), "loki") {
						isLoki = true
						break
					}
				}

				if isLoki {
					destInfo := AuditLogDestinationInfo{
						Type:        "Loki",
						Name:        sts.Name,
						Namespace:   ns,
						Status:      "active",
						Destination: "grafana loki",
						TotalPods:   int(*sts.Spec.Replicas),
						PodsRunning: int(sts.Status.ReadyReplicas),
						Configured:  true,
					}

					if destInfo.PodsRunning < destInfo.TotalPods {
						destInfo.Status = "degraded"
						destInfo.BypassRisk = fmt.Sprintf("Only %d/%d replicas ready", destInfo.PodsRunning, destInfo.TotalPods)
					}

					destinations = append(destinations, destInfo)
				}
			}
		}
	}

	// 4. Check for Splunk forwarder
	splunkNamespaces := []string{"splunk", "logging", "monitoring", "kube-system"}
	for _, ns := range splunkNamespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			for _, container := range ds.Spec.Template.Spec.Containers {
				if strings.Contains(strings.ToLower(container.Image), "splunk") {
					destInfo := AuditLogDestinationInfo{
						Type:        "Splunk",
						Name:        ds.Name,
						Namespace:   ns,
						Status:      "active",
						Destination: "splunk forwarder",
						TotalPods:   int(ds.Status.DesiredNumberScheduled),
						PodsRunning: int(ds.Status.NumberReady),
						Configured:  true,
					}

					if destInfo.PodsRunning < destInfo.TotalPods {
						destInfo.Status = "degraded"
						destInfo.BypassRisk = fmt.Sprintf("Only %d/%d pods running", destInfo.PodsRunning, destInfo.TotalPods)
					}

					destinations = append(destinations, destInfo)
					break
				}
			}
		}
	}

	// 5. Check for cloud provider logging integrations
	// AWS CloudWatch
	cwNamespaces := []string{"amazon-cloudwatch", "aws-observability", "kube-system"}
	for _, ns := range cwNamespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			for _, container := range ds.Spec.Template.Spec.Containers {
				if strings.Contains(strings.ToLower(container.Image), "cloudwatch") ||
					strings.Contains(strings.ToLower(ds.Name), "cloudwatch") {
					destInfo := AuditLogDestinationInfo{
						Type:        "CloudWatch",
						Name:        ds.Name,
						Namespace:   ns,
						Status:      "active",
						Destination: "AWS CloudWatch Logs",
						TotalPods:   int(ds.Status.DesiredNumberScheduled),
						PodsRunning: int(ds.Status.NumberReady),
						Configured:  true,
					}

					if destInfo.PodsRunning < destInfo.TotalPods {
						destInfo.Status = "degraded"
						destInfo.BypassRisk = fmt.Sprintf("Only %d/%d pods running", destInfo.PodsRunning, destInfo.TotalPods)
					}

					destinations = append(destinations, destInfo)
					break
				}
			}
		}
	}

	// 6. Check for Vector (Datadog/generic log collector)
	vectorNamespaces := []string{"vector", "logging", "monitoring", "datadog"}
	for _, ns := range vectorNamespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			for _, container := range ds.Spec.Template.Spec.Containers {
				if strings.Contains(strings.ToLower(container.Image), "vector") ||
					strings.Contains(strings.ToLower(container.Image), "timberio/vector") {
					destInfo := AuditLogDestinationInfo{
						Type:        "Vector",
						Name:        ds.Name,
						Namespace:   ns,
						Status:      "active",
						Destination: "vector pipeline",
						TotalPods:   int(ds.Status.DesiredNumberScheduled),
						PodsRunning: int(ds.Status.NumberReady),
						Configured:  true,
					}

					if destInfo.PodsRunning < destInfo.TotalPods {
						destInfo.Status = "degraded"
						destInfo.BypassRisk = fmt.Sprintf("Only %d/%d pods running", destInfo.PodsRunning, destInfo.TotalPods)
					}

					destinations = append(destinations, destInfo)
					break
				}
			}
		}
	}

	// 7. Check for Datadog agent
	datadogNamespaces := []string{"datadog", "monitoring", "kube-system"}
	for _, ns := range datadogNamespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ds := range daemonSets.Items {
			for _, container := range ds.Spec.Template.Spec.Containers {
				if strings.Contains(strings.ToLower(container.Image), "datadog") {
					destInfo := AuditLogDestinationInfo{
						Type:        "Datadog",
						Name:        ds.Name,
						Namespace:   ns,
						Status:      "active",
						Destination: "Datadog platform",
						TotalPods:   int(ds.Status.DesiredNumberScheduled),
						PodsRunning: int(ds.Status.NumberReady),
						Configured:  true,
					}

					if destInfo.PodsRunning < destInfo.TotalPods {
						destInfo.Status = "degraded"
						destInfo.BypassRisk = fmt.Sprintf("Only %d/%d pods running", destInfo.PodsRunning, destInfo.TotalPods)
					}

					destinations = append(destinations, destInfo)
					break
				}
			}
		}
	}

	// 8. Check kube-apiserver for audit webhook configuration
	pods, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err == nil && len(pods.Items) > 0 {
		for _, pod := range pods.Items {
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
			BypassRisk: "Audit logs may not be forwarded to SIEM",
		})
	}

	return destinations
}
