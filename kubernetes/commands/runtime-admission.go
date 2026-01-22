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
	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const K8S_RUNTIME_ADMISSION_MODULE_NAME = "runtime-admission"

var RuntimeAdmissionCmd = &cobra.Command{
	Use:     "runtime-admission",
	Aliases: []string{"runtime-security", "container-runtime"},
	Short:   "Analyze container runtime security configurations and policies",
	Long: `
Analyze all cluster runtime security configurations including:
  - RuntimeClasses (gVisor, Kata Containers, Firecracker, etc.)
  - Seccomp profiles (SeccompProfile CRDs, node profiles)
  - AppArmor profiles (node and pod configurations)
  - SELinux policies
  - Pod security context coverage
  - Sandboxed vs unsandboxed workload analysis
  - Runtime bypass detection

  cloudfox kubernetes runtime-admission`,
	Run: ListRuntimeAdmission,
}

type RuntimeAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t RuntimeAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t RuntimeAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// RuntimeAdmissionFinding represents runtime security analysis for a namespace
type RuntimeAdmissionFinding struct {
	Namespace string

	// Pod counts
	TotalPods           int
	SandboxedPods       int
	UnsandboxedPods     int
	SandboxedPercentage string

	// RuntimeClass usage
	RuntimeClassUsage   map[string]int // runtimeclass name -> pod count
	DefaultRuntimePods  int
	CustomRuntimePods   int

	// Seccomp coverage
	SeccompEnabled      int
	SeccompDisabled     int
	SeccompRuntimeDefault int
	SeccompLocalhost    int
	SeccompUnconfined   int
	SeccompCoverage     string

	// AppArmor coverage
	AppArmorEnabled     int
	AppArmorDisabled    int
	AppArmorRuntimeDefault int
	AppArmorLocalhost   int
	AppArmorUnconfined  int
	AppArmorCoverage    string

	// SELinux coverage
	SELinuxEnabled      int
	SELinuxDisabled     int
	SELinuxCoverage     string

	// Privileged pods (bypass runtime security)
	PrivilegedPods      int
	HostPIDPods         int
	HostNetworkPods     int
	HostIPCPods         int

	// Risk analysis
	RiskLevel           string
	SecurityIssues      []string
	Recommendations     []string
}

// RuntimeClassInfo represents a RuntimeClass configuration
type RuntimeClassInfo struct {
	Name           string
	Handler        string
	HandlerType    string // gvisor, kata, firecracker, runc, containerd, cri-o, etc.
	IsSandboxed    bool
	Scheduling     *nodev1.Scheduling
	Overhead       *nodev1.Overhead
	NodeSelector   map[string]string
	Tolerations    []string
	UsedByPods     int
	Namespaces     []string
	SecurityLevel  string // high, medium, low
	BypassRisk     string
}

// SeccompProfileInfo represents a Seccomp profile
type SeccompProfileInfo struct {
	Name            string
	Namespace       string
	IsClusterScoped bool
	ProfileType     string // SeccompProfile CRD or node profile
	Status          string
	TargetNodes     []string
	UsedByPods      int
	BypassRisk      string
}

// AppArmorProfileInfo represents an AppArmor profile
type AppArmorProfileInfo struct {
	Name         string
	Namespace    string
	ProfileType  string // AppArmorProfile CRD or node profile
	Status       string
	Enforced     bool
	TargetNodes  []string
	UsedByPods   int
	BypassRisk   string
}

// SeccompOperatorInfo represents Seccomp Operator status
type SeccompOperatorInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Profiles      int
	ImageVerified bool
	BypassRisk    string
}

// RuntimeFalcoInfo represents Falco runtime security configuration for runtime-admission
type RuntimeFalcoInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Version       string
	RulesLoaded   bool
	ImageVerified bool
	BypassRisk    string
}

// RuntimeTraceeInfo represents Tracee runtime security configuration for runtime-admission
type RuntimeTraceeInfo struct {
	Name          string
	Namespace     string
	Status        string
	PodsRunning   int
	TotalPods     int
	Version       string
	ImageVerified bool
	BypassRisk    string
}

// RuntimePSSInfo represents PSS enforcement configuration for runtime-admission
type RuntimePSSInfo struct {
	Namespace       string
	EnforceLevel    string // privileged, baseline, restricted
	AuditLevel      string
	WarnLevel       string
	EnforceVersion  string
	BypassRisk      string
}

// UnsandboxedPodInfo represents a pod without runtime sandboxing
type UnsandboxedPodInfo struct {
	Name            string
	Namespace       string
	RuntimeClass    string
	SeccompProfile  string
	AppArmorProfile string
	Privileged      bool
	HostPID         bool
	HostNetwork     bool
	Capabilities    []string
	RiskLevel       string
	RiskReasons     []string
}

func ListRuntimeAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")

	logger.InfoM(fmt.Sprintf("Analyzing runtime security for %s", globals.ClusterName), K8S_RUNTIME_ADMISSION_MODULE_NAME)

	clientset := config.GetClientOrExit()
	dynClient := config.GetDynamicClientOrExit()

	// Analyze RuntimeClasses
	logger.InfoM("Analyzing RuntimeClasses...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	runtimeClasses := analyzeRuntimeClasses(ctx, clientset)

	// Analyze Seccomp Operator and profiles
	logger.InfoM("Analyzing Seccomp profiles...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	seccompOperator, seccompProfiles := analyzeSeccompProfiles(ctx, clientset, dynClient)

	// Analyze AppArmor profiles
	logger.InfoM("Analyzing AppArmor profiles...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	appArmorProfiles := analyzeAppArmorProfiles(ctx, clientset, dynClient)

	// Analyze Falco
	logger.InfoM("Analyzing Falco runtime security...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	falco := analyzeRuntimeFalco(ctx, clientset)

	// Analyze Tracee
	logger.InfoM("Analyzing Tracee runtime security...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	tracee := analyzeRuntimeTracee(ctx, clientset)

	// Analyze Pod Security Standards
	logger.InfoM("Analyzing Pod Security Standards...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	pssResults := analyzeRuntimePSS(ctx, clientset)

	// Analyze pod runtime security
	logger.InfoM("Analyzing pod runtime security...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	findings, unsandboxedPods := analyzePodsRuntimeSecurity(ctx, clientset, runtimeClasses)

	// Update RuntimeClass usage counts
	updateRuntimeClassUsage(runtimeClasses, findings)

	// Generate tables
	summaryHeader := []string{
		"Namespace",
		"Total Pods",
		"Sandboxed",
		"Unsandboxed",
		"Sandbox %",
		"Seccomp Enabled",
		"Seccomp Coverage",
		"AppArmor Enabled",
		"AppArmor Coverage",
		"Privileged",
		"Risk Level",
		"Issues",
	}

	runtimeClassHeader := []string{
		"Name",
		"Handler",
		"Type",
		"Sandboxed",
		"Security Level",
		"Node Selector",
		"Used By Pods",
		"Namespaces",
		"Bypass Risk",
	}

	seccompProfileHeader := []string{
		"Name",
		"Namespace",
		"Scope",
		"Type",
		"Status",
		"Target Nodes",
		"Used By Pods",
		"Bypass Risk",
	}

	appArmorProfileHeader := []string{
		"Name",
		"Namespace",
		"Type",
		"Status",
		"Enforced",
		"Target Nodes",
		"Used By Pods",
		"Bypass Risk",
	}

	unsandboxedPodHeader := []string{
		"Name",
		"Namespace",
		"Runtime Class",
		"Seccomp",
		"AppArmor",
		"Privileged",
		"HostPID",
		"HostNetwork",
		"Capabilities",
		"Risk Level",
		"Risk Reasons",
	}

	runtimeSecurityToolsHeader := []string{
		"Tool",
		"Namespace",
		"Status",
		"Pods Running",
		"Total Pods",
		"Image Verified",
		"Bypass Risk",
	}

	pssHeader := []string{
		"Namespace",
		"Enforce Level",
		"Audit Level",
		"Warn Level",
		"Enforce Version",
		"Bypass Risk",
	}

	var summaryRows [][]string
	var runtimeClassRows [][]string
	var seccompProfileRows [][]string
	var appArmorProfileRows [][]string
	var unsandboxedPodRows [][]string
	var runtimeSecurityToolsRows [][]string
	var pssRows [][]string

	loot := shared.NewLootBuilder()

	// Build summary rows
	for _, finding := range findings {
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
			fmt.Sprintf("%d", finding.TotalPods),
			fmt.Sprintf("%d", finding.SandboxedPods),
			fmt.Sprintf("%d", finding.UnsandboxedPods),
			finding.SandboxedPercentage,
			fmt.Sprintf("%d", finding.SeccompEnabled),
			finding.SeccompCoverage,
			fmt.Sprintf("%d", finding.AppArmorEnabled),
			finding.AppArmorCoverage,
			fmt.Sprintf("%d", finding.PrivilegedPods),
			finding.RiskLevel,
			issues,
		})
	}

	// Build RuntimeClass rows
	for _, rc := range runtimeClasses {
		sandboxed := "No"
		if rc.IsSandboxed {
			sandboxed = "Yes"
		}

		nodeSelector := "-"
		if len(rc.NodeSelector) > 0 {
			var selectors []string
			for k, v := range rc.NodeSelector {
				selectors = append(selectors, fmt.Sprintf("%s=%s", k, v))
			}
			nodeSelector = strings.Join(selectors, ", ")
			if len(nodeSelector) > 40 {
				nodeSelector = nodeSelector[:37] + "..."
			}
		}

		namespaces := "-"
		if len(rc.Namespaces) > 0 {
			if len(rc.Namespaces) > 3 {
				namespaces = strings.Join(rc.Namespaces[:3], ", ") + fmt.Sprintf(" (+%d)", len(rc.Namespaces)-3)
			} else {
				namespaces = strings.Join(rc.Namespaces, ", ")
			}
		}

		runtimeClassRows = append(runtimeClassRows, []string{
			rc.Name,
			rc.Handler,
			rc.HandlerType,
			sandboxed,
			rc.SecurityLevel,
			nodeSelector,
			fmt.Sprintf("%d", rc.UsedByPods),
			namespaces,
			rc.BypassRisk,
		})
	}

	// Build Seccomp profile rows
	for _, sp := range seccompProfiles {
		scope := "Namespace"
		ns := sp.Namespace
		if sp.IsClusterScoped {
			scope = "Cluster"
			ns = "<CLUSTER>"
		}

		targetNodes := "-"
		if len(sp.TargetNodes) > 0 {
			if len(sp.TargetNodes) > 3 {
				targetNodes = strings.Join(sp.TargetNodes[:3], ", ") + fmt.Sprintf(" (+%d)", len(sp.TargetNodes)-3)
			} else {
				targetNodes = strings.Join(sp.TargetNodes, ", ")
			}
		}

		seccompProfileRows = append(seccompProfileRows, []string{
			sp.Name,
			ns,
			scope,
			sp.ProfileType,
			sp.Status,
			targetNodes,
			fmt.Sprintf("%d", sp.UsedByPods),
			sp.BypassRisk,
		})
	}

	// Build AppArmor profile rows
	for _, ap := range appArmorProfiles {
		ns := ap.Namespace
		if ns == "" {
			ns = "<NODE>"
		}

		enforced := "No"
		if ap.Enforced {
			enforced = "Yes"
		}

		targetNodes := "-"
		if len(ap.TargetNodes) > 0 {
			if len(ap.TargetNodes) > 3 {
				targetNodes = strings.Join(ap.TargetNodes[:3], ", ") + fmt.Sprintf(" (+%d)", len(ap.TargetNodes)-3)
			} else {
				targetNodes = strings.Join(ap.TargetNodes, ", ")
			}
		}

		appArmorProfileRows = append(appArmorProfileRows, []string{
			ap.Name,
			ns,
			ap.ProfileType,
			ap.Status,
			enforced,
			targetNodes,
			fmt.Sprintf("%d", ap.UsedByPods),
			ap.BypassRisk,
		})
	}

	// Build unsandboxed pod rows (limit to high risk ones)
	highRiskCount := 0
	for _, pod := range unsandboxedPods {
		if pod.RiskLevel == "CRITICAL" || pod.RiskLevel == "HIGH" {
			highRiskCount++
			if highRiskCount > 100 {
				continue // Limit rows
			}

			privileged := "No"
			if pod.Privileged {
				privileged = "Yes"
			}
			hostPID := "No"
			if pod.HostPID {
				hostPID = "Yes"
			}
			hostNetwork := "No"
			if pod.HostNetwork {
				hostNetwork = "Yes"
			}

			caps := "-"
			if len(pod.Capabilities) > 0 {
				if len(pod.Capabilities) > 3 {
					caps = strings.Join(pod.Capabilities[:3], ", ") + "..."
				} else {
					caps = strings.Join(pod.Capabilities, ", ")
				}
			}

			reasons := "-"
			if len(pod.RiskReasons) > 0 {
				if len(pod.RiskReasons) > 2 {
					reasons = strings.Join(pod.RiskReasons[:2], "; ") + "..."
				} else {
					reasons = strings.Join(pod.RiskReasons, "; ")
				}
			}

			unsandboxedPodRows = append(unsandboxedPodRows, []string{
				pod.Name,
				pod.Namespace,
				pod.RuntimeClass,
				pod.SeccompProfile,
				pod.AppArmorProfile,
				privileged,
				hostPID,
				hostNetwork,
				caps,
				pod.RiskLevel,
				reasons,
			})
		}
	}

	// Build runtime security tools rows
	if seccompOperator.Name != "" {
		imageVerified := "No"
		if seccompOperator.ImageVerified {
			imageVerified = "Yes"
		}
		bypassRisk := "-"
		if seccompOperator.BypassRisk != "" {
			bypassRisk = seccompOperator.BypassRisk
		}
		runtimeSecurityToolsRows = append(runtimeSecurityToolsRows, []string{
			seccompOperator.Name,
			seccompOperator.Namespace,
			seccompOperator.Status,
			fmt.Sprintf("%d", seccompOperator.PodsRunning),
			fmt.Sprintf("%d", seccompOperator.TotalPods),
			imageVerified,
			bypassRisk,
		})
	}

	if falco.Name != "" {
		imageVerified := "No"
		if falco.ImageVerified {
			imageVerified = "Yes"
		}
		bypassRisk := "-"
		if falco.BypassRisk != "" {
			bypassRisk = falco.BypassRisk
		}
		runtimeSecurityToolsRows = append(runtimeSecurityToolsRows, []string{
			falco.Name,
			falco.Namespace,
			falco.Status,
			fmt.Sprintf("%d", falco.PodsRunning),
			fmt.Sprintf("%d", falco.TotalPods),
			imageVerified,
			bypassRisk,
		})
	}

	if tracee.Name != "" {
		imageVerified := "No"
		if tracee.ImageVerified {
			imageVerified = "Yes"
		}
		bypassRisk := "-"
		if tracee.BypassRisk != "" {
			bypassRisk = tracee.BypassRisk
		}
		runtimeSecurityToolsRows = append(runtimeSecurityToolsRows, []string{
			tracee.Name,
			tracee.Namespace,
			tracee.Status,
			fmt.Sprintf("%d", tracee.PodsRunning),
			fmt.Sprintf("%d", tracee.TotalPods),
			imageVerified,
			bypassRisk,
		})
	}

	// Build PSS rows
	for _, pss := range pssResults {
		enforceLevel := "-"
		if pss.EnforceLevel != "" {
			enforceLevel = pss.EnforceLevel
		}
		auditLevel := "-"
		if pss.AuditLevel != "" {
			auditLevel = pss.AuditLevel
		}
		warnLevel := "-"
		if pss.WarnLevel != "" {
			warnLevel = pss.WarnLevel
		}
		enforceVersion := "-"
		if pss.EnforceVersion != "" {
			enforceVersion = pss.EnforceVersion
		}
		bypassRisk := "-"
		if pss.BypassRisk != "" {
			bypassRisk = pss.BypassRisk
		}

		pssRows = append(pssRows, []string{
			pss.Namespace,
			enforceLevel,
			auditLevel,
			warnLevel,
			enforceVersion,
			bypassRisk,
		})
	}

	// Generate loot
	generateRuntimeAdmissionLoot(loot, findings, runtimeClasses, seccompOperator, seccompProfiles, appArmorProfiles, unsandboxedPods, falco, tracee, pssResults)

	// Build output tables
	var tables []internal.TableFile

	tables = append(tables, internal.TableFile{
		Name:   "Runtime-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	if len(runtimeClassRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Runtime-Admission-RuntimeClasses",
			Header: runtimeClassHeader,
			Body:   runtimeClassRows,
		})
	}

	if len(seccompProfileRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Runtime-Admission-Seccomp-Profiles",
			Header: seccompProfileHeader,
			Body:   seccompProfileRows,
		})
	}

	if len(appArmorProfileRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Runtime-Admission-AppArmor-Profiles",
			Header: appArmorProfileHeader,
			Body:   appArmorProfileRows,
		})
	}

	if len(unsandboxedPodRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Runtime-Admission-HighRisk-Pods",
			Header: unsandboxedPodHeader,
			Body:   unsandboxedPodRows,
		})
	}

	if len(runtimeSecurityToolsRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Runtime-Admission-Security-Tools",
			Header: runtimeSecurityToolsHeader,
			Body:   runtimeSecurityToolsRows,
		})
	}

	if len(pssRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Runtime-Admission-Pod-Security-Standards",
			Header: pssHeader,
			Body:   pssRows,
		})
	}

	output := RuntimeAdmissionOutput{
		Table: tables,
		Loot:  loot.Build(),
	}

	err := internal.HandleOutput(
		"Kubernetes",
		"table",
		outputDir,
		verbosity,
		wrap,
		"Runtime-Admission",
		globals.ClusterName,
		"results",
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), K8S_RUNTIME_ADMISSION_MODULE_NAME)
		return
	}
}

// ============================================================================
// RuntimeClass Analysis
// ============================================================================

func analyzeRuntimeClasses(ctx context.Context, clientset kubernetes.Interface) []RuntimeClassInfo {
	var runtimeClasses []RuntimeClassInfo

	rcList, err := clientset.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return runtimeClasses
	}

	for _, rc := range rcList.Items {
		info := RuntimeClassInfo{
			Name:    rc.Name,
			Handler: rc.Handler,
		}

		// Determine handler type and if sandboxed
		handlerLC := strings.ToLower(rc.Handler)
		switch {
		case strings.Contains(handlerLC, "gvisor") || strings.Contains(handlerLC, "runsc"):
			info.HandlerType = "gVisor"
			info.IsSandboxed = true
			info.SecurityLevel = "HIGH"
		case strings.Contains(handlerLC, "kata"):
			info.HandlerType = "Kata"
			info.IsSandboxed = true
			info.SecurityLevel = "HIGH"
		case strings.Contains(handlerLC, "firecracker"):
			info.HandlerType = "Firecracker"
			info.IsSandboxed = true
			info.SecurityLevel = "HIGH"
		case strings.Contains(handlerLC, "wasm") || strings.Contains(handlerLC, "wasmtime") || strings.Contains(handlerLC, "wasmedge"):
			info.HandlerType = "WASM"
			info.IsSandboxed = true
			info.SecurityLevel = "HIGH"
		case strings.Contains(handlerLC, "nvidia") || strings.Contains(handlerLC, "gpu"):
			info.HandlerType = "GPU"
			info.IsSandboxed = false
			info.SecurityLevel = "MEDIUM"
		case strings.Contains(handlerLC, "runc"):
			info.HandlerType = "runc"
			info.IsSandboxed = false
			info.SecurityLevel = "LOW"
		case strings.Contains(handlerLC, "crun"):
			info.HandlerType = "crun"
			info.IsSandboxed = false
			info.SecurityLevel = "LOW"
		default:
			info.HandlerType = "standard"
			info.IsSandboxed = false
			info.SecurityLevel = "LOW"
		}

		// Check scheduling constraints
		if rc.Scheduling != nil {
			info.Scheduling = rc.Scheduling
			if rc.Scheduling.NodeSelector != nil {
				info.NodeSelector = rc.Scheduling.NodeSelector
			}
			if len(rc.Scheduling.Tolerations) > 0 {
				for _, t := range rc.Scheduling.Tolerations {
					info.Tolerations = append(info.Tolerations, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
				}
			}
		}

		// Check overhead
		if rc.Overhead != nil {
			info.Overhead = rc.Overhead
		}

		// Bypass risk analysis
		if !info.IsSandboxed {
			info.BypassRisk = "Standard runtime - no sandbox isolation"
		} else if len(info.NodeSelector) == 0 {
			info.BypassRisk = "No node selector - may not run on sandboxed nodes"
		}

		runtimeClasses = append(runtimeClasses, info)
	}

	return runtimeClasses
}

func updateRuntimeClassUsage(runtimeClasses []RuntimeClassInfo, findings []RuntimeAdmissionFinding) {
	for i := range runtimeClasses {
		for _, finding := range findings {
			if count, ok := finding.RuntimeClassUsage[runtimeClasses[i].Name]; ok {
				runtimeClasses[i].UsedByPods += count
				if !runtimeAdmissionContainsString(runtimeClasses[i].Namespaces, finding.Namespace) {
					runtimeClasses[i].Namespaces = append(runtimeClasses[i].Namespaces, finding.Namespace)
				}
			}
		}
	}
}

// ============================================================================
// Seccomp Profile Analysis
// ============================================================================

func analyzeSeccompProfiles(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (SeccompOperatorInfo, []SeccompProfileInfo) {
	operator := SeccompOperatorInfo{}
	var profiles []SeccompProfileInfo

	// Image patterns for verification to reduce false positives
	imagePatterns := []string{
		"security-profiles-operator",
		"seccomp-operator",
		"k8s.gcr.io/security-profiles-operator",
		"gcr.io/k8s-staging-sp-operator",
		"registry.k8s.io/security-profiles-operator",
	}

	// Check for Seccomp Operator
	namespaces := []string{"security-profiles-operator", "seccomp-operator", "kube-system"}
	labelSelectors := []string{
		"app=security-profiles-operator",
		"app=seccomp-operator",
		"app.kubernetes.io/name=security-profiles-operator",
	}

	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err == nil && len(pods.Items) > 0 {
				operator.Name = "Security Profiles Operator"
				operator.Namespace = ns
				operator.TotalPods = len(pods.Items)

				for _, pod := range pods.Items {
					// Verify by image to reduce false positives
					for _, container := range pod.Spec.Containers {
						for _, pattern := range imagePatterns {
							if strings.Contains(strings.ToLower(container.Image), pattern) {
								operator.ImageVerified = true
								break
							}
						}
						if operator.ImageVerified {
							break
						}
					}

					if pod.Status.Phase == corev1.PodRunning {
						operator.PodsRunning++
					}
				}
				break
			}
		}
		if operator.Name != "" {
			break
		}
	}

	// Check for SeccompProfile CRDs (security-profiles-operator)
	seccompProfileGVR := schema.GroupVersionResource{
		Group:    "security-profiles-operator.x-k8s.io",
		Version:  "v1beta1",
		Resource: "seccompprofiles",
	}

	spList, err := dynClient.Resource(seccompProfileGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, sp := range spList.Items {
			profile := parseSeccompProfile(sp.Object, false)
			profiles = append(profiles, profile)
		}
		operator.Profiles = len(profiles)
	}

	// Try v1alpha1 as well
	seccompProfileGVRAlpha := schema.GroupVersionResource{
		Group:    "security-profiles-operator.x-k8s.io",
		Version:  "v1alpha1",
		Resource: "seccompprofiles",
	}

	spListAlpha, err := dynClient.Resource(seccompProfileGVRAlpha).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, sp := range spListAlpha.Items {
			profile := parseSeccompProfile(sp.Object, false)
			profiles = append(profiles, profile)
		}
		operator.Profiles += len(spListAlpha.Items)
	}

	// Set operator status
	if operator.Name != "" {
		if !operator.ImageVerified {
			operator.Status = "unverified"
			operator.BypassRisk = "Detection based on labels only - verify manually"
		} else if operator.PodsRunning == 0 {
			operator.Status = "not-running"
			operator.BypassRisk = "Operator not running - profiles may not be applied"
		} else if operator.PodsRunning < operator.TotalPods {
			operator.Status = "degraded"
			operator.BypassRisk = fmt.Sprintf("Only %d/%d pods running", operator.PodsRunning, operator.TotalPods)
		} else {
			operator.Status = "active"
		}
	}

	return operator, profiles
}

func parseSeccompProfile(obj map[string]interface{}, isCluster bool) SeccompProfileInfo {
	profile := SeccompProfileInfo{
		ProfileType:     "SeccompProfile CRD",
		IsClusterScoped: isCluster,
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		profile.Name, _ = metadata["name"].(string)
		profile.Namespace, _ = metadata["namespace"].(string)
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if statusStr, ok := status["status"].(string); ok {
			profile.Status = statusStr
		}
		if localhostProfile, ok := status["localhostProfile"].(string); ok {
			if localhostProfile != "" {
				profile.Status = "Installed"
			}
		}
	}

	if profile.Status == "" {
		profile.Status = "Unknown"
	}

	return profile
}

// ============================================================================
// AppArmor Profile Analysis
// ============================================================================

func analyzeAppArmorProfiles(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) []AppArmorProfileInfo {
	var profiles []AppArmorProfileInfo

	// Check for AppArmorProfile CRDs (security-profiles-operator)
	appArmorProfileGVR := schema.GroupVersionResource{
		Group:    "security-profiles-operator.x-k8s.io",
		Version:  "v1alpha1",
		Resource: "apparmorprofiles",
	}

	apList, err := dynClient.Resource(appArmorProfileGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ap := range apList.Items {
			profile := parseAppArmorProfile(ap.Object)
			profiles = append(profiles, profile)
		}
	}

	return profiles
}

func parseAppArmorProfile(obj map[string]interface{}) AppArmorProfileInfo {
	profile := AppArmorProfileInfo{
		ProfileType: "AppArmorProfile CRD",
	}

	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		profile.Name, _ = metadata["name"].(string)
		profile.Namespace, _ = metadata["namespace"].(string)
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if enforced, ok := spec["enforced"].(bool); ok {
			profile.Enforced = enforced
		}
	}

	if status, ok := obj["status"].(map[string]interface{}); ok {
		if statusStr, ok := status["status"].(string); ok {
			profile.Status = statusStr
		}
	}

	if profile.Status == "" {
		profile.Status = "Unknown"
	}

	if !profile.Enforced {
		profile.BypassRisk = "Profile not enforced"
	}

	return profile
}

// ============================================================================
// Falco Analysis
// ============================================================================

func analyzeRuntimeFalco(ctx context.Context, clientset kubernetes.Interface) RuntimeFalcoInfo {
	info := RuntimeFalcoInfo{}

	// Use SDK for expected namespaces and label selectors
	namespaces := GetExpectedNamespaces("falco")
	if len(namespaces) == 0 {
		namespaces = []string{"falco", "falco-system", "security", "monitoring", "kube-system"}
	}
	labelSelectors := GetEngineLabelSelectors("falco")
	if len(labelSelectors) == 0 {
		labelSelectors = []string{"app=falco", "app.kubernetes.io/name=falco"}
	}

	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err != nil || len(pods.Items) == 0 {
				continue
			}

			// Verify by image using SDK to reduce false positives
			for _, pod := range pods.Items {
				imageVerified := false
				for _, container := range pod.Spec.Containers {
					if VerifyControllerImage(container.Image, "falco") {
						imageVerified = true
						info.ImageVerified = true
						break
					}
				}

				if imageVerified || info.Name != "" {
					info.Name = "Falco"
					info.Namespace = ns
					info.TotalPods++
					if pod.Status.Phase == corev1.PodRunning {
						info.PodsRunning++
					}
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

	// Also check DaemonSets for Falco
	if info.Name == "" {
		for _, ns := range namespaces {
			dsList, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}

			for _, ds := range dsList.Items {
				for _, container := range ds.Spec.Template.Spec.Containers {
					if VerifyControllerImage(container.Image, "falco") {
						info.Name = "Falco"
						info.Namespace = ns
						info.ImageVerified = true
						info.TotalPods = int(ds.Status.DesiredNumberScheduled)
						info.PodsRunning = int(ds.Status.NumberReady)
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
	}

	// Set status
	if info.Name != "" {
		if !info.ImageVerified {
			info.Status = "unverified"
			info.BypassRisk = "Detection based on labels only - verify manually"
		} else if info.PodsRunning == 0 {
			info.Status = "not-running"
			info.BypassRisk = "Falco pods not running - no runtime detection"
		} else if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
			info.BypassRisk = fmt.Sprintf("Only %d/%d pods running - partial coverage", info.PodsRunning, info.TotalPods)
		} else {
			info.Status = "active"
		}
	}

	return info
}

// ============================================================================
// Tracee Analysis
// ============================================================================

func analyzeRuntimeTracee(ctx context.Context, clientset kubernetes.Interface) RuntimeTraceeInfo {
	info := RuntimeTraceeInfo{}

	// Use SDK for expected namespaces and label selectors
	namespaces := GetExpectedNamespaces("tracee")
	if len(namespaces) == 0 {
		namespaces = []string{"tracee", "tracee-system", "security", "aqua", "kube-system"}
	}
	labelSelectors := GetEngineLabelSelectors("tracee")
	if len(labelSelectors) == 0 {
		labelSelectors = []string{"app=tracee", "app.kubernetes.io/name=tracee"}
	}

	for _, ns := range namespaces {
		for _, selector := range labelSelectors {
			pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err != nil || len(pods.Items) == 0 {
				continue
			}

			// Verify by image using SDK to reduce false positives
			for _, pod := range pods.Items {
				imageVerified := false
				for _, container := range pod.Spec.Containers {
					if VerifyControllerImage(container.Image, "tracee") {
						imageVerified = true
						info.ImageVerified = true
						break
					}
				}

				if imageVerified || info.Name != "" {
					info.Name = "Tracee"
					info.Namespace = ns
					info.TotalPods++
					if pod.Status.Phase == corev1.PodRunning {
						info.PodsRunning++
					}
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

	// Also check DaemonSets for Tracee
	if info.Name == "" {
		for _, ns := range namespaces {
			dsList, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}

			for _, ds := range dsList.Items {
				for _, container := range ds.Spec.Template.Spec.Containers {
					if VerifyControllerImage(container.Image, "tracee") {
						info.Name = "Tracee"
						info.Namespace = ns
						info.ImageVerified = true
						info.TotalPods = int(ds.Status.DesiredNumberScheduled)
						info.PodsRunning = int(ds.Status.NumberReady)
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
	}

	// Set status
	if info.Name != "" {
		if !info.ImageVerified {
			info.Status = "unverified"
			info.BypassRisk = "Detection based on labels only - verify manually"
		} else if info.PodsRunning == 0 {
			info.Status = "not-running"
			info.BypassRisk = "Tracee pods not running - no eBPF detection"
		} else if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
			info.BypassRisk = fmt.Sprintf("Only %d/%d pods running - partial coverage", info.PodsRunning, info.TotalPods)
		} else {
			info.Status = "active"
		}
	}

	return info
}

// ============================================================================
// Pod Security Standards Analysis
// ============================================================================

func analyzeRuntimePSS(ctx context.Context, clientset kubernetes.Interface) []RuntimePSSInfo {
	var results []RuntimePSSInfo

	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return results
	}

	for _, ns := range nsList.Items {
		info := RuntimePSSInfo{
			Namespace: ns.Name,
		}

		// Check PSS labels
		if ns.Labels != nil {
			// Enforce level
			if level, ok := ns.Labels["pod-security.kubernetes.io/enforce"]; ok {
				info.EnforceLevel = level
			}
			if version, ok := ns.Labels["pod-security.kubernetes.io/enforce-version"]; ok {
				info.EnforceVersion = version
			}

			// Audit level
			if level, ok := ns.Labels["pod-security.kubernetes.io/audit"]; ok {
				info.AuditLevel = level
			}

			// Warn level
			if level, ok := ns.Labels["pod-security.kubernetes.io/warn"]; ok {
				info.WarnLevel = level
			}
		}

		// Calculate bypass risk
		if info.EnforceLevel == "" && info.AuditLevel == "" && info.WarnLevel == "" {
			info.BypassRisk = "No PSS configured - privileged pods allowed"
		} else if info.EnforceLevel == "privileged" {
			info.BypassRisk = "Privileged level - no restrictions"
		} else if info.EnforceLevel == "" && (info.AuditLevel != "" || info.WarnLevel != "") {
			info.BypassRisk = "Audit/warn only - no enforcement"
		} else if info.EnforceLevel == "baseline" {
			info.BypassRisk = "Baseline - some privileged operations allowed"
		}

		// Only include namespaces with PSS configured or system namespaces
		if info.EnforceLevel != "" || info.AuditLevel != "" || info.WarnLevel != "" ||
			ns.Name == "default" || ns.Name == "kube-system" {
			results = append(results, info)
		}
	}

	return results
}

// ============================================================================
// Pod Runtime Security Analysis
// ============================================================================

func analyzePodsRuntimeSecurity(ctx context.Context, clientset kubernetes.Interface, runtimeClasses []RuntimeClassInfo) ([]RuntimeAdmissionFinding, []UnsandboxedPodInfo) {
	var findings []RuntimeAdmissionFinding
	var unsandboxedPods []UnsandboxedPodInfo

	// Build RuntimeClass lookup
	rcLookup := make(map[string]RuntimeClassInfo)
	for _, rc := range runtimeClasses {
		rcLookup[rc.Name] = rc
	}

	// Initialize findings per namespace
	namespaceData := make(map[string]*RuntimeAdmissionFinding)
	for _, ns := range globals.K8sNamespaces {
		namespaceData[ns] = &RuntimeAdmissionFinding{
			Namespace:         ns,
			RuntimeClassUsage: make(map[string]int),
		}
	}

	// Get all pods
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings, unsandboxedPods
	}

	for _, pod := range pods.Items {
		finding, ok := namespaceData[pod.Namespace]
		if !ok {
			continue
		}

		finding.TotalPods++

		podInfo := UnsandboxedPodInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		}

		// Analyze RuntimeClass
		isSandboxed := false
		if pod.Spec.RuntimeClassName != nil && *pod.Spec.RuntimeClassName != "" {
			rcName := *pod.Spec.RuntimeClassName
			podInfo.RuntimeClass = rcName
			finding.RuntimeClassUsage[rcName]++
			finding.CustomRuntimePods++

			if rc, ok := rcLookup[rcName]; ok && rc.IsSandboxed {
				isSandboxed = true
			}
		} else {
			podInfo.RuntimeClass = "<default>"
			finding.DefaultRuntimePods++
		}

		// Analyze Seccomp
		seccompProfile := getSeccompProfile(&pod)
		podInfo.SeccompProfile = seccompProfile

		switch seccompProfile {
		case "RuntimeDefault":
			finding.SeccompRuntimeDefault++
			finding.SeccompEnabled++
		case "Unconfined", "<none>":
			finding.SeccompUnconfined++
			finding.SeccompDisabled++
		default:
			if strings.HasPrefix(seccompProfile, "Localhost:") {
				finding.SeccompLocalhost++
				finding.SeccompEnabled++
			} else {
				finding.SeccompDisabled++
			}
		}

		// Analyze AppArmor
		appArmorProfile := getAppArmorProfileForPod(pod.Annotations)
		podInfo.AppArmorProfile = appArmorProfile

		switch appArmorProfile {
		case "runtime/default":
			finding.AppArmorRuntimeDefault++
			finding.AppArmorEnabled++
		case "unconfined", "<none>":
			finding.AppArmorUnconfined++
			finding.AppArmorDisabled++
		default:
			if strings.HasPrefix(appArmorProfile, "localhost/") {
				finding.AppArmorLocalhost++
				finding.AppArmorEnabled++
			} else {
				finding.AppArmorDisabled++
			}
		}

		// Analyze SELinux
		hasSELinux := false
		if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SELinuxOptions != nil {
			selinux := pod.Spec.SecurityContext.SELinuxOptions
			if selinux.Type != "" || selinux.Level != "" || selinux.Role != "" || selinux.User != "" {
				hasSELinux = true
			}
		}
		if hasSELinux {
			finding.SELinuxEnabled++
		} else {
			finding.SELinuxDisabled++
		}

		// Analyze privileged settings
		isPrivileged := false
		hasHostPID := pod.Spec.HostPID
		hasHostNetwork := pod.Spec.HostNetwork
		hasHostIPC := pod.Spec.HostIPC
		var capabilities []string

		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil {
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					isPrivileged = true
				}
				if container.SecurityContext.Capabilities != nil {
					for _, cap := range container.SecurityContext.Capabilities.Add {
						capabilities = append(capabilities, string(cap))
					}
				}
			}
		}

		podInfo.Privileged = isPrivileged
		podInfo.HostPID = hasHostPID
		podInfo.HostNetwork = hasHostNetwork
		podInfo.Capabilities = capabilities

		if isPrivileged {
			finding.PrivilegedPods++
		}
		if hasHostPID {
			finding.HostPIDPods++
		}
		if hasHostNetwork {
			finding.HostNetworkPods++
		}
		if hasHostIPC {
			finding.HostIPCPods++
		}

		// Determine if sandboxed
		if isSandboxed && !isPrivileged {
			finding.SandboxedPods++
		} else {
			finding.UnsandboxedPods++

			// Calculate risk for unsandboxed pods
			var riskReasons []string
			riskScore := 0

			if isPrivileged {
				riskReasons = append(riskReasons, "privileged")
				riskScore += 50
			}
			if hasHostPID {
				riskReasons = append(riskReasons, "hostPID")
				riskScore += 30
			}
			if hasHostNetwork {
				riskReasons = append(riskReasons, "hostNetwork")
				riskScore += 20
			}
			if hasHostIPC {
				riskReasons = append(riskReasons, "hostIPC")
				riskScore += 15
			}
			if seccompProfile == "Unconfined" || seccompProfile == "<none>" {
				riskReasons = append(riskReasons, "no seccomp")
				riskScore += 15
			}
			if appArmorProfile == "unconfined" || appArmorProfile == "<none>" {
				riskReasons = append(riskReasons, "no apparmor")
				riskScore += 10
			}
			for _, cap := range capabilities {
				capUpper := strings.ToUpper(cap)
				if capUpper == "SYS_ADMIN" || capUpper == "SYS_PTRACE" || capUpper == "NET_ADMIN" || capUpper == "ALL" {
					riskReasons = append(riskReasons, fmt.Sprintf("cap:%s", cap))
					riskScore += 20
				}
			}

			podInfo.RiskReasons = riskReasons

			if riskScore >= 50 {
				podInfo.RiskLevel = "CRITICAL"
			} else if riskScore >= 30 {
				podInfo.RiskLevel = "HIGH"
			} else if riskScore >= 15 {
				podInfo.RiskLevel = "MEDIUM"
			} else {
				podInfo.RiskLevel = "LOW"
			}

			unsandboxedPods = append(unsandboxedPods, podInfo)
		}
	}

	// Calculate coverage and risk for each namespace
	for _, finding := range namespaceData {
		if finding.TotalPods > 0 {
			finding.SandboxedPercentage = fmt.Sprintf("%.0f%%", float64(finding.SandboxedPods)/float64(finding.TotalPods)*100)
			finding.SeccompCoverage = fmt.Sprintf("%.0f%%", float64(finding.SeccompEnabled)/float64(finding.TotalPods)*100)
			finding.AppArmorCoverage = fmt.Sprintf("%.0f%%", float64(finding.AppArmorEnabled)/float64(finding.TotalPods)*100)
			finding.SELinuxCoverage = fmt.Sprintf("%.0f%%", float64(finding.SELinuxEnabled)/float64(finding.TotalPods)*100)
		} else {
			finding.SandboxedPercentage = "N/A"
			finding.SeccompCoverage = "N/A"
			finding.AppArmorCoverage = "N/A"
			finding.SELinuxCoverage = "N/A"
		}

		// Calculate risk level
		finding.RiskLevel = calculateRuntimeRiskLevel(finding)

		// Add security issues
		if finding.PrivilegedPods > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d privileged pods", finding.PrivilegedPods))
		}
		if finding.SeccompDisabled > finding.SeccompEnabled && finding.TotalPods > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, "Most pods lack seccomp")
		}
		if finding.AppArmorDisabled > finding.AppArmorEnabled && finding.TotalPods > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, "Most pods lack AppArmor")
		}
		if finding.HostPIDPods > 0 {
			finding.SecurityIssues = append(finding.SecurityIssues, fmt.Sprintf("%d hostPID pods", finding.HostPIDPods))
		}

		findings = append(findings, *finding)
	}

	// Sort findings by namespace
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Namespace < findings[j].Namespace
	})

	// Sort unsandboxed pods by risk level
	sort.Slice(unsandboxedPods, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		return riskOrder[unsandboxedPods[i].RiskLevel] < riskOrder[unsandboxedPods[j].RiskLevel]
	})

	return findings, unsandboxedPods
}

func getSeccompProfile(pod *corev1.Pod) string {
	// Check pod-level seccomp
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		sp := pod.Spec.SecurityContext.SeccompProfile
		switch sp.Type {
		case corev1.SeccompProfileTypeRuntimeDefault:
			return "RuntimeDefault"
		case corev1.SeccompProfileTypeUnconfined:
			return "Unconfined"
		case corev1.SeccompProfileTypeLocalhost:
			if sp.LocalhostProfile != nil {
				return fmt.Sprintf("Localhost:%s", *sp.LocalhostProfile)
			}
			return "Localhost"
		}
	}

	// Check container-level seccomp (first container)
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
			sp := container.SecurityContext.SeccompProfile
			switch sp.Type {
			case corev1.SeccompProfileTypeRuntimeDefault:
				return "RuntimeDefault"
			case corev1.SeccompProfileTypeUnconfined:
				return "Unconfined"
			case corev1.SeccompProfileTypeLocalhost:
				if sp.LocalhostProfile != nil {
					return fmt.Sprintf("Localhost:%s", *sp.LocalhostProfile)
				}
				return "Localhost"
			}
		}
	}

	// Check legacy annotation
	if pod.Annotations != nil {
		if profile, ok := pod.Annotations["seccomp.security.alpha.kubernetes.io/pod"]; ok {
			return profile
		}
	}

	return "<none>"
}

func getAppArmorProfileForPod(annotations map[string]string) string {
	if annotations == nil {
		return "<none>"
	}

	for k, v := range annotations {
		if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") {
			return v
		}
	}

	return "<none>"
}

func calculateRuntimeRiskLevel(finding *RuntimeAdmissionFinding) string {
	if finding.TotalPods == 0 {
		return "INFO"
	}

	score := 0

	// Privileged pods
	score += finding.PrivilegedPods * 30

	// Host namespace access
	score += finding.HostPIDPods * 20
	score += finding.HostNetworkPods * 10
	score += finding.HostIPCPods * 10

	// Lack of seccomp
	if finding.TotalPods > 0 && float64(finding.SeccompDisabled)/float64(finding.TotalPods) > 0.5 {
		score += 20
	}

	// Lack of AppArmor
	if finding.TotalPods > 0 && float64(finding.AppArmorDisabled)/float64(finding.TotalPods) > 0.5 {
		score += 15
	}

	// No sandboxed runtime
	if finding.SandboxedPods == 0 && finding.TotalPods > 5 {
		score += 10
	}

	if score >= 50 {
		return "CRITICAL"
	} else if score >= 30 {
		return "HIGH"
	} else if score >= 15 {
		return "MEDIUM"
	} else if score > 0 {
		return "LOW"
	}
	return "INFO"
}

func runtimeAdmissionContainsString(slice []string, s string) bool {
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

func generateRuntimeAdmissionLoot(loot *shared.LootBuilder,
	findings []RuntimeAdmissionFinding,
	runtimeClasses []RuntimeClassInfo,
	seccompOperator SeccompOperatorInfo,
	seccompProfiles []SeccompProfileInfo,
	appArmorProfiles []AppArmorProfileInfo,
	unsandboxedPods []UnsandboxedPodInfo,
	falco RuntimeFalcoInfo,
	tracee RuntimeTraceeInfo,
	pssResults []RuntimePSSInfo) {

	// Summary
	loot.Section("Summary").Add("# Runtime Security Summary")
	loot.Section("Summary").Add("#")

	// RuntimeClasses summary
	sandboxedRCs := 0
	for _, rc := range runtimeClasses {
		if rc.IsSandboxed {
			sandboxedRCs++
		}
	}
	loot.Section("Summary").Add(fmt.Sprintf("# RuntimeClasses: %d total, %d sandboxed", len(runtimeClasses), sandboxedRCs))

	// Seccomp summary
	if seccompOperator.Name != "" {
		status := seccompOperator.Status
		if seccompOperator.ImageVerified {
			status += " (verified)"
		}
		loot.Section("Summary").Add(fmt.Sprintf("# Security Profiles Operator: %s (%d profiles)", status, seccompOperator.Profiles))
	} else {
		loot.Section("Summary").Add("# Security Profiles Operator: Not installed")
	}

	// Falco summary
	if falco.Name != "" {
		status := falco.Status
		if falco.ImageVerified {
			status += " (verified)"
		}
		loot.Section("Summary").Add(fmt.Sprintf("# Falco: %s (%d/%d pods)", status, falco.PodsRunning, falco.TotalPods))
	} else {
		loot.Section("Summary").Add("# Falco: Not installed")
	}

	// Tracee summary
	if tracee.Name != "" {
		status := tracee.Status
		if tracee.ImageVerified {
			status += " (verified)"
		}
		loot.Section("Summary").Add(fmt.Sprintf("# Tracee: %s (%d/%d pods)", status, tracee.PodsRunning, tracee.TotalPods))
	} else {
		loot.Section("Summary").Add("# Tracee: Not installed")
	}

	// AppArmor summary
	loot.Section("Summary").Add(fmt.Sprintf("# AppArmor Profiles: %d", len(appArmorProfiles)))

	// PSS summary
	pssRestricted := 0
	pssBaseline := 0
	pssPrivileged := 0
	for _, pss := range pssResults {
		switch pss.EnforceLevel {
		case "restricted":
			pssRestricted++
		case "baseline":
			pssBaseline++
		case "privileged":
			pssPrivileged++
		}
	}
	loot.Section("Summary").Add(fmt.Sprintf("# Pod Security Standards: %d restricted, %d baseline, %d privileged", pssRestricted, pssBaseline, pssPrivileged))

	loot.Section("Summary").Add("#")

	// High-risk pods
	loot.Section("HighRiskPods").Add("# High-Risk Pods Without Runtime Protection")
	loot.Section("HighRiskPods").Add("#")

	criticalCount := 0
	for _, pod := range unsandboxedPods {
		if pod.RiskLevel == "CRITICAL" {
			criticalCount++
			if criticalCount <= 20 {
				loot.Section("HighRiskPods").Add(fmt.Sprintf("# %s/%s - %s", pod.Namespace, pod.Name, strings.Join(pod.RiskReasons, ", ")))
				loot.Section("HighRiskPods").Add(fmt.Sprintf("kubectl get pod %s -n %s -o yaml | grep -A5 securityContext", pod.Name, pod.Namespace))
			}
		}
	}

	if criticalCount == 0 {
		loot.Section("HighRiskPods").Add("# No critical risk pods found")
	} else if criticalCount > 20 {
		loot.Section("HighRiskPods").Add(fmt.Sprintf("# ... and %d more critical pods", criticalCount-20))
	}

	// RuntimeClass recommendations
	loot.Section("RuntimeClasses").Add("# RuntimeClass Analysis")
	loot.Section("RuntimeClasses").Add("#")

	if len(runtimeClasses) == 0 {
		loot.Section("RuntimeClasses").Add("# WARNING: No RuntimeClasses defined")
		loot.Section("RuntimeClasses").Add("# Consider deploying gVisor or Kata Containers for sensitive workloads")
		loot.Section("RuntimeClasses").Add("#")
		loot.Section("RuntimeClasses").Add("# Example gVisor RuntimeClass:")
		loot.Section("RuntimeClasses").Add("# apiVersion: node.k8s.io/v1")
		loot.Section("RuntimeClasses").Add("# kind: RuntimeClass")
		loot.Section("RuntimeClasses").Add("# metadata:")
		loot.Section("RuntimeClasses").Add("#   name: gvisor")
		loot.Section("RuntimeClasses").Add("# handler: runsc")
	} else {
		for _, rc := range runtimeClasses {
			if rc.IsSandboxed {
				loot.Section("RuntimeClasses").Add(fmt.Sprintf("# %s (%s): Sandboxed, used by %d pods", rc.Name, rc.HandlerType, rc.UsedByPods))
			} else {
				loot.Section("RuntimeClasses").Add(fmt.Sprintf("# %s (%s): NOT sandboxed, used by %d pods", rc.Name, rc.HandlerType, rc.UsedByPods))
			}
		}
	}

	// Seccomp recommendations
	loot.Section("Seccomp").Add("# Seccomp Analysis")
	loot.Section("Seccomp").Add("#")

	totalPods := 0
	seccompDisabled := 0
	for _, f := range findings {
		totalPods += f.TotalPods
		seccompDisabled += f.SeccompDisabled
	}

	if totalPods > 0 {
		disabledPercent := float64(seccompDisabled) / float64(totalPods) * 100
		loot.Section("Seccomp").Add(fmt.Sprintf("# %.0f%% of pods lack seccomp profiles (%d/%d)", disabledPercent, seccompDisabled, totalPods))
	}

	if seccompOperator.Name == "" {
		loot.Section("Seccomp").Add("#")
		loot.Section("Seccomp").Add("# Consider installing Security Profiles Operator:")
		loot.Section("Seccomp").Add("# kubectl apply -f https://github.com/kubernetes-sigs/security-profiles-operator/releases/latest/download/install.yaml")
	}

	// Falco section
	loot.Section("Falco").Add("# Falco Runtime Detection")
	loot.Section("Falco").Add("#")
	if falco.Name != "" {
		loot.Section("Falco").Add(fmt.Sprintf("# Status: %s", falco.Status))
		if falco.ImageVerified {
			loot.Section("Falco").Add("# Image: Verified")
		} else {
			loot.Section("Falco").Add("# WARNING: Image not verified - detection based on labels only")
		}
		loot.Section("Falco").Add(fmt.Sprintf("# Pods: %d/%d running", falco.PodsRunning, falco.TotalPods))
		if falco.BypassRisk != "" {
			loot.Section("Falco").Add(fmt.Sprintf("# Bypass Risk: %s", falco.BypassRisk))
		}
		loot.Section("Falco").Add("#")
		loot.Section("Falco").Add("# Check Falco logs:")
		loot.Section("Falco").Add(fmt.Sprintf("kubectl logs -n %s -l app=falco --tail=100", falco.Namespace))
	} else {
		loot.Section("Falco").Add("# Falco not detected")
		loot.Section("Falco").Add("# Consider installing Falco for runtime threat detection:")
		loot.Section("Falco").Add("# helm repo add falcosecurity https://falcosecurity.github.io/charts")
		loot.Section("Falco").Add("# helm install falco falcosecurity/falco -n falco --create-namespace")
	}

	// Tracee section
	loot.Section("Tracee").Add("# Tracee eBPF Security")
	loot.Section("Tracee").Add("#")
	if tracee.Name != "" {
		loot.Section("Tracee").Add(fmt.Sprintf("# Status: %s", tracee.Status))
		if tracee.ImageVerified {
			loot.Section("Tracee").Add("# Image: Verified")
		} else {
			loot.Section("Tracee").Add("# WARNING: Image not verified - detection based on labels only")
		}
		loot.Section("Tracee").Add(fmt.Sprintf("# Pods: %d/%d running", tracee.PodsRunning, tracee.TotalPods))
		if tracee.BypassRisk != "" {
			loot.Section("Tracee").Add(fmt.Sprintf("# Bypass Risk: %s", tracee.BypassRisk))
		}
		loot.Section("Tracee").Add("#")
		loot.Section("Tracee").Add("# Check Tracee logs:")
		loot.Section("Tracee").Add(fmt.Sprintf("kubectl logs -n %s -l app=tracee --tail=100", tracee.Namespace))
	} else {
		loot.Section("Tracee").Add("# Tracee not detected")
		loot.Section("Tracee").Add("# Consider installing Tracee for eBPF-based security monitoring:")
		loot.Section("Tracee").Add("# helm repo add aqua https://aquasecurity.github.io/helm-charts/")
		loot.Section("Tracee").Add("# helm install tracee aqua/tracee -n tracee --create-namespace")
	}

	// PSS section
	loot.Section("PSS").Add("# Pod Security Standards Analysis")
	loot.Section("PSS").Add("#")
	noPSS := 0
	privilegedPSS := 0
	for _, pss := range pssResults {
		if pss.EnforceLevel == "" {
			noPSS++
		} else if pss.EnforceLevel == "privileged" {
			privilegedPSS++
		}
	}
	if noPSS > 0 {
		loot.Section("PSS").Add(fmt.Sprintf("# WARNING: %d namespaces have no PSS enforcement", noPSS))
	}
	if privilegedPSS > 0 {
		loot.Section("PSS").Add(fmt.Sprintf("# WARNING: %d namespaces allow privileged pods", privilegedPSS))
	}
	loot.Section("PSS").Add("#")
	loot.Section("PSS").Add("# Apply restricted PSS to a namespace:")
	loot.Section("PSS").Add("kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted")
	loot.Section("PSS").Add("#")
	loot.Section("PSS").Add("# Check namespace PSS labels:")
	loot.Section("PSS").Add("kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}: enforce={.metadata.labels.pod-security\\.kubernetes\\.io/enforce}{\"\\n\"}{end}'")

	// Commands
	loot.Section("Commands").Add("# Useful Commands")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# List RuntimeClasses:")
	loot.Section("Commands").Add("kubectl get runtimeclasses")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Find privileged pods:")
	loot.Section("Commands").Add("kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + \"/\" + .metadata.name'")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Find pods without seccomp:")
	loot.Section("Commands").Add("kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.seccompProfile == null) | .metadata.namespace + \"/\" + .metadata.name'")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check Seccomp profiles:")
	loot.Section("Commands").Add("kubectl get seccompprofiles -A")
	loot.Section("Commands").Add("#")
	loot.Section("Commands").Add("# Check AppArmor profiles:")
	loot.Section("Commands").Add("kubectl get apparmorprofiles -A")
}
