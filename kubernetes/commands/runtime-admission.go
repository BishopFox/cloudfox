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
	"github.com/BishopFox/cloudfox/kubernetes/shared/admission"
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

Container Runtime Classes:
  - RuntimeClasses (gVisor, Kata Containers, Firecracker, etc.)
  - Sandboxed vs unsandboxed workload analysis
  - Runtime bypass detection

Security Profiles:
  - Seccomp profiles (SeccompProfile CRDs, node profiles)
  - AppArmor profiles (node and pod configurations)
  - SELinux policies
  - Pod security context coverage
  - Security Profiles Operator (SPO) detection

Cloud-Specific Runtime Security (in-cluster detection):
  Detects cloud-specific runtime configurations from RuntimeClasses and node labels.
  No --cloud-provider flag required - reads cluster resources directly.

  AWS:
    - AWS Bottlerocket OS detection
    - AWS Firecracker microVM runtime
    - EKS optimized AMI detection

  GCP:
    - GKE Sandbox (gVisor) RuntimeClass detection
    - GKE Autopilot secure-by-default enforcement

  Azure:
    - Azure Kata Containers runtime
    - Azure Confidential Containers
    - AKS node security configuration

Examples:
  cloudfox kubernetes runtime-admission
  cloudfox kubernetes runtime-admission --detailed`,
	Run: ListRuntimeAdmission,
}

// init() removed - detailed flag is now a global persistent flag in cli/kubernetes.go

type RuntimeAdmissionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t RuntimeAdmissionOutput) TableFiles() []internal.TableFile { return t.Table }
func (t RuntimeAdmissionOutput) LootFiles() []internal.LootFile   { return t.Loot }

// RuntimeEnumeratedPolicy is a unified representation of any policy/rule across runtime security tools
type RuntimeEnumeratedPolicy struct {
	Namespace string
	Tool      string
	Name      string
	Scope     string // Cluster or Namespace
	Type      string // RuntimeClass, SeccompProfile, AppArmorProfile, PSS, etc.
	Details   string // tool-specific summary
}

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

	// Security analysis
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
}

// RuntimePSSInfo represents PSS enforcement configuration for runtime-admission
type RuntimePSSInfo struct {
	Namespace       string
	EnforceLevel    string // privileged, baseline, restricted
	AuditLevel      string
	WarnLevel       string
	EnforceVersion  string
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
}

func ListRuntimeAdmission(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDir, _ := parentCmd.PersistentFlags().GetString("outdir")
	detailed := globals.K8sDetailed

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

	// Enumerate all policies into unified format
	logger.InfoM("Enumerating policies across all tools...", K8S_RUNTIME_ADMISSION_MODULE_NAME)
	var allPolicies []RuntimeEnumeratedPolicy

	// Convert RuntimeClasses
	for _, rc := range runtimeClasses {
		allPolicies = append(allPolicies, RuntimeEnumeratedPolicy{
			Namespace: "<CLUSTER>",
			Tool:      "RuntimeClass",
			Name:      rc.Name,
			Scope:     "Cluster",
			Type:      rc.HandlerType,
			Details:   fmt.Sprintf("handler=%s, sandboxed=%v, security=%s, used_by=%d pods", rc.Handler, rc.IsSandboxed, rc.SecurityLevel, rc.UsedByPods),
		})
	}

	// Convert Seccomp Profiles
	for _, sp := range seccompProfiles {
		ns := sp.Namespace
		scope := "Namespace"
		if sp.IsClusterScoped {
			ns = "<CLUSTER>"
			scope = "Cluster"
		}
		allPolicies = append(allPolicies, RuntimeEnumeratedPolicy{
			Namespace: ns,
			Tool:      "Seccomp Operator",
			Name:      sp.Name,
			Scope:     scope,
			Type:      sp.ProfileType,
			Details:   fmt.Sprintf("status=%s, used_by=%d pods", sp.Status, sp.UsedByPods),
		})
	}

	// Convert AppArmor Profiles
	for _, ap := range appArmorProfiles {
		ns := ap.Namespace
		if ns == "" {
			ns = "<NODE>"
		}
		allPolicies = append(allPolicies, RuntimeEnumeratedPolicy{
			Namespace: ns,
			Tool:      "AppArmor",
			Name:      ap.Name,
			Scope:     "Namespace",
			Type:      ap.ProfileType,
			Details:   fmt.Sprintf("status=%s, enforced=%v, used_by=%d pods", ap.Status, ap.Enforced, ap.UsedByPods),
		})
	}

	// Convert PSS levels
	for _, pss := range pssResults {
		allPolicies = append(allPolicies, RuntimeEnumeratedPolicy{
			Namespace: pss.Namespace,
			Tool:      "PSS",
			Name:      pss.Namespace,
			Scope:     "Namespace",
			Type:      "PodSecurityStandard",
			Details:   fmt.Sprintf("enforce=%s, audit=%s, warn=%s", pss.EnforceLevel, pss.AuditLevel, pss.WarnLevel),
		})
	}

	// Add runtime security tools
	if seccompOperator.Name != "" {
		allPolicies = append(allPolicies, RuntimeEnumeratedPolicy{
			Namespace: seccompOperator.Namespace,
			Tool:      "Seccomp Operator",
			Name:      seccompOperator.Name,
			Scope:     "Cluster",
			Type:      "Operator",
			Details:   fmt.Sprintf("status=%s, profiles=%d, pods=%d/%d", seccompOperator.Status, seccompOperator.Profiles, seccompOperator.PodsRunning, seccompOperator.TotalPods),
		})
	}
	if falco.Name != "" {
		allPolicies = append(allPolicies, RuntimeEnumeratedPolicy{
			Namespace: falco.Namespace,
			Tool:      "Falco",
			Name:      falco.Name,
			Scope:     "Cluster",
			Type:      "RuntimeDetection",
			Details:   fmt.Sprintf("status=%s, pods=%d/%d", falco.Status, falco.PodsRunning, falco.TotalPods),
		})
	}
	if tracee.Name != "" {
		allPolicies = append(allPolicies, RuntimeEnumeratedPolicy{
			Namespace: tracee.Namespace,
			Tool:      "Tracee",
			Name:      tracee.Name,
			Scope:     "Cluster",
			Type:      "eBPF Detection",
			Details:   fmt.Sprintf("status=%s, pods=%d/%d", tracee.Status, tracee.PodsRunning, tracee.TotalPods),
		})
	}

	// Sort by tool then namespace
	sort.Slice(allPolicies, func(i, j int) bool {
		if allPolicies[i].Tool != allPolicies[j].Tool {
			return allPolicies[i].Tool < allPolicies[j].Tool
		}
		return allPolicies[i].Namespace < allPolicies[j].Namespace
	})

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
		"Issues",
	}

	policiesHeader := []string{
		"Namespace",
		"Tool",
		"Name",
		"Scope",
		"Type",
		"Details",
	}

	runtimeClassHeader := []string{
		"Namespace",
		"Name",
		"Handler",
		"Type",
		"Sandboxed",
		"Security Level",
		"Node Selector",
		"Used By Pods",
		"Namespaces",
		"Issues",
	}

	seccompProfileHeader := []string{
		"Namespace",
		"Name",
		"Scope",
		"Type",
		"Status",
		"Target Nodes",
		"Used By Pods",
		"Issues",
	}

	appArmorProfileHeader := []string{
		"Namespace",
		"Name",
		"Type",
		"Status",
		"Enforced",
		"Target Nodes",
		"Used By Pods",
		"Issues",
	}

	unsandboxedPodHeader := []string{
		"Namespace",
		"Name",
		"Runtime Class",
		"Seccomp",
		"AppArmor",
		"Privileged",
		"HostPID",
		"HostNetwork",
		"Capabilities",
		"Issues",
	}

	runtimeSecurityToolsHeader := []string{
		"Namespace",
		"Tool",
		"Status",
		"Pods Running",
		"Total Pods",
		"Image Verified",
		"Issues",
	}

	pssHeader := []string{
		"Namespace",
		"Enforce Level",
		"Audit Level",
		"Warn Level",
		"Enforce Version",
		"Issues",
	}

	var summaryRows [][]string
	var policiesRows [][]string
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
			issues,
		})
	}

	// Build unified policies rows
	for _, p := range allPolicies {
		policiesRows = append(policiesRows, []string{
			p.Namespace,
			p.Tool,
			p.Name,
			p.Scope,
			p.Type,
			p.Details,
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

		// Detect issues
		var rcIssues []string
		if !rc.IsSandboxed {
			rcIssues = append(rcIssues, "Not sandboxed")
		}
		if rc.SecurityLevel == "low" || rc.SecurityLevel == "" {
			rcIssues = append(rcIssues, "Low security level")
		}
		if rc.UsedByPods == 0 {
			rcIssues = append(rcIssues, "Not used")
		}
		rcIssuesStr := "<NONE>"
		if len(rcIssues) > 0 {
			rcIssuesStr = strings.Join(rcIssues, "; ")
		}

		runtimeClassRows = append(runtimeClassRows, []string{
			"<CLUSTER>",
			rc.Name,
			rc.Handler,
			rc.HandlerType,
			sandboxed,
			rc.SecurityLevel,
			nodeSelector,
			fmt.Sprintf("%d", rc.UsedByPods),
			namespaces,
			rcIssuesStr,
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

		// Detect issues
		var spIssues []string
		if sp.Status != "Installed" && sp.Status != "Active" && sp.Status != "Ready" {
			spIssues = append(spIssues, "Status: "+sp.Status)
		}
		if sp.UsedByPods == 0 {
			spIssues = append(spIssues, "Not used")
		}
		if sp.ProfileType == "Unconfined" {
			spIssues = append(spIssues, "Unconfined profile")
		}
		spIssuesStr := "<NONE>"
		if len(spIssues) > 0 {
			spIssuesStr = strings.Join(spIssues, "; ")
		}

		seccompProfileRows = append(seccompProfileRows, []string{
			ns,
			sp.Name,
			scope,
			sp.ProfileType,
			sp.Status,
			targetNodes,
			fmt.Sprintf("%d", sp.UsedByPods),
			spIssuesStr,
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

		// Detect issues
		var apIssues []string
		if !ap.Enforced {
			apIssues = append(apIssues, "Not enforced")
		}
		if ap.Status != "Installed" && ap.Status != "Active" && ap.Status != "Ready" {
			apIssues = append(apIssues, "Status: "+ap.Status)
		}
		if ap.UsedByPods == 0 {
			apIssues = append(apIssues, "Not used")
		}
		apIssuesStr := "<NONE>"
		if len(apIssues) > 0 {
			apIssuesStr = strings.Join(apIssues, "; ")
		}

		appArmorProfileRows = append(appArmorProfileRows, []string{
			ns,
			ap.Name,
			ap.ProfileType,
			ap.Status,
			enforced,
			targetNodes,
			fmt.Sprintf("%d", ap.UsedByPods),
			apIssuesStr,
		})
	}

	// Build unsandboxed pod rows (limit to 100 pods)
	podCount := 0
	for _, pod := range unsandboxedPods {
		podCount++
		if podCount > 100 {
			break // Limit rows
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

		// Detect issues
		var podIssues []string
		if pod.Privileged {
			podIssues = append(podIssues, "Privileged")
		}
		if pod.HostPID {
			podIssues = append(podIssues, "Host PID")
		}
		if pod.HostNetwork {
			podIssues = append(podIssues, "Host network")
		}
		if len(pod.Capabilities) > 0 {
			podIssues = append(podIssues, "Extra capabilities")
		}
		if pod.SeccompProfile == "" || pod.SeccompProfile == "Unconfined" {
			podIssues = append(podIssues, "No seccomp")
		}
		podIssuesStr := "<NONE>"
		if len(podIssues) > 0 {
			podIssuesStr = strings.Join(podIssues, "; ")
		}

		unsandboxedPodRows = append(unsandboxedPodRows, []string{
			pod.Namespace,
			pod.Name,
			pod.RuntimeClass,
			pod.SeccompProfile,
			pod.AppArmorProfile,
			privileged,
			hostPID,
			hostNetwork,
			caps,
			podIssuesStr,
		})
	}

	// Build runtime security tools rows
	if seccompOperator.Name != "" {
		imageVerified := "No"
		if seccompOperator.ImageVerified {
			imageVerified = "Yes"
		}

		// Detect issues
		var soIssues []string
		if seccompOperator.Status != "Running" && seccompOperator.Status != "Healthy" {
			soIssues = append(soIssues, "Not running")
		}
		if seccompOperator.PodsRunning < seccompOperator.TotalPods {
			soIssues = append(soIssues, "Not all pods running")
		}
		if !seccompOperator.ImageVerified {
			soIssues = append(soIssues, "Image not verified")
		}
		soIssuesStr := "<NONE>"
		if len(soIssues) > 0 {
			soIssuesStr = strings.Join(soIssues, "; ")
		}

		runtimeSecurityToolsRows = append(runtimeSecurityToolsRows, []string{
			seccompOperator.Namespace,
			seccompOperator.Name,
			seccompOperator.Status,
			fmt.Sprintf("%d", seccompOperator.PodsRunning),
			fmt.Sprintf("%d", seccompOperator.TotalPods),
			imageVerified,
			soIssuesStr,
		})
	}

	if falco.Name != "" {
		imageVerified := "No"
		if falco.ImageVerified {
			imageVerified = "Yes"
		}

		// Detect issues
		var falcoIssues []string
		if falco.Status != "Running" && falco.Status != "Healthy" {
			falcoIssues = append(falcoIssues, "Not running")
		}
		if falco.PodsRunning < falco.TotalPods {
			falcoIssues = append(falcoIssues, "Not all pods running")
		}
		if !falco.ImageVerified {
			falcoIssues = append(falcoIssues, "Image not verified")
		}
		falcoIssuesStr := "<NONE>"
		if len(falcoIssues) > 0 {
			falcoIssuesStr = strings.Join(falcoIssues, "; ")
		}

		runtimeSecurityToolsRows = append(runtimeSecurityToolsRows, []string{
			falco.Namespace,
			falco.Name,
			falco.Status,
			fmt.Sprintf("%d", falco.PodsRunning),
			fmt.Sprintf("%d", falco.TotalPods),
			imageVerified,
			falcoIssuesStr,
		})
	}

	if tracee.Name != "" {
		imageVerified := "No"
		if tracee.ImageVerified {
			imageVerified = "Yes"
		}

		// Detect issues
		var traceeIssues []string
		if tracee.Status != "Running" && tracee.Status != "Healthy" {
			traceeIssues = append(traceeIssues, "Not running")
		}
		if tracee.PodsRunning < tracee.TotalPods {
			traceeIssues = append(traceeIssues, "Not all pods running")
		}
		if !tracee.ImageVerified {
			traceeIssues = append(traceeIssues, "Image not verified")
		}
		traceeIssuesStr := "<NONE>"
		if len(traceeIssues) > 0 {
			traceeIssuesStr = strings.Join(traceeIssues, "; ")
		}

		runtimeSecurityToolsRows = append(runtimeSecurityToolsRows, []string{
			tracee.Namespace,
			tracee.Name,
			tracee.Status,
			fmt.Sprintf("%d", tracee.PodsRunning),
			fmt.Sprintf("%d", tracee.TotalPods),
			imageVerified,
			traceeIssuesStr,
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

		// Detect issues
		var pssIssues []string
		if pss.EnforceLevel == "" || pss.EnforceLevel == "privileged" {
			pssIssues = append(pssIssues, "No PSS enforcement")
		}
		if pss.EnforceLevel == "baseline" {
			pssIssues = append(pssIssues, "Only baseline enforcement")
		}
		pssIssuesStr := "<NONE>"
		if len(pssIssues) > 0 {
			pssIssuesStr = strings.Join(pssIssues, "; ")
		}

		pssRows = append(pssRows, []string{
			pss.Namespace,
			enforceLevel,
			auditLevel,
			warnLevel,
			enforceVersion,
			pssIssuesStr,
		})
	}

	// Generate loot
	generateRuntimeAdmissionLoot(loot, findings, runtimeClasses, seccompOperator, seccompProfiles, appArmorProfiles, unsandboxedPods, falco, tracee, pssResults)

	// Build output tables
	var tables []internal.TableFile

	// Always show: summary + unified policies
	tables = append(tables, internal.TableFile{
		Name:   "Runtime-Admission-Summary",
		Header: summaryHeader,
		Body:   summaryRows,
	})

	if len(policiesRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "Runtime-Admission-Policies",
			Header: policiesHeader,
			Body:   policiesRows,
		})
	}

	// Detailed tables: per-tool breakdowns (only with --detailed)
	if detailed {
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
				Name:   "Runtime-Admission-Unsandboxed-Pods",
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
		} else if operator.PodsRunning == 0 {
			operator.Status = "not-running"
		} else if operator.PodsRunning < operator.TotalPods {
			operator.Status = "degraded"
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

	return profile
}

// ============================================================================
// Falco Analysis
// ============================================================================

func analyzeRuntimeFalco(ctx context.Context, clientset kubernetes.Interface) RuntimeFalcoInfo {
	info := RuntimeFalcoInfo{}

	// Use SDK for expected namespaces and label selectors
	namespaces := admission.GetExpectedNamespaces("falco")
	if len(namespaces) == 0 {
		namespaces = []string{"falco", "falco-system", "security", "monitoring", "kube-system"}
	}
	labelSelectors := admission.GetEngineLabelSelectors("falco")
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
					if admission.VerifyControllerImage(container.Image, "falco") {
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
					if admission.VerifyControllerImage(container.Image, "falco") {
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
		} else if info.PodsRunning == 0 {
			info.Status = "not-running"
		} else if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
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
	namespaces := admission.GetExpectedNamespaces("tracee")
	if len(namespaces) == 0 {
		namespaces = []string{"tracee", "tracee-system", "security", "aqua", "kube-system"}
	}
	labelSelectors := admission.GetEngineLabelSelectors("tracee")
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
					if admission.VerifyControllerImage(container.Image, "tracee") {
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
					if admission.VerifyControllerImage(container.Image, "tracee") {
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
		} else if info.PodsRunning == 0 {
			info.Status = "not-running"
		} else if info.PodsRunning < info.TotalPods {
			info.Status = "degraded"
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

	// Sort unsandboxed pods by namespace
	sort.Slice(unsandboxedPods, func(i, j int) bool {
		if unsandboxedPods[i].Namespace != unsandboxedPods[j].Namespace {
			return unsandboxedPods[i].Namespace < unsandboxedPods[j].Namespace
		}
		return unsandboxedPods[i].Name < unsandboxedPods[j].Name
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

	s := loot.Section("runtime-admission")
	s.Add("# Runtime Security Summary")
	s.Add("#")

	// RuntimeClasses summary
	sandboxedRCs := 0
	for _, rc := range runtimeClasses {
		if rc.IsSandboxed {
			sandboxedRCs++
		}
	}
	s.Add(fmt.Sprintf("# RuntimeClasses: %d total, %d sandboxed", len(runtimeClasses), sandboxedRCs))

	// Seccomp summary
	if seccompOperator.Name != "" {
		status := seccompOperator.Status
		if seccompOperator.ImageVerified {
			status += " (verified)"
		}
		s.Add(fmt.Sprintf("# Security Profiles Operator: %s (%d profiles)", status, seccompOperator.Profiles))
	} else {
		s.Add("# Security Profiles Operator: Not installed")
	}

	// Runtime detection tools
	type toolStatus struct {
		name   string
		status string
		detail string
	}
	var detected []toolStatus

	if falco.Name != "" {
		detail := fmt.Sprintf("%d/%d pods", falco.PodsRunning, falco.TotalPods)
		detected = append(detected, toolStatus{"Falco", falco.Status, detail})
	}
	if tracee.Name != "" {
		detail := fmt.Sprintf("%d/%d pods", tracee.PodsRunning, tracee.TotalPods)
		detected = append(detected, toolStatus{"Tracee", tracee.Status, detail})
	}

	if len(detected) > 0 {
		s.Add("#")
		s.Add("# Runtime Detection Tools:")
		for _, t := range detected {
			s.Addf("#   %s: %s (%s)", t.name, strings.ToUpper(t.status), t.detail)
		}
	}

	// AppArmor summary
	s.Add("#")
	s.Add(fmt.Sprintf("# AppArmor Profiles: %d", len(appArmorProfiles)))

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
	s.Add(fmt.Sprintf("# Pod Security Standards: %d restricted, %d baseline, %d privileged", pssRestricted, pssBaseline, pssPrivileged))

	// Unsandboxed pods
	if len(unsandboxedPods) > 0 {
		s.Add("#")
		s.Add(fmt.Sprintf("# Unsandboxed Pods: %d total", len(unsandboxedPods)))
	}

	// Commands section - only for detected tools
	s.Add("#")
	s.Add("# Commands")
	s.Add("#")

	if len(runtimeClasses) > 0 {
		s.Add("# List RuntimeClasses:")
		s.Add("kubectl get runtimeclasses")
		s.Add("#")
	}

	if seccompOperator.Name != "" {
		s.Add("# Check Seccomp profiles:")
		s.Add("kubectl get seccompprofiles -A")
		s.Add("#")
	}

	if len(appArmorProfiles) > 0 {
		s.Add("# Check AppArmor profiles:")
		s.Add("kubectl get apparmorprofiles -A")
		s.Add("#")
	}

	if falco.Name != "" {
		s.Add("# Check Falco logs:")
		s.Addf("kubectl logs -n %s -l app=falco --tail=100", falco.Namespace)
		s.Add("#")
	}

	if tracee.Name != "" {
		s.Add("# Check Tracee logs:")
		s.Addf("kubectl logs -n %s -l app=tracee --tail=100", tracee.Namespace)
		s.Add("#")
	}

	s.Add("# Find privileged pods:")
	s.Add("kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + \"/\" + .metadata.name'")
	s.Add("#")
	s.Add("# Find pods without seccomp:")
	s.Add("kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.seccompProfile == null) | .metadata.namespace + \"/\" + .metadata.name'")
}
