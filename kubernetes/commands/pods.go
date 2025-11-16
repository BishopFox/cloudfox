package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var PodsCmd = &cobra.Command{
	Use:     "pods",
	Aliases: []string{},
	Short:   "List all cluster pods with security analysis",
	Long: `
List all cluster pods with comprehensive security analysis including:
- Container escape vectors and privilege escalation paths
- Sensitive host path mounts and their security implications
- Dangerous Linux capabilities that enable container breakouts
- Pod Security Standards (PSS) compliance violations
- Security context analysis (SELinux, AppArmor, Seccomp)
- Secret and ConfigMap exposure detection
- Image security analysis and vulnerability indicators
- Resource abuse detection and QoS analysis
- Risk-based scoring for prioritized security review
  cloudfox kubernetes pods`,
	Run: ListPods,
}

type PodsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t PodsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t PodsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type PodFinding struct {
	// Basic Info
	Namespace      string
	Name           string
	PodIP          string
	ServiceAccount string
	Node           string
	Phase          string
	Age            string

	// Security Analysis
	RiskLevel      string
	RiskScore      int
	SecurityIssues []string

	// Container Security Context
	Privileged             bool
	HostPID                bool
	HostIPC                bool
	HostNetwork            bool
	RunAsRoot              bool
	AllowPrivEsc           bool
	ReadOnlyRootFilesystem bool
	ProcMountUnmasked      bool
	SELinuxContext         string
	SELinuxCustom          bool
	AppArmorProfile        string
	AppArmorUndefined      bool
	SeccompProfile         string
	SeccompUnconfined      bool
	FSGroup                string
	SupplementalGroups     []string

	// Capabilities
	Capabilities   []string
	DangerousCaps  []string
	DroppedAllCaps bool

	// Host Path Mounts
	HostPaths          []string
	SensitiveHostPaths []string
	WritableHostPaths  int

	// Secret & ConfigMap Exposure
	SecretVolumes       []string
	SecretEnvVars       []string
	ConfigMapVolumes    []string
	ConfigMapEnvVars    []string
	ProjectedVolumes    []string
	TotalSecretsExposed int

	// Service Account Token
	AutomountSAToken bool
	SATokenProjected bool
	SATokenPath      string

	// Image Security
	Images          []string
	ImageTagTypes   []string
	ImagePullPolicy []string
	ImageDigests    []string
	ImageRegistries []string
	LatestTag       bool
	UnverifiedImage bool

	// Resource Management
	ResourceLimits   []string
	ResourceRequests []string
	NoLimits         bool
	NoRequests       bool
	QoSClass         string

	// Workload Controller
	ControllerType string
	ControllerName string
	IsOrphaned     bool

	// Runtime & Isolation
	RuntimeClass        string
	ServiceMesh         string
	InitContainers      int
	EphemeralContainers int

	// Network
	ContainerPorts []string
	HostPorts      []string

	// Volume Analysis
	EmptyDirVolumes []string
	PVCVolumes      []string
	DownwardAPI     bool

	// PSS Compliance
	PSSCompliance        string
	PSSViolations        []string
	RestrictedViolations int
	BaselineViolations   int

	// Metadata
	Labels      map[string]string
	Affinity    string
	Tolerations []string
	Annotations map[string]string

	// Cloud
	CloudProvider string
	CloudRole     string
}

// SecurityContextAnalysis holds detailed security context info
type SecurityContextAnalysis struct {
	ReadOnlyRootFilesystem   bool
	RunAsUser                *int64
	RunAsGroup               *int64
	RunAsNonRoot             *bool
	AllowPrivilegeEscalation *bool
	Privileged               *bool
	ProcMount                string
	SELinuxOptions           *corev1.SELinuxOptions
	SeccompProfile           *corev1.SeccompProfile
	AppArmorProfile          string
	FSGroup                  *int64
	SupplementalGroups       []int64
	Capabilities             *corev1.Capabilities
}

// ImageAnalysis holds image security information
type ImageAnalysis struct {
	Image        string
	TagType      string
	PullPolicy   string
	Digest       string
	Registry     string
	IsLatest     bool
	IsUnverified bool
}

// ResourceAnalysis holds resource limit/request info
type PodResourceAnalysis struct {
	HasLimits   bool
	HasRequests bool
	Limits      map[string]string
	Requests    map[string]string
}

// PSSViolation represents a Pod Security Standards violation
type PSSViolation struct {
	Level       string // "baseline" or "restricted"
	Field       string
	Violation   string
	Remediation string
}

func ListPods(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating cluster pods for %s", globals.ClusterName), globals.K8S_PODS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_PODS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk", "Risk Score", "Namespace", "Pod Name", "Pod IP", "Phase",
		"Service Account", "Node", "Controller Type", "Controller Name",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "RunAsRoot",
		"AllowPrivEsc", "ReadOnlyRootFS", "SELinux", "AppArmor", "Seccomp",
		"Capabilities", "Dangerous Caps", "HostPaths", "Sensitive HostPaths",
		"Secret Volumes", "Secret EnvVars", "ConfigMap Volumes", "Image Tags",
		"Image Pull Policy", "Resource Limits", "Resource Requests", "QoS Class",
		"PSS Compliance", "PSS Violations", "Security Issues",
	}

	var outputRows [][]string
	var findings []PodFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Loot content builders
	var lootExec []string
	var lootEnum []string
	var lootPrivEsc []string
	var lootContainerEscape []string
	var lootHostCompromise []string
	var lootPSSViolations []string
	var lootSecretExposure []string
	var lootImageVulns []string
	var lootResourceAbuse []string
	var lootWeakIsolation []string
	var lootTokenExploit []string
	var lootLateralMovement []string
	var lootOrphaned []string
	var lootAttackChains []string
	var lootRemediation []string

	// Initialize loot headers
	lootExec = append(lootExec, `#####################################
##### Execute into running Kubernetes Pods
#####################################
#
# MANUAL EXECUTION REQUIRED
# kubectl exec commands for pod access
#
`)

	lootEnum = append(lootEnum, `#####################################
##### Enumerate Pod Information
#####################################
#
# MANUAL EXECUTION REQUIRED
# Detailed pod enumeration commands
#
`)

	lootPrivEsc = append(lootPrivEsc, `#####################################
##### Pod Privilege Escalation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Pods with security misconfigurations
# that can be leveraged for privilege escalation
#
`)

	lootContainerEscape = append(lootContainerEscape, `#####################################
##### Container Escape Techniques
#####################################
#
# MANUAL EXECUTION REQUIRED
# Detailed container escape vectors for high-risk pods
# Organized by escape method and risk level
#
`)

	lootHostCompromise = append(lootHostCompromise, `#####################################
##### Host Compromise Paths
#####################################
#
# MANUAL EXECUTION REQUIRED
# Techniques to compromise the underlying host node
# from privileged or misconfigured pods
#
`)

	lootPSSViolations = append(lootPSSViolations, `#####################################
##### Pod Security Standards Violations
#####################################
#
# ANALYSIS REPORT
# Pods violating PSS baseline and restricted levels
# Shows what security controls are missing
#
`)

	lootSecretExposure = append(lootSecretExposure, `#####################################
##### Secret and ConfigMap Exposure
#####################################
#
# MANUAL EXECUTION REQUIRED
# Pods with secrets/configmaps mounted or in env vars
# Commands to extract sensitive data
#
`)

	lootImageVulns = append(lootImageVulns, `#####################################
##### Image Security Vulnerabilities
#####################################
#
# ANALYSIS REPORT
# Pods using risky images (latest tags, unverified, etc.)
#
`)

	lootResourceAbuse = append(lootResourceAbuse, `#####################################
##### Resource Abuse Potential
#####################################
#
# ANALYSIS REPORT
# Pods without resource limits (DoS risk)
#
`)

	lootWeakIsolation = append(lootWeakIsolation, `#####################################
##### Weak Security Isolation
#####################################
#
# ANALYSIS REPORT
# Pods without seccomp/apparmor/selinux protections
#
`)

	lootTokenExploit = append(lootTokenExploit, `#####################################
##### Service Account Token Exploitation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Extract and test service account tokens
#
`)

	lootLateralMovement = append(lootLateralMovement, `#####################################
##### Lateral Movement Opportunities
#####################################
#
# MANUAL EXECUTION REQUIRED
# Pod-to-pod and pod-to-node attack paths
#
`)

	lootOrphaned = append(lootOrphaned, `#####################################
##### Orphaned Pods (No Controller)
#####################################
#
# ANALYSIS REPORT
# Manually created pods without controller management
# Often indicate testing or attacker activity
#
`)

	lootAttackChains = append(lootAttackChains, `#####################################
##### Complete Attack Chains
#####################################
#
# MANUAL EXECUTION REQUIRED
# Multi-step attack paths from pod compromise to cluster admin
#
`)

	lootRemediation = append(lootRemediation, `#####################################
##### Security Remediation Guide
#####################################
#
# REMEDIATION STEPS
# How to fix identified security issues
#
`)

	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing pods in namespace %s: %v\n", ns.Name, err)
			continue
		}

		for _, pod := range pods.Items {
			finding := PodFinding{
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				PodIP:          pod.Status.PodIP,
				ServiceAccount: pod.Spec.ServiceAccountName,
				Node:           pod.Spec.NodeName,
				Phase:          string(pod.Status.Phase),
				HostPID:        pod.Spec.HostPID,
				HostIPC:        pod.Spec.HostIPC,
				HostNetwork:    pod.Spec.HostNetwork,
				Labels:         pod.Labels,
				Annotations:    pod.Annotations,
				InitContainers: len(pod.Spec.InitContainers),
			}

			// Detect ephemeral containers
			if pod.Spec.EphemeralContainers != nil {
				finding.EphemeralContainers = len(pod.Spec.EphemeralContainers)
			}

			// Runtime class
			if pod.Spec.RuntimeClassName != nil {
				finding.RuntimeClass = *pod.Spec.RuntimeClassName
			}

			// Service mesh detection
			finding.ServiceMesh = detectServiceMesh(pod.Annotations, pod.Labels)

			// Workload controller detection
			finding.ControllerType, finding.ControllerName = detectController(pod.ObjectMeta)
			finding.IsOrphaned = (finding.ControllerType == "None")

			// QoS class
			finding.QoSClass = string(pod.Status.QOSClass)

			// Analyze all containers (init + regular + ephemeral)
			allContainers := []corev1.Container{}
			allContainers = append(allContainers, pod.Spec.InitContainers...)
			allContainers = append(allContainers, pod.Spec.Containers...)
			for _, ec := range pod.Spec.EphemeralContainers {
				allContainers = append(allContainers, corev1.Container{
					Name:            ec.Name,
					Image:           ec.Image,
					ImagePullPolicy: ec.ImagePullPolicy,
					SecurityContext: ec.SecurityContext,
					VolumeMounts:    ec.VolumeMounts,
					Env:             ec.Env,
				})
			}

			// Aggregate security context analysis
			secCtx := podAnalyzeSecurityContext(&pod.Spec, allContainers)
			finding.Privileged = secCtx.Privileged != nil && *secCtx.Privileged
			finding.AllowPrivEsc = secCtx.AllowPrivilegeEscalation == nil || *secCtx.AllowPrivilegeEscalation
			finding.ReadOnlyRootFilesystem = secCtx.ReadOnlyRootFilesystem
			finding.ProcMountUnmasked = (secCtx.ProcMount == "Unmasked")
			finding.RunAsRoot = isRunAsRoot(secCtx)

			// SELinux analysis
			if secCtx.SELinuxOptions != nil {
				finding.SELinuxContext = formatSELinuxContext(secCtx.SELinuxOptions)
				// Custom SELinux options are a PSS restricted violation
				finding.SELinuxCustom = (secCtx.SELinuxOptions.Level != "" || secCtx.SELinuxOptions.Role != "" ||
					secCtx.SELinuxOptions.Type != "" || secCtx.SELinuxOptions.User != "")
			} else {
				finding.SELinuxContext = "<none>"
			}

			// AppArmor analysis
			finding.AppArmorProfile = getAppArmorProfile(pod.Annotations)
			finding.AppArmorUndefined = (finding.AppArmorProfile == "" || finding.AppArmorProfile == "<none>")

			// Seccomp analysis
			if secCtx.SeccompProfile != nil {
				finding.SeccompProfile = formatSeccompProfile(secCtx.SeccompProfile)
				finding.SeccompUnconfined = (secCtx.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined)
			} else {
				finding.SeccompProfile = "<none>"
				finding.SeccompUnconfined = true // Not set = unconfined in older versions
			}

			// FSGroup and SupplementalGroups
			if secCtx.FSGroup != nil {
				finding.FSGroup = fmt.Sprintf("%d", *secCtx.FSGroup)
			} else {
				finding.FSGroup = "<none>"
			}
			for _, sg := range secCtx.SupplementalGroups {
				finding.SupplementalGroups = append(finding.SupplementalGroups, fmt.Sprintf("%d", sg))
			}

			// Capability analysis
			if secCtx.Capabilities != nil {
				for _, cap := range secCtx.Capabilities.Add {
					capStr := string(cap)
					finding.Capabilities = append(finding.Capabilities, capStr)
					if k8sinternal.IsDangerousCapability(capStr) {
						finding.DangerousCaps = append(finding.DangerousCaps, capStr)
					}
				}
				for _, cap := range secCtx.Capabilities.Drop {
					capStr := string(cap)
					finding.Capabilities = append(finding.Capabilities, "-"+capStr)
					if capStr == "ALL" {
						finding.DroppedAllCaps = true
					}
				}
			}

			// Image analysis
			imageAnalyses := analyzeImages(allContainers)
			for _, img := range imageAnalyses {
				finding.Images = append(finding.Images, img.Image)
				finding.ImageTagTypes = append(finding.ImageTagTypes, img.TagType)
				finding.ImagePullPolicy = append(finding.ImagePullPolicy, img.PullPolicy)
				finding.ImageDigests = append(finding.ImageDigests, img.Digest)
				finding.ImageRegistries = append(finding.ImageRegistries, img.Registry)
				if img.IsLatest {
					finding.LatestTag = true
				}
				if img.IsUnverified {
					finding.UnverifiedImage = true
				}
			}

			// Resource analysis
			resAnalysis := analyzeResources(allContainers)
			finding.NoLimits = !resAnalysis.HasLimits
			finding.NoRequests = !resAnalysis.HasRequests
			for k, v := range resAnalysis.Limits {
				finding.ResourceLimits = append(finding.ResourceLimits, fmt.Sprintf("%s=%s", k, v))
			}
			for k, v := range resAnalysis.Requests {
				finding.ResourceRequests = append(finding.ResourceRequests, fmt.Sprintf("%s=%s", k, v))
			}

			// Volume analysis
			podAnalyzeVolumes(&pod.Spec, &finding, allContainers)

			// Service Account token analysis
			finding.AutomountSAToken = true // Default
			if pod.Spec.AutomountServiceAccountToken != nil {
				finding.AutomountSAToken = *pod.Spec.AutomountServiceAccountToken
			}
			finding.SATokenProjected = hasProjectedSAToken(pod.Spec.Volumes)
			finding.SATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

			// Network ports
			for _, container := range allContainers {
				for _, port := range container.Ports {
					portStr := fmt.Sprintf("%d/%s", port.ContainerPort, port.Protocol)
					finding.ContainerPorts = append(finding.ContainerPorts, portStr)
					if port.HostPort != 0 {
						finding.HostPorts = append(finding.HostPorts, fmt.Sprintf("%d->%d", port.HostPort, port.ContainerPort))
					}
				}
			}

			// HostPath analysis
			analyzeHostPaths(&pod.Spec, &finding)

			// Cloud role detection
			roleResults := k8sinternal.DetectCloudRole(ctx, clientset, pod.Namespace, pod.Spec.ServiceAccountName, &pod.Spec, pod.Annotations)
			if len(roleResults) > 0 {
				finding.CloudProvider = roleResults[0].Provider
				finding.CloudRole = roleResults[0].Role
			}

			// PSS Compliance Analysis
			finding.PSSViolations, finding.PSSCompliance = analyzePSSCompliance(&pod.Spec, &finding, secCtx)
			finding.RestrictedViolations = countPSSViolations(finding.PSSViolations, "restricted")
			finding.BaselineViolations = countPSSViolations(finding.PSSViolations, "baseline")

			// Security Issues Summary
			finding.SecurityIssues = generateSecurityIssues(&finding)

			// Calculate risk score and level
			finding.RiskLevel, finding.RiskScore = calculatePodRiskScore(&finding)

			riskCounts[finding.RiskLevel]++
			findings = append(findings, finding)

			// Generate table row
			row := generateTableRow(&finding)
			outputRows = append(outputRows, row)

			// Generate loot content
			podGenerateLootContent(&finding, &pod,
				&lootExec, &lootEnum, &lootPrivEsc, &lootContainerEscape,
				&lootHostCompromise, &lootPSSViolations, &lootSecretExposure,
				&lootImageVulns, &lootResourceAbuse, &lootWeakIsolation,
				&lootTokenExploit, &lootLateralMovement, &lootOrphaned,
				&lootAttackChains, &lootRemediation)
		}
	}

	// Add summaries
	summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d pods
# HIGH: %d pods
# MEDIUM: %d pods
# LOW: %d pods
#
# Focus on CRITICAL and HIGH risk pods first for maximum impact.
# See detailed exploitation techniques below:
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

	lootPrivEsc = append([]string{summary}, lootPrivEsc...)
	lootContainerEscape = append([]string{summary}, lootContainerEscape...)
	lootHostCompromise = append([]string{summary}, lootHostCompromise...)

	// Create table
	table := internal.TableFile{
		Name:   "Pods",
		Header: headers,
		Body:   outputRows,
	}

	// Create loot files
	lootFiles := []internal.LootFile{
		{Name: "Pods-Execution", Contents: strings.Join(lootExec, "\n")},
		{Name: "Pods-Enum", Contents: strings.Join(lootEnum, "\n")},
		{Name: "Pods-Privilege-Escalation", Contents: strings.Join(lootPrivEsc, "\n")},
		{Name: "Pods-Container-Escape", Contents: strings.Join(lootContainerEscape, "\n")},
		{Name: "Pods-Host-Compromise", Contents: strings.Join(lootHostCompromise, "\n")},
		{Name: "Pods-PSS-Violations", Contents: strings.Join(lootPSSViolations, "\n")},
		{Name: "Pods-Secret-Exposure", Contents: strings.Join(lootSecretExposure, "\n")},
		{Name: "Pods-Image-Vulnerabilities", Contents: strings.Join(lootImageVulns, "\n")},
		{Name: "Pods-Resource-Abuse", Contents: strings.Join(lootResourceAbuse, "\n")},
		{Name: "Pods-Weak-Isolation", Contents: strings.Join(lootWeakIsolation, "\n")},
		{Name: "Pods-Token-Exploitation", Contents: strings.Join(lootTokenExploit, "\n")},
		{Name: "Pods-Lateral-Movement", Contents: strings.Join(lootLateralMovement, "\n")},
		{Name: "Pods-Orphaned", Contents: strings.Join(lootOrphaned, "\n")},
		{Name: "Pods-Attack-Chains", Contents: strings.Join(lootAttackChains, "\n")},
		{Name: "Pods-Remediation", Contents: strings.Join(lootRemediation, "\n")},
	}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Pods",
		globals.ClusterName,
		"results",
		PodsOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PODS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d pods found across %d namespaces | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows), len(namespaces.Items),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_PODS_MODULE_NAME)
	} else {
		logger.InfoM("No pods found, skipping output file creation", globals.K8S_PODS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PODS_MODULE_NAME), globals.K8S_PODS_MODULE_NAME)
}

// analyzeSecurityContext aggregates security context from pod and containers
func podAnalyzeSecurityContext(podSpec *corev1.PodSpec, containers []corev1.Container) SecurityContextAnalysis {
	analysis := SecurityContextAnalysis{}

	// Pod-level security context
	if podSpec.SecurityContext != nil {
		analysis.FSGroup = podSpec.SecurityContext.FSGroup
		analysis.SupplementalGroups = podSpec.SecurityContext.SupplementalGroups
		if podSpec.SecurityContext.SELinuxOptions != nil {
			analysis.SELinuxOptions = podSpec.SecurityContext.SELinuxOptions
		}
		if podSpec.SecurityContext.SeccompProfile != nil {
			analysis.SeccompProfile = podSpec.SecurityContext.SeccompProfile
		}
	}

	// Aggregate container-level security contexts
	privileged := false
	allowPrivEsc := false
	readOnlyRootFS := false
	var runAsUser *int64
	var runAsNonRoot *bool
	procMount := ""

	for _, container := range containers {
		if container.SecurityContext != nil {
			sc := container.SecurityContext

			if sc.Privileged != nil && *sc.Privileged {
				privileged = true
			}

			if sc.AllowPrivilegeEscalation != nil {
				if *sc.AllowPrivilegeEscalation {
					allowPrivEsc = true
				}
			} else {
				// Default is true
				allowPrivEsc = true
			}

			if sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem {
				readOnlyRootFS = true
			}

			if sc.RunAsUser != nil {
				runAsUser = sc.RunAsUser
			}

			if sc.RunAsNonRoot != nil {
				runAsNonRoot = sc.RunAsNonRoot
			}

			if sc.ProcMount != nil {
				procMount = string(*sc.ProcMount)
			}

			// SELinux - container overrides pod
			if sc.SELinuxOptions != nil {
				analysis.SELinuxOptions = sc.SELinuxOptions
			}

			// Seccomp - container overrides pod
			if sc.SeccompProfile != nil {
				analysis.SeccompProfile = sc.SeccompProfile
			}

			// Aggregate capabilities
			if sc.Capabilities != nil {
				if analysis.Capabilities == nil {
					analysis.Capabilities = &corev1.Capabilities{}
				}
				analysis.Capabilities.Add = append(analysis.Capabilities.Add, sc.Capabilities.Add...)
				analysis.Capabilities.Drop = append(analysis.Capabilities.Drop, sc.Capabilities.Drop...)
			}
		}
	}

	analysis.Privileged = &privileged
	analysis.AllowPrivilegeEscalation = &allowPrivEsc
	analysis.ReadOnlyRootFilesystem = readOnlyRootFS
	analysis.RunAsUser = runAsUser
	analysis.RunAsNonRoot = runAsNonRoot
	analysis.ProcMount = procMount

	return analysis
}

// isRunAsRoot determines if pod runs as root
func isRunAsRoot(secCtx SecurityContextAnalysis) bool {
	// If runAsNonRoot is explicitly true, not root
	if secCtx.RunAsNonRoot != nil && *secCtx.RunAsNonRoot {
		return false
	}

	// If runAsUser is 0, definitely root
	if secCtx.RunAsUser != nil && *secCtx.RunAsUser == 0 {
		return true
	}

	// If runAsUser is > 0, not root
	if secCtx.RunAsUser != nil && *secCtx.RunAsUser > 0 {
		return false
	}

	// Unset defaults to root in many images
	return true
}

// formatSELinuxContext formats SELinux options
func formatSELinuxContext(sel *corev1.SELinuxOptions) string {
	parts := []string{}
	if sel.User != "" {
		parts = append(parts, fmt.Sprintf("user:%s", sel.User))
	}
	if sel.Role != "" {
		parts = append(parts, fmt.Sprintf("role:%s", sel.Role))
	}
	if sel.Type != "" {
		parts = append(parts, fmt.Sprintf("type:%s", sel.Type))
	}
	if sel.Level != "" {
		parts = append(parts, fmt.Sprintf("level:%s", sel.Level))
	}
	if len(parts) == 0 {
		return "<none>"
	}
	return strings.Join(parts, ",")
}

// getAppArmorProfile extracts AppArmor profile from annotations
func getAppArmorProfile(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") {
			return v
		}
	}
	return "<none>"
}

// formatSeccompProfile formats seccomp profile
func formatSeccompProfile(profile *corev1.SeccompProfile) string {
	switch profile.Type {
	case corev1.SeccompProfileTypeUnconfined:
		return "Unconfined"
	case corev1.SeccompProfileTypeRuntimeDefault:
		return "RuntimeDefault"
	case corev1.SeccompProfileTypeLocalhost:
		if profile.LocalhostProfile != nil {
			return fmt.Sprintf("Localhost:%s", *profile.LocalhostProfile)
		}
		return "Localhost"
	default:
		return string(profile.Type)
	}
}

// analyzeImages analyzes container images
func analyzeImages(containers []corev1.Container) []ImageAnalysis {
	var analyses []ImageAnalysis

	for _, container := range containers {
		analysis := ImageAnalysis{
			Image:      container.Image,
			PullPolicy: string(container.ImagePullPolicy),
		}

		// Tag type
		analysis.TagType = k8sinternal.ImageTagType(container.Image)
		analysis.IsLatest = strings.HasSuffix(container.Image, ":latest") || !strings.Contains(container.Image, ":")

		// Digest vs tag
		if strings.Contains(container.Image, "@sha256:") {
			parts := strings.Split(container.Image, "@")
			if len(parts) == 2 {
				analysis.Digest = parts[1]
			}
			analysis.IsUnverified = false
		} else {
			analysis.Digest = "<none>"
			analysis.IsUnverified = true
		}

		// Registry
		if strings.Contains(container.Image, "/") {
			parts := strings.Split(container.Image, "/")
			analysis.Registry = parts[0]
		} else {
			analysis.Registry = "docker.io"
		}

		analyses = append(analyses, analysis)
	}

	return analyses
}

// analyzeResources analyzes resource limits and requests
func analyzeResources(containers []corev1.Container) PodResourceAnalysis {
	analysis := PodResourceAnalysis{
		Limits:   make(map[string]string),
		Requests: make(map[string]string),
	}

	for _, container := range containers {
		if container.Resources.Limits != nil && len(container.Resources.Limits) > 0 {
			analysis.HasLimits = true
			for k, v := range container.Resources.Limits {
				analysis.Limits[string(k)] = v.String()
			}
		}
		if container.Resources.Requests != nil && len(container.Resources.Requests) > 0 {
			analysis.HasRequests = true
			for k, v := range container.Resources.Requests {
				analysis.Requests[string(k)] = v.String()
			}
		}
	}

	return analysis
}

// analyzeVolumes analyzes all volume types
func podAnalyzeVolumes(podSpec *corev1.PodSpec, finding *PodFinding, containers []corev1.Container) {
	for _, volume := range podSpec.Volumes {
		// Secret volumes
		if volume.Secret != nil {
			secretInfo := fmt.Sprintf("%s (secret:%s)", volume.Name, volume.Secret.SecretName)
			finding.SecretVolumes = append(finding.SecretVolumes, secretInfo)
			finding.TotalSecretsExposed++
		}

		// ConfigMap volumes
		if volume.ConfigMap != nil {
			cmInfo := fmt.Sprintf("%s (cm:%s)", volume.Name, volume.ConfigMap.Name)
			finding.ConfigMapVolumes = append(finding.ConfigMapVolumes, cmInfo)
		}

		// Projected volumes (can contain secrets)
		if volume.Projected != nil {
			hasSecrets := false
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil {
					hasSecrets = true
					finding.TotalSecretsExposed++
				}
			}
			projInfo := volume.Name
			if hasSecrets {
				projInfo += " (contains secrets)"
			}
			finding.ProjectedVolumes = append(finding.ProjectedVolumes, projInfo)
		}

		// EmptyDir volumes
		if volume.EmptyDir != nil {
			finding.EmptyDirVolumes = append(finding.EmptyDirVolumes, volume.Name)
		}

		// PVC volumes
		if volume.PersistentVolumeClaim != nil {
			finding.PVCVolumes = append(finding.PVCVolumes, volume.PersistentVolumeClaim.ClaimName)
		}

		// DownwardAPI
		if volume.DownwardAPI != nil {
			finding.DownwardAPI = true
		}
	}

	// Check for secrets in environment variables
	for _, container := range containers {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				secretEnvInfo := fmt.Sprintf("%s (secret:%s, key:%s)",
					env.Name, env.ValueFrom.SecretKeyRef.Name, env.ValueFrom.SecretKeyRef.Key)
				finding.SecretEnvVars = append(finding.SecretEnvVars, secretEnvInfo)
				finding.TotalSecretsExposed++
			}
			if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
				cmEnvInfo := fmt.Sprintf("%s (cm:%s, key:%s)",
					env.Name, env.ValueFrom.ConfigMapKeyRef.Name, env.ValueFrom.ConfigMapKeyRef.Key)
				finding.ConfigMapEnvVars = append(finding.ConfigMapEnvVars, cmEnvInfo)
			}
		}
	}
}

// analyzeHostPaths analyzes host path mounts
func analyzeHostPaths(podSpec *corev1.PodSpec, finding *PodFinding) {
	for _, volume := range podSpec.Volumes {
		if volume.HostPath != nil {
			mountPoint := k8sinternal.FindMountPath(volume.Name, podSpec.Containers)

			// Determine if readonly
			readOnly := false
			for _, container := range podSpec.Containers {
				for _, vm := range container.VolumeMounts {
					if vm.Name == volume.Name {
						readOnly = vm.ReadOnly
						break
					}
				}
			}

			if !readOnly {
				finding.WritableHostPaths++
			}

			// Analyze host path
			isSensitive, description := k8sinternal.AnalyzeHostPath(volume.HostPath.Path, readOnly)

			hostPathLine := fmt.Sprintf("%s:%s", volume.HostPath.Path, mountPoint)
			if readOnly {
				hostPathLine += " (ro)"
			} else {
				hostPathLine += " (rw)"
			}

			if isSensitive {
				hostPathLine += fmt.Sprintf(" - %s", description)
				finding.SensitiveHostPaths = append(finding.SensitiveHostPaths, fmt.Sprintf("%s - %s", volume.HostPath.Path, description))
			}

			finding.HostPaths = append(finding.HostPaths, hostPathLine)
		}
	}
}

// hasProjectedSAToken checks if service account token is projected
func hasProjectedSAToken(volumes []corev1.Volume) bool {
	for _, vol := range volumes {
		if vol.Projected != nil {
			for _, source := range vol.Projected.Sources {
				if source.ServiceAccountToken != nil {
					return true
				}
			}
		}
	}
	return false
}

// detectServiceMesh detects service mesh injection
func detectServiceMesh(annotations, labels map[string]string) string {
	// Istio
	if annotations["sidecar.istio.io/status"] != "" || labels["istio.io/rev"] != "" {
		return "Istio"
	}
	if annotations["sidecar.istio.io/inject"] == "true" {
		return "Istio"
	}

	// Linkerd
	if annotations["linkerd.io/inject"] == "enabled" {
		return "Linkerd"
	}

	// Consul
	if annotations["consul.hashicorp.com/connect-inject"] == "true" {
		return "Consul"
	}

	return "<none>"
}

// detectController detects the workload controller that owns this pod
func detectController(meta metav1.ObjectMeta) (string, string) {
	if meta.OwnerReferences == nil || len(meta.OwnerReferences) == 0 {
		return "None", ""
	}

	// Primary owner
	owner := meta.OwnerReferences[0]

	switch owner.Kind {
	case "ReplicaSet":
		// ReplicaSet might be owned by Deployment
		rsName := owner.Name
		// Try to extract deployment name (RS name is usually deployment-name-hash)
		parts := strings.Split(rsName, "-")
		if len(parts) > 1 {
			deployName := strings.Join(parts[:len(parts)-1], "-")
			return "Deployment", deployName
		}
		return "ReplicaSet", owner.Name
	case "StatefulSet":
		return "StatefulSet", owner.Name
	case "DaemonSet":
		return "DaemonSet", owner.Name
	case "Job":
		return "Job", owner.Name
	case "CronJob":
		return "CronJob", owner.Name
	default:
		return owner.Kind, owner.Name
	}
}

// analyzePSSCompliance checks pod against PSS baseline and restricted levels
func analyzePSSCompliance(podSpec *corev1.PodSpec, finding *PodFinding, secCtx SecurityContextAnalysis) ([]string, string) {
	var violations []string

	// PSS Baseline violations (basic security restrictions)
	if finding.Privileged {
		violations = append(violations, "baseline: privileged containers not allowed")
	}

	if finding.HostPID {
		violations = append(violations, "baseline: hostPID not allowed")
	}

	if finding.HostIPC {
		violations = append(violations, "baseline: hostIPC not allowed")
	}

	if finding.HostNetwork {
		violations = append(violations, "baseline: hostNetwork not allowed")
	}

	if len(finding.HostPaths) > 0 {
		violations = append(violations, "baseline: hostPath volumes not allowed")
	}

	if len(finding.HostPorts) > 0 {
		violations = append(violations, "baseline: hostPorts not allowed")
	}

	if finding.AppArmorUndefined {
		violations = append(violations, "baseline: AppArmor profile undefined")
	}

	if finding.SELinuxCustom {
		violations = append(violations, "baseline: custom SELinux options not allowed")
	}

	if finding.ProcMountUnmasked {
		violations = append(violations, "baseline: unmasked /proc mount not allowed")
	}

	// Check dangerous capabilities (baseline)
	baselineForbiddenCaps := map[string]bool{
		"SYS_ADMIN": true, "NET_ADMIN": true, "SYS_MODULE": true,
		"SYS_RAWIO": true, "SYS_PTRACE": true, "SYS_BOOT": true,
		"MAC_ADMIN": true, "MAC_OVERRIDE": true, "PERFMON": true,
		"BPF": true, "NET_RAW": true,
	}
	for _, cap := range finding.DangerousCaps {
		if baselineForbiddenCaps[cap] {
			violations = append(violations, fmt.Sprintf("baseline: capability %s not allowed", cap))
		}
	}

	// PSS Restricted violations (hardened security)
	if !finding.DroppedAllCaps {
		violations = append(violations, "restricted: must drop ALL capabilities")
	}

	if len(finding.Capabilities) > 0 {
		// Restricted allows only NET_BIND_SERVICE
		for _, cap := range finding.Capabilities {
			if !strings.HasPrefix(cap, "-") && cap != "NET_BIND_SERVICE" {
				violations = append(violations, fmt.Sprintf("restricted: capability %s not in allowed list (only NET_BIND_SERVICE allowed)", cap))
			}
		}
	}

	if secCtx.RunAsNonRoot == nil || !*secCtx.RunAsNonRoot {
		violations = append(violations, "restricted: runAsNonRoot must be true")
	}

	if finding.AllowPrivEsc {
		violations = append(violations, "restricted: allowPrivilegeEscalation must be false")
	}

	if finding.SeccompProfile == "<none>" || finding.SeccompUnconfined {
		violations = append(violations, "restricted: seccompProfile must be RuntimeDefault or Localhost")
	}

	// Volume type restrictions (restricted)
	restrictedAllowedVolumes := map[string]bool{
		"configMap": true, "downwardAPI": true, "emptyDir": true,
		"persistentVolumeClaim": true, "projected": true, "secret": true,
	}
	for _, vol := range podSpec.Volumes {
		volType := getVolumeType(vol)
		if !restrictedAllowedVolumes[volType] {
			violations = append(violations, fmt.Sprintf("restricted: volume type %s not allowed", volType))
		}
	}

	// Determine compliance level
	compliance := "Privileged" // Most permissive
	if len(violations) == 0 {
		compliance = "Restricted" // Most secure
	} else {
		// Check if only restricted violations (no baseline violations)
		hasBaselineViolation := false
		for _, v := range violations {
			if strings.HasPrefix(v, "baseline:") {
				hasBaselineViolation = true
				break
			}
		}
		if !hasBaselineViolation {
			compliance = "Baseline" // Meets baseline but not restricted
		}
	}

	return violations, compliance
}

// getVolumeType returns the volume type
func getVolumeType(vol corev1.Volume) string {
	if vol.HostPath != nil {
		return "hostPath"
	}
	if vol.EmptyDir != nil {
		return "emptyDir"
	}
	if vol.Secret != nil {
		return "secret"
	}
	if vol.ConfigMap != nil {
		return "configMap"
	}
	if vol.PersistentVolumeClaim != nil {
		return "persistentVolumeClaim"
	}
	if vol.Projected != nil {
		return "projected"
	}
	if vol.DownwardAPI != nil {
		return "downwardAPI"
	}
	if vol.NFS != nil {
		return "nfs"
	}
	if vol.ISCSI != nil {
		return "iscsi"
	}
	if vol.Glusterfs != nil {
		return "glusterfs"
	}
	if vol.RBD != nil {
		return "rbd"
	}
	if vol.CephFS != nil {
		return "cephfs"
	}
	return "unknown"
}

// countPSSViolations counts violations for a specific level
func countPSSViolations(violations []string, level string) int {
	count := 0
	prefix := level + ":"
	for _, v := range violations {
		if strings.HasPrefix(v, prefix) {
			count++
		}
	}
	return count
}

// generateSecurityIssues creates a summary of security issues
func generateSecurityIssues(finding *PodFinding) []string {
	var issues []string

	if finding.Privileged {
		issues = append(issues, "PRIVILEGED container")
	}
	if finding.HostPID {
		issues = append(issues, "HOST_PID namespace")
	}
	if finding.HostIPC {
		issues = append(issues, "HOST_IPC namespace")
	}
	if finding.HostNetwork {
		issues = append(issues, "HOST_NETWORK namespace")
	}
	if len(finding.SensitiveHostPaths) > 0 {
		issues = append(issues, fmt.Sprintf("SENSITIVE_HOSTPATHS(%d)", len(finding.SensitiveHostPaths)))
	}
	if len(finding.DangerousCaps) > 0 {
		issues = append(issues, fmt.Sprintf("DANGEROUS_CAPS(%s)", strings.Join(finding.DangerousCaps, ",")))
	}
	if finding.RunAsRoot {
		issues = append(issues, "RUN_AS_ROOT")
	}
	if finding.AllowPrivEsc {
		issues = append(issues, "ALLOW_PRIV_ESC")
	}
	if !finding.ReadOnlyRootFilesystem {
		issues = append(issues, "WRITABLE_ROOT_FS")
	}
	if finding.SeccompUnconfined {
		issues = append(issues, "SECCOMP_UNCONFINED")
	}
	if finding.AppArmorUndefined {
		issues = append(issues, "APPARMOR_UNDEFINED")
	}
	if finding.TotalSecretsExposed > 0 {
		issues = append(issues, fmt.Sprintf("SECRETS_EXPOSED(%d)", finding.TotalSecretsExposed))
	}
	if finding.LatestTag {
		issues = append(issues, "LATEST_TAG")
	}
	if finding.NoLimits {
		issues = append(issues, "NO_RESOURCE_LIMITS")
	}
	if finding.IsOrphaned {
		issues = append(issues, "ORPHANED_POD")
	}
	if finding.RestrictedViolations > 0 {
		issues = append(issues, fmt.Sprintf("PSS_VIOLATIONS(%d)", finding.RestrictedViolations))
	}

	return issues
}

// calculatePodRiskScore calculates comprehensive risk score
func calculatePodRiskScore(finding *PodFinding) (string, int) {
	score := 0

	// CRITICAL factors (instant high score)
	if finding.Privileged {
		score += 90
		if finding.HostPID || finding.HostNetwork || finding.HostIPC {
			return "CRITICAL", 100 // Privileged + host namespace = guaranteed escape
		}
	}

	// Host namespace access
	if finding.HostPID {
		score += 70
	}
	if finding.HostNetwork {
		score += 60
	}
	if finding.HostIPC {
		score += 50
	}

	// Sensitive host paths
	for _, hp := range finding.SensitiveHostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd") {
			score += 95 // Container runtime socket = CRITICAL
		} else if strings.Contains(hp, "/etc/kubernetes") || strings.Contains(hp, "kubelet") {
			score += 85 // K8s secrets = CRITICAL
		} else if strings.Contains(hp, " / ") || strings.Contains(hp, "/etc ") {
			score += 80 // Root or /etc access
		} else {
			score += 30 // Other sensitive paths
		}
	}

	// Writable host paths
	score += finding.WritableHostPaths * 25

	// Dangerous capabilities
	for _, cap := range finding.DangerousCaps {
		switch cap {
		case "SYS_ADMIN", "SYS_MODULE":
			score += 80
		case "SYS_PTRACE", "SYS_RAWIO":
			score += 60
		case "NET_ADMIN", "DAC_READ_SEARCH", "DAC_OVERRIDE":
			score += 40
		default:
			score += 20
		}
	}

	// Security context weaknesses
	if finding.RunAsRoot {
		score += 15
	}
	if finding.AllowPrivEsc {
		score += 20
	}
	if !finding.ReadOnlyRootFilesystem {
		score += 10
	}
	if finding.SeccompUnconfined {
		score += 25
	}
	if finding.AppArmorUndefined {
		score += 15
	}
	if finding.ProcMountUnmasked {
		score += 30
	}

	// Secret exposure
	score += finding.TotalSecretsExposed * 10

	// Resource abuse potential
	if finding.NoLimits {
		score += 20
	}

	// Image security
	if finding.LatestTag {
		score += 10
	}
	if finding.UnverifiedImage {
		score += 5
	}

	// Cloud role access
	if finding.CloudRole != "" {
		score += 30
	}

	// PSS violations
	score += finding.BaselineViolations * 5
	score += finding.RestrictedViolations * 2

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

// generateTableRow creates table row for pod finding
func generateTableRow(finding *PodFinding) []string {
	return []string{
		finding.RiskLevel,
		fmt.Sprintf("%d", finding.RiskScore),
		finding.Namespace,
		finding.Name,
		k8sinternal.NonEmpty(finding.PodIP),
		finding.Phase,
		k8sinternal.NonEmpty(finding.ServiceAccount),
		k8sinternal.NonEmpty(finding.Node),
		finding.ControllerType,
		k8sinternal.NonEmpty(finding.ControllerName),
		fmt.Sprintf("%v", finding.HostPID),
		fmt.Sprintf("%v", finding.HostIPC),
		fmt.Sprintf("%v", finding.HostNetwork),
		fmt.Sprintf("%v", finding.Privileged),
		fmt.Sprintf("%v", finding.RunAsRoot),
		fmt.Sprintf("%v", finding.AllowPrivEsc),
		fmt.Sprintf("%v", finding.ReadOnlyRootFilesystem),
		finding.SELinuxContext,
		finding.AppArmorProfile,
		finding.SeccompProfile,
		stringListOrNone(finding.Capabilities),
		stringListOrNone(finding.DangerousCaps),
		stringListOrNone(finding.HostPaths),
		stringListOrNone(finding.SensitiveHostPaths),
		stringListOrNone(finding.SecretVolumes),
		stringListOrNone(finding.SecretEnvVars),
		stringListOrNone(finding.ConfigMapVolumes),
		stringListOrNone(finding.ImageTagTypes),
		stringListOrNone(finding.ImagePullPolicy),
		stringListOrNone(finding.ResourceLimits),
		stringListOrNone(finding.ResourceRequests),
		k8sinternal.NonEmpty(finding.QoSClass),
		finding.PSSCompliance,
		fmt.Sprintf("%d violations", len(finding.PSSViolations)),
		stringListOrNone(finding.SecurityIssues),
	}
}

// stringListOrNone returns comma-separated list or <NONE>
func stringListOrNone(list []string) string {
	if len(list) == 0 {
		return "<NONE>"
	}
	return strings.Join(list, ", ")
}

// generateLootContent generates loot file content for a pod
func podGenerateLootContent(finding *PodFinding, pod *corev1.Pod,
	lootExec, lootEnum, lootPrivEsc, lootContainerEscape,
	lootHostCompromise, lootPSSViolations, lootSecretExposure,
	lootImageVulns, lootResourceAbuse, lootWeakIsolation,
	lootTokenExploit, lootLateralMovement, lootOrphaned,
	lootAttackChains, lootRemediation *[]string) {

	podID := fmt.Sprintf("%s/%s", finding.Namespace, finding.Name)

	// Execution commands
	*lootExec = append(*lootExec, fmt.Sprintf("\n# %s (Risk: %s)", podID, finding.RiskLevel))
	*lootExec = append(*lootExec, fmt.Sprintf("kubectl exec -it -n %s %s -- sh\n", finding.Namespace, finding.Name))

	// Enumeration commands
	*lootEnum = append(*lootEnum, fmt.Sprintf("\n# %s", podID))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl describe pod -n %s %s", finding.Namespace, finding.Name))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get pod -n %s %s -o yaml\n", finding.Namespace, finding.Name))

	// Privilege escalation techniques
	if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
		*lootPrivEsc = append(*lootPrivEsc, fmt.Sprintf("\n### [%s] %s (Score: %d)", finding.RiskLevel, podID, finding.RiskScore))
		*lootPrivEsc = append(*lootPrivEsc, fmt.Sprintf("# Security Issues: %s", strings.Join(finding.SecurityIssues, ", ")))
		*lootPrivEsc = append(*lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s %s -- sh\n", finding.Namespace, finding.Name))
	}

	// Container escape techniques
	if finding.Privileged && (finding.HostPID || finding.HostNetwork || finding.HostIPC) {
		*lootContainerEscape = append(*lootContainerEscape, fmt.Sprintf("\n### [CRITICAL] Privileged + Host Namespaces: %s", podID))
		*lootContainerEscape = append(*lootContainerEscape, "# This pod has CRITICAL container escape vectors")
		*lootContainerEscape = append(*lootContainerEscape, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", finding.Namespace, finding.Name))
		*lootContainerEscape = append(*lootContainerEscape, "")
		*lootContainerEscape = append(*lootContainerEscape, "# Method 1: nsenter to host PID namespace")
		*lootContainerEscape = append(*lootContainerEscape, "nsenter --target 1 --mount --uts --ipc --net --pid -- bash")
		*lootContainerEscape = append(*lootContainerEscape, "")
		*lootContainerEscape = append(*lootContainerEscape, "# Method 2: Access host filesystem via /proc")
		*lootContainerEscape = append(*lootContainerEscape, "ls -la /proc/1/root/")
		*lootContainerEscape = append(*lootContainerEscape, "cat /proc/1/root/etc/shadow")
		*lootContainerEscape = append(*lootContainerEscape, "")
	} else if finding.Privileged {
		*lootContainerEscape = append(*lootContainerEscape, fmt.Sprintf("\n### [HIGH] Privileged Container: %s", podID))
		*lootContainerEscape = append(*lootContainerEscape, "# Privileged containers can escape to host")
		*lootContainerEscape = append(*lootContainerEscape, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", finding.Namespace, finding.Name))
		*lootContainerEscape = append(*lootContainerEscape, "")
		*lootContainerEscape = append(*lootContainerEscape, "# Method 1: Mount host disk")
		*lootContainerEscape = append(*lootContainerEscape, "mkdir /host && mount /dev/sda1 /host && chroot /host")
		*lootContainerEscape = append(*lootContainerEscape, "")
	}

	// Dangerous capabilities
	if len(finding.DangerousCaps) > 0 {
		*lootContainerEscape = append(*lootContainerEscape, fmt.Sprintf("\n### [HIGH] Dangerous Capabilities: %s", podID))
		*lootContainerEscape = append(*lootContainerEscape, fmt.Sprintf("# Capabilities: %s", strings.Join(finding.DangerousCaps, ", ")))
		*lootContainerEscape = append(*lootContainerEscape, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", finding.Namespace, finding.Name))
		*lootContainerEscape = append(*lootContainerEscape, "")

		for _, cap := range finding.DangerousCaps {
			switch cap {
			case "SYS_ADMIN":
				*lootContainerEscape = append(*lootContainerEscape, "# CAP_SYS_ADMIN exploitation:")
				*lootContainerEscape = append(*lootContainerEscape, "# Can mount filesystems, use unshare, pivot_root")
				*lootContainerEscape = append(*lootContainerEscape, "mkdir /tmp/cgroup && mount -t cgroup -o rdma cgroup /tmp/cgroup")
				*lootContainerEscape = append(*lootContainerEscape, "")
			case "SYS_PTRACE":
				*lootContainerEscape = append(*lootContainerEscape, "# CAP_SYS_PTRACE exploitation:")
				*lootContainerEscape = append(*lootContainerEscape, "# Can attach to processes and inject code")
				*lootContainerEscape = append(*lootContainerEscape, "gdb -p 1")
				*lootContainerEscape = append(*lootContainerEscape, "")
			case "SYS_MODULE":
				*lootContainerEscape = append(*lootContainerEscape, "# CAP_SYS_MODULE exploitation:")
				*lootContainerEscape = append(*lootContainerEscape, "# Can load kernel modules")
				*lootContainerEscape = append(*lootContainerEscape, "insmod /path/to/module.ko")
				*lootContainerEscape = append(*lootContainerEscape, "")
			}
		}
	}

	// Host compromise via sensitive paths
	if len(finding.SensitiveHostPaths) > 0 {
		*lootHostCompromise = append(*lootHostCompromise, fmt.Sprintf("\n### [%s] Sensitive Host Paths: %s", finding.RiskLevel, podID))
		for _, shp := range finding.SensitiveHostPaths {
			*lootHostCompromise = append(*lootHostCompromise, fmt.Sprintf("# %s", shp))
		}
		*lootHostCompromise = append(*lootHostCompromise, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", finding.Namespace, finding.Name))
		*lootHostCompromise = append(*lootHostCompromise, "")

		for _, hp := range finding.HostPaths {
			if strings.Contains(hp, "docker.sock") {
				*lootHostCompromise = append(*lootHostCompromise, "# Docker socket escape:")
				*lootHostCompromise = append(*lootHostCompromise, "docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter --target 1 --mount --uts --ipc --net --pid -- bash")
				*lootHostCompromise = append(*lootHostCompromise, "")
			} else if strings.Contains(hp, "containerd") {
				*lootHostCompromise = append(*lootHostCompromise, "# Containerd socket escape:")
				*lootHostCompromise = append(*lootHostCompromise, "ctr -a /run/containerd/containerd.sock namespace ls")
				*lootHostCompromise = append(*lootHostCompromise, "")
			}
		}
	}

	// PSS violations
	if len(finding.PSSViolations) > 0 {
		*lootPSSViolations = append(*lootPSSViolations, fmt.Sprintf("\n### %s - %s (%d violations)", podID, finding.PSSCompliance, len(finding.PSSViolations)))
		for _, violation := range finding.PSSViolations {
			*lootPSSViolations = append(*lootPSSViolations, fmt.Sprintf("  - %s", violation))
		}
		*lootPSSViolations = append(*lootPSSViolations, "")
	}

	// Secret exposure
	if finding.TotalSecretsExposed > 0 {
		*lootSecretExposure = append(*lootSecretExposure, fmt.Sprintf("\n### %s (%d secrets exposed)", podID, finding.TotalSecretsExposed))
		if len(finding.SecretVolumes) > 0 {
			*lootSecretExposure = append(*lootSecretExposure, fmt.Sprintf("# Secret volumes: %s", strings.Join(finding.SecretVolumes, ", ")))
		}
		if len(finding.SecretEnvVars) > 0 {
			*lootSecretExposure = append(*lootSecretExposure, fmt.Sprintf("# Secret env vars: %s", strings.Join(finding.SecretEnvVars, ", ")))
		}
		*lootSecretExposure = append(*lootSecretExposure, fmt.Sprintf("kubectl exec -n %s %s -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", finding.Namespace, finding.Name))
		*lootSecretExposure = append(*lootSecretExposure, "")
	}

	// Image vulnerabilities
	if finding.LatestTag || finding.UnverifiedImage {
		*lootImageVulns = append(*lootImageVulns, fmt.Sprintf("\n### %s", podID))
		if finding.LatestTag {
			*lootImageVulns = append(*lootImageVulns, "  - Uses :latest tag (unpinned version)")
		}
		if finding.UnverifiedImage {
			*lootImageVulns = append(*lootImageVulns, "  - Image not verified with digest (@sha256)")
		}
		*lootImageVulns = append(*lootImageVulns, fmt.Sprintf("  - Images: %s", strings.Join(finding.Images, ", ")))
		*lootImageVulns = append(*lootImageVulns, "")
	}

	// Resource abuse
	if finding.NoLimits {
		*lootResourceAbuse = append(*lootResourceAbuse, fmt.Sprintf("\n### %s - No resource limits (DoS risk)", podID))
		*lootResourceAbuse = append(*lootResourceAbuse, "  - Pod can consume unlimited CPU/memory")
		*lootResourceAbuse = append(*lootResourceAbuse, "  - Can cause node exhaustion and cluster-wide DoS")
		*lootResourceAbuse = append(*lootResourceAbuse, "")
	}

	// Weak isolation
	if finding.SeccompUnconfined || finding.AppArmorUndefined {
		*lootWeakIsolation = append(*lootWeakIsolation, fmt.Sprintf("\n### %s", podID))
		if finding.SeccompUnconfined {
			*lootWeakIsolation = append(*lootWeakIsolation, "  - Seccomp: Unconfined (all syscalls allowed)")
		}
		if finding.AppArmorUndefined {
			*lootWeakIsolation = append(*lootWeakIsolation, "  - AppArmor: Undefined (no MAC enforcement)")
		}
		*lootWeakIsolation = append(*lootWeakIsolation, "")
	}

	// Service account token exploitation
	if finding.AutomountSAToken {
		*lootTokenExploit = append(*lootTokenExploit, fmt.Sprintf("\n### %s (SA: %s)", podID, finding.ServiceAccount))
		*lootTokenExploit = append(*lootTokenExploit, fmt.Sprintf("kubectl exec -n %s %s -- cat %s", finding.Namespace, finding.Name, finding.SATokenPath))
		*lootTokenExploit = append(*lootTokenExploit, "# Test permissions:")
		*lootTokenExploit = append(*lootTokenExploit, fmt.Sprintf("kubectl exec -n %s %s -- sh -c 'TOKEN=$(cat %s); kubectl --token=$TOKEN auth can-i --list'", finding.Namespace, finding.Name, finding.SATokenPath))
		*lootTokenExploit = append(*lootTokenExploit, "")
	}

	// Lateral movement
	if finding.HostNetwork {
		*lootLateralMovement = append(*lootLateralMovement, fmt.Sprintf("\n### %s - Host network access", podID))
		*lootLateralMovement = append(*lootLateralMovement, "# Can access host services on localhost:")
		*lootLateralMovement = append(*lootLateralMovement, fmt.Sprintf("kubectl exec -n %s %s -- curl http://localhost:10250/pods", finding.Namespace, finding.Name))
		*lootLateralMovement = append(*lootLateralMovement, "")
	}

	// Orphaned pods
	if finding.IsOrphaned {
		*lootOrphaned = append(*lootOrphaned, fmt.Sprintf("\n### %s", podID))
		*lootOrphaned = append(*lootOrphaned, "  - No controller (manually created)")
		*lootOrphaned = append(*lootOrphaned, "  - May indicate testing or attacker activity")
		*lootOrphaned = append(*lootOrphaned, "")
	}

	// Attack chains (CRITICAL and HIGH only)
	if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
		*lootAttackChains = append(*lootAttackChains, fmt.Sprintf("\n### [%s] %s - Attack Chain", finding.RiskLevel, podID))
		*lootAttackChains = append(*lootAttackChains, "# Step 1: Access pod")
		*lootAttackChains = append(*lootAttackChains, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", finding.Namespace, finding.Name))
		*lootAttackChains = append(*lootAttackChains, "")
		*lootAttackChains = append(*lootAttackChains, "# Step 2: Exploit security weakness")
		if finding.Privileged {
			*lootAttackChains = append(*lootAttackChains, "nsenter --target 1 --mount --uts --ipc --net --pid -- bash")
		} else if len(finding.SensitiveHostPaths) > 0 {
			*lootAttackChains = append(*lootAttackChains, "# Access sensitive host paths")
		}
		*lootAttackChains = append(*lootAttackChains, "")
		*lootAttackChains = append(*lootAttackChains, "# Step 3: Establish persistence")
		*lootAttackChains = append(*lootAttackChains, "# Step 4: Lateral movement")
		*lootAttackChains = append(*lootAttackChains, "")
	}

	// Remediation advice
	if len(finding.SecurityIssues) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n### %s (%d issues)", podID, len(finding.SecurityIssues)))

		for _, issue := range finding.SecurityIssues {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n## Issue: %s", issue))

			switch {
			case strings.Contains(issue, "PRIVILEGED"):
				*lootRemediation = append(*lootRemediation, "Remediation: Remove privileged: true from securityContext")
			case strings.Contains(issue, "HOST_PID"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set hostPID: false in pod spec")
			case strings.Contains(issue, "HOST_NETWORK"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set hostNetwork: false in pod spec")
			case strings.Contains(issue, "RUN_AS_ROOT"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set runAsNonRoot: true and runAsUser: <non-zero> in securityContext")
			case strings.Contains(issue, "ALLOW_PRIV_ESC"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set allowPrivilegeEscalation: false in securityContext")
			case strings.Contains(issue, "WRITABLE_ROOT_FS"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set readOnlyRootFilesystem: true in securityContext")
			case strings.Contains(issue, "SECCOMP_UNCONFINED"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set seccompProfile.type: RuntimeDefault in securityContext")
			case strings.Contains(issue, "NO_RESOURCE_LIMITS"):
				*lootRemediation = append(*lootRemediation, "Remediation: Add resources.limits for cpu and memory")
			case strings.Contains(issue, "DANGEROUS_CAPS"):
				*lootRemediation = append(*lootRemediation, "Remediation: Drop dangerous capabilities and add only required ones")
			case strings.Contains(issue, "SENSITIVE_HOSTPATHS"):
				*lootRemediation = append(*lootRemediation, "Remediation: Remove hostPath volumes or use read-only mounts")
			}
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}
