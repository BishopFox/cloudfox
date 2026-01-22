package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
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

// PodContainer stores container-level details
type PodContainer struct {
	Name           string
	Image          string
	Tag            string
	Registry       string
	Command        string
	Args           string
	Privileged     bool
	Capabilities   []string
	RunAsUser      string
	AllowPrivEsc   string
	ReadOnlyRootFS string
	ResourceLimits string
}

// PodVolume stores volume details
type PodVolume struct {
	Name       string
	VolumeType string
	Source     string
	MountPath  string
	ReadOnly   bool
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

	// Containers and Volumes (for multi-table output)
	ContainerDetails []PodContainer
	VolumeDetails    []PodVolume

	// Suspicious pattern detection
	BackdoorPatterns []string
	ReverseShells    []string
	CryptoMiners     []string
	DataExfiltration []string
	ContainerEscape  []string

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
	Labels           map[string]string
	Affinity         string
	Tolerations      []string
	Annotations      map[string]string
	ImagePullSecrets []string

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
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating cluster pods for %s", globals.ClusterName), globals.K8S_PODS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_PODS_MODULE_NAME)

	// Table 1: Pods Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Labels", "Phase", "Node", "Pod IP",
		"Service Account", "Init Containers", "Image Pull Secrets",
		"Secrets", "ConfigMaps",
		"Controller", "Security Context", "Suspicious Patterns", "Cloud IAM",
		"Affinity", "Tolerations",
	}

	// Table 2: Pod-Containers Detail
	containerHeaders := []string{
		"Namespace", "Pod", "Container", "Privileged", "Capabilities",
		"RunAsUser", "AllowPrivEsc", "ReadOnlyRootFS", "Resource Limits",
		"Image", "Tag", "Registry",
	}

	// Table 3: Pod-Volumes Detail
	volumeHeaders := []string{
		"Namespace", "Pod", "Volume Name", "Type", "Source Path/Name", "Container Mount Path", "Read Only",
	}

	var summaryRows [][]string
	var containerRows [][]string
	var volumeRows [][]string
	var findings []PodFinding

	// Risk counters
	riskCounts := shared.NewRiskCounts()

	// Loot content will be generated after processing all pods
	// We'll use findings to generate consolidated loot

	for _, ns := range namespaces {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing pods in namespace %s: %v\n", ns, err)
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

			// Image Pull Secrets
			for _, ps := range pod.Spec.ImagePullSecrets {
				finding.ImagePullSecrets = append(finding.ImagePullSecrets, ps.Name)
			}

			// Affinity
			if pod.Spec.Affinity != nil {
				finding.Affinity = k8sinternal.PrettyPrintAffinity(pod.Spec.Affinity)
			}

			// Tolerations - full details
			for _, t := range pod.Spec.Tolerations {
				tolStr := ""
				if t.Key != "" {
					tolStr = t.Key
					if t.Value != "" {
						tolStr += "=" + t.Value
					}
				} else {
					tolStr = "*"
				}
				if t.Effect != "" {
					tolStr += ":" + string(t.Effect)
				}
				tolStr += fmt.Sprintf(" (%s)", t.Operator)
				if t.TolerationSeconds != nil {
					tolStr += fmt.Sprintf(" [%ds]", *t.TolerationSeconds)
				}
				finding.Tolerations = append(finding.Tolerations, tolStr)
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

			// Image analysis and container detail extraction
			imageAnalyses := analyzeImages(allContainers)
			var allCommands []string
			var allArgs []string
			for i, img := range imageAnalyses {
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

				// Build ContainerDetails for the container table
				if i < len(allContainers) {
					c := allContainers[i]
					containerPrivileged := false
					var containerCaps []string
					containerRunAsUser := "-"
					containerAllowPrivEsc := "true" // default is true if not specified
					containerReadOnlyRootFS := "false"
					containerResourceLimits := "-"

					if c.SecurityContext != nil {
						if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
							containerPrivileged = true
						}
						if c.SecurityContext.Capabilities != nil {
							for _, cap := range c.SecurityContext.Capabilities.Add {
								containerCaps = append(containerCaps, string(cap))
							}
						}
						if c.SecurityContext.RunAsUser != nil {
							containerRunAsUser = fmt.Sprintf("%d", *c.SecurityContext.RunAsUser)
						}
						if c.SecurityContext.AllowPrivilegeEscalation != nil {
							containerAllowPrivEsc = fmt.Sprintf("%v", *c.SecurityContext.AllowPrivilegeEscalation)
						}
						if c.SecurityContext.ReadOnlyRootFilesystem != nil {
							containerReadOnlyRootFS = fmt.Sprintf("%v", *c.SecurityContext.ReadOnlyRootFilesystem)
						}
					}

					// Build actual resource limits string (CPU/Memory)
					if c.Resources.Limits != nil && len(c.Resources.Limits) > 0 {
						var limitParts []string
						if cpu, ok := c.Resources.Limits["cpu"]; ok {
							limitParts = append(limitParts, fmt.Sprintf("cpu:%s", cpu.String()))
						}
						if mem, ok := c.Resources.Limits["memory"]; ok {
							limitParts = append(limitParts, fmt.Sprintf("mem:%s", mem.String()))
						}
						if len(limitParts) > 0 {
							containerResourceLimits = strings.Join(limitParts, ", ")
						}
					}

					finding.ContainerDetails = append(finding.ContainerDetails, PodContainer{
						Name:           c.Name,
						Image:          img.Image,
						Tag:            img.TagType,
						Registry:       img.Registry,
						Command:        strings.Join(c.Command, " "),
						Args:           strings.Join(c.Args, " "),
						Privileged:     containerPrivileged,
						Capabilities:   containerCaps,
						RunAsUser:      containerRunAsUser,
						AllowPrivEsc:   containerAllowPrivEsc,
						ReadOnlyRootFS: containerReadOnlyRootFS,
						ResourceLimits: containerResourceLimits,
					})
					allCommands = append(allCommands, c.Command...)
					allArgs = append(allArgs, c.Args...)
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

			// Volume detail extraction for volume table
			for _, v := range pod.Spec.Volumes {
				volume := PodVolume{
					Name: v.Name,
				}

				// Determine volume type and source
				if v.HostPath != nil {
					volume.VolumeType = "HostPath"
					volume.Source = v.HostPath.Path
				} else if v.Secret != nil {
					volume.VolumeType = "Secret"
					volume.Source = v.Secret.SecretName
				} else if v.ConfigMap != nil {
					volume.VolumeType = "ConfigMap"
					volume.Source = v.ConfigMap.Name
				} else if v.EmptyDir != nil {
					volume.VolumeType = "EmptyDir"
					volume.Source = "-"
				} else if v.PersistentVolumeClaim != nil {
					volume.VolumeType = "PVC"
					volume.Source = v.PersistentVolumeClaim.ClaimName
				} else if v.Projected != nil {
					volume.VolumeType = "Projected"
					volume.Source = "-"
				} else if v.DownwardAPI != nil {
					volume.VolumeType = "DownwardAPI"
					volume.Source = "-"
				} else {
					volume.VolumeType = "Other"
					volume.Source = "-"
				}

				// Find mount path and read-only status
				for _, container := range allContainers {
					for _, vm := range container.VolumeMounts {
						if vm.Name == v.Name {
							volume.MountPath = vm.MountPath
							volume.ReadOnly = vm.ReadOnly
							break
						}
					}
				}

				finding.VolumeDetails = append(finding.VolumeDetails, volume)
			}

			// Suspicious pattern detection using shared functions
			var hostPaths []string
			for _, hp := range finding.HostPaths {
				// Extract just the path part
				if idx := strings.Index(hp, ":"); idx != -1 {
					hostPaths = append(hostPaths, hp[:idx])
				} else {
					hostPaths = append(hostPaths, hp)
				}
			}
			finding.ReverseShells = shared.DetectReverseShells(allCommands, allArgs)
			finding.CryptoMiners = shared.DetectCryptoMiners(allCommands, allArgs, finding.Images)
			finding.DataExfiltration = shared.DetectDataExfiltration(allCommands, allArgs)
			finding.ContainerEscape = shared.DetectContainerEscape(allCommands, allArgs, hostPaths)

			// Combine all backdoor patterns
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ReverseShells...)
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.CryptoMiners...)
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.DataExfiltration...)
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ContainerEscape...)

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

			riskCounts.Add(finding.RiskLevel)
			findings = append(findings, finding)

			// Build Security Context column (pod-level only)
			var secContextParts []string
			if finding.HostPID {
				secContextParts = append(secContextParts, "HostPID")
			}
			if finding.HostIPC {
				secContextParts = append(secContextParts, "HostIPC")
			}
			if finding.HostNetwork {
				secContextParts = append(secContextParts, "HostNetwork")
			}
			for _, hp := range finding.SensitiveHostPaths {
				if strings.Contains(hp, " - ") {
					hpPath := strings.Split(hp, " - ")[0]
					secContextParts = append(secContextParts, fmt.Sprintf("HostPath:%s", hpPath))
				} else {
					secContextParts = append(secContextParts, fmt.Sprintf("HostPath:%s", hp))
				}
			}
			secContextStr := strings.Join(secContextParts, ", ")

			// Build Suspicious Patterns column
			suspiciousPatternsStr := strings.Join(finding.BackdoorPatterns, "; ")

			// Build Cloud IAM column
			var cloudIAMStr string
			if finding.CloudProvider != "" && finding.CloudRole != "" {
				cloudIAMStr = fmt.Sprintf("%s: %s", finding.CloudProvider, finding.CloudRole)
			}

			// Build controller string
			controllerStr := finding.ControllerType
			if finding.ControllerName != "" {
				controllerStr = fmt.Sprintf("%s/%s", finding.ControllerType, finding.ControllerName)
			}

			// Format labels for display
			var labelParts []string
			for k, v := range finding.Labels {
				labelParts = append(labelParts, fmt.Sprintf("%s=%s", k, v))
			}
			labelsStr := strings.Join(labelParts, ", ")

			// Format init containers count
			initContainersStr := ""
			if finding.InitContainers > 0 {
				initContainersStr = fmt.Sprintf("%d", finding.InitContainers)
			}

			// Format image pull secrets
			imagePullSecretsStr := strings.Join(finding.ImagePullSecrets, ", ")

			// Format secrets from volumes
			var secretNames []string
			for _, sv := range finding.SecretVolumes {
				// Extract secret name from format "volName (secret:secretName)"
				if idx := strings.Index(sv, "secret:"); idx != -1 {
					end := strings.Index(sv[idx:], ")")
					if end != -1 {
						secretNames = append(secretNames, sv[idx+7:idx+end])
					}
				}
			}
			secretsStr := strings.Join(secretNames, ", ")

			// Format configmaps from volumes
			var cmNames []string
			for _, cv := range finding.ConfigMapVolumes {
				// Extract configmap name from format "volName (cm:cmName)"
				if idx := strings.Index(cv, "cm:"); idx != -1 {
					end := strings.Index(cv[idx:], ")")
					if end != -1 {
						cmNames = append(cmNames, cv[idx+3:idx+end])
					}
				}
			}
			configMapsStr := strings.Join(cmNames, ", ")

			// Format tolerations
			tolerationsStr := strings.Join(finding.Tolerations, ", ")

			// Table 1: Summary row
			summaryRow := []string{
				finding.Namespace,
				finding.Name,
				k8sinternal.NonEmpty(labelsStr),
				finding.Phase,
				k8sinternal.NonEmpty(finding.Node),
				k8sinternal.NonEmpty(finding.PodIP),
				k8sinternal.NonEmpty(finding.ServiceAccount),
				k8sinternal.NonEmpty(initContainersStr),
				k8sinternal.NonEmpty(imagePullSecretsStr),
				k8sinternal.NonEmpty(secretsStr),
				k8sinternal.NonEmpty(configMapsStr),
				controllerStr,
				k8sinternal.NonEmpty(secContextStr),
				k8sinternal.NonEmpty(suspiciousPatternsStr),
				k8sinternal.NonEmpty(cloudIAMStr),
				k8sinternal.NonEmpty(finding.Affinity),
				k8sinternal.NonEmpty(tolerationsStr),
			}
			summaryRows = append(summaryRows, summaryRow)

			// Table 2: Container rows (one per container)
			for _, container := range finding.ContainerDetails {
				capsStr := strings.Join(container.Capabilities, ", ")
				containerRow := []string{
					finding.Namespace,
					finding.Name,
					container.Name,
					fmt.Sprintf("%v", container.Privileged),
					k8sinternal.NonEmpty(capsStr),
					container.RunAsUser,
					container.AllowPrivEsc,
					container.ReadOnlyRootFS,
					k8sinternal.NonEmpty(container.ResourceLimits),
					container.Image,
					container.Tag,
					container.Registry,
				}
				containerRows = append(containerRows, containerRow)
			}

			// Table 3: Volume rows (one per volume)
			for _, volume := range finding.VolumeDetails {
				volumeRow := []string{
					finding.Namespace,
					finding.Name,
					volume.Name,
					volume.VolumeType,
					volume.Source,
					volume.MountPath,
					fmt.Sprintf("%v", volume.ReadOnly),
				}
				volumeRows = append(volumeRows, volumeRow)
			}
		}
	}

	// Create all three tables
	summaryTable := internal.TableFile{Name: "Pods", Header: summaryHeaders, Body: summaryRows}
	containerTable := internal.TableFile{Name: "Pod-Containers", Header: containerHeaders, Body: containerRows}
	volumeTable := internal.TableFile{Name: "Pod-Volumes", Header: volumeHeaders, Body: volumeRows}

	// Generate consolidated loot files
	lootFiles := generatePodLoot(findings, riskCounts)

	err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Pods",
		globals.ClusterName,
		"results",
		PodsOutput{
			Table: []internal.TableFile{summaryTable, containerTable, volumeTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PODS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d pods found across %d namespaces", len(summaryRows), len(namespaces)), globals.K8S_PODS_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_PODS_MODULE_NAME)

		if riskCounts.Critical > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d CRITICAL risk pods detected!", riskCounts.Critical), globals.K8S_PODS_MODULE_NAME)
		}
		if riskCounts.High > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d HIGH risk pods detected!", riskCounts.High), globals.K8S_PODS_MODULE_NAME)
		}
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
		k8sinternal.NonEmpty(finding.CloudProvider),
		k8sinternal.NonEmpty(finding.CloudRole),
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

// generatePodLoot generates consolidated loot files for pods
func generatePodLoot(findings []PodFinding, riskCounts *shared.RiskCounts) []internal.LootFile {
	var lootContent []string
	var entrypointsContent []string

	// Header for Pod-Loot.txt
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "##### Pod Loot - Actionable Commands")
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "#")
	lootContent = append(lootContent, fmt.Sprintf("# Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low))
	lootContent = append(lootContent, "#")
	lootContent = append(lootContent, "")

	// Header for Pod-Entrypoints.txt
	entrypointsContent = append(entrypointsContent, "#####################################")
	entrypointsContent = append(entrypointsContent, "##### Pod Container Entrypoints")
	entrypointsContent = append(entrypointsContent, "#####################################")
	entrypointsContent = append(entrypointsContent, "#")
	entrypointsContent = append(entrypointsContent, "# Container startup commands (entrypoint/cmd) and arguments")
	entrypointsContent = append(entrypointsContent, "# Only containers with non-empty commands/args are listed")
	entrypointsContent = append(entrypointsContent, "#")
	entrypointsContent = append(entrypointsContent, "")

	// Sort findings by risk score (highest first)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	// Section: ENUMERATION
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### ENUMERATION - Describe and inspect pods")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
		lootContent = append(lootContent, fmt.Sprintf("kubectl describe pod -n %s %s", f.Namespace, f.Name))
		lootContent = append(lootContent, fmt.Sprintf("kubectl get pod -n %s %s -o yaml", f.Namespace, f.Name))
		lootContent = append(lootContent, "")
	}

	// Section: HIGH RISK - Critical and high risk pods
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### HIGH RISK - Critical and high risk pods for exploitation")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s - Score: %d", f.RiskLevel, f.Namespace, f.Name, f.RiskScore))
			lootContent = append(lootContent, fmt.Sprintf("# Security Issues: %s", strings.Join(f.SecurityIssues, ", ")))
			if f.CloudProvider != "" && f.CloudRole != "" {
				lootContent = append(lootContent, fmt.Sprintf("# Cloud Role: %s (%s)", f.CloudRole, f.CloudProvider))
			}
			lootContent = append(lootContent, fmt.Sprintf("kubectl exec -it -n %s %s -- sh", f.Namespace, f.Name))
			lootContent = append(lootContent, "")
		}
	}

	// Section: EXPLOITATION - Container escape and privilege escalation
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### EXPLOITATION - Container escape and privilege escalation")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.Privileged || len(f.DangerousCaps) > 0 || len(f.SensitiveHostPaths) > 0 {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
			if f.Privileged && (f.HostPID || f.HostNetwork || f.HostIPC) {
				lootContent = append(lootContent, "# CRITICAL: Privileged + Host Namespaces - Guaranteed escape")
				lootContent = append(lootContent, fmt.Sprintf("kubectl exec -it -n %s %s -- nsenter --target 1 --mount --uts --ipc --net --pid -- bash", f.Namespace, f.Name))
			} else if f.Privileged {
				lootContent = append(lootContent, "# Privileged container escape via disk mount:")
				lootContent = append(lootContent, fmt.Sprintf("kubectl exec -it -n %s %s -- sh -c 'mkdir /host && mount /dev/sda1 /host && chroot /host'", f.Namespace, f.Name))
			}
			if len(f.DangerousCaps) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# Dangerous capabilities: %s", strings.Join(f.DangerousCaps, ", ")))
			}
			for _, hp := range f.HostPaths {
				if strings.Contains(hp, "docker.sock") {
					lootContent = append(lootContent, "# Docker socket escape:")
					lootContent = append(lootContent, fmt.Sprintf("kubectl exec -it -n %s %s -- docker -H unix:///var/run/docker.sock ps", f.Namespace, f.Name))
				}
			}
			lootContent = append(lootContent, "")
		}
	}

	// Section: SECRETS ACCESS - Extract secrets and tokens
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### SECRETS ACCESS - Extract secrets and service account tokens")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.TotalSecretsExposed > 0 || f.AutomountSAToken {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s (SA: %s)", f.RiskLevel, f.Namespace, f.Name, f.ServiceAccount))
			if f.TotalSecretsExposed > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# Secrets exposed: %d", f.TotalSecretsExposed))
			}
			lootContent = append(lootContent, fmt.Sprintf("kubectl exec -n %s %s -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", f.Namespace, f.Name))
			lootContent = append(lootContent, "")
		}
	}

	// Section: LATERAL MOVEMENT - Network-based attacks
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### LATERAL MOVEMENT - Network and cloud-based attacks")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.HostNetwork || (f.CloudProvider != "" && f.CloudRole != "") {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
			if f.HostNetwork {
				lootContent = append(lootContent, "# Host network - can access node services:")
				lootContent = append(lootContent, fmt.Sprintf("kubectl exec -n %s %s -- curl -s http://localhost:10250/pods", f.Namespace, f.Name))
			}
			if f.CloudProvider != "" && f.CloudRole != "" {
				lootContent = append(lootContent, fmt.Sprintf("# Cloud IAM: %s (%s)", f.CloudRole, f.CloudProvider))
			}
			lootContent = append(lootContent, "")
		}
	}

	// Build entrypoints content
	for _, f := range findings {
		var containerEntries []string
		for _, c := range f.ContainerDetails {
			if c.Command != "" || c.Args != "" {
				containerEntries = append(containerEntries, fmt.Sprintf("  Container: %s", c.Name))
				containerEntries = append(containerEntries, fmt.Sprintf("    Image: %s", c.Image))
				if c.Command != "" {
					containerEntries = append(containerEntries, fmt.Sprintf("    Command: %s", c.Command))
				}
				if c.Args != "" {
					containerEntries = append(containerEntries, fmt.Sprintf("    Args: %s", c.Args))
				}
			}
		}
		if len(containerEntries) > 0 {
			entrypointsContent = append(entrypointsContent, fmt.Sprintf("Pod: %s/%s", f.Namespace, f.Name))
			entrypointsContent = append(entrypointsContent, containerEntries...)
			entrypointsContent = append(entrypointsContent, "")
		}
	}

	return []internal.LootFile{
		{Name: "Pod-Loot", Contents: strings.Join(lootContent, "\n")},
		{Name: "Pod-Entrypoints", Contents: strings.Join(entrypointsContent, "\n")},
	}
}
