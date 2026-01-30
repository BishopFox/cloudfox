package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var ReplicaSetsCmd = &cobra.Command{
	Use:     "replicasets",
	Aliases: []string{"rs"},
	Short:   "List all cluster ReplicaSets with security analysis",
	Long: `
List all cluster ReplicaSets with comprehensive security analysis including:
- Pod template security analysis (SELinux, AppArmor, Seccomp)
- PSS compliance checking on templates
- Secret and ConfigMap exposure in templates
- Image security analysis and vulnerability indicators
- Resource abuse detection and DoS potential
- Deployment ownership and orphaned ReplicaSet detection
- Blast radius calculation (vulnerabilities × replica count)
- Risk-based scoring for prioritized security review
  cloudfox kubernetes replicasets`,
	Run: ListReplicaSets,
}

type ReplicaSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ReplicaSetsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ReplicaSetsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

// ReplicaSetContainer stores container-level details
type ReplicaSetContainer struct {
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

// ReplicaSetVolume stores volume details
type ReplicaSetVolume struct {
	Name       string
	VolumeType string
	Source     string
	MountPath  string
	ReadOnly   bool
}

type ReplicaSetFinding struct {
	// Basic Info
	Namespace      string
	Name           string
	DeploymentName string
	IsOrphaned     bool
	IsSuperseded   bool
	Age            string

	// Replica Analysis
	DesiredReplicas   int32
	CurrentReplicas   int32
	ReadyReplicas     int32
	AvailableReplicas int32
	ReplicaCount      int32
	HighReplicaCount  bool

	// Containers and Volumes (for multi-table output)
	ContainerDetails []ReplicaSetContainer
	VolumeDetails    []ReplicaSetVolume

	// Suspicious pattern detection
	BackdoorPatterns []string
	ReverseShells    []string
	CryptoMiners     []string
	DataExfiltration []string
	ContainerEscapeP []string

	// Security Analysis
	SecurityIssues []string
	RiskScore      int // Internal score for prioritization (0-100)

	// Pod Template Security Context
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
	ServiceAccount   string
	AutomountSAToken bool
	SATokenProjected bool

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

	// Init Containers
	InitContainers int

	// PSS Compliance
	PSSCompliance        string
	PSSViolations        []string
	RestrictedViolations int
	BaselineViolations   int

	// Metadata
	Labels           map[string]string
	Selectors        map[string]string
	Tolerations      []string
	Annotations      map[string]string
	ImagePullSecrets []string
	Affinity         string

	// Cloud
	CloudProvider string
	CloudRole     string

	// Impact Analysis
	ImpactSummary string
}

func ListReplicaSets(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating replicasets for %s", globals.ClusterName), globals.K8S_REPLICASETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_REPLICASETS_MODULE_NAME)
	targetNamespaces := make(map[string]struct{})
	for _, ns := range namespaces {
		targetNamespaces[ns] = struct{}{}
	}

	// Fetch all replicasets using cached call
	allReplicaSets, err := sdk.GetReplicaSets(ctx, clientset)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching replicasets: %v", err), globals.K8S_REPLICASETS_MODULE_NAME)
		return
	}

	// Table 1: ReplicaSets Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Labels", "Deployment", "Replicas",
		"Service Account", "Init Containers", "Image Pull Secrets",
		"Secrets", "ConfigMaps",
		"Security Context", "Suspicious Patterns", "Cloud IAM",
		"Affinity", "Tolerations",
	}

	// Table 2: ReplicaSet-Containers Detail
	containerHeaders := []string{
		"Namespace", "ReplicaSet", "Container", "Privileged", "Capabilities",
		"RunAsUser", "AllowPrivEsc", "ReadOnlyRootFS", "Resource Limits",
		"Image", "Tag", "Registry",
	}

	// Table 3: ReplicaSet-Volumes Detail
	volumeHeaders := []string{
		"Namespace", "ReplicaSet", "Volume Name", "Type", "Source Path/Name", "Container Mount Path", "Read Only",
	}

	var summaryRows [][]string
	var containerRows [][]string
	var volumeRows [][]string
	var findings []ReplicaSetFinding

	// Loot content will be generated after processing all replicasets
	// We'll use findings to generate consolidated loot

	for _, rs := range allReplicaSets {
		// Filter by target namespaces
		if len(targetNamespaces) > 0 {
			if _, ok := targetNamespaces[rs.Namespace]; !ok {
				continue
			}
		}
			finding := ReplicaSetFinding{
				Namespace:         rs.Namespace,
				Name:              rs.Name,
				DesiredReplicas:   *rs.Spec.Replicas,
				CurrentReplicas:   rs.Status.Replicas,
				ReadyReplicas:     rs.Status.ReadyReplicas,
				AvailableReplicas: rs.Status.AvailableReplicas,
				ReplicaCount:      *rs.Spec.Replicas,
				Labels:            rs.Labels,
				Selectors:         rs.Spec.Selector.MatchLabels,
				Annotations:       rs.Annotations,
				InitContainers:    len(rs.Spec.Template.Spec.InitContainers),
			}

			// High replica count detection
			finding.HighReplicaCount = (finding.ReplicaCount > 10)

			// Deployment ownership detection
			finding.DeploymentName, finding.IsOrphaned = detectDeploymentOwnership(rs)

			// Detect superseded ReplicaSets (zero replicas, has deployment owner)
			finding.IsSuperseded = (!finding.IsOrphaned && finding.ReplicaCount == 0)

			// Tolerations with full details
			for _, t := range rs.Spec.Template.Spec.Tolerations {
				var tolParts []string
				if t.Key != "" {
					tolParts = append(tolParts, t.Key)
				}
				if t.Value != "" {
					tolParts = append(tolParts, fmt.Sprintf("=%s", t.Value))
				}
				if t.Effect != "" {
					tolParts = append(tolParts, fmt.Sprintf(":%s", t.Effect))
				}
				if t.Operator != "" {
					tolParts = append(tolParts, fmt.Sprintf(" (%s)", t.Operator))
				}
				if t.TolerationSeconds != nil {
					tolParts = append(tolParts, fmt.Sprintf(" [%ds]", *t.TolerationSeconds))
				}
				if len(tolParts) > 0 {
					finding.Tolerations = append(finding.Tolerations, strings.Join(tolParts, ""))
				}
			}

			// Extract Image Pull Secrets
			for _, ips := range rs.Spec.Template.Spec.ImagePullSecrets {
				finding.ImagePullSecrets = append(finding.ImagePullSecrets, ips.Name)
			}

			// Extract Affinity
			finding.Affinity = k8sinternal.PrettyPrintAffinity(rs.Spec.Template.Spec.Affinity)

			// Service Account
			finding.ServiceAccount = rs.Spec.Template.Spec.ServiceAccountName

			// Host namespace settings
			finding.HostPID = rs.Spec.Template.Spec.HostPID
			finding.HostIPC = rs.Spec.Template.Spec.HostIPC
			finding.HostNetwork = rs.Spec.Template.Spec.HostNetwork

			// Analyze all containers (init + regular)
			allContainers := []corev1.Container{}
			allContainers = append(allContainers, rs.Spec.Template.Spec.InitContainers...)
			allContainers = append(allContainers, rs.Spec.Template.Spec.Containers...)

			// Security context analysis
			secCtx := analyzeTemplateSecurityContext(&rs.Spec.Template.Spec, allContainers)
			finding.Privileged = secCtx.Privileged != nil && *secCtx.Privileged
			finding.AllowPrivEsc = secCtx.AllowPrivilegeEscalation == nil || *secCtx.AllowPrivilegeEscalation
			finding.ReadOnlyRootFilesystem = secCtx.ReadOnlyRootFilesystem
			finding.ProcMountUnmasked = (secCtx.ProcMount == "Unmasked")
			finding.RunAsRoot = isTemplateRunAsRoot(secCtx)

			// SELinux analysis
			if secCtx.SELinuxOptions != nil {
				finding.SELinuxContext = formatTemplateSELinuxContext(secCtx.SELinuxOptions)
				finding.SELinuxCustom = (secCtx.SELinuxOptions.Level != "" || secCtx.SELinuxOptions.Role != "" ||
					secCtx.SELinuxOptions.Type != "" || secCtx.SELinuxOptions.User != "")
			} else {
				finding.SELinuxContext = "<none>"
			}

			// AppArmor analysis
			finding.AppArmorProfile = getTemplateAppArmorProfile(rs.Spec.Template.Annotations)
			finding.AppArmorUndefined = (finding.AppArmorProfile == "" || finding.AppArmorProfile == "<none>")

			// Seccomp analysis
			if secCtx.SeccompProfile != nil {
				finding.SeccompProfile = formatTemplateSeccompProfile(secCtx.SeccompProfile)
				finding.SeccompUnconfined = (secCtx.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined)
			} else {
				finding.SeccompProfile = "<none>"
				finding.SeccompUnconfined = true
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
			imageAnalyses := analyzeTemplateImages(allContainers)
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
			resAnalysis := analyzeTemplateResources(allContainers)
			finding.NoLimits = !resAnalysis.HasLimits
			finding.NoRequests = !resAnalysis.HasRequests
			for k, v := range resAnalysis.Limits {
				finding.ResourceLimits = append(finding.ResourceLimits, fmt.Sprintf("%s=%s", k, v))
			}
			for k, v := range resAnalysis.Requests {
				finding.ResourceRequests = append(finding.ResourceRequests, fmt.Sprintf("%s=%s", k, v))
			}
			finding.QoSClass = determineQoSClass(resAnalysis)

			// Volume analysis
			analyzeTemplateVolumes(&rs.Spec.Template.Spec, &finding, allContainers)

			// Service Account token analysis
			finding.AutomountSAToken = true // Default
			if rs.Spec.Template.Spec.AutomountServiceAccountToken != nil {
				finding.AutomountSAToken = *rs.Spec.Template.Spec.AutomountServiceAccountToken
			}
			finding.SATokenProjected = hasTemplateProjectedSAToken(rs.Spec.Template.Spec.Volumes)

			// HostPath analysis
			analyzeTemplateHostPaths(&rs.Spec.Template.Spec, &finding)

			// Container detail extraction for container table
			var allCommands []string
			var allArgs []string
			for i, c := range allContainers {
				containerPrivileged := false
				var containerCaps []string
				containerRunAsUser := "N/A"
				containerAllowPrivEsc := "N/A"
				containerReadOnlyRootFS := "N/A"

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
						uid := *c.SecurityContext.RunAsUser
						if uid == 0 {
							containerRunAsUser = "root"
						} else {
							containerRunAsUser = fmt.Sprintf("%d", uid)
						}
					}
					if c.SecurityContext.AllowPrivilegeEscalation != nil {
						containerAllowPrivEsc = fmt.Sprintf("%v", *c.SecurityContext.AllowPrivilegeEscalation)
					}
					if c.SecurityContext.ReadOnlyRootFilesystem != nil {
						containerReadOnlyRootFS = fmt.Sprintf("%v", *c.SecurityContext.ReadOnlyRootFilesystem)
					}
				}

				// Extract resource limits
				var resourceParts []string
				if c.Resources.Limits != nil {
					if cpu := c.Resources.Limits.Cpu(); cpu != nil && !cpu.IsZero() {
						resourceParts = append(resourceParts, fmt.Sprintf("cpu:%s", cpu.String()))
					}
					if mem := c.Resources.Limits.Memory(); mem != nil && !mem.IsZero() {
						resourceParts = append(resourceParts, fmt.Sprintf("mem:%s", mem.String()))
					}
				}
				resourceLimits := strings.Join(resourceParts, ", ")

				// Parse image details
				image := c.Image
				tag := "latest"
				registry := "docker.io"
				if strings.Contains(image, ":") {
					parts := strings.SplitN(image, ":", 2)
					image = parts[0]
					tag = parts[1]
				}
				if strings.Contains(image, "/") {
					parts := strings.Split(image, "/")
					if strings.Contains(parts[0], ".") || parts[0] == "localhost" {
						registry = parts[0]
					}
				}

				// Use imageAnalyses for tag type if available
				if i < len(imageAnalyses) {
					tag = imageAnalyses[i].TagType
					registry = imageAnalyses[i].Registry
				}

				finding.ContainerDetails = append(finding.ContainerDetails, ReplicaSetContainer{
					Name:           c.Name,
					Image:          c.Image,
					Tag:            tag,
					Registry:       registry,
					Command:        strings.Join(c.Command, " "),
					Args:           strings.Join(c.Args, " "),
					Privileged:     containerPrivileged,
					Capabilities:   containerCaps,
					RunAsUser:      containerRunAsUser,
					AllowPrivEsc:   containerAllowPrivEsc,
					ReadOnlyRootFS: containerReadOnlyRootFS,
					ResourceLimits: resourceLimits,
				})
				allCommands = append(allCommands, c.Command...)
				allArgs = append(allArgs, c.Args...)
			}

			// Volume detail extraction for volume table
			for _, v := range rs.Spec.Template.Spec.Volumes {
				volume := ReplicaSetVolume{
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
			finding.ContainerEscapeP = shared.DetectContainerEscape(allCommands, allArgs, hostPaths)

			// Combine all backdoor patterns
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ReverseShells...)
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.CryptoMiners...)
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.DataExfiltration...)
			finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ContainerEscapeP...)

			// Cloud role detection
			roleResults := k8sinternal.DetectCloudRole(ctx, clientset, rs.Namespace, rs.Spec.Template.Spec.ServiceAccountName, &rs.Spec.Template.Spec, rs.Spec.Template.Annotations)
			if len(roleResults) > 0 {
				finding.CloudProvider = roleResults[0].Provider
				finding.CloudRole = roleResults[0].Role
			}

			// PSS Compliance Analysis
			finding.PSSViolations, finding.PSSCompliance = analyzeTemplatePSSCompliance(&rs.Spec.Template.Spec, &finding, secCtx)
			finding.RestrictedViolations = countTemplatePSSViolations(finding.PSSViolations, "restricted")
			finding.BaselineViolations = countTemplatePSSViolations(finding.PSSViolations, "baseline")

			// Security Issues Summary
			finding.SecurityIssues = generateTemplateSecurityIssues(&finding)

			// Impact summary
			finding.ImpactSummary = generateImpactSummary(&finding)

			// Calculate risk score for prioritization
			finding.RiskScore = calculateReplicaSetRiskScore(&finding)

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

			// Build replicas string
			replicasStr := fmt.Sprintf("%d/%d/%d", finding.DesiredReplicas, finding.CurrentReplicas, finding.ReadyReplicas)

			// Build Labels column
			labelsStr := strings.Join(k8sinternal.MapToStringList(finding.Labels), ", ")

			// Build Init Containers count
			initContainersStr := fmt.Sprintf("%d", finding.InitContainers)

			// Build Image Pull Secrets column
			imagePullSecretsStr := strings.Join(finding.ImagePullSecrets, ", ")

			// Build Secrets column from SecretVolumes
			var secretNames []string
			for _, sv := range finding.SecretVolumes {
				// Extract just the secret name from format "volname (secret:name)"
				if idx := strings.Index(sv, "(secret:"); idx != -1 {
					endIdx := strings.Index(sv[idx:], ")")
					if endIdx != -1 {
						secretNames = append(secretNames, sv[idx+8:idx+endIdx])
					}
				}
			}
			secretsStr := strings.Join(secretNames, ", ")

			// Build ConfigMaps column from ConfigMapVolumes
			var cmNames []string
			for _, cmv := range finding.ConfigMapVolumes {
				// Extract just the configmap name from format "volname (cm:name)"
				if idx := strings.Index(cmv, "(cm:"); idx != -1 {
					endIdx := strings.Index(cmv[idx:], ")")
					if endIdx != -1 {
						cmNames = append(cmNames, cmv[idx+4:idx+endIdx])
					}
				}
			}
			configMapsStr := strings.Join(cmNames, ", ")

			// Build Tolerations column
			tolerationsStr := strings.Join(finding.Tolerations, "; ")

			// Table 1: Summary row
			summaryRow := []string{
				finding.Namespace,
				finding.Name,
				k8sinternal.NonEmpty(labelsStr),
				k8sinternal.NonEmpty(finding.DeploymentName),
				replicasStr,
				k8sinternal.NonEmpty(finding.ServiceAccount),
				initContainersStr,
				k8sinternal.NonEmpty(imagePullSecretsStr),
				k8sinternal.NonEmpty(secretsStr),
				k8sinternal.NonEmpty(configMapsStr),
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
					k8sinternal.NonEmpty(container.RunAsUser),
					k8sinternal.NonEmpty(container.AllowPrivEsc),
					k8sinternal.NonEmpty(container.ReadOnlyRootFS),
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

	// Create all three tables
	summaryTable := internal.TableFile{Name: "ReplicaSets", Header: summaryHeaders, Body: summaryRows}
	containerTable := internal.TableFile{Name: "ReplicaSet-Containers", Header: containerHeaders, Body: containerRows}
	volumeTable := internal.TableFile{Name: "ReplicaSet-Volumes", Header: volumeHeaders, Body: volumeRows}

	// Generate consolidated loot files
	lootFiles := generateReplicaSetLoot(findings)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"ReplicaSets",
		globals.ClusterName,
		"results",
		ReplicaSetsOutput{
			Table: []internal.TableFile{summaryTable, containerTable, volumeTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_REPLICASETS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d replicasets found", len(summaryRows)), globals.K8S_REPLICASETS_MODULE_NAME)
	} else {
		logger.InfoM("No replicasets found, skipping output file creation", globals.K8S_REPLICASETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_REPLICASETS_MODULE_NAME), globals.K8S_REPLICASETS_MODULE_NAME)
}

// detectDeploymentOwnership detects if ReplicaSet is owned by a Deployment
func detectDeploymentOwnership(rs appsv1.ReplicaSet) (string, bool) {
	// Check OwnerReferences
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" {
			return owner.Name, false // Has owner, not orphaned
		}
	}

	// Check annotation (legacy method)
	if deployName, exists := rs.Annotations["deployment.kubernetes.io/desired-name"]; exists && deployName != "" {
		return deployName, false
	}

	return "", true // No owner found, orphaned
}

// Template analysis helper functions (similar to pods.go but for pod templates)

type TemplateSecurityContextAnalysis struct {
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

type TemplateImageAnalysis struct {
	Image        string
	TagType      string
	PullPolicy   string
	Digest       string
	Registry     string
	IsLatest     bool
	IsUnverified bool
}

type TemplateResourceAnalysis struct {
	HasLimits   bool
	HasRequests bool
	Limits      map[string]string
	Requests    map[string]string
}

func analyzeTemplateSecurityContext(podSpec *corev1.PodSpec, containers []corev1.Container) TemplateSecurityContextAnalysis {
	analysis := TemplateSecurityContextAnalysis{}

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

			if sc.SELinuxOptions != nil {
				analysis.SELinuxOptions = sc.SELinuxOptions
			}

			if sc.SeccompProfile != nil {
				analysis.SeccompProfile = sc.SeccompProfile
			}

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

func isTemplateRunAsRoot(secCtx TemplateSecurityContextAnalysis) bool {
	if secCtx.RunAsNonRoot != nil && *secCtx.RunAsNonRoot {
		return false
	}
	if secCtx.RunAsUser != nil && *secCtx.RunAsUser == 0 {
		return true
	}
	if secCtx.RunAsUser != nil && *secCtx.RunAsUser > 0 {
		return false
	}
	return true
}

func formatTemplateSELinuxContext(sel *corev1.SELinuxOptions) string {
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

func getTemplateAppArmorProfile(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") {
			return v
		}
	}
	return "<none>"
}

func formatTemplateSeccompProfile(profile *corev1.SeccompProfile) string {
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

func analyzeTemplateImages(containers []corev1.Container) []TemplateImageAnalysis {
	var analyses []TemplateImageAnalysis

	for _, container := range containers {
		analysis := TemplateImageAnalysis{
			Image:      container.Image,
			PullPolicy: string(container.ImagePullPolicy),
		}

		analysis.TagType = k8sinternal.ImageTagType(container.Image)
		analysis.IsLatest = strings.HasSuffix(container.Image, ":latest") || !strings.Contains(container.Image, ":")

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

func analyzeTemplateResources(containers []corev1.Container) TemplateResourceAnalysis {
	analysis := TemplateResourceAnalysis{
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

func determineQoSClass(res TemplateResourceAnalysis) string {
	if !res.HasLimits && !res.HasRequests {
		return "BestEffort"
	}
	if res.HasLimits && res.HasRequests {
		return "Guaranteed"
	}
	return "Burstable"
}

func analyzeTemplateVolumes(podSpec *corev1.PodSpec, finding *ReplicaSetFinding, containers []corev1.Container) {
	for _, volume := range podSpec.Volumes {
		if volume.Secret != nil {
			secretInfo := fmt.Sprintf("%s (secret:%s)", volume.Name, volume.Secret.SecretName)
			finding.SecretVolumes = append(finding.SecretVolumes, secretInfo)
			finding.TotalSecretsExposed++
		}

		if volume.ConfigMap != nil {
			cmInfo := fmt.Sprintf("%s (cm:%s)", volume.Name, volume.ConfigMap.Name)
			finding.ConfigMapVolumes = append(finding.ConfigMapVolumes, cmInfo)
		}

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
	}

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

func analyzeTemplateHostPaths(podSpec *corev1.PodSpec, finding *ReplicaSetFinding) {
	for _, volume := range podSpec.Volumes {
		if volume.HostPath != nil {
			mountPoint := k8sinternal.FindMountPath(volume.Name, podSpec.Containers)

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

func hasTemplateProjectedSAToken(volumes []corev1.Volume) bool {
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

func analyzeTemplatePSSCompliance(podSpec *corev1.PodSpec, finding *ReplicaSetFinding, secCtx TemplateSecurityContextAnalysis) ([]string, string) {
	var violations []string

	// PSS Baseline violations
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
	if finding.AppArmorUndefined {
		violations = append(violations, "baseline: AppArmor profile undefined")
	}
	if finding.SELinuxCustom {
		violations = append(violations, "baseline: custom SELinux options not allowed")
	}
	if finding.ProcMountUnmasked {
		violations = append(violations, "baseline: unmasked /proc mount not allowed")
	}

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

	// PSS Restricted violations
	if !finding.DroppedAllCaps {
		violations = append(violations, "restricted: must drop ALL capabilities")
	}

	if len(finding.Capabilities) > 0 {
		for _, cap := range finding.Capabilities {
			if !strings.HasPrefix(cap, "-") && cap != "NET_BIND_SERVICE" {
				violations = append(violations, fmt.Sprintf("restricted: capability %s not in allowed list", cap))
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

	compliance := "Privileged"
	if len(violations) == 0 {
		compliance = "Restricted"
	} else {
		hasBaselineViolation := false
		for _, v := range violations {
			if strings.HasPrefix(v, "baseline:") {
				hasBaselineViolation = true
				break
			}
		}
		if !hasBaselineViolation {
			compliance = "Baseline"
		}
	}

	return violations, compliance
}

func countTemplatePSSViolations(violations []string, level string) int {
	count := 0
	prefix := level + ":"
	for _, v := range violations {
		if strings.HasPrefix(v, prefix) {
			count++
		}
	}
	return count
}

func generateTemplateSecurityIssues(finding *ReplicaSetFinding) []string {
	var issues []string

	if finding.Privileged {
		issues = append(issues, "PRIVILEGED template")
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
		issues = append(issues, "ORPHANED_RS")
	}
	if finding.HighReplicaCount && finding.NoLimits {
		issues = append(issues, "HIGH_REPLICA_NO_LIMITS")
	}

	return issues
}


func generateImpactSummary(finding *ReplicaSetFinding) string {
	if finding.ReplicaCount == 0 {
		return "Inactive (0 replicas)"
	}

	if finding.IsOrphaned {
		return fmt.Sprintf("Orphaned RS with %d replicas", finding.ReplicaCount)
	}

	if finding.HighReplicaCount {
		return fmt.Sprintf("High replica count (%d)", finding.ReplicaCount)
	}

	return fmt.Sprintf("%d replicas", finding.ReplicaCount)
}


func stringListOrNoneRS(list []string) string {
	if len(list) == 0 {
		return "<NONE>"
	}
	return strings.Join(list, ", ")
}

// calculateReplicaSetRiskScore returns an internal score (0-100) for prioritization
func calculateReplicaSetRiskScore(finding *ReplicaSetFinding) int {
	score := 0

	// Critical patterns (50+ points)
	if len(finding.ReverseShells) > 0 {
		score += 50
	}
	if len(finding.CryptoMiners) > 0 {
		score += 45
	}
	if len(finding.DataExfiltration) > 0 {
		score += 45
	}
	if len(finding.ContainerEscapeP) > 0 {
		score += 50
	}

	// Privileged access (30-40 points)
	if finding.Privileged {
		score += 40
	}
	if finding.HostPID {
		score += 35
	}
	if finding.HostIPC {
		score += 30
	}
	if finding.HostNetwork {
		score += 30
	}

	// Sensitive access (20-30 points)
	if len(finding.SensitiveHostPaths) > 0 {
		score += 25
	}
	if finding.WritableHostPaths > 0 {
		score += 20
	}

	// Dangerous capabilities (15-25 points each)
	for _, cap := range finding.DangerousCaps {
		switch cap {
		case "SYS_ADMIN":
			score += 25
		case "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE":
			score += 20
		case "DAC_READ_SEARCH", "NET_ADMIN":
			score += 15
		}
	}

	// Medium risk factors (10-15 points)
	if finding.RunAsRoot {
		score += 15
	}
	if finding.AllowPrivEsc {
		score += 10
	}
	if finding.NoLimits {
		score += 10
	}
	if finding.LatestTag {
		score += 5
	}

	// High replica count amplifies risk
	if finding.HighReplicaCount {
		score += 10
	}

	// Orphaned ReplicaSet (potential persistence)
	if finding.IsOrphaned && finding.ReplicaCount > 0 {
		score += 15
	}

	// Cloud role adds value
	if finding.CloudRole != "" {
		score += 15
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// generateReplicaSetLoot generates consolidated loot files for replicasets
func generateReplicaSetLoot(findings []ReplicaSetFinding) []internal.LootFile {
	// Sort findings by RiskScore descending for prioritization
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	var lootContent []string
	var entrypointsContent []string
	var suspiciousContent []string

	// Header for ReplicaSet-Loot.txt
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "##### ReplicaSet Commands")
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "#")
	lootContent = append(lootContent, "")

	// Header for ReplicaSet-Entrypoints.txt
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "##### ReplicaSet Container Entrypoints")
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "#")
	entrypointsContent = append(entrypointsContent, "# Container startup commands (entrypoint/cmd) and arguments")
	entrypointsContent = append(entrypointsContent, "# Only containers with non-empty commands/args are listed")
	entrypointsContent = append(entrypointsContent, "#")
	entrypointsContent = append(entrypointsContent, "")

	// Header for Suspicious ReplicaSets
	suspiciousContent = append(suspiciousContent, "########################################")
	suspiciousContent = append(suspiciousContent, "##### Suspicious ReplicaSets")
	suspiciousContent = append(suspiciousContent, "########################################")
	suspiciousContent = append(suspiciousContent, "#")
	suspiciousContent = append(suspiciousContent, "")

	// Section: ENUMERATION
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "=== ENUMERATION ===")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		lootContent = append(lootContent, fmt.Sprintf("# %s/%s (Replicas: %d)", f.Namespace, f.Name, f.ReplicaCount))
		lootContent = append(lootContent, fmt.Sprintf("kubectl describe replicaset -n %s %s", f.Namespace, f.Name))
		lootContent = append(lootContent, fmt.Sprintf("kubectl get replicaset -n %s %s -o yaml", f.Namespace, f.Name))
		lootContent = append(lootContent, "")
	}

	// Section: SUSPICIOUS REPLICASETS
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "=== SUSPICIOUS REPLICASETS ===")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.Privileged || f.HostPID || f.HostIPC || f.HostNetwork || len(f.BackdoorPatterns) > 0 || len(f.DangerousCaps) > 0 || len(f.SensitiveHostPaths) > 0 {
			issues := f.SecurityIssues
			lootEntry := shared.FormatSuspiciousEntry(f.Namespace, f.Name, issues)
			lootContent = append(lootContent, lootEntry...)
			lootContent = append(lootContent, fmt.Sprintf("# Replicas: %d pods with these vulnerabilities", f.ReplicaCount))
			if !f.IsOrphaned && f.DeploymentName != "" {
				lootContent = append(lootContent, fmt.Sprintf("kubectl edit deployment -n %s %s", f.Namespace, f.DeploymentName))
			} else {
				lootContent = append(lootContent, fmt.Sprintf("kubectl edit replicaset -n %s %s", f.Namespace, f.Name))
			}
			lootContent = append(lootContent, "")

			// Also add to suspicious content
			suspiciousContent = append(suspiciousContent, lootEntry...)
			suspiciousContent = append(suspiciousContent, "")
		}
	}

	// Section: EXPLOITATION - Pods from vulnerable templates
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "=== EXPLOITATION ===")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.Privileged || len(f.DangerousCaps) > 0 || len(f.SensitiveHostPaths) > 0 {
			lootContent = append(lootContent, fmt.Sprintf("# %s/%s - %d vulnerable pods", f.Namespace, f.Name, f.ReplicaCount))
			lootContent = append(lootContent, fmt.Sprintf("# Get pod names: kubectl get pods -n %s -l app=%s", f.Namespace, f.Name))
			if f.Privileged {
				lootContent = append(lootContent, "# Privileged template - all pods can escape to host")
			}
			if len(f.DangerousCaps) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# Dangerous capabilities: %s", strings.Join(f.DangerousCaps, ", ")))
			}
			lootContent = append(lootContent, "")
		}
	}

	// Section: SECRETS ACCESS
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "=== SECRETS ACCESS ===")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.TotalSecretsExposed > 0 {
			lootContent = append(lootContent, fmt.Sprintf("# %s/%s (%d secrets × %d replicas)", f.Namespace, f.Name, f.TotalSecretsExposed, f.ReplicaCount))
			if len(f.SecretVolumes) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# Secrets: %s", strings.Join(f.SecretVolumes, ", ")))
			}
			lootContent = append(lootContent, "")
		}
	}

	// Section: PERSISTENCE - Orphaned replicasets
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "=== PERSISTENCE ===")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.IsOrphaned {
			lootContent = append(lootContent, fmt.Sprintf("# %s/%s - Orphaned (%d replicas)", f.Namespace, f.Name, f.ReplicaCount))
			lootContent = append(lootContent, "# May indicate attacker persistence or forgotten test resource")
			lootContent = append(lootContent, fmt.Sprintf("kubectl delete replicaset -n %s %s", f.Namespace, f.Name))
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
			entrypointsContent = append(entrypointsContent, fmt.Sprintf("ReplicaSet: %s/%s (Replicas: %d)", f.Namespace, f.Name, f.ReplicaCount))
			entrypointsContent = append(entrypointsContent, containerEntries...)
			entrypointsContent = append(entrypointsContent, "")
		}
	}

	return []internal.LootFile{
		{Name: "ReplicaSet-Loot", Contents: strings.Join(lootContent, "\n")},
		{Name: "ReplicaSet-Entrypoints", Contents: strings.Join(entrypointsContent, "\n")},
		{Name: "ReplicaSet-Suspicious", Contents: strings.Join(suspiciousContent, "\n")},
	}
}
