package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var StatefulSetsCmd = &cobra.Command{
	Use:     "statefulsets",
	Aliases: []string{"ss", "sts"},
	Short:   "Enumerate StatefulSets with comprehensive security analysis",
	Long: `
Enumerate all StatefulSets with security analysis including:
  - Persistent volume security and storage class analysis
  - Privileged containers and host access (PID/IPC/Network)
  - Security context analysis (runAsRoot, capabilities, read-only filesystem)
  - Resource limits and quota enforcement
  - Update strategy and partition risks
  - Data persistence and backup detection
  - Headless service exposure
  - Pod disruption budget analysis
  - StatefulSet-specific risks (ordered updates, stable identities)
  - Volume type security (HostPath, EmptyDir, ConfigMap, Secret)

  cloudfox kubernetes statefulsets`,
	Run: ListStatefulSets,
}

type StatefulSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t StatefulSetsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t StatefulSetsOutput) LootFiles() []internal.LootFile   { return t.Loot }

// StatefulSetContainer stores container-level details
type StatefulSetContainer struct {
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

// StatefulSetVolume stores volume details
type StatefulSetVolume struct {
	Name       string
	VolumeType string
	Source     string
	MountPath  string
	ReadOnly   bool
}

type StatefulSetFinding struct {
	// Basic Info
	Namespace string
	Name      string
	Age       time.Duration
	AgeDays   int

	// Replica Info
	Replicas        int32
	ReadyReplicas   int32
	CurrentReplicas int32
	UpdatedReplicas int32
	Revision        string

	// StatefulSet-Specific
	ServiceName         string
	UpdateStrategy      string
	Partition           int32
	PodManagementPolicy string
	Ordinals            string // Start/End for ordinal indexing

	// PVC Analysis
	VolumeClaimTemplates []VolumeClaimInfo
	TotalPVCCount        int
	PVCStorageSize       string
	StorageClasses       []string
	DangerousAccessModes []string // ReadWriteMany can be risky

	// Containers and Volumes (for multi-table output)
	ContainerDetails []StatefulSetContainer
	VolumeDetails    []StatefulSetVolume

	// Suspicious pattern detection
	BackdoorPatterns []string
	ReverseShells    []string
	CryptoMiners     []string
	DataExfiltration []string
	ContainerEscapeP []string

	// Volume Security
	HostPathVolumes  []string
	EmptyDirVolumes  []string
	SecretVolumes    []string
	ConfigMapVolumes []string
	DangerousVolumes []string

	// Container Security
	PrivilegedContainers     int
	HostPID                  bool
	HostIPC                  bool
	HostNetwork              bool
	RunAsRoot                int // Count of containers running as root
	ReadOnlyRootFilesystem   int
	AllowPrivilegeEscalation int
	Capabilities             []string
	SecurityIssues           []string

	// Resource Analysis
	HasResourceLimits   bool
	HasResourceRequests bool
	LimitsCPU           string
	LimitsMemory        string
	RequestsCPU         string
	RequestsMemory      string

	// Service Account
	ServiceAccount string
	CloudProvider  string
	CloudRole      string

	// Risk Assessment
	RiskLevel     string
	RiskScore     int
	ImpactSummary string

	// Labels and Selectors
	Labels           map[string]string
	Selectors        map[string]string
	ImagePullSecrets []string
	Affinity         string
	Tolerations      []string
	InitContainers   int
}

type VolumeClaimInfo struct {
	Name         string
	StorageClass string
	AccessModes  []string
	Size         string
}

func ListStatefulSets(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating statefulsets for %s", globals.ClusterName), globals.K8S_STATEFULSETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_STATEFULSETS_MODULE_NAME)

	// Table 1: StatefulSets Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Labels", "Replicas", "Update Strategy",
		"Service Account", "Init Containers", "Image Pull Secrets",
		"Secrets", "ConfigMaps",
		"Security Context", "Suspicious Patterns", "Cloud IAM",
		"Affinity", "Tolerations",
	}

	// Table 2: StatefulSet-Containers Detail
	containerHeaders := []string{
		"Namespace", "StatefulSet", "Container", "Privileged", "Capabilities",
		"RunAsUser", "AllowPrivEsc", "ReadOnlyRootFS", "Resource Limits",
		"Image", "Tag", "Registry",
	}

	// Table 3: StatefulSet-Volumes Detail
	volumeHeaders := []string{
		"Namespace", "StatefulSet", "Volume Name", "Type", "Source Path/Name", "Container Mount Path", "Read Only",
	}

	var summaryRows [][]string
	var containerRows [][]string
	var volumeRows [][]string
	var findings []StatefulSetFinding

	// Risk counters
	riskCounts := shared.NewRiskCounts()

	// Loot content will be generated after processing all statefulsets
	// We'll use findings to generate consolidated loot

	for _, ns := range namespaces {
		statefulSets, err := clientset.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "statefulsets", ns, err, globals.K8S_STATEFULSETS_MODULE_NAME, false)
			continue
		}

		// Get all PVCs for correlation in this namespace
		allPVCs, err := clientset.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Warning: Could not list PVCs in namespace %s: %v", ns, err), globals.K8S_STATEFULSETS_MODULE_NAME)
			allPVCs = &corev1.PersistentVolumeClaimList{}
		}

		// Get all services for headless service detection in this namespace
		allServices, err := clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Warning: Could not list services in namespace %s: %v", ns, err), globals.K8S_STATEFULSETS_MODULE_NAME)
			allServices = &corev1.ServiceList{}
		}

		for _, ss := range statefulSets.Items {
		finding := analyzeStatefulSet(&ss, allPVCs.Items, allServices.Items, clientset, ctx)
		findings = append(findings, finding)
		riskCounts.Add(finding.RiskLevel)

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
		for _, hp := range finding.HostPathVolumes {
			secContextParts = append(secContextParts, fmt.Sprintf("HostPath:%s", hp))
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
		replicasStr := fmt.Sprintf("%d/%d", finding.ReadyReplicas, finding.Replicas)

		// Build Labels column
		labelsStr := strings.Join(k8sinternal.MapToStringList(finding.Labels), ", ")

		// Build Init Containers count
		initContainersStr := fmt.Sprintf("%d", finding.InitContainers)

		// Build Image Pull Secrets column
		imagePullSecretsStr := strings.Join(finding.ImagePullSecrets, ", ")

		// Build Secrets column
		secretsStr := strings.Join(finding.SecretVolumes, ", ")

		// Build ConfigMaps column
		configMapsStr := strings.Join(finding.ConfigMapVolumes, ", ")

		// Build Tolerations column
		tolerationsStr := strings.Join(finding.Tolerations, "; ")

		// Table 1: Summary row
		summaryRow := []string{
			finding.Namespace,
			finding.Name,
			k8sinternal.NonEmpty(labelsStr),
			replicasStr,
			finding.UpdateStrategy,
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
	}

	// Create all three tables
	summaryTable := internal.TableFile{Name: "StatefulSets", Header: summaryHeaders, Body: summaryRows}
	containerTable := internal.TableFile{Name: "StatefulSet-Containers", Header: containerHeaders, Body: containerRows}
	volumeTable := internal.TableFile{Name: "StatefulSet-Volumes", Header: volumeHeaders, Body: volumeRows}

	// Generate consolidated loot files
	lootFiles := generateStatefulSetConsolidatedLoot(findings, riskCounts)

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"StatefulSets",
		globals.ClusterName,
		"results",
		StatefulSetsOutput{
			Table: []internal.TableFile{summaryTable, containerTable, volumeTable},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_STATEFULSETS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d statefulsets found", len(summaryRows)), globals.K8S_STATEFULSETS_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_STATEFULSETS_MODULE_NAME)
		if riskCounts.Critical > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d CRITICAL risk statefulsets detected!", riskCounts.Critical), globals.K8S_STATEFULSETS_MODULE_NAME)
		}
		if riskCounts.High > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d HIGH risk statefulsets detected!", riskCounts.High), globals.K8S_STATEFULSETS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No statefulsets found, skipping output file creation", globals.K8S_STATEFULSETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_STATEFULSETS_MODULE_NAME), globals.K8S_STATEFULSETS_MODULE_NAME)
}

func analyzeStatefulSet(ss *appsv1.StatefulSet, allPVCs []corev1.PersistentVolumeClaim,
	allServices []corev1.Service, clientset *kubernetes.Clientset, ctx context.Context) StatefulSetFinding {

	finding := StatefulSetFinding{
		Namespace:   ss.Namespace,
		Name:        ss.Name,
		Labels:      ss.Labels,
		Selectors:   ss.Spec.Selector.MatchLabels,
		ServiceName: ss.Spec.ServiceName,
	}

	// Age calculation
	finding.Age = time.Since(ss.CreationTimestamp.Time)
	finding.AgeDays = int(finding.Age.Hours() / 24)

	// Replica info
	if ss.Spec.Replicas != nil {
		finding.Replicas = *ss.Spec.Replicas
	}
	finding.ReadyReplicas = ss.Status.ReadyReplicas
	finding.CurrentReplicas = ss.Status.CurrentReplicas
	finding.UpdatedReplicas = ss.Status.UpdatedReplicas
	finding.Revision = ss.Status.CurrentRevision

	// Update strategy
	finding.UpdateStrategy = string(ss.Spec.UpdateStrategy.Type)
	if ss.Spec.UpdateStrategy.RollingUpdate != nil && ss.Spec.UpdateStrategy.RollingUpdate.Partition != nil {
		finding.Partition = *ss.Spec.UpdateStrategy.RollingUpdate.Partition
	}

	// Pod management policy
	if ss.Spec.PodManagementPolicy != "" {
		finding.PodManagementPolicy = string(ss.Spec.PodManagementPolicy)
	} else {
		finding.PodManagementPolicy = "OrderedReady"
	}

	// Ordinals (if using ordinal indexing)
	if ss.Spec.Ordinals != nil {
		finding.Ordinals = fmt.Sprintf("start:%d", ss.Spec.Ordinals.Start)
	}

	// Init Containers count
	finding.InitContainers = len(ss.Spec.Template.Spec.InitContainers)

	// Extract Image Pull Secrets
	for _, ips := range ss.Spec.Template.Spec.ImagePullSecrets {
		finding.ImagePullSecrets = append(finding.ImagePullSecrets, ips.Name)
	}

	// Extract Affinity
	finding.Affinity = k8sinternal.PrettyPrintAffinity(ss.Spec.Template.Spec.Affinity)

	// Extract Tolerations with full details
	for _, t := range ss.Spec.Template.Spec.Tolerations {
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

	// Analyze VolumeClaimTemplates
	for _, vct := range ss.Spec.VolumeClaimTemplates {
		vci := VolumeClaimInfo{
			Name: vct.Name,
		}

		if vct.Spec.StorageClassName != nil {
			vci.StorageClass = *vct.Spec.StorageClassName
			if !Contains(finding.StorageClasses, vci.StorageClass) {
				finding.StorageClasses = append(finding.StorageClasses, vci.StorageClass)
			}
		}

		for _, mode := range vct.Spec.AccessModes {
			modeStr := string(mode)
			vci.AccessModes = append(vci.AccessModes, modeStr)

			// ReadWriteMany can be a security risk
			if mode == corev1.ReadWriteMany {
				finding.DangerousAccessModes = append(finding.DangerousAccessModes, vct.Name)
				finding.SecurityIssues = append(finding.SecurityIssues,
					fmt.Sprintf("PVC %s has ReadWriteMany access mode (pod escape risk)", vct.Name))
			}
		}

		if storage, ok := vct.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			vci.Size = storage.String()
		}

		finding.VolumeClaimTemplates = append(finding.VolumeClaimTemplates, vci)
	}

	finding.TotalPVCCount = len(finding.VolumeClaimTemplates) * int(finding.Replicas)
	if len(finding.VolumeClaimTemplates) > 0 {
		finding.PVCStorageSize = finding.VolumeClaimTemplates[0].Size
	}

	// Analyze volumes
	for _, vol := range ss.Spec.Template.Spec.Volumes {
		if vol.HostPath != nil {
			finding.HostPathVolumes = append(finding.HostPathVolumes, vol.Name)
			finding.DangerousVolumes = append(finding.DangerousVolumes, fmt.Sprintf("HostPath:%s->%s", vol.Name, vol.HostPath.Path))
			finding.SecurityIssues = append(finding.SecurityIssues,
				fmt.Sprintf("HostPath volume %s mounts %s (node escape risk)", vol.Name, vol.HostPath.Path))
		}
		if vol.EmptyDir != nil {
			finding.EmptyDirVolumes = append(finding.EmptyDirVolumes, vol.Name)
		}
		if vol.Secret != nil {
			finding.SecretVolumes = append(finding.SecretVolumes, vol.Name)
		}
		if vol.ConfigMap != nil {
			finding.ConfigMapVolumes = append(finding.ConfigMapVolumes, vol.Name)
		}
	}

	// Analyze containers (including init and ephemeral)
	allContainers := append([]corev1.Container{}, ss.Spec.Template.Spec.Containers...)
	for _, c := range ss.Spec.Template.Spec.InitContainers {
		allContainers = append(allContainers, c)
	}
	for _, c := range ss.Spec.Template.Spec.EphemeralContainers {
		allContainers = append(allContainers, corev1.Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: c.SecurityContext,
		})
	}

	for _, container := range allContainers {
		// Privileged
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			finding.PrivilegedContainers++
		}

		// RunAsRoot check
		if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil {
			if *container.SecurityContext.RunAsUser == 0 {
				finding.RunAsRoot++
			}
		} else {
			// If not specified, assume root (default)
			finding.RunAsRoot++
		}

		// ReadOnlyRootFilesystem
		if container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil && *container.SecurityContext.ReadOnlyRootFilesystem {
			finding.ReadOnlyRootFilesystem++
		}

		// AllowPrivilegeEscalation
		if container.SecurityContext != nil && container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			finding.AllowPrivilegeEscalation++
		}

		// Capabilities
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				capStr := string(cap)
				if !Contains(finding.Capabilities, capStr) {
					finding.Capabilities = append(finding.Capabilities, capStr)
				}
			}
		}

		// Resource limits
		if container.Resources.Limits != nil && len(container.Resources.Limits) > 0 {
			finding.HasResourceLimits = true
			if cpu, ok := container.Resources.Limits[corev1.ResourceCPU]; ok {
				finding.LimitsCPU = cpu.String()
			}
			if mem, ok := container.Resources.Limits[corev1.ResourceMemory]; ok {
				finding.LimitsMemory = mem.String()
			}
		}

		if container.Resources.Requests != nil && len(container.Resources.Requests) > 0 {
			finding.HasResourceRequests = true
			if cpu, ok := container.Resources.Requests[corev1.ResourceCPU]; ok {
				finding.RequestsCPU = cpu.String()
			}
			if mem, ok := container.Resources.Requests[corev1.ResourceMemory]; ok {
				finding.RequestsMemory = mem.String()
			}
		}
	}

	// Container detail extraction for container table
	var allCommands []string
	var allArgs []string
	var allImages []string
	for _, c := range allContainers {
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

		finding.ContainerDetails = append(finding.ContainerDetails, StatefulSetContainer{
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
		allImages = append(allImages, c.Image)
	}

	// Volume detail extraction for volume table
	for _, v := range ss.Spec.Template.Spec.Volumes {
		volume := StatefulSetVolume{
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
	for _, hp := range finding.HostPathVolumes {
		hostPaths = append(hostPaths, hp)
	}
	finding.ReverseShells = shared.DetectReverseShells(allCommands, allArgs)
	finding.CryptoMiners = shared.DetectCryptoMiners(allCommands, allArgs, allImages)
	finding.DataExfiltration = shared.DetectDataExfiltration(allCommands, allArgs)
	finding.ContainerEscapeP = shared.DetectContainerEscape(allCommands, allArgs, hostPaths)

	// Combine all backdoor patterns
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ReverseShells...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.CryptoMiners...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.DataExfiltration...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ContainerEscapeP...)

	// Host access
	finding.HostPID = ss.Spec.Template.Spec.HostPID
	finding.HostIPC = ss.Spec.Template.Spec.HostIPC
	finding.HostNetwork = ss.Spec.Template.Spec.HostNetwork

	// Service account
	finding.ServiceAccount = ss.Spec.Template.Spec.ServiceAccountName

	// Cloud role detection
	roleResults := k8sinternal.DetectCloudRole(
		ctx,
		clientset,
		ss.Namespace,
		ss.Spec.Template.Spec.ServiceAccountName,
		&ss.Spec.Template.Spec,
		ss.Spec.Template.Annotations,
	)

	if len(roleResults) > 0 {
		finding.CloudProvider = roleResults[0].Provider
		finding.CloudRole = roleResults[0].Role
	}

	// Add security issues
	if finding.PrivilegedContainers > 0 {
		finding.SecurityIssues = append(finding.SecurityIssues,
			fmt.Sprintf("%d privileged containers", finding.PrivilegedContainers))
	}

	if finding.HostPID {
		finding.SecurityIssues = append(finding.SecurityIssues, "HostPID enabled (can see all node processes)")
	}

	if finding.HostIPC {
		finding.SecurityIssues = append(finding.SecurityIssues, "HostIPC enabled (shared IPC namespace)")
	}

	if finding.HostNetwork {
		finding.SecurityIssues = append(finding.SecurityIssues, "HostNetwork enabled (bypasses network policies)")
	}

	if finding.RunAsRoot > 0 {
		finding.SecurityIssues = append(finding.SecurityIssues,
			fmt.Sprintf("%d containers running as root", finding.RunAsRoot))
	}

	if !finding.HasResourceLimits {
		finding.SecurityIssues = append(finding.SecurityIssues, "No resource limits (DoS risk)")
	}

	if finding.Partition > 0 {
		finding.SecurityIssues = append(finding.SecurityIssues,
			fmt.Sprintf("Partition set to %d (pods may be on old versions)", finding.Partition))
	}

	// Calculate risk
	finding.RiskLevel, finding.RiskScore = calculateStatefulSetRisk(&finding)
	finding.ImpactSummary = generateStatefulSetImpact(&finding)

	return finding
}

func calculateStatefulSetRisk(finding *StatefulSetFinding) (string, int) {
	score := 0

	// StatefulSets are inherently higher risk (critical data)
	score += 10

	// Privileged containers
	if finding.PrivilegedContainers > 0 {
		score += 40
	}

	// Host access
	if finding.HostPID {
		score += 25
	}
	if finding.HostIPC {
		score += 20
	}
	if finding.HostNetwork {
		score += 30
	}

	// Dangerous volumes
	if len(finding.HostPathVolumes) > 0 {
		score += 35 // HostPath = node escape
	}

	// RunAsRoot
	if finding.RunAsRoot > 0 {
		score += finding.RunAsRoot * 5
	}

	// Dangerous access modes
	if len(finding.DangerousAccessModes) > 0 {
		score += 20
	}

	// No resource limits
	if !finding.HasResourceLimits {
		score += 15
	}

	// Risky update strategy
	if finding.Partition > 0 {
		score += 10 // Partitioned updates can leave inconsistent state
	}

	// Capabilities
	for _, cap := range finding.Capabilities {
		if cap == "SYS_ADMIN" || cap == "NET_ADMIN" {
			score += 20
		}
	}

	// Determine risk level
	if score >= 80 {
		return "CRITICAL", statefulSetsMin(score, 100)
	} else if score >= 50 {
		return "HIGH", score
	} else if score >= 25 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func generateStatefulSetImpact(finding *StatefulSetFinding) string {
	if finding.RiskLevel == "CRITICAL" {
		return fmt.Sprintf("CRITICAL stateful workload with %d security issues", len(finding.SecurityIssues))
	}

	if finding.PrivilegedContainers > 0 && len(finding.HostPathVolumes) > 0 {
		return "Privileged containers with HostPath access = full node compromise"
	}

	if finding.TotalPVCCount > 0 {
		return fmt.Sprintf("Manages %d PVCs (%s each) - data persistence risk", finding.TotalPVCCount, finding.PVCStorageSize)
	}

	return fmt.Sprintf("%d replicas with %d security issues", finding.Replicas, len(finding.SecurityIssues))
}

// generateStatefulSetConsolidatedLoot generates consolidated loot files for statefulsets
func generateStatefulSetConsolidatedLoot(findings []StatefulSetFinding, riskCounts *shared.RiskCounts) []internal.LootFile {
	var lootContent []string
	var entrypointsContent []string

	// Header for StatefulSet-Loot.txt
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "##### StatefulSet Loot - Actionable Commands")
	lootContent = append(lootContent, "#####################################")
	lootContent = append(lootContent, "#")
	lootContent = append(lootContent, fmt.Sprintf("# Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
		riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low))
	lootContent = append(lootContent, "#")
	lootContent = append(lootContent, "")

	// Header for StatefulSet-Entrypoints.txt
	entrypointsContent = append(entrypointsContent, "#####################################")
	entrypointsContent = append(entrypointsContent, "##### StatefulSet Container Entrypoints")
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
	lootContent = append(lootContent, "### ENUMERATION - Describe and inspect statefulsets")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s (Replicas: %d/%d, PVCs: %d)", f.RiskLevel, f.Namespace, f.Name, f.ReadyReplicas, f.Replicas, f.TotalPVCCount))
		lootContent = append(lootContent, fmt.Sprintf("kubectl describe statefulset -n %s %s", f.Namespace, f.Name))
		lootContent = append(lootContent, fmt.Sprintf("kubectl get statefulset -n %s %s -o yaml", f.Namespace, f.Name))
		lootContent = append(lootContent, "")
	}

	// Section: HIGH RISK - Critical and high risk statefulsets
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### HIGH RISK - Critical and high risk statefulsets")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s - Score: %d", f.RiskLevel, f.Namespace, f.Name, f.RiskScore))
			lootContent = append(lootContent, fmt.Sprintf("# Security Issues: %s", strings.Join(f.SecurityIssues, ", ")))
			if f.CloudProvider != "" && f.CloudRole != "" {
				lootContent = append(lootContent, fmt.Sprintf("# Cloud Role: %s (%s)", f.CloudRole, f.CloudProvider))
			}
			lootContent = append(lootContent, fmt.Sprintf("kubectl edit statefulset -n %s %s", f.Namespace, f.Name))
			lootContent = append(lootContent, "")
		}
	}

	// Section: EXPLOITATION - Privileged statefulsets
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### EXPLOITATION - Privileged statefulsets and host access")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.PrivilegedContainers > 0 || len(f.HostPathVolumes) > 0 || f.HostPID || f.HostNetwork {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
			if f.PrivilegedContainers > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# %d privileged containers - can escape to host", f.PrivilegedContainers))
			}
			if f.HostPID {
				lootContent = append(lootContent, "# HostPID - can see all node processes")
			}
			if f.HostNetwork {
				lootContent = append(lootContent, "# HostNetwork - bypasses network policies")
			}
			if len(f.HostPathVolumes) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# HostPath volumes: %s", strings.Join(f.DangerousVolumes, ", ")))
			}
			lootContent = append(lootContent, fmt.Sprintf("# Get pods: kubectl get pods -n %s -l app=%s", f.Namespace, f.Name))
			lootContent = append(lootContent, "")
		}
	}

	// Section: PERSISTENCE - PVCs and data access
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### PERSISTENCE - PVCs and persistent data access")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if f.TotalPVCCount > 0 {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s - %d PVCs (%s each)", f.RiskLevel, f.Namespace, f.Name, f.TotalPVCCount, f.PVCStorageSize))
			if len(f.StorageClasses) > 0 {
				lootContent = append(lootContent, fmt.Sprintf("# Storage classes: %s", strings.Join(f.StorageClasses, ", ")))
			}
			lootContent = append(lootContent, fmt.Sprintf("kubectl get pvc -n %s -l app=%s", f.Namespace, f.Name))
			lootContent = append(lootContent, "")
		}
	}

	// Section: SECRETS ACCESS
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "### SECRETS ACCESS - Statefulsets exposing secrets")
	lootContent = append(lootContent, "")
	for _, f := range findings {
		if len(f.SecretVolumes) > 0 {
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s (%d secret volumes)", f.RiskLevel, f.Namespace, f.Name, len(f.SecretVolumes)))
			lootContent = append(lootContent, fmt.Sprintf("# Secrets: %s", strings.Join(f.SecretVolumes, ", ")))
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
			entrypointsContent = append(entrypointsContent, fmt.Sprintf("StatefulSet: %s/%s (Replicas: %d)", f.Namespace, f.Name, f.Replicas))
			entrypointsContent = append(entrypointsContent, containerEntries...)
			entrypointsContent = append(entrypointsContent, "")
		}
	}

	return []internal.LootFile{
		{Name: "StatefulSet-Loot", Contents: strings.Join(lootContent, "\n")},
		{Name: "StatefulSet-Entrypoints", Contents: strings.Join(entrypointsContent, "\n")},
	}
}

func statefulSetsMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
