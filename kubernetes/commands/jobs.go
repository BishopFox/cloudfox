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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var JobsCmd = &cobra.Command{
	Use:     "jobs",
	Aliases: []string{"job"},
	Short:   "Enumerate jobs with comprehensive security analysis",
	Long: `
Enumerate all jobs in the cluster with comprehensive security analysis including:
  - Risk-based scoring (CRITICAL/HIGH/MEDIUM/LOW)
  - Security context analysis (privileged, capabilities, runAsRoot)
  - Secret and credential exposure detection
  - Image security validation (tags, registries, pull policies)
  - Resource limits and DoS risk assessment
  - Job failure and retry pattern analysis
  - Command injection and malicious payload detection
  - CronJob correlation and scheduling analysis

  cloudfox kubernetes jobs`,
	Run: ListJobs,
}

type JobsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t JobsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t JobsOutput) LootFiles() []internal.LootFile   { return t.Loot }

// JobContainer stores container-level details
type JobContainer struct {
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

// JobVolume stores volume details
type JobVolume struct {
	Name       string
	VolumeType string
	Source     string
	MountPath  string
	ReadOnly   bool
}

// JobFinding contains comprehensive job security analysis
type JobFinding struct {
	// Basic info
	Namespace    string
	Name         string
	Completions  int32
	Parallelism  int32
	BackoffLimit int32

	// Status
	Status         string // "Completed", "Failed", "Running", "Backoff", "Pending"
	Active         int32
	Succeeded      int32
	Failed         int32
	FailureRate    float64
	StartTime      string
	CompletionTime string
	Duration       string

	// Security analysis
	RiskLevel      string // CRITICAL/HIGH/MEDIUM/LOW
	SecurityIssues []string

	// Suspicious pattern detection
	BackdoorPatterns []string
	ReverseShells    []string
	CryptoMiners     []string
	DataExfiltration []string
	ContainerEscape  []string

	// Containers and Volumes
	Containers     []JobContainer
	InitContainers []JobContainer
	Volumes        []JobVolume
	Images         []string
	ImageTagTypes  []string // "latest", "pinned", "sha256"

	// Container security (aggregated)
	Privileged        bool
	RunAsUser         string // "root", "1000", "N/A"
	RunAsNonRoot      bool
	Capabilities      []string
	DangerousCaps     []string
	AllowPrivEsc      bool
	ReadOnlyRootFS    bool
	HasResourceLimits bool
	ResourceLimits    string // "Set", "Partial", "None"

	// Volumes & secrets
	Secrets            []string
	ConfigMaps         []string
	HostPaths          []string
	SensitiveHostPaths []string
	WritableHostPaths  int

	// Host namespaces
	HostPID     bool
	HostIPC     bool
	HostNetwork bool

	// Job-specific
	RestartPolicy    string
	ActiveDeadline   int64
	TTL              int32
	FromCronJob      bool
	CronJobName      string
	ServiceAccount   string
	AutomountSAToken bool
	ImagePullSecrets []string
	Affinity         string
	Tolerations      []string

	// Cloud
	CloudProvider string
	CloudRole     string

	// Metadata
	Labels      []string
	Annotations []string
}

func ListJobs(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating jobs for %s", globals.ClusterName), globals.K8S_JOBS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get target namespaces
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_JOBS_MODULE_NAME)

	// Collect all jobs from target namespaces
	var allJobs []batchv1.Job
	for _, ns := range namespaces {
		jobs, err := clientset.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			shared.LogListError(&logger, "jobs", ns, err, globals.K8S_JOBS_MODULE_NAME, false)
			continue
		}
		allJobs = append(allJobs, jobs.Items...)
	}

	// Table 1: Jobs Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Labels", "Status", "Duration", "Completions",
		"Service Account", "Init Containers", "Image Pull Secrets",
		"Secrets", "ConfigMaps",
		"Security Context", "Suspicious Patterns", "Cloud IAM",
		"Affinity", "Tolerations",
	}

	// Table 2: Job-Containers Detail
	containerHeaders := []string{
		"Namespace", "Job", "Container", "Privileged", "Capabilities",
		"RunAsUser", "AllowPrivEsc", "ReadOnlyRootFS", "Resource Limits",
		"Image", "Tag", "Registry",
	}

	// Table 3: Job-Volumes Detail
	volumeHeaders := []string{
		"Namespace", "Job", "Volume Name", "Type", "Source Path/Name", "Container Mount Path", "Read Only",
	}

	var summaryRows [][]string
	var containerRows [][]string
	var volumeRows [][]string
	var findings []JobFinding

	// Risk counters
	riskCounts := shared.NewRiskCounts()

	for _, job := range allJobs {
		finding := analyzeJob(ctx, clientset, &job)
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
		for _, hp := range finding.HostPaths {
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

		// Build completions info
		completionsStr := fmt.Sprintf("%d/%d", finding.Succeeded, finding.Completions)

		// Build Labels column
		labelsStr := strings.Join(finding.Labels, ", ")

		// Build Init Containers count
		initContainersStr := fmt.Sprintf("%d", len(finding.InitContainers))

		// Build Image Pull Secrets column
		imagePullSecretsStr := strings.Join(finding.ImagePullSecrets, ", ")

		// Build Secrets and ConfigMaps columns
		secretsStr := strings.Join(finding.Secrets, ", ")
		configMapsStr := strings.Join(finding.ConfigMaps, ", ")

		// Build Tolerations column
		tolerationsStr := strings.Join(finding.Tolerations, "; ")

		// Table 1: Summary row
		summaryRow := []string{
			finding.Namespace,
			finding.Name,
			k8sinternal.NonEmpty(labelsStr),
			finding.Status,
			finding.Duration,
			completionsStr,
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
		for _, container := range finding.Containers {
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
		for _, volume := range finding.Volumes {
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

	// Generate loot files
	lootFiles := generateJobLoot(findings, globals.KubeContext, riskCounts)

	// Create all three tables
	summaryTable := internal.TableFile{Name: "Jobs", Header: summaryHeaders, Body: summaryRows}
	containerTable := internal.TableFile{Name: "Job-Containers", Header: containerHeaders, Body: containerRows}
	volumeTable := internal.TableFile{Name: "Job-Volumes", Header: volumeHeaders, Body: volumeRows}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Jobs",
		globals.ClusterName,
		"results",
		JobsOutput{
			Table: []internal.TableFile{summaryTable, containerTable, volumeTable},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_JOBS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d jobs found", len(summaryRows)), globals.K8S_JOBS_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_JOBS_MODULE_NAME)

		if riskCounts.Critical > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d CRITICAL risk jobs detected!", riskCounts.Critical), globals.K8S_JOBS_MODULE_NAME)
		}
		if riskCounts.High > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d HIGH risk jobs detected!", riskCounts.High), globals.K8S_JOBS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No jobs found, skipping output file creation", globals.K8S_JOBS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_JOBS_MODULE_NAME), globals.K8S_JOBS_MODULE_NAME)
}

// ====================
// Main Analysis Function
// ====================

func analyzeJob(ctx context.Context, clientset *kubernetes.Clientset, job *batchv1.Job) JobFinding {
	finding := JobFinding{
		Namespace:    job.Namespace,
		Name:         job.Name,
		Completions:  0,
		Parallelism:  0,
		BackoffLimit: 0,
		Active:       job.Status.Active,
		Succeeded:    job.Status.Succeeded,
		Failed:       job.Status.Failed,
	}

	if job.Spec.Completions != nil {
		finding.Completions = *job.Spec.Completions
	}
	if job.Spec.Parallelism != nil {
		finding.Parallelism = *job.Spec.Parallelism
	}
	if job.Spec.BackoffLimit != nil {
		finding.BackoffLimit = *job.Spec.BackoffLimit
	}

	podSpec := job.Spec.Template.Spec

	// Analyze status
	finding.Status, finding.Duration = analyzeJobStatus(job)
	finding.FailureRate = calculateFailureRate(job)

	// Time tracking
	if job.Status.StartTime != nil {
		finding.StartTime = job.Status.StartTime.Format(time.RFC3339)
	}
	if job.Status.CompletionTime != nil {
		finding.CompletionTime = job.Status.CompletionTime.Format(time.RFC3339)
	}

	// Host namespaces
	finding.HostPID = podSpec.HostPID
	finding.HostIPC = podSpec.HostIPC
	finding.HostNetwork = podSpec.HostNetwork

	// ServiceAccount
	finding.ServiceAccount = podSpec.ServiceAccountName
	if finding.ServiceAccount == "" {
		finding.ServiceAccount = "default"
	}
	if podSpec.AutomountServiceAccountToken != nil {
		finding.AutomountSAToken = *podSpec.AutomountServiceAccountToken
	} else {
		finding.AutomountSAToken = true // default is true
	}

	// Extract containers, commands, args, images
	var containers []JobContainer
	var initContainers []JobContainer
	var allCommands []string
	var allArgs []string
	var allImages []string
	var capabilities []string
	privileged := false
	runAsUser := "N/A"

	// Process main containers
	for _, c := range podSpec.Containers {
		container := parseJobContainer(c, &privileged, &runAsUser, &capabilities)
		containers = append(containers, container)
		allImages = append(allImages, c.Image)
		allCommands = append(allCommands, c.Command...)
		allArgs = append(allArgs, c.Args...)
	}

	// Process init containers
	for _, c := range podSpec.InitContainers {
		container := parseJobContainer(c, &privileged, &runAsUser, &capabilities)
		initContainers = append(initContainers, container)
		allImages = append(allImages, c.Image)
		allCommands = append(allCommands, c.Command...)
		allArgs = append(allArgs, c.Args...)
	}

	finding.Containers = containers
	finding.InitContainers = initContainers
	finding.Images = allImages
	finding.Privileged = privileged
	finding.RunAsUser = runAsUser
	finding.Capabilities = capabilities

	// Determine image tag types
	for _, img := range allImages {
		if strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":") {
			finding.ImageTagTypes = append(finding.ImageTagTypes, "latest")
		} else if strings.Contains(img, "@sha256:") {
			finding.ImageTagTypes = append(finding.ImageTagTypes, "sha256")
		} else {
			finding.ImageTagTypes = append(finding.ImageTagTypes, "pinned")
		}
	}

	// Extract volumes and hostPaths
	var volumes []JobVolume
	var hostPaths []string
	var secrets []string
	var configMaps []string
	for _, v := range podSpec.Volumes {
		volume := JobVolume{
			Name: v.Name,
		}

		// Determine volume type and source
		if v.HostPath != nil {
			volume.VolumeType = "HostPath"
			volume.Source = v.HostPath.Path
			hostPaths = append(hostPaths, v.HostPath.Path)
		} else if v.Secret != nil {
			volume.VolumeType = "Secret"
			volume.Source = v.Secret.SecretName
			secrets = append(secrets, v.Secret.SecretName)
		} else if v.ConfigMap != nil {
			volume.VolumeType = "ConfigMap"
			volume.Source = v.ConfigMap.Name
			configMaps = append(configMaps, v.ConfigMap.Name)
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
		for _, container := range podSpec.Containers {
			for _, vm := range container.VolumeMounts {
				if vm.Name == v.Name {
					volume.MountPath = vm.MountPath
					volume.ReadOnly = vm.ReadOnly
					break
				}
			}
		}

		volumes = append(volumes, volume)
	}
	finding.Volumes = volumes
	finding.HostPaths = hostPaths
	finding.Secrets = secrets
	finding.ConfigMaps = configMaps

	// Check for sensitive host paths
	for _, hp := range hostPaths {
		if isSensitiveHostPath(hp) {
			finding.SensitiveHostPaths = append(finding.SensitiveHostPaths, hp)
		}
		if isWritableMount(hp, podSpec.Volumes, podSpec.Containers) {
			finding.WritableHostPaths++
		}
	}

	// Resource limits
	finding.HasResourceLimits, finding.ResourceLimits = analyzeResourceLimits(&podSpec)

	// Job-specific
	finding.RestartPolicy = string(podSpec.RestartPolicy)
	if job.Spec.ActiveDeadlineSeconds != nil {
		finding.ActiveDeadline = *job.Spec.ActiveDeadlineSeconds
	}
	if job.Spec.TTLSecondsAfterFinished != nil {
		finding.TTL = *job.Spec.TTLSecondsAfterFinished
	}

	// CronJob detection
	finding.FromCronJob, finding.CronJobName = detectCronJob(job)

	// Extract Image Pull Secrets
	for _, ips := range podSpec.ImagePullSecrets {
		finding.ImagePullSecrets = append(finding.ImagePullSecrets, ips.Name)
	}

	// Extract Affinity
	finding.Affinity = k8sinternal.PrettyPrintAffinity(podSpec.Affinity)

	// Extract Tolerations with full details
	for _, t := range podSpec.Tolerations {
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

	// Cloud role detection
	roleResults := k8sinternal.DetectCloudRole(ctx, clientset, job.Namespace, podSpec.ServiceAccountName, &podSpec, job.Spec.Template.Annotations)
	if len(roleResults) > 0 {
		finding.CloudProvider = roleResults[0].Provider
		finding.CloudRole = roleResults[0].Role
	}

	// Run suspicious pattern detection using shared functions
	finding.ReverseShells = shared.DetectReverseShells(allCommands, allArgs)
	finding.CryptoMiners = shared.DetectCryptoMiners(allCommands, allArgs, allImages)
	finding.DataExfiltration = shared.DetectDataExfiltration(allCommands, allArgs)
	finding.ContainerEscape = shared.DetectContainerEscape(allCommands, allArgs, hostPaths)

	// Combine all backdoor patterns
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ReverseShells...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.CryptoMiners...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.DataExfiltration...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ContainerEscape...)

	// Metadata
	finding.Labels = k8sinternal.MapToStringList(job.Labels)
	finding.Annotations = k8sinternal.MapToStringList(job.Annotations)

	// Security issues analysis
	finding.SecurityIssues = analyzeJobSecurityIssues(finding)

	// Calculate risk level
	finding.RiskLevel = calculateJobRiskLevel(finding)

	return finding
}

// parseJobContainer extracts container details including security context
func parseJobContainer(c corev1.Container, privileged *bool, runAsUser *string, capabilities *[]string) JobContainer {
	// Parse image into components
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

	// Security context - per container
	containerPrivileged := false
	var containerCaps []string
	containerRunAsUser := "N/A"
	containerAllowPrivEsc := "N/A"
	containerReadOnlyRootFS := "N/A"

	if c.SecurityContext != nil {
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			containerPrivileged = true
			*privileged = true
		}
		if c.SecurityContext.RunAsUser != nil {
			uid := *c.SecurityContext.RunAsUser
			if uid == 0 {
				containerRunAsUser = "root"
				*runAsUser = "root"
			} else {
				containerRunAsUser = fmt.Sprintf("%d", uid)
				*runAsUser = fmt.Sprintf("%d", uid)
			}
		}
		if c.SecurityContext.AllowPrivilegeEscalation != nil {
			containerAllowPrivEsc = fmt.Sprintf("%v", *c.SecurityContext.AllowPrivilegeEscalation)
		}
		if c.SecurityContext.ReadOnlyRootFilesystem != nil {
			containerReadOnlyRootFS = fmt.Sprintf("%v", *c.SecurityContext.ReadOnlyRootFilesystem)
		}
		if c.SecurityContext.Capabilities != nil {
			for _, cap := range c.SecurityContext.Capabilities.Add {
				containerCaps = append(containerCaps, string(cap))
				*capabilities = append(*capabilities, string(cap))
			}
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

	return JobContainer{
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
	}
}

// ====================
// Helper Functions
// ====================

func analyzeJobStatus(job *batchv1.Job) (string, string) {
	duration := "N/A"

	if job.Status.CompletionTime != nil && job.Status.StartTime != nil {
		d := job.Status.CompletionTime.Sub(job.Status.StartTime.Time)
		duration = jobsFormatDuration(d)
	} else if job.Status.StartTime != nil {
		d := time.Since(job.Status.StartTime.Time)
		duration = jobsFormatDuration(d) + " (running)"
	}

	if job.Status.Succeeded > 0 {
		return "Completed", duration
	}

	if job.Status.Failed > 0 {
		if job.Spec.BackoffLimit != nil && job.Status.Failed >= *job.Spec.BackoffLimit {
			return "Backoff", duration
		}
		return "Failed", duration
	}

	if job.Status.Active > 0 {
		return "Running", duration
	}

	return "Pending", duration
}

func jobsFormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}

func calculateFailureRate(job *batchv1.Job) float64 {
	total := job.Status.Succeeded + job.Status.Failed
	if total == 0 {
		return 0.0
	}
	return float64(job.Status.Failed) / float64(total)
}

func isSensitiveHostPath(path string) bool {
	sensitivePaths := []string{
		"/var/run/docker.sock",
		"/var/run/containerd",
		"/var/run/crio",
		"/etc",
		"/root",
		"/var/lib/kubelet",
		"/var/lib/docker",
		"/proc",
		"/sys",
		"/dev",
	}
	for _, sensPath := range sensitivePaths {
		if strings.HasPrefix(path, sensPath) {
			return true
		}
	}
	return false
}

func isWritableMount(hostPath string, volumes []corev1.Volume, containers []corev1.Container) bool {
	// Find volume name for this hostPath
	var volumeName string
	for _, v := range volumes {
		if v.HostPath != nil && v.HostPath.Path == hostPath {
			volumeName = v.Name
			break
		}
	}
	if volumeName == "" {
		return false
	}

	// Check if any container mounts it as writable
	for _, c := range containers {
		for _, vm := range c.VolumeMounts {
			if vm.Name == volumeName && !vm.ReadOnly {
				return true
			}
		}
	}
	return false
}

func analyzeResourceLimits(podSpec *corev1.PodSpec) (bool, string) {
	hasLimits := 0
	hasRequests := 0
	totalContainers := len(podSpec.Containers)

	for _, c := range podSpec.Containers {
		if c.Resources.Limits != nil && (c.Resources.Limits.Cpu() != nil || c.Resources.Limits.Memory() != nil) {
			hasLimits++
		}
		if c.Resources.Requests != nil && (c.Resources.Requests.Cpu() != nil || c.Resources.Requests.Memory() != nil) {
			hasRequests++
		}
	}

	if hasLimits == totalContainers && hasRequests == totalContainers {
		return true, "Set"
	} else if hasLimits > 0 || hasRequests > 0 {
		return false, "Partial"
	}
	return false, "None"
}

func detectCronJob(job *batchv1.Job) (bool, string) {
	for _, owner := range job.OwnerReferences {
		if owner.Kind == "CronJob" {
			return true, owner.Name
		}
	}
	return false, ""
}

func analyzeJobSecurityIssues(finding JobFinding) []string {
	var issues []string

	// CRITICAL issues - malicious activity detected
	if len(finding.ReverseShells) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Reverse shell patterns: %s", strings.Join(finding.ReverseShells, ", ")))
	}
	if len(finding.CryptoMiners) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Crypto mining patterns: %s", strings.Join(finding.CryptoMiners, ", ")))
	}
	if len(finding.DataExfiltration) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Data exfiltration patterns: %s", strings.Join(finding.DataExfiltration, ", ")))
	}
	if len(finding.ContainerEscape) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Container escape patterns: %s", strings.Join(finding.ContainerEscape, ", ")))
	}

	// CRITICAL issues - security context
	if finding.Privileged {
		issues = append(issues, "Privileged container")
	}
	if finding.HostPID {
		issues = append(issues, "Host PID namespace")
	}
	if finding.HostIPC {
		issues = append(issues, "Host IPC namespace")
	}
	if finding.HostNetwork {
		issues = append(issues, "Host network namespace")
	}
	if len(finding.SensitiveHostPaths) > 0 {
		issues = append(issues, fmt.Sprintf("Sensitive hostPath mounts: %s", strings.Join(finding.SensitiveHostPaths, ", ")))
	}

	// Check for dangerous capabilities
	dangerousCaps := []string{"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN"}
	for _, cap := range finding.Capabilities {
		for _, dangerousCap := range dangerousCaps {
			if strings.EqualFold(cap, dangerousCap) {
				issues = append(issues, fmt.Sprintf("Dangerous capability: %s", cap))
			}
		}
	}

	// HIGH issues
	if finding.RunAsUser == "root" || finding.RunAsUser == "0" {
		issues = append(issues, "Running as root")
	}
	if finding.WritableHostPaths > 0 {
		issues = append(issues, fmt.Sprintf("%d writable hostPath mounts", finding.WritableHostPaths))
	}

	// MEDIUM issues
	if !finding.HasResourceLimits {
		issues = append(issues, "No resource limits set")
	}
	for _, tagType := range finding.ImageTagTypes {
		if tagType == "latest" {
			issues = append(issues, "Using :latest image tag")
			break
		}
	}
	if finding.ServiceAccount == "default" && finding.AutomountSAToken {
		issues = append(issues, "Using default ServiceAccount with token automount")
	}
	if finding.RestartPolicy == "Always" {
		issues = append(issues, "RestartPolicy set to Always (incorrect for jobs)")
	}
	if finding.TTL == 0 && finding.Status == "Completed" {
		issues = append(issues, "No TTL set (job will not be cleaned up)")
	}

	// Failure-related issues
	if finding.FailureRate > 0.5 && finding.Failed > 0 {
		issues = append(issues, fmt.Sprintf("High failure rate: %.1f%%", finding.FailureRate*100))
	}
	if finding.Status == "Backoff" {
		issues = append(issues, "Job exceeded backoff limit")
	}

	return issues
}

func calculateJobRiskLevel(finding JobFinding) string {
	// CRITICAL: Active backdoors, reverse shells, crypto miners
	if len(finding.ReverseShells) > 0 {
		return shared.RiskCritical
	}
	if len(finding.CryptoMiners) > 0 {
		return shared.RiskCritical
	}
	if len(finding.ContainerEscape) > 0 {
		return shared.RiskCritical
	}
	// Privileged job with hostPath to runtime sockets
	if finding.Privileged && len(finding.HostPaths) > 0 {
		for _, hp := range finding.HostPaths {
			if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") ||
				hp == "/" || strings.HasPrefix(hp, "/:") {
				return shared.RiskCritical
			}
		}
	}

	// HIGH: Data exfiltration, privileged + host access
	if len(finding.DataExfiltration) > 0 {
		return shared.RiskHigh
	}
	if finding.Privileged && (finding.HostPID || finding.HostIPC) {
		return shared.RiskHigh
	}
	// Check for dangerous capabilities
	dangerousCaps := []string{"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN"}
	for _, cap := range finding.Capabilities {
		for _, dangerousCap := range dangerousCaps {
			if strings.EqualFold(cap, dangerousCap) {
				return shared.RiskHigh
			}
		}
	}

	// MEDIUM: HostNetwork, cloud roles, privileged alone
	if finding.HostNetwork {
		return shared.RiskMedium
	}
	if finding.CloudRole != "" && finding.CloudRole != "<NONE>" {
		return shared.RiskMedium
	}
	if finding.Privileged {
		return shared.RiskMedium
	}
	if finding.HostPID || finding.HostIPC {
		return shared.RiskMedium
	}

	// LOW: Standard job
	return shared.RiskLow
}

// ====================
// Loot File Builders
// ====================

func generateJobLoot(findings []JobFinding, kubeContext string, riskCounts *shared.RiskCounts) []internal.LootFile {
	var lootContent []string
	var entrypointsContent []string

	// Sort findings by namespace/name
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Namespace != findings[j].Namespace {
			return findings[i].Namespace < findings[j].Namespace
		}
		return findings[i].Name < findings[j].Name
	})

	// ========================================
	// Jobs-Commands.txt - Consolidated commands
	// ========================================
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "##### Jobs Commands")
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "")

	if kubeContext != "" {
		lootContent = append(lootContent, fmt.Sprintf("kubectl config use-context %s", kubeContext))
		lootContent = append(lootContent, "")
	}

	// === ENUMERATION ===
	lootContent = append(lootContent, "=== ENUMERATION ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# List all jobs")
	lootContent = append(lootContent, "kubectl get jobs -A -o wide")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find privileged jobs")
	lootContent = append(lootContent, "kubectl get jobs -A -o json | jq -r '.items[] | select(.spec.template.spec.containers[]?.securityContext?.privileged == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find jobs with hostPath volumes")
	lootContent = append(lootContent, "kubectl get jobs -A -o json | jq -r '.items[] | select(.spec.template.spec.volumes[]?.hostPath != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find failed jobs")
	lootContent = append(lootContent, "kubectl get jobs -A -o json | jq -r '.items[] | select(.status.failed > 0) | \"\\(.metadata.namespace)/\\(.metadata.name) - Failed: \\(.status.failed)\"'")
	lootContent = append(lootContent, "")

	// === HIGH RISK ===
	var hasHighRisk bool
	for _, f := range findings {
		if f.RiskLevel == shared.RiskCritical || f.RiskLevel == shared.RiskHigh {
			if !hasHighRisk {
				lootContent = append(lootContent, "=== HIGH RISK ===")
				lootContent = append(lootContent, "")
				hasHighRisk = true
			}
			lootContent = append(lootContent, fmt.Sprintf("# [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
			lootContent = append(lootContent, fmt.Sprintf("kubectl get job %s -n %s -o yaml", f.Name, f.Namespace))
			lootContent = append(lootContent, fmt.Sprintf("kubectl describe job %s -n %s", f.Name, f.Namespace))
			if len(f.SecurityIssues) > 0 {
				for _, issue := range f.SecurityIssues {
					lootContent = append(lootContent, fmt.Sprintf("#   - %s", issue))
				}
			}
			lootContent = append(lootContent, "")
		}
	}

	// === SECRETS ACCESS ===
	var hasSecrets bool
	for _, f := range findings {
		if len(f.Secrets) > 0 {
			if !hasSecrets {
				lootContent = append(lootContent, "=== SECRETS ACCESS ===")
				lootContent = append(lootContent, "")
				hasSecrets = true
			}
			lootContent = append(lootContent, fmt.Sprintf("# %s/%s - Secrets: %s", f.Namespace, f.Name, strings.Join(f.Secrets, ", ")))
			for _, secret := range f.Secrets {
				lootContent = append(lootContent, fmt.Sprintf("kubectl get secret %s -n %s -o yaml", secret, f.Namespace))
			}
			lootContent = append(lootContent, "")
		}
	}

	// === CRONJOB MAPPING ===
	cronJobMap := make(map[string][]JobFinding)
	for _, f := range findings {
		if f.FromCronJob {
			cronJobMap[f.CronJobName] = append(cronJobMap[f.CronJobName], f)
		}
	}
	if len(cronJobMap) > 0 {
		lootContent = append(lootContent, "=== CRONJOB MAPPING ===")
		lootContent = append(lootContent, "")
		for cronJob, jobs := range cronJobMap {
			lootContent = append(lootContent, fmt.Sprintf("# CronJob: %s - Job Count: %d", cronJob, len(jobs)))
			for _, job := range jobs {
				lootContent = append(lootContent, fmt.Sprintf("#   - [%s] %s/%s (Status: %s)", job.RiskLevel, job.Namespace, job.Name, job.Status))
			}
			if len(jobs) > 0 {
				ns := jobs[0].Namespace
				lootContent = append(lootContent, fmt.Sprintf("kubectl get cronjob %s -n %s -o yaml", cronJob, ns))
			}
			lootContent = append(lootContent, "")
		}
	}

	// ========================================
	// Job-Entrypoints.txt - Container startup commands
	// ========================================
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "##### Job Container Entrypoints")
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "# Only containers with commands or args are shown")
	entrypointsContent = append(entrypointsContent, "")

	for _, f := range findings {
		var containerEntries []string
		for _, c := range f.Containers {
			if c.Command != "" || c.Args != "" {
				containerEntries = append(containerEntries, fmt.Sprintf("Container: %s", c.Name))
				containerEntries = append(containerEntries, fmt.Sprintf("  Image: %s", c.Image))
				if c.Command != "" {
					containerEntries = append(containerEntries, fmt.Sprintf("  Command: %s", c.Command))
				}
				if c.Args != "" {
					containerEntries = append(containerEntries, fmt.Sprintf("  Args: %s", c.Args))
				}
				containerEntries = append(containerEntries, "")
			}
		}

		if len(containerEntries) > 0 {
			entrypointsContent = append(entrypointsContent, fmt.Sprintf("=== %s/%s ===", f.Namespace, f.Name))
			entrypointsContent = append(entrypointsContent, "")
			entrypointsContent = append(entrypointsContent, containerEntries...)
		}
	}

	return []internal.LootFile{
		{Name: "Jobs-Commands", Contents: strings.Join(lootContent, "\n")},
		{Name: "Job-Entrypoints", Contents: strings.Join(entrypointsContent, "\n")},
	}
}
