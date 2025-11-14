package commands

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
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

	// Container security
	Containers        []string
	InitContainers    []string
	Images            []string
	ImageTagTypes     []string // "latest", "pinned", "sha256"
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
	RestartPolicy      string
	ActiveDeadline     int64
	TTL                int32
	FromCronJob        bool
	CronJobName        string
	ServiceAccount     string
	AutomountSAToken   bool
	DangerousCommands  []string
	SuspiciousActivity bool

	// Cloud
	CloudProvider string
	CloudRole     string

	// Metadata
	Labels      []string
	Annotations []string
}

func ListJobs(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating jobs for %s", globals.ClusterName), globals.K8S_JOBS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	jobs, err := clientset.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Jobs: %v", err), globals.K8S_JOBS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk",
		"Namespace",
		"Job Name",
		"Status",
		"Duration",
		"Security Issues",
		"Privileged",
		"Run As Root",
		"Host Namespaces",
		"Secrets",
		"Image Tags",
		"Resource Limits",
		"Dangerous Commands",
		"From CronJob",
		"Cloud Role",
	}

	var outputRows [][]string
	var findings []JobFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Loot file builders
	var lootEnum []string
	var lootRiskDashboard []string
	var lootFailures []string
	var lootHighRisk []string
	var lootSecrets []string
	var lootCronJobs []string
	var lootLongRunning []string

	lootEnum = append(lootEnum, `#####################################
##### Job Enumeration
#####################################
#
# Basic job enumeration commands
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, job := range jobs.Items {
		finding := analyzeJob(ctx, clientset, &job)
		findings = append(findings, finding)
		riskCounts[finding.RiskLevel]++

		// Build table row
		securityIssuesStr := "<none>"
		if len(finding.SecurityIssues) > 0 {
			if len(finding.SecurityIssues) > 2 {
				securityIssuesStr = strings.Join(finding.SecurityIssues[:2], "; ") + fmt.Sprintf(" (+%d more)", len(finding.SecurityIssues)-2)
			} else {
				securityIssuesStr = strings.Join(finding.SecurityIssues, "; ")
			}
		}

		privilegedStr := "No"
		if finding.Privileged {
			privilegedStr = "Yes"
		}

		runAsRootStr := "No"
		if finding.RunAsUser == "root" || finding.RunAsUser == "0" {
			runAsRootStr = "Yes"
		} else if finding.RunAsUser != "N/A" {
			runAsRootStr = fmt.Sprintf("No (UID %s)", finding.RunAsUser)
		}

		hostNamespacesStr := "<none>"
		hostNS := []string{}
		if finding.HostPID {
			hostNS = append(hostNS, "PID")
		}
		if finding.HostIPC {
			hostNS = append(hostNS, "IPC")
		}
		if finding.HostNetwork {
			hostNS = append(hostNS, "Network")
		}
		if len(hostNS) > 0 {
			hostNamespacesStr = strings.Join(hostNS, ", ")
		}

		secretsStr := "<none>"
		if len(finding.Secrets) > 0 {
			secretsStr = fmt.Sprintf("%d secrets", len(finding.Secrets))
		}

		imageTagsStr := "<mixed>"
		if len(finding.ImageTagTypes) > 0 {
			tagCounts := make(map[string]int)
			for _, tagType := range finding.ImageTagTypes {
				tagCounts[tagType]++
			}
			var tagParts []string
			for tagType, count := range tagCounts {
				tagParts = append(tagParts, fmt.Sprintf("%s(%d)", tagType, count))
			}
			imageTagsStr = strings.Join(tagParts, ", ")
		}

		dangerousCmdsStr := "No"
		if len(finding.DangerousCommands) > 0 {
			dangerousCmdsStr = fmt.Sprintf("Yes (%d)", len(finding.DangerousCommands))
		}

		fromCronJobStr := "No"
		if finding.FromCronJob {
			fromCronJobStr = finding.CronJobName
		}

		outputRows = append(outputRows, []string{
			finding.RiskLevel,
			finding.Namespace,
			finding.Name,
			finding.Status,
			finding.Duration,
			securityIssuesStr,
			privilegedStr,
			runAsRootStr,
			hostNamespacesStr,
			secretsStr,
			imageTagsStr,
			finding.ResourceLimits,
			dangerousCmdsStr,
			fromCronJobStr,
			k8sinternal.NonEmpty(finding.CloudRole),
		})

		// Generate enumeration commands
		lootEnum = append(lootEnum, fmt.Sprintf("\n# [%s] %s/%s", finding.RiskLevel, finding.Namespace, finding.Name))
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl get job %s -n %s -o yaml", finding.Name, finding.Namespace))
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl describe job %s -n %s", finding.Name, finding.Namespace))
		lootEnum = append(lootEnum, "")
	}

	// Build Risk Dashboard loot file
	lootRiskDashboard = buildRiskDashboard(findings, riskCounts)

	// Build Failures loot file
	lootFailures = buildFailuresLoot(findings)

	// Build High Risk loot file
	lootHighRisk = buildHighRiskLoot(findings)

	// Build Secrets Access loot file
	lootSecrets = buildSecretsLoot(findings)

	// Build CronJob Mapping loot file
	lootCronJobs = buildCronJobsLoot(findings)

	// Build Long Running loot file
	lootLongRunning = buildLongRunningLoot(findings)

	table := internal.TableFile{
		Name:   "Jobs",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{Name: "Job-Risk-Dashboard", Contents: strings.Join(lootRiskDashboard, "\n")},
		{Name: "Job-Enum", Contents: strings.Join(lootEnum, "\n")},
		{Name: "Job-Failures", Contents: strings.Join(lootFailures, "\n")},
		{Name: "Job-High-Risk", Contents: strings.Join(lootHighRisk, "\n")},
		{Name: "Job-Secrets-Access", Contents: strings.Join(lootSecrets, "\n")},
		{Name: "Job-CronJob-Mapping", Contents: strings.Join(lootCronJobs, "\n")},
		{Name: "Job-Long-Running", Contents: strings.Join(lootLongRunning, "\n")},
	}

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
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_JOBS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d jobs found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_JOBS_MODULE_NAME)
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

	podSpec := &job.Spec.Template.Spec

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

	// Container analysis
	finding.Containers, finding.Images, finding.ImageTagTypes = analyzeContainers(podSpec.Containers)
	finding.InitContainers, _, _ = analyzeContainers(podSpec.InitContainers)

	// Security context analysis
	finding.Privileged, finding.RunAsUser, finding.RunAsNonRoot, finding.Capabilities, finding.DangerousCaps, finding.AllowPrivEsc, finding.ReadOnlyRootFS = analyzeSecurityContext(podSpec)

	// Volume analysis
	finding.Secrets, finding.ConfigMaps, finding.HostPaths, finding.SensitiveHostPaths, finding.WritableHostPaths = analyzeVolumes(podSpec)

	// Host namespaces
	finding.HostPID = podSpec.HostPID
	finding.HostIPC = podSpec.HostIPC
	finding.HostNetwork = podSpec.HostNetwork

	// Resource limits
	finding.HasResourceLimits, finding.ResourceLimits = analyzeResourceLimits(podSpec)

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

	// Command analysis
	finding.DangerousCommands = analyzeDangerousCommands(podSpec)

	// Cloud role detection
	roleResults := k8sinternal.DetectCloudRole(ctx, clientset, job.Namespace, podSpec.ServiceAccountName, podSpec, job.Spec.Template.Annotations)
	if len(roleResults) > 0 {
		finding.CloudProvider = roleResults[0].Provider
		finding.CloudRole = roleResults[0].Role
	} else {
		finding.CloudProvider = "<NONE>"
		finding.CloudRole = "<NONE>"
	}

	// Metadata
	finding.Labels = k8sinternal.MapToStringList(job.Labels)
	finding.Annotations = k8sinternal.MapToStringList(job.Annotations)

	// Security issues analysis
	finding.SecurityIssues = analyzeJobSecurityIssues(finding)

	// Calculate risk level
	finding.RiskLevel = calculateJobRiskLevel(finding)

	return finding
}

// ====================
// Helper Functions
// ====================

func analyzeJobStatus(job *batchv1.Job) (string, string) {
	duration := "N/A"

	if job.Status.CompletionTime != nil && job.Status.StartTime != nil {
		d := job.Status.CompletionTime.Sub(job.Status.StartTime.Time)
		duration = formatDuration(d)
	} else if job.Status.StartTime != nil {
		d := time.Since(job.Status.StartTime.Time)
		duration = formatDuration(d) + " (running)"
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

func formatDuration(d time.Duration) string {
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

func analyzeContainers(containers []corev1.Container) ([]string, []string, []string) {
	var containerNames []string
	var images []string
	var imageTagTypes []string

	for _, c := range containers {
		containerNames = append(containerNames, fmt.Sprintf("%s:%s", c.Name, c.Image))
		images = append(images, c.Image)

		// Determine image tag type
		if strings.HasSuffix(c.Image, ":latest") || !strings.Contains(c.Image, ":") {
			imageTagTypes = append(imageTagTypes, "latest")
		} else if strings.Contains(c.Image, "@sha256:") {
			imageTagTypes = append(imageTagTypes, "sha256")
		} else {
			imageTagTypes = append(imageTagTypes, "pinned")
		}
	}

	return containerNames, images, imageTagTypes
}

func analyzeSecurityContext(podSpec *corev1.PodSpec) (bool, string, bool, []string, []string, bool, bool) {
	privileged := false
	runAsUser := "N/A"
	runAsNonRoot := false
	var capabilities []string
	var dangerousCaps []string
	allowPrivEsc := true // default is true
	readOnlyRootFS := false

	// Pod-level security context
	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.RunAsUser != nil {
			uid := *podSpec.SecurityContext.RunAsUser
			if uid == 0 {
				runAsUser = "root"
			} else {
				runAsUser = fmt.Sprintf("%d", uid)
			}
		}
		if podSpec.SecurityContext.RunAsNonRoot != nil {
			runAsNonRoot = *podSpec.SecurityContext.RunAsNonRoot
		}
	}

	// Container-level security context (overrides pod-level)
	for _, c := range podSpec.Containers {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = true
			}
			if c.SecurityContext.RunAsUser != nil {
				uid := *c.SecurityContext.RunAsUser
				if uid == 0 {
					runAsUser = "root"
				} else {
					runAsUser = fmt.Sprintf("%d", uid)
				}
			}
			if c.SecurityContext.RunAsNonRoot != nil {
				runAsNonRoot = *c.SecurityContext.RunAsNonRoot
			}
			if c.SecurityContext.AllowPrivilegeEscalation != nil {
				allowPrivEsc = *c.SecurityContext.AllowPrivilegeEscalation
			}
			if c.SecurityContext.ReadOnlyRootFilesystem != nil {
				readOnlyRootFS = *c.SecurityContext.ReadOnlyRootFilesystem
			}
			if c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					capStr := string(cap)
					capabilities = append(capabilities, capStr)
					if isDangerousCap(capStr) {
						dangerousCaps = append(dangerousCaps, capStr)
					}
				}
			}
		}
	}

	// If runAsUser not set and not runAsNonRoot, assume root
	if runAsUser == "N/A" && !runAsNonRoot {
		runAsUser = "root"
	}

	return privileged, runAsUser, runAsNonRoot, capabilities, dangerousCaps, allowPrivEsc, readOnlyRootFS
}

func isDangerousCap(cap string) bool {
	dangerousCaps := []string{
		"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE",
		"SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE", "DAC_OVERRIDE",
		"DAC_READ_SEARCH", "NET_ADMIN", "NET_RAW",
	}
	for _, dangerous := range dangerousCaps {
		if strings.EqualFold(cap, dangerous) {
			return true
		}
	}
	return false
}

func analyzeVolumes(podSpec *corev1.PodSpec) ([]string, []string, []string, []string, int) {
	var secrets []string
	var configMaps []string
	var hostPaths []string
	var sensitiveHostPaths []string
	writableHostPaths := 0

	for _, v := range podSpec.Volumes {
		if v.Secret != nil {
			secrets = append(secrets, v.Secret.SecretName)
		}
		if v.ConfigMap != nil {
			configMaps = append(configMaps, v.ConfigMap.Name)
		}
		if v.HostPath != nil {
			hostPaths = append(hostPaths, v.HostPath.Path)
			if isSensitiveHostPath(v.HostPath.Path) {
				sensitiveHostPaths = append(sensitiveHostPaths, v.HostPath.Path)
			}
			// Check if mounted as writable
			if isWritableMount(v.Name, podSpec.Containers) {
				writableHostPaths++
			}
		}
	}

	return secrets, configMaps, hostPaths, sensitiveHostPaths, writableHostPaths
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

func isWritableMount(volumeName string, containers []corev1.Container) bool {
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

var dangerousCommandPatterns = []struct {
	pattern     *regexp.Regexp
	description string
}{
	{regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/tcp/`), "Reverse shell (bash)"},
	{regexp.MustCompile(`nc\s+-e\s+/bin/(ba)?sh`), "Reverse shell (netcat)"},
	{regexp.MustCompile(`python.*-c.*socket`), "Reverse shell (python)"},
	{regexp.MustCompile(`perl.*socket`), "Reverse shell (perl)"},
	{regexp.MustCompile(`xmrig|ethminer|minerd|cpuminer`), "Crypto mining"},
	{regexp.MustCompile(`curl.*\|\s*bash|wget.*\|\s*sh`), "Download and execute"},
	{regexp.MustCompile(`base64\s+-d.*\|\s*(ba)?sh`), "Base64 encoded execution"},
	{regexp.MustCompile(`eval\s*\$\(echo.*base64`), "Eval base64 payload"},
	{regexp.MustCompile(`kubectl\s+get\s+secrets?`), "Secret extraction"},
	{regexp.MustCompile(`aws\s+s3\s+(cp|sync)`), "AWS data exfiltration"},
	{regexp.MustCompile(`nmap|masscan|nikto`), "Network scanning"},
	{regexp.MustCompile(`sqlmap|hydra|john`), "Hacking tools"},
	{regexp.MustCompile(`/var/run/secrets/kubernetes.io`), "ServiceAccount token access"},
}

func analyzeDangerousCommands(podSpec *corev1.PodSpec) []string {
	var dangerous []string
	seen := make(map[string]bool)

	// Check container commands and args
	allContainers := append(podSpec.Containers, podSpec.InitContainers...)
	for _, c := range allContainers {
		commandStr := strings.Join(append(c.Command, c.Args...), " ")

		for _, pattern := range dangerousCommandPatterns {
			if pattern.pattern.MatchString(commandStr) {
				if !seen[pattern.description] {
					dangerous = append(dangerous, pattern.description)
					seen[pattern.description] = true
				}
			}
		}
	}

	return dangerous
}

func analyzeJobSecurityIssues(finding JobFinding) []string {
	var issues []string

	// CRITICAL issues
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
	if len(finding.DangerousCaps) > 0 {
		issues = append(issues, fmt.Sprintf("Dangerous capabilities: %s", strings.Join(finding.DangerousCaps, ", ")))
	}
	if len(finding.DangerousCommands) > 0 {
		issues = append(issues, fmt.Sprintf("Dangerous commands detected: %s", strings.Join(finding.DangerousCommands, ", ")))
	}

	// HIGH issues
	if finding.RunAsUser == "root" || finding.RunAsUser == "0" {
		issues = append(issues, "Running as root")
	}
	if finding.AllowPrivEsc {
		issues = append(issues, "allowPrivilegeEscalation not set to false")
	}
	if finding.WritableHostPaths > 0 {
		issues = append(issues, fmt.Sprintf("%d writable hostPath mounts", finding.WritableHostPaths))
	}

	// MEDIUM issues
	if !finding.ReadOnlyRootFS {
		issues = append(issues, "readOnlyRootFilesystem not set to true")
	}
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
	riskScore := 0

	// CRITICAL FACTORS (50+ points each)
	if finding.Privileged && finding.HostNetwork && (finding.RunAsUser == "root" || finding.RunAsUser == "0") {
		riskScore += 100
	}
	if finding.Privileged && finding.WritableHostPaths > 0 {
		riskScore += 80
	}
	if len(finding.DangerousCommands) > 0 && finding.Privileged {
		riskScore += 70
	}
	if len(finding.SensitiveHostPaths) > 0 && finding.WritableHostPaths > 0 {
		riskScore += 60
	}
	if len(finding.DangerousCaps) > 0 && finding.HostPID {
		riskScore += 50
	}

	// HIGH FACTORS (20-40 points each)
	if finding.Privileged {
		riskScore += 40
	}
	if len(finding.DangerousCaps) > 0 {
		riskScore += 30
	}
	if len(finding.DangerousCommands) > 0 {
		riskScore += 30
	}
	if finding.HostPID || finding.HostIPC {
		riskScore += 25
	}
	if finding.HostNetwork {
		riskScore += 25
	}
	if len(finding.SensitiveHostPaths) > 0 {
		riskScore += 20
	}
	if finding.RunAsUser == "root" || finding.RunAsUser == "0" {
		riskScore += 20
	}

	// MEDIUM FACTORS (5-15 points each)
	if finding.AllowPrivEsc {
		riskScore += 15
	}
	if !finding.HasResourceLimits && finding.Parallelism > 5 {
		riskScore += 15 // DoS risk
	}
	if len(finding.HostPaths) > 0 {
		riskScore += 10
	}
	if finding.WritableHostPaths > 0 {
		riskScore += 10
	}
	for _, tagType := range finding.ImageTagTypes {
		if tagType == "latest" {
			riskScore += 8
			break
		}
	}
	if !finding.ReadOnlyRootFS {
		riskScore += 5
	}

	// LOW FACTORS (1-3 points each)
	if len(finding.Secrets) > 0 {
		riskScore += 3
	}
	if !finding.HasResourceLimits {
		riskScore += 2
	}
	if finding.ServiceAccount == "default" && finding.AutomountSAToken {
		riskScore += 2
	}

	// Determine risk level
	if riskScore >= 50 {
		return "CRITICAL"
	} else if riskScore >= 25 {
		return "HIGH"
	} else if riskScore >= 10 {
		return "MEDIUM"
	}
	return "LOW"
}

// ====================
// Loot File Builders
// ====================

func buildRiskDashboard(findings []JobFinding, riskCounts map[string]int) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Job Risk Statistics Dashboard
#####################################
#
# Summary of job security posture
#
`)

	totalJobs := len(findings)
	lines = append(lines, "\n## Overall Statistics")
	lines = append(lines, fmt.Sprintf("Total Jobs: %d", totalJobs))
	lines = append(lines, fmt.Sprintf("CRITICAL Risk: %d", riskCounts["CRITICAL"]))
	lines = append(lines, fmt.Sprintf("HIGH Risk:     %d", riskCounts["HIGH"]))
	lines = append(lines, fmt.Sprintf("MEDIUM Risk:   %d", riskCounts["MEDIUM"]))
	lines = append(lines, fmt.Sprintf("LOW Risk:      %d", riskCounts["LOW"]))

	// Count various security metrics
	privilegedCount := 0
	rootCount := 0
	failedCount := 0
	backoffCount := 0
	noLimitsCount := 0
	dangerousCmdCount := 0
	fromCronJobCount := 0

	for _, f := range findings {
		if f.Privileged {
			privilegedCount++
		}
		if f.RunAsUser == "root" || f.RunAsUser == "0" {
			rootCount++
		}
		if f.Status == "Failed" || f.Status == "Backoff" {
			failedCount++
		}
		if f.Status == "Backoff" {
			backoffCount++
		}
		if !f.HasResourceLimits {
			noLimitsCount++
		}
		if len(f.DangerousCommands) > 0 {
			dangerousCmdCount++
		}
		if f.FromCronJob {
			fromCronJobCount++
		}
	}

	lines = append(lines, "\n## Security Posture")
	lines = append(lines, fmt.Sprintf("Privileged Jobs: %d", privilegedCount))
	lines = append(lines, fmt.Sprintf("Running as Root: %d", rootCount))
	lines = append(lines, fmt.Sprintf("Failed/Backoff: %d", failedCount))
	lines = append(lines, fmt.Sprintf("Jobs in Backoff: %d", backoffCount))
	lines = append(lines, fmt.Sprintf("No Resource Limits: %d", noLimitsCount))
	lines = append(lines, fmt.Sprintf("Dangerous Commands: %d", dangerousCmdCount))
	lines = append(lines, fmt.Sprintf("From CronJobs: %d", fromCronJobCount))

	lines = append(lines, "\n## Recommendations")
	if riskCounts["CRITICAL"] > 0 {
		lines = append(lines, fmt.Sprintf("⚠️  URGENT: %d CRITICAL jobs require immediate investigation", riskCounts["CRITICAL"]))
	}
	if privilegedCount > 0 {
		lines = append(lines, fmt.Sprintf("⚠️  WARNING: %d privileged jobs detected", privilegedCount))
	}
	if dangerousCmdCount > 0 {
		lines = append(lines, fmt.Sprintf("⚠️  WARNING: %d jobs with dangerous commands", dangerousCmdCount))
	}
	if backoffCount > 0 {
		lines = append(lines, fmt.Sprintf("⚠️  WARNING: %d jobs stuck in backoff (investigate failures)", backoffCount))
	}

	return lines
}

func buildFailuresLoot(findings []JobFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Job Failures Analysis
#####################################
#
# Failed jobs and backoff situations
#
`)

	hasFailures := false
	for _, f := range findings {
		if f.Status == "Failed" || f.Status == "Backoff" || f.Failed > 0 {
			hasFailures = true
			lines = append(lines, fmt.Sprintf("\n## [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
			lines = append(lines, fmt.Sprintf("Status: %s", f.Status))
			lines = append(lines, fmt.Sprintf("Failed: %d | Succeeded: %d | Failure Rate: %.1f%%", f.Failed, f.Succeeded, f.FailureRate*100))
			lines = append(lines, fmt.Sprintf("Backoff Limit: %d", f.BackoffLimit))
			if len(f.SecurityIssues) > 0 {
				lines = append(lines, "Security Issues:")
				for _, issue := range f.SecurityIssues {
					lines = append(lines, fmt.Sprintf("  - %s", issue))
				}
			}
			lines = append(lines, "\n# Investigation commands:")
			lines = append(lines, fmt.Sprintf("kubectl describe job %s -n %s", f.Name, f.Namespace))
			lines = append(lines, fmt.Sprintf("kubectl get pods -n %s -l job-name=%s", f.Namespace, f.Name))
			lines = append(lines, fmt.Sprintf("kubectl logs -n %s -l job-name=%s --tail=100", f.Namespace, f.Name))
			lines = append(lines, "")
		}
	}

	if !hasFailures {
		lines = append(lines, "\n# No failed jobs detected")
	}

	return lines
}

func buildHighRiskLoot(findings []JobFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### High Risk Jobs
#####################################
#
# CRITICAL and HIGH risk jobs requiring immediate attention
#
`)

	hasHighRisk := false
	for _, f := range findings {
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			hasHighRisk = true
			lines = append(lines, fmt.Sprintf("\n### [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
			lines = append(lines, fmt.Sprintf("Status: %s | Duration: %s", f.Status, f.Duration))

			if f.Privileged {
				lines = append(lines, "⚠️  PRIVILEGED CONTAINER")
			}
			if f.RunAsUser == "root" {
				lines = append(lines, "⚠️  RUNNING AS ROOT")
			}
			if len(f.DangerousCommands) > 0 {
				lines = append(lines, fmt.Sprintf("⚠️  DANGEROUS COMMANDS: %s", strings.Join(f.DangerousCommands, ", ")))
			}

			lines = append(lines, "\nSecurity Issues:")
			for _, issue := range f.SecurityIssues {
				lines = append(lines, fmt.Sprintf("  - %s", issue))
			}

			if len(f.SensitiveHostPaths) > 0 {
				lines = append(lines, fmt.Sprintf("\nSensitive HostPaths: %s", strings.Join(f.SensitiveHostPaths, ", ")))
			}

			lines = append(lines, "\n# Exploitation / Investigation:")
			lines = append(lines, fmt.Sprintf("kubectl get job %s -n %s -o yaml", f.Name, f.Namespace))
			lines = append(lines, fmt.Sprintf("kubectl get pods -n %s -l job-name=%s -o wide", f.Namespace, f.Name))
			if f.Status == "Running" {
				lines = append(lines, fmt.Sprintf("# Exec into running pod:"))
				lines = append(lines, fmt.Sprintf("POD=$(kubectl get pods -n %s -l job-name=%s -o jsonpath='{.items[0].metadata.name}')", f.Namespace, f.Name))
				lines = append(lines, fmt.Sprintf("kubectl exec -it -n %s $POD -- /bin/sh", f.Namespace))
			}
			lines = append(lines, "")
		}
	}

	if !hasHighRisk {
		lines = append(lines, "\n# No CRITICAL or HIGH risk jobs detected")
	}

	return lines
}

func buildSecretsLoot(findings []JobFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Jobs with Secret Access
#####################################
#
# Jobs accessing secrets or ServiceAccount tokens
#
`)

	hasSecrets := false
	for _, f := range findings {
		if len(f.Secrets) > 0 || f.AutomountSAToken {
			hasSecrets = true
			lines = append(lines, fmt.Sprintf("\n## [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
			lines = append(lines, fmt.Sprintf("ServiceAccount: %s (AutomountToken: %v)", f.ServiceAccount, f.AutomountSAToken))
			if len(f.Secrets) > 0 {
				lines = append(lines, fmt.Sprintf("Mounted Secrets: %s", strings.Join(f.Secrets, ", ")))
				lines = append(lines, "\n# Extract secrets:")
				for _, secret := range f.Secrets {
					lines = append(lines, fmt.Sprintf("kubectl get secret %s -n %s -o yaml", secret, f.Namespace))
				}
			}
			if f.AutomountSAToken {
				lines = append(lines, "\n# ServiceAccount token location in pod:")
				lines = append(lines, "# /var/run/secrets/kubernetes.io/serviceaccount/token")
				if f.Status == "Running" {
					lines = append(lines, fmt.Sprintf("POD=$(kubectl get pods -n %s -l job-name=%s -o jsonpath='{.items[0].metadata.name}')", f.Namespace, f.Name))
					lines = append(lines, fmt.Sprintf("kubectl exec -n %s $POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", f.Namespace))
				}
			}
			lines = append(lines, "")
		}
	}

	if !hasSecrets {
		lines = append(lines, "\n# No jobs with explicit secret access detected")
	}

	return lines
}

func buildCronJobsLoot(findings []JobFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### CronJob to Job Mapping
#####################################
#
# Jobs created by CronJobs
#
`)

	cronJobMap := make(map[string][]JobFinding)
	for _, f := range findings {
		if f.FromCronJob {
			cronJobMap[f.CronJobName] = append(cronJobMap[f.CronJobName], f)
		}
	}

	if len(cronJobMap) > 0 {
		for cronJob, jobs := range cronJobMap {
			lines = append(lines, fmt.Sprintf("\n## CronJob: %s", cronJob))
			lines = append(lines, fmt.Sprintf("Job Count: %d", len(jobs)))

			for _, job := range jobs {
				lines = append(lines, fmt.Sprintf("  - [%s] %s/%s (Status: %s, Duration: %s)",
					job.RiskLevel, job.Namespace, job.Name, job.Status, job.Duration))
			}

			// Show CronJob details
			if len(jobs) > 0 {
				ns := jobs[0].Namespace
				lines = append(lines, fmt.Sprintf("\n# CronJob details:"))
				lines = append(lines, fmt.Sprintf("kubectl get cronjob %s -n %s -o yaml", cronJob, ns))
				lines = append(lines, fmt.Sprintf("kubectl describe cronjob %s -n %s", cronJob, ns))
			}
			lines = append(lines, "")
		}
	} else {
		lines = append(lines, "\n# No CronJob-managed jobs detected")
	}

	// List one-time jobs
	var oneTimeJobs []JobFinding
	for _, f := range findings {
		if !f.FromCronJob {
			oneTimeJobs = append(oneTimeJobs, f)
		}
	}

	if len(oneTimeJobs) > 0 {
		lines = append(lines, fmt.Sprintf("\n## One-Time Jobs (not from CronJobs): %d", len(oneTimeJobs)))
		for _, job := range oneTimeJobs {
			lines = append(lines, fmt.Sprintf("  - [%s] %s/%s", job.RiskLevel, job.Namespace, job.Name))
		}
	}

	return lines
}

func buildLongRunningLoot(findings []JobFinding) []string {
	var lines []string
	lines = append(lines, `#####################################
##### Long Running Jobs Analysis
#####################################
#
# Jobs with unusual duration patterns
#
`)

	hasLongRunning := false
	for _, f := range findings {
		// Consider jobs running > 1 hour or never completing
		if f.Status == "Running" && f.StartTime != "" {
			startTime, err := time.Parse(time.RFC3339, f.StartTime)
			if err == nil {
				duration := time.Since(startTime)
				if duration > time.Hour {
					hasLongRunning = true
					lines = append(lines, fmt.Sprintf("\n## [%s] %s/%s", f.RiskLevel, f.Namespace, f.Name))
					lines = append(lines, fmt.Sprintf("Status: %s", f.Status))
					lines = append(lines, fmt.Sprintf("Running Duration: %s", formatDuration(duration)))
					lines = append(lines, fmt.Sprintf("Start Time: %s", f.StartTime))

					if f.ActiveDeadline > 0 {
						lines = append(lines, fmt.Sprintf("Active Deadline: %ds", f.ActiveDeadline))
					} else {
						lines = append(lines, "⚠️  WARNING: No active deadline set (job can run forever)")
					}

					if len(f.DangerousCommands) > 0 {
						lines = append(lines, fmt.Sprintf("⚠️  SUSPICIOUS: Dangerous commands detected: %s", strings.Join(f.DangerousCommands, ", ")))
						lines = append(lines, "⚠️  Possible crypto mining or malicious activity")
					}

					lines = append(lines, "\n# Investigation:")
					lines = append(lines, fmt.Sprintf("kubectl get pods -n %s -l job-name=%s", f.Namespace, f.Name))
					lines = append(lines, fmt.Sprintf("kubectl top pods -n %s -l job-name=%s", f.Namespace, f.Name))
					lines = append(lines, fmt.Sprintf("kubectl logs -n %s -l job-name=%s --tail=50", f.Namespace, f.Name))
					lines = append(lines, "")
				}
			}
		}
	}

	if !hasLongRunning {
		lines = append(lines, "\n# No long-running jobs detected (>1 hour)")
	}

	return lines
}
