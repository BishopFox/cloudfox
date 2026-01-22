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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var DeploymentsCmd = &cobra.Command{
	Use:     "deployments",
	Aliases: []string{"deploy"},
	Short:   "List all cluster deployments with security analysis",
	Long: `
List all cluster deployments with comprehensive security analysis including:
- Container escape vectors and privilege escalation paths
- Sensitive host path mounts and their security implications
- Dangerous Linux capabilities that enable container breakouts
- Risk-based scoring for prioritized security review
- Supply chain security (image tags, registries)
- Resource limit enforcement
  cloudfox kubernetes deployments`,
	Run: ListDeployments,
}

type DeploymentsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t DeploymentsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t DeploymentsOutput) LootFiles() []internal.LootFile   { return t.Loot }

type DeploymentFinding struct {
	Namespace           string
	Name                string
	Replicas            int32
	ServiceAccount      string
	Selectors           []string
	Images              []string
	ImageTagTypes       []string
	InitContainers      []string
	Containers          []DeploymentContainer
	ImagePullSecrets    []string
	Secrets             []string
	ConfigMaps          []string
	HostPID             bool
	HostIPC             bool
	HostNetwork         bool
	Privileged          bool
	RunAsUser           int
	AllowPrivEsc        bool
	ReadOnlyRootFS      bool
	Capabilities        []string
	DangerousCaps       []string
	HasResourceLimits   bool
	HostPaths           []string
	SensitiveHostPaths  []string
	WritableHostPaths   int
	Volumes             []DeploymentVolume
	Labels              map[string]string
	Affinity            string
	Tolerations         []string
	CloudProvider       string
	CloudRole           string
	DeploymentStrategy  string
	SecurityAnnotations map[string]string
	RiskLevel           string
	// Suspicious patterns
	BackdoorPatterns []string
	ReverseShells    []string
	CryptoMiners     []string
	DataExfiltration []string
	ContainerEscape  []string
	Commands         []string
	Args             []string
}

type DeploymentContainer struct {
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
	ResourceLimits string // Actual CPU/Memory limits
}

type DeploymentVolume struct {
	Name       string
	VolumeType string
	Source     string
	MountPath  string
	ReadOnly   bool
}

func ListDeployments(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating deployments for %s", globals.ClusterName), globals.K8S_DEPLOYMENTS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_DEPLOYMENTS_MODULE_NAME)

	// Table 1: Deployments Summary
	summaryHeaders := []string{
		"Namespace", "Name", "Labels", "Selectors", "Replicas", "Strategy",
		"Service Account", "Init Containers", "Image Pull Secrets",
		"Secrets", "ConfigMaps",
		"Security Context", "Suspicious Patterns", "Cloud IAM",
		"Affinity", "Tolerations",
	}

	// Table 2: Deployment-Containers Detail
	containerHeaders := []string{
		"Namespace", "Deployment", "Container", "Privileged", "Capabilities",
		"RunAsUser", "AllowPrivEsc", "ReadOnlyRootFS", "Resource Limits",
		"Image", "Tag", "Registry",
	}

	// Table 3: Deployment-Volumes Detail
	volumeHeaders := []string{
		"Namespace", "Deployment", "Volume Name", "Type", "Source Path/Name", "Container Mount Path", "Read Only",
	}

	var summaryRows [][]string
	var containerRows [][]string
	var volumeRows [][]string
	var findings []DeploymentFinding
	namespaceMap := make(map[string][]string)

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Loot collections
	var lootHighRisk []string
	var lootPrivEsc []string
	var lootSecretsAccess []string

	lootHighRisk = append(lootHighRisk, `#####################################
##### High-Risk Deployments
#####################################
#
# MANUAL REVIEW REQUIRED
# Deployments with CRITICAL or HIGH security risks
# Prioritize these for immediate remediation
#
`)

	lootPrivEsc = append(lootPrivEsc, `#####################################
##### Deployment Privilege Escalation
#####################################
#
# MANUAL EXECUTION REQUIRED
# Deployments with security misconfigurations
# that can be leveraged for privilege escalation
#
`)

	lootSecretsAccess = append(lootSecretsAccess, `#####################################
##### Secret and ConfigMap Access
#####################################
#
# MANUAL REVIEW REQUIRED
# Deployments with access to secrets and configmaps
# Review for credential exposure and sensitive data access
#
`)

	for _, ns := range namespaces {
		deployments, err := clientset.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error listing Deployments in namespace %s: %v", ns, err), globals.K8S_DEPLOYMENTS_MODULE_NAME)
			continue
		}

		for _, dep := range deployments.Items {
		finding := DeploymentFinding{
			Namespace: dep.Namespace,
			Name:      dep.Name,
			Labels:    dep.Spec.Template.Labels,
		}

		// Nil pointer safety for replicas
		if dep.Spec.Replicas != nil {
			finding.Replicas = *dep.Spec.Replicas
		}

		// Deployment strategy
		finding.DeploymentStrategy = string(dep.Spec.Strategy.Type)
		if dep.Spec.Strategy.RollingUpdate != nil {
			if dep.Spec.Strategy.RollingUpdate.MaxSurge != nil {
				finding.DeploymentStrategy += fmt.Sprintf(" (MaxSurge: %s)", dep.Spec.Strategy.RollingUpdate.MaxSurge.String())
			}
			if dep.Spec.Strategy.RollingUpdate.MaxUnavailable != nil {
				finding.DeploymentStrategy += fmt.Sprintf(" (MaxUnavailable: %s)", dep.Spec.Strategy.RollingUpdate.MaxUnavailable.String())
			}
		}

		// Service Account
		finding.ServiceAccount = dep.Spec.Template.Spec.ServiceAccountName

		// Selectors
		for k, v := range dep.Spec.Selector.MatchLabels {
			finding.Selectors = append(finding.Selectors, fmt.Sprintf("%s=%s", k, v))
		}

		// Security annotations
		finding.SecurityAnnotations = make(map[string]string)
		for k, v := range dep.Spec.Template.Annotations {
			if strings.Contains(k, "apparmor") || strings.Contains(k, "seccomp") || strings.Contains(k, "selinux") {
				finding.SecurityAnnotations[k] = v
			}
		}

		// Volume analysis
		var volumes []DeploymentVolume
		var hostPaths []string
		sensitiveHostPaths := []string{}
		hostPathCount := 0
		writableHostPaths := 0

		for _, v := range dep.Spec.Template.Spec.Volumes {
			volume := DeploymentVolume{
				Name: v.Name,
			}

			// Secret volumes
			if v.Secret != nil {
				finding.Secrets = append(finding.Secrets, v.Secret.SecretName)
				volume.VolumeType = "Secret"
				volume.Source = v.Secret.SecretName
			}

			// ConfigMap volumes
			if v.ConfigMap != nil {
				finding.ConfigMaps = append(finding.ConfigMaps, v.ConfigMap.Name)
				volume.VolumeType = "ConfigMap"
				volume.Source = v.ConfigMap.Name
			}

			// HostPath analysis
			if v.HostPath != nil {
				hostPathCount++
				volume.VolumeType = "HostPath"
				volume.Source = v.HostPath.Path
				hostPaths = append(hostPaths, v.HostPath.Path)
			}

			// Other volume types
			if v.EmptyDir != nil {
				volume.VolumeType = "EmptyDir"
				volume.Source = "-"
			}
			if v.PersistentVolumeClaim != nil {
				volume.VolumeType = "PVC"
				volume.Source = v.PersistentVolumeClaim.ClaimName
			}
			if v.Projected != nil {
				volume.VolumeType = "Projected"
				volume.Source = "-"
			}
			if v.DownwardAPI != nil {
				volume.VolumeType = "DownwardAPI"
				volume.Source = "-"
			}
			if volume.VolumeType == "" {
				volume.VolumeType = "Other"
				volume.Source = "-"
			}

			// Find mount path and read-only status
			for _, container := range append(dep.Spec.Template.Spec.InitContainers, dep.Spec.Template.Spec.Containers...) {
				for _, vm := range container.VolumeMounts {
					if vm.Name == v.Name {
						volume.MountPath = vm.MountPath
						volume.ReadOnly = vm.ReadOnly
						break
					}
				}
			}

			// Track writable host paths
			if v.HostPath != nil && !volume.ReadOnly {
				writableHostPaths++
				// Analyze host path sensitivity
				isSensitive, description := k8sinternal.AnalyzeHostPath(v.HostPath.Path, volume.ReadOnly)
				if isSensitive {
					sensitiveHostPaths = append(sensitiveHostPaths, fmt.Sprintf("%s - %s", v.HostPath.Path, description))
				}
			}

			volumes = append(volumes, volume)
		}
		finding.Volumes = volumes
		finding.HostPaths = hostPaths
		finding.SensitiveHostPaths = sensitiveHostPaths
		finding.WritableHostPaths = writableHostPaths

		// Container analysis (including init containers)
		privileged := false
		runAsUser := -1 // -1 means unset
		allowPrivEsc := false
		readOnlyRootFS := false
		hasResourceLimits := false
		hasImageWithLatestTag := false
		var capabilities []string
		var dangerousCaps []string
		var containers []DeploymentContainer
		var allCommands []string
		var allArgs []string

		allK8sContainers := append(dep.Spec.Template.Spec.InitContainers, dep.Spec.Template.Spec.Containers...)

		// Init containers
		for _, c := range dep.Spec.Template.Spec.InitContainers {
			finding.InitContainers = append(finding.InitContainers, c.Name)
		}

		// Analyze all containers (init + regular)
		for _, c := range allK8sContainers {
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

			// Image info
			finding.Images = append(finding.Images, c.Image)
			tagType := k8sinternal.ImageTagType(c.Image)
			finding.ImageTagTypes = append(finding.ImageTagTypes, tagType)
			if tagType == "latest" || !strings.Contains(c.Image, ":") {
				hasImageWithLatestTag = true
			}

			// Resource limits
			if c.Resources.Limits != nil && len(c.Resources.Limits) > 0 {
				hasResourceLimits = true
			}

			// Security context analysis - per container
			containerPrivileged := false
			var containerCaps []string
			if c.SecurityContext != nil {
				// Privileged
				if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					containerPrivileged = true
					privileged = true
				}

				// RunAsUser
				if c.SecurityContext.RunAsUser != nil {
					runAsUser = int(*c.SecurityContext.RunAsUser)
				}

				// AllowPrivilegeEscalation
				if c.SecurityContext.AllowPrivilegeEscalation != nil {
					if *c.SecurityContext.AllowPrivilegeEscalation {
						allowPrivEsc = true
					}
				} else {
					// Default is true if not specified
					allowPrivEsc = true
				}

				// ReadOnlyRootFilesystem
				if c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem {
					readOnlyRootFS = true
				}

				// Capabilities
				if c.SecurityContext.Capabilities != nil {
					for _, cap := range c.SecurityContext.Capabilities.Add {
						capStr := string(cap)
						containerCaps = append(containerCaps, capStr)
						capabilities = append(capabilities, capStr)
						if k8sinternal.IsDangerousCapability(capStr) {
							dangerousCaps = append(dangerousCaps, capStr)
						}
					}
					for _, cap := range c.SecurityContext.Capabilities.Drop {
						capabilities = append(capabilities, "-"+string(cap))
					}
				}
			}

			// Collect commands and args for suspicious pattern detection
			allCommands = append(allCommands, c.Command...)
			allArgs = append(allArgs, c.Args...)

			// Per-container security context values for table output
			containerRunAsUser := "-"
			containerAllowPrivEsc := "true" // default is true if not specified
			containerReadOnlyRootFS := "false"
			containerResourceLimits := "-"

			if c.SecurityContext != nil {
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

			// Build actual resource limits string (CPU/Memory)
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

			container := DeploymentContainer{
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
		}

		finding.Containers = containers
		finding.Commands = allCommands
		finding.Args = allArgs

		finding.Privileged = privileged
		finding.RunAsUser = runAsUser
		finding.AllowPrivEsc = allowPrivEsc
		finding.ReadOnlyRootFS = readOnlyRootFS
		finding.Capabilities = k8sinternal.UniqueStrings(capabilities)
		finding.DangerousCaps = k8sinternal.UniqueStrings(dangerousCaps)
		finding.HasResourceLimits = hasResourceLimits
		finding.HostPID = dep.Spec.Template.Spec.HostPID
		finding.HostIPC = dep.Spec.Template.Spec.HostIPC
		finding.HostNetwork = dep.Spec.Template.Spec.HostNetwork

		// Image Pull Secrets
		for _, ps := range dep.Spec.Template.Spec.ImagePullSecrets {
			finding.ImagePullSecrets = append(finding.ImagePullSecrets, ps.Name)
		}

		// Affinity / Tolerations
		if dep.Spec.Template.Spec.Affinity != nil {
			finding.Affinity = k8sinternal.PrettyPrintAffinity(dep.Spec.Template.Spec.Affinity)
		}
		if len(dep.Spec.Template.Spec.Tolerations) > 0 {
			for _, t := range dep.Spec.Template.Spec.Tolerations {
				// Build full toleration string: key=value:effect (operator)
				tolStr := ""
				if t.Key != "" {
					tolStr = t.Key
					if t.Value != "" {
						tolStr += "=" + t.Value
					}
				} else {
					tolStr = "*" // matches all keys
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
		}

		// Cloud Role detection
		roleResults := k8sinternal.DetectCloudRole(
			ctx,
			clientset,
			dep.Namespace,
			dep.Spec.Template.Spec.ServiceAccountName,
			&dep.Spec.Template.Spec,
			dep.Spec.Template.Annotations,
		)
		if len(roleResults) > 0 {
			finding.CloudProvider = roleResults[0].Provider
			finding.CloudRole = roleResults[0].Role
		}

		// Suspicious pattern detection
		finding.ReverseShells = shared.DetectReverseShells(allCommands, allArgs)
		finding.CryptoMiners = shared.DetectCryptoMiners(allCommands, allArgs, finding.Images)
		finding.DataExfiltration = shared.DetectDataExfiltration(allCommands, allArgs)
		finding.ContainerEscape = shared.DetectContainerEscape(allCommands, allArgs, hostPaths)

		// Combine all backdoor patterns
		finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ReverseShells...)
		finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.CryptoMiners...)
		finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.DataExfiltration...)
		finding.BackdoorPatterns = append(finding.BackdoorPatterns, finding.ContainerEscape...)

		// Calculate risk level
		runAsRoot := (runAsUser == 0 || runAsUser == -1)
		hasDangerousCaps := len(dangerousCaps) > 0
		finding.RiskLevel = k8sinternal.GetDeploymentRiskLevel(
			privileged,
			dep.Spec.Template.Spec.HostPID,
			dep.Spec.Template.Spec.HostIPC,
			dep.Spec.Template.Spec.HostNetwork,
			hostPathCount,
			writableHostPaths,
			runAsRoot,
			hasDangerousCaps,
			allowPrivEsc,
			hasImageWithLatestTag,
			hasResourceLimits,
		)

		riskCounts[finding.RiskLevel]++
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

		// Format labels for display
		var labelParts []string
		for k, v := range finding.Labels {
			labelParts = append(labelParts, fmt.Sprintf("%s=%s", k, v))
		}
		labelsStr := strings.Join(labelParts, ", ")

		// Format selectors for display
		selectorsStr := strings.Join(finding.Selectors, ", ")

		// Format init containers for display
		initContainersStr := strings.Join(finding.InitContainers, ", ")

		// Format image pull secrets for display
		imagePullSecretsStr := strings.Join(finding.ImagePullSecrets, ", ")

		// Format secrets for display
		secretsStr := strings.Join(finding.Secrets, ", ")

		// Format configmaps for display
		configMapsStr := strings.Join(finding.ConfigMaps, ", ")

		// Format tolerations for display
		tolerationsStr := strings.Join(finding.Tolerations, ", ")

		// Table 1: Summary row
		summaryRow := []string{
			finding.Namespace,
			finding.Name,
			k8sinternal.NonEmpty(labelsStr),
			k8sinternal.NonEmpty(selectorsStr),
			fmt.Sprintf("%d", finding.Replicas),
			finding.DeploymentStrategy,
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

		// Loot: Basic enumerate command
		jq := `'{Namespace:.metadata.namespace,
Name:.metadata.name,
Replicas:.spec.replicas,
ServiceAccount:.spec.template.spec.serviceAccountName,
Selectors:(.spec.selector.matchLabels // {}),
Images:([.spec.template.spec.containers[]?.image]),
InitContainers:([.spec.template.spec.initContainers[]?.name]),
Containers:([.spec.template.spec.containers[]?.name]),
Volumes:(.spec.template.spec.volumes // [] | map(.name)),
Secrets:([.spec.template.spec.volumes[]? | select(.secret) | .secret.secretName]),
ConfigMaps:([.spec.template.spec.volumes[]? | select(.configMap) | .configMap.name]),
ImagePullSecrets:(.spec.template.spec.imagePullSecrets // [] | map(.name)),
HostPID:(.spec.template.spec.hostPID // false),
HostIPC:(.spec.template.spec.hostIPC // false),
HostNetwork:(.spec.template.spec.hostNetwork // false),
Privileged:([.spec.template.spec.containers[]? | .securityContext?.privileged // false] | any),
HostPaths:([.spec.template.spec.volumes[]? | select(.hostPath) | {path:.hostPath.path}]),
RunAsUser:([.spec.template.spec.containers[]? | .securityContext?.runAsUser // empty] | map(select(. != null)) | unique),
Capabilities:([.spec.template.spec.containers[]? | .securityContext?.capabilities?.add // []] | add // []),
Affinity:(.spec.template.spec.affinity // {}),
Tolerations:(.spec.template.spec.tolerations // []),
Strategy:.spec.strategy.type}'`
		cmdStr := fmt.Sprintf("kubectl get deployment %q -n %q -o json | jq -r %s \n", dep.Name, dep.Namespace, jq)
		namespaceMap[dep.Namespace] = append(namespaceMap[dep.Namespace], cmdStr)

		// Generate detailed loot based on risk level
		depID := fmt.Sprintf("%s/%s", dep.Namespace, dep.Name)

		// HIGH RISK LOOT
		if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
			lootHighRisk = append(lootHighRisk, fmt.Sprintf("\n### [%s] %s", finding.RiskLevel, depID))

			var riskFactors []string
			if privileged {
				riskFactors = append(riskFactors, "PRIVILEGED")
			}
			if dep.Spec.Template.Spec.HostPID {
				riskFactors = append(riskFactors, "HOSTPID")
			}
			if dep.Spec.Template.Spec.HostIPC {
				riskFactors = append(riskFactors, "HOSTIPC")
			}
			if dep.Spec.Template.Spec.HostNetwork {
				riskFactors = append(riskFactors, "HOSTNETWORK")
			}
			if writableHostPaths > 0 {
				riskFactors = append(riskFactors, fmt.Sprintf("WRITABLE_HOSTPATHS:%d", writableHostPaths))
			}
			if len(dangerousCaps) > 0 {
				riskFactors = append(riskFactors, fmt.Sprintf("DANGEROUS_CAPS:%s", strings.Join(dangerousCaps, ",")))
			}
			if hasImageWithLatestTag {
				riskFactors = append(riskFactors, "LATEST_TAG")
			}
			if !hasResourceLimits {
				riskFactors = append(riskFactors, "NO_RESOURCE_LIMITS")
			}

			lootHighRisk = append(lootHighRisk, fmt.Sprintf("# Risk Factors: %s", strings.Join(riskFactors, ", ")))
			lootHighRisk = append(lootHighRisk, fmt.Sprintf("# Replicas: %d (multiply exposure by replica count)", finding.Replicas))
			lootHighRisk = append(lootHighRisk, fmt.Sprintf("kubectl get deployment -n %s %s -o yaml", dep.Namespace, dep.Name))
			lootHighRisk = append(lootHighRisk, "# Scale down to investigate:")
			lootHighRisk = append(lootHighRisk, fmt.Sprintf("kubectl scale deployment -n %s %s --replicas=0\n", dep.Namespace, dep.Name))
		}

		// PRIVILEGE ESCALATION LOOT
		if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
			lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("\n### [%s] %s", finding.RiskLevel, depID))

			if privileged && (dep.Spec.Template.Spec.HostPID || dep.Spec.Template.Spec.HostNetwork || dep.Spec.Template.Spec.HostIPC) {
				lootPrivEsc = append(lootPrivEsc, "# CRITICAL: Privileged + Host Namespaces = Container Escape")
				lootPrivEsc = append(lootPrivEsc, "# Pods from this deployment can escape to host")
				lootPrivEsc = append(lootPrivEsc, "# Get pods:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl get pods -n %s -l %s", dep.Namespace, strings.Join(finding.Selectors, ",")))
				lootPrivEsc = append(lootPrivEsc, "# Exec into pod:")
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("POD=$(kubectl get pods -n %s -l %s -o jsonpath='{.items[0].metadata.name}')", dep.Namespace, strings.Join(finding.Selectors, ",")))
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("kubectl exec -it -n %s $POD -- sh", dep.Namespace))
				lootPrivEsc = append(lootPrivEsc, "# Escape to host:")
				lootPrivEsc = append(lootPrivEsc, "nsenter --target 1 --mount --uts --ipc --net --pid -- bash\n")
			}

			if len(sensitiveHostPaths) > 0 {
				lootPrivEsc = append(lootPrivEsc, "# Sensitive Host Paths Mounted:")
				for _, shp := range sensitiveHostPaths {
					lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# - %s", shp))
				}
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Check running pods: kubectl get pods -n %s -l %s\n", dep.Namespace, strings.Join(finding.Selectors, ",")))
			}

			if len(dangerousCaps) > 0 {
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Dangerous Capabilities: %s", strings.Join(dangerousCaps, ", ")))
				lootPrivEsc = append(lootPrivEsc, "# These capabilities can be exploited for privilege escalation\n")
			}

			if finding.CloudProvider != "" && finding.CloudRole != "" {
				lootPrivEsc = append(lootPrivEsc, fmt.Sprintf("# Cloud Role: %s (%s)", finding.CloudRole, finding.CloudProvider))
				lootPrivEsc = append(lootPrivEsc, "# Pods can assume this cloud role for lateral movement\n")
			}
		}

		// SECRETS ACCESS LOOT
		if len(finding.Secrets) > 0 || len(finding.ConfigMaps) > 0 {
			lootSecretsAccess = append(lootSecretsAccess, fmt.Sprintf("\n### [%s] %s", finding.RiskLevel, depID))

			if len(finding.Secrets) > 0 {
				lootSecretsAccess = append(lootSecretsAccess, fmt.Sprintf("# Secrets: %s", strings.Join(finding.Secrets, ", ")))
				for _, secret := range finding.Secrets {
					lootSecretsAccess = append(lootSecretsAccess, fmt.Sprintf("kubectl get secret -n %s %s -o yaml", dep.Namespace, secret))
				}
			}

			if len(finding.ConfigMaps) > 0 {
				lootSecretsAccess = append(lootSecretsAccess, fmt.Sprintf("# ConfigMaps: %s", strings.Join(finding.ConfigMaps, ", ")))
				for _, cm := range finding.ConfigMaps {
					lootSecretsAccess = append(lootSecretsAccess, fmt.Sprintf("kubectl get configmap -n %s %s -o yaml", dep.Namespace, cm))
				}
			}

			lootSecretsAccess = append(lootSecretsAccess, "# Extract from running pod:")
			lootSecretsAccess = append(lootSecretsAccess, fmt.Sprintf("POD=$(kubectl get pods -n %s -l %s -o jsonpath='{.items[0].metadata.name}')", dep.Namespace, strings.Join(finding.Selectors, ",")))
			lootSecretsAccess = append(lootSecretsAccess, fmt.Sprintf("kubectl exec -n %s $POD -- env | grep -i secret\n", dep.Namespace))
		}
		}
	}

	// Build consolidated Deployment-Commands
	var lootContent []string
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "##### Deployment Commands")
	lootContent = append(lootContent, "########################################")
	lootContent = append(lootContent, "")

	if globals.KubeContext != "" {
		lootContent = append(lootContent, fmt.Sprintf("kubectl config use-context %s", globals.KubeContext))
		lootContent = append(lootContent, "")
	}

	// === ENUMERATION ===
	lootContent = append(lootContent, "=== ENUMERATION ===")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# List all deployments")
	lootContent = append(lootContent, "kubectl get deployments -A -o wide")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find privileged deployments")
	lootContent = append(lootContent, "kubectl get deployments -A -o json | jq -r '.items[] | select(.spec.template.spec.containers[]?.securityContext?.privileged == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find deployments with hostPID/hostIPC/hostNetwork")
	lootContent = append(lootContent, "kubectl get deployments -A -o json | jq -r '.items[] | select(.spec.template.spec.hostPID == true or .spec.template.spec.hostIPC == true or .spec.template.spec.hostNetwork == true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")
	lootContent = append(lootContent, "# Find deployments with hostPath volumes")
	lootContent = append(lootContent, "kubectl get deployments -A -o json | jq -r '.items[] | select(.spec.template.spec.volumes[]?.hostPath != null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")
	lootContent = append(lootContent, "")

	var sortedNamespaces []string
	for ns := range namespaceMap {
		sortedNamespaces = append(sortedNamespaces, ns)
	}
	sort.Strings(sortedNamespaces)

	for _, ns := range sortedNamespaces {
		lootContent = append(lootContent, fmt.Sprintf("# Namespace: %s", ns))
		lootContent = append(lootContent, namespaceMap[ns]...)
		lootContent = append(lootContent, "")
	}

	// === HIGH RISK ===
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		lootContent = append(lootContent, "=== HIGH RISK ===")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, fmt.Sprintf("# Risk Distribution: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]))
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, lootHighRisk...)
	}

	// === PRIVILEGE ESCALATION ===
	if len(lootPrivEsc) > 0 {
		lootContent = append(lootContent, "=== PRIVILEGE ESCALATION ===")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, lootPrivEsc...)
	}

	// === SECRETS ACCESS ===
	if len(lootSecretsAccess) > 0 {
		lootContent = append(lootContent, "=== SECRETS ACCESS ===")
		lootContent = append(lootContent, "")
		lootContent = append(lootContent, lootSecretsAccess...)
	}

	// Build Deployment-Entrypoints
	var entrypointsContent []string
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "##### Deployment Container Entrypoints")
	entrypointsContent = append(entrypointsContent, "########################################")
	entrypointsContent = append(entrypointsContent, "# Only containers with commands or args are shown")
	entrypointsContent = append(entrypointsContent, "")

	// Sort findings by namespace/name
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Namespace != findings[j].Namespace {
			return findings[i].Namespace < findings[j].Namespace
		}
		return findings[i].Name < findings[j].Name
	})

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

	// Create all three tables
	summaryTable := internal.TableFile{Name: "Deployments", Header: summaryHeaders, Body: summaryRows}
	containerTable := internal.TableFile{Name: "Deployment-Containers", Header: containerHeaders, Body: containerRows}
	volumeTable := internal.TableFile{Name: "Deployment-Volumes", Header: volumeHeaders, Body: volumeRows}

	lootFiles := []internal.LootFile{
		{Name: "Deployment-Commands", Contents: strings.Join(lootContent, "\n")},
		{Name: "Deployment-Entrypoints", Contents: strings.Join(entrypointsContent, "\n")},
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"Deployments",
		globals.ClusterName,
		"results",
		DeploymentsOutput{
			Table: []internal.TableFile{summaryTable, containerTable, volumeTable},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_DEPLOYMENTS_MODULE_NAME)
		return
	}

	if len(summaryRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d deployments found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(summaryRows),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_DEPLOYMENTS_MODULE_NAME)
	} else {
		logger.InfoM("No deployments found, skipping output file creation", globals.K8S_DEPLOYMENTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DEPLOYMENTS_MODULE_NAME), globals.K8S_DEPLOYMENTS_MODULE_NAME)
}
