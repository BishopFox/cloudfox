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
	Namespace              string
	Name                   string
	Replicas               int32
	ServiceAccount         string
	Selectors              []string
	Images                 []string
	ImageTagTypes          []string
	InitContainers         []string
	Containers             []string
	ImagePullSecrets       []string
	Secrets                []string
	ConfigMaps             []string
	HostPID                bool
	HostIPC                bool
	HostNetwork            bool
	Privileged             bool
	RunAsUser              int
	AllowPrivEsc           bool
	ReadOnlyRootFS         bool
	Capabilities           []string
	DangerousCaps          []string
	HasResourceLimits      bool
	HostPaths              []string
	SensitiveHostPaths     []string
	WritableHostPaths      int
	Labels                 map[string]string
	Affinity               string
	Tolerations            []string
	CloudProvider          string
	CloudRole              string
	DeploymentStrategy     string
	SecurityAnnotations    map[string]string
	RiskLevel              string
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

	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing Deployments: %v", err), globals.K8S_DEPLOYMENTS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk", "Namespace", "Deployment Name", "Replicas", "Images", "ImageTagTypes",
		"ServiceAccount", "Selectors", "Volumes", "Secrets", "ConfigMaps",
		"Containers", "InitContainers", "ImagePullSecrets",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "RunAsUser",
		"AllowPrivEsc", "ReadOnlyRootFS", "Capabilities", "ResourceLimits",
		"HostPaths", "Labels", "Affinity", "Tolerations", "Strategy",
		"Cloud Provider", "Cloud Role",
	}

	var outputRows [][]string
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
		var volumes []string
		hostPaths := []string{}
		sensitiveHostPaths := []string{}
		hostPathCount := 0
		writableHostPaths := 0

		for _, v := range dep.Spec.Template.Spec.Volumes {
			volumes = append(volumes, v.Name)

			// Secret volumes
			if v.Secret != nil {
				finding.Secrets = append(finding.Secrets, v.Secret.SecretName)
			}

			// ConfigMap volumes
			if v.ConfigMap != nil {
				finding.ConfigMaps = append(finding.ConfigMaps, v.ConfigMap.Name)
			}

			// HostPath analysis
			if v.HostPath != nil {
				hostPathCount++
				mountPoint := k8sinternal.FindMountPath(v.Name, dep.Spec.Template.Spec.Containers)

				// Determine if readonly
				readOnly := false
				for _, container := range append(dep.Spec.Template.Spec.InitContainers, dep.Spec.Template.Spec.Containers...) {
					for _, vm := range container.VolumeMounts {
						if vm.Name == v.Name {
							readOnly = vm.ReadOnly
							break
						}
					}
				}

				if !readOnly {
					writableHostPaths++
				}

				// Analyze host path sensitivity
				isSensitive, description := k8sinternal.AnalyzeHostPath(v.HostPath.Path, readOnly)

				hostPathLine := fmt.Sprintf("%s:%s", v.HostPath.Path, mountPoint)
				if readOnly {
					hostPathLine += " (ro)"
				} else {
					hostPathLine += " (rw)"
				}

				if isSensitive {
					hostPathLine += fmt.Sprintf(" - %s", description)
					sensitiveHostPaths = append(sensitiveHostPaths, fmt.Sprintf("%s - %s", v.HostPath.Path, description))
				}

				hostPaths = append(hostPaths, hostPathLine)
			}
		}
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

		allContainers := append(dep.Spec.Template.Spec.InitContainers, dep.Spec.Template.Spec.Containers...)

		// Init containers
		for _, c := range dep.Spec.Template.Spec.InitContainers {
			finding.InitContainers = append(finding.InitContainers, c.Name)
		}

		// Regular containers
		for _, c := range dep.Spec.Template.Spec.Containers {
			finding.Containers = append(finding.Containers, c.Name)
		}

		// Analyze all containers (init + regular)
		for _, container := range allContainers {
			// Image info
			finding.Images = append(finding.Images, container.Image)
			tagType := k8sinternal.ImageTagType(container.Image)
			finding.ImageTagTypes = append(finding.ImageTagTypes, tagType)
			if tagType == "latest" || !strings.Contains(container.Image, ":") {
				hasImageWithLatestTag = true
			}

			// Resource limits
			if container.Resources.Limits != nil && len(container.Resources.Limits) > 0 {
				hasResourceLimits = true
			}

			// Security context analysis
			if container.SecurityContext != nil {
				// Privileged
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					privileged = true
				}

				// RunAsUser
				if container.SecurityContext.RunAsUser != nil {
					runAsUser = int(*container.SecurityContext.RunAsUser)
				}

				// AllowPrivilegeEscalation
				if container.SecurityContext.AllowPrivilegeEscalation != nil {
					if *container.SecurityContext.AllowPrivilegeEscalation {
						allowPrivEsc = true
					}
				} else {
					// Default is true if not specified
					allowPrivEsc = true
				}

				// ReadOnlyRootFilesystem
				if container.SecurityContext.ReadOnlyRootFilesystem != nil && *container.SecurityContext.ReadOnlyRootFilesystem {
					readOnlyRootFS = true
				}

				// Capabilities
				if container.SecurityContext.Capabilities != nil {
					for _, cap := range container.SecurityContext.Capabilities.Add {
						capStr := string(cap)
						capabilities = append(capabilities, capStr)
						if k8sinternal.IsDangerousCapability(capStr) {
							dangerousCaps = append(dangerousCaps, capStr)
						}
					}
					for _, cap := range container.SecurityContext.Capabilities.Drop {
						capabilities = append(capabilities, "-"+string(cap))
					}
				}
			}
		}

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
				finding.Tolerations = append(finding.Tolerations, fmt.Sprintf("%s:%s", t.Key, t.Operator))
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

		// Build table row
		runAsUserStr := "<unset>"
		if runAsUser == 0 {
			runAsUserStr = "root"
		} else if runAsUser > 0 {
			runAsUserStr = fmt.Sprintf("%d", runAsUser)
		}

		hostPathsStr := "<NONE>"
		if len(hostPaths) > 0 {
			hostPathsStr = strings.Join(hostPaths, "\n")
		}

		labelsStr := "<NONE>"
		if len(finding.Labels) > 0 {
			var parts []string
			for k, v := range finding.Labels {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			sort.Strings(parts)
			labelsStr = strings.Join(parts, ",")
		}

		affinityStr := "<NONE>"
		if finding.Affinity != "" {
			affinityStr = finding.Affinity
		}

		row := []string{
			finding.RiskLevel,
			dep.Namespace,
			dep.Name,
			fmt.Sprintf("%d", finding.Replicas),
			k8sinternal.NonEmpty(strings.Join(finding.Images, ",")),
			k8sinternal.NonEmpty(strings.Join(finding.ImageTagTypes, ",")),
			k8sinternal.NonEmpty(finding.ServiceAccount),
			k8sinternal.NonEmpty(strings.Join(finding.Selectors, ",")),
			k8sinternal.NonEmpty(strings.Join(volumes, ",")),
			k8sinternal.NonEmpty(strings.Join(finding.Secrets, ",")),
			k8sinternal.NonEmpty(strings.Join(finding.ConfigMaps, ",")),
			k8sinternal.NonEmpty(strings.Join(finding.Containers, ",")),
			k8sinternal.NonEmpty(strings.Join(finding.InitContainers, ",")),
			k8sinternal.NonEmpty(strings.Join(finding.ImagePullSecrets, ",")),
			k8sinternal.SafeBool(dep.Spec.Template.Spec.HostPID),
			k8sinternal.SafeBool(dep.Spec.Template.Spec.HostIPC),
			k8sinternal.SafeBool(dep.Spec.Template.Spec.HostNetwork),
			fmt.Sprintf("%v", privileged),
			runAsUserStr,
			fmt.Sprintf("%v", allowPrivEsc),
			fmt.Sprintf("%v", readOnlyRootFS),
			k8sinternal.NonEmpty(strings.Join(finding.Capabilities, ",")),
			fmt.Sprintf("%v", hasResourceLimits),
			hostPathsStr,
			labelsStr,
			affinityStr,
			k8sinternal.NonEmpty(strings.Join(finding.Tolerations, ",")),
			finding.DeploymentStrategy,
			k8sinternal.NonEmpty(finding.CloudProvider),
			k8sinternal.NonEmpty(finding.CloudRole),
		}
		outputRows = append(outputRows, row)

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

	// Build lootEnum with namespace separators
	lootEnum := []string{
		"#####################################",
		"##### Enumerate Deployment Information",
		"#####################################",
		"",
	}
	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	var namespaces []string
	for ns := range namespaceMap {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	for i, ns := range namespaces {
		lootEnum = append(lootEnum, fmt.Sprintf("\n# Namespace: %s\n", ns))
		lootEnum = append(lootEnum, namespaceMap[ns]...)
		if i < len(namespaces)-1 {
			lootEnum = append(lootEnum, "")
		}
	}

	// Add summaries to loot files
	if riskCounts["CRITICAL"] > 0 || riskCounts["HIGH"] > 0 {
		summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d deployments
# HIGH: %d deployments
# MEDIUM: %d deployments
# LOW: %d deployments
#
# Focus on CRITICAL and HIGH risk deployments first for maximum impact.
# Each deployment may have multiple replicas, multiplying the attack surface.
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

		lootHighRisk = append([]string{summary}, lootHighRisk...)
		lootPrivEsc = append([]string{summary}, lootPrivEsc...)
	}

	table := internal.TableFile{
		Name:   "Deployments",
		Header: headers,
		Body:   outputRows,
	}

	lootEnumFile := internal.LootFile{
		Name:     "Deployment-Enum",
		Contents: strings.Join(lootEnum, "\n"),
	}

	lootHighRiskFile := internal.LootFile{
		Name:     "Deployment-High-Risk",
		Contents: strings.Join(lootHighRisk, "\n"),
	}

	lootPrivEscFile := internal.LootFile{
		Name:     "Deployment-Privilege-Escalation",
		Contents: strings.Join(lootPrivEsc, "\n"),
	}

	lootSecretsFile := internal.LootFile{
		Name:     "Deployment-Secrets-Access",
		Contents: strings.Join(lootSecretsAccess, "\n"),
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
			Table: []internal.TableFile{table},
			Loot:  []internal.LootFile{lootEnumFile, lootHighRiskFile, lootPrivEscFile, lootSecretsFile},
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_DEPLOYMENTS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d deployments found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_DEPLOYMENTS_MODULE_NAME)
	} else {
		logger.InfoM("No deployments found, skipping output file creation", globals.K8S_DEPLOYMENTS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_DEPLOYMENTS_MODULE_NAME), globals.K8S_DEPLOYMENTS_MODULE_NAME)
}
