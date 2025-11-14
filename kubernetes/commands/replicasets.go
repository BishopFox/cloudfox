package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ReplicaSetsCmd = &cobra.Command{
	Use:     "replicasets",
	Aliases: []string{"rs"},
	Short:   "List all cluster ReplicaSets with security analysis",
	Long: `
List all cluster ReplicaSets with comprehensive security analysis including:
- Pod template security analysis (SELinux, AppArmor, Seccomp)
- PSS compliance checking on templates
- Secret and ConfigMap exposure in templates
- Image security analysis and vulnerability indicators
- Resource abuse detection and DoS potential
- Deployment ownership and orphaned ReplicaSet detection
- Blast radius calculation (vulnerabilities × replica count)
- Risk-based scoring for prioritized security review
  cloudfox kubernetes replicasets`,
	Run: ListReplicaSets,
}

type ReplicaSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t ReplicaSetsOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t ReplicaSetsOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type ReplicaSetFinding struct {
	// Basic Info
	Namespace      string
	Name           string
	DeploymentName string
	IsOrphaned     bool
	IsSuperseded   bool
	Age            string

	// Replica Analysis
	DesiredReplicas   int32
	CurrentReplicas   int32
	ReadyReplicas     int32
	AvailableReplicas int32
	ReplicaCount      int32
	HighReplicaCount  bool

	// Security Analysis
	RiskLevel      string
	RiskScore      int
	BlastRadius    int
	SecurityIssues []string

	// Pod Template Security Context
	Privileged             bool
	HostPID                bool
	HostIPC                bool
	HostNetwork            bool
	RunAsRoot              bool
	AllowPrivEsc           bool
	ReadOnlyRootFilesystem bool
	ProcMountUnmasked      bool
	SELinuxContext         string
	SELinuxCustom          bool
	AppArmorProfile        string
	AppArmorUndefined      bool
	SeccompProfile         string
	SeccompUnconfined      bool
	FSGroup                string
	SupplementalGroups     []string

	// Capabilities
	Capabilities   []string
	DangerousCaps  []string
	DroppedAllCaps bool

	// Host Path Mounts
	HostPaths          []string
	SensitiveHostPaths []string
	WritableHostPaths  int

	// Secret & ConfigMap Exposure
	SecretVolumes       []string
	SecretEnvVars       []string
	ConfigMapVolumes    []string
	ConfigMapEnvVars    []string
	ProjectedVolumes    []string
	TotalSecretsExposed int

	// Service Account Token
	ServiceAccount   string
	AutomountSAToken bool
	SATokenProjected bool

	// Image Security
	Images          []string
	ImageTagTypes   []string
	ImagePullPolicy []string
	ImageDigests    []string
	ImageRegistries []string
	LatestTag       bool
	UnverifiedImage bool

	// Resource Management
	ResourceLimits   []string
	ResourceRequests []string
	NoLimits         bool
	NoRequests       bool
	QoSClass         string

	// Init Containers
	InitContainers int

	// PSS Compliance
	PSSCompliance        string
	PSSViolations        []string
	RestrictedViolations int
	BaselineViolations   int

	// Metadata
	Labels      map[string]string
	Selectors   map[string]string
	Tolerations []string
	Annotations map[string]string

	// Cloud
	CloudProvider string
	CloudRole     string

	// Impact Analysis
	ImpactSummary string
}

func ListReplicaSets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating replicasets for %s", globals.ClusterName), globals.K8S_REPLICASETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	replicaSets, err := clientset.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing ReplicaSets: %v", err), globals.K8S_REPLICASETS_MODULE_NAME)
		return
	}

	headers := []string{
		"Risk", "Blast Radius", "Namespace", "ReplicaSet Name", "Deployment", "Is Orphaned",
		"Replicas (Desired/Current/Ready)", "Service Account",
		"HostPID", "HostIPC", "HostNetwork", "Privileged", "RunAsRoot",
		"AllowPrivEsc", "ReadOnlyRootFS", "SELinux", "AppArmor", "Seccomp",
		"Capabilities", "Dangerous Caps", "HostPaths", "Sensitive HostPaths",
		"Secret Volumes", "Secret EnvVars", "Image Tags", "Latest Tags",
		"Resource Limits", "Resource Requests", "PSS Compliance", "PSS Violations",
		"Security Issues", "Impact Summary",
	}

	var outputRows [][]string
	var findings []ReplicaSetFinding

	// Risk level counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Loot content builders
	var lootEnum []string
	var lootHighRisk []string
	var lootPSSViolations []string
	var lootOrphaned []string
	var lootSecretExposure []string
	var lootImageVulns []string
	var lootResourceAbuse []string
	var lootAttackSurface []string
	var lootRemediation []string

	// Initialize loot headers
	lootEnum = append(lootEnum, `#####################################
##### Enumerate ReplicaSet Information
#####################################
#
# ANALYSIS REPORT
# Detailed ReplicaSet enumeration commands
#
`)

	lootHighRisk = append(lootHighRisk, `#####################################
##### High Risk ReplicaSets
#####################################
#
# MANUAL REVIEW REQUIRED
# ReplicaSets with CRITICAL or HIGH risk pod templates
# Each ReplicaSet will create multiple pods with these vulnerabilities
#
`)

	lootPSSViolations = append(lootPSSViolations, `#####################################
##### PSS Violations in Pod Templates
#####################################
#
# ANALYSIS REPORT
# ReplicaSets with pod templates violating PSS baseline and restricted levels
# Fix the template to prevent creating non-compliant pods
#
`)

	lootOrphaned = append(lootOrphaned, `#####################################
##### Orphaned ReplicaSets
#####################################
#
# ANALYSIS REPORT
# ReplicaSets without Deployment ownership
# May indicate manual creation or attacker persistence
#
`)

	lootSecretExposure = append(lootSecretExposure, `#####################################
##### Secret Exposure in Templates
#####################################
#
# ANALYSIS REPORT
# ReplicaSets with secrets/configmaps in pod templates
# Each replica will expose these secrets
#
`)

	lootImageVulns = append(lootImageVulns, `#####################################
##### Image Vulnerabilities in Templates
#####################################
#
# ANALYSIS REPORT
# ReplicaSets using risky images (latest tags, unverified)
# Each replica will use these vulnerable images
#
`)

	lootResourceAbuse = append(lootResourceAbuse, `#####################################
##### Resource Abuse Potential
#####################################
#
# ANALYSIS REPORT
# ReplicaSets without resource limits
# High replica count without limits = cluster DoS risk
#
`)

	lootAttackSurface = append(lootAttackSurface, `#####################################
##### Attack Surface Analysis
#####################################
#
# ANALYSIS REPORT
# Total attack surface: vulnerabilities × replica count
# Shows blast radius of insecure templates
#
`)

	lootRemediation = append(lootRemediation, `#####################################
##### ReplicaSet Remediation Guide
#####################################
#
# REMEDIATION STEPS
# How to fix pod template security issues
# Changes will apply to all new pods created by the ReplicaSet
#
`)

	for _, rs := range replicaSets.Items {
		finding := ReplicaSetFinding{
			Namespace:         rs.Namespace,
			Name:              rs.Name,
			DesiredReplicas:   *rs.Spec.Replicas,
			CurrentReplicas:   rs.Status.Replicas,
			ReadyReplicas:     rs.Status.ReadyReplicas,
			AvailableReplicas: rs.Status.AvailableReplicas,
			ReplicaCount:      *rs.Spec.Replicas,
			Labels:            rs.Labels,
			Selectors:         rs.Spec.Selector.MatchLabels,
			Annotations:       rs.Annotations,
			InitContainers:    len(rs.Spec.Template.Spec.InitContainers),
		}

		// High replica count detection
		finding.HighReplicaCount = (finding.ReplicaCount > 10)

		// Deployment ownership detection
		finding.DeploymentName, finding.IsOrphaned = detectDeploymentOwnership(rs)

		// Detect superseded ReplicaSets (zero replicas, has deployment owner)
		finding.IsSuperseded = (!finding.IsOrphaned && finding.ReplicaCount == 0)

		// Tolerations
		for _, t := range rs.Spec.Template.Spec.Tolerations {
			finding.Tolerations = append(finding.Tolerations, fmt.Sprintf("Key=%s,Op=%s,Val=%s,Effect=%s", t.Key, t.Operator, t.Value, t.Effect))
		}

		// Service Account
		finding.ServiceAccount = rs.Spec.Template.Spec.ServiceAccountName

		// Host namespace settings
		finding.HostPID = rs.Spec.Template.Spec.HostPID
		finding.HostIPC = rs.Spec.Template.Spec.HostIPC
		finding.HostNetwork = rs.Spec.Template.Spec.HostNetwork

		// Analyze all containers (init + regular)
		allContainers := []corev1.Container{}
		allContainers = append(allContainers, rs.Spec.Template.Spec.InitContainers...)
		allContainers = append(allContainers, rs.Spec.Template.Spec.Containers...)

		// Security context analysis
		secCtx := analyzeTemplateSecurityContext(&rs.Spec.Template.Spec, allContainers)
		finding.Privileged = secCtx.Privileged != nil && *secCtx.Privileged
		finding.AllowPrivEsc = secCtx.AllowPrivilegeEscalation == nil || *secCtx.AllowPrivilegeEscalation
		finding.ReadOnlyRootFilesystem = secCtx.ReadOnlyRootFilesystem
		finding.ProcMountUnmasked = (secCtx.ProcMount == "Unmasked")
		finding.RunAsRoot = isTemplateRunAsRoot(secCtx)

		// SELinux analysis
		if secCtx.SELinuxOptions != nil {
			finding.SELinuxContext = formatTemplateSELinuxContext(secCtx.SELinuxOptions)
			finding.SELinuxCustom = (secCtx.SELinuxOptions.Level != "" || secCtx.SELinuxOptions.Role != "" ||
				secCtx.SELinuxOptions.Type != "" || secCtx.SELinuxOptions.User != "")
		} else {
			finding.SELinuxContext = "<none>"
		}

		// AppArmor analysis
		finding.AppArmorProfile = getTemplateAppArmorProfile(rs.Spec.Template.Annotations)
		finding.AppArmorUndefined = (finding.AppArmorProfile == "" || finding.AppArmorProfile == "<none>")

		// Seccomp analysis
		if secCtx.SeccompProfile != nil {
			finding.SeccompProfile = formatTemplateSeccompProfile(secCtx.SeccompProfile)
			finding.SeccompUnconfined = (secCtx.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined)
		} else {
			finding.SeccompProfile = "<none>"
			finding.SeccompUnconfined = true
		}

		// FSGroup and SupplementalGroups
		if secCtx.FSGroup != nil {
			finding.FSGroup = fmt.Sprintf("%d", *secCtx.FSGroup)
		} else {
			finding.FSGroup = "<none>"
		}
		for _, sg := range secCtx.SupplementalGroups {
			finding.SupplementalGroups = append(finding.SupplementalGroups, fmt.Sprintf("%d", sg))
		}

		// Capability analysis
		if secCtx.Capabilities != nil {
			for _, cap := range secCtx.Capabilities.Add {
				capStr := string(cap)
				finding.Capabilities = append(finding.Capabilities, capStr)
				if k8sinternal.IsDangerousCapability(capStr) {
					finding.DangerousCaps = append(finding.DangerousCaps, capStr)
				}
			}
			for _, cap := range secCtx.Capabilities.Drop {
				capStr := string(cap)
				finding.Capabilities = append(finding.Capabilities, "-"+capStr)
				if capStr == "ALL" {
					finding.DroppedAllCaps = true
				}
			}
		}

		// Image analysis
		imageAnalyses := analyzeTemplateImages(allContainers)
		for _, img := range imageAnalyses {
			finding.Images = append(finding.Images, img.Image)
			finding.ImageTagTypes = append(finding.ImageTagTypes, img.TagType)
			finding.ImagePullPolicy = append(finding.ImagePullPolicy, img.PullPolicy)
			finding.ImageDigests = append(finding.ImageDigests, img.Digest)
			finding.ImageRegistries = append(finding.ImageRegistries, img.Registry)
			if img.IsLatest {
				finding.LatestTag = true
			}
			if img.IsUnverified {
				finding.UnverifiedImage = true
			}
		}

		// Resource analysis
		resAnalysis := analyzeTemplateResources(allContainers)
		finding.NoLimits = !resAnalysis.HasLimits
		finding.NoRequests = !resAnalysis.HasRequests
		for k, v := range resAnalysis.Limits {
			finding.ResourceLimits = append(finding.ResourceLimits, fmt.Sprintf("%s=%s", k, v))
		}
		for k, v := range resAnalysis.Requests {
			finding.ResourceRequests = append(finding.ResourceRequests, fmt.Sprintf("%s=%s", k, v))
		}
		finding.QoSClass = determineQoSClass(resAnalysis)

		// Volume analysis
		analyzeTemplateVolumes(&rs.Spec.Template.Spec, &finding, allContainers)

		// Service Account token analysis
		finding.AutomountSAToken = true // Default
		if rs.Spec.Template.Spec.AutomountServiceAccountToken != nil {
			finding.AutomountSAToken = *rs.Spec.Template.Spec.AutomountServiceAccountToken
		}
		finding.SATokenProjected = hasTemplateProjectedSAToken(rs.Spec.Template.Spec.Volumes)

		// HostPath analysis
		analyzeTemplateHostPaths(&rs.Spec.Template.Spec, &finding)

		// Cloud role detection
		roleResults := k8sinternal.DetectCloudRole(ctx, clientset, rs.Namespace, rs.Spec.Template.Spec.ServiceAccountName, &rs.Spec.Template.Spec, rs.Spec.Template.Annotations)
		if len(roleResults) > 0 {
			finding.CloudProvider = roleResults[0].Provider
			finding.CloudRole = roleResults[0].Role
		}

		// PSS Compliance Analysis
		finding.PSSViolations, finding.PSSCompliance = analyzeTemplatePSSCompliance(&rs.Spec.Template.Spec, &finding, secCtx)
		finding.RestrictedViolations = countTemplatePSSViolations(finding.PSSViolations, "restricted")
		finding.BaselineViolations = countTemplatePSSViolations(finding.PSSViolations, "baseline")

		// Security Issues Summary
		finding.SecurityIssues = generateTemplateSecurityIssues(&finding)

		// Calculate risk score and level
		finding.RiskLevel, finding.RiskScore = calculateReplicaSetRiskScore(&finding)

		// Calculate blast radius (risk score × replica count)
		finding.BlastRadius = finding.RiskScore * int(finding.ReplicaCount)

		// Impact summary
		finding.ImpactSummary = generateImpactSummary(&finding)

		riskCounts[finding.RiskLevel]++
		findings = append(findings, finding)

		// Generate table row
		row := generateReplicaSetTableRow(&finding)
		outputRows = append(outputRows, row)

		// Generate loot content
		generateReplicaSetLootContent(&finding, &rs,
			&lootEnum, &lootHighRisk, &lootPSSViolations, &lootOrphaned,
			&lootSecretExposure, &lootImageVulns, &lootResourceAbuse,
			&lootAttackSurface, &lootRemediation)
	}

	// Add summaries
	summary := fmt.Sprintf(`
# SUMMARY: Risk Distribution
# CRITICAL: %d ReplicaSets
# HIGH: %d ReplicaSets
# MEDIUM: %d ReplicaSets
# LOW: %d ReplicaSets
#
# Focus on CRITICAL and HIGH risk ReplicaSets first
# Fixing one template prevents creating multiple vulnerable pods
`, riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"])

	lootHighRisk = append([]string{summary}, lootHighRisk...)

	// Create table
	table := internal.TableFile{
		Name:   "ReplicaSets",
		Header: headers,
		Body:   outputRows,
	}

	// Create loot files
	lootFiles := []internal.LootFile{
		{Name: "ReplicaSets-Enum", Contents: strings.Join(lootEnum, "\n")},
		{Name: "ReplicaSets-High-Risk", Contents: strings.Join(lootHighRisk, "\n")},
		{Name: "ReplicaSets-PSS-Violations", Contents: strings.Join(lootPSSViolations, "\n")},
		{Name: "ReplicaSets-Orphaned", Contents: strings.Join(lootOrphaned, "\n")},
		{Name: "ReplicaSets-Secret-Exposure", Contents: strings.Join(lootSecretExposure, "\n")},
		{Name: "ReplicaSets-Image-Vulnerabilities", Contents: strings.Join(lootImageVulns, "\n")},
		{Name: "ReplicaSets-Resource-Abuse", Contents: strings.Join(lootResourceAbuse, "\n")},
		{Name: "ReplicaSets-Attack-Surface", Contents: strings.Join(lootAttackSurface, "\n")},
		{Name: "ReplicaSets-Remediation", Contents: strings.Join(lootRemediation, "\n")},
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"ReplicaSets",
		globals.ClusterName,
		"results",
		ReplicaSetsOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_REPLICASETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d replicasets found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows), riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_REPLICASETS_MODULE_NAME)
	} else {
		logger.InfoM("No replicasets found, skipping output file creation", globals.K8S_REPLICASETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_REPLICASETS_MODULE_NAME), globals.K8S_REPLICASETS_MODULE_NAME)
}

// detectDeploymentOwnership detects if ReplicaSet is owned by a Deployment
func detectDeploymentOwnership(rs appsv1.ReplicaSet) (string, bool) {
	// Check OwnerReferences
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" {
			return owner.Name, false // Has owner, not orphaned
		}
	}

	// Check annotation (legacy method)
	if deployName, exists := rs.Annotations["deployment.kubernetes.io/desired-name"]; exists && deployName != "" {
		return deployName, false
	}

	return "", true // No owner found, orphaned
}

// Template analysis helper functions (similar to pods.go but for pod templates)

type TemplateSecurityContextAnalysis struct {
	ReadOnlyRootFilesystem   bool
	RunAsUser                *int64
	RunAsGroup               *int64
	RunAsNonRoot             *bool
	AllowPrivilegeEscalation *bool
	Privileged               *bool
	ProcMount                string
	SELinuxOptions           *corev1.SELinuxOptions
	SeccompProfile           *corev1.SeccompProfile
	AppArmorProfile          string
	FSGroup                  *int64
	SupplementalGroups       []int64
	Capabilities             *corev1.Capabilities
}

type TemplateImageAnalysis struct {
	Image        string
	TagType      string
	PullPolicy   string
	Digest       string
	Registry     string
	IsLatest     bool
	IsUnverified bool
}

type TemplateResourceAnalysis struct {
	HasLimits   bool
	HasRequests bool
	Limits      map[string]string
	Requests    map[string]string
}

func analyzeTemplateSecurityContext(podSpec *corev1.PodSpec, containers []corev1.Container) TemplateSecurityContextAnalysis {
	analysis := TemplateSecurityContextAnalysis{}

	// Pod-level security context
	if podSpec.SecurityContext != nil {
		analysis.FSGroup = podSpec.SecurityContext.FSGroup
		analysis.SupplementalGroups = podSpec.SecurityContext.SupplementalGroups
		if podSpec.SecurityContext.SELinuxOptions != nil {
			analysis.SELinuxOptions = podSpec.SecurityContext.SELinuxOptions
		}
		if podSpec.SecurityContext.SeccompProfile != nil {
			analysis.SeccompProfile = podSpec.SecurityContext.SeccompProfile
		}
	}

	// Aggregate container-level security contexts
	privileged := false
	allowPrivEsc := false
	readOnlyRootFS := false
	var runAsUser *int64
	var runAsNonRoot *bool
	procMount := ""

	for _, container := range containers {
		if container.SecurityContext != nil {
			sc := container.SecurityContext

			if sc.Privileged != nil && *sc.Privileged {
				privileged = true
			}

			if sc.AllowPrivilegeEscalation != nil {
				if *sc.AllowPrivilegeEscalation {
					allowPrivEsc = true
				}
			} else {
				allowPrivEsc = true
			}

			if sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem {
				readOnlyRootFS = true
			}

			if sc.RunAsUser != nil {
				runAsUser = sc.RunAsUser
			}

			if sc.RunAsNonRoot != nil {
				runAsNonRoot = sc.RunAsNonRoot
			}

			if sc.ProcMount != nil {
				procMount = string(*sc.ProcMount)
			}

			if sc.SELinuxOptions != nil {
				analysis.SELinuxOptions = sc.SELinuxOptions
			}

			if sc.SeccompProfile != nil {
				analysis.SeccompProfile = sc.SeccompProfile
			}

			if sc.Capabilities != nil {
				if analysis.Capabilities == nil {
					analysis.Capabilities = &corev1.Capabilities{}
				}
				analysis.Capabilities.Add = append(analysis.Capabilities.Add, sc.Capabilities.Add...)
				analysis.Capabilities.Drop = append(analysis.Capabilities.Drop, sc.Capabilities.Drop...)
			}
		}
	}

	analysis.Privileged = &privileged
	analysis.AllowPrivilegeEscalation = &allowPrivEsc
	analysis.ReadOnlyRootFilesystem = readOnlyRootFS
	analysis.RunAsUser = runAsUser
	analysis.RunAsNonRoot = runAsNonRoot
	analysis.ProcMount = procMount

	return analysis
}

func isTemplateRunAsRoot(secCtx TemplateSecurityContextAnalysis) bool {
	if secCtx.RunAsNonRoot != nil && *secCtx.RunAsNonRoot {
		return false
	}
	if secCtx.RunAsUser != nil && *secCtx.RunAsUser == 0 {
		return true
	}
	if secCtx.RunAsUser != nil && *secCtx.RunAsUser > 0 {
		return false
	}
	return true
}

func formatTemplateSELinuxContext(sel *corev1.SELinuxOptions) string {
	parts := []string{}
	if sel.User != "" {
		parts = append(parts, fmt.Sprintf("user:%s", sel.User))
	}
	if sel.Role != "" {
		parts = append(parts, fmt.Sprintf("role:%s", sel.Role))
	}
	if sel.Type != "" {
		parts = append(parts, fmt.Sprintf("type:%s", sel.Type))
	}
	if sel.Level != "" {
		parts = append(parts, fmt.Sprintf("level:%s", sel.Level))
	}
	if len(parts) == 0 {
		return "<none>"
	}
	return strings.Join(parts, ",")
}

func getTemplateAppArmorProfile(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") {
			return v
		}
	}
	return "<none>"
}

func formatTemplateSeccompProfile(profile *corev1.SeccompProfile) string {
	switch profile.Type {
	case corev1.SeccompProfileTypeUnconfined:
		return "Unconfined"
	case corev1.SeccompProfileTypeRuntimeDefault:
		return "RuntimeDefault"
	case corev1.SeccompProfileTypeLocalhost:
		if profile.LocalhostProfile != nil {
			return fmt.Sprintf("Localhost:%s", *profile.LocalhostProfile)
		}
		return "Localhost"
	default:
		return string(profile.Type)
	}
}

func analyzeTemplateImages(containers []corev1.Container) []TemplateImageAnalysis {
	var analyses []TemplateImageAnalysis

	for _, container := range containers {
		analysis := TemplateImageAnalysis{
			Image:      container.Image,
			PullPolicy: string(container.ImagePullPolicy),
		}

		analysis.TagType = k8sinternal.ImageTagType(container.Image)
		analysis.IsLatest = strings.HasSuffix(container.Image, ":latest") || !strings.Contains(container.Image, ":")

		if strings.Contains(container.Image, "@sha256:") {
			parts := strings.Split(container.Image, "@")
			if len(parts) == 2 {
				analysis.Digest = parts[1]
			}
			analysis.IsUnverified = false
		} else {
			analysis.Digest = "<none>"
			analysis.IsUnverified = true
		}

		if strings.Contains(container.Image, "/") {
			parts := strings.Split(container.Image, "/")
			analysis.Registry = parts[0]
		} else {
			analysis.Registry = "docker.io"
		}

		analyses = append(analyses, analysis)
	}

	return analyses
}

func analyzeTemplateResources(containers []corev1.Container) TemplateResourceAnalysis {
	analysis := TemplateResourceAnalysis{
		Limits:   make(map[string]string),
		Requests: make(map[string]string),
	}

	for _, container := range containers {
		if container.Resources.Limits != nil && len(container.Resources.Limits) > 0 {
			analysis.HasLimits = true
			for k, v := range container.Resources.Limits {
				analysis.Limits[string(k)] = v.String()
			}
		}
		if container.Resources.Requests != nil && len(container.Resources.Requests) > 0 {
			analysis.HasRequests = true
			for k, v := range container.Resources.Requests {
				analysis.Requests[string(k)] = v.String()
			}
		}
	}

	return analysis
}

func determineQoSClass(res TemplateResourceAnalysis) string {
	if !res.HasLimits && !res.HasRequests {
		return "BestEffort"
	}
	if res.HasLimits && res.HasRequests {
		return "Guaranteed"
	}
	return "Burstable"
}

func analyzeTemplateVolumes(podSpec *corev1.PodSpec, finding *ReplicaSetFinding, containers []corev1.Container) {
	for _, volume := range podSpec.Volumes {
		if volume.Secret != nil {
			secretInfo := fmt.Sprintf("%s (secret:%s)", volume.Name, volume.Secret.SecretName)
			finding.SecretVolumes = append(finding.SecretVolumes, secretInfo)
			finding.TotalSecretsExposed++
		}

		if volume.ConfigMap != nil {
			cmInfo := fmt.Sprintf("%s (cm:%s)", volume.Name, volume.ConfigMap.Name)
			finding.ConfigMapVolumes = append(finding.ConfigMapVolumes, cmInfo)
		}

		if volume.Projected != nil {
			hasSecrets := false
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil {
					hasSecrets = true
					finding.TotalSecretsExposed++
				}
			}
			projInfo := volume.Name
			if hasSecrets {
				projInfo += " (contains secrets)"
			}
			finding.ProjectedVolumes = append(finding.ProjectedVolumes, projInfo)
		}
	}

	for _, container := range containers {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				secretEnvInfo := fmt.Sprintf("%s (secret:%s, key:%s)",
					env.Name, env.ValueFrom.SecretKeyRef.Name, env.ValueFrom.SecretKeyRef.Key)
				finding.SecretEnvVars = append(finding.SecretEnvVars, secretEnvInfo)
				finding.TotalSecretsExposed++
			}
			if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
				cmEnvInfo := fmt.Sprintf("%s (cm:%s, key:%s)",
					env.Name, env.ValueFrom.ConfigMapKeyRef.Name, env.ValueFrom.ConfigMapKeyRef.Key)
				finding.ConfigMapEnvVars = append(finding.ConfigMapEnvVars, cmEnvInfo)
			}
		}
	}
}

func analyzeTemplateHostPaths(podSpec *corev1.PodSpec, finding *ReplicaSetFinding) {
	for _, volume := range podSpec.Volumes {
		if volume.HostPath != nil {
			mountPoint := k8sinternal.FindMountPath(volume.Name, podSpec.Containers)

			readOnly := false
			for _, container := range podSpec.Containers {
				for _, vm := range container.VolumeMounts {
					if vm.Name == volume.Name {
						readOnly = vm.ReadOnly
						break
					}
				}
			}

			if !readOnly {
				finding.WritableHostPaths++
			}

			isSensitive, description := k8sinternal.AnalyzeHostPath(volume.HostPath.Path, readOnly)

			hostPathLine := fmt.Sprintf("%s:%s", volume.HostPath.Path, mountPoint)
			if readOnly {
				hostPathLine += " (ro)"
			} else {
				hostPathLine += " (rw)"
			}

			if isSensitive {
				hostPathLine += fmt.Sprintf(" - %s", description)
				finding.SensitiveHostPaths = append(finding.SensitiveHostPaths, fmt.Sprintf("%s - %s", volume.HostPath.Path, description))
			}

			finding.HostPaths = append(finding.HostPaths, hostPathLine)
		}
	}
}

func hasTemplateProjectedSAToken(volumes []corev1.Volume) bool {
	for _, vol := range volumes {
		if vol.Projected != nil {
			for _, source := range vol.Projected.Sources {
				if source.ServiceAccountToken != nil {
					return true
				}
			}
		}
	}
	return false
}

func analyzeTemplatePSSCompliance(podSpec *corev1.PodSpec, finding *ReplicaSetFinding, secCtx TemplateSecurityContextAnalysis) ([]string, string) {
	var violations []string

	// PSS Baseline violations
	if finding.Privileged {
		violations = append(violations, "baseline: privileged containers not allowed")
	}
	if finding.HostPID {
		violations = append(violations, "baseline: hostPID not allowed")
	}
	if finding.HostIPC {
		violations = append(violations, "baseline: hostIPC not allowed")
	}
	if finding.HostNetwork {
		violations = append(violations, "baseline: hostNetwork not allowed")
	}
	if len(finding.HostPaths) > 0 {
		violations = append(violations, "baseline: hostPath volumes not allowed")
	}
	if finding.AppArmorUndefined {
		violations = append(violations, "baseline: AppArmor profile undefined")
	}
	if finding.SELinuxCustom {
		violations = append(violations, "baseline: custom SELinux options not allowed")
	}
	if finding.ProcMountUnmasked {
		violations = append(violations, "baseline: unmasked /proc mount not allowed")
	}

	baselineForbiddenCaps := map[string]bool{
		"SYS_ADMIN": true, "NET_ADMIN": true, "SYS_MODULE": true,
		"SYS_RAWIO": true, "SYS_PTRACE": true, "SYS_BOOT": true,
		"MAC_ADMIN": true, "MAC_OVERRIDE": true, "PERFMON": true,
		"BPF": true, "NET_RAW": true,
	}
	for _, cap := range finding.DangerousCaps {
		if baselineForbiddenCaps[cap] {
			violations = append(violations, fmt.Sprintf("baseline: capability %s not allowed", cap))
		}
	}

	// PSS Restricted violations
	if !finding.DroppedAllCaps {
		violations = append(violations, "restricted: must drop ALL capabilities")
	}

	if len(finding.Capabilities) > 0 {
		for _, cap := range finding.Capabilities {
			if !strings.HasPrefix(cap, "-") && cap != "NET_BIND_SERVICE" {
				violations = append(violations, fmt.Sprintf("restricted: capability %s not in allowed list", cap))
			}
		}
	}

	if secCtx.RunAsNonRoot == nil || !*secCtx.RunAsNonRoot {
		violations = append(violations, "restricted: runAsNonRoot must be true")
	}

	if finding.AllowPrivEsc {
		violations = append(violations, "restricted: allowPrivilegeEscalation must be false")
	}

	if finding.SeccompProfile == "<none>" || finding.SeccompUnconfined {
		violations = append(violations, "restricted: seccompProfile must be RuntimeDefault or Localhost")
	}

	compliance := "Privileged"
	if len(violations) == 0 {
		compliance = "Restricted"
	} else {
		hasBaselineViolation := false
		for _, v := range violations {
			if strings.HasPrefix(v, "baseline:") {
				hasBaselineViolation = true
				break
			}
		}
		if !hasBaselineViolation {
			compliance = "Baseline"
		}
	}

	return violations, compliance
}

func countTemplatePSSViolations(violations []string, level string) int {
	count := 0
	prefix := level + ":"
	for _, v := range violations {
		if strings.HasPrefix(v, prefix) {
			count++
		}
	}
	return count
}

func generateTemplateSecurityIssues(finding *ReplicaSetFinding) []string {
	var issues []string

	if finding.Privileged {
		issues = append(issues, "PRIVILEGED template")
	}
	if finding.HostPID {
		issues = append(issues, "HOST_PID namespace")
	}
	if finding.HostIPC {
		issues = append(issues, "HOST_IPC namespace")
	}
	if finding.HostNetwork {
		issues = append(issues, "HOST_NETWORK namespace")
	}
	if len(finding.SensitiveHostPaths) > 0 {
		issues = append(issues, fmt.Sprintf("SENSITIVE_HOSTPATHS(%d)", len(finding.SensitiveHostPaths)))
	}
	if len(finding.DangerousCaps) > 0 {
		issues = append(issues, fmt.Sprintf("DANGEROUS_CAPS(%s)", strings.Join(finding.DangerousCaps, ",")))
	}
	if finding.RunAsRoot {
		issues = append(issues, "RUN_AS_ROOT")
	}
	if finding.AllowPrivEsc {
		issues = append(issues, "ALLOW_PRIV_ESC")
	}
	if !finding.ReadOnlyRootFilesystem {
		issues = append(issues, "WRITABLE_ROOT_FS")
	}
	if finding.SeccompUnconfined {
		issues = append(issues, "SECCOMP_UNCONFINED")
	}
	if finding.AppArmorUndefined {
		issues = append(issues, "APPARMOR_UNDEFINED")
	}
	if finding.TotalSecretsExposed > 0 {
		issues = append(issues, fmt.Sprintf("SECRETS_EXPOSED(%d)", finding.TotalSecretsExposed))
	}
	if finding.LatestTag {
		issues = append(issues, "LATEST_TAG")
	}
	if finding.NoLimits {
		issues = append(issues, "NO_RESOURCE_LIMITS")
	}
	if finding.IsOrphaned {
		issues = append(issues, "ORPHANED_RS")
	}
	if finding.HighReplicaCount && finding.NoLimits {
		issues = append(issues, "HIGH_REPLICA_NO_LIMITS")
	}

	return issues
}

func calculateReplicaSetRiskScore(finding *ReplicaSetFinding) (string, int) {
	score := 0

	// CRITICAL factors
	if finding.Privileged {
		score += 90
		if finding.HostPID || finding.HostNetwork || finding.HostIPC {
			return "CRITICAL", 100
		}
	}

	// Host namespace access
	if finding.HostPID {
		score += 70
	}
	if finding.HostNetwork {
		score += 60
	}
	if finding.HostIPC {
		score += 50
	}

	// Sensitive host paths
	for _, hp := range finding.SensitiveHostPaths {
		if strings.Contains(hp, "docker.sock") || strings.Contains(hp, "containerd") {
			score += 95
		} else if strings.Contains(hp, "/etc/kubernetes") || strings.Contains(hp, "kubelet") {
			score += 85
		} else if strings.Contains(hp, " / ") || strings.Contains(hp, "/etc ") {
			score += 80
		} else {
			score += 30
		}
	}

	score += finding.WritableHostPaths * 25

	// Dangerous capabilities
	for _, cap := range finding.DangerousCaps {
		switch cap {
		case "SYS_ADMIN", "SYS_MODULE":
			score += 80
		case "SYS_PTRACE", "SYS_RAWIO":
			score += 60
		case "NET_ADMIN", "DAC_READ_SEARCH", "DAC_OVERRIDE":
			score += 40
		default:
			score += 20
		}
	}

	// Security context weaknesses
	if finding.RunAsRoot {
		score += 15
	}
	if finding.AllowPrivEsc {
		score += 20
	}
	if !finding.ReadOnlyRootFilesystem {
		score += 10
	}
	if finding.SeccompUnconfined {
		score += 25
	}
	if finding.AppArmorUndefined {
		score += 15
	}
	if finding.ProcMountUnmasked {
		score += 30
	}

	score += finding.TotalSecretsExposed * 10

	if finding.NoLimits {
		score += 20
		if finding.HighReplicaCount {
			score += 30 // Extra penalty for high replica count without limits
		}
	}

	if finding.LatestTag {
		score += 10
	}
	if finding.UnverifiedImage {
		score += 5
	}

	if finding.CloudRole != "" {
		score += 30
	}

	score += finding.BaselineViolations * 5
	score += finding.RestrictedViolations * 2

	// Determine risk level
	if score >= 80 {
		return "CRITICAL", score
	} else if score >= 50 {
		return "HIGH", score
	} else if score >= 25 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func generateImpactSummary(finding *ReplicaSetFinding) string {
	if finding.ReplicaCount == 0 {
		return "Inactive (0 replicas)"
	}

	if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
		return fmt.Sprintf("Will create %d %s risk pods", finding.ReplicaCount, finding.RiskLevel)
	}

	if finding.IsOrphaned {
		return fmt.Sprintf("Orphaned RS with %d replicas", finding.ReplicaCount)
	}

	if finding.HighReplicaCount {
		return fmt.Sprintf("High replica count (%d)", finding.ReplicaCount)
	}

	return fmt.Sprintf("%d replicas", finding.ReplicaCount)
}

func generateReplicaSetTableRow(finding *ReplicaSetFinding) []string {
	return []string{
		finding.RiskLevel,
		fmt.Sprintf("%d", finding.BlastRadius),
		finding.Namespace,
		finding.Name,
		k8sinternal.NonEmpty(finding.DeploymentName),
		fmt.Sprintf("%v", finding.IsOrphaned),
		fmt.Sprintf("%d/%d/%d", finding.DesiredReplicas, finding.CurrentReplicas, finding.ReadyReplicas),
		k8sinternal.NonEmpty(finding.ServiceAccount),
		fmt.Sprintf("%v", finding.HostPID),
		fmt.Sprintf("%v", finding.HostIPC),
		fmt.Sprintf("%v", finding.HostNetwork),
		fmt.Sprintf("%v", finding.Privileged),
		fmt.Sprintf("%v", finding.RunAsRoot),
		fmt.Sprintf("%v", finding.AllowPrivEsc),
		fmt.Sprintf("%v", finding.ReadOnlyRootFilesystem),
		finding.SELinuxContext,
		finding.AppArmorProfile,
		finding.SeccompProfile,
		stringListOrNoneRS(finding.Capabilities),
		stringListOrNoneRS(finding.DangerousCaps),
		stringListOrNoneRS(finding.HostPaths),
		stringListOrNoneRS(finding.SensitiveHostPaths),
		stringListOrNoneRS(finding.SecretVolumes),
		stringListOrNoneRS(finding.SecretEnvVars),
		stringListOrNoneRS(finding.ImageTagTypes),
		fmt.Sprintf("%v", finding.LatestTag),
		stringListOrNoneRS(finding.ResourceLimits),
		stringListOrNoneRS(finding.ResourceRequests),
		finding.PSSCompliance,
		fmt.Sprintf("%d violations", len(finding.PSSViolations)),
		stringListOrNoneRS(finding.SecurityIssues),
		finding.ImpactSummary,
	}
}

func stringListOrNoneRS(list []string) string {
	if len(list) == 0 {
		return "<NONE>"
	}
	return strings.Join(list, ", ")
}

func generateReplicaSetLootContent(finding *ReplicaSetFinding, rs *appsv1.ReplicaSet,
	lootEnum, lootHighRisk, lootPSSViolations, lootOrphaned,
	lootSecretExposure, lootImageVulns, lootResourceAbuse,
	lootAttackSurface, lootRemediation *[]string) {

	rsID := fmt.Sprintf("%s/%s", finding.Namespace, finding.Name)

	// Enumeration
	*lootEnum = append(*lootEnum, fmt.Sprintf("\n# %s", rsID))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl describe replicaset -n %s %s", finding.Namespace, finding.Name))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get replicaset -n %s %s -o yaml\n", finding.Namespace, finding.Name))

	// High risk ReplicaSets
	if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
		*lootHighRisk = append(*lootHighRisk, fmt.Sprintf("\n### [%s] %s (Blast Radius: %d)", finding.RiskLevel, rsID, finding.BlastRadius))
		*lootHighRisk = append(*lootHighRisk, fmt.Sprintf("# Deployment: %s", k8sinternal.NonEmpty(finding.DeploymentName)))
		*lootHighRisk = append(*lootHighRisk, fmt.Sprintf("# Replicas: %d (will create %d %s risk pods)", finding.ReplicaCount, finding.ReplicaCount, finding.RiskLevel))
		*lootHighRisk = append(*lootHighRisk, fmt.Sprintf("# Security Issues: %s", strings.Join(finding.SecurityIssues, ", ")))
		*lootHighRisk = append(*lootHighRisk, fmt.Sprintf("# Impact: %s", finding.ImpactSummary))
		*lootHighRisk = append(*lootHighRisk, "")
		*lootHighRisk = append(*lootHighRisk, "# Fix template to prevent creating vulnerable pods:")
		if !finding.IsOrphaned {
			*lootHighRisk = append(*lootHighRisk, fmt.Sprintf("kubectl edit deployment -n %s %s", finding.Namespace, finding.DeploymentName))
		} else {
			*lootHighRisk = append(*lootHighRisk, fmt.Sprintf("kubectl edit replicaset -n %s %s", finding.Namespace, finding.Name))
		}
		*lootHighRisk = append(*lootHighRisk, "")
	}

	// PSS violations
	if len(finding.PSSViolations) > 0 {
		*lootPSSViolations = append(*lootPSSViolations, fmt.Sprintf("\n### %s - %s (%d violations)", rsID, finding.PSSCompliance, len(finding.PSSViolations)))
		*lootPSSViolations = append(*lootPSSViolations, fmt.Sprintf("# Replicas: %d (each pod will have these violations)", finding.ReplicaCount))
		for _, violation := range finding.PSSViolations {
			*lootPSSViolations = append(*lootPSSViolations, fmt.Sprintf("  - %s", violation))
		}
		*lootPSSViolations = append(*lootPSSViolations, "")
	}

	// Orphaned ReplicaSets
	if finding.IsOrphaned {
		*lootOrphaned = append(*lootOrphaned, fmt.Sprintf("\n### %s", rsID))
		*lootOrphaned = append(*lootOrphaned, "  - No Deployment owner (manually created)")
		*lootOrphaned = append(*lootOrphaned, fmt.Sprintf("  - Replicas: %d", finding.ReplicaCount))
		*lootOrphaned = append(*lootOrphaned, "  - May indicate attacker persistence or forgotten test resource")
		*lootOrphaned = append(*lootOrphaned, fmt.Sprintf("  - Risk Level: %s", finding.RiskLevel))
		*lootOrphaned = append(*lootOrphaned, "")
	}

	// Secret exposure
	if finding.TotalSecretsExposed > 0 {
		*lootSecretExposure = append(*lootSecretExposure, fmt.Sprintf("\n### %s (%d secrets × %d replicas = %d total exposures)",
			rsID, finding.TotalSecretsExposed, finding.ReplicaCount, finding.TotalSecretsExposed*int(finding.ReplicaCount)))
		if len(finding.SecretVolumes) > 0 {
			*lootSecretExposure = append(*lootSecretExposure, fmt.Sprintf("# Secret volumes: %s", strings.Join(finding.SecretVolumes, ", ")))
		}
		if len(finding.SecretEnvVars) > 0 {
			*lootSecretExposure = append(*lootSecretExposure, fmt.Sprintf("# Secret env vars: %s", strings.Join(finding.SecretEnvVars, ", ")))
		}
		*lootSecretExposure = append(*lootSecretExposure, "")
	}

	// Image vulnerabilities
	if finding.LatestTag || finding.UnverifiedImage {
		*lootImageVulns = append(*lootImageVulns, fmt.Sprintf("\n### %s (%d replicas with vulnerable images)", rsID, finding.ReplicaCount))
		if finding.LatestTag {
			*lootImageVulns = append(*lootImageVulns, "  - Uses :latest tag (unpinned version)")
		}
		if finding.UnverifiedImage {
			*lootImageVulns = append(*lootImageVulns, "  - Image not verified with digest (@sha256)")
		}
		*lootImageVulns = append(*lootImageVulns, fmt.Sprintf("  - Images: %s", strings.Join(finding.Images, ", ")))
		*lootImageVulns = append(*lootImageVulns, "")
	}

	// Resource abuse
	if finding.NoLimits {
		*lootResourceAbuse = append(*lootResourceAbuse, fmt.Sprintf("\n### %s - No resource limits", rsID))
		*lootResourceAbuse = append(*lootResourceAbuse, fmt.Sprintf("  - Replicas: %d", finding.ReplicaCount))
		*lootResourceAbuse = append(*lootResourceAbuse, "  - Each pod can consume unlimited CPU/memory")
		if finding.HighReplicaCount {
			*lootResourceAbuse = append(*lootResourceAbuse, fmt.Sprintf("  - HIGH RISK: %d pods without limits = cluster DoS potential", finding.ReplicaCount))
		}
		*lootResourceAbuse = append(*lootResourceAbuse, "")
	}

	// Attack surface
	if finding.RiskLevel == "CRITICAL" || finding.RiskLevel == "HIGH" {
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("\n### %s", rsID))
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("  Risk Score: %d", finding.RiskScore))
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("  Replica Count: %d", finding.ReplicaCount))
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("  Blast Radius: %d (score × replicas)", finding.BlastRadius))
		*lootAttackSurface = append(*lootAttackSurface, fmt.Sprintf("  Impact: Fixing 1 template prevents %d vulnerable pods", finding.ReplicaCount))
		*lootAttackSurface = append(*lootAttackSurface, "")
	}

	// Remediation
	if len(finding.SecurityIssues) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n### %s (%d issues affecting %d replicas)", rsID, len(finding.SecurityIssues), finding.ReplicaCount))
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("# Total pod-level issues: %d × %d = %d", len(finding.SecurityIssues), finding.ReplicaCount, len(finding.SecurityIssues)*int(finding.ReplicaCount)))
		*lootRemediation = append(*lootRemediation, "")

		for _, issue := range finding.SecurityIssues {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("## Issue: %s", issue))

			switch {
			case strings.Contains(issue, "PRIVILEGED"):
				*lootRemediation = append(*lootRemediation, "Remediation: Remove privileged: true from pod template securityContext")
			case strings.Contains(issue, "HOST_PID"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set hostPID: false in pod template spec")
			case strings.Contains(issue, "HOST_NETWORK"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set hostNetwork: false in pod template spec")
			case strings.Contains(issue, "RUN_AS_ROOT"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set runAsNonRoot: true in pod template securityContext")
			case strings.Contains(issue, "ALLOW_PRIV_ESC"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set allowPrivilegeEscalation: false in pod template securityContext")
			case strings.Contains(issue, "WRITABLE_ROOT_FS"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set readOnlyRootFilesystem: true in pod template securityContext")
			case strings.Contains(issue, "SECCOMP_UNCONFINED"):
				*lootRemediation = append(*lootRemediation, "Remediation: Set seccompProfile.type: RuntimeDefault in pod template securityContext")
			case strings.Contains(issue, "NO_RESOURCE_LIMITS"):
				*lootRemediation = append(*lootRemediation, "Remediation: Add resources.limits for cpu and memory in pod template")
			case strings.Contains(issue, "ORPHANED_RS"):
				*lootRemediation = append(*lootRemediation, "Remediation: Delete orphaned ReplicaSet or create Deployment to manage it")
			}
		}

		if !finding.IsOrphaned {
			*lootRemediation = append(*lootRemediation, "")
			*lootRemediation = append(*lootRemediation, "# Edit Deployment to update template:")
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("kubectl edit deployment -n %s %s", finding.Namespace, finding.DeploymentName))
		} else {
			*lootRemediation = append(*lootRemediation, "")
			*lootRemediation = append(*lootRemediation, "# Edit ReplicaSet directly (orphaned):")
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("kubectl edit replicaset -n %s %s", finding.Namespace, finding.Name))
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}
