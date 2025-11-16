package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	k8sinternal "github.com/BishopFox/cloudfox/internal/kubernetes"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var StatefulSetsCmd = &cobra.Command{
	Use:     "statefulsets",
	Aliases: []string{"ss", "sts"},
	Short:   "Enumerate StatefulSets with comprehensive security analysis",
	Long: `
Enumerate all StatefulSets with security analysis including:
  - Persistent volume security and storage class analysis
  - Privileged containers and host access (PID/IPC/Network)
  - Security context analysis (runAsRoot, capabilities, read-only filesystem)
  - Resource limits and quota enforcement
  - Update strategy and partition risks
  - Data persistence and backup detection
  - Headless service exposure
  - Pod disruption budget analysis
  - StatefulSet-specific risks (ordered updates, stable identities)
  - Volume type security (HostPath, EmptyDir, ConfigMap, Secret)

  cloudfox kubernetes statefulsets`,
	Run: ListStatefulSets,
}

type StatefulSetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t StatefulSetsOutput) TableFiles() []internal.TableFile { return t.Table }
func (t StatefulSetsOutput) LootFiles() []internal.LootFile   { return t.Loot }

type StatefulSetFinding struct {
	// Basic Info
	Namespace string
	Name      string
	Age       time.Duration
	AgeDays   int

	// Replica Info
	Replicas        int32
	ReadyReplicas   int32
	CurrentReplicas int32
	UpdatedReplicas int32
	Revision        string

	// StatefulSet-Specific
	ServiceName         string
	UpdateStrategy      string
	Partition           int32
	PodManagementPolicy string
	Ordinals            string // Start/End for ordinal indexing

	// PVC Analysis
	VolumeClaimTemplates []VolumeClaimInfo
	TotalPVCCount        int
	PVCStorageSize       string
	StorageClasses       []string
	DangerousAccessModes []string // ReadWriteMany can be risky

	// Volume Security
	HostPathVolumes  []string
	EmptyDirVolumes  []string
	SecretVolumes    []string
	ConfigMapVolumes []string
	DangerousVolumes []string

	// Container Security
	PrivilegedContainers     int
	HostPID                  bool
	HostIPC                  bool
	HostNetwork              bool
	RunAsRoot                int // Count of containers running as root
	ReadOnlyRootFilesystem   int
	AllowPrivilegeEscalation int
	Capabilities             []string
	SecurityIssues           []string

	// Resource Analysis
	HasResourceLimits   bool
	HasResourceRequests bool
	LimitsCPU           string
	LimitsMemory        string
	RequestsCPU         string
	RequestsMemory      string

	// Service Account
	ServiceAccount string
	CloudProvider  string
	CloudRole      string

	// Risk Assessment
	RiskLevel     string
	RiskScore     int
	ImpactSummary string

	// Labels and Selectors
	Labels    map[string]string
	Selectors map[string]string
}

type VolumeClaimInfo struct {
	Name         string
	StorageClass string
	AccessModes  []string
	Size         string
}

func ListStatefulSets(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating statefulsets for %s", globals.ClusterName), globals.K8S_STATEFULSETS_MODULE_NAME)

	clientset := config.GetClientOrExit()

	statefulSets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing StatefulSets: %v", err), globals.K8S_STATEFULSETS_MODULE_NAME)
		return
	}

	// Get all PVCs for correlation
	allPVCs, err := clientset.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Warning: Could not list PVCs: %v", err), globals.K8S_STATEFULSETS_MODULE_NAME)
		allPVCs = &corev1.PersistentVolumeClaimList{}
	}

	// Get all services for headless service detection
	allServices, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Warning: Could not list services: %v", err), globals.K8S_STATEFULSETS_MODULE_NAME)
		allServices = &corev1.ServiceList{}
	}

	headers := []string{
		"Risk",
		"Score",
		"Namespace",
		"Name",
		"Replicas",
		"PVCs",
		"Storage",
		"Privileged",
		"HostAccess",
		"RunAsRoot",
		"UpdateStrategy",
		"ResourceLimits",
		"CloudRole",
		"Issues",
	}

	var outputRows [][]string
	var findings []StatefulSetFinding

	// Risk counters
	riskCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	var lootEnum []string
	var lootPVCs []string
	var lootPrivileged []string
	var lootDataPersistence []string
	var lootRiskyUpdates []string
	var lootRemediation []string

	lootEnum = append(lootEnum, `#####################################
##### StatefulSet Enumeration
#####################################
#
# StatefulSets manage stateful applications with persistent storage
# Often run critical infrastructure: databases, queues, caches
#
`)

	lootPVCs = append(lootPVCs, `#####################################
##### StatefulSet Persistent Volume Claims
#####################################
#
# PVCs provide persistent storage for stateful applications
# CRITICAL: Review storage classes, backup policies, and access modes
#
`)

	lootPrivileged = append(lootPrivileged, `#####################################
##### Privileged StatefulSets
#####################################
#
# Privileged StatefulSets can compromise node security
# HIGH RISK: Review necessity of privileged access
#
`)

	lootDataPersistence = append(lootDataPersistence, `#####################################
##### Data Persistence Analysis
#####################################
#
# StatefulSets with persistent data require backup and DR planning
# Review retention policies, encryption, and access controls
#
`)

	lootRiskyUpdates = append(lootRiskyUpdates, `#####################################
##### Risky Update Strategies
#####################################
#
# Update strategy can cause downtime or leave pods in inconsistent states
# Review partition values and PodManagementPolicy
#
`)

	lootRemediation = append(lootRemediation, `#####################################
##### Security Remediation Recommendations
#####################################
#
# Step-by-step fixes for identified security issues
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
		lootPVCs = append(lootPVCs, fmt.Sprintf("kubectl config use-context %s\n", globals.KubeContext))
	}

	for _, ss := range statefulSets.Items {
		finding := analyzeStatefulSet(&ss, allPVCs.Items, allServices.Items, clientset, ctx)
		findings = append(findings, finding)
		riskCounts[finding.RiskLevel]++

		// Build output row
		hostAccess := "None"
		hostAccessParts := []string{}
		if finding.HostPID {
			hostAccessParts = append(hostAccessParts, "PID")
		}
		if finding.HostIPC {
			hostAccessParts = append(hostAccessParts, "IPC")
		}
		if finding.HostNetwork {
			hostAccessParts = append(hostAccessParts, "Network")
		}
		if len(hostAccessParts) > 0 {
			hostAccess = strings.Join(hostAccessParts, ",")
		}

		resourceLimits := "No"
		if finding.HasResourceLimits {
			resourceLimits = "Yes"
		}

		pvcInfo := fmt.Sprintf("%d", finding.TotalPVCCount)
		if finding.TotalPVCCount > 0 {
			pvcInfo = fmt.Sprintf("%d (%s)", finding.TotalPVCCount, finding.PVCStorageSize)
		}

		storageClassStr := "None"
		if len(finding.StorageClasses) > 0 {
			storageClassStr = strings.Join(finding.StorageClasses, ",")
		}

		row := []string{
			finding.RiskLevel,
			fmt.Sprintf("%d", finding.RiskScore),
			ss.Namespace,
			ss.Name,
			fmt.Sprintf("%d/%d", finding.ReadyReplicas, finding.Replicas),
			pvcInfo,
			storageClassStr,
			fmt.Sprintf("%d", finding.PrivilegedContainers),
			hostAccess,
			fmt.Sprintf("%d", finding.RunAsRoot),
			finding.UpdateStrategy,
			resourceLimits,
			k8sinternal.NonEmpty(finding.CloudRole),
			fmt.Sprintf("%d", len(finding.SecurityIssues)),
		}

		outputRows = append(outputRows, row)

		// Generate loot content
		generateStatefulSetLoot(&finding, &lootEnum, &lootPVCs, &lootPrivileged,
			&lootDataPersistence, &lootRiskyUpdates, &lootRemediation)
	}

	// Sort by risk score descending
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	table := internal.TableFile{
		Name:   "StatefulSets",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "StatefulSets-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "StatefulSets-PVCs",
			Contents: strings.Join(lootPVCs, "\n"),
		},
		{
			Name:     "StatefulSets-Privileged",
			Contents: strings.Join(lootPrivileged, "\n"),
		},
		{
			Name:     "StatefulSets-Data-Persistence",
			Contents: strings.Join(lootDataPersistence, "\n"),
		},
		{
			Name:     "StatefulSets-Risky-Updates",
			Contents: strings.Join(lootRiskyUpdates, "\n"),
		},
		{
			Name:     "StatefulSets-Remediation",
			Contents: strings.Join(lootRemediation, "\n"),
		},
	}

	if err := internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"StatefulSets",
		globals.ClusterName,
		"results",
		StatefulSetsOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_STATEFULSETS_MODULE_NAME)
		return
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d statefulsets found | Risk: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d",
			len(outputRows),
			riskCounts["CRITICAL"], riskCounts["HIGH"], riskCounts["MEDIUM"], riskCounts["LOW"]),
			globals.K8S_STATEFULSETS_MODULE_NAME)
	} else {
		logger.InfoM("No statefulsets found, skipping output file creation", globals.K8S_STATEFULSETS_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_STATEFULSETS_MODULE_NAME), globals.K8S_STATEFULSETS_MODULE_NAME)
}

func analyzeStatefulSet(ss *appsv1.StatefulSet, allPVCs []corev1.PersistentVolumeClaim,
	allServices []corev1.Service, clientset *kubernetes.Clientset, ctx context.Context) StatefulSetFinding {

	finding := StatefulSetFinding{
		Namespace:   ss.Namespace,
		Name:        ss.Name,
		Labels:      ss.Labels,
		Selectors:   ss.Spec.Selector.MatchLabels,
		ServiceName: ss.Spec.ServiceName,
	}

	// Age calculation
	finding.Age = time.Since(ss.CreationTimestamp.Time)
	finding.AgeDays = int(finding.Age.Hours() / 24)

	// Replica info
	if ss.Spec.Replicas != nil {
		finding.Replicas = *ss.Spec.Replicas
	}
	finding.ReadyReplicas = ss.Status.ReadyReplicas
	finding.CurrentReplicas = ss.Status.CurrentReplicas
	finding.UpdatedReplicas = ss.Status.UpdatedReplicas
	finding.Revision = ss.Status.CurrentRevision

	// Update strategy
	finding.UpdateStrategy = string(ss.Spec.UpdateStrategy.Type)
	if ss.Spec.UpdateStrategy.RollingUpdate != nil && ss.Spec.UpdateStrategy.RollingUpdate.Partition != nil {
		finding.Partition = *ss.Spec.UpdateStrategy.RollingUpdate.Partition
	}

	// Pod management policy
	if ss.Spec.PodManagementPolicy != "" {
		finding.PodManagementPolicy = string(ss.Spec.PodManagementPolicy)
	} else {
		finding.PodManagementPolicy = "OrderedReady"
	}

	// Ordinals (if using ordinal indexing)
	if ss.Spec.Ordinals != nil {
		finding.Ordinals = fmt.Sprintf("start:%d", ss.Spec.Ordinals.Start)
	}

	// Analyze VolumeClaimTemplates
	for _, vct := range ss.Spec.VolumeClaimTemplates {
		vci := VolumeClaimInfo{
			Name: vct.Name,
		}

		if vct.Spec.StorageClassName != nil {
			vci.StorageClass = *vct.Spec.StorageClassName
			if !Contains(finding.StorageClasses, vci.StorageClass) {
				finding.StorageClasses = append(finding.StorageClasses, vci.StorageClass)
			}
		}

		for _, mode := range vct.Spec.AccessModes {
			modeStr := string(mode)
			vci.AccessModes = append(vci.AccessModes, modeStr)

			// ReadWriteMany can be a security risk
			if mode == corev1.ReadWriteMany {
				finding.DangerousAccessModes = append(finding.DangerousAccessModes, vct.Name)
				finding.SecurityIssues = append(finding.SecurityIssues,
					fmt.Sprintf("PVC %s has ReadWriteMany access mode (pod escape risk)", vct.Name))
			}
		}

		if storage, ok := vct.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			vci.Size = storage.String()
		}

		finding.VolumeClaimTemplates = append(finding.VolumeClaimTemplates, vci)
	}

	finding.TotalPVCCount = len(finding.VolumeClaimTemplates) * int(finding.Replicas)
	if len(finding.VolumeClaimTemplates) > 0 {
		finding.PVCStorageSize = finding.VolumeClaimTemplates[0].Size
	}

	// Analyze volumes
	for _, vol := range ss.Spec.Template.Spec.Volumes {
		if vol.HostPath != nil {
			finding.HostPathVolumes = append(finding.HostPathVolumes, vol.Name)
			finding.DangerousVolumes = append(finding.DangerousVolumes, fmt.Sprintf("HostPath:%s->%s", vol.Name, vol.HostPath.Path))
			finding.SecurityIssues = append(finding.SecurityIssues,
				fmt.Sprintf("HostPath volume %s mounts %s (node escape risk)", vol.Name, vol.HostPath.Path))
		}
		if vol.EmptyDir != nil {
			finding.EmptyDirVolumes = append(finding.EmptyDirVolumes, vol.Name)
		}
		if vol.Secret != nil {
			finding.SecretVolumes = append(finding.SecretVolumes, vol.Name)
		}
		if vol.ConfigMap != nil {
			finding.ConfigMapVolumes = append(finding.ConfigMapVolumes, vol.Name)
		}
	}

	// Analyze containers (including init and ephemeral)
	allContainers := append([]corev1.Container{}, ss.Spec.Template.Spec.Containers...)
	for _, c := range ss.Spec.Template.Spec.InitContainers {
		allContainers = append(allContainers, c)
	}
	for _, c := range ss.Spec.Template.Spec.EphemeralContainers {
		allContainers = append(allContainers, corev1.Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: c.SecurityContext,
		})
	}

	for _, container := range allContainers {
		// Privileged
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			finding.PrivilegedContainers++
		}

		// RunAsRoot check
		if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil {
			if *container.SecurityContext.RunAsUser == 0 {
				finding.RunAsRoot++
			}
		} else {
			// If not specified, assume root (default)
			finding.RunAsRoot++
		}

		// ReadOnlyRootFilesystem
		if container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil && *container.SecurityContext.ReadOnlyRootFilesystem {
			finding.ReadOnlyRootFilesystem++
		}

		// AllowPrivilegeEscalation
		if container.SecurityContext != nil && container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			finding.AllowPrivilegeEscalation++
		}

		// Capabilities
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				capStr := string(cap)
				if !Contains(finding.Capabilities, capStr) {
					finding.Capabilities = append(finding.Capabilities, capStr)
				}
			}
		}

		// Resource limits
		if container.Resources.Limits != nil && len(container.Resources.Limits) > 0 {
			finding.HasResourceLimits = true
			if cpu, ok := container.Resources.Limits[corev1.ResourceCPU]; ok {
				finding.LimitsCPU = cpu.String()
			}
			if mem, ok := container.Resources.Limits[corev1.ResourceMemory]; ok {
				finding.LimitsMemory = mem.String()
			}
		}

		if container.Resources.Requests != nil && len(container.Resources.Requests) > 0 {
			finding.HasResourceRequests = true
			if cpu, ok := container.Resources.Requests[corev1.ResourceCPU]; ok {
				finding.RequestsCPU = cpu.String()
			}
			if mem, ok := container.Resources.Requests[corev1.ResourceMemory]; ok {
				finding.RequestsMemory = mem.String()
			}
		}
	}

	// Host access
	finding.HostPID = ss.Spec.Template.Spec.HostPID
	finding.HostIPC = ss.Spec.Template.Spec.HostIPC
	finding.HostNetwork = ss.Spec.Template.Spec.HostNetwork

	// Service account
	finding.ServiceAccount = ss.Spec.Template.Spec.ServiceAccountName

	// Cloud role detection
	roleResults := k8sinternal.DetectCloudRole(
		ctx,
		clientset,
		ss.Namespace,
		ss.Spec.Template.Spec.ServiceAccountName,
		&ss.Spec.Template.Spec,
		ss.Spec.Template.Annotations,
	)

	if len(roleResults) > 0 {
		finding.CloudProvider = roleResults[0].Provider
		finding.CloudRole = roleResults[0].Role
	}

	// Add security issues
	if finding.PrivilegedContainers > 0 {
		finding.SecurityIssues = append(finding.SecurityIssues,
			fmt.Sprintf("%d privileged containers", finding.PrivilegedContainers))
	}

	if finding.HostPID {
		finding.SecurityIssues = append(finding.SecurityIssues, "HostPID enabled (can see all node processes)")
	}

	if finding.HostIPC {
		finding.SecurityIssues = append(finding.SecurityIssues, "HostIPC enabled (shared IPC namespace)")
	}

	if finding.HostNetwork {
		finding.SecurityIssues = append(finding.SecurityIssues, "HostNetwork enabled (bypasses network policies)")
	}

	if finding.RunAsRoot > 0 {
		finding.SecurityIssues = append(finding.SecurityIssues,
			fmt.Sprintf("%d containers running as root", finding.RunAsRoot))
	}

	if !finding.HasResourceLimits {
		finding.SecurityIssues = append(finding.SecurityIssues, "No resource limits (DoS risk)")
	}

	if finding.Partition > 0 {
		finding.SecurityIssues = append(finding.SecurityIssues,
			fmt.Sprintf("Partition set to %d (pods may be on old versions)", finding.Partition))
	}

	// Calculate risk
	finding.RiskLevel, finding.RiskScore = calculateStatefulSetRisk(&finding)
	finding.ImpactSummary = generateStatefulSetImpact(&finding)

	return finding
}

func calculateStatefulSetRisk(finding *StatefulSetFinding) (string, int) {
	score := 0

	// StatefulSets are inherently higher risk (critical data)
	score += 10

	// Privileged containers
	if finding.PrivilegedContainers > 0 {
		score += 40
	}

	// Host access
	if finding.HostPID {
		score += 25
	}
	if finding.HostIPC {
		score += 20
	}
	if finding.HostNetwork {
		score += 30
	}

	// Dangerous volumes
	if len(finding.HostPathVolumes) > 0 {
		score += 35 // HostPath = node escape
	}

	// RunAsRoot
	if finding.RunAsRoot > 0 {
		score += finding.RunAsRoot * 5
	}

	// Dangerous access modes
	if len(finding.DangerousAccessModes) > 0 {
		score += 20
	}

	// No resource limits
	if !finding.HasResourceLimits {
		score += 15
	}

	// Risky update strategy
	if finding.Partition > 0 {
		score += 10 // Partitioned updates can leave inconsistent state
	}

	// Capabilities
	for _, cap := range finding.Capabilities {
		if cap == "SYS_ADMIN" || cap == "NET_ADMIN" {
			score += 20
		}
	}

	// Determine risk level
	if score >= 80 {
		return "CRITICAL", statefulSetsMin(score, 100)
	} else if score >= 50 {
		return "HIGH", score
	} else if score >= 25 {
		return "MEDIUM", score
	}
	return "LOW", score
}

func generateStatefulSetImpact(finding *StatefulSetFinding) string {
	if finding.RiskLevel == "CRITICAL" {
		return fmt.Sprintf("CRITICAL stateful workload with %d security issues", len(finding.SecurityIssues))
	}

	if finding.PrivilegedContainers > 0 && len(finding.HostPathVolumes) > 0 {
		return "Privileged containers with HostPath access = full node compromise"
	}

	if finding.TotalPVCCount > 0 {
		return fmt.Sprintf("Manages %d PVCs (%s each) - data persistence risk", finding.TotalPVCCount, finding.PVCStorageSize)
	}

	return fmt.Sprintf("%d replicas with %d security issues", finding.Replicas, len(finding.SecurityIssues))
}

func generateStatefulSetLoot(finding *StatefulSetFinding, lootEnum, lootPVCs, lootPrivileged,
	lootDataPersistence, lootRiskyUpdates, lootRemediation *[]string) {

	ns := finding.Namespace
	name := finding.Name

	// Enumeration
	*lootEnum = append(*lootEnum, fmt.Sprintf("\n# [%s] StatefulSet: %s/%s", finding.RiskLevel, ns, name))
	*lootEnum = append(*lootEnum, fmt.Sprintf("# Replicas: %d | PVCs: %d | Risk Score: %d",
		finding.Replicas, finding.TotalPVCCount, finding.RiskScore))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get statefulset %s -n %s -o yaml", name, ns))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl describe statefulset %s -n %s", name, ns))
	*lootEnum = append(*lootEnum, "")

	// PVCs
	if finding.TotalPVCCount > 0 {
		*lootPVCs = append(*lootPVCs, fmt.Sprintf("\n### %s/%s - %d PVCs", ns, name, finding.TotalPVCCount))
		*lootPVCs = append(*lootPVCs, fmt.Sprintf("# Storage: %s | Classes: %s",
			finding.PVCStorageSize, strings.Join(finding.StorageClasses, ",")))
		*lootPVCs = append(*lootPVCs, fmt.Sprintf("kubectl get pvc -n %s -l app=%s", ns, name))
		*lootPVCs = append(*lootPVCs, fmt.Sprintf("# Backup PVCs:"))
		*lootPVCs = append(*lootPVCs, fmt.Sprintf("kubectl get pvc -n %s -o json | jq -r '.items[] | select(.metadata.labels.app==\"%s\")'", ns, name))
		*lootPVCs = append(*lootPVCs, "")
	}

	// Privileged
	if finding.PrivilegedContainers > 0 || len(finding.HostPathVolumes) > 0 {
		*lootPrivileged = append(*lootPrivileged, fmt.Sprintf("\n### [%s] %s/%s - Privileged Access",
			finding.RiskLevel, ns, name))
		*lootPrivileged = append(*lootPrivileged, fmt.Sprintf("# Privileged: %d | HostPath: %d",
			finding.PrivilegedContainers, len(finding.HostPathVolumes)))
		if len(finding.HostPathVolumes) > 0 {
			*lootPrivileged = append(*lootPrivileged, fmt.Sprintf("# HostPath volumes: %s",
				strings.Join(finding.DangerousVolumes, ", ")))
		}
		*lootPrivileged = append(*lootPrivileged, "")
	}

	// Data persistence
	if finding.TotalPVCCount > 0 {
		*lootDataPersistence = append(*lootDataPersistence, fmt.Sprintf("\n### %s/%s - Data Persistence", ns, name))
		*lootDataPersistence = append(*lootDataPersistence, fmt.Sprintf("# Total PVCs: %d (%d replicas × %d templates)",
			finding.TotalPVCCount, finding.Replicas, len(finding.VolumeClaimTemplates)))
		*lootDataPersistence = append(*lootDataPersistence, "# CRITICAL: Review backup and disaster recovery plans")
		*lootDataPersistence = append(*lootDataPersistence, fmt.Sprintf("kubectl get pvc -n %s", ns))
		*lootDataPersistence = append(*lootDataPersistence, "")
	}

	// Risky updates
	if finding.Partition > 0 || finding.PodManagementPolicy == "Parallel" {
		*lootRiskyUpdates = append(*lootRiskyUpdates, fmt.Sprintf("\n### %s/%s - Update Strategy: %s",
			ns, name, finding.UpdateStrategy))
		if finding.Partition > 0 {
			*lootRiskyUpdates = append(*lootRiskyUpdates, fmt.Sprintf("# Partition: %d (only pods >= %d will be updated)",
				finding.Partition, finding.Partition))
		}
		*lootRiskyUpdates = append(*lootRiskyUpdates, fmt.Sprintf("# PodManagementPolicy: %s", finding.PodManagementPolicy))
		*lootRiskyUpdates = append(*lootRiskyUpdates, "")
	}

	// Remediation
	if len(finding.SecurityIssues) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n### %s/%s - %d Security Issues",
			ns, name, len(finding.SecurityIssues)))
		for _, issue := range finding.SecurityIssues {
			*lootRemediation = append(*lootRemediation, fmt.Sprintf("# - %s", issue))
		}
		*lootRemediation = append(*lootRemediation, "# Remediation steps:")

		if finding.PrivilegedContainers > 0 {
			*lootRemediation = append(*lootRemediation, "# 1. Remove privileged: true from container securityContext")
		}
		if finding.RunAsRoot > 0 {
			*lootRemediation = append(*lootRemediation, "# 2. Set runAsNonRoot: true and runAsUser: 1000")
		}
		if !finding.HasResourceLimits {
			*lootRemediation = append(*lootRemediation, "# 3. Add resource limits to prevent resource exhaustion")
		}
		if len(finding.HostPathVolumes) > 0 {
			*lootRemediation = append(*lootRemediation, "# 4. Replace HostPath volumes with PVCs")
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}

func statefulSetsMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
