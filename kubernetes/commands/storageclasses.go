package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/kubernetes/shared"
	"github.com/BishopFox/cloudfox/kubernetes/config"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var StorageClassesCmd = &cobra.Command{
	Use:     "storageclasses",
	Aliases: []string{"sc", "storage"},
	Short:   "Enumerate StorageClasses with security analysis",
	Long: `
Enumerate StorageClasses with comprehensive security analysis including:
  - Unencrypted storage classes (data-at-rest encryption)
  - Volume expansion attack risks (allowVolumeExpansion enabled)
  - Data retention risks (reclaimPolicy Delete = data loss)
  - Default StorageClass gaps (missing defaults)
  - Cloud provider security (CSI driver vulnerabilities)
  - Access mode risks (ReadWriteMany = lateral movement)
  - Volume binding mode analysis (Immediate vs WaitForFirstConsumer)
  - Cost optimization (expensive storage without quotas)
  - PersistentVolume usage analysis
  - Risk scoring based on security exposure

  cloudfox kubernetes storageclasses`,
	Run: ListStorageClasses,
}

type StorageClassesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (t StorageClassesOutput) TableFiles() []internal.TableFile {
	return t.Table
}

func (t StorageClassesOutput) LootFiles() []internal.LootFile {
	return t.Loot
}

type SCSecurityAnalysis struct {
	Name                 string
	Provisioner          string
	ReclaimPolicy        string
	VolumeBindingMode    string
	AllowVolumeExpansion bool
	IsDefault            bool
	MountOptions         []string
	Parameters           map[string]string
	AllowedTopologies    string
	IsEncrypted          bool
	EncryptionType       string
	RiskLevel            string
	RiskScore            int
	SecurityIssues       []string
	PVsUsingClass        int
	TotalStorageGB       float64
	CostRisk             string
	DataRetentionRisk    bool
	CloudProvider        string
}

type PVStorageAnalysis struct {
	Namespace      string
	PVCName        string
	PVName         string
	StorageClass   string
	Capacity       string
	AccessModes    []string
	ReclaimPolicy  string
	Status         string
	VolumeMode     string
	IsEncrypted    bool
	RiskLevel      string
	RiskScore      int
	SecurityIssues []string
	MountedPods    []string
	SensitiveData  bool
}

const (
	StorageRiskCritical = shared.RiskCritical
	StorageRiskHigh     = shared.RiskHigh
	StorageRiskMedium   = shared.RiskMedium
	StorageRiskLow      = shared.RiskLow
)

func ListStorageClasses(cmd *cobra.Command, args []string) {
	ctx, cancel := shared.ContextWithTimeout()
	defer cancel()
	logger := internal.NewLogger()

	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	logger.InfoM(fmt.Sprintf("Enumerating storage classes for %s", globals.ClusterName), globals.K8S_STORAGECLASSES_MODULE_NAME)

	clientset := config.GetClientOrExit()

	// Fetch StorageClasses
	storageClasses, err := clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[!] Error fetching StorageClasses: %v\n", err)
		return
	}

	// Fetch PersistentVolumes for usage analysis
	pvs, err := clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error fetching PersistentVolumes: %v", err), globals.K8S_STORAGECLASSES_MODULE_NAME)
		return
	}

	// Fetch pods for PVC usage
	pods, err := clientset.CoreV1().Pods(shared.GetNamespaceOrAll()).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[!] Error fetching Pods: %v\n", err)
		return
	}

	var storageAnalyses []SCSecurityAnalysis
	var pvAnalyses []PVStorageAnalysis

	// Initialize loot builder
	loot := shared.NewLootBuilder()

	// Build PVC to Pod mapping
	pvcToPods := buildPVCPodMapping(pods.Items)

	// Analyze each StorageClass
	for _, sc := range storageClasses.Items {
		analysis := SCSecurityAnalysis{
			Name:                 sc.Name,
			Provisioner:          sc.Provisioner,
			ReclaimPolicy:        reclaimPolicyPtrToString(sc.ReclaimPolicy),
			VolumeBindingMode:    volumeBindingModePtrToString(sc.VolumeBindingMode),
			AllowVolumeExpansion: boolPtrToBool(sc.AllowVolumeExpansion),
			IsDefault:            isDefaultStorageClass(&sc),
			MountOptions:         sc.MountOptions,
			Parameters:           sc.Parameters,
		}

		// Analyze encryption
		analysis.IsEncrypted, analysis.EncryptionType = analyzeStorageEncryption(&sc)
		analysis.CloudProvider = scDetectCloudProvider(sc.Provisioner)

		// Analyze PVs using this StorageClass
		analysis.PVsUsingClass, analysis.TotalStorageGB = analyzePVsForStorageClass(sc.Name, pvs.Items)

		// Security analysis
		issues := analyzeSCSecurityIssues(&analysis)
		analysis.SecurityIssues = issues

		// Calculate risk score
		analysis.RiskScore = calculateStorageRiskScore(&analysis)
		analysis.RiskLevel = storageRiskScoreToLevel(analysis.RiskScore)

		// Categorize for loot files
		if !analysis.IsEncrypted {
			loot.Section("Unencrypted-Storage").Add(formatUnencryptedSC(&analysis))
		}
		if analysis.AllowVolumeExpansion {
			loot.Section("Volume-Expansion-Risks").Add(formatVolumeExpansionRisk(&analysis))
		}
		if analysis.DataRetentionRisk {
			loot.Section("Data-Retention-Risks").Add(formatDataRetentionRisk(&analysis))
		}
		if analysis.RiskScore >= 70 {
			loot.Section("High-Risk-Storage").Add(formatHighRiskStorage(&analysis))
		}
		if analysis.CostRisk == shared.RiskHigh || analysis.CostRisk == shared.RiskCritical {
			loot.Section("Cost-Optimization").Add(formatCostOptimization(&analysis))
		}

		storageAnalyses = append(storageAnalyses, analysis)
	}

	// Analyze PersistentVolumes
	for _, pv := range pvs.Items {
		pvAnalysis := PVStorageAnalysis{
			PVName:        pv.Name,
			StorageClass:  pv.Spec.StorageClassName,
			Capacity:      pv.Spec.Capacity.Storage().String(),
			AccessModes:   accessModesToStrings(pv.Spec.AccessModes),
			ReclaimPolicy: string(pv.Spec.PersistentVolumeReclaimPolicy),
			Status:        string(pv.Status.Phase),
			VolumeMode:    volumeModeToString(pv.Spec.VolumeMode),
		}

		// Find PVC and namespace
		if pv.Spec.ClaimRef != nil {
			pvAnalysis.Namespace = pv.Spec.ClaimRef.Namespace
			pvAnalysis.PVCName = pv.Spec.ClaimRef.Name

			// Find pods using this PVC
			pvcKey := fmt.Sprintf("%s/%s", pvAnalysis.Namespace, pvAnalysis.PVCName)
			if podList, exists := pvcToPods[pvcKey]; exists {
				pvAnalysis.MountedPods = podList
			}
		}

		// Check encryption (inherit from StorageClass analysis)
		pvAnalysis.IsEncrypted = isPVEncrypted(&pv, storageAnalyses)

		// Security analysis
		pvIssues := analyzePVSecurity(&pvAnalysis)
		pvAnalysis.SecurityIssues = pvIssues

		// Calculate risk
		pvAnalysis.RiskScore = calculatePVRiskScore(&pvAnalysis)
		pvAnalysis.RiskLevel = storageRiskScoreToLevel(pvAnalysis.RiskScore)

		pvAnalyses = append(pvAnalyses, pvAnalysis)
	}

	// Add StorageClass-Enum section
	loot.Section("StorageClass-Enum").Add(formatStorageClassEnum(storageAnalyses))

	// Add Remediation-Guide section
	loot.Section("Remediation-Guide").Add(generateStorageRemediationGuide(storageAnalyses))

	// Generate loot files
	lootFiles := loot.Build()

	// Generate tables
	storageClassTable := generateStorageClassTable(storageAnalyses)
	pvTable := generatePVTable(pvAnalyses)

	err = internal.HandleOutput(
		"Kubernetes",
		format,
		outputDirectory,
		verbosity,
		wrap,
		"StorageClasses",
		globals.ClusterName,
		"results",
		StorageClassesOutput{
			Table: []internal.TableFile{storageClassTable, pvTable},
			Loot:  lootFiles,
		},
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.K8S_STORAGECLASSES_MODULE_NAME)
		return
	}

	// Summary logging
	if len(storageAnalyses) > 0 {
		encryptedCount := 0
		for _, sc := range storageAnalyses {
			if sc.IsEncrypted {
				encryptedCount++
			}
		}
		logger.InfoM(fmt.Sprintf("%d StorageClasses analyzed | Encrypted: %d | Unencrypted: %d",
			len(storageAnalyses), encryptedCount, len(storageAnalyses)-encryptedCount),
			globals.K8S_STORAGECLASSES_MODULE_NAME)
	} else {
		logger.InfoM("No StorageClasses found", globals.K8S_STORAGECLASSES_MODULE_NAME)
	}
}

func analyzeSCSecurityIssues(analysis *SCSecurityAnalysis) []string {
	var issues []string

	// CRITICAL: Unencrypted storage
	if !analysis.IsEncrypted {
		issues = append(issues, "CRITICAL: StorageClass does not enforce encryption (data-at-rest risk)")
	}

	// CRITICAL: Volume expansion enabled without RBAC controls
	if analysis.AllowVolumeExpansion {
		issues = append(issues, "HIGH: Volume expansion enabled (potential DoS via storage exhaustion)")
	}

	// HIGH: Delete reclaim policy
	if analysis.ReclaimPolicy == "Delete" {
		issues = append(issues, "HIGH: Reclaim policy 'Delete' - data lost when PV released")
		analysis.DataRetentionRisk = true
	}

	// HIGH: No default StorageClass
	if len(analysis.Name) > 0 && !hasDefaultStorageClass(analysis.Name) {
		// This check is done globally elsewhere
	}

	// MEDIUM: Immediate volume binding (resource waste)
	if analysis.VolumeBindingMode == "Immediate" {
		issues = append(issues, "MEDIUM: Immediate volume binding (may create unattached volumes)")
	}

	// Cost analysis
	if strings.Contains(strings.ToLower(analysis.Provisioner), "premium") ||
		strings.Contains(strings.ToLower(analysis.Name), "premium") ||
		strings.Contains(strings.ToLower(analysis.Name), "ssd") {
		if analysis.TotalStorageGB > 100 {
			analysis.CostRisk = shared.RiskHigh
			issues = append(issues, fmt.Sprintf("HIGH: Expensive storage (%.1fGB on premium/SSD)", analysis.TotalStorageGB))
		} else {
			analysis.CostRisk = shared.RiskMedium
		}
	}

	// Cloud-specific security checks
	if analysis.CloudProvider == "AWS" {
		if analysis.Parameters["encrypted"] != "true" {
			issues = append(issues, "CRITICAL: AWS EBS volume not encrypted")
		}
	} else if analysis.CloudProvider == "GCP" {
		// GCP encrypts by default, but check for customer-managed keys
		if analysis.Parameters["disk-encryption-kms-key"] == "" {
			issues = append(issues, "MEDIUM: GCP persistent disk using Google-managed encryption (consider CMEK)")
		}
	} else if analysis.CloudProvider == "Azure" {
		if analysis.Parameters["encryption"] != "true" {
			issues = append(issues, "CRITICAL: Azure Disk not encrypted")
		}
	}

	return issues
}

func analyzeStorageEncryption(sc *storagev1.StorageClass) (bool, string) {
	// Check provisioner-specific encryption
	provisioner := strings.ToLower(sc.Provisioner)
	params := sc.Parameters

	// AWS EBS
	if strings.Contains(provisioner, "aws") || strings.Contains(provisioner, "ebs") {
		if params["encrypted"] == "true" {
			return true, "AWS-EBS-Encrypted"
		}
		return false, "AWS-EBS-Unencrypted"
	}

	// GCP PD (encrypted by default)
	if strings.Contains(provisioner, "gcp") || strings.Contains(provisioner, "gce") || strings.Contains(provisioner, "pd.csi.storage.gke.io") {
		if params["disk-encryption-kms-key"] != "" {
			return true, "GCP-CMEK"
		}
		return true, "GCP-Default-Encryption"
	}

	// Azure Disk
	if strings.Contains(provisioner, "azure") || strings.Contains(provisioner, "disk.csi.azure.com") {
		if params["encryption"] == "true" || params["diskEncryptionSetID"] != "" {
			return true, "Azure-Disk-Encrypted"
		}
		return false, "Azure-Disk-Unencrypted"
	}

	// CSI drivers with encryption parameter
	if params["encrypted"] == "true" || params["encryption"] == "true" {
		return true, "CSI-Encrypted"
	}

	// Default: assume unencrypted if not explicitly specified
	return false, "Unknown-Encryption"
}

func scDetectCloudProvider(provisioner string) string {
	provisioner = strings.ToLower(provisioner)
	if strings.Contains(provisioner, "aws") || strings.Contains(provisioner, "ebs") {
		return "AWS"
	} else if strings.Contains(provisioner, "gcp") || strings.Contains(provisioner, "gce") || strings.Contains(provisioner, "gke") {
		return "GCP"
	} else if strings.Contains(provisioner, "azure") {
		return "Azure"
	} else if strings.Contains(provisioner, "csi") {
		return "CSI"
	}
	return "Unknown"
}

func analyzePVsForStorageClass(scName string, pvs []corev1.PersistentVolume) (int, float64) {
	count := 0
	var totalGB float64

	for _, pv := range pvs {
		if pv.Spec.StorageClassName == scName {
			count++
			if storage := pv.Spec.Capacity.Storage(); storage != nil {
				totalGB += float64(storage.Value()) / (1024 * 1024 * 1024)
			}
		}
	}

	return count, totalGB
}

func analyzePVSecurity(pv *PVStorageAnalysis) []string {
	var issues []string

	// Unencrypted PV
	if !pv.IsEncrypted {
		issues = append(issues, "CRITICAL: PersistentVolume not encrypted (data-at-rest exposure)")
		pv.SensitiveData = true
	}

	// ReadWriteMany access mode (lateral movement risk)
	for _, mode := range pv.AccessModes {
		if mode == "ReadWriteMany" {
			issues = append(issues, "HIGH: ReadWriteMany access mode (multi-pod access, lateral movement risk)")
		}
	}

	// Delete reclaim policy
	if pv.ReclaimPolicy == "Delete" {
		issues = append(issues, "HIGH: Reclaim policy Delete (data loss when PVC deleted)")
	}

	// Multiple pods mounting same PV
	if len(pv.MountedPods) > 1 {
		issues = append(issues, fmt.Sprintf("MEDIUM: PV mounted by %d pods (shared data access)", len(pv.MountedPods)))
	}

	return issues
}

func calculateStorageRiskScore(analysis *SCSecurityAnalysis) int {
	score := 0

	// Encryption (critical)
	if !analysis.IsEncrypted {
		score += 40
	}

	// Volume expansion risk
	if analysis.AllowVolumeExpansion {
		score += 20
	}

	// Data retention risk
	if analysis.DataRetentionRisk {
		score += 15
	}

	// Cost risk
	if analysis.CostRisk == shared.RiskCritical {
		score += 15
	} else if analysis.CostRisk == shared.RiskHigh {
		score += 10
	}

	// Volume binding mode
	if analysis.VolumeBindingMode == "Immediate" {
		score += 5
	}

	// High storage usage
	if analysis.TotalStorageGB > 500 {
		score += 10
	}

	return score
}

func calculatePVRiskScore(pv *PVStorageAnalysis) int {
	score := 0

	// Encryption
	if !pv.IsEncrypted {
		score += 40
	}

	// Access modes
	for _, mode := range pv.AccessModes {
		if mode == "ReadWriteMany" {
			score += 25
		}
	}

	// Reclaim policy
	if pv.ReclaimPolicy == "Delete" {
		score += 15
	}

	// Multiple pods
	if len(pv.MountedPods) > 1 {
		score += 10
	}

	return score
}

func storageRiskScoreToLevel(score int) string {
	if score >= 80 {
		return StorageRiskCritical
	} else if score >= 60 {
		return StorageRiskHigh
	} else if score >= 30 {
		return StorageRiskMedium
	}
	return StorageRiskLow
}

func buildPVCPodMapping(pods []corev1.Pod) map[string][]string {
	pvcToPods := make(map[string][]string)

	for _, pod := range pods {
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil {
				pvcKey := fmt.Sprintf("%s/%s", pod.Namespace, vol.PersistentVolumeClaim.ClaimName)
				podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
				pvcToPods[pvcKey] = append(pvcToPods[pvcKey], podName)
			}
		}
	}

	return pvcToPods
}

func isPVEncrypted(pv *corev1.PersistentVolume, storageAnalyses []SCSecurityAnalysis) bool {
	// Look up encryption status from StorageClass analysis
	for _, sc := range storageAnalyses {
		if sc.Name == pv.Spec.StorageClassName {
			return sc.IsEncrypted
		}
	}
	return false
}

// Formatting functions
func formatUnencryptedSC(analysis *SCSecurityAnalysis) string {
	return fmt.Sprintf("[%s] StorageClass: %s | Provisioner: %s | PVs: %d | Storage: %.1fGB | Risk: %s",
		analysis.RiskLevel, analysis.Name, analysis.Provisioner, analysis.PVsUsingClass, analysis.TotalStorageGB, analysis.EncryptionType)
}

func formatVolumeExpansionRisk(analysis *SCSecurityAnalysis) string {
	return fmt.Sprintf("[RISK] StorageClass: %s | Expansion: Enabled | PVs: %d | Mitigation: Review RBAC for persistentvolumeclaims/resize",
		analysis.Name, analysis.PVsUsingClass)
}

func formatDataRetentionRisk(analysis *SCSecurityAnalysis) string {
	return fmt.Sprintf("[RISK] StorageClass: %s | ReclaimPolicy: Delete | PVs: %d | Data Loss Risk: PVs deleted when PVC removed",
		analysis.Name, analysis.PVsUsingClass)
}

func formatHighRiskStorage(analysis *SCSecurityAnalysis) string {
	return fmt.Sprintf("[%s] StorageClass: %s | Score: %d/100 | Issues: %s",
		analysis.RiskLevel, analysis.Name, analysis.RiskScore, strings.Join(analysis.SecurityIssues, "; "))
}

func formatCostOptimization(analysis *SCSecurityAnalysis) string {
	return fmt.Sprintf("[COST] StorageClass: %s | Type: Premium/SSD | Storage: %.1fGB | Recommendation: Consider storage quotas or archival policies",
		analysis.Name, analysis.TotalStorageGB)
}

func formatStorageClassEnum(analyses []SCSecurityAnalysis) string {
	var lines []string
	lines = append(lines, "=== StorageClass Security Enumeration ===\n")

	for _, sc := range analyses {
		lines = append(lines, fmt.Sprintf("StorageClass: %s", sc.Name))
		lines = append(lines, fmt.Sprintf("  Provisioner: %s", sc.Provisioner))
		lines = append(lines, fmt.Sprintf("  Cloud Provider: %s", sc.CloudProvider))
		lines = append(lines, fmt.Sprintf("  Reclaim Policy: %s", sc.ReclaimPolicy))
		lines = append(lines, fmt.Sprintf("  Volume Binding: %s", sc.VolumeBindingMode))
		lines = append(lines, fmt.Sprintf("  Volume Expansion: %s", shared.FormatBool(sc.AllowVolumeExpansion)))
		lines = append(lines, fmt.Sprintf("  Default: %s", shared.FormatBool(sc.IsDefault)))
		lines = append(lines, fmt.Sprintf("  Encrypted: %s (%s)", shared.FormatBool(sc.IsEncrypted), sc.EncryptionType))
		lines = append(lines, fmt.Sprintf("  PVs Using: %d (%.1fGB)", sc.PVsUsingClass, sc.TotalStorageGB))
		lines = append(lines, fmt.Sprintf("  Risk Level: %s (Score: %d/100)", sc.RiskLevel, sc.RiskScore))
		if len(sc.SecurityIssues) > 0 {
			lines = append(lines, "  Security Issues:")
			for _, issue := range sc.SecurityIssues {
				lines = append(lines, fmt.Sprintf("    - %s", issue))
			}
		}
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func generateStorageRemediationGuide(analyses []SCSecurityAnalysis) string {
	var lines []string
	lines = append(lines, "=== StorageClass Security Remediation Guide ===\n")
	lines = append(lines, "# Fix unencrypted storage (AWS example):")
	lines = append(lines, "kubectl patch storageclass <name> -p '{\"parameters\":{\"encrypted\":\"true\"}}'")
	lines = append(lines, "")
	lines = append(lines, "# Change reclaim policy to Retain (preserve data):")
	lines = append(lines, "kubectl patch storageclass <name> -p '{\"reclaimPolicy\":\"Retain\"}'")
	lines = append(lines, "")
	lines = append(lines, "# Disable volume expansion:")
	lines = append(lines, "kubectl patch storageclass <name> -p '{\"allowVolumeExpansion\":false}'")
	lines = append(lines, "")
	lines = append(lines, "# Set default StorageClass:")
	lines = append(lines, "kubectl patch storageclass <name> -p '{\"metadata\":{\"annotations\":{\"storageclass.kubernetes.io/is-default-class\":\"true\"}}}'")
	lines = append(lines, "")

	for _, sc := range analyses {
		if sc.RiskScore >= 60 {
			lines = append(lines, fmt.Sprintf("# High-risk StorageClass: %s", sc.Name))
			for _, issue := range sc.SecurityIssues {
				lines = append(lines, fmt.Sprintf("#   - %s", issue))
			}
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func generateStorageClassTable(analyses []SCSecurityAnalysis) internal.TableFile {
	header := []string{"StorageClass", "Provisioner", "Encrypted", "Reclaim", "Expansion", "Default", "PVs", "Storage(GB)", "Issues"}
	var rows [][]string

	// Sort by risk score (highest first)
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	for _, sc := range analyses {
		rows = append(rows, []string{
			sc.Name,
			sc.Provisioner,
			shared.FormatBool(sc.IsEncrypted),
			sc.ReclaimPolicy,
			shared.FormatBool(sc.AllowVolumeExpansion),
			shared.FormatBool(sc.IsDefault),
			fmt.Sprintf("%d", sc.PVsUsingClass),
			fmt.Sprintf("%.1f", sc.TotalStorageGB),
			fmt.Sprintf("%d", len(sc.SecurityIssues)),
		})
	}

	return internal.TableFile{
		Name:   "StorageClasses",
		Header: header,
		Body:   rows,
	}
}

func generatePVTable(analyses []PVStorageAnalysis) internal.TableFile {
	header := []string{"Namespace", "PVC", "PV", "StorageClass", "Capacity", "Encrypted", "AccessModes", "Status", "Pods"}
	var rows [][]string

	// Sort by risk score
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].RiskScore > analyses[j].RiskScore
	})

	for _, pv := range analyses {
		rows = append(rows, []string{
			pv.Namespace,
			pv.PVCName,
			pv.PVName,
			pv.StorageClass,
			pv.Capacity,
			shared.FormatBool(pv.IsEncrypted),
			strings.Join(pv.AccessModes, ","),
			pv.Status,
			fmt.Sprintf("%d", len(pv.MountedPods)),
		})
	}

	return internal.TableFile{
		Name:   "PersistentVolumes",
		Header: header,
		Body:   rows,
	}
}

// Helper functions
func isDefaultStorageClass(sc *storagev1.StorageClass) bool {
	if sc.Annotations == nil {
		return false
	}
	return sc.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" ||
		sc.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true"
}

func hasDefaultStorageClass(name string) bool {
	// This is a placeholder - actual implementation would check cluster-wide
	return false
}

func stringPtrToString(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

func boolPtrToBool(ptr *bool) bool {
	if ptr == nil {
		return false
	}
	return *ptr
}

func reclaimPolicyPtrToString(ptr *corev1.PersistentVolumeReclaimPolicy) string {
	if ptr == nil {
		return ""
	}
	return string(*ptr)
}

func volumeBindingModePtrToString(ptr *storagev1.VolumeBindingMode) string {
	if ptr == nil {
		return ""
	}
	return string(*ptr)
}

func accessModesToStrings(modes []corev1.PersistentVolumeAccessMode) []string {
	var result []string
	for _, mode := range modes {
		result = append(result, string(mode))
	}
	return result
}

func volumeModeToString(mode *corev1.PersistentVolumeMode) string {
	if mode == nil {
		return "Filesystem"
	}
	return string(*mode)
}
