package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/sqladmin/v1beta4"
	"google.golang.org/api/storage/v1"
)

// Module name constant
const GCP_COSTSECURITY_MODULE_NAME string = "cost-security"

var GCPCostSecurityCommand = &cobra.Command{
	Use:     GCP_COSTSECURITY_MODULE_NAME,
	Aliases: []string{"cost", "cost-anomaly", "orphaned", "cryptomining"},
	Hidden:  true,
	Short:   "Identify cost anomalies, orphaned resources, and potential cryptomining activity",
	Long: `Analyze resources for cost-related security issues and waste.

Features:
- Detects potential cryptomining indicators (high CPU instances, GPUs)
- Identifies orphaned resources (unattached disks, unused IPs)
- Finds expensive idle resources
- Analyzes resource utilization patterns
- Identifies resources without cost allocation labels
- Detects unusual resource creation patterns

Requires appropriate IAM permissions:
- roles/compute.viewer
- roles/storage.admin
- roles/cloudsql.viewer`,
	Run: runGCPCostSecurityCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type CostAnomaly struct {
	Name         string
	ProjectID    string
	ResourceType string
	AnomalyType  string // cryptomining, orphaned, idle, unlabeled, unusual-creation
	Severity     string
	Details      string
	EstCostMonth float64
	CreatedTime  string
	Location     string
	Remediation  string
}

type OrphanedResource struct {
	Name         string
	ProjectID    string
	ResourceType string
	Location     string
	SizeGB       int64
	Status       string
	CreatedTime  string
	EstCostMonth float64
	Reason       string
}

type ExpensiveResource struct {
	Name         string
	ProjectID    string
	ResourceType string
	Location     string
	MachineType  string
	VCPUs        int64
	MemoryGB     float64
	GPUs         int
	Status       string
	CreatedTime  string
	Labels       map[string]string
	EstCostMonth float64
}

type CryptominingIndicator struct {
	Name         string
	ProjectID    string
	ResourceType string
	Location     string
	Indicator    string
	Confidence   string // HIGH, MEDIUM, LOW
	Details      string
	CreatedTime  string
	Remediation  string
}

// ------------------------------
// Module Struct
// ------------------------------
type CostSecurityModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	CostAnomalies  []CostAnomaly
	Orphaned       []OrphanedResource
	Expensive      []ExpensiveResource
	Cryptomining   []CryptominingIndicator
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex

	// Tracking
	totalEstCost     float64
	orphanedEstCost  float64
	cryptoIndicators int
}

// ------------------------------
// Output Struct
// ------------------------------
type CostSecurityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CostSecurityOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CostSecurityOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCostSecurityCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_COSTSECURITY_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &CostSecurityModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		CostAnomalies: []CostAnomaly{},
		Orphaned:      []OrphanedResource{},
		Expensive:     []ExpensiveResource{},
		Cryptomining:  []CryptominingIndicator{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CostSecurityModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing resources for cost anomalies and security issues...", GCP_COSTSECURITY_MODULE_NAME)

	// Create service clients
	computeService, err := compute.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Compute service: %v", err), GCP_COSTSECURITY_MODULE_NAME)
		return
	}

	storageService, err := storage.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Storage service: %v", err), GCP_COSTSECURITY_MODULE_NAME)
		}
	}

	sqlService, err := sqladmin.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create SQL service: %v", err), GCP_COSTSECURITY_MODULE_NAME)
		}
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, computeService, storageService, sqlService, logger)
		}(projectID)
	}
	wg.Wait()

	// Check results
	totalFindings := len(m.CostAnomalies) + len(m.Orphaned) + len(m.Cryptomining)
	if totalFindings == 0 {
		logger.InfoM("No cost anomalies or security issues found", GCP_COSTSECURITY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d cost anomaly(ies), %d orphaned resource(s), %d cryptomining indicator(s)",
		len(m.CostAnomalies), len(m.Orphaned), len(m.Cryptomining)), GCP_COSTSECURITY_MODULE_NAME)

	if len(m.Cryptomining) > 0 {
		logger.InfoM(fmt.Sprintf("[CRITICAL] %d potential cryptomining indicator(s) detected!", len(m.Cryptomining)), GCP_COSTSECURITY_MODULE_NAME)
	}

	if m.orphanedEstCost > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Estimated monthly cost of orphaned resources: $%.2f", m.orphanedEstCost), GCP_COSTSECURITY_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CostSecurityModule) processProject(ctx context.Context, projectID string, computeService *compute.Service, storageService *storage.Service, sqlService *sqladmin.Service, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing costs for project: %s", projectID), GCP_COSTSECURITY_MODULE_NAME)
	}

	// Analyze compute instances
	m.analyzeComputeInstances(ctx, projectID, computeService, logger)

	// Find orphaned disks
	m.findOrphanedDisks(ctx, projectID, computeService, logger)

	// Find orphaned IPs
	m.findOrphanedIPs(ctx, projectID, computeService, logger)

	// Analyze SQL instances
	if sqlService != nil {
		m.analyzeSQLInstances(ctx, projectID, sqlService, logger)
	}

	// Analyze storage buckets
	if storageService != nil {
		m.analyzeStorageBuckets(ctx, projectID, storageService, logger)
	}
}

func (m *CostSecurityModule) analyzeComputeInstances(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Instances.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, instanceList := range page.Items {
			if instanceList.Instances == nil {
				continue
			}
			for _, instance := range instanceList.Instances {
				m.analyzeInstance(instance, projectID, m.extractZoneFromURL(zone), logger)
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_COSTSECURITY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate compute instances in project %s", projectID))
	}
}

func (m *CostSecurityModule) analyzeInstance(instance *compute.Instance, projectID, zone string, logger internal.Logger) {
	machineType := m.extractMachineTypeName(instance.MachineType)
	vcpus, memGB := m.parseMachineType(machineType)

	// Count GPUs
	gpuCount := 0
	for _, accel := range instance.GuestAccelerators {
		gpuCount += int(accel.AcceleratorCount)
	}

	// Check for cryptomining indicators
	m.checkCryptominingIndicators(instance, projectID, zone, machineType, vcpus, memGB, gpuCount)

	// Check for expensive resources
	estCost := m.estimateInstanceCost(machineType, vcpus, memGB, gpuCount)
	if estCost > 500 { // Monthly threshold
		expensive := ExpensiveResource{
			Name:         instance.Name,
			ProjectID:    projectID,
			ResourceType: "compute-instance",
			Location:     zone,
			MachineType:  machineType,
			VCPUs:        vcpus,
			MemoryGB:     memGB,
			GPUs:         gpuCount,
			Status:       instance.Status,
			CreatedTime:  instance.CreationTimestamp,
			Labels:       instance.Labels,
			EstCostMonth: estCost,
		}

		m.mu.Lock()
		m.Expensive = append(m.Expensive, expensive)
		m.totalEstCost += estCost
		m.mu.Unlock()
	}

	// Check for unlabeled resources
	if len(instance.Labels) == 0 {
		anomaly := CostAnomaly{
			Name:         instance.Name,
			ProjectID:    projectID,
			ResourceType: "compute-instance",
			AnomalyType:  "unlabeled",
			Severity:     "LOW",
			Details:      "Instance has no cost allocation labels",
			EstCostMonth: estCost,
			CreatedTime:  instance.CreationTimestamp,
			Location:     zone,
			Remediation:  fmt.Sprintf("gcloud compute instances add-labels %s --labels=cost-center=UNKNOWN,owner=UNKNOWN --zone=%s --project=%s", instance.Name, zone, projectID),
		}

		m.mu.Lock()
		m.CostAnomalies = append(m.CostAnomalies, anomaly)
		m.mu.Unlock()
	}

	// Check for unusual creation times (off-hours)
	m.checkUnusualCreation(instance, projectID, zone, estCost)
}

func (m *CostSecurityModule) checkCryptominingIndicators(instance *compute.Instance, projectID, zone, machineType string, vcpus int64, memGB float64, gpuCount int) {
	indicators := []CryptominingIndicator{}

	// Indicator 1: GPU instance
	if gpuCount > 0 {
		indicator := CryptominingIndicator{
			Name:         instance.Name,
			ProjectID:    projectID,
			ResourceType: "compute-instance",
			Location:     zone,
			Indicator:    "GPU_INSTANCE",
			Confidence:   "MEDIUM",
			Details:      fmt.Sprintf("Instance has %d GPU(s) attached", gpuCount),
			CreatedTime:  instance.CreationTimestamp,
			Remediation:  "Verify this instance is authorized for GPU workloads",
		}
		indicators = append(indicators, indicator)
	}

	// Indicator 2: High CPU count
	if vcpus >= 32 {
		indicator := CryptominingIndicator{
			Name:         instance.Name,
			ProjectID:    projectID,
			ResourceType: "compute-instance",
			Location:     zone,
			Indicator:    "HIGH_CPU",
			Confidence:   "LOW",
			Details:      fmt.Sprintf("Instance has %d vCPUs (high compute capacity)", vcpus),
			CreatedTime:  instance.CreationTimestamp,
			Remediation:  "Verify this instance's CPU usage is legitimate",
		}
		indicators = append(indicators, indicator)
	}

	// Indicator 3: Preemptible/Spot with high specs (common for mining)
	if instance.Scheduling != nil && instance.Scheduling.Preemptible && (vcpus >= 8 || gpuCount > 0) {
		indicator := CryptominingIndicator{
			Name:         instance.Name,
			ProjectID:    projectID,
			ResourceType: "compute-instance",
			Location:     zone,
			Indicator:    "PREEMPTIBLE_HIGH_SPEC",
			Confidence:   "MEDIUM",
			Details:      "Preemptible instance with high specs (common mining pattern)",
			CreatedTime:  instance.CreationTimestamp,
			Remediation:  "Verify this preemptible instance is used for legitimate batch processing",
		}
		indicators = append(indicators, indicator)
	}

	// Indicator 4: Suspicious naming patterns
	nameLower := strings.ToLower(instance.Name)
	suspiciousPatterns := []string{"miner", "mining", "xmr", "monero", "btc", "ethereum", "eth", "crypto", "hash"}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(nameLower, pattern) {
			indicator := CryptominingIndicator{
				Name:         instance.Name,
				ProjectID:    projectID,
				ResourceType: "compute-instance",
				Location:     zone,
				Indicator:    "SUSPICIOUS_NAME",
				Confidence:   "HIGH",
				Details:      fmt.Sprintf("Instance name contains suspicious pattern: %s", pattern),
				CreatedTime:  instance.CreationTimestamp,
				Remediation:  "Investigate this instance immediately for cryptomining",
			}
			indicators = append(indicators, indicator)
			break
		}
	}

	// Indicator 5: N2D/C2 machine types (AMD EPYC - preferred for mining)
	if strings.HasPrefix(machineType, "n2d-") || strings.HasPrefix(machineType, "c2-") {
		if vcpus >= 16 {
			indicator := CryptominingIndicator{
				Name:         instance.Name,
				ProjectID:    projectID,
				ResourceType: "compute-instance",
				Location:     zone,
				Indicator:    "AMD_HIGH_CPU",
				Confidence:   "LOW",
				Details:      fmt.Sprintf("AMD EPYC instance with high CPU (%s)", machineType),
				CreatedTime:  instance.CreationTimestamp,
				Remediation:  "Verify legitimate use of AMD EPYC high-CPU instance",
			}
			indicators = append(indicators, indicator)
		}
	}

	// Add indicators to tracking
	m.mu.Lock()
	for _, ind := range indicators {
		m.Cryptomining = append(m.Cryptomining, ind)
		m.cryptoIndicators++

		// Add to loot
		m.LootMap["cost-security-commands"].Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# CRYPTOMINING INDICATOR: %s\n"+
				"# =============================================================================\n"+
				"# Project: %s\n"+
				"# Location: %s | Type: %s\n"+
				"# Investigate instance:\n"+
				"gcloud compute instances describe %s --zone=%s --project=%s\n"+
				"# Stop instance if suspicious:\n"+
				"gcloud compute instances stop %s --zone=%s --project=%s\n\n",
			ind.Name,
			ind.ProjectID,
			ind.Location, ind.Indicator,
			ind.Name, ind.Location, ind.ProjectID,
			ind.Name, ind.Location, ind.ProjectID,
		)
	}
	m.mu.Unlock()
}

func (m *CostSecurityModule) checkUnusualCreation(instance *compute.Instance, projectID, zone string, estCost float64) {
	createdTime, err := time.Parse(time.RFC3339, instance.CreationTimestamp)
	if err != nil {
		return
	}

	// Check if created during unusual hours (midnight to 5am local, or weekends)
	hour := createdTime.Hour()
	weekday := createdTime.Weekday()

	if (hour >= 0 && hour <= 5) || weekday == time.Saturday || weekday == time.Sunday {
		anomaly := CostAnomaly{
			Name:         instance.Name,
			ProjectID:    projectID,
			ResourceType: "compute-instance",
			AnomalyType:  "unusual-creation",
			Severity:     "MEDIUM",
			Details:      fmt.Sprintf("Instance created at unusual time: %s", createdTime.Format("Mon 2006-01-02 15:04")),
			EstCostMonth: estCost,
			CreatedTime:  instance.CreationTimestamp,
			Location:     zone,
			Remediation:  "Verify this instance creation was authorized",
		}

		m.mu.Lock()
		m.CostAnomalies = append(m.CostAnomalies, anomaly)
		m.mu.Unlock()
	}
}

func (m *CostSecurityModule) findOrphanedDisks(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Disks.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.DiskAggregatedList) error {
		for zone, diskList := range page.Items {
			if diskList.Disks == nil {
				continue
			}
			for _, disk := range diskList.Disks {
				// Check if disk is attached to any instance
				if len(disk.Users) == 0 {
					estCost := m.estimateDiskCost(disk.SizeGb, disk.Type)

					orphaned := OrphanedResource{
						Name:         disk.Name,
						ProjectID:    projectID,
						ResourceType: "compute-disk",
						Location:     m.extractZoneFromURL(zone),
						SizeGB:       disk.SizeGb,
						Status:       disk.Status,
						CreatedTime:  disk.CreationTimestamp,
						EstCostMonth: estCost,
						Reason:       "Disk not attached to any instance",
					}

					m.mu.Lock()
					m.Orphaned = append(m.Orphaned, orphaned)
					m.orphanedEstCost += estCost
					m.mu.Unlock()

					// Add cleanup command to loot
					m.mu.Lock()
					m.LootMap["cost-security-commands"].Contents += fmt.Sprintf(
						"# =============================================================================\n"+
							"# ORPHANED DISK: %s\n"+
							"# =============================================================================\n"+
							"# Project: %s\n"+
							"# Size: %dGB | Est. Cost: $%.2f/month\n"+
							"# Delete orphaned disk:\n"+
							"gcloud compute disks delete %s --zone=%s --project=%s\n\n",
						disk.Name,
						projectID,
						disk.SizeGb, estCost,
						disk.Name, m.extractZoneFromURL(zone), projectID,
					)
					m.mu.Unlock()
				}
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_COSTSECURITY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate disks in project %s", projectID))
	}
}

func (m *CostSecurityModule) findOrphanedIPs(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	// Global addresses
	req := computeService.Addresses.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.AddressAggregatedList) error {
		for region, addressList := range page.Items {
			if addressList.Addresses == nil {
				continue
			}
			for _, addr := range addressList.Addresses {
				// Check if address is in use
				if addr.Status == "RESERVED" && len(addr.Users) == 0 {
					// Static IP costs ~$7.2/month when not in use
					estCost := 7.2

					orphaned := OrphanedResource{
						Name:         addr.Name,
						ProjectID:    projectID,
						ResourceType: "static-ip",
						Location:     m.extractRegionFromURL(region),
						Status:       addr.Status,
						CreatedTime:  addr.CreationTimestamp,
						EstCostMonth: estCost,
						Reason:       "Static IP reserved but not attached",
					}

					m.mu.Lock()
					m.Orphaned = append(m.Orphaned, orphaned)
					m.orphanedEstCost += estCost
					m.mu.Unlock()

					m.mu.Lock()
					m.LootMap["cost-security-commands"].Contents += fmt.Sprintf(
						"# =============================================================================\n"+
							"# ORPHANED IP: %s\n"+
							"# =============================================================================\n"+
							"# Project: %s\n"+
							"# Address: %s | Est. Cost: $%.2f/month\n"+
							"# Release static IP:\n"+
							"gcloud compute addresses delete %s --region=%s --project=%s\n\n",
						addr.Name,
						projectID,
						addr.Address, estCost,
						addr.Name, m.extractRegionFromURL(region), projectID,
					)
					m.mu.Unlock()
				}
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_COSTSECURITY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate addresses in project %s", projectID))
	}
}

func (m *CostSecurityModule) analyzeSQLInstances(ctx context.Context, projectID string, sqlService *sqladmin.Service, logger internal.Logger) {
	instances, err := sqlService.Instances.List(projectID).Do()
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_COSTSECURITY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate SQL instances in project %s", projectID))
		return
	}

	for _, instance := range instances.Items {
		// Check for stopped but still provisioned instances (still incur storage costs)
		if instance.State == "SUSPENDED" {
			anomaly := CostAnomaly{
				Name:         instance.Name,
				ProjectID:    projectID,
				ResourceType: "cloudsql-instance",
				AnomalyType:  "idle",
				Severity:     "MEDIUM",
				Details:      "Cloud SQL instance is suspended but still incurs storage costs",
				Location:     instance.Region,
				Remediation:  "Consider deleting if not needed, or start if needed for operations",
			}

			m.mu.Lock()
			m.CostAnomalies = append(m.CostAnomalies, anomaly)
			m.mu.Unlock()
		}

		// Check for high-tier instances without labels
		if instance.Settings != nil && strings.Contains(instance.Settings.Tier, "db-custom") {
			if instance.Settings.UserLabels == nil || len(instance.Settings.UserLabels) == 0 {
				anomaly := CostAnomaly{
					Name:         instance.Name,
					ProjectID:    projectID,
					ResourceType: "cloudsql-instance",
					AnomalyType:  "unlabeled",
					Severity:     "LOW",
					Details:      fmt.Sprintf("High-tier Cloud SQL instance (%s) has no cost allocation labels", instance.Settings.Tier),
					Location:     instance.Region,
					Remediation:  fmt.Sprintf("gcloud sql instances patch %s --update-labels=cost-center=UNKNOWN,owner=UNKNOWN", instance.Name),
				}

				m.mu.Lock()
				m.CostAnomalies = append(m.CostAnomalies, anomaly)
				m.mu.Unlock()
			}
		}
	}
}

func (m *CostSecurityModule) analyzeStorageBuckets(ctx context.Context, projectID string, storageService *storage.Service, logger internal.Logger) {
	buckets, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_COSTSECURITY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate storage buckets in project %s", projectID))
		return
	}

	for _, bucket := range buckets.Items {
		// Check for buckets without labels
		if len(bucket.Labels) == 0 {
			anomaly := CostAnomaly{
				Name:         bucket.Name,
				ProjectID:    projectID,
				ResourceType: "storage-bucket",
				AnomalyType:  "unlabeled",
				Severity:     "LOW",
				Details:      "Storage bucket has no cost allocation labels",
				Location:     bucket.Location,
				Remediation:  fmt.Sprintf("gsutil label ch -l cost-center:UNKNOWN gs://%s", bucket.Name),
			}

			m.mu.Lock()
			m.CostAnomalies = append(m.CostAnomalies, anomaly)
			m.mu.Unlock()
		}

		// Check for multi-regional buckets with nearline/coldline (unusual pattern)
		if bucket.StorageClass == "NEARLINE" || bucket.StorageClass == "COLDLINE" {
			if strings.Contains(strings.ToUpper(bucket.Location), "DUAL") || len(bucket.Location) <= 4 {
				anomaly := CostAnomaly{
					Name:         bucket.Name,
					ProjectID:    projectID,
					ResourceType: "storage-bucket",
					AnomalyType:  "suboptimal-config",
					Severity:     "LOW",
					Details:      fmt.Sprintf("Multi-regional bucket with %s storage (consider single region for cost)", bucket.StorageClass),
					Location:     bucket.Location,
					Remediation:  "Consider using single-region buckets for archival storage",
				}

				m.mu.Lock()
				m.CostAnomalies = append(m.CostAnomalies, anomaly)
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func (m *CostSecurityModule) extractMachineTypeName(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func (m *CostSecurityModule) extractZoneFromURL(url string) string {
	if strings.Contains(url, "zones/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "zones" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return url
}

func (m *CostSecurityModule) extractRegionFromURL(url string) string {
	if strings.Contains(url, "regions/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "regions" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return url
}

func (m *CostSecurityModule) parseMachineType(machineType string) (vcpus int64, memGB float64) {
	// Common machine type patterns
	// n1-standard-4: 4 vCPUs, 15 GB
	// e2-medium: 2 vCPUs, 4 GB
	// custom-8-32768: 8 vCPUs, 32 GB

	switch {
	case strings.HasPrefix(machineType, "custom-"):
		// Parse custom machine type
		parts := strings.Split(machineType, "-")
		if len(parts) >= 3 {
			fmt.Sscanf(parts[1], "%d", &vcpus)
			var memMB int64
			fmt.Sscanf(parts[2], "%d", &memMB)
			memGB = float64(memMB) / 1024
		}
	case strings.HasPrefix(machineType, "n1-"):
		vcpuMap := map[string]int64{
			"n1-standard-1": 1, "n1-standard-2": 2, "n1-standard-4": 4,
			"n1-standard-8": 8, "n1-standard-16": 16, "n1-standard-32": 32,
			"n1-standard-64": 64, "n1-standard-96": 96,
			"n1-highmem-2": 2, "n1-highmem-4": 4, "n1-highmem-8": 8,
			"n1-highmem-16": 16, "n1-highmem-32": 32, "n1-highmem-64": 64,
			"n1-highcpu-2": 2, "n1-highcpu-4": 4, "n1-highcpu-8": 8,
			"n1-highcpu-16": 16, "n1-highcpu-32": 32, "n1-highcpu-64": 64,
		}
		vcpus = vcpuMap[machineType]
		memGB = float64(vcpus) * 3.75 // Standard ratio
	case strings.HasPrefix(machineType, "e2-"):
		vcpuMap := map[string]int64{
			"e2-micro": 2, "e2-small": 2, "e2-medium": 2,
			"e2-standard-2": 2, "e2-standard-4": 4, "e2-standard-8": 8,
			"e2-standard-16": 16, "e2-standard-32": 32,
			"e2-highmem-2": 2, "e2-highmem-4": 4, "e2-highmem-8": 8,
			"e2-highmem-16": 16,
			"e2-highcpu-2": 2, "e2-highcpu-4": 4, "e2-highcpu-8": 8,
			"e2-highcpu-16": 16, "e2-highcpu-32": 32,
		}
		vcpus = vcpuMap[machineType]
		memGB = float64(vcpus) * 4 // Approximate
	case strings.HasPrefix(machineType, "n2-") || strings.HasPrefix(machineType, "n2d-"):
		parts := strings.Split(machineType, "-")
		if len(parts) >= 3 {
			fmt.Sscanf(parts[2], "%d", &vcpus)
			memGB = float64(vcpus) * 4
		}
	case strings.HasPrefix(machineType, "c2-"):
		parts := strings.Split(machineType, "-")
		if len(parts) >= 3 {
			fmt.Sscanf(parts[2], "%d", &vcpus)
			memGB = float64(vcpus) * 4
		}
	default:
		vcpus = 2
		memGB = 4
	}

	return vcpus, memGB
}

func (m *CostSecurityModule) estimateInstanceCost(machineType string, vcpus int64, memGB float64, gpuCount int) float64 {
	// Rough monthly estimates based on on-demand pricing in us-central1
	// Actual costs vary by region and commitment

	baseCost := float64(vcpus)*25 + memGB*3 // Rough per-vCPU and per-GB costs

	// GPU costs (rough estimates)
	if gpuCount > 0 {
		baseCost += float64(gpuCount) * 400 // ~$400/month per GPU
	}

	// Adjust for machine type efficiency
	if strings.HasPrefix(machineType, "e2-") {
		baseCost *= 0.7 // E2 is cheaper
	} else if strings.HasPrefix(machineType, "c2-") {
		baseCost *= 1.2 // C2 is more expensive
	}

	return baseCost
}

func (m *CostSecurityModule) estimateDiskCost(sizeGB int64, diskType string) float64 {
	// Rough monthly estimates per GB
	// pd-standard: $0.04/GB, pd-ssd: $0.17/GB, pd-balanced: $0.10/GB

	pricePerGB := 0.04
	if strings.Contains(diskType, "ssd") {
		pricePerGB = 0.17
	} else if strings.Contains(diskType, "balanced") {
		pricePerGB = 0.10
	}

	return float64(sizeGB) * pricePerGB
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CostSecurityModule) initializeLootFiles() {
	m.LootMap["cost-security-commands"] = &internal.LootFile{
		Name:     "cost-security-commands",
		Contents: "# Cost Security Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CostSecurityModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *CostSecurityModule) buildTables() []internal.TableFile {
	// Main cost-security table (combines cryptomining, orphaned, and anomalies)
	mainHeader := []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Type",
		"Location",
		"Issue",
		"Est. Cost/Mo",
	}

	var mainBody [][]string

	// Add cryptomining indicators
	for _, c := range m.Cryptomining {
		mainBody = append(mainBody, []string{
			c.ProjectID,
			m.GetProjectName(c.ProjectID),
			c.Name,
			c.ResourceType,
			c.Location,
			fmt.Sprintf("cryptomining: %s", c.Indicator),
			"-",
		})
	}

	// Add orphaned resources
	for _, o := range m.Orphaned {
		mainBody = append(mainBody, []string{
			o.ProjectID,
			m.GetProjectName(o.ProjectID),
			o.Name,
			o.ResourceType,
			o.Location,
			"orphaned",
			fmt.Sprintf("$%.2f", o.EstCostMonth),
		})
	}

	// Add cost anomalies
	for _, a := range m.CostAnomalies {
		mainBody = append(mainBody, []string{
			a.ProjectID,
			m.GetProjectName(a.ProjectID),
			a.Name,
			a.ResourceType,
			a.Location,
			a.AnomalyType,
			fmt.Sprintf("$%.2f", a.EstCostMonth),
		})

		// Add remediation to loot
		if a.Remediation != "" {
			m.LootMap["cost-security-commands"].Contents += fmt.Sprintf(
				"# =============================================================================\n"+
					"# %s: %s\n"+
					"# =============================================================================\n"+
					"# Project: %s\n"+
					"# %s\n"+
					"%s\n\n",
				strings.ToUpper(a.AnomalyType), a.Name,
				a.ProjectID, a.Details, a.Remediation,
			)
		}
	}

	// Expensive Resources table (keep separate due to different structure)
	expensiveHeader := []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Location",
		"Machine Type",
		"vCPUs",
		"Memory GB",
		"GPUs",
		"Labeled",
		"Est. Cost/Mo",
	}

	var expensiveBody [][]string
	for _, e := range m.Expensive {
		labeled := "No"
		if len(e.Labels) > 0 {
			labeled = "Yes"
		}

		expensiveBody = append(expensiveBody, []string{
			e.ProjectID,
			m.GetProjectName(e.ProjectID),
			e.Name,
			e.Location,
			e.MachineType,
			fmt.Sprintf("%d", e.VCPUs),
			fmt.Sprintf("%.1f", e.MemoryGB),
			fmt.Sprintf("%d", e.GPUs),
			labeled,
			fmt.Sprintf("$%.2f", e.EstCostMonth),
		})
	}

	// Build tables
	var tables []internal.TableFile

	if len(mainBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cost-security",
			Header: mainHeader,
			Body:   mainBody,
		})
	}

	if len(expensiveBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cost-security-expensive",
			Header: expensiveHeader,
			Body:   expensiveBody,
		})
	}

	return tables
}

func (m *CostSecurityModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *CostSecurityModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Determine org ID from hierarchy
	orgID := ""
	if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		tables := m.buildTables()
		lootFiles := m.collectLootFiles()
		outputData.OrgLevelData[orgID] = CostSecurityOutput{Table: tables, Loot: lootFiles}

		// DUAL OUTPUT: Filtered per-project output
		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			if len(projectTables) > 0 {
				outputData.ProjectLevelData[projectID] = CostSecurityOutput{Table: projectTables, Loot: nil}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		tables := m.buildTables()
		lootFiles := m.collectLootFiles()
		outputData.ProjectLevelData[m.ProjectIDs[0]] = CostSecurityOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_COSTSECURITY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// buildTablesForProject builds tables filtered to only include data for a specific project
func (m *CostSecurityModule) buildTablesForProject(projectID string) []internal.TableFile {
	mainHeader := []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Type",
		"Location",
		"Issue",
		"Est. Cost/Mo",
	}

	var mainBody [][]string

	// Add cryptomining indicators for this project
	for _, c := range m.Cryptomining {
		if c.ProjectID != projectID {
			continue
		}
		mainBody = append(mainBody, []string{
			c.ProjectID,
			m.GetProjectName(c.ProjectID),
			c.Name,
			c.ResourceType,
			c.Location,
			fmt.Sprintf("cryptomining: %s", c.Indicator),
			"-",
		})
	}

	// Add orphaned resources for this project
	for _, o := range m.Orphaned {
		if o.ProjectID != projectID {
			continue
		}
		mainBody = append(mainBody, []string{
			o.ProjectID,
			m.GetProjectName(o.ProjectID),
			o.Name,
			o.ResourceType,
			o.Location,
			"orphaned",
			fmt.Sprintf("$%.2f", o.EstCostMonth),
		})
	}

	// Add cost anomalies for this project
	for _, a := range m.CostAnomalies {
		if a.ProjectID != projectID {
			continue
		}
		mainBody = append(mainBody, []string{
			a.ProjectID,
			m.GetProjectName(a.ProjectID),
			a.Name,
			a.ResourceType,
			a.Location,
			a.AnomalyType,
			fmt.Sprintf("$%.2f", a.EstCostMonth),
		})
	}

	// Expensive Resources for this project
	expensiveHeader := []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Location",
		"Machine Type",
		"vCPUs",
		"Memory GB",
		"GPUs",
		"Labeled",
		"Est. Cost/Mo",
	}

	var expensiveBody [][]string
	for _, e := range m.Expensive {
		if e.ProjectID != projectID {
			continue
		}
		labeled := "No"
		if len(e.Labels) > 0 {
			labeled = "Yes"
		}
		expensiveBody = append(expensiveBody, []string{
			e.ProjectID,
			m.GetProjectName(e.ProjectID),
			e.Name,
			e.Location,
			e.MachineType,
			fmt.Sprintf("%d", e.VCPUs),
			fmt.Sprintf("%.1f", e.MemoryGB),
			fmt.Sprintf("%d", e.GPUs),
			labeled,
			fmt.Sprintf("$%.2f", e.EstCostMonth),
		})
	}

	// Build tables
	var tables []internal.TableFile

	if len(mainBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cost-security",
			Header: mainHeader,
			Body:   mainBody,
		})
	}

	if len(expensiveBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "expensive-resources",
			Header: expensiveHeader,
			Body:   expensiveBody,
		})
	}

	return tables
}

func (m *CostSecurityModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := CostSecurityOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scope names with project names
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	// Write output
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_COSTSECURITY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
