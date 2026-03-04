package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/compute/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// Module name constant
const GCP_BACKUPINVENTORY_MODULE_NAME string = "backup-inventory"

var GCPBackupInventoryCommand = &cobra.Command{
	Use:     GCP_BACKUPINVENTORY_MODULE_NAME,
	Aliases: []string{"backups", "backup", "snapshots", "dr"},
	Short:   "Enumerate backup policies, protected resources, and identify backup gaps",
	Long: `Inventory backup and disaster recovery configurations across GCP resources.

Features:
- Compute Engine disk snapshots and snapshot schedules
- Cloud SQL automated backups and point-in-time recovery
- Identifies unprotected resources (no backup coverage)
- Analyzes backup retention policies
- Checks for stale or failing backups`,
	Run: runGCPBackupInventoryCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type BackupResource struct {
	ProjectID      string
	Name           string
	ResourceType   string // compute-disk, cloudsql-instance
	Location       string
	SizeGB         int64
	Protected      bool
	BackupType     string // snapshot, automated, none
	Schedule       string
	RetentionDays  int
	LastBackup     string
	BackupCount    int
	BackupStatus   string
	PITREnabled    bool
	BackupLocation string
}

type IAMBinding struct {
	Role    string
	Members []string
}

type ComputeSnapshot struct {
	ProjectID      string
	Name           string
	SourceDisk     string
	Status         string
	DiskSizeGB     int64
	StorageBytes   int64
	CreationTime   string
	StorageLocats  []string
	AutoCreated    bool
	SnapshotType   string
	IAMBindings    []IAMBinding
	PublicAccess   bool
	EncryptionType string
	KMSKeyName     string
}

// ------------------------------
// Module Struct
// ------------------------------
type BackupInventoryModule struct {
	gcpinternal.BaseGCPModule

	ProjectResources map[string][]BackupResource              // projectID -> resources
	ProjectSnapshots map[string][]ComputeSnapshot             // projectID -> snapshots
	LootMap          map[string]map[string]*internal.LootFile // projectID -> loot files
	mu               sync.Mutex

	// Tracking maps
	disksWithBackups map[string]bool
	sqlWithBackups   map[string]bool
	allDisks         map[string]diskInfo
	allSQLInstances  map[string]sqlInstanceInfo
}

type diskInfo struct {
	SizeGB    int64
	Zone      string
	ProjectID string
	Name      string
}

type sqlInstanceInfo struct {
	ProjectID string
	Region    string
}

// ------------------------------
// Output Struct
// ------------------------------
type BackupInventoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BackupInventoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BackupInventoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPBackupInventoryCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_BACKUPINVENTORY_MODULE_NAME)
	if err != nil {
		return
	}

	module := &BackupInventoryModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectResources: make(map[string][]BackupResource),
		ProjectSnapshots: make(map[string][]ComputeSnapshot),
		LootMap:          make(map[string]map[string]*internal.LootFile),
		disksWithBackups: make(map[string]bool),
		sqlWithBackups:   make(map[string]bool),
		allDisks:         make(map[string]diskInfo),
		allSQLInstances:  make(map[string]sqlInstanceInfo),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *BackupInventoryModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Inventorying backup configurations...", GCP_BACKUPINVENTORY_MODULE_NAME)

	computeService, err := compute.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Compute service: %v", err), GCP_BACKUPINVENTORY_MODULE_NAME)
		return
	}

	sqlService, err := sqladmin.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create SQL Admin service: %v", err), GCP_BACKUPINVENTORY_MODULE_NAME)
		}
	}

	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, computeService, sqlService, logger)
		}(projectID)
	}
	wg.Wait()

	// Identify unprotected resources
	m.identifyUnprotectedResources()

	allResources := m.getAllResources()
	allSnapshots := m.getAllSnapshots()

	if len(allResources) == 0 && len(allSnapshots) == 0 {
		logger.InfoM("No backup data found", GCP_BACKUPINVENTORY_MODULE_NAME)
		return
	}

	// Count protected vs unprotected
	protectedCount := 0
	unprotectedCount := 0
	for _, r := range allResources {
		if r.Protected {
			protectedCount++
		} else {
			unprotectedCount++
		}
	}

	// Count public snapshots
	publicSnapshotCount := 0
	for _, s := range allSnapshots {
		if s.PublicAccess {
			publicSnapshotCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d resource(s): %d protected, %d unprotected, %d snapshot(s)",
		len(allResources), protectedCount, unprotectedCount, len(allSnapshots)), GCP_BACKUPINVENTORY_MODULE_NAME)

	if unprotectedCount > 0 {
		logger.InfoM(fmt.Sprintf("Found %d resource(s) without backup coverage", unprotectedCount), GCP_BACKUPINVENTORY_MODULE_NAME)
	}

	if publicSnapshotCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d publicly accessible snapshot(s)!", publicSnapshotCount), GCP_BACKUPINVENTORY_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

func (m *BackupInventoryModule) getAllResources() []BackupResource {
	var all []BackupResource
	for _, resources := range m.ProjectResources {
		all = append(all, resources...)
	}
	return all
}

func (m *BackupInventoryModule) getAllSnapshots() []ComputeSnapshot {
	var all []ComputeSnapshot
	for _, snapshots := range m.ProjectSnapshots {
		all = append(all, snapshots...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *BackupInventoryModule) processProject(ctx context.Context, projectID string, computeService *compute.Service, sqlService *sqladmin.Service, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating backups for project: %s", projectID), GCP_BACKUPINVENTORY_MODULE_NAME)
	}

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["backup-inventory-commands"] = &internal.LootFile{
			Name:     "backup-inventory-commands",
			Contents: "# Backup Inventory Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
	m.mu.Unlock()

	// List all disks first (for gap analysis)
	m.enumerateDisks(ctx, projectID, computeService, logger)

	// List snapshots
	m.enumerateSnapshots(ctx, projectID, computeService, logger)

	// List SQL instances and backups
	if sqlService != nil {
		m.enumerateSQLBackups(ctx, projectID, sqlService, logger)
	}
}

func (m *BackupInventoryModule) enumerateDisks(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Disks.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.DiskAggregatedList) error {
		for zone, diskList := range page.Items {
			if diskList.Disks == nil {
				continue
			}
			for _, disk := range diskList.Disks {
				m.mu.Lock()
				m.allDisks[disk.SelfLink] = diskInfo{
					SizeGB:    disk.SizeGb,
					Zone:      m.extractZoneFromURL(zone),
					ProjectID: projectID,
					Name:      disk.Name,
				}
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_BACKUPINVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate disks in project %s", projectID))
	}
}

func (m *BackupInventoryModule) enumerateSnapshots(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Snapshots.List(projectID)
	err := req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			// Determine encryption type and KMS key name
			encryptionType := "Google-managed"
			kmsKeyName := ""
			if snapshot.SnapshotEncryptionKey != nil {
				if snapshot.SnapshotEncryptionKey.KmsKeyName != "" {
					encryptionType = "CMEK"
					kmsKeyName = snapshot.SnapshotEncryptionKey.KmsKeyName
				} else if snapshot.SnapshotEncryptionKey.RawKey != "" || snapshot.SnapshotEncryptionKey.Sha256 != "" {
					encryptionType = "CSEK"
				}
			}

			snap := ComputeSnapshot{
				ProjectID:      projectID,
				Name:           snapshot.Name,
				SourceDisk:     snapshot.SourceDisk,
				Status:         snapshot.Status,
				DiskSizeGB:     snapshot.DiskSizeGb,
				StorageBytes:   snapshot.StorageBytes,
				CreationTime:   snapshot.CreationTimestamp,
				StorageLocats:  snapshot.StorageLocations,
				AutoCreated:    snapshot.AutoCreated,
				SnapshotType:   snapshot.SnapshotType,
				EncryptionType: encryptionType,
				KMSKeyName:     kmsKeyName,
			}

			// Get IAM policy for this snapshot
			iamPolicy, iamErr := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Context(ctx).Do()
			if iamErr == nil && iamPolicy != nil {
				for _, binding := range iamPolicy.Bindings {
					snap.IAMBindings = append(snap.IAMBindings, IAMBinding{
						Role:    binding.Role,
						Members: binding.Members,
					})
					// Check for public access
					for _, member := range binding.Members {
						if shared.IsPublicPrincipal(member) {
							snap.PublicAccess = true
						}
					}
				}
			}

			m.mu.Lock()
			m.ProjectSnapshots[projectID] = append(m.ProjectSnapshots[projectID], snap)
			m.disksWithBackups[snapshot.SourceDisk] = true

			// Add post-exploit commands for snapshots
			if m.LootMap[projectID] != nil {
				if lootFile := m.LootMap[projectID]["backup-inventory-commands"]; lootFile != nil {
					// Determine a zone from storage locations or use a default
					zone := "us-central1-a"
					if len(snapshot.StorageLocations) > 0 {
						zone = snapshot.StorageLocations[0] + "-a"
					}

					lootFile.Contents += fmt.Sprintf(
						"# -----------------------------------------------------------------------------\n"+
							"# SNAPSHOT: %s (Source: %s, Size: %dGB)\n"+
							"# -----------------------------------------------------------------------------\n"+
							"# Create a disk from this snapshot\n"+
							"gcloud compute disks create disk-from-%s \\\n"+
							"  --project=%s \\\n"+
							"  --zone=%s \\\n"+
							"  --source-snapshot=%s\n\n"+
							"# Create an instance using a disk from this snapshot\n"+
							"gcloud compute instances create instance-from-%s \\\n"+
							"  --project=%s \\\n"+
							"  --zone=%s \\\n"+
							"  --disk=name=disk-from-%s,boot=yes\n\n",
						snapshot.Name, m.extractDiskName(snapshot.SourceDisk), snapshot.DiskSizeGb,
						snapshot.Name, projectID, zone, snapshot.Name,
						snapshot.Name, projectID, zone, snapshot.Name,
					)
				}
			}
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_BACKUPINVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate snapshots in project %s", projectID))
	}

	// Track protected resources from snapshots
	m.trackSnapshotProtection(projectID)
}

func (m *BackupInventoryModule) trackSnapshotProtection(projectID string) {
	m.mu.Lock()
	projectSnapshots := m.ProjectSnapshots[projectID]
	m.mu.Unlock()

	// Group snapshots by source disk
	diskSnapshots := make(map[string][]ComputeSnapshot)
	for _, snap := range projectSnapshots {
		diskSnapshots[snap.SourceDisk] = append(diskSnapshots[snap.SourceDisk], snap)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for diskURL, snaps := range diskSnapshots {
		// Find latest snapshot
		var latestTime time.Time
		var latestSnap ComputeSnapshot
		for _, snap := range snaps {
			t, err := time.Parse(time.RFC3339, snap.CreationTime)
			if err == nil && t.After(latestTime) {
				latestTime = t
				latestSnap = snap
			}
		}

		diskInfo := m.allDisks[diskURL]
		backupStatus := latestSnap.Status

		// Calculate age of last backup
		if !latestTime.IsZero() {
			age := time.Since(latestTime)
			if age > 7*24*time.Hour {
				backupStatus = "STALE"
			} else {
				backupStatus = "CURRENT"
			}
		}

		resource := BackupResource{
			ProjectID:      projectID,
			Name:           m.extractDiskName(diskURL),
			ResourceType:   "compute-disk",
			Location:       diskInfo.Zone,
			SizeGB:         diskInfo.SizeGB,
			Protected:      true,
			BackupType:     "snapshot",
			LastBackup:     latestSnap.CreationTime,
			BackupCount:    len(snaps),
			BackupStatus:   backupStatus,
			BackupLocation: strings.Join(latestSnap.StorageLocats, ","),
		}

		m.ProjectResources[projectID] = append(m.ProjectResources[projectID], resource)
	}
}

func (m *BackupInventoryModule) enumerateSQLBackups(ctx context.Context, projectID string, sqlService *sqladmin.Service, logger internal.Logger) {
	instances, err := sqlService.Instances.List(projectID).Do()
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_BACKUPINVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate SQL instances in project %s", projectID))
		return
	}

	for _, instance := range instances.Items {
		m.mu.Lock()
		m.allSQLInstances[instance.Name] = sqlInstanceInfo{
			ProjectID: projectID,
			Region:    instance.Region,
		}
		m.mu.Unlock()

		// Check backup configuration
		backupEnabled := false
		pitrEnabled := false
		var retentionDays int
		var backupStartTime string

		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			backupEnabled = instance.Settings.BackupConfiguration.Enabled
			pitrEnabled = instance.Settings.BackupConfiguration.PointInTimeRecoveryEnabled
			retentionDays = int(instance.Settings.BackupConfiguration.TransactionLogRetentionDays)
			backupStartTime = instance.Settings.BackupConfiguration.StartTime
		}

		if backupEnabled {
			m.mu.Lock()
			m.sqlWithBackups[instance.Name] = true
			m.mu.Unlock()

			// List actual backups for this instance
			backups, err := sqlService.BackupRuns.List(projectID, instance.Name).Do()
			if err != nil {
				continue
			}

			var latestBackupTime string
			var latestStatus string
			var latestLocation string
			backupCount := 0

			for _, backup := range backups.Items {
				backupCount++
				if latestBackupTime == "" || backup.StartTime > latestBackupTime {
					latestBackupTime = backup.StartTime
					latestStatus = backup.Status
					latestLocation = backup.Location
				}
			}

			resource := BackupResource{
				ProjectID:      projectID,
				Name:           instance.Name,
				ResourceType:   "cloudsql-instance",
				Location:       instance.Region,
				Protected:      true,
				BackupType:     "automated",
				Schedule:       fmt.Sprintf("Daily at %s", backupStartTime),
				RetentionDays:  retentionDays,
				LastBackup:     latestBackupTime,
				BackupCount:    backupCount,
				BackupStatus:   latestStatus,
				PITREnabled:    pitrEnabled,
				BackupLocation: latestLocation,
			}

			m.mu.Lock()
			m.ProjectResources[projectID] = append(m.ProjectResources[projectID], resource)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Gap Analysis
// ------------------------------
func (m *BackupInventoryModule) identifyUnprotectedResources() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find disks without snapshots
	for diskURL, info := range m.allDisks {
		if !m.disksWithBackups[diskURL] {
			resource := BackupResource{
				ProjectID:    info.ProjectID,
				Name:         info.Name,
				ResourceType: "compute-disk",
				Location:     info.Zone,
				SizeGB:       info.SizeGB,
				Protected:    false,
				BackupType:   "none",
			}

			m.ProjectResources[info.ProjectID] = append(m.ProjectResources[info.ProjectID], resource)

			// Add to loot (ensure project loot is initialized)
			if m.LootMap[info.ProjectID] == nil {
				m.LootMap[info.ProjectID] = make(map[string]*internal.LootFile)
				m.LootMap[info.ProjectID]["backup-inventory-commands"] = &internal.LootFile{
					Name:     "backup-inventory-commands",
					Contents: "# Backup Inventory Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
				}
			}
			// No loot commands for unprotected disks - these are informational only
		}
	}

	// Find SQL instances without backups
	for instanceName, info := range m.allSQLInstances {
		if !m.sqlWithBackups[instanceName] {
			resource := BackupResource{
				ProjectID:    info.ProjectID,
				Name:         instanceName,
				ResourceType: "cloudsql-instance",
				Location:     info.Region,
				Protected:    false,
				BackupType:   "none",
			}

			m.ProjectResources[info.ProjectID] = append(m.ProjectResources[info.ProjectID], resource)

			// Add to loot (ensure project loot is initialized)
			if m.LootMap[info.ProjectID] == nil {
				m.LootMap[info.ProjectID] = make(map[string]*internal.LootFile)
				m.LootMap[info.ProjectID]["backup-inventory-commands"] = &internal.LootFile{
					Name:     "backup-inventory-commands",
					Contents: "# Backup Inventory Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
				}
			}
			// No loot commands for unprotected SQL instances - these are informational only
		}
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func (m *BackupInventoryModule) extractDiskName(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func (m *BackupInventoryModule) extractZoneFromURL(url string) string {
	if strings.Contains(url, "zones/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "zones" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *BackupInventoryModule) extractRegionFromZone(zone string) string {
	if zone == "" {
		return ""
	}
	// Zone format: us-central1-a -> Region: us-central1
	parts := strings.Split(zone, "-")
	if len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return zone
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *BackupInventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *BackupInventoryModule) getResourcesHeader() []string {
	return []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Type",
		"Location",
		"Size (GB)",
		"Protected",
		"Backup Type",
		"Schedule",
		"Retention",
		"Last Backup",
		"Count",
		"Status",
		"PITR",
	}
}

func (m *BackupInventoryModule) getSnapshotsHeader() []string {
	return []string{
		"Project",
		"Snapshot",
		"Source Disk",
		"Size (GB)",
		"Created",
		"Status",
		"Type",
		"Auto Created",
		"Locations",
		"Encryption",
		"IAM Binding Role",
		"IAM Binding Principal",
		"Public",
	}
}

func (m *BackupInventoryModule) resourcesToTableBody(resources []BackupResource) [][]string {
	var body [][]string
	for _, r := range resources {
		protectedStr := "No"
		if r.Protected {
			protectedStr = "Yes"
		}

		pitrStr := "No"
		if r.PITREnabled {
			pitrStr = "Yes"
		}

		retentionStr := ""
		if r.RetentionDays > 0 {
			retentionStr = fmt.Sprintf("%d days", r.RetentionDays)
		}

		sizeStr := ""
		if r.SizeGB > 0 {
			sizeStr = fmt.Sprintf("%d", r.SizeGB)
		}

		countStr := ""
		if r.BackupCount > 0 {
			countStr = fmt.Sprintf("%d", r.BackupCount)
		}

		body = append(body, []string{
			r.ProjectID,
			m.GetProjectName(r.ProjectID),
			r.Name,
			r.ResourceType,
			r.Location,
			sizeStr,
			protectedStr,
			r.BackupType,
			r.Schedule,
			retentionStr,
			r.LastBackup,
			countStr,
			r.BackupStatus,
			pitrStr,
		})
	}
	return body
}

func (m *BackupInventoryModule) snapshotsToTableBody(snapshots []ComputeSnapshot) [][]string {
	var body [][]string
	for _, s := range snapshots {
		autoCreatedStr := "No"
		if s.AutoCreated {
			autoCreatedStr = "Yes"
		}

		publicAccess := "No"
		if s.PublicAccess {
			publicAccess = "Yes"
		}

		// Format encryption - show KMS key name if CMEK
		encryptionDisplay := s.EncryptionType
		if s.EncryptionType == "CMEK" && s.KMSKeyName != "" {
			// Extract just the key name from the full path for display
			// Format: projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
			keyParts := strings.Split(s.KMSKeyName, "/")
			if len(keyParts) >= 2 {
				encryptionDisplay = fmt.Sprintf("CMEK (%s)", keyParts[len(keyParts)-1])
			}
		}

		// If no IAM bindings, still show the snapshot
		if len(s.IAMBindings) == 0 {
			body = append(body, []string{
				m.GetProjectName(s.ProjectID),
				s.Name,
				m.extractDiskName(s.SourceDisk),
				fmt.Sprintf("%d", s.DiskSizeGB),
				s.CreationTime,
				s.Status,
				s.SnapshotType,
				autoCreatedStr,
				strings.Join(s.StorageLocats, ","),
				encryptionDisplay,
				"-",
				"-",
				publicAccess,
			})
		} else {
			// One row per member per role
			for _, binding := range s.IAMBindings {
				for _, member := range binding.Members {
					body = append(body, []string{
						m.GetProjectName(s.ProjectID),
						s.Name,
						m.extractDiskName(s.SourceDisk),
						fmt.Sprintf("%d", s.DiskSizeGB),
						s.CreationTime,
						s.Status,
						s.SnapshotType,
						autoCreatedStr,
						strings.Join(s.StorageLocats, ","),
						encryptionDisplay,
						binding.Role,
						member,
						publicAccess,
					})
				}
			}
		}
	}
	return body
}

func (m *BackupInventoryModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if resources, ok := m.ProjectResources[projectID]; ok && len(resources) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "backup-inventory",
			Header: m.getResourcesHeader(),
			Body:   m.resourcesToTableBody(resources),
		})
	}

	if snapshots, ok := m.ProjectSnapshots[projectID]; ok && len(snapshots) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "backup-snapshots",
			Header: m.getSnapshotsHeader(),
			Body:   m.snapshotsToTableBody(snapshots),
		})
	}

	return tableFiles
}

func (m *BackupInventoryModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Get all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectResources {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectSnapshots {
		projectIDs[projectID] = true
	}

	for projectID := range projectIDs {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = BackupInventoryOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_BACKUPINVENTORY_MODULE_NAME)
	}
}

func (m *BackupInventoryModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allResources := m.getAllResources()
	allSnapshots := m.getAllSnapshots()

	var tables []internal.TableFile

	if len(allResources) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "backup-inventory",
			Header: m.getResourcesHeader(),
			Body:   m.resourcesToTableBody(allResources),
		})
	}

	if len(allSnapshots) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "backup-snapshots",
			Header: m.getSnapshotsHeader(),
			Body:   m.snapshotsToTableBody(allSnapshots),
		})
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := BackupInventoryOutput{Table: tables, Loot: lootFiles}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_BACKUPINVENTORY_MODULE_NAME)
	}
}
