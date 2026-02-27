package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudStorageService "github.com/BishopFox/cloudfox/gcp/services/cloudStorageService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPStorageCommand = &cobra.Command{
	Use:     globals.GCP_STORAGE_MODULE_NAME,
	Aliases: []string{"buckets", "gcs"},
	Short:   "Enumerate GCP Cloud Storage buckets with security configuration",
	Long: `Enumerate GCP Cloud Storage buckets across projects with security-relevant details.

Features:
- Lists all buckets accessible to the authenticated user
- Shows security configuration (public access prevention, uniform access, versioning)
- Enumerates IAM policies and identifies public buckets
- Shows encryption type (Google-managed vs CMEK)
- Shows retention, soft delete, and lifecycle policies
- Generates gcloud commands for further enumeration
- Generates exploitation commands for data access

Security Columns:
- Public: Whether the bucket has allUsers or allAuthenticatedUsers access
- Public Access Prevention:
    "enforced" = Public access blocked at bucket level
    "inherited" = Inherits from project/org (may allow public if not blocked above)
    "unspecified" = No prevention (most permissive)
- Uniform Access:
    "Yes" = IAM-only access control (recommended, no ACLs)
    "No (ACLs)" = Legacy ACLs enabled - access can be granted at object level
                  bypassing bucket IAM, harder to audit
- Soft Delete: Retention period for deleted objects (ransomware protection)
    "No" = Deleted objects are immediately removed
    "Xd" = Deleted objects retained for X days before permanent deletion
- Lifecycle: Automated object management rules
    "Delete@Xd" = Objects auto-deleted after X days (data loss risk if short)
    "Archive" = Objects transitioned to cheaper storage classes
    "X rules" = Number of lifecycle rules configured
- Versioning: Object versioning (helps recovery, compliance)
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)`,
	Run: runGCPStorageCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type BucketsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectBuckets  map[string][]CloudStorageService.BucketInfo // projectID -> buckets
	LootMap         map[string]map[string]*internal.LootFile    // projectID -> loot files
	FoxMapperCache  *gcpinternal.FoxMapperCache                 // FoxMapper graph data (preferred)
	mu              sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type BucketsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BucketsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BucketsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPStorageCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_STORAGE_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &BucketsModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectBuckets: make(map[string][]CloudStorageService.BucketInfo),
		LootMap:        make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *BucketsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Try to get FoxMapper cache (preferred - graph-based analysis)
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_STORAGE_MODULE_NAME)
	}

	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_STORAGE_MODULE_NAME, m.processProject)

	// Get all buckets for stats
	allBuckets := m.getAllBuckets()
	if len(allBuckets) == 0 {
		logger.InfoM("No buckets found", globals.GCP_STORAGE_MODULE_NAME)
		return
	}

	// Count public buckets for summary
	publicCount := 0
	for _, bucket := range allBuckets {
		if bucket.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d bucket(s), %d PUBLIC", len(allBuckets), publicCount), globals.GCP_STORAGE_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d bucket(s)", len(allBuckets)), globals.GCP_STORAGE_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllBuckets returns all buckets from all projects (for statistics)
func (m *BucketsModule) getAllBuckets() []CloudStorageService.BucketInfo {
	var all []CloudStorageService.BucketInfo
	for _, buckets := range m.ProjectBuckets {
		all = append(all, buckets...)
	}
	return all
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *BucketsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating buckets in project: %s", projectID), globals.GCP_STORAGE_MODULE_NAME)
	}

	// Create service and fetch buckets
	cs := CloudStorageService.New()
	buckets, err := cs.Buckets(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_STORAGE_MODULE_NAME,
			fmt.Sprintf("Could not enumerate buckets in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectBuckets[projectID] = buckets

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["buckets-commands"] = &internal.LootFile{
			Name:     "buckets-commands",
			Contents: "# GCP Cloud Storage Bucket Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	// Generate loot for each bucket
	for _, bucket := range buckets {
		m.addBucketToLoot(projectID, bucket)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d bucket(s) in project %s", len(buckets), projectID), globals.GCP_STORAGE_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *BucketsModule) addBucketToLoot(projectID string, bucket CloudStorageService.BucketInfo) {
	lootFile := m.LootMap[projectID]["buckets-commands"]
	if lootFile == nil {
		return
	}

	// All commands for this bucket
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# BUCKET: gs://%s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Location: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe bucket:\n"+
			"gcloud storage buckets describe gs://%s --project=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud storage buckets get-iam-policy gs://%s --project=%s\n"+
			"# List objects:\n"+
			"gsutil ls gs://%s/\n"+
			"gsutil ls -L gs://%s/\n"+
			"# List all objects recursively:\n"+
			"gsutil ls -r gs://%s/**\n"+
			"# Get bucket size:\n"+
			"gsutil du -s gs://%s/\n\n"+
			"# === EXPLOIT COMMANDS ===\n\n"+
			"# Download all contents (create directory first):\n"+
			"mkdir -p bucket/%s/\n"+
			"gsutil -m cp -r gs://%s/ bucket/%s/\n"+
			"# Check for public access:\n"+
			"curl -s https://storage.googleapis.com/%s/ | head -20\n\n",
		bucket.Name, bucket.ProjectID, bucket.Location,
		bucket.Name, bucket.ProjectID,
		bucket.Name, bucket.ProjectID,
		bucket.Name,
		bucket.Name,
		bucket.Name,
		bucket.Name,
		bucket.Name,
		bucket.Name, bucket.Name,
		bucket.Name,
	)
}

// Helper functions are now provided by the shared package:
// - shared.BoolToYesNo() for boolean formatting
// - shared.GetPrincipalType() for IAM member type extraction

// ------------------------------
// Output Generation
// ------------------------------
func (m *BucketsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Log findings first
	allBuckets := m.getAllBuckets()
	publicCount := 0
	for _, bucket := range allBuckets {
		if bucket.IsPublic {
			publicCount++
		}
	}
	if publicCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d publicly accessible bucket(s)!", publicCount), globals.GCP_STORAGE_MODULE_NAME)
	}

	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *BucketsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()

	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, buckets := range m.ProjectBuckets {
		body := m.bucketsToTableBody(buckets)
		tables := []internal.TableFile{{
			Name:   globals.GCP_STORAGE_MODULE_NAME,
			Header: header,
			Body:   body,
		}}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = BucketsOutput{Table: tables, Loot: lootFiles}
	}

	// Create path builder using the module's hierarchy
	pathBuilder := m.BuildPathBuilder()

	// Write using hierarchical output
	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_STORAGE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *BucketsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()
	allBuckets := m.getAllBuckets()
	body := m.bucketsToTableBody(allBuckets)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tableFiles := []internal.TableFile{{
		Name:   globals.GCP_STORAGE_MODULE_NAME,
		Header: header,
		Body:   body,
	}}

	output := BucketsOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	// Build scope names from project names map
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	// Write output using HandleOutputSmart with scope support
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",    // scopeType
		m.ProjectIDs, // scopeIdentifiers
		scopeNames,   // scopeNames (display names)
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_STORAGE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// getTableHeader returns the buckets table header
func (m *BucketsModule) getTableHeader() []string {
	return []string{
		"Project",
		"Name",
		"Location",
		"Public",
		"Public Access Prevention",
		"Uniform Access",
		"Soft Delete",
		"Lifecycle",
		"Versioning",
		"Encryption",
		"IAM Binding Role",
		"Principal Type",
		"IAM Binding Principal",
		"Principal Attack Paths",
	}
}

// bucketsToTableBody converts buckets to table body rows
func (m *BucketsModule) bucketsToTableBody(buckets []CloudStorageService.BucketInfo) [][]string {
	var body [][]string
	for _, bucket := range buckets {
		// Format public access
		publicDisplay := "No"
		if bucket.IsPublic {
			publicDisplay = bucket.PublicAccess
		}

		// Format soft delete
		softDeleteDisplay := "No"
		if bucket.SoftDeleteEnabled {
			softDeleteDisplay = fmt.Sprintf("%dd", bucket.SoftDeleteRetentionDays)
		}

		// Format lifecycle - show delete rule age if present
		lifecycleDisplay := "No"
		if bucket.LifecycleEnabled {
			if bucket.HasDeleteRule && bucket.ShortestDeleteDays > 0 {
				lifecycleDisplay = fmt.Sprintf("Delete@%dd", bucket.ShortestDeleteDays)
			} else if bucket.HasArchiveRule {
				lifecycleDisplay = "Archive"
			} else {
				lifecycleDisplay = fmt.Sprintf("%d rules", bucket.LifecycleRuleCount)
			}
		}

		// Format uniform access - highlight security concern if disabled
		uniformAccessDisplay := "Yes"
		if !bucket.UniformBucketLevelAccess {
			uniformAccessDisplay = "No (ACLs)"
		}

		// Format encryption - show KMS key if CMEK
		encryptionDisplay := bucket.EncryptionType
		if bucket.EncryptionType == "CMEK" && bucket.KMSKeyName != "" {
			// Extract just the key name from the full path for display
			// Format: projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
			keyParts := strings.Split(bucket.KMSKeyName, "/")
			if len(keyParts) >= 2 {
				encryptionDisplay = fmt.Sprintf("CMEK (%s)", keyParts[len(keyParts)-1])
			}
		}

		// One row per IAM member
		if len(bucket.IAMBindings) > 0 {
			for _, binding := range bucket.IAMBindings {
				for _, member := range binding.Members {
					memberType := shared.GetPrincipalType(member)

					// Check attack paths for service account principals
					attackPaths := "-"
					if memberType == "ServiceAccount" {
						// Extract email from member string (serviceAccount:email@...)
						email := strings.TrimPrefix(member, "serviceAccount:")
						attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, email)
					}

					body = append(body, []string{
						m.GetProjectName(bucket.ProjectID),
						bucket.Name,
						bucket.Location,
						publicDisplay,
						bucket.PublicAccessPrevention,
						uniformAccessDisplay,
						softDeleteDisplay,
						lifecycleDisplay,
						shared.BoolToYesNo(bucket.VersioningEnabled),
						encryptionDisplay,
						binding.Role,
						memberType,
						member,
						attackPaths,
					})
				}
			}
		} else {
			// Bucket with no IAM bindings
			body = append(body, []string{
				m.GetProjectName(bucket.ProjectID),
				bucket.Name,
				bucket.Location,
				publicDisplay,
				bucket.PublicAccessPrevention,
				uniformAccessDisplay,
				softDeleteDisplay,
				lifecycleDisplay,
				shared.BoolToYesNo(bucket.VersioningEnabled),
				encryptionDisplay,
				"-",
				"-",
				"-",
				"-",
			})
		}
	}
	return body
}
