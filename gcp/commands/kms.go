package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	KMSService "github.com/BishopFox/cloudfox/gcp/services/kmsService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPKMSCommand = &cobra.Command{
	Use:     globals.GCP_KMS_MODULE_NAME,
	Aliases: []string{"crypto", "encryption-keys"},
	Short:   "Enumerate Cloud KMS key rings and crypto keys with security analysis",
	Long: `Enumerate Cloud KMS key rings and crypto keys across projects with security-relevant details.

Features:
- Lists all KMS key rings and crypto keys
- Shows key purpose (encryption, signing, MAC)
- Identifies protection level (software, HSM, external)
- Shows rotation configuration and status
- Detects public key access via IAM
- Generates gcloud commands for key operations

Security Columns:
- Purpose: ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC
- Protection: SOFTWARE, HSM, EXTERNAL, EXTERNAL_VPC
- Rotation: Key rotation period and next rotation time
- PublicDecrypt: Whether allUsers/allAuthenticatedUsers can decrypt

Resource IAM Columns:
- IAM Binding Role: The IAM role granted ON this key (e.g., roles/cloudkms.cryptoKeyDecrypter)
- IAM Binding Principal: The principal (user/SA/group) who has that role on this key

Attack Surface:
- Public decrypt access allows unauthorized data access
- Keys without rotation may be compromised long-term
- HSM vs software protection affects key extraction risk
- External keys indicate third-party key management`,
	Run: runGCPKMSCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type KMSModule struct {
	gcpinternal.BaseGCPModule

	// Per-project data for hierarchical output
	ProjectKeyRings   map[string][]KMSService.KeyRingInfo
	ProjectCryptoKeys map[string][]KMSService.CryptoKeyInfo
	LootMap           map[string]map[string]*internal.LootFile
	mu                sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type KMSOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o KMSOutput) TableFiles() []internal.TableFile { return o.Table }
func (o KMSOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPKMSCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_KMS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &KMSModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectKeyRings:   make(map[string][]KMSService.KeyRingInfo),
		ProjectCryptoKeys: make(map[string][]KMSService.CryptoKeyInfo),
		LootMap:           make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *KMSModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_KMS_MODULE_NAME, m.processProject)

	// Get all data for stats
	allKeyRings := m.getAllKeyRings()
	allCryptoKeys := m.getAllCryptoKeys()

	if len(allCryptoKeys) == 0 {
		logger.InfoM("No KMS keys found", globals.GCP_KMS_MODULE_NAME)
		return
	}

	// Count security-relevant metrics
	hsmCount := 0
	publicDecryptCount := 0
	for _, key := range allCryptoKeys {
		if key.ProtectionLevel == "HSM" {
			hsmCount++
		}
		if key.IsPublicDecrypt {
			publicDecryptCount++
		}
	}

	msg := fmt.Sprintf("Found %d key ring(s), %d key(s)", len(allKeyRings), len(allCryptoKeys))
	if hsmCount > 0 {
		msg += fmt.Sprintf(" [%d HSM]", hsmCount)
	}
	if publicDecryptCount > 0 {
		msg += fmt.Sprintf(" [%d PUBLIC DECRYPT!]", publicDecryptCount)
	}
	logger.SuccessM(msg, globals.GCP_KMS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllKeyRings returns all key rings from all projects
func (m *KMSModule) getAllKeyRings() []KMSService.KeyRingInfo {
	var all []KMSService.KeyRingInfo
	for _, keyRings := range m.ProjectKeyRings {
		all = append(all, keyRings...)
	}
	return all
}

// getAllCryptoKeys returns all crypto keys from all projects
func (m *KMSModule) getAllCryptoKeys() []KMSService.CryptoKeyInfo {
	var all []KMSService.CryptoKeyInfo
	for _, keys := range m.ProjectCryptoKeys {
		all = append(all, keys...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *KMSModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating KMS in project: %s", projectID), globals.GCP_KMS_MODULE_NAME)
	}

	ks := KMSService.New()

	// Initialize loot for this project
	m.mu.Lock()
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["kms-commands"] = &internal.LootFile{
			Name:     "kms-commands",
			Contents: "# KMS Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
	m.mu.Unlock()

	// Get key rings
	keyRings, err := ks.KeyRings(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KMS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate KMS key rings in project %s", projectID))
		return
	}

	// Get crypto keys
	keys, err := ks.CryptoKeys(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KMS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate KMS keys in project %s", projectID))
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectKeyRings[projectID] = keyRings
	m.ProjectCryptoKeys[projectID] = keys

	for _, key := range keys {
		m.addKeyToLoot(projectID, key)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d key ring(s), %d key(s) in project %s", len(keyRings), len(keys), projectID), globals.GCP_KMS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *KMSModule) addKeyToLoot(projectID string, key KMSService.CryptoKeyInfo) {
	lootFile := m.LootMap[projectID]["kms-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# KMS KEY: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, KeyRing: %s, Location: %s\n"+
			"# Purpose: %s, Protection: %s\n",
		key.Name,
		key.ProjectID, key.KeyRing, key.Location,
		key.Purpose, key.ProtectionLevel,
	)

	// Commands
	lootFile.Contents += fmt.Sprintf(
		"\n# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe key:\n"+
			"gcloud kms keys describe %s --keyring=%s --location=%s --project=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud kms keys get-iam-policy %s --keyring=%s --location=%s --project=%s\n"+
			"# List versions:\n"+
			"gcloud kms keys versions list --key=%s --keyring=%s --location=%s --project=%s\n",
		key.Name, key.KeyRing, key.Location, key.ProjectID,
		key.Name, key.KeyRing, key.Location, key.ProjectID,
		key.Name, key.KeyRing, key.Location, key.ProjectID,
	)

	// Purpose-specific commands
	lootFile.Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
	switch key.Purpose {
	case "ENCRYPT_DECRYPT":
		lootFile.Contents += fmt.Sprintf(
			"# Encrypt data:\n"+
				"echo -n 'secret data' | gcloud kms encrypt --key=%s --keyring=%s --location=%s --project=%s --plaintext-file=- --ciphertext-file=encrypted.bin\n"+
				"# Decrypt data:\n"+
				"gcloud kms decrypt --key=%s --keyring=%s --location=%s --project=%s --ciphertext-file=encrypted.bin --plaintext-file=-\n",
			key.Name, key.KeyRing, key.Location, key.ProjectID,
			key.Name, key.KeyRing, key.Location, key.ProjectID,
		)
	case "ASYMMETRIC_SIGN":
		lootFile.Contents += fmt.Sprintf(
			"# Sign data:\n"+
				"gcloud kms asymmetric-sign --key=%s --keyring=%s --location=%s --project=%s --version=1 --digest-algorithm=sha256 --input-file=data.txt --signature-file=signature.bin\n"+
				"# Get public key:\n"+
				"gcloud kms keys versions get-public-key 1 --key=%s --keyring=%s --location=%s --project=%s\n",
			key.Name, key.KeyRing, key.Location, key.ProjectID,
			key.Name, key.KeyRing, key.Location, key.ProjectID,
		)
	case "ASYMMETRIC_DECRYPT":
		lootFile.Contents += fmt.Sprintf(
			"# Decrypt data:\n"+
				"gcloud kms asymmetric-decrypt --key=%s --keyring=%s --location=%s --project=%s --version=1 --ciphertext-file=encrypted.bin --plaintext-file=-\n"+
				"# Get public key:\n"+
				"gcloud kms keys versions get-public-key 1 --key=%s --keyring=%s --location=%s --project=%s\n",
			key.Name, key.KeyRing, key.Location, key.ProjectID,
			key.Name, key.KeyRing, key.Location, key.ProjectID,
		)
	}

	lootFile.Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *KMSModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getKeysHeader returns the header for the crypto keys table
func (m *KMSModule) getKeysHeader() []string {
	return []string{
		"Project",
		"Key Name",
		"Key Ring",
		"Location",
		"Purpose",
		"Protection",
		"Version",
		"State",
		"Rotation",
		"Public Encrypt",
		"Public Decrypt",
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

// getKeyRingsHeader returns the header for the key rings table
func (m *KMSModule) getKeyRingsHeader() []string {
	return []string{
		"Project",
		"Key Ring",
		"Location",
		"Key Count",
	}
}

// keysToTableBody converts crypto keys to table body rows
func (m *KMSModule) keysToTableBody(keys []KMSService.CryptoKeyInfo) [][]string {
	var body [][]string
	for _, key := range keys {
		// Format rotation
		rotation := "-"
		if key.RotationPeriod != "" {
			rotation = formatDuration(key.RotationPeriod)
		}

		// Format protection level
		protection := key.ProtectionLevel
		if protection == "" {
			protection = "SOFTWARE"
		}

		// If key has IAM bindings, create one row per binding
		if len(key.IAMBindings) > 0 {
			for _, binding := range key.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(key.ProjectID),
					key.Name,
					key.KeyRing,
					key.Location,
					formatPurpose(key.Purpose),
					protection,
					key.PrimaryVersion,
					key.PrimaryState,
					rotation,
					shared.BoolToYesNo(key.IsPublicEncrypt),
					shared.BoolToYesNo(key.IsPublicDecrypt),
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// No IAM bindings - single row
			body = append(body, []string{
				m.GetProjectName(key.ProjectID),
				key.Name,
				key.KeyRing,
				key.Location,
				formatPurpose(key.Purpose),
				protection,
				key.PrimaryVersion,
				key.PrimaryState,
				rotation,
				shared.BoolToYesNo(key.IsPublicEncrypt),
				shared.BoolToYesNo(key.IsPublicDecrypt),
				"-",
				"-",
			})
		}
	}
	return body
}

// keyRingsToTableBody converts key rings to table body rows
func (m *KMSModule) keyRingsToTableBody(keyRings []KMSService.KeyRingInfo) [][]string {
	var body [][]string
	for _, kr := range keyRings {
		body = append(body, []string{
			m.GetProjectName(kr.ProjectID),
			kr.Name,
			kr.Location,
			fmt.Sprintf("%d", kr.KeyCount),
		})
	}
	return body
}

// buildTablesForProject builds table files for a single project
func (m *KMSModule) buildTablesForProject(projectID string) []internal.TableFile {
	keys := m.ProjectCryptoKeys[projectID]
	keyRings := m.ProjectKeyRings[projectID]

	keysBody := m.keysToTableBody(keys)
	keyRingsBody := m.keyRingsToTableBody(keyRings)

	var tableFiles []internal.TableFile
	if len(keysBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_KMS_MODULE_NAME + "-keys",
			Header: m.getKeysHeader(),
			Body:   keysBody,
		})
	}
	if len(keyRingsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_KMS_MODULE_NAME + "-keyrings",
			Header: m.getKeyRingsHeader(),
			Body:   keyRingsBody,
		})
	}
	return tableFiles
}

// writeHierarchicalOutput writes output to per-project directories
func (m *KMSModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all projects with data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectCryptoKeys {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectKeyRings {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		tableFiles := m.buildTablesForProject(projectID)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = KMSOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_KMS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *KMSModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allKeys := m.getAllCryptoKeys()
	allKeyRings := m.getAllKeyRings()

	keysBody := m.keysToTableBody(allKeys)
	keyRingsBody := m.keyRingsToTableBody(allKeyRings)

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
	var tableFiles []internal.TableFile
	if len(keysBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_KMS_MODULE_NAME + "-keys",
			Header: m.getKeysHeader(),
			Body:   keysBody,
		})
	}
	if len(keyRingsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_KMS_MODULE_NAME + "-keyrings",
			Header: m.getKeyRingsHeader(),
			Body:   keyRingsBody,
		})
	}

	output := KMSOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

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
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_KMS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// formatPurpose formats key purpose for display
func formatPurpose(purpose string) string {
	switch purpose {
	case "ENCRYPT_DECRYPT":
		return "Symmetric"
	case "ASYMMETRIC_SIGN":
		return "Sign"
	case "ASYMMETRIC_DECRYPT":
		return "Asymm Decrypt"
	case "MAC":
		return "MAC"
	default:
		return purpose
	}
}

// formatDuration formats a duration string for display
func formatDuration(duration string) string {
	// Duration is in format like "7776000s" (90 days)
	duration = strings.TrimSuffix(duration, "s")
	if duration == "" {
		return "-"
	}

	// Parse seconds
	var seconds int64
	fmt.Sscanf(duration, "%d", &seconds)

	if seconds == 0 {
		return "-"
	}

	days := seconds / 86400
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}

	hours := seconds / 3600
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}

	return fmt.Sprintf("%ds", seconds)
}
