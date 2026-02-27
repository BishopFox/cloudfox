package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	SecretsService "github.com/BishopFox/cloudfox/gcp/services/secretsService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPSecretsCommand = &cobra.Command{
	Use:     globals.GCP_SECRETS_MODULE_NAME,
	Aliases: []string{"secretmanager", "sm"},
	Short:   "Enumerate GCP Secret Manager secrets with security configuration",
	Long: `Enumerate GCP Secret Manager secrets across projects with security-relevant details.

Features:
- Lists all secrets with metadata and security configuration
- Shows encryption type (Google-managed vs CMEK)
- Shows replication configuration (automatic vs user-managed)
- Shows expiration and rotation settings
- Enumerates IAM policies per secret
- Generates gcloud commands for secret access
- Generates exploitation commands for secret extraction

Security Columns:
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)
- Replication: "automatic" or "user-managed" with locations
- Rotation: Whether automatic rotation is enabled
- Expiration: Whether the secret has an expiration time/TTL
- VersionDestroyTTL: Delayed destruction period for old versions

Resource IAM Columns:
- IAM Binding Role: The IAM role granted ON this secret (e.g., roles/secretmanager.secretAccessor)
- IAM Binding Principal: The principal (user/SA/group) who has that role on this secret`,
	Run: runGCPSecretsCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type SecretsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectSecrets map[string][]SecretsService.SecretInfo   // projectID -> secrets
	LootMap        map[string]map[string]*internal.LootFile // projectID -> loot files
	FoxMapperCache *gcpinternal.FoxMapperCache              // Cached FoxMapper analysis results
	client         *secretmanager.Client
	mu             sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type SecretsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SecretsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SecretsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPSecretsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_SECRETS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create Secret Manager client
	client, err := secretmanager.NewClient(cmdCtx.Ctx)
	if err != nil {
		cmdCtx.Logger.ErrorM(fmt.Sprintf("Failed to create Secret Manager client: %v", err), globals.GCP_SECRETS_MODULE_NAME)
		return
	}
	defer client.Close()

	// Create module instance
	module := &SecretsModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectSecrets: make(map[string][]SecretsService.SecretInfo),
		LootMap:        make(map[string]map[string]*internal.LootFile),
		client:         client,
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *SecretsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get FoxMapper cache for graph-based analysis
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_SECRETS_MODULE_NAME)
	}

	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_SECRETS_MODULE_NAME, m.processProject)

	// Get all secrets for stats
	allSecrets := m.getAllSecrets()
	if len(allSecrets) == 0 {
		logger.InfoM("No secrets found", globals.GCP_SECRETS_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d secret(s)", len(allSecrets)), globals.GCP_SECRETS_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllSecrets returns all secrets from all projects (for statistics)
func (m *SecretsModule) getAllSecrets() []SecretsService.SecretInfo {
	var all []SecretsService.SecretInfo
	for _, secrets := range m.ProjectSecrets {
		all = append(all, secrets...)
	}
	return all
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *SecretsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating secrets in project: %s", projectID), globals.GCP_SECRETS_MODULE_NAME)
	}

	// Create service and fetch secrets
	ss := SecretsService.New(m.client)
	secrets, err := ss.Secrets(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_SECRETS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate secrets in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectSecrets[projectID] = secrets

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["secrets-commands"] = &internal.LootFile{
			Name:     "secrets-commands",
			Contents: "# GCP Secret Manager Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	// Generate loot for each secret
	for _, secret := range secrets {
		m.addSecretToLoot(projectID, secret)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d secret(s) in project %s", len(secrets), projectID), globals.GCP_SECRETS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *SecretsModule) addSecretToLoot(projectID string, secret SecretsService.SecretInfo) {
	lootFile := m.LootMap[projectID]["secrets-commands"]
	if lootFile == nil {
		return
	}

	// Extract secret name from full path
	secretName := getSecretShortName(secret.Name)

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# SECRET: %s (Project: %s)\n"+
			"# =============================================================================\n"+
			"# Encryption: %s, Replication: %s, Rotation: %s\n"+
			"# Created: %s\n",
		secretName, secret.ProjectID,
		secret.EncryptionType, secret.ReplicationType, secret.Rotation,
		secret.CreationTime,
	)

	// KMS key info
	if secret.KMSKeyName != "" {
		lootFile.Contents += fmt.Sprintf("# KMS Key: %s\n", secret.KMSKeyName)
	}

	// Rotation info
	if secret.Rotation == "enabled" {
		if secret.RotationPeriod != "" {
			lootFile.Contents += fmt.Sprintf("# Rotation Period: %s\n", secret.RotationPeriod)
		}
		if secret.NextRotationTime != "" {
			lootFile.Contents += fmt.Sprintf("# Next Rotation: %s\n", secret.NextRotationTime)
		}
	}

	// IAM bindings
	if len(secret.IAMBindings) > 0 {
		lootFile.Contents += "# IAM Bindings:\n"
		for _, binding := range secret.IAMBindings {
			lootFile.Contents += fmt.Sprintf(
				"#   %s: %s\n",
				binding.Role,
				strings.Join(binding.Members, ", "),
			)
		}
	}

	// Commands
	lootFile.Contents += fmt.Sprintf(
		"\n# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe secret:\n"+
			"gcloud secrets describe %s --project=%s\n"+
			"# List versions:\n"+
			"gcloud secrets versions list %s --project=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud secrets get-iam-policy %s --project=%s\n\n"+
			"# === EXPLOIT COMMANDS ===\n\n"+
			"# Access latest version:\n"+
			"gcloud secrets versions access latest --secret=%s --project=%s\n"+
			"# Download all versions:\n"+
			"for v in $(gcloud secrets versions list %s --project=%s --format='value(name)'); do\n"+
			"  echo \"=== Version $v ===\"\n"+
			"  gcloud secrets versions access $v --secret=%s --project=%s\n"+
			"done\n"+
			"# Add a new version:\n"+
			"echo -n 'new-secret-value' | gcloud secrets versions add %s --project=%s --data-file=-\n\n",
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
	)
}


// ------------------------------
// Helper functions
// ------------------------------

// getSecretShortName extracts the short name from a full secret resource path
func getSecretShortName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *SecretsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *SecretsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()

	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, secrets := range m.ProjectSecrets {
		body := m.secretsToTableBody(secrets)
		tables := []internal.TableFile{{
			Name:   globals.GCP_SECRETS_MODULE_NAME,
			Header: header,
			Body:   body,
		}}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = SecretsOutput{Table: tables, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_SECRETS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *SecretsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()
	allSecrets := m.getAllSecrets()
	body := m.secretsToTableBody(allSecrets)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tableFiles := []internal.TableFile{{
		Name:   globals.GCP_SECRETS_MODULE_NAME,
		Header: header,
		Body:   body,
	}}

	output := SecretsOutput{
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
		scopeNames,   // scopeNames
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SECRETS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// getTableHeader returns the secrets table header
func (m *SecretsModule) getTableHeader() []string {
	return []string{
		"Project",
		"Name",
		"Encryption",
		"KMS Key",
		"Replication",
		"Rotation",
		"Rotation Period",
		"Next Rotation",
		"Expiration",
		"Destroy TTL",
		"Created",
		"IAM Binding Role",
		"Principal Type",
		"IAM Binding Principal",
		"Principal Attack Paths",
	}
}

// secretsToTableBody converts secrets to table body rows
func (m *SecretsModule) secretsToTableBody(secrets []SecretsService.SecretInfo) [][]string {
	var body [][]string
	for _, secret := range secrets {
		secretName := getSecretShortName(secret.Name)

		// Format expiration
		expiration := "-"
		if secret.HasExpiration {
			if secret.ExpireTime != "" {
				expiration = secret.ExpireTime
			} else if secret.TTL != "" {
				expiration = "TTL: " + secret.TTL
			}
		}

		// Format version destroy TTL
		destroyTTL := "-"
		if secret.VersionDestroyTTL != "" {
			destroyTTL = secret.VersionDestroyTTL
		}

		// Format KMS key (no truncation)
		kmsKey := "-"
		if secret.KMSKeyName != "" {
			kmsKey = secret.KMSKeyName
		}

		// Format rotation period
		rotationPeriod := "-"
		if secret.RotationPeriod != "" {
			rotationPeriod = secret.RotationPeriod
		}

		// Format next rotation
		nextRotation := "-"
		if secret.NextRotationTime != "" {
			nextRotation = secret.NextRotationTime
		}

		// One row per IAM member
		if len(secret.IAMBindings) > 0 {
			for _, binding := range secret.IAMBindings {
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
						m.GetProjectName(secret.ProjectID),
						secretName,
						secret.EncryptionType,
						kmsKey,
						secret.ReplicationType,
						secret.Rotation,
						rotationPeriod,
						nextRotation,
						expiration,
						destroyTTL,
						secret.CreationTime,
						binding.Role,
						memberType,
						member,
						attackPaths,
					})
				}
			}
		} else {
			// Secret with no IAM bindings
			body = append(body, []string{
				m.GetProjectName(secret.ProjectID),
				secretName,
				secret.EncryptionType,
				kmsKey,
				secret.ReplicationType,
				secret.Rotation,
				rotationPeriod,
				nextRotation,
				expiration,
				destroyTTL,
				secret.CreationTime,
				"-",
				"-",
				"-",
				"-",
			})
		}
	}
	return body
}
