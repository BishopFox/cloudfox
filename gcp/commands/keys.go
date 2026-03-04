package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	apikeysservice "github.com/BishopFox/cloudfox/gcp/services/apikeysService"
	hmacservice "github.com/BishopFox/cloudfox/gcp/services/hmacService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPKeysCommand = &cobra.Command{
	Use:     globals.GCP_KEYS_MODULE_NAME,
	Aliases: []string{"credentials", "creds", "access-keys"},
	Short:   "Enumerate all GCP keys (SA keys, HMAC keys, API keys)",
	Long: `Enumerate all types of GCP keys and credentials.

Key Types:
- SA Keys: Service account RSA keys for OAuth 2.0 authentication
- HMAC Keys: S3-compatible access keys for Cloud Storage
- API Keys: Project-level keys for API access (Maps, Translation, etc.)

Features:
- Unified view of all credential types
- Shows key age and expiration status
- Identifies Google-managed vs user-managed keys
- Generates exploitation commands for penetration testing`,
	Run: runGCPKeysCommand,
}

// UnifiedKeyInfo represents a key from any source
type UnifiedKeyInfo struct {
	ProjectID    string
	KeyType      string // "SA Key", "HMAC", "API Key"
	KeyID        string
	Owner        string // Email for SA/HMAC, "Project-level" for API keys
	DisplayName  string
	Origin       string // "Google Managed", "User Managed", "Service Account", "User", "-"
	Algorithm    string // Key algorithm (e.g., "KEY_ALG_RSA_2048")
	State        string // "ACTIVE", "INACTIVE", "DELETED", "DISABLED"
	CreateTime   time.Time
	ExpireTime   time.Time
	Expired      bool
	DWDEnabled   bool   // For SA keys - whether the SA has Domain-Wide Delegation enabled
	Restrictions string // For API keys only
	KeyString    string // For API keys only (if accessible)
}

type KeysModule struct {
	gcpinternal.BaseGCPModule
	ProjectKeys map[string][]UnifiedKeyInfo              // projectID -> keys
	LootMap     map[string]map[string]*internal.LootFile // projectID -> loot files
	mu          sync.Mutex
}

type KeysOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o KeysOutput) TableFiles() []internal.TableFile { return o.Table }
func (o KeysOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPKeysCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_KEYS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &KeysModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectKeys:   make(map[string][]UnifiedKeyInfo),
		LootMap:       make(map[string]map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *KeysModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_KEYS_MODULE_NAME, m.processProject)

	allKeys := m.getAllKeys()
	if len(allKeys) == 0 {
		logger.InfoM("No keys found", globals.GCP_KEYS_MODULE_NAME)
		return
	}

	// Count by type
	saKeyCount := 0
	hmacKeyCount := 0
	apiKeyCount := 0
	userManagedCount := 0

	for _, key := range allKeys {
		switch key.KeyType {
		case "SA Key":
			saKeyCount++
			if key.Origin == "User Managed" {
				userManagedCount++
			}
		case "HMAC":
			hmacKeyCount++
		case "API Key":
			apiKeyCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d key(s) (%d SA keys [%d user-managed], %d HMAC keys, %d API keys)",
		len(allKeys), saKeyCount, userManagedCount, hmacKeyCount, apiKeyCount), globals.GCP_KEYS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllKeys returns all keys from all projects
func (m *KeysModule) getAllKeys() []UnifiedKeyInfo {
	var all []UnifiedKeyInfo
	for _, keys := range m.ProjectKeys {
		all = append(all, keys...)
	}
	return all
}

func (m *KeysModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating keys in project: %s", projectID), globals.GCP_KEYS_MODULE_NAME)
	}

	var projectKeys []UnifiedKeyInfo

	// 1. Enumerate Service Account Keys
	iamService := IAMService.New()
	serviceAccounts, err := iamService.ServiceAccounts(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KEYS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate service accounts in project %s", projectID))
	} else {
		for _, sa := range serviceAccounts {
			// Check if DWD is enabled (OAuth2ClientID is set)
			dwdEnabled := sa.OAuth2ClientID != ""

			for _, key := range sa.Keys {
				// Extract key ID from full name
				keyID := key.Name
				if parts := strings.Split(key.Name, "/"); len(parts) > 0 {
					keyID = parts[len(parts)-1]
				}

				origin := "Google Managed"
				if key.KeyType == "USER_MANAGED" {
					origin = "User Managed"
				}

				state := "ACTIVE"
				if key.Disabled {
					state = "DISABLED"
				}

				expired := false
				if !key.ValidBefore.IsZero() && time.Now().After(key.ValidBefore) {
					expired = true
				}

				projectKeys = append(projectKeys, UnifiedKeyInfo{
					ProjectID:   projectID,
					KeyType:     "SA Key",
					KeyID:       keyID,
					Owner:       sa.Email,
					DisplayName: sa.DisplayName,
					Origin:      origin,
					Algorithm:   key.KeyAlgorithm,
					State:       state,
					CreateTime:  key.ValidAfter,
					ExpireTime:  key.ValidBefore,
					Expired:     expired,
					DWDEnabled:  dwdEnabled,
				})
			}
		}
	}

	// 2. Enumerate HMAC Keys
	hmacService := hmacservice.New()
	hmacKeys, err := hmacService.ListHMACKeys(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KEYS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate HMAC keys in project %s", projectID))
	} else {
		for _, key := range hmacKeys {
			origin := "Service Account"
			// Note: User HMAC keys are not enumerable via API, so all we see are SA keys

			projectKeys = append(projectKeys, UnifiedKeyInfo{
				ProjectID:   projectID,
				KeyType:     "HMAC",
				KeyID:       key.AccessID,
				Owner:       key.ServiceAccountEmail,
				DisplayName: "",
				Origin:      origin,
				State:       key.State,
				CreateTime:  key.TimeCreated,
				Expired:     false, // HMAC keys don't expire
			})
		}
	}

	// 3. Enumerate API Keys
	apiKeysService := apikeysservice.New()
	apiKeys, err := apiKeysService.ListAPIKeysWithKeyStrings(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KEYS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate API keys in project %s", projectID))
	} else {
		for _, key := range apiKeys {
			// Extract key ID from full name
			keyID := key.UID
			if keyID == "" {
				if parts := strings.Split(key.Name, "/"); len(parts) > 0 {
					keyID = parts[len(parts)-1]
				}
			}

			state := "ACTIVE"
			if !key.DeleteTime.IsZero() {
				state = "DELETED"
			}

			restrictions := "None"
			if key.HasRestrictions {
				restrictions = key.RestrictionType
				if len(key.AllowedAPIs) > 0 {
					restrictions = fmt.Sprintf("%s (APIs: %d)", key.RestrictionType, len(key.AllowedAPIs))
				}
			}

			projectKeys = append(projectKeys, UnifiedKeyInfo{
				ProjectID:    projectID,
				KeyType:      "API Key",
				KeyID:        keyID,
				Owner:        "Project-level",
				DisplayName:  key.DisplayName,
				Origin:       "-",
				State:        state,
				CreateTime:   key.CreateTime,
				Expired:      false, // API keys don't expire
				Restrictions: restrictions,
				KeyString:    key.KeyString,
			})
		}
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectKeys[projectID] = projectKeys

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["keys-hmac-s3-commands"] = &internal.LootFile{
			Name:     "keys-hmac-s3-commands",
			Contents: "# HMAC S3-Compatible Access Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["keys-apikey-test-commands"] = &internal.LootFile{
			Name:     "keys-apikey-test-commands",
			Contents: "# API Key Test Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["keys-enumeration-commands"] = &internal.LootFile{
			Name:     "keys-enumeration-commands",
			Contents: "# Key Enumeration Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	for _, key := range projectKeys {
		m.addKeyToLoot(projectID, key)
	}
	m.mu.Unlock()
}

func (m *KeysModule) addKeyToLoot(projectID string, key UnifiedKeyInfo) {
	switch key.KeyType {
	case "SA Key":
		// Add enumeration commands for user-managed SA keys, especially old ones
		if key.Origin == "User Managed" {
			lootFile := m.LootMap[projectID]["keys-enumeration-commands"]
			if lootFile != nil {
				age := "-"
				ageWarning := ""
				if !key.CreateTime.IsZero() {
					ageDuration := time.Since(key.CreateTime)
					age = formatKeyAge(ageDuration)
					days := int(ageDuration.Hours() / 24)
					if days >= 365 {
						ageWarning = " [OLD KEY - " + age + "]"
					} else if days >= 90 {
						ageWarning = " [" + age + " old]"
					}
				}

				lootFile.Contents += fmt.Sprintf(
					"# SA Key: %s%s\n"+
						"# Service Account: %s\n"+
						"# Project: %s\n"+
						"# Created: %s (Age: %s)\n"+
						"# Origin: %s\n\n"+
						"# List all keys for this service account:\n"+
						"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n\n"+
						"# Describe specific key:\n"+
						"gcloud iam service-accounts keys get-public-key %s --iam-account=%s --project=%s\n\n",
					key.KeyID,
					ageWarning,
					key.Owner,
					key.ProjectID,
					key.CreateTime.Format("2006-01-02"),
					age,
					key.Origin,
					key.Owner,
					key.ProjectID,
					key.KeyID,
					key.Owner,
					key.ProjectID,
				)
			}
		}

	case "HMAC":
		if key.State == "ACTIVE" {
			lootFile := m.LootMap[projectID]["keys-hmac-s3-commands"]
			if lootFile != nil {
				lootFile.Contents += fmt.Sprintf(
					"# HMAC Key: %s\n"+
						"# Service Account: %s\n"+
						"# Project: %s\n\n"+
						"# Configure AWS CLI with HMAC credentials:\n"+
						"aws configure set aws_access_key_id %s\n"+
						"aws configure set aws_secret_access_key <SECRET_KEY_HERE>\n\n"+
						"# List buckets via S3-compatible endpoint:\n"+
						"aws --endpoint-url https://storage.googleapis.com s3 ls\n\n",
					key.KeyID,
					key.Owner,
					key.ProjectID,
					key.KeyID,
				)
			}
		}

	case "API Key":
		if key.KeyString != "" {
			lootFile := m.LootMap[projectID]["keys-apikey-test-commands"]
			if lootFile != nil {
				lootFile.Contents += fmt.Sprintf(
					"# API Key: %s (%s)\n"+
						"# Project: %s\n"+
						"# Restrictions: %s\n\n"+
						"# Test API access:\n"+
						"curl -H 'X-Goog-Api-Key: %s' 'https://maps.googleapis.com/maps/api/geocode/json?address=test'\n"+
						"curl -H 'X-Goog-Api-Key: %s' 'https://translation.googleapis.com/language/translate/v2?q=Hello&target=es'\n\n",
					key.KeyID,
					key.DisplayName,
					key.ProjectID,
					key.Restrictions,
					key.KeyString,
					key.KeyString,
				)
			}
		}
	}
}

func (m *KeysModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getTableHeader returns the header for the keys table
func (m *KeysModule) getTableHeader() []string {
	return []string{
		"Project ID",
		"Project Name",
		"Key Type",
		"Key ID",
		"Owner",
		"Origin",
		"Algorithm",
		"State",
		"Created",
		"Expires",
		"Age",
		"DWD",
		"Restrictions",
	}
}

// keysToTableBody converts keys to table body rows
func (m *KeysModule) keysToTableBody(keys []UnifiedKeyInfo) [][]string {
	var body [][]string
	for _, key := range keys {
		created := "-"
		if !key.CreateTime.IsZero() {
			created = key.CreateTime.Format("2006-01-02")
		}

		// Calculate age
		age := "-"
		if !key.CreateTime.IsZero() {
			age = formatKeyAge(time.Since(key.CreateTime))
		}

		expires := "-"
		if !key.ExpireTime.IsZero() {
			// Check for "never expires" (year 9999)
			if key.ExpireTime.Year() >= 9999 {
				expires = "Never"
			} else {
				expires = key.ExpireTime.Format("2006-01-02")
			}
		}

		dwd := "-"
		if key.KeyType == "SA Key" {
			if key.DWDEnabled {
				dwd = "Yes"
			} else {
				dwd = "No"
			}
		}

		restrictions := "-"
		if key.KeyType == "API Key" {
			restrictions = key.Restrictions
		}

		algorithm := key.Algorithm
		if algorithm == "" {
			algorithm = "-"
		}

		body = append(body, []string{
			key.ProjectID,
			m.GetProjectName(key.ProjectID),
			key.KeyType,
			key.KeyID,
			key.Owner,
			key.Origin,
			algorithm,
			key.State,
			created,
			expires,
			age,
			dwd,
			restrictions,
		})
	}
	return body
}

// formatKeyAge formats a duration into a human-readable age string
func formatKeyAge(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days >= 365 {
		years := days / 365
		remainingDays := days % 365
		months := remainingDays / 30
		if months > 0 {
			return fmt.Sprintf("%dy %dm", years, months)
		}
		return fmt.Sprintf("%dy", years)
	} else if days >= 30 {
		months := days / 30
		remainingDays := days % 30
		if remainingDays > 0 {
			return fmt.Sprintf("%dm %dd", months, remainingDays)
		}
		return fmt.Sprintf("%dm", months)
	}
	return fmt.Sprintf("%dd", days)
}

// writeHierarchicalOutput writes output to per-project directories
func (m *KeysModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID, keys := range m.ProjectKeys {
		body := m.keysToTableBody(keys)
		tableFiles := []internal.TableFile{{
			Name:   "keys",
			Header: m.getTableHeader(),
			Body:   body,
		}}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !isEmptyLootFile(loot.Contents) {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = KeysOutput{Table: tableFiles, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_KEYS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *KeysModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allKeys := m.getAllKeys()
	body := m.keysToTableBody(allKeys)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !isEmptyLootFile(loot.Contents) {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tables := []internal.TableFile{{
		Name:   "keys",
		Header: m.getTableHeader(),
		Body:   body,
	}}

	output := KeysOutput{Table: tables, Loot: lootFiles}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_KEYS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
