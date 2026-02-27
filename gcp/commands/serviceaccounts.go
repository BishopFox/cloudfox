package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPServiceAccountsCommand = &cobra.Command{
	Use:     globals.GCP_SERVICEACCOUNTS_MODULE_NAME,
	Aliases: []string{"sa", "sas", "service-accounts"},
	Short:   "Enumerate GCP service accounts with security analysis",
	Long: `Enumerate GCP service accounts with detailed security analysis.

Features:
- Lists all service accounts with metadata
- Analyzes user-managed keys (age, expiration)
- Identifies default service accounts (Compute, App Engine, etc.)
- Detects disabled service accounts
- Flags service accounts without key rotation
- Identifies impersonation opportunities

Column Descriptions:
- Impersonation Type: The type of access a principal has TO this service account
  (TokenCreator=can generate access tokens, KeyAdmin=can create keys,
   ActAs=can attach SA to resources, SAAdmin=full admin, SignBlob/SignJwt=can sign as SA)
- Impersonator: The principal (user/SA/group) who has that impersonation capability`,
	Run: runGCPServiceAccountsCommand,
}

// ServiceAccountAnalysis extends ServiceAccountInfo with security analysis
type ServiceAccountAnalysis struct {
	IAMService.ServiceAccountInfo
	IsDefaultSA       bool
	DefaultSAType     string // "compute", "appengine", "cloudbuild", etc.
	OldestKeyAge      int    // Days
	HasExpiredKeys    bool
	HasOldKeys        bool // Keys older than 90 days
	// Pentest: Impersonation analysis
	ImpersonationInfo *IAMService.SAImpersonationInfo
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type ServiceAccountsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectServiceAccounts map[string][]ServiceAccountAnalysis      // projectID -> service accounts
	LootMap                map[string]map[string]*internal.LootFile // projectID -> loot files
	FoxMapperCache         *gcpinternal.FoxMapperCache              // FoxMapper graph data (preferred)
	SARolesCache           map[string]map[string][]string           // projectID -> saEmail -> roles
	mu                     sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type ServiceAccountsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ServiceAccountsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ServiceAccountsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPServiceAccountsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &ServiceAccountsModule{
		BaseGCPModule:          gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectServiceAccounts: make(map[string][]ServiceAccountAnalysis),
		LootMap:                make(map[string]map[string]*internal.LootFile),
		SARolesCache:           make(map[string]map[string][]string),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ServiceAccountsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Try to get FoxMapper cache (preferred - graph-based analysis)
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}

	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_SERVICEACCOUNTS_MODULE_NAME, m.processProject)

	// Get all service accounts for stats
	allSAs := m.getAllServiceAccounts()

	// Check results
	if len(allSAs) == 0 {
		logger.InfoM("No service accounts found", globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
		return
	}

	// Count findings
	withKeys := 0
	defaultSAs := 0
	impersonatable := 0
	for _, sa := range allSAs {
		if sa.HasKeys {
			withKeys++
		}
		if sa.IsDefaultSA {
			defaultSAs++
		}
		if sa.ImpersonationInfo != nil && (len(sa.ImpersonationInfo.TokenCreators) > 0 || len(sa.ImpersonationInfo.KeyCreators) > 0) {
			impersonatable++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d service account(s) (%d with keys, %d default, %d impersonatable)",
		len(allSAs), withKeys, defaultSAs, impersonatable), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllServiceAccounts returns all service accounts from all projects
func (m *ServiceAccountsModule) getAllServiceAccounts() []ServiceAccountAnalysis {
	var all []ServiceAccountAnalysis
	for _, sas := range m.ProjectServiceAccounts {
		all = append(all, sas...)
	}
	return all
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *ServiceAccountsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating service accounts in project: %s", projectID), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}

	// Create service and fetch service accounts with impersonation analysis
	iamService := IAMService.New()
	serviceAccounts, err := iamService.ServiceAccountsWithImpersonation(projectID)
	if err != nil {
		// Fallback to basic enumeration if impersonation analysis fails
		serviceAccounts, err = iamService.ServiceAccounts(projectID)
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_SERVICEACCOUNTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate service accounts in project %s", projectID))
			return
		}
	}

	// Get impersonation info for each SA
	impersonationMap := make(map[string]*IAMService.SAImpersonationInfo)
	impersonationInfos, err := iamService.GetAllServiceAccountImpersonation(projectID)
	if err == nil {
		for i := range impersonationInfos {
			impersonationMap[impersonationInfos[i].ServiceAccount] = &impersonationInfos[i]
		}
	}

	// Get roles for each service account (best effort)
	saRoles := make(map[string][]string)
	for _, sa := range serviceAccounts {
		roles, err := iamService.GetRolesForServiceAccount(projectID, sa.Email)
		if err == nil {
			saRoles[sa.Email] = roles
		}
		// Silently skip if we can't get roles - user may not have IAM permissions
	}

	// Analyze each service account
	var analyzedSAs []ServiceAccountAnalysis
	for _, sa := range serviceAccounts {
		analyzed := m.analyzeServiceAccount(sa, projectID)
		// Attach impersonation info if available
		if info, ok := impersonationMap[sa.Email]; ok {
			analyzed.ImpersonationInfo = info
		}
		// Attach roles if available
		if roles, ok := saRoles[sa.Email]; ok {
			analyzed.Roles = roles
		}
		analyzedSAs = append(analyzedSAs, analyzed)
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectServiceAccounts[projectID] = analyzedSAs
	m.SARolesCache[projectID] = saRoles

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["serviceaccounts-commands"] = &internal.LootFile{
			Name:     "serviceaccounts-commands",
			Contents: "# Service Account Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n# See also: iam-commands/iam-enumeration for IAM policy analysis and high-privilege role flags\n\n",
		}
	}

	// Generate loot for each service account
	for _, sa := range analyzedSAs {
		m.addServiceAccountToLoot(projectID, sa)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d service account(s) in project %s", len(analyzedSAs), projectID), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}
}

// analyzeServiceAccount performs security analysis on a service account
func (m *ServiceAccountsModule) analyzeServiceAccount(sa IAMService.ServiceAccountInfo, projectID string) ServiceAccountAnalysis {
	analyzed := ServiceAccountAnalysis{
		ServiceAccountInfo: sa,
	}

	// Check if it's a default service account
	analyzed.IsDefaultSA, analyzed.DefaultSAType = isDefaultServiceAccount(sa.Email, projectID)

	// Analyze keys
	if len(sa.Keys) > 0 {
		now := time.Now()
		oldestAge := 0

		for _, key := range sa.Keys {
			if key.KeyType == "USER_MANAGED" {
				// Calculate key age
				keyAge := int(now.Sub(key.ValidAfter).Hours() / 24)
				if keyAge > oldestAge {
					oldestAge = keyAge
				}

				// Check for expired keys
				if !key.ValidBefore.IsZero() && now.After(key.ValidBefore) {
					analyzed.HasExpiredKeys = true
				}

				// Check for old keys (> 90 days)
				if keyAge > 90 {
					analyzed.HasOldKeys = true
				}
			}
		}

		analyzed.OldestKeyAge = oldestAge
	}

	return analyzed
}

// isDefaultServiceAccount checks if a service account is a GCP default service account
func isDefaultServiceAccount(email, projectID string) (bool, string) {
	// Compute Engine default service account
	if strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") {
		return true, "Compute Engine"
	}

	// App Engine default service account
	if strings.HasSuffix(email, "@appspot.gserviceaccount.com") {
		return true, "App Engine"
	}

	// Cloud Build service account
	if strings.Contains(email, "@cloudbuild.gserviceaccount.com") {
		return true, "Cloud Build"
	}

	// Cloud Functions service account (project-id@appspot.gserviceaccount.com)
	if email == fmt.Sprintf("%s@appspot.gserviceaccount.com", projectID) {
		return true, "App Engine/Functions"
	}

	// Dataflow service account
	if strings.Contains(email, "-compute@developer.gserviceaccount.com") {
		// This is also used by Dataflow
		return true, "Compute/Dataflow"
	}

	// GKE service account
	if strings.Contains(email, "@container-engine-robot.iam.gserviceaccount.com") {
		return true, "GKE"
	}

	// Cloud SQL service account
	if strings.Contains(email, "@gcp-sa-cloud-sql.iam.gserviceaccount.com") {
		return true, "Cloud SQL"
	}

	// Pub/Sub service account
	if strings.Contains(email, "@gcp-sa-pubsub.iam.gserviceaccount.com") {
		return true, "Pub/Sub"
	}

	// Firebase service accounts
	if strings.Contains(email, "@firebase.iam.gserviceaccount.com") {
		return true, "Firebase"
	}

	// Google APIs service account
	if strings.Contains(email, "@cloudservices.gserviceaccount.com") {
		return true, "Google APIs"
	}

	return false, ""
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ServiceAccountsModule) addServiceAccountToLoot(projectID string, sa ServiceAccountAnalysis) {
	lootFile := m.LootMap[projectID]["serviceaccounts-commands"]
	if lootFile == nil {
		return
	}

	keyFileName := strings.Split(sa.Email, "@")[0]

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# SERVICE ACCOUNT: %s\n"+
			"# =============================================================================\n",
		sa.Email,
	)

	if sa.DisplayName != "" {
		lootFile.Contents += fmt.Sprintf("# Display Name: %s\n", sa.DisplayName)
	}
	if sa.Disabled {
		lootFile.Contents += "# DISABLED\n"
	}
	if sa.IsDefaultSA {
		lootFile.Contents += fmt.Sprintf("# Default SA: %s\n", sa.DefaultSAType)
	}
	if sa.OAuth2ClientID != "" {
		lootFile.Contents += fmt.Sprintf("# DWD Enabled (Client ID: %s)\n", sa.OAuth2ClientID)
	}

	// Add key summary - only show if keys exist
	userKeyCount := 0
	for _, key := range sa.Keys {
		if key.KeyType == "USER_MANAGED" {
			userKeyCount++
		}
	}
	if userKeyCount > 0 {
		lootFile.Contents += fmt.Sprintf("# User Managed Keys: %d\n", userKeyCount)
	}
	if sa.OldestKeyAge > 90 {
		lootFile.Contents += fmt.Sprintf("# WARNING: Key older than 90 days (%d days)\n", sa.OldestKeyAge)
	}

	// Add impersonation info if available
	if sa.ImpersonationInfo != nil {
		if len(sa.ImpersonationInfo.TokenCreators) > 0 {
			lootFile.Contents += fmt.Sprintf("# Token Creators: %s\n", strings.Join(sa.ImpersonationInfo.TokenCreators, ", "))
		}
		if len(sa.ImpersonationInfo.KeyCreators) > 0 {
			lootFile.Contents += fmt.Sprintf("# Key Creators: %s\n", strings.Join(sa.ImpersonationInfo.KeyCreators, ", "))
		}
		if len(sa.ImpersonationInfo.ActAsUsers) > 0 {
			lootFile.Contents += fmt.Sprintf("# ActAs Users: %s\n", strings.Join(sa.ImpersonationInfo.ActAsUsers, ", "))
		}
	}

	lootFile.Contents += fmt.Sprintf(`
# === ENUMERATION COMMANDS ===

# Describe service account
gcloud iam service-accounts describe %s --project=%s --format=json | jq '{email: .email, displayName: .displayName, disabled: .disabled, oauth2ClientId: .oauth2ClientId}'

# List all keys with creation dates and expiration
gcloud iam service-accounts keys list --iam-account=%s --project=%s --format=json | jq -r '.[] | {keyId: .name | split("/") | last, keyType: .keyType, created: .validAfterTime, expires: .validBeforeTime}'

# Get IAM policy - who can impersonate this SA
gcloud iam service-accounts get-iam-policy %s --project=%s --format=json | jq '.bindings[] | {role: .role, members: .members}'

# Check project-level IAM bindings for this SA
gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains("%s")) | {role: .role, member: "%s"}'

# Check what resources this SA can access
gcloud asset search-all-iam-policies --scope=projects/%s --query='policy:%s' --format=json | jq -r '.results[] | {resource: .resource, roles: [.policy.bindings[].role]}'

`, sa.Email, projectID,
		sa.Email, projectID,
		sa.Email, projectID,
		projectID, sa.Email, sa.Email,
		projectID, sa.Email)

	lootFile.Contents += fmt.Sprintf(`# === EXPLOIT COMMANDS ===

# Impersonate SA - get access token
gcloud auth print-access-token --impersonate-service-account=%s

# Impersonate SA - get identity token (for Cloud Run/Functions)
gcloud auth print-identity-token --impersonate-service-account=%s

# Create a new key for this SA (requires iam.serviceAccountKeys.create)
gcloud iam service-accounts keys create %s-key.json --iam-account=%s --project=%s

# Activate the downloaded key
gcloud auth activate-service-account --key-file=%s-key.json

# Test impersonation - list projects as this SA
gcloud projects list --impersonate-service-account=%s

`, sa.Email, sa.Email, keyFileName, sa.Email, projectID, keyFileName, sa.Email)

	// Add DWD exploitation if enabled
	if sa.OAuth2ClientID != "" {
		lootFile.Contents += fmt.Sprintf(`# === DOMAIN-WIDE DELEGATION EXPLOITATION ===
# This SA has DWD enabled - can impersonate Workspace users!
# OAuth2 Client ID: %s

# Run the domain-wide-delegation module for detailed exploitation:
# cloudfox gcp domain-wide-delegation -p %s

# Quick test - requires SA key and target Workspace user email:
# python dwd_exploit.py --key-file %s-key.json --subject admin@domain.com --all-scopes

`, sa.OAuth2ClientID, projectID, keyFileName)
	}

	lootFile.Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ServiceAccountsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getTableHeader returns the header for service accounts table
// Columns are grouped logically:
// - Identity: Project, Email, Display Name, Disabled, Default SA
// - Keys: User Managed Keys, Google Managed Keys, Oldest Key Age
// - Permissions: DWD, Roles, SA Attack Paths
// - Impersonation: IAM Binding Role, IAM Binding Principal
func (m *ServiceAccountsModule) getTableHeader() []string {
	return []string{
		// Identity
		"Project",
		"Email",
		"Display Name",
		"Disabled",
		"Default SA",
		// Keys
		"User Managed Keys",
		"Google Managed Keys",
		"Oldest Key Age",
		// Permissions
		"DWD",
		"Roles",
		"SA Attack Paths",
		// Impersonation
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

// serviceAccountsToTableBody converts service accounts to table body rows
func (m *ServiceAccountsModule) serviceAccountsToTableBody(serviceAccounts []ServiceAccountAnalysis) [][]string {
	var body [][]string
	for _, sa := range serviceAccounts {
		disabled := "No"
		if sa.Disabled {
			disabled = "Yes"
		}

		defaultSA := "No"
		if sa.IsDefaultSA {
			defaultSA = sa.DefaultSAType
		}

		// Check if DWD is enabled
		dwd := "No"
		if sa.OAuth2ClientID != "" {
			dwd = "Yes"
		}

		// Check attack paths (privesc/exfil/lateral) for this service account
		// FoxMapper takes priority if available (graph-based analysis)
		attackPaths := gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, sa.Email)

		// Count keys by type and find oldest key age
		userKeyCount := 0
		googleKeyCount := 0
		for _, key := range sa.Keys {
			if key.KeyType == "USER_MANAGED" {
				userKeyCount++
			} else if key.KeyType == "SYSTEM_MANAGED" {
				googleKeyCount++
			}
		}
		userKeys := "-"
		if userKeyCount > 0 {
			userKeys = fmt.Sprintf("%d", userKeyCount)
		}
		googleKeys := "-"
		if googleKeyCount > 0 {
			googleKeys = fmt.Sprintf("%d", googleKeyCount)
		}

		// Format oldest key age
		oldestKeyAge := "-"
		if sa.OldestKeyAge > 0 {
			if sa.OldestKeyAge > 365 {
				oldestKeyAge = fmt.Sprintf("%dy %dd", sa.OldestKeyAge/365, sa.OldestKeyAge%365)
			} else {
				oldestKeyAge = fmt.Sprintf("%dd", sa.OldestKeyAge)
			}
			// Add warning indicator for old keys
			if sa.OldestKeyAge > 90 {
				oldestKeyAge += " ⚠"
			}
		}

		// Format roles for display
		rolesDisplay := IAMService.FormatRolesShort(sa.Roles)

		// Build IAM bindings from impersonation info
		// Row order: Identity (Project, Email, Display Name, Disabled, Default SA),
		//            Keys (User Managed Keys, Google Managed Keys, Oldest Key Age),
		//            Permissions (DWD, Roles, SA Attack Paths),
		//            Impersonation (IAM Binding Role, IAM Binding Principal)
		hasBindings := false
		if sa.ImpersonationInfo != nil {
			for _, member := range sa.ImpersonationInfo.TokenCreators {
				email := extractEmailFromMember(member)
				if email != sa.Email {
					hasBindings = true
					body = append(body, []string{
						m.GetProjectName(sa.ProjectID), sa.Email, sa.DisplayName, disabled, defaultSA,
						userKeys, googleKeys, oldestKeyAge,
						dwd, rolesDisplay, attackPaths,
						"TokenCreator", member,
					})
				}
			}
			for _, member := range sa.ImpersonationInfo.KeyCreators {
				email := extractEmailFromMember(member)
				if email != sa.Email {
					hasBindings = true
					body = append(body, []string{
						m.GetProjectName(sa.ProjectID), sa.Email, sa.DisplayName, disabled, defaultSA,
						userKeys, googleKeys, oldestKeyAge,
						dwd, rolesDisplay, attackPaths,
						"KeyAdmin", member,
					})
				}
			}
			for _, member := range sa.ImpersonationInfo.ActAsUsers {
				email := extractEmailFromMember(member)
				if email != sa.Email {
					hasBindings = true
					body = append(body, []string{
						m.GetProjectName(sa.ProjectID), sa.Email, sa.DisplayName, disabled, defaultSA,
						userKeys, googleKeys, oldestKeyAge,
						dwd, rolesDisplay, attackPaths,
						"ActAs", member,
					})
				}
			}
			for _, member := range sa.ImpersonationInfo.SAAdmins {
				email := extractEmailFromMember(member)
				if email != sa.Email {
					hasBindings = true
					body = append(body, []string{
						m.GetProjectName(sa.ProjectID), sa.Email, sa.DisplayName, disabled, defaultSA,
						userKeys, googleKeys, oldestKeyAge,
						dwd, rolesDisplay, attackPaths,
						"SAAdmin", member,
					})
				}
			}
			for _, member := range sa.ImpersonationInfo.SignBlobUsers {
				email := extractEmailFromMember(member)
				if email != sa.Email {
					hasBindings = true
					body = append(body, []string{
						m.GetProjectName(sa.ProjectID), sa.Email, sa.DisplayName, disabled, defaultSA,
						userKeys, googleKeys, oldestKeyAge,
						dwd, rolesDisplay, attackPaths,
						"SignBlob", member,
					})
				}
			}
			for _, member := range sa.ImpersonationInfo.SignJwtUsers {
				email := extractEmailFromMember(member)
				if email != sa.Email {
					hasBindings = true
					body = append(body, []string{
						m.GetProjectName(sa.ProjectID), sa.Email, sa.DisplayName, disabled, defaultSA,
						userKeys, googleKeys, oldestKeyAge,
						dwd, rolesDisplay, attackPaths,
						"SignJwt", member,
					})
				}
			}
		}

		if !hasBindings {
			body = append(body, []string{
				m.GetProjectName(sa.ProjectID), sa.Email, sa.DisplayName, disabled, defaultSA,
				userKeys, googleKeys, oldestKeyAge,
				dwd, rolesDisplay, attackPaths,
				"-", "-",
			})
		}
	}
	return body
}

// writeHierarchicalOutput writes output to per-project directories
func (m *ServiceAccountsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID, sas := range m.ProjectServiceAccounts {
		body := m.serviceAccountsToTableBody(sas)
		tableFiles := []internal.TableFile{{
			Name:   "serviceaccounts",
			Header: m.getTableHeader(),
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

		outputData.ProjectLevelData[projectID] = ServiceAccountsOutput{Table: tableFiles, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *ServiceAccountsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allSAs := m.getAllServiceAccounts()
	body := m.serviceAccountsToTableBody(allSAs)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tables := []internal.TableFile{{
		Name:   "serviceaccounts",
		Header: m.getTableHeader(),
		Body:   body,
	}}

	output := ServiceAccountsOutput{Table: tables, Loot: lootFiles}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// extractEmailFromMember extracts the email/identity from an IAM member string
// e.g., "user:alice@example.com" -> "alice@example.com"
// e.g., "serviceAccount:sa@project.iam.gserviceaccount.com" -> "sa@project.iam..."
func extractEmailFromMember(member string) string {
	if idx := strings.Index(member, ":"); idx != -1 {
		return member[idx+1:]
	}
	return member
}
