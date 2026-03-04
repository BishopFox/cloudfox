package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPIAMCommand = &cobra.Command{
	Use:     globals.GCP_IAM_MODULE_NAME,
	Aliases: []string{"roles"},
	Short:   "Enumerate GCP IAM principals across organizations, folders, and projects",
	Long: `Enumerate GCP IAM principals and their role bindings across the entire hierarchy.

Features:
- Enumerates IAM bindings at organization, folder, and project levels
- Shows role assignments per principal with scope information
- Enumerates service accounts with key information
- Lists custom roles with their permissions
- Identifies groups and their role assignments
- Detects high-privilege roles and public access
- Shows conditional IAM policies with details
- Attempts to retrieve MFA status for users (requires Admin SDK)
- Generates gcloud commands for privilege escalation testing`,
	Run: runGCPIAMCommand,
}

// High-privilege roles that should be flagged
var highPrivilegeRoles = map[string]bool{
	// Owner/Editor
	"roles/owner":  true,
	"roles/editor": true,
	// IAM Admin roles
	"roles/iam.securityAdmin":              true,
	"roles/iam.serviceAccountAdmin":        true,
	"roles/iam.serviceAccountKeyAdmin":     true,
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.serviceAccountUser":         true,
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.roleAdmin":                  true,
	// Resource Manager roles
	"roles/resourcemanager.projectIamAdmin":   true,
	"roles/resourcemanager.folderAdmin":       true,
	"roles/resourcemanager.folderIamAdmin":    true,
	"roles/resourcemanager.organizationAdmin": true,
	// Compute roles
	"roles/compute.admin":         true,
	"roles/compute.instanceAdmin": true,
	"roles/compute.osAdminLogin":  true,
	// Storage roles
	"roles/storage.admin": true,
	// Functions/Run roles
	"roles/cloudfunctions.admin":     true,
	"roles/cloudfunctions.developer": true,
	"roles/run.admin":                true,
	"roles/run.developer":            true,
	// Secret Manager
	"roles/secretmanager.admin": true,
	// Container/Kubernetes
	"roles/container.admin":        true,
	"roles/container.clusterAdmin": true,
	// BigQuery
	"roles/bigquery.admin": true,
	// Deployment Manager
	"roles/deploymentmanager.editor": true,
	// Cloud Build
	"roles/cloudbuild.builds.editor": true,
	// Service Usage
	"roles/serviceusage.serviceUsageAdmin": true,
	// Org Policy
	"roles/orgpolicy.policyAdmin": true,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type IAMModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - using enhanced data
	ScopeBindings   []IAMService.ScopeBinding
	ServiceAccounts []IAMService.ServiceAccountInfo
	CustomRoles     []IAMService.CustomRole
	Groups          []IAMService.GroupInfo
	MFAStatus       map[string]*IAMService.MFAStatus

	// Per-scope loot for inheritance-aware output
	OrgLoot     map[string]*internal.LootFile // orgID -> loot commands
	FolderLoot  map[string]*internal.LootFile // folderID -> loot commands
	ProjectLoot map[string]*internal.LootFile // projectID -> loot commands

	FoxMapperCache *gcpinternal.FoxMapperCache
	OrgCache       *gcpinternal.OrgCache
	mu             sync.Mutex

	// Member to groups mapping (email -> list of group emails)
	MemberToGroups map[string][]string

	// Organization info for output path
	OrgIDs   []string
	OrgNames map[string]string
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type IAMOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o IAMOutput) TableFiles() []internal.TableFile { return o.Table }
func (o IAMOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPIAMCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_IAM_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &IAMModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ScopeBindings:   []IAMService.ScopeBinding{},
		ServiceAccounts: []IAMService.ServiceAccountInfo{},
		CustomRoles:     []IAMService.CustomRole{},
		Groups:          []IAMService.GroupInfo{},
		MFAStatus:       make(map[string]*IAMService.MFAStatus),
		OrgLoot:         make(map[string]*internal.LootFile),
		FolderLoot:      make(map[string]*internal.LootFile),
		ProjectLoot:     make(map[string]*internal.LootFile),
		MemberToGroups:  make(map[string][]string),
		OrgIDs:          []string{},
		OrgNames:        make(map[string]string),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *IAMModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get FoxMapper cache for graph-based analysis
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_IAM_MODULE_NAME)
	}

	// Get OrgCache for hierarchy lookups
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)

	logger.InfoM("Enumerating IAM across organizations, folders, and projects...", globals.GCP_IAM_MODULE_NAME)

	// Use the enhanced IAM enumeration
	iamService := IAMService.New()
	iamData, err := iamService.CombinedIAMEnhanced(ctx, m.ProjectIDs, m.ProjectNames)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_IAM_MODULE_NAME, "Failed to enumerate IAM")
		return
	}

	m.ScopeBindings = iamData.ScopeBindings
	m.ServiceAccounts = iamData.ServiceAccounts
	m.CustomRoles = iamData.CustomRoles
	m.Groups = iamData.Groups
	m.MFAStatus = iamData.MFAStatus

	// Try to enumerate group memberships to build reverse lookup
	enrichedGroups := iamService.GetGroupMemberships(ctx, m.Groups)
	m.Groups = enrichedGroups

	// Build member-to-groups reverse mapping
	for _, group := range enrichedGroups {
		if group.MembershipEnumerated {
			for _, member := range group.Members {
				if member.Email != "" {
					m.MemberToGroups[member.Email] = append(m.MemberToGroups[member.Email], group.Email)
				}
			}
		}
	}

	// Generate loot
	m.generateLoot()

	// Count scopes and track org IDs
	orgCount, folderCount, projectCount := 0, 0, 0
	scopeSeen := make(map[string]bool)
	for _, sb := range m.ScopeBindings {
		key := sb.ScopeType + ":" + sb.ScopeID
		if !scopeSeen[key] {
			scopeSeen[key] = true
			switch sb.ScopeType {
			case "organization":
				orgCount++
				m.OrgIDs = append(m.OrgIDs, sb.ScopeID)
				m.OrgNames[sb.ScopeID] = sb.ScopeName
			case "folder":
				folderCount++
			case "project":
				projectCount++
			}
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d binding(s) across %d org(s), %d folder(s), %d project(s); %d SA(s), %d custom role(s), %d group(s)",
		len(m.ScopeBindings), orgCount, folderCount, projectCount,
		len(m.ServiceAccounts), len(m.CustomRoles), len(m.Groups)), globals.GCP_IAM_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *IAMModule) initializeLootFiles() {
	// Per-scope loot is initialized lazily in addToScopeLoot
}

func (m *IAMModule) generateLoot() {
	// Track unique service accounts we've seen per scope
	sasSeen := make(map[string]bool)

	for _, sb := range m.ScopeBindings {
		if sb.MemberType != "ServiceAccount" {
			continue
		}

		// Create a unique key combining SA email and scope
		scopeKey := fmt.Sprintf("%s:%s:%s", sb.ScopeType, sb.ScopeID, sb.MemberEmail)
		if sasSeen[scopeKey] {
			continue
		}
		sasSeen[scopeKey] = true

		// Check for high privilege roles
		isHighPriv := highPrivilegeRoles[sb.Role]

		var lootContent string
		if isHighPriv {
			lootContent = fmt.Sprintf(
				"# Service Account: %s [HIGH PRIVILEGE] (%s)\n"+
					"# See serviceaccounts-commands loot for describe/keys/impersonation commands\n\n",
				sb.MemberEmail, sb.Role,
			)
		} else {
			continue // Skip non-high-privilege SAs — covered by serviceaccounts-commands loot
		}

		// Route loot to appropriate scope
		m.addToScopeLoot(sb.ScopeType, sb.ScopeID, "iam-commands", lootContent)
	}

	// Add custom roles (project-level)
	for _, role := range m.CustomRoles {
		lootContent := fmt.Sprintf(
			"# Custom Role: %s (%d permissions)\n"+
				"gcloud iam roles describe %s --project=%s\n\n",
			role.Title, role.PermissionCount,
			extractRoleName(role.Name), role.ProjectID,
		)
		m.addToScopeLoot("project", role.ProjectID, "iam-commands", lootContent)
	}

	// Generate IAM enumeration commands
	m.generateEnumerationLoot()
}

// addToScopeLoot adds loot content to the appropriate scope-level loot file
func (m *IAMModule) addToScopeLoot(scopeType, scopeID, lootName, content string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lootMap map[string]*internal.LootFile
	switch scopeType {
	case "organization":
		lootMap = m.OrgLoot
	case "folder":
		lootMap = m.FolderLoot
	case "project":
		lootMap = m.ProjectLoot
	default:
		return
	}

	key := scopeID + ":" + lootName
	if lootMap[key] == nil {
		lootMap[key] = &internal.LootFile{
			Name:     lootName,
			Contents: "# GCP IAM Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n# See also: serviceaccounts-commands for SA-specific describe/keys/impersonation commands\n\n",
		}
	}
	lootMap[key].Contents += content
}

func (m *IAMModule) generateEnumerationLoot() {
	// Add organization-level enumeration commands
	for _, orgID := range m.OrgIDs {
		orgName := m.OrgNames[orgID]
		var lootContent string
		lootContent += fmt.Sprintf("# =============================================================================\n")
		lootContent += fmt.Sprintf("# Organization: %s (%s)\n", orgName, orgID)
		lootContent += fmt.Sprintf("# =============================================================================\n\n")

		lootContent += fmt.Sprintf("# List all IAM bindings for organization\n")
		lootContent += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json\n\n", orgID)

		lootContent += fmt.Sprintf("# List all roles assigned at organization level\n")
		lootContent += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json | jq -r '.bindings[].role' | sort -u\n\n", orgID)

		lootContent += fmt.Sprintf("# List all members with their roles at organization level\n")
		lootContent += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json | jq -r '.bindings[] | \"\\(.role): \\(.members[])\"'\n\n", orgID)

		m.addToScopeLoot("organization", orgID, "iam-enumeration", lootContent)
	}

	// Add project-level enumeration commands
	for _, projectID := range m.ProjectIDs {
		projectName := m.GetProjectName(projectID)
		var lootContent string
		lootContent += fmt.Sprintf("# =============================================================================\n")
		lootContent += fmt.Sprintf("# Project: %s (%s)\n", projectName, projectID)
		lootContent += fmt.Sprintf("# =============================================================================\n\n")

		lootContent += fmt.Sprintf("# List all IAM bindings for project\n")
		lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json\n\n", projectID)

		lootContent += fmt.Sprintf("# List all roles assigned at project level\n")
		lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[].role' | sort -u\n\n", projectID)

		lootContent += fmt.Sprintf("# List all members with their roles at project level\n")
		lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | \"\\(.role): \\(.members[])\"'\n\n", projectID)

		lootContent += fmt.Sprintf("# Find all roles for a specific user (replace USER_EMAIL)\n")
		lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"USER_EMAIL\")) | .role'\n\n", projectID)

		lootContent += fmt.Sprintf("# Find all roles for a specific service account (replace SA_EMAIL)\n")
		lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"SA_EMAIL\")) | .role'\n\n", projectID)

		lootContent += fmt.Sprintf("# List all service accounts in project\n")
		lootContent += fmt.Sprintf("gcloud iam service-accounts list --project=%s --format=json\n\n", projectID)

		lootContent += fmt.Sprintf("# List all custom roles in project\n")
		lootContent += fmt.Sprintf("gcloud iam roles list --project=%s --format=json\n\n", projectID)

		m.addToScopeLoot("project", projectID, "iam-enumeration", lootContent)
	}

	// Track unique identities for enumeration commands - add to project level
	identitiesSeen := make(map[string]bool)
	type identityInfo struct {
		email      string
		memberType string
		roles      []string
		scopes     []string
	}
	identities := make(map[string]*identityInfo)

	// Collect all unique identities and their roles/scopes
	for _, sb := range m.ScopeBindings {
		if sb.MemberEmail == "" {
			continue
		}
		key := sb.MemberEmail
		if !identitiesSeen[key] {
			identitiesSeen[key] = true
			identities[key] = &identityInfo{
				email:      sb.MemberEmail,
				memberType: sb.MemberType,
				roles:      []string{},
				scopes:     []string{},
			}
		}
		identities[key].roles = append(identities[key].roles, sb.Role)
		scopeKey := fmt.Sprintf("%s:%s", sb.ScopeType, sb.ScopeID)
		// Check if scope already exists
		found := false
		for _, s := range identities[key].scopes {
			if s == scopeKey {
				found = true
				break
			}
		}
		if !found {
			identities[key].scopes = append(identities[key].scopes, scopeKey)
		}
	}

	// Add identity-specific enumeration commands per project
	for _, projectID := range m.ProjectIDs {
		var lootContent string
		lootContent += fmt.Sprintf("# =============================================================================\n")
		lootContent += fmt.Sprintf("# Identity-Specific Enumeration Commands\n")
		lootContent += fmt.Sprintf("# =============================================================================\n\n")

		for email, info := range identities {
			if info.memberType == "ServiceAccount" {
				lootContent += fmt.Sprintf("# Service Account: %s\n", email)
				lootContent += fmt.Sprintf("# Find all roles for this service account\n")
				lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"%s\")) | .role'\n\n", projectID, email)
			} else if info.memberType == "User" {
				lootContent += fmt.Sprintf("# User: %s\n", email)
				lootContent += fmt.Sprintf("# Find all roles for this user\n")
				lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"%s\")) | .role'\n\n", projectID, email)
			} else if info.memberType == "Group" {
				lootContent += fmt.Sprintf("# Group: %s\n", email)
				lootContent += fmt.Sprintf("# Find all roles for this group\n")
				lootContent += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"%s\")) | .role'\n\n", projectID, email)
			}
		}

		m.addToScopeLoot("project", projectID, "iam-enumeration", lootContent)
	}
}

// extractRoleName extracts the role name from full path
func extractRoleName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// FederatedIdentityInfo contains parsed information about a federated identity
type FederatedIdentityInfo struct {
	IsFederated  bool
	ProviderType string // AWS, GitHub, GitLab, OIDC, SAML, Azure, etc.
	PoolName     string
	Subject      string
	Attribute    string
}

// parseFederatedIdentity detects and parses federated identity principals
// Federated identities use principal:// or principalSet:// format
func parseFederatedIdentity(identity string) FederatedIdentityInfo {
	info := FederatedIdentityInfo{}

	// Check for principal:// or principalSet:// format
	if !strings.HasPrefix(identity, "principal://") && !strings.HasPrefix(identity, "principalSet://") {
		return info
	}

	info.IsFederated = true

	// Parse the principal URL
	// Format: principal://iam.googleapis.com/projects/{project}/locations/global/workloadIdentityPools/{pool}/subject/{subject}
	// Or: principalSet://iam.googleapis.com/projects/{project}/locations/global/workloadIdentityPools/{pool}/attribute.{attr}/{value}

	// Extract pool name if present
	if strings.Contains(identity, "workloadIdentityPools/") {
		parts := strings.Split(identity, "workloadIdentityPools/")
		if len(parts) > 1 {
			poolParts := strings.Split(parts[1], "/")
			if len(poolParts) > 0 {
				info.PoolName = poolParts[0]
			}
		}
	}

	// Detect provider type based on common patterns in pool names and attributes
	identityLower := strings.ToLower(identity)

	switch {
	case strings.Contains(identityLower, "aws") || strings.Contains(identityLower, "amazon"):
		info.ProviderType = "AWS"
	case strings.Contains(identityLower, "github"):
		info.ProviderType = "GitHub"
	case strings.Contains(identityLower, "gitlab"):
		info.ProviderType = "GitLab"
	case strings.Contains(identityLower, "azure") || strings.Contains(identityLower, "microsoft"):
		info.ProviderType = "Azure"
	case strings.Contains(identityLower, "okta"):
		info.ProviderType = "Okta"
	case strings.Contains(identityLower, "bitbucket"):
		info.ProviderType = "Bitbucket"
	case strings.Contains(identityLower, "circleci"):
		info.ProviderType = "CircleCI"
	case strings.Contains(identity, "attribute."):
		// Has OIDC attributes but unknown provider
		info.ProviderType = "OIDC"
	case strings.Contains(identity, "/subject/"):
		// Has subject but unknown provider type
		info.ProviderType = "Federated"
	default:
		info.ProviderType = "Federated"
	}

	// Extract subject if present
	if strings.Contains(identity, "/subject/") {
		parts := strings.Split(identity, "/subject/")
		if len(parts) > 1 {
			info.Subject = parts[1]
		}
	}

	// Extract attribute and value if present
	// Format: .../attribute.{attr}/{value}
	if strings.Contains(identity, "/attribute.") {
		parts := strings.Split(identity, "/attribute.")
		if len(parts) > 1 {
			attrParts := strings.Split(parts[1], "/")
			if len(attrParts) >= 1 {
				info.Attribute = attrParts[0]
			}
			if len(attrParts) >= 2 {
				// The value is the specific identity (e.g., repo name)
				info.Subject = attrParts[1]
			}
		}
	}

	return info
}

// formatFederatedInfo formats federated identity info for display
func formatFederatedInfo(info FederatedIdentityInfo) string {
	if !info.IsFederated {
		return "-"
	}

	result := info.ProviderType

	// Show subject (specific identity like repo/workflow) if available
	if info.Subject != "" {
		result += ": " + info.Subject
	} else if info.Attribute != "" {
		result += " [" + info.Attribute + "]"
	}

	// Add pool name in parentheses
	if info.PoolName != "" {
		result += " (pool: " + info.PoolName + ")"
	}

	return result
}

// formatCondition formats a condition for display
func formatCondition(condInfo *IAMService.IAMCondition) string {
	if condInfo == nil {
		return "No"
	}

	// Build a meaningful condition summary
	parts := []string{}

	if condInfo.Title != "" {
		parts = append(parts, condInfo.Title)
	}

	// Parse common condition patterns from expression
	expr := condInfo.Expression
	if expr != "" {
		// Check for time-based conditions
		if strings.Contains(expr, "request.time") {
			if strings.Contains(expr, "timestamp") {
				parts = append(parts, "[time-limited]")
			}
		}
		// Check for resource-based conditions
		if strings.Contains(expr, "resource.name") {
			parts = append(parts, "[resource-scoped]")
		}
		// Check for IP-based conditions
		if strings.Contains(expr, "origin.ip") || strings.Contains(expr, "request.origin") {
			parts = append(parts, "[IP-restricted]")
		}
		// Check for device policy
		if strings.Contains(expr, "device") {
			parts = append(parts, "[device-policy]")
		}
	}

	if len(parts) == 0 {
		return "Yes"
	}

	return strings.Join(parts, " ")
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *IAMModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *IAMModule) buildTables() []internal.TableFile {
	// New table structure with Scope Type/ID/Name
	header := []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Entry Type",
		"Identity",
		"Role",
		"Admin",
		"Custom Role",
		"Has Keys",
		"Condition",
		"MFA",
		"Groups",
		"Federated",
		"SA Attack Paths",
	}

	var body [][]string

	// Add scope bindings (one row per binding)
	for _, sb := range m.ScopeBindings {
		// Check admin status from FoxMapper only - shows Org/Folder/Project or No
		// This is different from "high privilege roles" - Admin means broad IAM control
		adminStatus := gcpinternal.GetAdminStatusFromCache(m.FoxMapperCache, sb.MemberEmail)
		if adminStatus == "" {
			adminStatus = "No"
		}

		isCustom := "No"
		if sb.IsCustom {
			isCustom = "Yes"
		}

		// Format condition
		condition := "No"
		if sb.HasCondition {
			condition = formatCondition(sb.ConditionInfo)
		}

		// Get MFA status
		mfa := "-"
		if sb.MemberType == "User" {
			if status, ok := m.MFAStatus[sb.MemberEmail]; ok {
				if status.Error != "" {
					mfa = "Unknown"
				} else if status.HasMFA {
					mfa = "Yes"
				} else {
					mfa = "No"
				}
			}
		} else if sb.MemberType == "ServiceAccount" {
			mfa = "N/A"
		}

		// Get groups this member belongs to
		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sb.MemberEmail]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		// Check for federated identity
		federated := formatFederatedInfo(parseFederatedIdentity(sb.MemberEmail))

		// Check attack paths for service account principals
		attackPaths := "-"
		if sb.MemberType == "ServiceAccount" {
			attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, sb.MemberEmail)
		}

		body = append(body, []string{
			sb.ScopeType,
			sb.ScopeID,
			sb.ScopeName,
			sb.MemberType,
			sb.MemberEmail,
			sb.Role,
			adminStatus,
			isCustom,
			"-",
			condition,
			mfa,
			groups,
			federated,
			attackPaths,
		})
	}

	// Add service accounts
	for _, sa := range m.ServiceAccounts {
		hasKeys := "No"
		if sa.HasKeys {
			hasKeys = "Yes"
		}

		disabled := ""
		if sa.Disabled {
			disabled = " (disabled)"
		}

		// Get groups this SA belongs to
		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sa.Email]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		// Check admin status from FoxMapper
		adminStatus := gcpinternal.GetAdminStatusFromCache(m.FoxMapperCache, sa.Email)
		if adminStatus == "" {
			adminStatus = "No"
		}

		// Check attack paths for this service account
		attackPaths := gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, sa.Email)

		body = append(body, []string{
			"project",
			sa.ProjectID,
			m.GetProjectName(sa.ProjectID),
			"ServiceAccountInfo",
			sa.Email + disabled,
			sa.DisplayName,
			adminStatus,
			"-",
			hasKeys,
			"-",
			"N/A",
			groups,
			"-", // Service accounts are not federated identities
			attackPaths,
		})
	}

	// Add custom roles
	for _, role := range m.CustomRoles {
		deleted := ""
		if role.Deleted {
			deleted = " (deleted)"
		}

		body = append(body, []string{
			"project",
			role.ProjectID,
			m.GetProjectName(role.ProjectID),
			"CustomRole",
			extractRoleName(role.Name) + deleted,
			fmt.Sprintf("%s (%d permissions)", role.Title, role.PermissionCount),
			"-",
			"Yes",
			"-",
			"-",
			"-",
			"-",
			"-", // Custom roles are not federated identities
			"-", // Custom roles don't have attack paths
		})
	}

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "iam",
			Header: header,
			Body:   body,
		},
	}

	return tables
}

// collectAllLootFiles collects all loot files from all scopes for org-level output.
// This merges loot by name (iam-commands, iam-enumeration) across all scopes.
func (m *IAMModule) collectAllLootFiles() []internal.LootFile {
	// Merge loot by name across all scopes
	mergedLoot := make(map[string]*internal.LootFile)

	// Helper to add loot content
	addLoot := func(lootMap map[string]*internal.LootFile) {
		for key, loot := range lootMap {
			// Key format is "scopeID:lootName"
			parts := strings.SplitN(key, ":", 2)
			if len(parts) != 2 {
				continue
			}
			lootName := parts[1]

			if mergedLoot[lootName] == nil {
				mergedLoot[lootName] = &internal.LootFile{
					Name:     lootName,
					Contents: "",
				}
			}
			// Avoid duplicate headers
			content := loot.Contents
			if strings.HasPrefix(content, "# GCP IAM") {
				// Skip header if already present
				if mergedLoot[lootName].Contents == "" {
					// First entry, keep header
				} else {
					// Strip header from subsequent entries
					lines := strings.SplitN(content, "\n\n", 2)
					if len(lines) > 1 {
						content = lines[1]
					}
				}
			}
			mergedLoot[lootName].Contents += content
		}
	}

	// Add in order: org, folder, project
	addLoot(m.OrgLoot)
	addLoot(m.FolderLoot)
	addLoot(m.ProjectLoot)

	var lootFiles []internal.LootFile
	for _, loot := range mergedLoot {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

// collectLootFilesForProject returns loot files for a specific project with inheritance.
// This includes org-level loot + ancestor folder loot + project-level loot.
func (m *IAMModule) collectLootFilesForProject(projectID string) []internal.LootFile {
	// Get ancestry for this project
	var projectOrgID string
	var ancestorFolders []string
	if m.OrgCache != nil && m.OrgCache.IsPopulated() {
		projectOrgID = m.OrgCache.GetProjectOrgID(projectID)
		ancestorFolders = m.OrgCache.GetProjectAncestorFolders(projectID)
	}

	// Merge loot by name
	mergedLoot := make(map[string]*internal.LootFile)

	// Helper to add loot content
	addLoot := func(key string, loot *internal.LootFile) {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return
		}
		lootName := parts[1]

		if mergedLoot[lootName] == nil {
			mergedLoot[lootName] = &internal.LootFile{
				Name:     lootName,
				Contents: "",
			}
		}
		// Avoid duplicate headers
		content := loot.Contents
		if strings.HasPrefix(content, "# GCP IAM") {
			if mergedLoot[lootName].Contents == "" {
				// First entry, keep header
			} else {
				// Strip header from subsequent entries
				lines := strings.SplitN(content, "\n\n", 2)
				if len(lines) > 1 {
					content = lines[1]
				}
			}
		}
		mergedLoot[lootName].Contents += content
	}

	// Add org-level loot
	if projectOrgID != "" {
		for key, loot := range m.OrgLoot {
			if strings.HasPrefix(key, projectOrgID+":") {
				addLoot(key, loot)
			}
		}
	}

	// Add ancestor folder loot (in order from top to bottom)
	for i := len(ancestorFolders) - 1; i >= 0; i-- {
		folderID := ancestorFolders[i]
		for key, loot := range m.FolderLoot {
			if strings.HasPrefix(key, folderID+":") {
				addLoot(key, loot)
			}
		}
	}

	// Add project-level loot
	for key, loot := range m.ProjectLoot {
		if strings.HasPrefix(key, projectID+":") {
			addLoot(key, loot)
		}
	}

	var lootFiles []internal.LootFile
	for _, loot := range mergedLoot {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *IAMModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// Determine org ID - prefer discovered orgs, fall back to hierarchy
	orgID := ""
	if len(m.OrgIDs) > 0 {
		orgID = m.OrgIDs[0]
	} else if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	lootFiles := m.collectAllLootFiles()
	tables := m.buildTables()

	// Check if we should use single-pass tee streaming for large datasets
	totalRows := 0
	for _, t := range tables {
		totalRows += len(t.Body)
	}

	if orgID != "" && totalRows >= 50000 {
		m.writeHierarchicalOutputTee(ctx, logger, orgID, tables, lootFiles)
		return
	}

	// Standard output path for smaller datasets
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		outputData.OrgLevelData[orgID] = IAMOutput{Table: tables, Loot: lootFiles}

		// DUAL OUTPUT: Filtered per-project output (with inherited loot)
		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			projectLoot := m.collectLootFilesForProject(projectID)
			if len(projectTables) > 0 && len(projectTables[0].Body) > 0 {
				outputData.ProjectLevelData[projectID] = IAMOutput{Table: projectTables, Loot: projectLoot}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		outputData.ProjectLevelData[m.ProjectIDs[0]] = IAMOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_IAM_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeHierarchicalOutputTee uses single-pass streaming for large datasets.
func (m *IAMModule) writeHierarchicalOutputTee(ctx context.Context, logger internal.Logger, orgID string, tables []internal.TableFile, lootFiles []internal.LootFile) {
	totalRows := 0
	for _, t := range tables {
		totalRows += len(t.Body)
	}
	logger.InfoM(fmt.Sprintf("Using single-pass tee streaming for %d rows", totalRows), globals.GCP_IAM_MODULE_NAME)

	pathBuilder := m.BuildPathBuilder()

	// Build reverse lookup: for each folder, which projects are under it
	folderToProjects := make(map[string][]string)
	orgToProjects := make(map[string][]string)

	if m.OrgCache != nil && m.OrgCache.IsPopulated() {
		for _, projectID := range m.ProjectIDs {
			// Get the org this project belongs to
			projectOrgID := m.OrgCache.GetProjectOrgID(projectID)
			if projectOrgID != "" {
				orgToProjects[projectOrgID] = append(orgToProjects[projectOrgID], projectID)
			}

			// Get all ancestor folders for this project
			ancestorFolders := m.OrgCache.GetProjectAncestorFolders(projectID)
			for _, folderID := range ancestorFolders {
				folderToProjects[folderID] = append(folderToProjects[folderID], projectID)
			}
		}
	}

	// Create a row router that routes based on scope type and OrgCache
	rowRouter := func(row []string) []string {
		// Row format: [ScopeType, ScopeID, ScopeName, ...]
		scopeType := row[0]
		scopeID := row[1]

		switch scopeType {
		case "project":
			// Direct project binding - route to that project only
			return []string{scopeID}
		case "organization":
			// Org binding - route to all projects under this org
			if projects, ok := orgToProjects[scopeID]; ok {
				return projects
			}
			return m.ProjectIDs
		case "folder":
			// Folder binding - route to all projects under this folder
			if projects, ok := folderToProjects[scopeID]; ok {
				return projects
			}
			return m.ProjectIDs
		default:
			return nil
		}
	}

	config := internal.TeeStreamingConfig{
		OrgID:                orgID,
		ProjectIDs:           m.ProjectIDs,
		Tables:               tables,
		LootFiles:            lootFiles,
		ProjectLootCollector: m.collectLootFilesForProject,
		RowRouter:            rowRouter,
		PathBuilder:          pathBuilder,
		Format:               m.Format,
		Verbosity:            m.Verbosity,
		Wrap:                 m.WrapTable,
	}

	err := internal.HandleHierarchicalOutputTee(config)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing tee streaming output: %v", err), globals.GCP_IAM_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// buildTablesForProject builds tables filtered to only include data for a specific project
func (m *IAMModule) buildTablesForProject(projectID string) []internal.TableFile {
	header := []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Member Type",
		"Member",
		"Role",
		"Admin",
		"Custom Role",
		"Has Keys",
		"Condition",
		"MFA",
		"Groups",
		"Federated",
		"SA Attack Paths",
	}

	var body [][]string

	// Get ancestry data for this project to include org and folder bindings
	var ancestorFolders []string
	var projectOrgID string
	if m.OrgCache != nil && m.OrgCache.IsPopulated() {
		ancestorFolders = m.OrgCache.GetProjectAncestorFolders(projectID)
		projectOrgID = m.OrgCache.GetProjectOrgID(projectID)
	}

	// Build a set of ancestor folder IDs for quick lookup
	ancestorFolderSet := make(map[string]bool)
	for _, folderID := range ancestorFolders {
		ancestorFolderSet[folderID] = true
	}

	// Add scope bindings - include project, org, and ancestor folder bindings
	for _, sb := range m.ScopeBindings {
		// Check if this binding applies to this project
		include := false
		switch sb.ScopeType {
		case "project":
			include = sb.ScopeID == projectID
		case "organization":
			// Include org bindings if this is the project's org
			include = projectOrgID != "" && sb.ScopeID == projectOrgID
		case "folder":
			// Include folder bindings if folder is in project's ancestry
			include = ancestorFolderSet[sb.ScopeID]
		}

		if !include {
			continue
		}

		// Check admin status from FoxMapper only - shows Org/Folder/Project or No
		adminStatus := gcpinternal.GetAdminStatusFromCache(m.FoxMapperCache, sb.MemberEmail)
		if adminStatus == "" {
			adminStatus = "No"
		}

		isCustom := "No"
		if sb.IsCustom {
			isCustom = "Yes"
		}

		condition := "No"
		if sb.HasCondition {
			condition = formatCondition(sb.ConditionInfo)
		}

		mfa := "-"
		if sb.MemberType == "User" {
			if status, ok := m.MFAStatus[sb.MemberEmail]; ok {
				if status.Error != "" {
					mfa = "Unknown"
				} else if status.HasMFA {
					mfa = "Yes"
				} else {
					mfa = "No"
				}
			}
		} else if sb.MemberType == "ServiceAccount" {
			mfa = "N/A"
		}

		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sb.MemberEmail]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		federated := formatFederatedInfo(parseFederatedIdentity(sb.MemberEmail))

		// Check attack paths for service account principals
		attackPaths := "-"
		if sb.MemberType == "ServiceAccount" {
			attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, sb.MemberEmail)
		}

		body = append(body, []string{
			sb.ScopeType,
			sb.ScopeID,
			sb.ScopeName,
			sb.MemberType,
			sb.MemberEmail,
			sb.Role,
			adminStatus,
			isCustom,
			"-",
			condition,
			mfa,
			groups,
			federated,
			attackPaths,
		})
	}

	// Add service accounts for this project only
	for _, sa := range m.ServiceAccounts {
		if sa.ProjectID != projectID {
			continue
		}

		hasKeys := "No"
		if sa.HasKeys {
			hasKeys = "Yes"
		}

		disabled := ""
		if sa.Disabled {
			disabled = " (disabled)"
		}

		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sa.Email]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		// Check admin status from FoxMapper
		adminStatus := gcpinternal.GetAdminStatusFromCache(m.FoxMapperCache, sa.Email)
		if adminStatus == "" {
			adminStatus = "No"
		}

		// Check attack paths for this service account
		attackPaths := gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, sa.Email)

		body = append(body, []string{
			"project",
			sa.ProjectID,
			m.GetProjectName(sa.ProjectID),
			"ServiceAccountInfo",
			sa.Email + disabled,
			sa.DisplayName,
			adminStatus,
			"-",
			hasKeys,
			"-",
			"N/A",
			groups,
			"-",
			attackPaths,
		})
	}

	// Add custom roles for this project only
	for _, role := range m.CustomRoles {
		if role.ProjectID != projectID {
			continue
		}

		deleted := ""
		if role.Deleted {
			deleted = " (deleted)"
		}

		body = append(body, []string{
			"project",
			role.ProjectID,
			m.GetProjectName(role.ProjectID),
			"CustomRole",
			extractRoleName(role.Name) + deleted,
			fmt.Sprintf("%s (%d permissions)", role.Title, role.PermissionCount),
			"-",
			"Yes",
			"-",
			"-",
			"-",
			"-",
			"-",
			"-", // Custom roles don't have attack paths
		})
	}

	if len(body) == 0 {
		return nil
	}

	return []internal.TableFile{
		{
			Name:   "iam",
			Header: header,
			Body:   body,
		},
	}
}

func (m *IAMModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectAllLootFiles()

	// Count security findings for logging
	publicAccessFound := false
	saWithKeys := 0
	highPrivCount := 0

	for _, sb := range m.ScopeBindings {
		if highPrivilegeRoles[sb.Role] {
			highPrivCount++
		}
		if sb.MemberType == "PUBLIC" || sb.MemberType == "ALL_AUTHENTICATED" {
			publicAccessFound = true
		}
	}

	for _, sa := range m.ServiceAccounts {
		if sa.HasKeys {
			saWithKeys++
		}
	}

	// Log warnings for security findings
	if publicAccessFound {
		logger.InfoM("[FINDING] Public access (allUsers/allAuthenticatedUsers) detected in IAM bindings!", globals.GCP_IAM_MODULE_NAME)
	}
	if saWithKeys > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d service account(s) with user-managed keys!", saWithKeys), globals.GCP_IAM_MODULE_NAME)
	}
	if highPrivCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d high-privilege role binding(s)!", highPrivCount), globals.GCP_IAM_MODULE_NAME)
	}

	output := IAMOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output scope - use org if available, otherwise fall back to project
	var scopeType string
	var scopeIdentifiers []string
	var scopeNames []string

	if len(m.OrgIDs) > 0 {
		// Use organization scope with [O] prefix format
		scopeType = "organization"
		for _, orgID := range m.OrgIDs {
			scopeIdentifiers = append(scopeIdentifiers, orgID)
			if name, ok := m.OrgNames[orgID]; ok && name != "" {
				scopeNames = append(scopeNames, name)
			} else {
				scopeNames = append(scopeNames, orgID)
			}
		}
	} else {
		// Fall back to project scope
		scopeType = "project"
		scopeIdentifiers = m.ProjectIDs
		for _, id := range m.ProjectIDs {
			scopeNames = append(scopeNames, m.GetProjectName(id))
		}
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIdentifiers,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_IAM_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
