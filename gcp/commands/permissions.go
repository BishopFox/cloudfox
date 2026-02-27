package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPermissionsCommand = &cobra.Command{
	Use:     globals.GCP_PERMISSIONS_MODULE_NAME,
	Aliases: []string{"perms", "privs"},
	Short:   "Enumerate ALL permissions for each IAM entity with full inheritance explosion",
	Long: `Enumerate ALL permissions for each IAM entity with complete inheritance explosion.

This module provides COMPLETE permission visibility by:
- Enumerating organization-level IAM bindings (top of hierarchy)
- Enumerating folder-level IAM bindings (inherited to child resources)
- Enumerating project-level IAM bindings (resource-specific)
- EXPLODING every role into its individual permissions (one line per permission)
- Tracking the exact inheritance source for each permission
- Expanding group memberships to show inherited permissions
- Identifying cross-project access patterns
- Flagging dangerous/privesc permissions

Output: Single unified table with one row per permission entry.`,
	Run: runGCPPermissionsCommand,
}

// High-privilege permission prefixes that should be flagged
var highPrivilegePermissionPrefixes = []string{
	"iam.serviceAccounts.actAs",
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccounts.getOpenIdToken",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccountKeys.create",
	"iam.roles.create",
	"iam.roles.update",
	"resourcemanager.projects.setIamPolicy",
	"resourcemanager.folders.setIamPolicy",
	"resourcemanager.organizations.setIamPolicy",
	"compute.instances.setMetadata",
	"compute.instances.setServiceAccount",
	"compute.projects.setCommonInstanceMetadata",
	"storage.buckets.setIamPolicy",
	"storage.objects.setIamPolicy",
	"cloudfunctions.functions.setIamPolicy",
	"run.services.setIamPolicy",
	"secretmanager.secrets.setIamPolicy",
	"deploymentmanager.deployments.create",
	"cloudbuild.builds.create",
	"container.clusters.getCredentials",
	"orgpolicy.policy.set",
}

// ExplodedPermission represents a single permission entry with full context
type ExplodedPermission struct {
	Entity            string
	EntityType        string
	EntityEmail       string
	Permission        string
	Role              string
	RoleType          string
	ResourceScope     string
	ResourceScopeType string
	ResourceScopeID   string
	ResourceScopeName string
	InheritedFrom     string
	IsInherited       bool
	HasCondition      bool
	Condition         string
	ConditionTitle    string
	EffectiveProject  string
	ProjectName       string
	IsCrossProject    bool
	SourceProject     string
	IsHighPrivilege   bool
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type PermissionsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - now per-project for hierarchical output
	ProjectPerms      map[string][]ExplodedPermission          // projectID -> permissions
	OrgPerms          map[string][]ExplodedPermission          // orgID -> org-level permissions
	FolderPerms       map[string][]ExplodedPermission          // folderID -> folder-level permissions
	EntityPermissions []IAMService.EntityPermissions           // Legacy: aggregated for stats
	GroupInfos        []IAMService.GroupInfo                   // Legacy: aggregated for stats
	OrgBindings       []IAMService.PolicyBinding               // org-level bindings
	FolderBindings    map[string][]IAMService.PolicyBinding    // folder-level bindings

	// Per-scope loot files for inheritance-aware output
	OrgLoot     map[string]*internal.LootFile // orgID -> loot commands for org-level bindings
	FolderLoot  map[string]*internal.LootFile // folderID -> loot commands for folder-level bindings
	ProjectLoot map[string]*internal.LootFile // projectID -> loot commands for project-level bindings
	EnumLoot    *internal.LootFile            // permissions-enumeration loot file

	OrgCache *gcpinternal.OrgCache // OrgCache for hierarchy lookups
	mu       sync.Mutex

	// Organization info for output path
	OrgIDs   []string
	OrgNames map[string]string
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type PermissionsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PermissionsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PermissionsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPPermissionsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PERMISSIONS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PermissionsModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPerms:      make(map[string][]ExplodedPermission),
		OrgPerms:          make(map[string][]ExplodedPermission),
		FolderPerms:       make(map[string][]ExplodedPermission),
		EntityPermissions: []IAMService.EntityPermissions{},
		GroupInfos:        []IAMService.GroupInfo{},
		OrgBindings:       []IAMService.PolicyBinding{},
		FolderBindings:    make(map[string][]IAMService.PolicyBinding),
		OrgLoot:           make(map[string]*internal.LootFile),
		FolderLoot:        make(map[string]*internal.LootFile),
		ProjectLoot:       make(map[string]*internal.LootFile),
		OrgIDs:            []string{},
		OrgNames:          make(map[string]string),
		EnumLoot:          &internal.LootFile{Name: "permissions-enumeration", Contents: ""},
	}

	// Initialize enumeration loot file
	module.initializeEnumerationLoot()

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *PermissionsModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Enumerating ALL permissions with full inheritance explosion...", globals.GCP_PERMISSIONS_MODULE_NAME)
	logger.InfoM("This includes organization, folder, and project-level bindings", globals.GCP_PERMISSIONS_MODULE_NAME)

	// Get OrgCache for hierarchy lookups (used for inheritance-aware routing)
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)

	// First, try to enumerate organization-level bindings
	m.enumerateOrganizationBindings(ctx, logger)

	// Run project enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_PERMISSIONS_MODULE_NAME, m.processProject)

	// Get all permissions for stats
	allPerms := m.getAllExplodedPerms()
	if len(allPerms) == 0 {
		logger.InfoM("No permissions found", globals.GCP_PERMISSIONS_MODULE_NAME)
		return
	}

	// Count statistics
	uniqueEntities := make(map[string]bool)
	uniquePerms := make(map[string]bool)
	inheritedCount := 0
	crossProjectCount := 0
	highPrivCount := 0

	for _, ep := range allPerms {
		uniqueEntities[ep.Entity] = true
		uniquePerms[ep.Permission] = true
		if ep.IsInherited {
			inheritedCount++
		}
		if ep.IsCrossProject {
			crossProjectCount++
		}
		if ep.IsHighPrivilege {
			highPrivCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Exploded %d total permission entries for %d entities",
		len(allPerms), len(uniqueEntities)), globals.GCP_PERMISSIONS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Unique permissions: %d | Inherited: %d | Cross-project: %d | High-privilege: %d",
		len(uniquePerms), inheritedCount, crossProjectCount, highPrivCount), globals.GCP_PERMISSIONS_MODULE_NAME)

	if len(m.GroupInfos) > 0 {
		groupsEnumerated := 0
		for _, gi := range m.GroupInfos {
			if gi.MembershipEnumerated {
				groupsEnumerated++
			}
		}
		logger.InfoM(fmt.Sprintf("Found %d group(s), enumerated membership for %d", len(m.GroupInfos), groupsEnumerated), globals.GCP_PERMISSIONS_MODULE_NAME)

		unenumeratedGroups := len(m.GroupInfos) - groupsEnumerated
		if unenumeratedGroups > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Could not enumerate membership for %d group(s) - permissions inherited via these groups are NOT visible!", unenumeratedGroups), globals.GCP_PERMISSIONS_MODULE_NAME)
		}
	}

	// Generate enumeration loot after all projects are processed
	m.generateEnumerationLoot()

	m.writeOutput(ctx, logger)
}

// getAllExplodedPerms returns all permissions from all scopes (for statistics)
func (m *PermissionsModule) getAllExplodedPerms() []ExplodedPermission {
	var all []ExplodedPermission
	for _, perms := range m.OrgPerms {
		all = append(all, perms...)
	}
	for _, perms := range m.FolderPerms {
		all = append(all, perms...)
	}
	for _, perms := range m.ProjectPerms {
		all = append(all, perms...)
	}
	return all
}

// enumerateOrganizationBindings tries to get organization-level IAM bindings
func (m *PermissionsModule) enumerateOrganizationBindings(ctx context.Context, logger internal.Logger) {
	orgsSvc := orgsservice.New()

	// Get org display names mapping (orgID -> displayName)
	orgDisplayNames := make(map[string]string)
	orgs, err := orgsSvc.SearchOrganizations()
	if err == nil {
		for _, org := range orgs {
			// org.Name is "organizations/ORGID", extract just the ID
			orgID := strings.TrimPrefix(org.Name, "organizations/")
			orgDisplayNames[orgID] = org.DisplayName
		}
	}

	if len(m.ProjectIDs) > 0 {
		iamSvc := IAMService.New()

		bindings, err := iamSvc.PoliciesWithInheritance(m.ProjectIDs[0])
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not get inherited policies: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
			}
			return
		}

		for _, binding := range bindings {
			if binding.ResourceType == "organization" {
				m.mu.Lock()
				m.OrgBindings = append(m.OrgBindings, binding)
				// Track org IDs
				if !contains(m.OrgIDs, binding.ResourceID) {
					m.OrgIDs = append(m.OrgIDs, binding.ResourceID)
					// Use display name if available, otherwise fall back to ID
					if displayName, ok := orgDisplayNames[binding.ResourceID]; ok && displayName != "" {
						m.OrgNames[binding.ResourceID] = displayName
					} else {
						m.OrgNames[binding.ResourceID] = binding.ResourceID
					}
				}
				m.mu.Unlock()
			} else if binding.ResourceType == "folder" {
				m.mu.Lock()
				m.FolderBindings[binding.ResourceID] = append(m.FolderBindings[binding.ResourceID], binding)
				m.mu.Unlock()
			}
		}

		if len(m.OrgBindings) > 0 {
			logger.InfoM(fmt.Sprintf("Found %d organization-level IAM binding(s)", len(m.OrgBindings)), globals.GCP_PERMISSIONS_MODULE_NAME)
		}

		totalFolderBindings := 0
		for _, bindings := range m.FolderBindings {
			totalFolderBindings += len(bindings)
		}
		if totalFolderBindings > 0 {
			logger.InfoM(fmt.Sprintf("Found %d folder-level IAM binding(s) across %d folder(s)", totalFolderBindings, len(m.FolderBindings)), globals.GCP_PERMISSIONS_MODULE_NAME)
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *PermissionsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating permissions in project: %s", projectID), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	iamService := IAMService.New()
	entityPerms, groupInfos, err := iamService.GetAllEntityPermissionsWithGroupExpansion(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PERMISSIONS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate permissions in project %s", projectID))
		return
	}

	var projectPerms []ExplodedPermission
	var orgPerms []ExplodedPermission
	var folderPerms []ExplodedPermission

	for _, ep := range entityPerms {
		for _, perm := range ep.Permissions {
			isHighPriv := isHighPrivilegePermission(perm.Permission)

			exploded := ExplodedPermission{
				Entity:            ep.Entity,
				EntityType:        ep.EntityType,
				EntityEmail:       ep.Email,
				Permission:        perm.Permission,
				Role:              perm.Role,
				RoleType:          perm.RoleType,
				ResourceScope:     fmt.Sprintf("%s/%s", perm.ResourceType, perm.ResourceID),
				ResourceScopeType: perm.ResourceType,
				ResourceScopeID:   perm.ResourceID,
				ResourceScopeName: m.getScopeName(perm.ResourceType, perm.ResourceID),
				IsInherited:       perm.IsInherited,
				InheritedFrom:     perm.InheritedFrom,
				HasCondition:      perm.HasCondition,
				Condition:         perm.Condition,
				EffectiveProject:  projectID,
				ProjectName:       m.GetProjectName(projectID),
				IsHighPrivilege:   isHighPriv,
			}

			// Parse condition title if present
			if perm.HasCondition && perm.Condition != "" {
				exploded.ConditionTitle = parseConditionTitle(perm.Condition)
			}

			// Detect cross-project access
			if ep.EntityType == "ServiceAccount" {
				saProject := extractProjectFromPrincipal(ep.Email, m.OrgCache)
				if saProject != "" && saProject != projectID {
					exploded.IsCrossProject = true
					exploded.SourceProject = saProject
				}
			}

			// Route to appropriate scope: org, folder, or project
			switch perm.ResourceType {
			case "organization":
				orgPerms = append(orgPerms, exploded)
			case "folder":
				folderPerms = append(folderPerms, exploded)
			default:
				projectPerms = append(projectPerms, exploded)
			}
		}
	}

	m.mu.Lock()
	// Store per-project permissions
	m.ProjectPerms[projectID] = append(m.ProjectPerms[projectID], projectPerms...)

	// Store org-level permissions (keyed by org ID)
	for _, ep := range orgPerms {
		m.OrgPerms[ep.ResourceScopeID] = append(m.OrgPerms[ep.ResourceScopeID], ep)
	}

	// Store folder-level permissions (keyed by folder ID)
	for _, ep := range folderPerms {
		m.FolderPerms[ep.ResourceScopeID] = append(m.FolderPerms[ep.ResourceScopeID], ep)
	}

	// Legacy aggregated fields for stats
	m.EntityPermissions = append(m.EntityPermissions, entityPerms...)
	m.GroupInfos = append(m.GroupInfos, groupInfos...)

	// Generate loot per-scope based on exploded permissions
	// We use a set to track which service accounts we've already added per scope
	addedSAsOrg := make(map[string]map[string]bool)     // orgID -> email -> added
	addedSAsFolder := make(map[string]map[string]bool)  // folderID -> email -> added
	addedSAsProject := make(map[string]map[string]bool) // projectID -> email -> added

	allPerms := append(append(projectPerms, orgPerms...), folderPerms...)
	for _, ep := range allPerms {
		if ep.EntityType != "ServiceAccount" {
			continue
		}
		m.addPermissionToLoot(ep, addedSAsOrg, addedSAsFolder, addedSAsProject)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Exploded %d permission entries in project %s", len(projectPerms), projectID), globals.GCP_PERMISSIONS_MODULE_NAME)
	}
}

func (m *PermissionsModule) getScopeName(scopeType, scopeID string) string {
	switch scopeType {
	case "project":
		return m.GetProjectName(scopeID)
	case "organization":
		if name, ok := m.OrgNames[scopeID]; ok {
			return name
		}
		return scopeID
	case "folder":
		return scopeID // Could be enhanced to lookup folder names
	default:
		return scopeID
	}
}

func parseConditionTitle(condition string) string {
	// Try to extract title from condition if it looks like a struct
	if strings.Contains(condition, "title:") {
		parts := strings.Split(condition, "title:")
		if len(parts) > 1 {
			titlePart := strings.TrimSpace(parts[1])
			if idx := strings.Index(titlePart, " "); idx > 0 {
				return titlePart[:idx]
			}
			return titlePart
		}
	}
	return ""
}

// ------------------------------
// Loot File Management
// ------------------------------

// addPermissionToLoot adds a service account to the appropriate scope-based loot file.
// It tracks which SAs have been added per scope to avoid duplicates.
func (m *PermissionsModule) addPermissionToLoot(ep ExplodedPermission,
	addedSAsOrg map[string]map[string]bool,
	addedSAsFolder map[string]map[string]bool,
	addedSAsProject map[string]map[string]bool) {

	if ep.EntityType != "ServiceAccount" {
		return
	}

	scopeType := ep.ResourceScopeType
	scopeID := ep.ResourceScopeID
	email := ep.EntityEmail

	// Determine which loot file and tracking map to use
	var lootFile *internal.LootFile
	var addedSet map[string]bool

	switch scopeType {
	case "organization":
		if m.OrgLoot[scopeID] == nil {
			m.OrgLoot[scopeID] = &internal.LootFile{
				Name:     "permissions-commands",
				Contents: "# GCP Permissions Commands (Organization Level)\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
			}
		}
		lootFile = m.OrgLoot[scopeID]
		if addedSAsOrg[scopeID] == nil {
			addedSAsOrg[scopeID] = make(map[string]bool)
		}
		addedSet = addedSAsOrg[scopeID]

	case "folder":
		if m.FolderLoot[scopeID] == nil {
			m.FolderLoot[scopeID] = &internal.LootFile{
				Name:     "permissions-commands",
				Contents: "# GCP Permissions Commands (Folder Level)\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
			}
		}
		lootFile = m.FolderLoot[scopeID]
		if addedSAsFolder[scopeID] == nil {
			addedSAsFolder[scopeID] = make(map[string]bool)
		}
		addedSet = addedSAsFolder[scopeID]

	default: // project
		if m.ProjectLoot[scopeID] == nil {
			m.ProjectLoot[scopeID] = &internal.LootFile{
				Name:     "permissions-commands",
				Contents: "# GCP Permissions Commands (Project Level)\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
			}
		}
		lootFile = m.ProjectLoot[scopeID]
		if addedSAsProject[scopeID] == nil {
			addedSAsProject[scopeID] = make(map[string]bool)
		}
		addedSet = addedSAsProject[scopeID]
	}

	// Skip if already added to this scope
	if addedSet[email] {
		return
	}
	addedSet[email] = true

	// Extract project from SA email for commands
	saProject := ep.EffectiveProject
	if saProject == "" {
		// Try to extract from email
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			saParts := strings.Split(parts[1], ".")
			if len(saParts) >= 1 {
				saProject = saParts[0]
			}
		}
	}

	// Add service account commands
	highPriv := ""
	if ep.IsHighPrivilege {
		highPriv = " [HIGH PRIVILEGE]"
	}

	lootFile.Contents += fmt.Sprintf(
		"# Service Account: %s%s\n"+
			"# Role: %s (at %s/%s)\n",
		email, highPriv,
		ep.Role, scopeType, scopeID,
	)

	lootFile.Contents += fmt.Sprintf(
		"gcloud iam service-accounts describe %s --project=%s\n"+
			"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n"+
			"gcloud iam service-accounts get-iam-policy %s --project=%s\n"+
			"gcloud iam service-accounts keys create ./key.json --iam-account=%s --project=%s\n"+
			"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
		email, saProject,
		email, saProject,
		email, saProject,
		email, saProject,
		email,
	)
}

// isHighPrivilegePermission checks if a permission is considered high-privilege
func isHighPrivilegePermission(permission string) bool {
	for _, prefix := range highPrivilegePermissionPrefixes {
		if strings.HasPrefix(permission, prefix) {
			return true
		}
	}
	return false
}

// initializeEnumerationLoot initializes the enumeration loot file
func (m *PermissionsModule) initializeEnumerationLoot() {
	m.EnumLoot.Contents = "# GCP Permissions Enumeration Commands\n"
	m.EnumLoot.Contents += "# Generated by CloudFox\n"
	m.EnumLoot.Contents += "# WARNING: Only use with proper authorization\n\n"
}

// collectAllLootFiles collects all loot files for org-level output (all scopes combined)
func (m *PermissionsModule) collectAllLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile

	// Combine all org, folder, and project loot into one file for org-level output
	combinedLoot := &internal.LootFile{
		Name:     "permissions-commands",
		Contents: "# GCP Permissions Commands (All Scopes)\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}

	// Add org-level loot
	for orgID, loot := range m.OrgLoot {
		if loot != nil && loot.Contents != "" {
			combinedLoot.Contents += fmt.Sprintf("# === Organization: %s ===\n", orgID)
			// Skip the header line from the individual loot
			lines := strings.Split(loot.Contents, "\n")
			for i, line := range lines {
				if i >= 2 { // Skip first 2 header lines
					combinedLoot.Contents += line + "\n"
				}
			}
		}
	}

	// Add folder-level loot
	for folderID, loot := range m.FolderLoot {
		if loot != nil && loot.Contents != "" {
			combinedLoot.Contents += fmt.Sprintf("# === Folder: %s ===\n", folderID)
			lines := strings.Split(loot.Contents, "\n")
			for i, line := range lines {
				if i >= 2 {
					combinedLoot.Contents += line + "\n"
				}
			}
		}
	}

	// Add project-level loot
	for projectID, loot := range m.ProjectLoot {
		if loot != nil && loot.Contents != "" {
			combinedLoot.Contents += fmt.Sprintf("# === Project: %s ===\n", projectID)
			lines := strings.Split(loot.Contents, "\n")
			for i, line := range lines {
				if i >= 2 {
					combinedLoot.Contents += line + "\n"
				}
			}
		}
	}

	// Only add if there's actual content beyond the header
	if len(combinedLoot.Contents) > 60 { // More than just the header
		lootFiles = append(lootFiles, *combinedLoot)
	}

	// Add enumeration loot file
	if m.EnumLoot != nil && m.EnumLoot.Contents != "" {
		lootFiles = append(lootFiles, *m.EnumLoot)
	}

	return lootFiles
}

// collectLootFilesForProject collects loot files for a specific project with inheritance.
// This includes: org-level loot + ancestor folder loot + project-level loot
func (m *PermissionsModule) collectLootFilesForProject(projectID string) []internal.LootFile {
	var lootFiles []internal.LootFile

	combinedLoot := &internal.LootFile{
		Name:     "permissions-commands",
		Contents: "# GCP Permissions Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}

	// Get ancestry for this project
	var projectOrgID string
	var ancestorFolders []string
	if m.OrgCache != nil && m.OrgCache.IsPopulated() {
		projectOrgID = m.OrgCache.GetProjectOrgID(projectID)
		ancestorFolders = m.OrgCache.GetProjectAncestorFolders(projectID)
	}

	// Add org-level loot if this project belongs to an org
	if projectOrgID != "" {
		if loot, ok := m.OrgLoot[projectOrgID]; ok && loot != nil && loot.Contents != "" {
			combinedLoot.Contents += fmt.Sprintf("# === Inherited from Organization: %s ===\n", projectOrgID)
			lines := strings.Split(loot.Contents, "\n")
			for i, line := range lines {
				if i >= 2 {
					combinedLoot.Contents += line + "\n"
				}
			}
		}
	}

	// Add folder-level loot for ancestor folders (in order from org to project)
	// Reverse the slice to go from org-level folders to project-level folders
	for i := len(ancestorFolders) - 1; i >= 0; i-- {
		folderID := ancestorFolders[i]
		if loot, ok := m.FolderLoot[folderID]; ok && loot != nil && loot.Contents != "" {
			combinedLoot.Contents += fmt.Sprintf("# === Inherited from Folder: %s ===\n", folderID)
			lines := strings.Split(loot.Contents, "\n")
			for i, line := range lines {
				if i >= 2 {
					combinedLoot.Contents += line + "\n"
				}
			}
		}
	}

	// Add project-level loot
	if loot, ok := m.ProjectLoot[projectID]; ok && loot != nil && loot.Contents != "" {
		combinedLoot.Contents += fmt.Sprintf("# === Project: %s ===\n", projectID)
		lines := strings.Split(loot.Contents, "\n")
		for i, line := range lines {
			if i >= 2 {
				combinedLoot.Contents += line + "\n"
			}
		}
	}

	// Only add if there's actual content beyond the header
	if len(combinedLoot.Contents) > 50 {
		lootFiles = append(lootFiles, *combinedLoot)
	}

	return lootFiles
}

// generateEnumerationLoot generates commands to enumerate permissions
func (m *PermissionsModule) generateEnumerationLoot() {
	loot := m.EnumLoot

	// Add organization-level enumeration commands
	for _, orgID := range m.OrgIDs {
		orgName := m.OrgNames[orgID]
		loot.Contents += fmt.Sprintf("# =============================================================================\n")
		loot.Contents += fmt.Sprintf("# Organization: %s (%s)\n", orgName, orgID)
		loot.Contents += fmt.Sprintf("# =============================================================================\n\n")

		loot.Contents += fmt.Sprintf("# List all IAM bindings for organization\n")
		loot.Contents += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json\n\n", orgID)

		loot.Contents += fmt.Sprintf("# List all roles and their members at organization level\n")
		loot.Contents += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json | jq -r '.bindings[] | \"Role: \\(.role)\\nMembers: \\(.members | join(\", \"))\\n\"'\n\n", orgID)

		loot.Contents += fmt.Sprintf("# Get permissions for a specific role (replace ROLE_NAME)\n")
		loot.Contents += fmt.Sprintf("gcloud iam roles describe ROLE_NAME --format=json | jq -r '.includedPermissions[]'\n\n")
	}

	// Add project-level enumeration commands
	for _, projectID := range m.ProjectIDs {
		projectName := m.GetProjectName(projectID)
		loot.Contents += fmt.Sprintf("# =============================================================================\n")
		loot.Contents += fmt.Sprintf("# Project: %s (%s)\n", projectName, projectID)
		loot.Contents += fmt.Sprintf("# =============================================================================\n\n")

		loot.Contents += fmt.Sprintf("# List all IAM bindings for project\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json\n\n", projectID)

		loot.Contents += fmt.Sprintf("# List all roles and their members at project level\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | \"Role: \\(.role)\\nMembers: \\(.members | join(\", \"))\\n\"'\n\n", projectID)

		loot.Contents += fmt.Sprintf("# Find all entities with a specific role (replace ROLE_NAME, e.g., roles/owner)\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.role == \"ROLE_NAME\") | .members[]'\n\n", projectID)

		loot.Contents += fmt.Sprintf("# Get all roles for a specific entity (replace ENTITY, e.g., user:email@example.com)\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"ENTITY\")) | .role'\n\n", projectID)

		loot.Contents += fmt.Sprintf("# List all service accounts and their IAM policy\n")
		loot.Contents += fmt.Sprintf("for sa in $(gcloud iam service-accounts list --project=%s --format='value(email)'); do echo \"=== $sa ===\"; gcloud iam service-accounts get-iam-policy $sa --project=%s --format=json 2>/dev/null | jq -r '.bindings[] | \"\\(.role): \\(.members | join(\", \"))\"' 2>/dev/null || echo \"No IAM policy\"; done\n\n", projectID, projectID)

		loot.Contents += fmt.Sprintf("# List all custom roles with their permissions\n")
		loot.Contents += fmt.Sprintf("for role in $(gcloud iam roles list --project=%s --format='value(name)'); do echo \"=== $role ===\"; gcloud iam roles describe $role --project=%s --format=json | jq -r '.includedPermissions[]' 2>/dev/null; done\n\n", projectID, projectID)

		loot.Contents += fmt.Sprintf("# Get permissions for a predefined role\n")
		loot.Contents += fmt.Sprintf("gcloud iam roles describe roles/editor --format=json | jq -r '.includedPermissions[]'\n\n")
	}

	// Add entity-specific enumeration based on discovered permissions
	loot.Contents += fmt.Sprintf("# =============================================================================\n")
	loot.Contents += fmt.Sprintf("# Entity-Specific Permission Enumeration\n")
	loot.Contents += fmt.Sprintf("# =============================================================================\n\n")

	// Collect unique entities with their roles
	entityRoles := make(map[string]map[string]bool) // entity -> set of roles
	entityTypes := make(map[string]string)          // entity -> type

	allPerms := m.getAllExplodedPerms()
	for _, ep := range allPerms {
		if ep.EntityEmail == "" {
			continue
		}
		if entityRoles[ep.EntityEmail] == nil {
			entityRoles[ep.EntityEmail] = make(map[string]bool)
		}
		entityRoles[ep.EntityEmail][ep.Role] = true
		entityTypes[ep.EntityEmail] = ep.EntityType
	}

	// Generate commands for each entity type
	for entity, roles := range entityRoles {
		entityType := entityTypes[entity]

		// Convert roles set to slice
		var roleList []string
		for role := range roles {
			roleList = append(roleList, role)
		}
		sort.Strings(roleList)

		switch entityType {
		case "ServiceAccount":
			loot.Contents += fmt.Sprintf("# Service Account: %s\n", entity)
			loot.Contents += fmt.Sprintf("# Current Roles: %s\n", strings.Join(roleList, ", "))

			// Extract project from SA email
			saProject := ""
			parts := strings.Split(entity, "@")
			if len(parts) == 2 {
				saParts := strings.Split(parts[1], ".")
				if len(saParts) >= 1 {
					saProject = saParts[0]
				}
			}

			if saProject != "" {
				loot.Contents += fmt.Sprintf("# Describe service account\n")
				loot.Contents += fmt.Sprintf("gcloud iam service-accounts describe %s --project=%s --format=json\n", entity, saProject)

				loot.Contents += fmt.Sprintf("# Get IAM policy on the service account itself\n")
				loot.Contents += fmt.Sprintf("gcloud iam service-accounts get-iam-policy %s --project=%s --format=json\n", entity, saProject)
			}

			loot.Contents += fmt.Sprintf("# Get all permissions for each role\n")
			for _, role := range roleList {
				if strings.HasPrefix(role, "projects/") || strings.HasPrefix(role, "organizations/") {
					// Custom role - need to describe with full path
					loot.Contents += fmt.Sprintf("gcloud iam roles describe %s --format=json | jq -r '.includedPermissions[]'\n", role)
				} else {
					loot.Contents += fmt.Sprintf("gcloud iam roles describe %s --format=json | jq -r '.includedPermissions[]'\n", role)
				}
			}
			loot.Contents += "\n"

		case "User":
			loot.Contents += fmt.Sprintf("# User: %s\n", entity)
			loot.Contents += fmt.Sprintf("# Current Roles: %s\n", strings.Join(roleList, ", "))

			loot.Contents += fmt.Sprintf("# Get all permissions for each role\n")
			for _, role := range roleList {
				if strings.HasPrefix(role, "projects/") || strings.HasPrefix(role, "organizations/") {
					loot.Contents += fmt.Sprintf("gcloud iam roles describe %s --format=json | jq -r '.includedPermissions[]'\n", role)
				} else {
					loot.Contents += fmt.Sprintf("gcloud iam roles describe %s --format=json | jq -r '.includedPermissions[]'\n", role)
				}
			}
			loot.Contents += "\n"

		case "Group":
			loot.Contents += fmt.Sprintf("# Group: %s\n", entity)
			loot.Contents += fmt.Sprintf("# Current Roles: %s\n", strings.Join(roleList, ", "))

			loot.Contents += fmt.Sprintf("# Get all permissions for each role\n")
			for _, role := range roleList {
				if strings.HasPrefix(role, "projects/") || strings.HasPrefix(role, "organizations/") {
					loot.Contents += fmt.Sprintf("gcloud iam roles describe %s --format=json | jq -r '.includedPermissions[]'\n", role)
				} else {
					loot.Contents += fmt.Sprintf("gcloud iam roles describe %s --format=json | jq -r '.includedPermissions[]'\n", role)
				}
			}
			loot.Contents += "\n"
		}
	}

	// Add high-privilege permission search commands
	loot.Contents += fmt.Sprintf("# =============================================================================\n")
	loot.Contents += fmt.Sprintf("# High-Privilege Permission Search\n")
	loot.Contents += fmt.Sprintf("# =============================================================================\n\n")

	loot.Contents += fmt.Sprintf("# Find entities with setIamPolicy permissions\n")
	for _, projectID := range m.ProjectIDs {
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.role | test(\"admin|owner|editor\"; \"i\")) | \"\\(.role): \\(.members | join(\", \"))\"'\n", projectID)
	}
	loot.Contents += "\n"

	loot.Contents += fmt.Sprintf("# Find service accounts that can be impersonated\n")
	for _, projectID := range m.ProjectIDs {
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.role | test(\"serviceAccountUser|serviceAccountTokenCreator\"; \"i\")) | \"\\(.role): \\(.members | join(\", \"))\"'\n", projectID)
	}
	loot.Contents += "\n"
}

// PermFederatedIdentityInfo contains parsed information about a federated identity
type PermFederatedIdentityInfo struct {
	IsFederated  bool
	ProviderType string // AWS, GitHub, GitLab, OIDC, SAML, Azure, etc.
	PoolName     string
	Subject      string
	Attribute    string
}

// parsePermFederatedIdentity detects and parses federated identity principals
func parsePermFederatedIdentity(identity string) PermFederatedIdentityInfo {
	info := PermFederatedIdentityInfo{}

	// Check for principal:// or principalSet:// format
	if !strings.HasPrefix(identity, "principal://") && !strings.HasPrefix(identity, "principalSet://") {
		return info
	}

	info.IsFederated = true

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

	// Detect provider type based on common patterns
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
		info.ProviderType = "OIDC"
	default:
		info.ProviderType = "Federated"
	}

	// Extract subject if present
	// Format: .../subject/{subject}
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

// formatPermFederatedInfo formats federated identity info for display
func formatPermFederatedInfo(info PermFederatedIdentityInfo) string {
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
func formatPermissionCondition(hasCondition bool, condition, conditionTitle string) string {
	if !hasCondition {
		return "No"
	}

	if conditionTitle != "" {
		return conditionTitle
	}

	// Parse common patterns
	if strings.Contains(condition, "request.time") {
		return "[time-limited]"
	}
	if strings.Contains(condition, "resource.name") {
		return "[resource-scoped]"
	}
	if strings.Contains(condition, "origin.ip") || strings.Contains(condition, "request.origin") {
		return "[IP-restricted]"
	}
	if strings.Contains(condition, "device") {
		return "[device-policy]"
	}

	return "Yes"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PermissionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Log findings first
	allPerms := m.getAllExplodedPerms()
	highPrivCount := 0
	crossProjectCount := 0
	for _, ep := range allPerms {
		if ep.IsHighPrivilege {
			highPrivCount++
		}
		if ep.IsCrossProject {
			crossProjectCount++
		}
	}

	if highPrivCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d high-privilege permission entries!", highPrivCount), globals.GCP_PERMISSIONS_MODULE_NAME)
	}
	if crossProjectCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d cross-project permission entries!", crossProjectCount), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *PermissionsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()

	// Determine org ID - prefer discovered orgs, fall back to hierarchy
	orgID := ""
	if len(m.OrgIDs) > 0 {
		orgID = m.OrgIDs[0]
	} else if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	// Collect all loot files for org-level output
	allLootFiles := m.collectAllLootFiles()

	// Get all permissions for output
	allPerms := m.getAllExplodedPerms()

	// Check if we should use single-pass tee streaming for large datasets
	if orgID != "" && len(allPerms) >= 50000 {
		m.writeHierarchicalOutputTee(ctx, logger, orgID, header, allPerms, allLootFiles)
		return
	}

	// Standard output path for smaller datasets
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		body := m.permsToTableBody(allPerms)
		tables := []internal.TableFile{{
			Name:   "permissions",
			Header: header,
			Body:   body,
		}}
		outputData.OrgLevelData[orgID] = PermissionsOutput{Table: tables, Loot: allLootFiles}

		// DUAL OUTPUT: Filtered per-project output with inherited loot
		for projectID, perms := range m.ProjectPerms {
			if len(perms) == 0 {
				continue
			}
			body := m.permsToTableBody(perms)
			tables := []internal.TableFile{{
				Name:   "permissions",
				Header: header,
				Body:   body,
			}}
			// Get loot for this project with inheritance (org + folders + project)
			projectLoot := m.collectLootFilesForProject(projectID)
			outputData.ProjectLevelData[projectID] = PermissionsOutput{Table: tables, Loot: projectLoot}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		body := m.permsToTableBody(allPerms)
		tables := []internal.TableFile{{
			Name:   "permissions",
			Header: header,
			Body:   body,
		}}
		outputData.ProjectLevelData[m.ProjectIDs[0]] = PermissionsOutput{Table: tables, Loot: allLootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeHierarchicalOutputTee uses single-pass streaming for large datasets.
// It streams through all permissions once, writing each row to:
// 1. The org-level output (always)
// 2. The appropriate project-level output based on EffectiveProject
func (m *PermissionsModule) writeHierarchicalOutputTee(ctx context.Context, logger internal.Logger, orgID string, header []string, allPerms []ExplodedPermission, lootFiles []internal.LootFile) {
	logger.InfoM(fmt.Sprintf("Using single-pass tee streaming for %d permissions", len(allPerms)), globals.GCP_PERMISSIONS_MODULE_NAME)

	pathBuilder := m.BuildPathBuilder()

	// Build the table data
	body := m.permsToTableBody(allPerms)
	tables := []internal.TableFile{{
		Name:   "permissions",
		Header: header,
		Body:   body,
	}}

	// Build reverse lookup: for each folder, which projects are under it
	// This allows O(1) lookup during row routing
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
		// Row format: [ScopeType, ScopeID, ScopeName, EntityType, Identity, Permission, ...]
		scopeType := row[0]
		scopeID := row[1]

		switch scopeType {
		case "project":
			// Direct project permission - route to that project only
			return []string{scopeID}
		case "organization":
			// Org permission - route to all projects under this org
			if projects, ok := orgToProjects[scopeID]; ok {
				return projects
			}
			// Fallback if OrgCache not populated: route to all projects
			return m.ProjectIDs
		case "folder":
			// Folder permission - route to all projects under this folder
			if projects, ok := folderToProjects[scopeID]; ok {
				return projects
			}
			// Fallback if folder not in cache: route to all projects
			return m.ProjectIDs
		default:
			return nil
		}
	}

	// Use the tee streaming function
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
		logger.ErrorM(fmt.Sprintf("Error writing tee streaming output: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *PermissionsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()
	allPerms := m.getAllExplodedPerms()
	body := m.permsToTableBody(allPerms)

	// Sort by scope type (org first, then folder, then project), then entity, then permission
	scopeOrder := map[string]int{"organization": 0, "folder": 1, "project": 2}
	sort.Slice(body, func(i, j int) bool {
		if body[i][0] != body[j][0] {
			return scopeOrder[body[i][0]] < scopeOrder[body[j][0]]
		}
		if body[i][4] != body[j][4] {
			return body[i][4] < body[j][4]
		}
		return body[i][5] < body[j][5]
	})

	// Collect all loot files for flat output
	lootFiles := m.collectAllLootFiles()

	tables := []internal.TableFile{{
		Name:   "permissions",
		Header: header,
		Body:   body,
	}}

	output := PermissionsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output scope - use org if available, otherwise fall back to project
	var scopeType string
	var scopeIdentifiers []string
	var scopeNames []string

	if len(m.OrgIDs) > 0 {
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// getTableHeader returns the permissions table header
func (m *PermissionsModule) getTableHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Entity Type",
		"Identity",
		"Permission",
		"Role",
		"Custom Role",
		"Inherited",
		"Inherited From",
		"Condition",
		"Cross-Project",
		"High Privilege",
		"Federated",
	}
}

// permsToTableBody converts permissions to table body rows
func (m *PermissionsModule) permsToTableBody(perms []ExplodedPermission) [][]string {
	var body [][]string
	for _, ep := range perms {
		isCustom := "No"
		if ep.RoleType == "custom" || strings.HasPrefix(ep.Role, "projects/") || strings.HasPrefix(ep.Role, "organizations/") {
			isCustom = "Yes"
		}

		inherited := "No"
		if ep.IsInherited {
			inherited = "Yes"
		}

		inheritedFrom := "-"
		if ep.IsInherited && ep.InheritedFrom != "" {
			inheritedFrom = ep.InheritedFrom
		}

		condition := formatPermissionCondition(ep.HasCondition, ep.Condition, ep.ConditionTitle)

		crossProject := "No"
		if ep.IsCrossProject {
			crossProject = fmt.Sprintf("Yes (from %s)", ep.SourceProject)
		}

		highPriv := "No"
		if ep.IsHighPrivilege {
			highPriv = "Yes"
		}

		// Check for federated identity
		federated := formatPermFederatedInfo(parsePermFederatedIdentity(ep.EntityEmail))

		body = append(body, []string{
			ep.ResourceScopeType,
			ep.ResourceScopeID,
			ep.ResourceScopeName,
			ep.EntityType,
			ep.EntityEmail,
			ep.Permission,
			ep.Role,
			isCustom,
			inherited,
			inheritedFrom,
			condition,
			crossProject,
			highPriv,
			federated,
		})
	}
	return body
}
