package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
)

var GCPHiddenAdminsCommand = &cobra.Command{
	Use:     globals.GCP_HIDDEN_ADMINS_MODULE_NAME,
	Aliases: []string{"ha", "hidden"},
	Short:   "Identify principals who can modify IAM policies (hidden admins)",
	Long: `Analyze GCP IAM policies to identify principals who can modify IAM bindings.

This module finds "hidden admins" - principals who may not have obvious admin roles
but possess permissions to grant themselves or others elevated access.

Detected IAM modification capabilities:

Organization Level:
- resourcemanager.organizations.setIamPolicy - Modify org-wide IAM
- iam.roles.create/update at org level - Create/modify org custom roles

Folder Level:
- resourcemanager.folders.setIamPolicy - Modify folder IAM (affects all children)

Project Level:
- resourcemanager.projects.setIamPolicy - Modify project IAM
- iam.roles.create/update - Create/modify project custom roles

Service Account Level:
- iam.serviceAccounts.setIamPolicy - Grant SA access to others
- iam.serviceAccounts.create + setIamPolicy combo

Resource Level IAM:
- storage.buckets.setIamPolicy - Modify bucket IAM
- bigquery.datasets.setIamPolicy - Modify dataset IAM
- pubsub.topics/subscriptions.setIamPolicy - Modify Pub/Sub IAM
- secretmanager.secrets.setIamPolicy - Modify secret IAM
- compute.instances.setIamPolicy - Modify instance IAM
- cloudfunctions.functions.setIamPolicy - Modify function IAM
- run.services.setIamPolicy - Modify Cloud Run IAM
- artifactregistry.repositories.setIamPolicy - Modify registry IAM`,
	Run: runGCPHiddenAdminsCommand,
}

// IAMModificationPermission represents a permission that allows IAM policy modification
type IAMModificationPermission struct {
	Permission  string
	Category    string
	Description string
}

// HiddenAdmin represents a principal with IAM modification capabilities
type HiddenAdmin struct {
	Principal      string
	PrincipalType  string
	Permission     string
	Category       string
	Description    string
	ScopeType      string // organization, folder, project, resource
	ScopeID        string
	ScopeName      string
	ExploitCommand string
}

type HiddenAdminsModule struct {
	gcpinternal.BaseGCPModule

	AllAdmins      []HiddenAdmin
	OrgAdmins      []HiddenAdmin
	FolderAdmins   []HiddenAdmin
	ProjectAdmins  map[string][]HiddenAdmin // projectID -> admins
	ResourceAdmins []HiddenAdmin

	// FoxMapper-based wrong admins
	WrongAdmins    []foxmapperservice.WrongAdminFinding
	FoxMapperCache *gcpinternal.FoxMapperCache

	// OrgCache for ancestry lookups
	OrgCache *gcpinternal.OrgCache

	OrgIDs      []string
	OrgNames    map[string]string
	FolderNames map[string]string

	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

type HiddenAdminsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o HiddenAdminsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o HiddenAdminsOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPHiddenAdminsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &HiddenAdminsModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		AllAdmins:      []HiddenAdmin{},
		OrgAdmins:      []HiddenAdmin{},
		FolderAdmins:   []HiddenAdmin{},
		ProjectAdmins:  make(map[string][]HiddenAdmin),
		ResourceAdmins: []HiddenAdmin{},
		OrgIDs:         []string{},
		OrgNames:       make(map[string]string),
		FolderNames:    make(map[string]string),
		LootMap:        make(map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// GetIAMModificationPermissions returns permissions that allow IAM policy modification
func GetIAMModificationPermissions() []IAMModificationPermission {
	return []IAMModificationPermission{
		// Organization-level IAM
		{Permission: "resourcemanager.organizations.setIamPolicy", Category: "Org IAM", Description: "Modify organization-wide IAM policy"},

		// Folder-level IAM
		{Permission: "resourcemanager.folders.setIamPolicy", Category: "Folder IAM", Description: "Modify folder IAM policy (affects all children)"},

		// Project-level IAM
		{Permission: "resourcemanager.projects.setIamPolicy", Category: "Project IAM", Description: "Modify project IAM policy"},

		// Custom Role Management
		{Permission: "iam.roles.create", Category: "Custom Roles", Description: "Create custom IAM roles"},
		{Permission: "iam.roles.update", Category: "Custom Roles", Description: "Modify custom IAM role permissions"},

		// Service Account IAM
		{Permission: "iam.serviceAccounts.setIamPolicy", Category: "SA IAM", Description: "Grant access to service accounts"},

		// Org Policy (can disable security constraints)
		{Permission: "orgpolicy.policy.set", Category: "Org Policy", Description: "Modify organization policies"},

		// Resource-specific IAM
		{Permission: "storage.buckets.setIamPolicy", Category: "Storage IAM", Description: "Modify bucket IAM policy"},
		{Permission: "bigquery.datasets.setIamPolicy", Category: "BigQuery IAM", Description: "Modify dataset IAM policy"},
		{Permission: "pubsub.topics.setIamPolicy", Category: "Pub/Sub IAM", Description: "Modify topic IAM policy"},
		{Permission: "pubsub.subscriptions.setIamPolicy", Category: "Pub/Sub IAM", Description: "Modify subscription IAM policy"},
		{Permission: "secretmanager.secrets.setIamPolicy", Category: "Secrets IAM", Description: "Modify secret IAM policy"},
		{Permission: "compute.instances.setIamPolicy", Category: "Compute IAM", Description: "Modify instance IAM policy"},
		{Permission: "compute.images.setIamPolicy", Category: "Compute IAM", Description: "Modify image IAM policy"},
		{Permission: "compute.snapshots.setIamPolicy", Category: "Compute IAM", Description: "Modify snapshot IAM policy"},
		{Permission: "cloudfunctions.functions.setIamPolicy", Category: "Functions IAM", Description: "Modify function IAM policy"},
		{Permission: "run.services.setIamPolicy", Category: "Cloud Run IAM", Description: "Modify Cloud Run service IAM policy"},
		{Permission: "artifactregistry.repositories.setIamPolicy", Category: "Artifact Registry IAM", Description: "Modify repository IAM policy"},
		{Permission: "cloudkms.cryptoKeys.setIamPolicy", Category: "KMS IAM", Description: "Modify KMS key IAM policy"},
	}
}

func (m *HiddenAdminsModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing IAM policies to identify hidden admins...", globals.GCP_HIDDEN_ADMINS_MODULE_NAME)

	// Load OrgCache for ancestry lookups (needed for per-project filtering)
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)
	if m.OrgCache == nil || !m.OrgCache.IsPopulated() {
		diskCache, _, err := gcpinternal.LoadOrgCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			m.OrgCache = diskCache
		}
	}

	// Try to load FoxMapper data for wrongadmin analysis
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache == nil || !m.FoxMapperCache.IsPopulated() {
		orgID := ""
		if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
			orgID = m.Hierarchy.Organizations[0].ID
		}
		m.FoxMapperCache = gcpinternal.TryLoadFoxMapper(orgID, m.ProjectIDs)
	}

	// Use FoxMapper wrongadmin analysis if available
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		svc := m.FoxMapperCache.GetService()
		m.WrongAdmins = svc.AnalyzeWrongAdmins()
		if len(m.WrongAdmins) > 0 {
			logger.InfoM(fmt.Sprintf("FoxMapper found %d 'wrong admins' (admins without explicit roles/owner)", len(m.WrongAdmins)), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
		}
	}

	// Build permission map
	permMap := make(map[string]IAMModificationPermission)
	for _, p := range GetIAMModificationPermissions() {
		permMap[p.Permission] = p
	}

	// Analyze organization-level IAM
	m.analyzeOrganizationIAM(ctx, logger, permMap)

	// Analyze folder-level IAM
	m.analyzeFolderIAM(ctx, logger, permMap)

	// Analyze project-level IAM for each project
	for _, projectID := range m.ProjectIDs {
		m.analyzeProjectIAM(ctx, logger, projectID, permMap)
	}

	// Generate loot (playbook)
	m.generateLoot()

	if len(m.AllAdmins) == 0 && len(m.WrongAdmins) == 0 {
		logger.InfoM("No hidden admins found", globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
		return
	}

	// Count by scope type
	orgCount := len(m.OrgAdmins)
	folderCount := len(m.FolderAdmins)
	projectCount := 0
	for _, admins := range m.ProjectAdmins {
		projectCount += len(admins)
	}
	resourceCount := len(m.ResourceAdmins)

	if len(m.AllAdmins) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d hidden admin(s) with IAM modification permissions: %d org-level, %d folder-level, %d project-level, %d resource-level",
			len(m.AllAdmins), orgCount, folderCount, projectCount, resourceCount), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	}

	if len(m.WrongAdmins) > 0 {
		// Count by admin level
		orgWrong := 0
		folderWrong := 0
		projectWrong := 0
		for _, wa := range m.WrongAdmins {
			switch wa.AdminLevel {
			case "org":
				orgWrong++
			case "folder":
				folderWrong++
			default:
				projectWrong++
			}
		}
		logger.SuccessM(fmt.Sprintf("Found %d 'wrong admins' (FoxMapper): %d org-level, %d folder-level, %d project-level",
			len(m.WrongAdmins), orgWrong, folderWrong, projectWrong), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

func (m *HiddenAdminsModule) analyzeOrganizationIAM(ctx context.Context, logger internal.Logger, permMap map[string]IAMModificationPermission) {
	orgsClient, err := resourcemanager.NewOrganizationsClient(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_HIDDEN_ADMINS_MODULE_NAME, "Could not create organizations client")
		}
		return
	}
	defer orgsClient.Close()

	// Get IAM service for role resolution
	iamService, _ := m.getIAMService(ctx)

	searchReq := &resourcemanagerpb.SearchOrganizationsRequest{}
	it := orgsClient.SearchOrganizations(ctx, searchReq)
	for {
		org, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		orgID := strings.TrimPrefix(org.Name, "organizations/")
		m.OrgNames[orgID] = org.DisplayName
		m.OrgIDs = append(m.OrgIDs, orgID)

		policy, err := orgsClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: org.Name,
		})
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := m.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				m.checkForHiddenAdmins(member, permissions, permMap, "organization", orgID, org.DisplayName)
			}
		}
	}
}

func (m *HiddenAdminsModule) analyzeFolderIAM(ctx context.Context, logger internal.Logger, permMap map[string]IAMModificationPermission) {
	foldersClient, err := resourcemanager.NewFoldersClient(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_HIDDEN_ADMINS_MODULE_NAME, "Could not create folders client")
		}
		return
	}
	defer foldersClient.Close()

	iamService, _ := m.getIAMService(ctx)

	searchReq := &resourcemanagerpb.SearchFoldersRequest{}
	it := foldersClient.SearchFolders(ctx, searchReq)
	for {
		folder, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		folderID := strings.TrimPrefix(folder.Name, "folders/")
		m.FolderNames[folderID] = folder.DisplayName

		policy, err := foldersClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: folder.Name,
		})
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := m.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				m.checkForHiddenAdmins(member, permissions, permMap, "folder", folderID, folder.DisplayName)
			}
		}
	}
}

func (m *HiddenAdminsModule) analyzeProjectIAM(ctx context.Context, logger internal.Logger, projectID string, permMap map[string]IAMModificationPermission) {
	crmService, err := crmv1.NewService(ctx)
	if err != nil {
		return
	}

	policy, err := crmService.Projects.GetIamPolicy(projectID, &crmv1.GetIamPolicyRequest{}).Do()
	if err != nil {
		return
	}

	iamService, _ := m.getIAMService(ctx)
	projectName := m.GetProjectName(projectID)

	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		permissions := m.getRolePermissions(iamService, binding.Role, projectID)
		for _, member := range binding.Members {
			m.checkForHiddenAdmins(member, permissions, permMap, "project", projectID, projectName)
		}
	}
}

func (m *HiddenAdminsModule) checkForHiddenAdmins(member string, permissions []string, permMap map[string]IAMModificationPermission, scopeType, scopeID, scopeName string) {
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return
	}

	principalType := extractPrincipalType(member)
	principal := extractPrincipalEmail(member)

	for _, perm := range permissions {
		if iamPerm, ok := permMap[perm]; ok {
			admin := HiddenAdmin{
				Principal:      principal,
				PrincipalType:  principalType,
				Permission:     perm,
				Category:       iamPerm.Category,
				Description:    iamPerm.Description,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				ExploitCommand: m.generateExploitCommand(perm, scopeType, scopeID),
			}

			m.mu.Lock()
			m.AllAdmins = append(m.AllAdmins, admin)
			switch scopeType {
			case "organization":
				m.OrgAdmins = append(m.OrgAdmins, admin)
			case "folder":
				m.FolderAdmins = append(m.FolderAdmins, admin)
			case "project":
				m.ProjectAdmins[scopeID] = append(m.ProjectAdmins[scopeID], admin)
			case "resource":
				m.ResourceAdmins = append(m.ResourceAdmins, admin)
			}
			m.mu.Unlock()
		}
	}
}

func (m *HiddenAdminsModule) generateExploitCommand(permission, scopeType, scopeID string) string {
	switch permission {
	case "resourcemanager.organizations.setIamPolicy":
		return fmt.Sprintf("gcloud organizations add-iam-policy-binding %s --member='user:ATTACKER@example.com' --role='roles/owner'", scopeID)
	case "resourcemanager.folders.setIamPolicy":
		return fmt.Sprintf("gcloud resource-manager folders add-iam-policy-binding %s --member='user:ATTACKER@example.com' --role='roles/owner'", scopeID)
	case "resourcemanager.projects.setIamPolicy":
		return fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member='user:ATTACKER@example.com' --role='roles/owner'", scopeID)
	case "iam.roles.create":
		return fmt.Sprintf("gcloud iam roles create customAdmin --project=%s --permissions=resourcemanager.projects.setIamPolicy", scopeID)
	case "iam.roles.update":
		return fmt.Sprintf("gcloud iam roles update ROLE_ID --project=%s --add-permissions=resourcemanager.projects.setIamPolicy", scopeID)
	case "iam.serviceAccounts.setIamPolicy":
		return fmt.Sprintf("gcloud iam service-accounts add-iam-policy-binding SA@%s.iam.gserviceaccount.com --member='user:ATTACKER@example.com' --role='roles/iam.serviceAccountTokenCreator'", scopeID)
	case "orgpolicy.policy.set":
		return "# Disable org policy constraints to bypass security controls"
	case "storage.buckets.setIamPolicy":
		return "gsutil iam ch user:ATTACKER@example.com:objectViewer gs://BUCKET_NAME"
	case "bigquery.datasets.setIamPolicy":
		return fmt.Sprintf("bq add-iam-policy-binding --member='user:ATTACKER@example.com' --role='roles/bigquery.dataViewer' %s:DATASET", scopeID)
	default:
		return fmt.Sprintf("# %s - refer to GCP documentation", permission)
	}
}

func (m *HiddenAdminsModule) getIAMService(ctx context.Context) (*iam.Service, error) {
	return iam.NewService(ctx)
}

func (m *HiddenAdminsModule) getRolePermissions(iamService *iam.Service, role string, projectID string) []string {
	if iamService == nil {
		return []string{}
	}

	var roleInfo *iam.Role
	var err error

	if strings.HasPrefix(role, "roles/") {
		roleInfo, err = iamService.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "projects/") {
		roleInfo, err = iamService.Projects.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "organizations/") {
		roleInfo, err = iamService.Organizations.Roles.Get(role).Do()
	} else {
		roleInfo, err = iamService.Roles.Get("roles/" + role).Do()
	}

	if err != nil {
		return m.getKnownRolePermissions(role)
	}

	return roleInfo.IncludedPermissions
}

func (m *HiddenAdminsModule) getKnownRolePermissions(role string) []string {
	knownRoles := map[string][]string{
		"roles/owner": {
			"resourcemanager.projects.setIamPolicy",
			"iam.serviceAccounts.setIamPolicy",
			"iam.roles.create",
			"iam.roles.update",
			"storage.buckets.setIamPolicy",
			"bigquery.datasets.setIamPolicy",
		},
		"roles/resourcemanager.organizationAdmin": {
			"resourcemanager.organizations.setIamPolicy",
		},
		"roles/resourcemanager.folderAdmin": {
			"resourcemanager.folders.setIamPolicy",
		},
		"roles/resourcemanager.projectIamAdmin": {
			"resourcemanager.projects.setIamPolicy",
		},
		"roles/iam.securityAdmin": {
			"resourcemanager.projects.setIamPolicy",
			"iam.serviceAccounts.setIamPolicy",
		},
		"roles/iam.serviceAccountAdmin": {
			"iam.serviceAccounts.setIamPolicy",
		},
		"roles/iam.roleAdmin": {
			"iam.roles.create",
			"iam.roles.update",
		},
	}

	if perms, ok := knownRoles[role]; ok {
		return perms
	}
	return []string{}
}

func (m *HiddenAdminsModule) generateLoot() {
	// Loot is now generated per-project in writeHierarchicalOutput/writeFlatOutput
}

func (m *HiddenAdminsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *HiddenAdminsModule) getHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Principal",
		"Principal Type",
		"Permission",
		"Category",
	}
}

func (m *HiddenAdminsModule) adminsToTableBody(admins []HiddenAdmin) [][]string {
	var body [][]string
	for _, admin := range admins {
		scopeName := admin.ScopeName
		if scopeName == "" {
			scopeName = admin.ScopeID
		}

		body = append(body, []string{
			admin.ScopeType,
			admin.ScopeID,
			scopeName,
			admin.Principal,
			admin.PrincipalType,
			admin.Permission,
			admin.Category,
		})
	}
	return body
}

// adminsForProject returns hidden admins filtered for a specific project
// Includes:
// - Project-scoped findings where ScopeID matches this project
// - Org-scoped findings where the org is this project's org
// - Folder-scoped findings where the folder is in this project's ancestry path
// For all of the above, the principal must either be from this project (SA) or be a user/group
func (m *HiddenAdminsModule) adminsForProject(projectID string) []HiddenAdmin {
	var filtered []HiddenAdmin

	// Get ancestry data for this project
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

	for _, admin := range m.AllAdmins {
		// Check if principal is relevant for this project
		principalProject := extractProjectFromPrincipal(admin.Principal, m.OrgCache)
		principalRelevant := principalProject == projectID || principalProject == ""

		if !principalRelevant {
			continue
		}

		switch admin.ScopeType {
		case "project":
			// Project-scoped: must match this project
			if admin.ScopeID == projectID {
				filtered = append(filtered, admin)
			}
		case "organization":
			// Org-scoped: must be this project's org
			if projectOrgID != "" && admin.ScopeID == projectOrgID {
				filtered = append(filtered, admin)
			} else if projectOrgID == "" {
				// No org info, include all org findings for users/groups
				filtered = append(filtered, admin)
			}
		case "folder":
			// Folder-scoped: must be in this project's ancestry
			if len(ancestorFolderSet) > 0 {
				if ancestorFolderSet[admin.ScopeID] {
					filtered = append(filtered, admin)
				}
			} else {
				// No ancestry info, include all folder findings for users/groups
				filtered = append(filtered, admin)
			}
		default:
			// Resource-level: include if principal is relevant
			filtered = append(filtered, admin)
		}
	}

	return filtered
}

// adminsToTableBodyForProject returns table body filtered for a specific project
func (m *HiddenAdminsModule) adminsToTableBodyForProject(projectID string) [][]string {
	admins := m.adminsForProject(projectID)
	return m.adminsToTableBody(admins)
}

// wrongAdminsForProject returns wrong admins filtered for a specific project
// Includes:
// - Project-level wrong admins where ProjectID matches this project
// - Org-level wrong admins where OrgID matches this project's org
// - Folder-level wrong admins where FolderID is in this project's ancestry
// For all of the above, the principal must either be from this project (SA) or be a user/group
func (m *HiddenAdminsModule) wrongAdminsForProject(projectID string) []foxmapperservice.WrongAdminFinding {
	var filtered []foxmapperservice.WrongAdminFinding

	// Get ancestry data for this project
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

	for _, wa := range m.WrongAdmins {
		principalProject := extractProjectFromPrincipal(wa.Principal, m.OrgCache)
		principalRelevant := principalProject == projectID || principalProject == ""

		if !principalRelevant {
			continue
		}

		switch wa.AdminLevel {
		case "project":
			// Project-level: include if ProjectID matches this project
			if wa.ProjectID == projectID {
				filtered = append(filtered, wa)
			}
		case "org":
			// Org-level: must be this project's org
			if projectOrgID != "" && wa.OrgID == projectOrgID {
				filtered = append(filtered, wa)
			} else if projectOrgID == "" {
				// No org info available, include all org findings for relevant principals
				filtered = append(filtered, wa)
			}
		case "folder":
			// Folder-level: must be in this project's ancestry
			if len(ancestorFolderSet) > 0 && wa.FolderID != "" {
				if ancestorFolderSet[wa.FolderID] {
					filtered = append(filtered, wa)
				}
			} else if len(ancestorFolderSet) == 0 {
				// No ancestry info available, include all folder findings for relevant principals
				filtered = append(filtered, wa)
			}
		default:
			// Unknown level, include for relevant principals if ProjectID matches
			if wa.ProjectID == projectID || wa.ProjectID == "" {
				filtered = append(filtered, wa)
			}
		}
	}

	return filtered
}

// wrongAdminsToTableBodyForProject returns wrong admins table body for a project
func (m *HiddenAdminsModule) wrongAdminsToTableBodyForProject(projectID string) [][]string {
	var body [][]string
	for _, wa := range m.wrongAdminsForProject(projectID) {
		reasonsStr := strings.Join(wa.Reasons, "; ")

		displayProject := wa.ProjectID
		if displayProject == "" {
			displayProject = "-"
		}

		body = append(body, []string{
			wa.Principal,
			wa.MemberType,
			wa.AdminLevel,
			displayProject,
			reasonsStr,
		})
	}
	return body
}

// generatePlaybookForProject generates a loot file specific to a project
func (m *HiddenAdminsModule) generatePlaybookForProject(projectID string) *internal.LootFile {
	admins := m.adminsForProject(projectID)
	wrongAdmins := m.wrongAdminsForProject(projectID)

	if len(admins) == 0 && len(wrongAdmins) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString("# GCP Hidden Admins Exploitation Playbook\n")
	sb.WriteString(fmt.Sprintf("# Project: %s\n", projectID))
	sb.WriteString("# Generated by CloudFox\n")
	sb.WriteString("# WARNING: Only use with proper authorization\n\n")

	// Add wrong admins section if available
	if len(wrongAdmins) > 0 {
		sb.WriteString("# === WRONG ADMINS (FOXMAPPER ANALYSIS) ===\n\n")
		sb.WriteString("# These principals are marked as admin but don't have explicit admin roles.\n\n")

		for _, wa := range wrongAdmins {
			sb.WriteString(fmt.Sprintf("# =============================================================================\n"+
				"# %s [%s]\n"+
				"# =============================================================================\n", wa.Principal, wa.MemberType))
			sb.WriteString(fmt.Sprintf("Admin Level: %s\n", wa.AdminLevel))
			for _, reason := range wa.Reasons {
				sb.WriteString(fmt.Sprintf("  - %s\n", reason))
			}

			// Add exploit command based on admin level
			switch wa.AdminLevel {
			case "org":
				sb.WriteString("\n# Grant yourself org-level owner:\n")
				orgID := wa.OrgID
				if orgID == "" {
					orgID = "ORG_ID"
				}
				sb.WriteString(fmt.Sprintf("gcloud organizations add-iam-policy-binding %s --member='%s:%s' --role='roles/owner'\n\n", orgID, wa.MemberType, wa.Principal))
			case "folder":
				sb.WriteString("\n# Grant yourself folder-level owner:\n")
				folderID := wa.FolderID
				if folderID == "" {
					folderID = "FOLDER_ID"
				}
				sb.WriteString(fmt.Sprintf("gcloud resource-manager folders add-iam-policy-binding %s --member='%s:%s' --role='roles/owner'\n\n", folderID, wa.MemberType, wa.Principal))
			default:
				sb.WriteString("\n# Grant yourself project-level owner:\n")
				targetProject := wa.ProjectID
				if targetProject == "" {
					targetProject = projectID
				}
				sb.WriteString(fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member='%s:%s' --role='roles/owner'\n\n", targetProject, wa.MemberType, wa.Principal))
			}
		}
	}

	// Add hidden admins section
	if len(admins) > 0 {
		sb.WriteString("# === HIDDEN ADMINS (IAM MODIFICATION CAPABILITIES) ===\n\n")

		for _, admin := range admins {
			scopeInfo := fmt.Sprintf("%s: %s", admin.ScopeType, admin.ScopeName)
			if admin.ScopeName == "" {
				scopeInfo = fmt.Sprintf("%s: %s", admin.ScopeType, admin.ScopeID)
			}

			sb.WriteString(fmt.Sprintf("# =============================================================================\n"+
				"# %s [%s]\n"+
				"# =============================================================================\n", admin.Principal, admin.PrincipalType))
			sb.WriteString(fmt.Sprintf("Permission: %s\n", admin.Permission))
			sb.WriteString(fmt.Sprintf("Category: %s\n", admin.Category))
			sb.WriteString(fmt.Sprintf("Scope: %s\n", scopeInfo))
			sb.WriteString("\n")
			sb.WriteString(admin.ExploitCommand)
			sb.WriteString("\n\n")
		}
	}

	return &internal.LootFile{
		Name:     "hidden-admins-commands",
		Contents: sb.String(),
	}
}

func (m *HiddenAdminsModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	// Hidden admins table
	body := m.adminsToTableBodyForProject(projectID)
	if len(body) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "hidden-admins",
			Header: m.getHeader(),
			Body:   body,
		})
	}

	// Wrong admins table
	wrongBody := m.wrongAdminsToTableBodyForProject(projectID)
	if len(wrongBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "wrong-admins",
			Header: m.getWrongAdminsHeader(),
			Body:   wrongBody,
		})
	}

	return tableFiles
}

func (m *HiddenAdminsModule) buildAllTables() []internal.TableFile {
	var tables []internal.TableFile

	if len(m.AllAdmins) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "hidden-admins",
			Header: m.getHeader(),
			Body:   m.adminsToTableBody(m.AllAdmins),
		})
	}

	// Add wrong admins table if FoxMapper data is available
	if len(m.WrongAdmins) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "wrong-admins",
			Header: m.getWrongAdminsHeader(),
			Body:   m.wrongAdminsToTableBody(),
		})
	}

	return tables
}

func (m *HiddenAdminsModule) getWrongAdminsHeader() []string {
	return []string{
		"Principal",
		"Type",
		"Admin Level",
		"Project",
		"Reasons",
	}
}

func (m *HiddenAdminsModule) wrongAdminsToTableBody() [][]string {
	var body [][]string
	for _, wa := range m.WrongAdmins {
		// Combine reasons into a single string
		reasonsStr := strings.Join(wa.Reasons, "; ")

		projectID := wa.ProjectID
		if projectID == "" {
			projectID = "-"
		}

		body = append(body, []string{
			wa.Principal,
			wa.MemberType,
			wa.AdminLevel,
			projectID,
			reasonsStr,
		})
	}
	return body
}


func (m *HiddenAdminsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		FolderLevelData:  make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Process each specified project
	for _, projectID := range m.ProjectIDs {
		// Build tables for this project
		tableFiles := m.buildTablesForProject(projectID)

		// Generate loot file for this project
		var lootFiles []internal.LootFile
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil {
			lootFiles = append(lootFiles, *playbook)
		}

		// Add project to output if there's any data
		if len(tableFiles) > 0 || len(lootFiles) > 0 {
			outputData.ProjectLevelData[projectID] = HiddenAdminsOutput{Table: tableFiles, Loot: lootFiles}
		}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	}
}

func (m *HiddenAdminsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildAllTables()

	// Generate per-project playbooks
	var lootFiles []internal.LootFile
	for _, projectID := range m.ProjectIDs {
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil {
			// Rename to include project for flat output
			playbook.Name = fmt.Sprintf("hidden-admins-commands-%s", projectID)
			lootFiles = append(lootFiles, *playbook)
		}
	}

	output := HiddenAdminsOutput{Table: tables, Loot: lootFiles}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	}
}

// Helper functions (shared with attackpathService)
func extractPrincipalType(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	} else if strings.HasPrefix(member, "serviceAccount:") {
		return "serviceAccount"
	} else if strings.HasPrefix(member, "group:") {
		return "group"
	} else if strings.HasPrefix(member, "domain:") {
		return "domain"
	}
	return "unknown"
}

func extractPrincipalEmail(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return member
}
