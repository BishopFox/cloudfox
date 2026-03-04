package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	OAuthService "github.com/BishopFox/cloudfox/gcp/services/oauthService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	cloudidentity "google.golang.org/api/cloudidentity/v1"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	crmv3 "google.golang.org/api/cloudresourcemanager/v3"
)

// Flags for whoami command
var whoamiExtended bool
var whoamiGroups []string
var whoamiGroupsFile string

var GCPWhoAmICommand = &cobra.Command{
	Use:     globals.GCP_WHOAMI_MODULE_NAME,
	Aliases: []string{"identity", "me"},
	Short:   "Display identity context for the authenticated GCP user/service account",
	Long: `Display identity context for the authenticated GCP user/service account.

Default output:
- Current identity details (email, type)
- Organization and folder context
- Effective role bindings across projects (with inheritance source)

With --extended flag (adds):
- Service accounts that can be impersonated
- Privilege escalation opportunities
- Data exfiltration capabilities (compute exports, logging sinks, database exports, etc.)
- Lateral movement capabilities (VPC peering, OS Login, firewall modifications, etc.)
- Exploitation commands

With --groups flag:
- Provide known group email addresses when group enumeration is permission denied
- Role bindings from these groups will be included in the output
- Use comma-separated list: --groups=group1@domain.com,group2@domain.com

With --groupslist flag:
- Import groups from a file (one group per line)
- Same behavior as --groups but reads from file
- Example: --groupslist=groups.txt`,
	Run: runGCPWhoAmICommand,
}

func init() {
	GCPWhoAmICommand.Flags().BoolVarP(&whoamiExtended, "extended", "e", false, "Enable extended enumeration (impersonation targets, privilege escalation paths)")
	GCPWhoAmICommand.Flags().StringSliceVarP(&whoamiGroups, "groups", "g", []string{}, "Comma-separated list of known group email addresses (used when group enumeration is permission denied)")
	GCPWhoAmICommand.Flags().StringVar(&whoamiGroupsFile, "groupslist", "", "Path to file containing group email addresses (one per line)")
}

// ------------------------------
// Data Structures
// ------------------------------

type IdentityContext struct {
	Email             string
	Type              string // "user" or "serviceAccount"
	UniqueID          string
	ProjectIDs        []string      // Keep for backward compatibility
	Projects          []ProjectInfo // New: stores project ID and display name
	Organizations     []OrgInfo
	Folders           []FolderInfo
	Groups            []GroupMembership // Groups the identity is a member of
	GroupsEnumerated  bool              // Whether group enumeration was successful
	GroupsProvided    []string          // Groups provided via --groups flag
	GroupsMismatch    bool              // True if provided groups differ from enumerated
}

type ProjectInfo struct {
	ProjectID   string
	DisplayName string
}

type OrgInfo struct {
	Name        string
	DisplayName string
	OrgID       string
}

type FolderInfo struct {
	Name        string
	DisplayName string
	Parent      string
}

type GroupMembership struct {
	GroupID     string // e.g., "groups/abc123"
	Email       string // e.g., "security-team@example.com"
	DisplayName string // e.g., "Security Team"
	Source      string // "enumerated" or "provided"
}

type RoleBinding struct {
	Role            string
	Scope           string // "organization", "folder", "project"
	ScopeID         string
	ScopeName       string // Display name of the scope resource
	Inherited       bool
	Condition       string
	InheritedFrom   string // Source of binding: "direct", group email, or parent resource
	MemberType      string // "user", "serviceAccount", "group"
}

type ImpersonationTarget struct {
	ServiceAccount string
	ProjectID      string
	CanImpersonate bool
	CanCreateKeys  bool
	CanActAs       bool
}

type PrivilegeEscalationPath struct {
	ProjectID      string // GCP project ID
	Permission     string // The permission/method enabling privesc
	Category       string // Category of the privesc (SA Impersonation, Key Creation, etc.)
	Description    string
	SourceRole     string // The role that grants this potential path
	SourceScope    string // Where the role is granted (project ID, folder, org)
	Command        string // Exploit command (for loot file only)
	Confidence     string // "confirmed" (verified via API) or "potential" (inferred from role)
	RequiredPerms  string // Specific permissions needed for this path
}

// DataExfilCapability represents a data exfiltration capability for the current identity
type DataExfilCapability struct {
	ProjectID   string
	Permission  string
	Category    string
	Description string
	SourceRole  string // The role/principal that grants this capability
	SourceScope string // Where the role is granted (project, folder, org)
}

// LateralMoveCapability represents a lateral movement capability for the current identity
type LateralMoveCapability struct {
	ProjectID   string
	Permission  string
	Category    string
	Description string
	SourceRole  string // The role/principal that grants this capability
	SourceScope string // Where the role is granted (project, folder, org)
}

// ------------------------------
// Module Struct
// ------------------------------
type WhoAmIModule struct {
	gcpinternal.BaseGCPModule

	Identity               IdentityContext
	RoleBindings           []RoleBinding
	ImpersonationTargets   []ImpersonationTarget
	PrivEscPaths           []PrivilegeEscalationPath
	DataExfilCapabilities  []DataExfilCapability
	LateralMoveCapabilities []LateralMoveCapability
	DangerousPermissions   []string
	LootMap                map[string]*internal.LootFile
	Extended               bool
	ProvidedGroups         []string // Groups provided via --groups flag
	mu                     sync.Mutex

	// FoxMapper findings - store the full findings for detailed path visualization
	FoxMapperPrivescFindings []foxmapperservice.PrivescFinding
	FoxMapperLateralFindings []foxmapperservice.LateralFinding
	FoxMapperDataExfilFindings []foxmapperservice.DataExfilFinding
	FoxMapperService         *foxmapperservice.FoxMapperService
}

// ------------------------------
// Output Struct
// ------------------------------
type WhoAmIOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o WhoAmIOutput) TableFiles() []internal.TableFile { return o.Table }
func (o WhoAmIOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPWhoAmICommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_WHOAMI_MODULE_NAME)
	if err != nil {
		return
	}

	// Combine groups from --groups flag and --groupslist file
	allGroups := whoamiGroups
	if whoamiGroupsFile != "" {
		fileGroups := internal.LoadFileLinesIntoArray(whoamiGroupsFile)
		allGroups = append(allGroups, fileGroups...)
	}

	// Create module instance
	module := &WhoAmIModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		RoleBindings:         []RoleBinding{},
		ImpersonationTargets: []ImpersonationTarget{},
		PrivEscPaths:         []PrivilegeEscalationPath{},
		DangerousPermissions: []string{},
		LootMap:              make(map[string]*internal.LootFile),
		Extended:             whoamiExtended,
		ProvidedGroups:       allGroups,
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *WhoAmIModule) Execute(ctx context.Context, logger internal.Logger) {
	if m.Extended {
		logger.InfoM("Gathering comprehensive identity context (extended mode)...", globals.GCP_WHOAMI_MODULE_NAME)
	} else {
		logger.InfoM("Gathering identity context...", globals.GCP_WHOAMI_MODULE_NAME)
	}

	// Step 1: Get current identity
	oauthService := OAuthService.NewOAuthService()
	principal, err := oauthService.WhoAmI()
	if err != nil {
		parsedErr := gcpinternal.ParseGCPError(err, "oauth2.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not retrieve token info")
		return
	}

	m.Identity = IdentityContext{
		Email:      principal.Email,
		ProjectIDs: m.ProjectIDs,
	}

	// Determine identity type
	if strings.HasSuffix(principal.Email, ".gserviceaccount.com") {
		m.Identity.Type = "serviceAccount"
	} else {
		m.Identity.Type = "user"
	}

	logger.InfoM(fmt.Sprintf("Authenticated as: %s (%s)", m.Identity.Email, m.Identity.Type), globals.GCP_WHOAMI_MODULE_NAME)

	// Step 2: Get organization context (always run)
	m.getOrganizationContext(ctx, logger)

	// Step 3: Get group memberships for the current identity
	m.getGroupMemberships(ctx, logger)

	// Step 4: Get role bindings across projects (always run)
	m.getRoleBindings(ctx, logger)

	// Extended mode: Additional enumeration
	if m.Extended {
		// Step 4: Find impersonation targets
		m.findImpersonationTargets(ctx, logger)

		// Step 5: Identify privilege escalation paths
		m.identifyPrivEscPaths(ctx, logger)

		// Step 6: Identify data exfiltration capabilities
		m.identifyDataExfilCapabilities(ctx, logger)

		// Step 7: Identify lateral movement capabilities
		m.identifyLateralMoveCapabilities(ctx, logger)
	}

	// Step 8: Generate loot
	m.generateLoot()

	// Write output
	m.writeOutput(ctx, logger)
}

// getOrganizationContext retrieves organization and folder hierarchy
func (m *WhoAmIModule) getOrganizationContext(ctx context.Context, logger internal.Logger) {
	// Create resource manager clients
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not create Cloud Resource Manager client")
		return
	}

	// Create v3 client for fetching folder details
	crmv3Service, err := crmv3.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not create Cloud Resource Manager v3 client")
		// Continue without v3, we just won't get display names for folders
	}

	// Get project ancestry for each project
	for _, projectID := range m.ProjectIDs {
		// Fetch project details to get display name
		projectInfo := ProjectInfo{
			ProjectID: projectID,
		}
		project, err := crmService.Projects.Get(projectID).Do()
		if err == nil && project != nil {
			projectInfo.DisplayName = project.Name
		}
		m.Identity.Projects = append(m.Identity.Projects, projectInfo)

		// Get ancestry
		resp, err := crmService.Projects.GetAncestry(projectID, &cloudresourcemanager.GetAncestryRequest{}).Do()
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
				fmt.Sprintf("Could not get ancestry for project %s", projectID))
			continue
		}

		for _, ancestor := range resp.Ancestor {
			switch ancestor.ResourceId.Type {
			case "organization":
				orgInfo := OrgInfo{
					OrgID: ancestor.ResourceId.Id,
					Name:  fmt.Sprintf("organizations/%s", ancestor.ResourceId.Id),
				}
				// Try to get display name for organization
				org, err := crmService.Organizations.Get(orgInfo.Name).Do()
				if err == nil && org != nil {
					orgInfo.DisplayName = org.DisplayName
				}
				// Check if already added
				exists := false
				for _, o := range m.Identity.Organizations {
					if o.OrgID == orgInfo.OrgID {
						exists = true
						break
					}
				}
				if !exists {
					m.Identity.Organizations = append(m.Identity.Organizations, orgInfo)
				}
			case "folder":
				folderName := fmt.Sprintf("folders/%s", ancestor.ResourceId.Id)
				folderInfo := FolderInfo{
					Name: folderName,
				}
				// Try to get display name for folder using v3 API
				if crmv3Service != nil {
					folder, err := crmv3Service.Folders.Get(folderName).Do()
					if err == nil && folder != nil {
						folderInfo.DisplayName = folder.DisplayName
						folderInfo.Parent = folder.Parent
					}
				}
				// Check if already added
				exists := false
				for _, f := range m.Identity.Folders {
					if f.Name == folderInfo.Name {
						exists = true
						break
					}
				}
				if !exists {
					m.Identity.Folders = append(m.Identity.Folders, folderInfo)
				}
			}
		}
	}

	if len(m.Identity.Organizations) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d organization(s), %d folder(s)", len(m.Identity.Organizations), len(m.Identity.Folders)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// normalizeGroupEmail ensures group has full email format
// If group doesn't contain @, tries to infer domain from identity email
func (m *WhoAmIModule) normalizeGroupEmail(group string) string {
	if strings.Contains(group, "@") {
		return group
	}

	// Try to infer domain from identity email
	if m.Identity.Email != "" && strings.Contains(m.Identity.Email, "@") {
		parts := strings.SplitN(m.Identity.Email, "@", 2)
		if len(parts) == 2 {
			return group + "@" + parts[1]
		}
	}

	// Return as-is if we can't infer domain
	return group
}

// getGroupMemberships retrieves the groups that the current identity is a member of
func (m *WhoAmIModule) getGroupMemberships(ctx context.Context, logger internal.Logger) {
	// Normalize provided groups to full email format
	var normalizedGroups []string
	for _, group := range m.ProvidedGroups {
		normalizedGroups = append(normalizedGroups, m.normalizeGroupEmail(group))
	}
	m.ProvidedGroups = normalizedGroups

	// Store provided groups
	m.Identity.GroupsProvided = m.ProvidedGroups

	// Only applicable for user identities (not service accounts)
	if m.Identity.Type != "user" {
		m.Identity.GroupsEnumerated = true // N/A for service accounts
		// If groups were provided for a service account, add them as provided
		if len(m.ProvidedGroups) > 0 {
			for _, groupEmail := range m.ProvidedGroups {
				m.Identity.Groups = append(m.Identity.Groups, GroupMembership{
					Email:  groupEmail,
					Source: "provided",
				})
			}
			logger.InfoM(fmt.Sprintf("Using %d provided group(s) for service account", len(m.ProvidedGroups)), globals.GCP_WHOAMI_MODULE_NAME)
		}
		return
	}

	ciService, err := cloudidentity.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		parsedErr := gcpinternal.ParseGCPError(err, "cloudidentity.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not create Cloud Identity client")
		// GroupsEnumerated stays false - use provided groups if available
		m.useProvidedGroups(logger)
		return
	}

	// Search for groups that the user is a direct member of
	// The parent must be "groups/-" to search across all groups
	query := fmt.Sprintf("member_key_id == '%s'", m.Identity.Email)
	resp, err := ciService.Groups.Memberships.SearchDirectGroups("groups/-").Query(query).Do()
	if err != nil {
		m.CommandCounter.Error++
		parsedErr := gcpinternal.ParseGCPError(err, "cloudidentity.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not fetch group memberships")
		// GroupsEnumerated stays false - use provided groups if available
		m.useProvidedGroups(logger)
		return
	}

	// Successfully enumerated groups
	m.Identity.GroupsEnumerated = true

	var enumeratedEmails []string
	for _, membership := range resp.Memberships {
		group := GroupMembership{
			GroupID:     membership.Group,
			DisplayName: membership.DisplayName,
			Source:      "enumerated",
		}
		if membership.GroupKey != nil {
			group.Email = membership.GroupKey.Id
			enumeratedEmails = append(enumeratedEmails, strings.ToLower(membership.GroupKey.Id))
		}
		m.Identity.Groups = append(m.Identity.Groups, group)
	}

	// Check for mismatch with provided groups
	if len(m.ProvidedGroups) > 0 {
		m.checkGroupMismatch(enumeratedEmails, logger)
	}

	if len(m.Identity.Groups) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d group membership(s)", len(m.Identity.Groups)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// useProvidedGroups adds provided groups when enumeration fails
func (m *WhoAmIModule) useProvidedGroups(logger internal.Logger) {
	if len(m.ProvidedGroups) > 0 {
		for _, groupEmail := range m.ProvidedGroups {
			m.Identity.Groups = append(m.Identity.Groups, GroupMembership{
				Email:  groupEmail,
				Source: "provided",
			})
		}
		logger.InfoM(fmt.Sprintf("Using %d provided group(s) (enumeration failed)", len(m.ProvidedGroups)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// checkGroupMismatch compares provided groups with enumerated groups
func (m *WhoAmIModule) checkGroupMismatch(enumeratedEmails []string, logger internal.Logger) {
	enumeratedSet := make(map[string]bool)
	for _, email := range enumeratedEmails {
		enumeratedSet[strings.ToLower(email)] = true
	}

	providedSet := make(map[string]bool)
	for _, email := range m.ProvidedGroups {
		providedSet[strings.ToLower(email)] = true
	}

	// Check for provided groups not in enumerated
	var notInEnumerated []string
	for _, email := range m.ProvidedGroups {
		if !enumeratedSet[strings.ToLower(email)] {
			notInEnumerated = append(notInEnumerated, email)
		}
	}

	// Check for enumerated groups not in provided
	var notInProvided []string
	for _, email := range enumeratedEmails {
		if !providedSet[strings.ToLower(email)] {
			notInProvided = append(notInProvided, email)
		}
	}

	if len(notInEnumerated) > 0 || len(notInProvided) > 0 {
		m.Identity.GroupsMismatch = true
		if len(notInEnumerated) > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Provided groups not found in enumerated: %s", strings.Join(notInEnumerated, ", ")), globals.GCP_WHOAMI_MODULE_NAME)
		}
		if len(notInProvided) > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Enumerated groups not in provided list: %s", strings.Join(notInProvided, ", ")), globals.GCP_WHOAMI_MODULE_NAME)
		}
	}
}

// getRoleBindings retrieves IAM role bindings for the current identity
func (m *WhoAmIModule) getRoleBindings(ctx context.Context, logger internal.Logger) {
	iamService := IAMService.New()

	// Determine the member format for current identity
	var memberPrefix string
	if m.Identity.Type == "serviceAccount" {
		memberPrefix = "serviceAccount:"
	} else {
		memberPrefix = "user:"
	}
	fullMember := memberPrefix + m.Identity.Email

	// Build list of group members to check
	groupMembers := make(map[string]string) // group:email -> email for display
	for _, group := range m.Identity.Groups {
		if group.Email != "" {
			groupMembers["group:"+group.Email] = group.Email
		}
	}

	// Get role bindings from each project
	for _, projectID := range m.ProjectIDs {
		// Use PrincipalsWithRolesEnhanced which includes inheritance
		principals, err := iamService.PrincipalsWithRolesEnhanced(projectID)
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
				fmt.Sprintf("Could not get IAM bindings for project %s", projectID))
			continue
		}

		// Find bindings for the current identity (direct)
		for _, principal := range principals {
			if principal.Name == fullMember || principal.Email == m.Identity.Email {
				for _, binding := range principal.PolicyBindings {
					rb := RoleBinding{
						Role:          binding.Role,
						Scope:         binding.ResourceType,
						ScopeID:       binding.ResourceID,
						Inherited:     binding.IsInherited,
						InheritedFrom: "direct",
						MemberType:    m.Identity.Type,
					}
					if binding.HasCondition && binding.ConditionInfo != nil {
						rb.Condition = binding.ConditionInfo.Title
					}
					// Set inherited source if from parent resource
					if binding.IsInherited && binding.InheritedFrom != "" {
						rb.InheritedFrom = binding.InheritedFrom
					}

					// Check for dangerous permissions
					if isDangerousRole(binding.Role) {
						m.DangerousPermissions = append(m.DangerousPermissions, fmt.Sprintf("%s on %s", binding.Role, binding.ResourceID))
					}

					m.mu.Lock()
					m.RoleBindings = append(m.RoleBindings, rb)
					m.mu.Unlock()
				}
			}

			// Check for group-based bindings
			if groupEmail, ok := groupMembers[principal.Name]; ok {
				for _, binding := range principal.PolicyBindings {
					rb := RoleBinding{
						Role:          binding.Role,
						Scope:         binding.ResourceType,
						ScopeID:       binding.ResourceID,
						Inherited:     binding.IsInherited,
						InheritedFrom: fmt.Sprintf("group:%s", groupEmail),
						MemberType:    "group",
					}
					if binding.HasCondition && binding.ConditionInfo != nil {
						rb.Condition = binding.ConditionInfo.Title
					}

					// Check for dangerous permissions
					if isDangerousRole(binding.Role) {
						m.DangerousPermissions = append(m.DangerousPermissions, fmt.Sprintf("%s on %s (via group %s)", binding.Role, binding.ResourceID, groupEmail))
					}

					m.mu.Lock()
					m.RoleBindings = append(m.RoleBindings, rb)
					m.mu.Unlock()
				}
			}
		}
	}

	directCount := 0
	groupCount := 0
	for _, rb := range m.RoleBindings {
		if rb.MemberType == "group" {
			groupCount++
		} else {
			directCount++
		}
	}

	if groupCount > 0 {
		logger.InfoM(fmt.Sprintf("Found %d role binding(s) (%d direct, %d via groups)", len(m.RoleBindings), directCount, groupCount), globals.GCP_WHOAMI_MODULE_NAME)
	} else {
		logger.InfoM(fmt.Sprintf("Found %d role binding(s) for current identity", len(m.RoleBindings)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// findImpersonationTargets identifies service accounts that can be impersonated
func (m *WhoAmIModule) findImpersonationTargets(ctx context.Context, logger internal.Logger) {
	iamService := IAMService.New()

	// Determine the member format for current identity
	var memberPrefix string
	if m.Identity.Type == "serviceAccount" {
		memberPrefix = "serviceAccount:"
	} else {
		memberPrefix = "user:"
	}
	fullMember := memberPrefix + m.Identity.Email

	for _, projectID := range m.ProjectIDs {
		// Get all service accounts in the project (without keys - not needed for impersonation check)
		serviceAccounts, err := iamService.ServiceAccountsBasic(projectID)
		if err != nil {
			continue
		}

		for _, sa := range serviceAccounts {
			// Check if current identity can impersonate this SA using GetServiceAccountIAMPolicy
			impersonationInfo, err := iamService.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
			if err != nil {
				continue
			}

			// Check if current identity is in the token creators or key creators list
			canImpersonate := false
			canCreateKeys := false
			canActAs := false

			for _, tc := range impersonationInfo.TokenCreators {
				if tc == fullMember || tc == m.Identity.Email || shared.IsPublicPrincipal(tc) {
					canImpersonate = true
					break
				}
			}

			for _, kc := range impersonationInfo.KeyCreators {
				if kc == fullMember || kc == m.Identity.Email || shared.IsPublicPrincipal(kc) {
					canCreateKeys = true
					break
				}
			}

			for _, aa := range impersonationInfo.ActAsUsers {
				if aa == fullMember || aa == m.Identity.Email || shared.IsPublicPrincipal(aa) {
					canActAs = true
					break
				}
			}

			if canImpersonate || canCreateKeys || canActAs {
				target := ImpersonationTarget{
					ServiceAccount: sa.Email,
					ProjectID:      projectID,
					CanImpersonate: canImpersonate,
					CanCreateKeys:  canCreateKeys,
					CanActAs:       canActAs,
				}
				m.ImpersonationTargets = append(m.ImpersonationTargets, target)
			}
		}
	}

	if len(m.ImpersonationTargets) > 0 {
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d service account(s) that can be impersonated", len(m.ImpersonationTargets)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// identifyPrivEscPaths identifies privilege escalation paths based on current permissions
// Uses FoxMapperService for comprehensive graph-based analysis
// Filters results to only show paths relevant to the current identity and their groups
// Will use cached FoxMapper data from context if available (e.g., from all-checks run)
func (m *WhoAmIModule) identifyPrivEscPaths(ctx context.Context, logger internal.Logger) {
	// Build set of principals to filter for (current identity + groups)
	relevantPrincipals := make(map[string]bool)
	// Add current identity email (with various formats)
	relevantPrincipals[m.Identity.Email] = true
	relevantPrincipals[strings.ToLower(m.Identity.Email)] = true
	// Add with type prefixes
	if m.Identity.Type == "serviceAccount" {
		relevantPrincipals["serviceAccount:"+m.Identity.Email] = true
		relevantPrincipals["serviceAccount:"+strings.ToLower(m.Identity.Email)] = true
	} else {
		relevantPrincipals["user:"+m.Identity.Email] = true
		relevantPrincipals["user:"+strings.ToLower(m.Identity.Email)] = true
	}
	// Add groups (enumerated or provided)
	for _, group := range m.Identity.Groups {
		if group.Email != "" {
			relevantPrincipals[group.Email] = true
			relevantPrincipals[strings.ToLower(group.Email)] = true
			relevantPrincipals["group:"+group.Email] = true
			relevantPrincipals["group:"+strings.ToLower(group.Email)] = true
		}
	}
	// Add special principals that apply to everyone
	relevantPrincipals["allUsers"] = true
	relevantPrincipals["allAuthenticatedUsers"] = true

	// Check if FoxMapper cache is available from context
	foxMapperCache := gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if foxMapperCache != nil && foxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper cache for privesc analysis", globals.GCP_WHOAMI_MODULE_NAME)
		m.identifyPrivEscPathsFromFoxMapper(foxMapperCache, relevantPrincipals, logger)
	} else {
		// No cache available, try to load FoxMapper data
		m.identifyPrivEscPathsFromAnalysis(ctx, relevantPrincipals, logger)
	}

	// Also check impersonation-based privilege escalation from findImpersonationTargets
	for _, target := range m.ImpersonationTargets {
		if target.CanImpersonate {
			path := PrivilegeEscalationPath{
				ProjectID:     target.ProjectID,
				Permission:    "iam.serviceAccounts.getAccessToken",
				Category:      "SA Impersonation",
				Description:   fmt.Sprintf("Can generate access tokens for %s", target.ServiceAccount),
				SourceRole:    "(via SA IAM policy)",
				SourceScope:   fmt.Sprintf("project/%s", target.ProjectID),
				Command:       fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", target.ServiceAccount),
				Confidence:    "confirmed",
				RequiredPerms: "iam.serviceAccounts.getAccessToken",
			}
			m.PrivEscPaths = append(m.PrivEscPaths, path)
		}

		if target.CanCreateKeys {
			path := PrivilegeEscalationPath{
				ProjectID:     target.ProjectID,
				Permission:    "iam.serviceAccountKeys.create",
				Category:      "Key Creation",
				Description:   fmt.Sprintf("Can create persistent keys for %s", target.ServiceAccount),
				SourceRole:    "(via SA IAM policy)",
				SourceScope:   fmt.Sprintf("project/%s", target.ProjectID),
				Command:       fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", target.ServiceAccount),
				Confidence:    "confirmed",
				RequiredPerms: "iam.serviceAccountKeys.create",
			}
			m.PrivEscPaths = append(m.PrivEscPaths, path)
		}
	}

	if len(m.PrivEscPaths) > 0 {
		logger.InfoM(fmt.Sprintf("[PRIVESC] Found %d privilege escalation path(s)", len(m.PrivEscPaths)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// identifyPrivEscPathsFromFoxMapper extracts privesc paths from FoxMapper cache
func (m *WhoAmIModule) identifyPrivEscPathsFromFoxMapper(cache *gcpinternal.FoxMapperCache, relevantPrincipals map[string]bool, logger internal.Logger) {
	svc := cache.GetService()
	if svc == nil {
		return
	}

	// Store the service for path lookups in playbook generation
	m.FoxMapperService = svc

	findings := svc.AnalyzePrivesc()
	for _, finding := range findings {
		// Check if this principal is relevant to our identity
		cleanPrincipal := finding.Principal
		if !relevantPrincipals[cleanPrincipal] && !relevantPrincipals["serviceAccount:"+cleanPrincipal] && !relevantPrincipals["user:"+cleanPrincipal] {
			continue
		}

		if !finding.CanEscalate && !finding.IsAdmin {
			continue
		}

		// Store full finding for detailed playbook generation
		m.FoxMapperPrivescFindings = append(m.FoxMapperPrivescFindings, finding)

		privEscPath := PrivilegeEscalationPath{
			ProjectID:     "",
			Permission:    "privesc",
			Category:      fmt.Sprintf("%s admin reachable", finding.HighestAdminLevel),
			Description:   fmt.Sprintf("Can escalate to %s admin in %d hops via %d paths", finding.HighestAdminLevel, finding.ShortestPathHops, finding.ViablePathCount),
			SourceRole:    finding.Principal,
			SourceScope:   finding.MemberType,
			Command:       "",
			Confidence:    "confirmed",
			RequiredPerms: fmt.Sprintf("%d paths to admin", finding.ViablePathCount),
		}
		m.PrivEscPaths = append(m.PrivEscPaths, privEscPath)
	}
}

// identifyPrivEscPathsFromAnalysis runs fresh privesc analysis using FoxMapperService
func (m *WhoAmIModule) identifyPrivEscPathsFromAnalysis(ctx context.Context, relevantPrincipals map[string]bool, logger internal.Logger) {
	// Use FoxMapperService for comprehensive privesc analysis
	svc := foxmapperservice.New()

	// Determine org ID or use first project
	orgID := ""
	if len(m.Identity.Organizations) > 0 {
		orgID = m.Identity.Organizations[0].OrgID
	}

	// Load FoxMapper graph data
	var err error
	if orgID != "" {
		err = svc.LoadGraph(orgID, true)
	} else if len(m.ProjectIDs) > 0 {
		err = svc.LoadGraph(m.ProjectIDs[0], false)
	} else {
		logger.InfoM("No org or project context available for FoxMapper analysis", globals.GCP_WHOAMI_MODULE_NAME)
		return
	}

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME, "Could not load FoxMapper graph data")
		return
	}

	// Store the service for path lookups in playbook generation
	m.FoxMapperService = svc

	// Run privesc analysis
	findings := svc.AnalyzePrivesc()

	// Filter findings for relevant principals only
	for _, finding := range findings {
		// Check if this finding is for a relevant principal
		if !relevantPrincipals[finding.Principal] && !relevantPrincipals[strings.ToLower(finding.Principal)] {
			continue
		}

		// Store full finding for detailed playbook generation
		m.FoxMapperPrivescFindings = append(m.FoxMapperPrivescFindings, finding)

		// Convert each privesc path to whoami format
		for _, path := range finding.Paths {
			// Build command from first edge if available
			command := ""
			permission := ""
			if len(path.Edges) > 0 {
				command = generatePrivescCommandFromEdge(path.Edges[0])
				permission = path.Edges[0].ShortReason
			}

			pathConf := path.Confidence
			if pathConf == "" || pathConf == "high" {
				pathConf = "confirmed"
			}

			privEscPath := PrivilegeEscalationPath{
				ProjectID:     "", // FoxMapper doesn't track project per edge
				Permission:    permission,
				Category:      "Privesc",
				Description:   fmt.Sprintf("Can escalate to %s admin via %d-hop path", path.AdminLevel, path.HopCount),
				SourceRole:    finding.Principal,
				SourceScope:   path.AdminLevel,
				Command:       command,
				Confidence:    pathConf,
				RequiredPerms: permission,
			}

			if path.ScopeBlocked {
				privEscPath.Description += " (blocked by IAM condition)"
			}

			m.PrivEscPaths = append(m.PrivEscPaths, privEscPath)
		}
	}
}

// generatePrivescCommandFromEdge generates a simple exploit command from a FoxMapper edge
func generatePrivescCommandFromEdge(edge foxmapperservice.Edge) string {
	// Simple command generation based on edge reason
	reason := strings.ToLower(edge.ShortReason)

	if strings.Contains(reason, "iam.serviceaccounts.getaccesstoken") {
		return "gcloud auth print-access-token --impersonate-service-account=TARGET_SA"
	} else if strings.Contains(reason, "iam.serviceaccountkeys.create") {
		return "gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA"
	} else if strings.Contains(reason, "iam.serviceaccounts.actas") {
		return "# Use actAs to run services as the target SA"
	} else if strings.Contains(reason, "setiampolicy") {
		return "# Modify IAM policy to grant yourself additional permissions"
	} else if strings.Contains(reason, "cloudfunctions") {
		return "gcloud functions deploy FUNC --runtime=python311 --service-account=TARGET_SA"
	} else if strings.Contains(reason, "run.services") {
		return "gcloud run deploy SERVICE --image=IMAGE --service-account=TARGET_SA"
	}

	return fmt.Sprintf("# Exploit via: %s", edge.Reason)
}

// generateExfilCommand generates a data exfiltration command based on permission
func generateExfilCommand(permission, service string) string {
	switch {
	case strings.Contains(permission, "storage.objects.get"):
		return "gsutil cp gs://BUCKET/path/to/file ./local/"
	case strings.Contains(permission, "bigquery.tables.getData"):
		return "bq query 'SELECT * FROM dataset.table'"
	case strings.Contains(permission, "bigquery.tables.export"):
		return "bq extract dataset.table gs://BUCKET/export.csv"
	case strings.Contains(permission, "cloudsql.instances.export"):
		return "gcloud sql export sql INSTANCE gs://BUCKET/export.sql --database=DB"
	case strings.Contains(permission, "secretmanager.versions.access"):
		return "gcloud secrets versions access latest --secret=SECRET"
	case strings.Contains(permission, "cloudkms.cryptoKeyVersions.useToDecrypt"):
		return "gcloud kms decrypt --key=KEY --keyring=KEYRING --location=LOCATION"
	case strings.Contains(permission, "logging.logEntries.list"):
		return "gcloud logging read 'logName=\"projects/PROJECT/logs/LOG\"'"
	case strings.Contains(permission, "pubsub.subscriptions.consume"):
		return "gcloud pubsub subscriptions pull SUBSCRIPTION --auto-ack"
	default:
		return fmt.Sprintf("# Use permission: %s (service: %s)", permission, service)
	}
}

// generateLateralCommand generates a lateral movement command based on permission
func generateLateralCommand(permission, category string) string {
	switch {
	case strings.Contains(permission, "iam.serviceAccounts.getAccessToken"):
		return "gcloud auth print-access-token --impersonate-service-account=SA_EMAIL"
	case strings.Contains(permission, "iam.serviceAccountKeys.create"):
		return "gcloud iam service-accounts keys create key.json --iam-account=SA_EMAIL"
	case strings.Contains(permission, "compute.instances.osLogin"):
		return "gcloud compute ssh INSTANCE_NAME --zone=ZONE"
	case strings.Contains(permission, "compute.instances.setMetadata"):
		return "gcloud compute instances add-metadata INSTANCE --metadata=ssh-keys=\"user:SSH_KEY\""
	case strings.Contains(permission, "container.clusters.getCredentials"):
		return "gcloud container clusters get-credentials CLUSTER --zone=ZONE"
	case strings.Contains(permission, "container.pods.exec"):
		return "kubectl exec -it POD -- /bin/sh"
	case strings.Contains(permission, "cloudfunctions.functions.create"):
		return "gcloud functions deploy FUNC --runtime=python311 --service-account=SA_EMAIL"
	case strings.Contains(permission, "run.services.create"):
		return "gcloud run deploy SERVICE --image=IMAGE --service-account=SA_EMAIL"
	default:
		return fmt.Sprintf("# Use permission: %s (category: %s)", permission, category)
	}
}

// isDangerousRole checks if a role is considered dangerous
func isDangerousRole(role string) bool {
	// Roles that map to dangerous permissions for privilege escalation
	dangerousRoles := []string{
		// Owner/Editor - broad access
		"roles/owner",
		"roles/editor",
		// IAM roles - service account impersonation and key creation
		"roles/iam.securityAdmin",
		"roles/iam.serviceAccountAdmin",
		"roles/iam.serviceAccountKeyAdmin",
		"roles/iam.serviceAccountTokenCreator",
		"roles/iam.serviceAccountUser", // iam.serviceAccounts.actAs
		// Resource Manager - IAM policy modification
		"roles/resourcemanager.organizationAdmin",
		"roles/resourcemanager.folderAdmin",
		"roles/resourcemanager.projectIamAdmin",
		// Compute - metadata injection, instance creation
		"roles/compute.admin",
		"roles/compute.instanceAdmin",
		"roles/compute.instanceAdmin.v1",
		// Serverless - code execution with SA
		"roles/cloudfunctions.admin",
		"roles/cloudfunctions.developer",
		"roles/run.admin",
		"roles/run.developer",
		// CI/CD - Cloud Build SA abuse
		"roles/cloudbuild.builds.editor",
		"roles/cloudbuild.builds.builder",
		// GKE - cluster and pod access
		"roles/container.admin",
		"roles/container.clusterAdmin",
		// Storage
		"roles/storage.admin",
		// Secrets
		"roles/secretmanager.admin",
		"roles/secretmanager.secretAccessor",
		// Deployment Manager
		"roles/deploymentmanager.editor",
		// Org Policy
		"roles/orgpolicy.policyAdmin",
	}

	for _, dr := range dangerousRoles {
		if role == dr {
			return true
		}
	}
	return false
}

// identifyDataExfilCapabilities identifies data exfiltration capabilities for the current identity
// Uses FoxMapper cache if available, otherwise runs FoxMapperService for comprehensive analysis
// Filters results to only show capabilities relevant to the current identity and their groups
func (m *WhoAmIModule) identifyDataExfilCapabilities(ctx context.Context, logger internal.Logger) {
	// Build set of principals to filter for (current identity + groups)
	relevantPrincipals := make(map[string]bool)
	relevantPrincipals[m.Identity.Email] = true
	relevantPrincipals[strings.ToLower(m.Identity.Email)] = true
	if m.Identity.Type == "serviceAccount" {
		relevantPrincipals["serviceAccount:"+m.Identity.Email] = true
		relevantPrincipals["serviceAccount:"+strings.ToLower(m.Identity.Email)] = true
	} else {
		relevantPrincipals["user:"+m.Identity.Email] = true
		relevantPrincipals["user:"+strings.ToLower(m.Identity.Email)] = true
	}
	for _, group := range m.Identity.Groups {
		if group.Email != "" {
			relevantPrincipals[group.Email] = true
			relevantPrincipals[strings.ToLower(group.Email)] = true
			relevantPrincipals["group:"+group.Email] = true
			relevantPrincipals["group:"+strings.ToLower(group.Email)] = true
		}
	}
	relevantPrincipals["allUsers"] = true
	relevantPrincipals["allAuthenticatedUsers"] = true

	// Check if FoxMapper cache is available from context (e.g., from all-checks run)
	foxMapperCache := gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if foxMapperCache != nil && foxMapperCache.IsPopulated() {
		logger.InfoM("Using cached exfil data", globals.GCP_WHOAMI_MODULE_NAME)
		m.identifyDataExfilFromCache(foxMapperCache, relevantPrincipals)
	} else {
		// No cache available, run fresh analysis
		m.identifyDataExfilFromAnalysis(ctx, relevantPrincipals, logger)
	}

	if len(m.DataExfilCapabilities) > 0 {
		logger.InfoM(fmt.Sprintf("[EXFIL] Found %d data exfiltration capability(s)", len(m.DataExfilCapabilities)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// identifyDataExfilFromCache extracts exfil capabilities from the FoxMapper cached data
func (m *WhoAmIModule) identifyDataExfilFromCache(foxMapperCache *gcpinternal.FoxMapperCache, relevantPrincipals map[string]bool) {
	if foxMapperCache == nil || !foxMapperCache.IsPopulated() {
		return
	}

	// Get the FoxMapper service from cache
	// Note: This currently requires accessing internal service from cache
	// For now, we'll just skip cache-based exfil detection and always run fresh analysis
	// TODO: Enhance FoxMapperCache to expose AnalyzeDataExfil method
}

// identifyDataExfilFromAnalysis runs fresh exfil analysis using FoxMapperService
func (m *WhoAmIModule) identifyDataExfilFromAnalysis(ctx context.Context, relevantPrincipals map[string]bool, logger internal.Logger) {
	// Use FoxMapperService for comprehensive exfil analysis
	svc := foxmapperservice.New()

	// Determine org ID or use first project
	orgID := ""
	if len(m.Identity.Organizations) > 0 {
		orgID = m.Identity.Organizations[0].OrgID
	}

	// Load FoxMapper graph data
	var err error
	if orgID != "" {
		err = svc.LoadGraph(orgID, true)
	} else if len(m.ProjectIDs) > 0 {
		err = svc.LoadGraph(m.ProjectIDs[0], false)
	} else {
		logger.InfoM("No org or project context available for FoxMapper analysis", globals.GCP_WHOAMI_MODULE_NAME)
		return
	}

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME, "Could not load FoxMapper graph data")
		return
	}

	// Store the service if not already set
	if m.FoxMapperService == nil {
		m.FoxMapperService = svc
	}

	// Run data exfil analysis (empty string means all services)
	findings := svc.AnalyzeDataExfil("")

	// Filter findings for relevant principals only
	for _, finding := range findings {
		hasRelevantPrincipal := false
		for _, principalAccess := range finding.Principals {
			// Check if this principal is relevant to the current identity
			if relevantPrincipals[principalAccess.Principal] || relevantPrincipals[strings.ToLower(principalAccess.Principal)] {
				hasRelevantPrincipal = true

				capability := DataExfilCapability{
					ProjectID:   "", // FoxMapper doesn't track project ID per finding
					Permission:  finding.Permission,
					Category:    finding.Service,
					Description: finding.Description,
					SourceRole:  principalAccess.Principal,
					SourceScope: "via privilege escalation",
				}
				m.DataExfilCapabilities = append(m.DataExfilCapabilities, capability)
			}
		}

		// Store full finding for detailed playbook generation
		if hasRelevantPrincipal {
			m.FoxMapperDataExfilFindings = append(m.FoxMapperDataExfilFindings, finding)
		}
	}
}

// identifyLateralMoveCapabilities identifies lateral movement capabilities for the current identity
// Uses FoxMapper cache if available, otherwise runs FoxMapperService for comprehensive analysis
// Filters results to only show capabilities relevant to the current identity and their groups
func (m *WhoAmIModule) identifyLateralMoveCapabilities(ctx context.Context, logger internal.Logger) {
	// Build set of principals to filter for (current identity + groups)
	relevantPrincipals := make(map[string]bool)
	relevantPrincipals[m.Identity.Email] = true
	relevantPrincipals[strings.ToLower(m.Identity.Email)] = true
	if m.Identity.Type == "serviceAccount" {
		relevantPrincipals["serviceAccount:"+m.Identity.Email] = true
		relevantPrincipals["serviceAccount:"+strings.ToLower(m.Identity.Email)] = true
	} else {
		relevantPrincipals["user:"+m.Identity.Email] = true
		relevantPrincipals["user:"+strings.ToLower(m.Identity.Email)] = true
	}
	for _, group := range m.Identity.Groups {
		if group.Email != "" {
			relevantPrincipals[group.Email] = true
			relevantPrincipals[strings.ToLower(group.Email)] = true
			relevantPrincipals["group:"+group.Email] = true
			relevantPrincipals["group:"+strings.ToLower(group.Email)] = true
		}
	}
	relevantPrincipals["allUsers"] = true
	relevantPrincipals["allAuthenticatedUsers"] = true

	// Check if FoxMapper cache is available from context (e.g., from all-checks run)
	foxMapperCache := gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if foxMapperCache != nil && foxMapperCache.IsPopulated() {
		logger.InfoM("Using cached lateral data", globals.GCP_WHOAMI_MODULE_NAME)
		m.identifyLateralFromCache(foxMapperCache, relevantPrincipals)
	} else {
		// No cache available, run fresh analysis
		m.identifyLateralFromAnalysis(ctx, relevantPrincipals, logger)
	}

	if len(m.LateralMoveCapabilities) > 0 {
		logger.InfoM(fmt.Sprintf("[LATERAL] Found %d lateral movement capability(s)", len(m.LateralMoveCapabilities)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// identifyLateralFromCache extracts lateral movement capabilities from the FoxMapper cached data
func (m *WhoAmIModule) identifyLateralFromCache(foxMapperCache *gcpinternal.FoxMapperCache, relevantPrincipals map[string]bool) {
	if foxMapperCache == nil || !foxMapperCache.IsPopulated() {
		return
	}

	// Get the FoxMapper service from cache
	// Note: This currently requires accessing internal service from cache
	// For now, we'll just skip cache-based lateral detection and always run fresh analysis
	// TODO: Enhance FoxMapperCache to expose AnalyzeLateral method
}

// identifyLateralFromAnalysis runs fresh lateral movement analysis using FoxMapperService
func (m *WhoAmIModule) identifyLateralFromAnalysis(ctx context.Context, relevantPrincipals map[string]bool, logger internal.Logger) {
	// Use FoxMapperService for comprehensive lateral movement analysis
	svc := foxmapperservice.New()

	// Determine org ID or use first project
	orgID := ""
	if len(m.Identity.Organizations) > 0 {
		orgID = m.Identity.Organizations[0].OrgID
	}

	// Load FoxMapper graph data
	var err error
	if orgID != "" {
		err = svc.LoadGraph(orgID, true)
	} else if len(m.ProjectIDs) > 0 {
		err = svc.LoadGraph(m.ProjectIDs[0], false)
	} else {
		logger.InfoM("No org or project context available for FoxMapper analysis", globals.GCP_WHOAMI_MODULE_NAME)
		return
	}

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME, "Could not load FoxMapper graph data")
		return
	}

	// Store the service if not already set
	if m.FoxMapperService == nil {
		m.FoxMapperService = svc
	}

	// Run lateral movement analysis (empty string means all categories)
	findings := svc.AnalyzeLateral("")

	// Filter findings for relevant principals only
	for _, finding := range findings {
		hasRelevantPrincipal := false
		for _, principalAccess := range finding.Principals {
			// Check if this principal is relevant to the current identity
			if relevantPrincipals[principalAccess.Principal] || relevantPrincipals[strings.ToLower(principalAccess.Principal)] {
				hasRelevantPrincipal = true

				capability := LateralMoveCapability{
					ProjectID:   "", // FoxMapper doesn't track project ID per finding
					Permission:  finding.Permission,
					Category:    finding.Category,
					Description: finding.Description,
					SourceRole:  principalAccess.Principal,
					SourceScope: "via privilege escalation",
				}
				m.LateralMoveCapabilities = append(m.LateralMoveCapabilities, capability)
			}
		}

		// Store full finding for detailed playbook generation
		if hasRelevantPrincipal {
			m.FoxMapperLateralFindings = append(m.FoxMapperLateralFindings, finding)
		}
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *WhoAmIModule) initializeLootFiles() {
	// Note: whoami-context and whoami-permissions loot files removed as redundant
	// The same information is already saved to table/csv/json files

	// Extended mode loot files - these contain actionable commands
	if m.Extended {
		m.LootMap["whoami-impersonation"] = &internal.LootFile{
			Name:     "whoami-impersonation",
			Contents: "# Service Account Impersonation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap["whoami-privesc"] = &internal.LootFile{
			Name:     "whoami-privesc",
			Contents: "# Privilege Escalation Paths\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap["whoami-data-exfil"] = &internal.LootFile{
			Name:     "whoami-data-exfil",
			Contents: "# Data Exfiltration Capabilities\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap["whoami-lateral-movement"] = &internal.LootFile{
			Name:     "whoami-lateral-movement",
			Contents: "# Lateral Movement Capabilities\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		// Playbook files with detailed exploitation techniques
		m.LootMap["whoami-privesc-playbook"] = &internal.LootFile{
			Name:     "whoami-privesc-playbook",
			Contents: "",
		}
		m.LootMap["whoami-data-exfil-playbook"] = &internal.LootFile{
			Name:     "whoami-data-exfil-playbook",
			Contents: "",
		}
		m.LootMap["whoami-lateral-movement-playbook"] = &internal.LootFile{
			Name:     "whoami-lateral-movement-playbook",
			Contents: "",
		}
	}
}

func (m *WhoAmIModule) generateLoot() {
	// Note: Context and permissions info is already saved to table/csv/json files
	// Only generate loot files for extended mode (actionable commands)

	// Extended mode loot
	if m.Extended {
		// Impersonation loot
		for _, target := range m.ImpersonationTargets {
			m.LootMap["whoami-impersonation"].Contents += fmt.Sprintf(
				"# Service Account: %s\n"+
					"# Project: %s\n",
				target.ServiceAccount,
				target.ProjectID,
			)
			if target.CanImpersonate {
				m.LootMap["whoami-impersonation"].Contents += fmt.Sprintf(
					"gcloud auth print-access-token --impersonate-service-account=%s\n",
					target.ServiceAccount,
				)
			}
			if target.CanCreateKeys {
				m.LootMap["whoami-impersonation"].Contents += fmt.Sprintf(
					"gcloud iam service-accounts keys create key.json --iam-account=%s\n",
					target.ServiceAccount,
				)
			}
			m.LootMap["whoami-impersonation"].Contents += "\n"
		}

		// Privilege escalation loot
		for _, path := range m.PrivEscPaths {
			confidenceNote := ""
			if path.Confidence == "potential" {
				confidenceNote = "# NOTE: This is a POTENTIAL path based on role name. Actual exploitation depends on resource configuration.\n"
			}
			m.LootMap["whoami-privesc"].Contents += fmt.Sprintf(
				"## %s\n"+
					"# %s\n"+
					"# Source: %s at %s\n"+
					"# Confidence: %s\n"+
					"# Required permissions: %s\n"+
					"%s"+
					"%s\n\n",
				path.Permission,
				path.Description,
				path.SourceRole,
				path.SourceScope,
				path.Confidence,
				path.RequiredPerms,
				confidenceNote,
				path.Command,
			)
		}

		// Data exfiltration capabilities loot
		for _, cap := range m.DataExfilCapabilities {
			exfilCmd := generateExfilCommand(cap.Permission, cap.Category)
			m.LootMap["whoami-data-exfil"].Contents += fmt.Sprintf(
				"## %s\n"+
					"# Category: %s\n"+
					"# Description: %s\n"+
					"# Source Role: %s\n"+
					"# Source Scope: %s\n"+
					"%s\n\n",
				cap.Permission,
				cap.Category,
				cap.Description,
				cap.SourceRole,
				cap.SourceScope,
				exfilCmd,
			)
		}

		// Lateral movement capabilities loot
		for _, cap := range m.LateralMoveCapabilities {
			lateralCmd := generateLateralCommand(cap.Permission, cap.Category)
			m.LootMap["whoami-lateral-movement"].Contents += fmt.Sprintf(
				"## %s\n"+
					"# Category: %s\n"+
					"# Description: %s\n"+
					"# Source Role: %s\n"+
					"# Source Scope: %s\n"+
					"%s\n\n",
				cap.Permission,
				cap.Category,
				cap.Description,
				cap.SourceRole,
				cap.SourceScope,
				lateralCmd,
			)
		}

		// Generate playbooks based on FoxMapper findings
		m.generatePlaybooks()
	}
}

// generatePlaybooks creates detailed playbooks based on FoxMapper findings
// Uses the same visual path style as the foxmapper module
func (m *WhoAmIModule) generatePlaybooks() {
	// Privilege escalation playbook with detailed paths
	m.LootMap["whoami-privesc-playbook"].Contents = m.generatePrivescPlaybook()

	// Data exfiltration playbook
	m.LootMap["whoami-data-exfil-playbook"].Contents = m.generateDataExfilPlaybook()

	// Lateral movement playbook
	m.LootMap["whoami-lateral-movement-playbook"].Contents = m.generateLateralPlaybook()
}

// generatePrivescPlaybook creates a detailed privesc playbook with FoxMapper path visualization
func (m *WhoAmIModule) generatePrivescPlaybook() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Privilege Escalation Playbook for %s\n\n", m.Identity.Email))
	sb.WriteString("This playbook contains privilege escalation paths identified by FoxMapper analysis.\n")
	sb.WriteString("Paths show the escalation chain from your current identity to admin principals.\n\n")

	// Summary
	sb.WriteString("================================================================================\n")
	sb.WriteString("SUMMARY\n")
	sb.WriteString("================================================================================\n\n")
	sb.WriteString(fmt.Sprintf("Identity: %s (%s)\n", m.Identity.Email, m.Identity.Type))
	sb.WriteString(fmt.Sprintf("Findings with escalation paths: %d\n", len(m.FoxMapperPrivescFindings)))

	// Count total paths and by level
	totalPaths := 0
	orgPaths := 0
	folderPaths := 0
	projectPaths := 0
	for _, finding := range m.FoxMapperPrivescFindings {
		totalPaths += len(finding.Paths)
		orgPaths += finding.PathsToOrgAdmin
		folderPaths += finding.PathsToFolderAdmin
		projectPaths += finding.PathsToProjectAdmin
	}
	sb.WriteString(fmt.Sprintf("Total escalation paths: %d\n", totalPaths))
	if orgPaths > 0 {
		sb.WriteString(fmt.Sprintf("  → Paths to Org Admin: %d\n", orgPaths))
	}
	if folderPaths > 0 {
		sb.WriteString(fmt.Sprintf("  → Paths to Folder Admin: %d\n", folderPaths))
	}
	if projectPaths > 0 {
		sb.WriteString(fmt.Sprintf("  → Paths to Project Admin: %d\n", projectPaths))
	}
	sb.WriteString("\n")

	// If we have FoxMapper service and findings, show detailed paths
	if m.FoxMapperService != nil && len(m.FoxMapperPrivescFindings) > 0 {
		for _, finding := range m.FoxMapperPrivescFindings {
			if len(finding.Paths) == 0 {
				continue
			}

			sb.WriteString("================================================================================\n")
			sb.WriteString(fmt.Sprintf("SOURCE: %s (%s)\n", finding.Principal, finding.MemberType))
			sb.WriteString(fmt.Sprintf("Highest reachable: %s admin\n", finding.HighestAdminLevel))
			sb.WriteString(fmt.Sprintf("Escalation paths: %d (viable: %d, scope-blocked: %d)\n",
				len(finding.Paths), finding.ViablePathCount, finding.ScopeBlockedCount))
			sb.WriteString("================================================================================\n\n")

			for pathIdx, path := range finding.Paths {
				scopeStatus := ""
				if path.ScopeBlocked {
					scopeStatus = " [SCOPE-BLOCKED]"
				}
				confidenceStatus := ""
				if path.Confidence != "" && path.Confidence != "high" {
					confidenceStatus = fmt.Sprintf(" [%s confidence]", path.Confidence)
				}

				sb.WriteString(fmt.Sprintf("--- Path %d: %s → %s (%s admin, %d hops)%s%s ---\n\n",
					pathIdx+1, path.Source, path.Destination, path.AdminLevel, path.HopCount, scopeStatus, confidenceStatus))

				// Show the path as a visual chain
				sb.WriteString(fmt.Sprintf("  %s\n", path.Source))
				for i, edge := range path.Edges {
					sb.WriteString("    │\n")

					annotations := ""
					if edge.ScopeBlocksEscalation {
						annotations = " ⚠️  BLOCKED BY OAUTH SCOPE"
					} else if edge.ScopeLimited {
						annotations = " ⚠️  scope-limited"
					}
					edgeConf := edge.EffectiveConfidence()
					if edgeConf != "high" {
						annotations += fmt.Sprintf(" [%s confidence]", edgeConf)
					}

					sb.WriteString(fmt.Sprintf("    ├── [%d] %s%s\n", i+1, edge.ShortReason, annotations))

					if edge.Resource != "" {
						sb.WriteString(fmt.Sprintf("    │       Resource: %s\n", edge.Resource))
					}

					if edge.Reason != "" && edge.Reason != edge.ShortReason {
						reason := edge.Reason
						if len(reason) > 80 {
							sb.WriteString(fmt.Sprintf("    │       %s\n", reason[:80]))
							sb.WriteString(fmt.Sprintf("    │       %s\n", reason[80:]))
						} else {
							sb.WriteString(fmt.Sprintf("    │       %s\n", reason))
						}
					}

					if i < len(path.Edges)-1 {
						sb.WriteString("    │\n")
						sb.WriteString("    ▼\n")
						sb.WriteString(fmt.Sprintf("  %s\n", edge.Destination))
					} else {
						sb.WriteString("    │\n")
						sb.WriteString(fmt.Sprintf("    └──▶ %s (ADMIN)\n", edge.Destination))
					}
				}
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		}
	} else if len(m.PrivEscPaths) > 0 {
		// Fallback to simplified output if no FoxMapper findings
		sb.WriteString("================================================================================\n")
		sb.WriteString("ESCALATION PATHS (Summary)\n")
		sb.WriteString("================================================================================\n\n")

		for i, path := range m.PrivEscPaths {
			sb.WriteString(fmt.Sprintf("### Path %d: %s\n\n", i+1, path.Category))
			sb.WriteString(fmt.Sprintf("- Permission: %s\n", path.Permission))
			sb.WriteString(fmt.Sprintf("- Description: %s\n", path.Description))
			sb.WriteString(fmt.Sprintf("- Source: %s at %s\n", path.SourceRole, path.SourceScope))
			sb.WriteString(fmt.Sprintf("- Confidence: %s\n\n", path.Confidence))
			if path.Command != "" {
				sb.WriteString(fmt.Sprintf("```bash\n%s\n```\n\n", path.Command))
			}
		}
	}

	// Add impersonation targets section if we have any
	if len(m.ImpersonationTargets) > 0 {
		sb.WriteString("================================================================================\n")
		sb.WriteString("IMPERSONATION TARGETS (Verified via IAM Policy)\n")
		sb.WriteString("================================================================================\n\n")

		for _, target := range m.ImpersonationTargets {
			sb.WriteString(fmt.Sprintf("Service Account: %s\n", target.ServiceAccount))
			sb.WriteString(fmt.Sprintf("Project: %s\n", target.ProjectID))
			if target.CanImpersonate {
				sb.WriteString("  ✓ Can generate access tokens\n")
				sb.WriteString(fmt.Sprintf("    gcloud auth print-access-token --impersonate-service-account=%s\n", target.ServiceAccount))
			}
			if target.CanCreateKeys {
				sb.WriteString("  ✓ Can create service account keys\n")
				sb.WriteString(fmt.Sprintf("    gcloud iam service-accounts keys create key.json --iam-account=%s\n", target.ServiceAccount))
			}
			if target.CanActAs {
				sb.WriteString("  ✓ Can act as (use with compute, functions, etc.)\n")
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// generateDataExfilPlaybook creates a detailed data exfil playbook
func (m *WhoAmIModule) generateDataExfilPlaybook() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Data Exfiltration Playbook for %s\n\n", m.Identity.Email))
	sb.WriteString("This playbook contains data exfiltration capabilities identified by FoxMapper analysis.\n\n")

	// Summary
	sb.WriteString("================================================================================\n")
	sb.WriteString("SUMMARY\n")
	sb.WriteString("================================================================================\n\n")
	sb.WriteString(fmt.Sprintf("Identity: %s (%s)\n", m.Identity.Email, m.Identity.Type))
	sb.WriteString(fmt.Sprintf("Exfiltration techniques: %d\n", len(m.FoxMapperDataExfilFindings)))
	sb.WriteString(fmt.Sprintf("Total capabilities: %d\n\n", len(m.DataExfilCapabilities)))

	// Group by service
	if len(m.FoxMapperDataExfilFindings) > 0 {
		sb.WriteString("================================================================================\n")
		sb.WriteString("DATA EXFILTRATION TECHNIQUES\n")
		sb.WriteString("================================================================================\n\n")

		for _, finding := range m.FoxMapperDataExfilFindings {
			sb.WriteString(fmt.Sprintf("--- %s: %s ---\n\n", strings.ToUpper(finding.Service), finding.Technique))
			sb.WriteString(fmt.Sprintf("Permission: %s\n", finding.Permission))
			sb.WriteString(fmt.Sprintf("Description: %s\n\n", finding.Description))

			sb.WriteString("Principals with access:\n")
			for _, principal := range finding.Principals {
				adminStatus := ""
				if principal.IsAdmin {
					adminStatus = " (Admin)"
				}
				sb.WriteString(fmt.Sprintf("  • %s%s\n", principal.Principal, adminStatus))
			}
			sb.WriteString("\n")

			sb.WriteString("Exploitation:\n")
			sb.WriteString(fmt.Sprintf("  %s\n\n", finding.Exploitation))
		}
	} else if len(m.DataExfilCapabilities) > 0 {
		// Fallback
		sb.WriteString("================================================================================\n")
		sb.WriteString("CAPABILITIES\n")
		sb.WriteString("================================================================================\n\n")

		for i, cap := range m.DataExfilCapabilities {
			sb.WriteString(fmt.Sprintf("### Capability %d: %s\n\n", i+1, cap.Category))
			sb.WriteString(fmt.Sprintf("- Permission: %s\n", cap.Permission))
			sb.WriteString(fmt.Sprintf("- Description: %s\n", cap.Description))
			sb.WriteString(fmt.Sprintf("- Source: %s at %s\n\n", cap.SourceRole, cap.SourceScope))
			exfilCmd := generateExfilCommand(cap.Permission, cap.Category)
			if exfilCmd != "" {
				sb.WriteString(fmt.Sprintf("```bash\n%s\n```\n\n", exfilCmd))
			}
		}
	}

	return sb.String()
}

// generateLateralPlaybook creates a detailed lateral movement playbook
func (m *WhoAmIModule) generateLateralPlaybook() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Lateral Movement Playbook for %s\n\n", m.Identity.Email))
	sb.WriteString("This playbook contains lateral movement capabilities identified by FoxMapper analysis.\n\n")

	// Summary
	sb.WriteString("================================================================================\n")
	sb.WriteString("SUMMARY\n")
	sb.WriteString("================================================================================\n\n")
	sb.WriteString(fmt.Sprintf("Identity: %s (%s)\n", m.Identity.Email, m.Identity.Type))
	sb.WriteString(fmt.Sprintf("Lateral movement techniques: %d\n", len(m.FoxMapperLateralFindings)))
	sb.WriteString(fmt.Sprintf("Total capabilities: %d\n\n", len(m.LateralMoveCapabilities)))

	// Group by category
	if len(m.FoxMapperLateralFindings) > 0 {
		sb.WriteString("================================================================================\n")
		sb.WriteString("LATERAL MOVEMENT TECHNIQUES\n")
		sb.WriteString("================================================================================\n\n")

		// Group by category
		categories := make(map[string][]foxmapperservice.LateralFinding)
		for _, finding := range m.FoxMapperLateralFindings {
			categories[finding.Category] = append(categories[finding.Category], finding)
		}

		for category, findings := range categories {
			sb.WriteString(fmt.Sprintf("=== %s ===\n\n", strings.ToUpper(strings.ReplaceAll(category, "_", " "))))

			for _, finding := range findings {
				sb.WriteString(fmt.Sprintf("--- %s ---\n\n", finding.Technique))
				sb.WriteString(fmt.Sprintf("Permission: %s\n", finding.Permission))
				sb.WriteString(fmt.Sprintf("Description: %s\n\n", finding.Description))

				sb.WriteString("Principals with access:\n")
				for _, principal := range finding.Principals {
					adminStatus := ""
					if principal.IsAdmin {
						adminStatus = " (Admin)"
					}
					sb.WriteString(fmt.Sprintf("  • %s%s\n", principal.Principal, adminStatus))
				}
				sb.WriteString("\n")

				sb.WriteString("Exploitation:\n")
				sb.WriteString(fmt.Sprintf("  %s\n\n", finding.Exploitation))
			}
		}
	} else if len(m.LateralMoveCapabilities) > 0 {
		// Fallback
		sb.WriteString("================================================================================\n")
		sb.WriteString("CAPABILITIES\n")
		sb.WriteString("================================================================================\n\n")

		for i, cap := range m.LateralMoveCapabilities {
			sb.WriteString(fmt.Sprintf("### Capability %d: %s\n\n", i+1, cap.Category))
			sb.WriteString(fmt.Sprintf("- Permission: %s\n", cap.Permission))
			sb.WriteString(fmt.Sprintf("- Description: %s\n", cap.Description))
			sb.WriteString(fmt.Sprintf("- Source: %s at %s\n\n", cap.SourceRole, cap.SourceScope))
			lateralCmd := generateLateralCommand(cap.Permission, cap.Category)
			if lateralCmd != "" {
				sb.WriteString(fmt.Sprintf("```bash\n%s\n```\n\n", lateralCmd))
			}
		}
	}

	return sb.String()
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *WhoAmIModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Determine output mode based on hierarchy availability
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *WhoAmIModule) buildTables() []internal.TableFile {
	// Identity table
	identityHeader := []string{
		"Property",
		"Value",
	}

	identityBody := [][]string{
		{"Email", m.Identity.Email},
		{"Type", m.Identity.Type},
	}

	// Add project details (expanded)
	for i, proj := range m.Identity.Projects {
		label := "Project"
		if len(m.Identity.Projects) > 1 {
			label = fmt.Sprintf("Project %d", i+1)
		}
		if proj.DisplayName != "" {
			identityBody = append(identityBody, []string{label, fmt.Sprintf("%s (%s)", proj.DisplayName, proj.ProjectID)})
		} else {
			identityBody = append(identityBody, []string{label, proj.ProjectID})
		}
	}
	if len(m.Identity.Projects) == 0 {
		identityBody = append(identityBody, []string{"Projects", "0"})
	}

	// Add organization details (expanded)
	for i, org := range m.Identity.Organizations {
		label := "Organization"
		if len(m.Identity.Organizations) > 1 {
			label = fmt.Sprintf("Organization %d", i+1)
		}
		if org.DisplayName != "" {
			identityBody = append(identityBody, []string{label, fmt.Sprintf("%s (%s)", org.DisplayName, org.OrgID)})
		} else {
			identityBody = append(identityBody, []string{label, org.OrgID})
		}
	}
	if len(m.Identity.Organizations) == 0 {
		identityBody = append(identityBody, []string{"Organizations", "0"})
	}

	// Add folder details (expanded)
	for i, folder := range m.Identity.Folders {
		label := "Folder"
		if len(m.Identity.Folders) > 1 {
			label = fmt.Sprintf("Folder %d", i+1)
		}
		folderID := strings.TrimPrefix(folder.Name, "folders/")
		if folder.DisplayName != "" {
			identityBody = append(identityBody, []string{label, fmt.Sprintf("%s (%s)", folder.DisplayName, folderID)})
		} else {
			identityBody = append(identityBody, []string{label, folderID})
		}
	}
	if len(m.Identity.Folders) == 0 {
		identityBody = append(identityBody, []string{"Folders", "0"})
	}

	// Add group membership details (expanded)
	for i, group := range m.Identity.Groups {
		label := "Group"
		if len(m.Identity.Groups) > 1 {
			label = fmt.Sprintf("Group %d", i+1)
		}

		// Build display value with source indicator
		var displayValue string
		if group.DisplayName != "" && group.Email != "" {
			displayValue = fmt.Sprintf("%s (%s)", group.DisplayName, group.Email)
		} else if group.Email != "" {
			displayValue = group.Email
		} else if group.DisplayName != "" {
			displayValue = group.DisplayName
		} else {
			displayValue = group.GroupID
		}

		// Add source indicator
		if group.Source == "provided" {
			displayValue += " (provided)"
		} else if group.Source == "enumerated" && m.Identity.GroupsMismatch {
			displayValue += " (enumerated)"
		}

		identityBody = append(identityBody, []string{label, displayValue})
	}
	if len(m.Identity.Groups) == 0 {
		if m.Identity.GroupsEnumerated {
			identityBody = append(identityBody, []string{"Groups", "0"})
		} else {
			identityBody = append(identityBody, []string{"Groups", "Unknown (permission denied)"})
		}
	}

	// Add role binding details (expanded)
	for i, rb := range m.RoleBindings {
		label := "Role Binding"
		if len(m.RoleBindings) > 1 {
			label = fmt.Sprintf("Role Binding %d", i+1)
		}
		// Format: Role -> Scope (ScopeID)
		scopeDisplay := rb.ScopeID
		if rb.ScopeName != "" {
			scopeDisplay = fmt.Sprintf("%s (%s)", rb.ScopeName, rb.ScopeID)
		}

		// Build source/inheritance info
		sourceStr := ""
		if rb.InheritedFrom != "" && rb.InheritedFrom != "direct" {
			if strings.HasPrefix(rb.InheritedFrom, "group:") {
				// Group-based binding
				sourceStr = fmt.Sprintf(" [via %s]", rb.InheritedFrom)
			} else {
				// Inherited from parent resource (folder/org)
				sourceStr = fmt.Sprintf(" [inherited from %s]", rb.InheritedFrom)
			}
		} else if rb.InheritedFrom == "direct" {
			sourceStr = " [direct]"
		}

		identityBody = append(identityBody, []string{label, fmt.Sprintf("%s on %s/%s%s", rb.Role, rb.Scope, scopeDisplay, sourceStr)})
	}
	if len(m.RoleBindings) == 0 {
		identityBody = append(identityBody, []string{"Role Bindings", "0"})
	}

	// Add extended info to identity table
	if m.Extended {
		identityBody = append(identityBody, []string{"Impersonation Targets", fmt.Sprintf("%d", len(m.ImpersonationTargets))})
		identityBody = append(identityBody, []string{"Privilege Escalation Paths", fmt.Sprintf("%d", len(m.PrivEscPaths))})
		identityBody = append(identityBody, []string{"Lateral Movement Paths", fmt.Sprintf("%d", len(m.LateralMoveCapabilities))})
		identityBody = append(identityBody, []string{"Data Exfiltration Paths", fmt.Sprintf("%d", len(m.DataExfilCapabilities))})
	}

	// Role bindings table
	rolesHeader := []string{
		"Role",
		"Scope",
		"Scope ID",
		"Source",
	}

	var rolesBody [][]string
	for _, rb := range m.RoleBindings {
		source := rb.InheritedFrom
		if source == "" {
			source = "direct"
		}
		rolesBody = append(rolesBody, []string{
			rb.Role,
			rb.Scope,
			rb.ScopeID,
			source,
		})
	}

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "whoami-identity",
			Header: identityHeader,
			Body:   identityBody,
		},
	}

	if len(rolesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "whoami-roles",
			Header: rolesHeader,
			Body:   rolesBody,
		})
	}

	// Extended mode tables
	if m.Extended {
		// Impersonation targets table
		if len(m.ImpersonationTargets) > 0 {
			impersonationHeader := []string{
				"Service Account",
				"Project",
				"Can Impersonate",
				"Can Create Keys",
				"Can ActAs",
			}

			var impersonationBody [][]string
			for _, target := range m.ImpersonationTargets {
				impersonationBody = append(impersonationBody, []string{
					target.ServiceAccount,
					target.ProjectID,
					shared.BoolToYesNo(target.CanImpersonate),
					shared.BoolToYesNo(target.CanCreateKeys),
					shared.BoolToYesNo(target.CanActAs),
				})
			}

			tables = append(tables, internal.TableFile{
				Name:   "whoami-impersonation",
				Header: impersonationHeader,
				Body:   impersonationBody,
			})
		}

		// Combined attack paths table (privesc, data exfil, lateral movement)
		totalPaths := len(m.PrivEscPaths) + len(m.DataExfilCapabilities) + len(m.LateralMoveCapabilities)
		if totalPaths > 0 {
			attackPathsHeader := []string{
				"Type",
				"Source Scope",
				"Source Role",
				"Permission",
				"Category",
				"Description",
			}

			var attackPathsBody [][]string

			// Add privilege escalation paths
			for _, path := range m.PrivEscPaths {
				attackPathsBody = append(attackPathsBody, []string{
					"Privesc",
					path.SourceScope,
					path.SourceRole,
					path.Permission,
					path.Category,
					path.Description,
				})
			}

			// Add data exfiltration capabilities
			for _, cap := range m.DataExfilCapabilities {
				attackPathsBody = append(attackPathsBody, []string{
					"Exfil",
					cap.SourceScope,
					cap.SourceRole,
					cap.Permission,
					cap.Category,
					cap.Description,
				})
			}

			// Add lateral movement capabilities
			for _, cap := range m.LateralMoveCapabilities {
				attackPathsBody = append(attackPathsBody, []string{
					"Lateral",
					cap.SourceScope,
					cap.SourceRole,
					cap.Permission,
					cap.Category,
					cap.Description,
				})
			}

			tables = append(tables, internal.TableFile{
				Name:   "whoami-attack-paths",
				Header: attackPathsHeader,
				Body:   attackPathsBody,
			})
		}
	}

	return tables
}

func (m *WhoAmIModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		// Include loot files that have content beyond the header comments
		// Headers end with "# WARNING: Only use with proper authorization\n\n"
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *WhoAmIModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// For whoami, output at org level since it's account-level data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := WhoAmIOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output location - prefer org-level, fall back to project-level
	orgID := ""
	if len(m.Identity.Organizations) > 0 {
		orgID = m.Identity.Organizations[0].OrgID
	} else if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	if orgID != "" {
		// Place at org level
		outputData.OrgLevelData[orgID] = output
	} else if len(m.ProjectIDs) > 0 {
		// Fall back to first project level if no org discovered
		outputData.ProjectLevelData[m.ProjectIDs[0]] = output
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_WHOAMI_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *WhoAmIModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := WhoAmIOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Write output
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_WHOAMI_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

