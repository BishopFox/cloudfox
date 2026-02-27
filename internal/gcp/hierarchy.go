package gcpinternal

import (
	"path/filepath"
	"regexp"
	"strings"
)

// ------------------------------
// Scope Hierarchy Types
// ------------------------------

// ScopeHierarchy represents the discovered GCP resource hierarchy
type ScopeHierarchy struct {
	Organizations   []OrgScope     // Organizations (may be empty if no org access)
	Folders         []FolderScope  // Folders (may be empty)
	Projects        []ProjectScope // All projects being processed
	StandaloneProjs []string       // Project IDs not belonging to any known org
}

// OrgScope represents an organization in the hierarchy
type OrgScope struct {
	ID          string   // Numeric org ID (e.g., "672370982061")
	DisplayName string   // Org display name (e.g., "acme.com") - may be empty if inaccessible
	Accessible  bool     // Whether we can enumerate org-level resources
	FolderIDs   []string // Folder IDs directly under this org
	ProjectIDs  []string // Project IDs under this org (directly or via folders)
}

// FolderScope represents a folder in the hierarchy
type FolderScope struct {
	ID          string   // Folder ID
	DisplayName string   // Folder display name
	ParentType  string   // "organization" or "folder"
	ParentID    string   // Parent org or folder ID
	ProjectIDs  []string // Project IDs directly under this folder
	Depth       int      // Depth in hierarchy (0 = direct child of org)
}

// ProjectScope represents a project in the hierarchy
type ProjectScope struct {
	ID       string // Project ID
	Name     string // Project display name
	OrgID    string // Parent org ID (empty if standalone/unknown)
	FolderID string // Direct parent folder ID (empty if directly under org)
}

// ------------------------------
// Ancestry Node (for building hierarchy)
// ------------------------------

// AncestryNode represents a node in the resource hierarchy ancestry
type AncestryNode struct {
	Type        string // organization, folder, project
	ID          string
	DisplayName string
	Parent      string
	Depth       int
}

// OrganizationData represents organization info for hierarchy building
type OrganizationData struct {
	Name        string // organizations/ORGID
	DisplayName string
}

// ------------------------------
// Hierarchy Builder Interface
// ------------------------------

// HierarchyDataProvider interface allows fetching hierarchy data without import cycles
type HierarchyDataProvider interface {
	GetProjectAncestry(projectID string) ([]AncestryNode, error)
	SearchOrganizations() ([]OrganizationData, error)
}

// ------------------------------
// Hierarchy Detection
// ------------------------------

// BuildScopeHierarchy analyzes the given projects and discovers their organizational hierarchy.
// It uses the provided HierarchyDataProvider to fetch data without import cycles.
// It attempts to:
// 1. Get org ID from project ancestry for each project
// 2. Get org display names (requires org-level permissions)
// 3. Get folder information (from ancestry data)
// 4. Identify standalone projects (no org association)
func BuildScopeHierarchy(projectIDs []string, provider HierarchyDataProvider) (*ScopeHierarchy, error) {
	hierarchy := &ScopeHierarchy{
		Organizations:   []OrgScope{},
		Folders:         []FolderScope{},
		Projects:        []ProjectScope{},
		StandaloneProjs: []string{},
	}

	if len(projectIDs) == 0 {
		return hierarchy, nil
	}

	// Maps to track relationships
	orgProjects := make(map[string][]string)   // orgID -> projectIDs
	projectToOrg := make(map[string]string)    // projectID -> orgID
	projectToFolder := make(map[string]string) // projectID -> folderID
	folderToOrg := make(map[string]string)     // folderID -> orgID
	folderInfo := make(map[string]FolderScope) // folderID -> FolderScope
	projectNames := make(map[string]string)    // projectID -> displayName

	// Step 1: Get project ancestry for each project to discover org/folder relationships
	for _, projectID := range projectIDs {
		ancestry, err := provider.GetProjectAncestry(projectID)
		if err != nil {
			// Can't get ancestry - mark as standalone for now
			hierarchy.StandaloneProjs = append(hierarchy.StandaloneProjs, projectID)
			continue
		}

		// If ancestry is empty, mark as standalone
		if len(ancestry) == 0 {
			hierarchy.StandaloneProjs = append(hierarchy.StandaloneProjs, projectID)
			continue
		}

		// Parse ancestry to find org and folder
		// Note: ancestry is ordered from org -> folder(s) -> project
		var foundOrg, foundFolder string
		var lastFolderID string
		for _, node := range ancestry {
			switch node.Type {
			case "organization":
				foundOrg = node.ID
			case "folder":
				lastFolderID = node.ID
				folderToOrg[node.ID] = foundOrg
				if _, exists := folderInfo[node.ID]; !exists {
					folderInfo[node.ID] = FolderScope{
						ID:          node.ID,
						DisplayName: node.DisplayName,
						ParentType:  node.Type,
						ParentID:    "", // Will be filled later
						Depth:       node.Depth,
					}
				}
			case "project":
				projectNames[node.ID] = node.DisplayName
				// The folder directly containing this project is the last folder we saw
				if lastFolderID != "" {
					foundFolder = lastFolderID
				}
			}
		}

		if foundOrg != "" {
			projectToOrg[projectID] = foundOrg
			orgProjects[foundOrg] = append(orgProjects[foundOrg], projectID)
		} else {
			hierarchy.StandaloneProjs = append(hierarchy.StandaloneProjs, projectID)
		}

		if foundFolder != "" {
			projectToFolder[projectID] = foundFolder
		}
	}

	// Step 2: Try to get org display names (requires resourcemanager.organizations.get)
	orgDisplayNames := make(map[string]string)
	orgAccessible := make(map[string]bool)

	orgs, err := provider.SearchOrganizations()
	if err == nil {
		for _, org := range orgs {
			orgID := strings.TrimPrefix(org.Name, "organizations/")
			orgDisplayNames[orgID] = org.DisplayName
			orgAccessible[orgID] = true
		}
	}

	// Step 3: Build organization scopes
	for orgID, projIDs := range orgProjects {
		orgScope := OrgScope{
			ID:          orgID,
			DisplayName: orgDisplayNames[orgID], // May be empty
			Accessible:  orgAccessible[orgID],
			ProjectIDs:  projIDs,
			FolderIDs:   []string{},
		}

		// Collect folders for this org
		for folderID, fOrgID := range folderToOrg {
			if fOrgID == orgID {
				orgScope.FolderIDs = append(orgScope.FolderIDs, folderID)
			}
		}

		hierarchy.Organizations = append(hierarchy.Organizations, orgScope)
	}

	// Step 4: Build folder scopes
	for folderID, fScope := range folderInfo {
		// Find projects directly under this folder
		for projID, fID := range projectToFolder {
			if fID == folderID {
				fScope.ProjectIDs = append(fScope.ProjectIDs, projID)
			}
		}
		hierarchy.Folders = append(hierarchy.Folders, fScope)
	}

	// Step 5: Build project scopes
	for _, projectID := range projectIDs {
		pScope := ProjectScope{
			ID:       projectID,
			Name:     projectNames[projectID],
			OrgID:    projectToOrg[projectID],
			FolderID: projectToFolder[projectID],
		}
		if pScope.Name == "" {
			pScope.Name = projectID // Fallback to ID
		}
		hierarchy.Projects = append(hierarchy.Projects, pScope)
	}

	return hierarchy, nil
}

// ------------------------------
// Path Building Functions
// ------------------------------

// GetOrgIdentifier returns the best identifier for an org (display name or ID)
func (h *ScopeHierarchy) GetOrgIdentifier(orgID string) string {
	for _, org := range h.Organizations {
		if org.ID == orgID {
			if org.DisplayName != "" {
				return org.DisplayName
			}
			return org.ID
		}
	}
	return orgID
}

// GetProjectOrg returns the org ID for a project, or empty string if standalone
func (h *ScopeHierarchy) GetProjectOrg(projectID string) string {
	for _, proj := range h.Projects {
		if proj.ID == projectID {
			return proj.OrgID
		}
	}
	return ""
}

// GetProjectName returns the display name for a project
func (h *ScopeHierarchy) GetProjectName(projectID string) string {
	for _, proj := range h.Projects {
		if proj.ID == projectID {
			if proj.Name != "" {
				return proj.Name
			}
			return proj.ID
		}
	}
	return projectID
}

// IsStandalone returns true if the project has no org association
func (h *ScopeHierarchy) IsStandalone(projectID string) bool {
	for _, standaloneID := range h.StandaloneProjs {
		if standaloneID == projectID {
			return true
		}
	}
	return false
}

// HasOrgAccess returns true if at least one org is accessible
func (h *ScopeHierarchy) HasOrgAccess() bool {
	for _, org := range h.Organizations {
		if org.Accessible {
			return true
		}
	}
	return false
}

// ------------------------------
// Output Path Builder
// ------------------------------

// sanitizePathComponent removes or replaces invalid characters for directory names
func sanitizePathComponent(name string) string {
	// Replace characters invalid on Windows/Linux
	re := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	sanitized := re.ReplaceAllString(name, "_")

	// Trim spaces and dots from ends (Windows restriction)
	sanitized = strings.TrimRight(sanitized, ". ")
	sanitized = strings.TrimLeft(sanitized, ". ")

	// Limit length
	if len(sanitized) > 100 {
		sanitized = sanitized[:100]
	}

	if sanitized == "" {
		sanitized = "unknown"
	}

	return sanitized
}

// BuildHierarchicalPath constructs the output path for hierarchical output.
// Parameters:
//   - baseDir: Base output directory (e.g., ~/.cloudfox/cloudfox-output)
//   - principal: Authenticated account email
//   - hierarchy: The detected scope hierarchy
//   - scopeType: "organization", "folder", or "project"
//   - scopeID: The ID of the scope (orgID, folderID, or projectID)
//
// Returns paths like:
//   - Org level: baseDir/cloudfox-output/gcp/principal/[O]org-name/
//   - Folder level: baseDir/cloudfox-output/gcp/principal/[O]org-name/[F]folder-name/
//   - Project under org: baseDir/cloudfox-output/gcp/principal/[O]org-name/[P]project-name/
//   - Project under folder: baseDir/cloudfox-output/gcp/principal/[O]org-name/[F]folder/[P]project/
//   - Standalone project: baseDir/cloudfox-output/gcp/principal/[P]project-name/
func BuildHierarchicalPath(
	baseDir string,
	principal string,
	hierarchy *ScopeHierarchy,
	scopeType string,
	scopeID string,
) string {
	base := filepath.Join(baseDir, "cloudfox-output", "gcp", sanitizePathComponent(principal))

	switch scopeType {
	case "organization":
		orgName := hierarchy.GetOrgIdentifier(scopeID)
		return filepath.Join(base, "[O]"+sanitizePathComponent(orgName))

	case "folder":
		// Find the folder and its parent org
		var folder *FolderScope
		for i := range hierarchy.Folders {
			if hierarchy.Folders[i].ID == scopeID {
				folder = &hierarchy.Folders[i]
				break
			}
		}

		if folder == nil {
			// Fallback - just use folder ID
			return filepath.Join(base, "[F]"+sanitizePathComponent(scopeID))
		}

		// Get org path first
		orgID := ""
		for oID, fIDs := range getOrgFolderMap(hierarchy) {
			for _, fID := range fIDs {
				if fID == scopeID {
					orgID = oID
					break
				}
			}
		}

		if orgID != "" {
			orgName := hierarchy.GetOrgIdentifier(orgID)
			folderName := folder.DisplayName
			if folderName == "" {
				folderName = folder.ID
			}
			return filepath.Join(base, "[O]"+sanitizePathComponent(orgName), "[F]"+sanitizePathComponent(folderName))
		}

		// No org found - just folder
		folderName := folder.DisplayName
		if folderName == "" {
			folderName = folder.ID
		}
		return filepath.Join(base, "[F]"+sanitizePathComponent(folderName))

	case "project":
		projectName := hierarchy.GetProjectName(scopeID)
		orgID := hierarchy.GetProjectOrg(scopeID)

		// Standalone project
		if orgID == "" || hierarchy.IsStandalone(scopeID) {
			return filepath.Join(base, "[P]"+sanitizePathComponent(projectName))
		}

		// Project under org
		orgName := hierarchy.GetOrgIdentifier(orgID)

		// Check if project is under a folder
		var folderID string
		for _, proj := range hierarchy.Projects {
			if proj.ID == scopeID && proj.FolderID != "" {
				folderID = proj.FolderID
				break
			}
		}

		if folderID != "" {
			// Project under folder under org
			var folderName string
			for _, f := range hierarchy.Folders {
				if f.ID == folderID {
					folderName = f.DisplayName
					if folderName == "" {
						folderName = f.ID
					}
					break
				}
			}
			return filepath.Join(base, "[O]"+sanitizePathComponent(orgName), "[F]"+sanitizePathComponent(folderName), "[P]"+sanitizePathComponent(projectName))
		}

		// Project directly under org
		return filepath.Join(base, "[O]"+sanitizePathComponent(orgName), "[P]"+sanitizePathComponent(projectName))

	default:
		// Unknown scope type - use as-is
		return filepath.Join(base, sanitizePathComponent(scopeID))
	}
}

// getOrgFolderMap builds a map of orgID -> folderIDs
func getOrgFolderMap(hierarchy *ScopeHierarchy) map[string][]string {
	result := make(map[string][]string)
	for _, org := range hierarchy.Organizations {
		result[org.ID] = org.FolderIDs
	}
	return result
}

// ------------------------------
// Flat Output Path (Legacy Mode)
// ------------------------------

// BuildFlatPath constructs the legacy flat output path (for --flat-output mode)
// All data goes to a single folder based on the "highest" scope available
func BuildFlatPath(
	baseDir string,
	principal string,
	hierarchy *ScopeHierarchy,
) string {
	base := filepath.Join(baseDir, "cloudfox-output", "gcp", sanitizePathComponent(principal))

	// If we have org access, use org-level folder
	if len(hierarchy.Organizations) > 0 {
		// Use first org (or combine if multiple)
		if len(hierarchy.Organizations) == 1 {
			orgName := hierarchy.GetOrgIdentifier(hierarchy.Organizations[0].ID)
			return filepath.Join(base, "[O]"+sanitizePathComponent(orgName))
		}
		// Multiple orgs - use combined name
		orgName := hierarchy.GetOrgIdentifier(hierarchy.Organizations[0].ID)
		return filepath.Join(base, "[O]"+sanitizePathComponent(orgName)+"_and_"+
			sanitizePathComponent(string(rune(len(hierarchy.Organizations)-1)))+"_more")
	}

	// No org - use project-level
	if len(hierarchy.Projects) > 0 {
		if len(hierarchy.Projects) == 1 {
			return filepath.Join(base, "[P]"+sanitizePathComponent(hierarchy.Projects[0].Name))
		}
		// Multiple projects - use combined name
		return filepath.Join(base, "[P]"+sanitizePathComponent(hierarchy.Projects[0].Name)+
			"_and_"+sanitizePathComponent(string(rune(len(hierarchy.Projects)-1)))+"_more")
	}

	return filepath.Join(base, "unknown-scope")
}
