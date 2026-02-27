package gcpinternal

import (
	"context"
	"sync"
)

// OrgCache holds cached organization, folder, and project data
// This allows modules to access full org enumeration without re-querying
type OrgCache struct {
	// All accessible organizations
	Organizations []CachedOrganization

	// All accessible folders
	Folders []CachedFolder

	// All accessible projects (full enumeration)
	AllProjects []CachedProject

	// Quick lookups
	ProjectByID     map[string]*CachedProject
	ProjectByNumber map[string]*CachedProject
	FolderByID      map[string]*CachedFolder
	OrgByID         map[string]*CachedOrganization

	// Populated indicates whether the cache has been populated
	Populated bool

	mu sync.RWMutex
}

// CachedOrganization represents cached org info
type CachedOrganization struct {
	ID          string // Numeric org ID
	Name        string // organizations/ORGID
	DisplayName string
	DirectoryID string // Cloud Identity directory customer ID
	State       string // ACTIVE, DELETE_REQUESTED, etc.
}

// CachedFolder represents cached folder info
type CachedFolder struct {
	ID          string // Folder ID
	Name        string // folders/FOLDERID
	DisplayName string
	Parent      string // Parent org or folder
	State       string // ACTIVE, DELETE_REQUESTED, etc.
}

// CachedProject represents cached project info
type CachedProject struct {
	ID          string // Project ID (e.g. "my-project")
	Number      string // Project number (e.g. "123456789")
	Name        string // projects/PROJECT_NUMBER
	DisplayName string
	Parent      string // Parent org or folder
	State       string // ACTIVE, DELETE_REQUESTED, etc.
}

// NewOrgCache creates a new empty org cache
func NewOrgCache() *OrgCache {
	return &OrgCache{
		Organizations:   []CachedOrganization{},
		Folders:         []CachedFolder{},
		AllProjects:     []CachedProject{},
		ProjectByID:     make(map[string]*CachedProject),
		ProjectByNumber: make(map[string]*CachedProject),
		FolderByID:      make(map[string]*CachedFolder),
		OrgByID:         make(map[string]*CachedOrganization),
		Populated:       false,
	}
}

// AddOrganization adds an organization to the cache
func (c *OrgCache) AddOrganization(org CachedOrganization) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Organizations = append(c.Organizations, org)
	c.OrgByID[org.ID] = &c.Organizations[len(c.Organizations)-1]
}

// AddFolder adds a folder to the cache
func (c *OrgCache) AddFolder(folder CachedFolder) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Folders = append(c.Folders, folder)
	c.FolderByID[folder.ID] = &c.Folders[len(c.Folders)-1]
}

// AddProject adds a project to the cache
func (c *OrgCache) AddProject(project CachedProject) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.AllProjects = append(c.AllProjects, project)
	ptr := &c.AllProjects[len(c.AllProjects)-1]
	c.ProjectByID[project.ID] = ptr
	if project.Number != "" {
		c.ProjectByNumber[project.Number] = ptr
	}
}

// MarkPopulated marks the cache as populated
func (c *OrgCache) MarkPopulated() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Populated = true
}

// IsPopulated returns whether the cache has been populated
func (c *OrgCache) IsPopulated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Populated
}

// GetAllProjectIDs returns all project IDs in the cache
func (c *OrgCache) GetAllProjectIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ids := make([]string, len(c.AllProjects))
	for i, p := range c.AllProjects {
		ids[i] = p.ID
	}
	return ids
}

// GetActiveProjectIDs returns only active project IDs
func (c *OrgCache) GetActiveProjectIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var ids []string
	for _, p := range c.AllProjects {
		if p.State == "ACTIVE" {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

// GetProject returns a project by ID
func (c *OrgCache) GetProject(projectID string) *CachedProject {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ProjectByID[projectID]
}

// GetProjectIDByNumber returns the project ID for a given project number.
// Returns empty string if not found.
func (c *OrgCache) GetProjectIDByNumber(number string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if p, ok := c.ProjectByNumber[number]; ok {
		return p.ID
	}
	return ""
}

// GetFolder returns a folder by ID
func (c *OrgCache) GetFolder(folderID string) *CachedFolder {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.FolderByID[folderID]
}

// GetOrganization returns an organization by ID
func (c *OrgCache) GetOrganization(orgID string) *CachedOrganization {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.OrgByID[orgID]
}

// GetStats returns statistics about the cache
func (c *OrgCache) GetStats() (orgs, folders, projects int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Organizations), len(c.Folders), len(c.AllProjects)
}

// HasProject returns true if the project ID exists in the org cache
func (c *OrgCache) HasProject(projectID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.ProjectByID[projectID]
	return exists
}

// GetProjectScope returns the scope of a project relative to the org cache:
// - "Internal" if the project is in the cache (part of enumerated org)
// - "External" if the cache is populated but project is not in it
// - "Unknown" if the cache is not populated
func (c *OrgCache) GetProjectScope(projectID string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.Populated {
		return "Unknown"
	}

	if _, exists := c.ProjectByID[projectID]; exists {
		return "Internal"
	}
	return "External"
}

// GetProjectsInOrg returns all project IDs belonging to an organization
func (c *OrgCache) GetProjectsInOrg(orgID string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var ids []string
	orgPrefix := "organizations/" + orgID

	// Direct children of org
	for _, p := range c.AllProjects {
		if p.Parent == orgPrefix {
			ids = append(ids, p.ID)
		}
	}

	// Children of folders in this org (simplified - doesn't handle nested folders)
	for _, f := range c.Folders {
		if f.Parent == orgPrefix {
			folderPrefix := "folders/" + f.ID
			for _, p := range c.AllProjects {
				if p.Parent == folderPrefix {
					ids = append(ids, p.ID)
				}
			}
		}
	}

	return ids
}

// GetProjectAncestorFolders returns all folder IDs in the ancestry path for a project.
// This walks up from the project's parent through all nested folders.
func (c *OrgCache) GetProjectAncestorFolders(projectID string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	project := c.ProjectByID[projectID]
	if project == nil {
		return nil
	}

	var folderIDs []string
	currentParent := project.Parent

	// Walk up the folder chain
	for {
		if currentParent == "" {
			break
		}

		// Check if parent is a folder
		if len(currentParent) > 8 && currentParent[:8] == "folders/" {
			folderID := currentParent[8:]
			folderIDs = append(folderIDs, folderID)

			// Get next parent
			if folder := c.FolderByID[folderID]; folder != nil {
				currentParent = folder.Parent
			} else {
				break
			}
		} else {
			// Parent is an org or unknown, stop here
			break
		}
	}

	return folderIDs
}

// GetProjectOrgID returns the organization ID for a project.
// Returns empty string if the project is not found or has no org.
func (c *OrgCache) GetProjectOrgID(projectID string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	project := c.ProjectByID[projectID]
	if project == nil {
		return ""
	}

	currentParent := project.Parent

	// Walk up until we find an org
	for {
		if currentParent == "" {
			break
		}

		// Check if parent is an org
		if len(currentParent) > 14 && currentParent[:14] == "organizations/" {
			return currentParent[14:]
		}

		// Check if parent is a folder
		if len(currentParent) > 8 && currentParent[:8] == "folders/" {
			folderID := currentParent[8:]
			if folder := c.FolderByID[folderID]; folder != nil {
				currentParent = folder.Parent
			} else {
				break
			}
		} else {
			break
		}
	}

	return ""
}

// Context key for org cache
type orgCacheKey struct{}

// GetOrgCacheFromContext retrieves the org cache from context
func GetOrgCacheFromContext(ctx context.Context) *OrgCache {
	if cache, ok := ctx.Value(orgCacheKey{}).(*OrgCache); ok {
		return cache
	}
	return nil
}

// SetOrgCacheInContext returns a new context with the org cache
func SetOrgCacheInContext(ctx context.Context, cache *OrgCache) context.Context {
	return context.WithValue(ctx, orgCacheKey{}, cache)
}
