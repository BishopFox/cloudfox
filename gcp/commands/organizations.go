package commands

import (
	"context"
	"fmt"
	"strings"

	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPOrganizationsCommand = &cobra.Command{
	Use:     globals.GCP_ORGANIZATIONS_MODULE_NAME,
	Aliases: []string{"org", "orgs", "hierarchy"},
	Short:   "Enumerate GCP organization hierarchy",
	Long: `Enumerate GCP organization, folder, and project hierarchy.

Features:
- Lists accessible organizations
- Shows folder structure
- Maps project relationships
- Displays resource hierarchy tree
- Shows ancestry paths for projects`,
	Run: runGCPOrganizationsCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type OrganizationsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Organizations []orgsservice.OrganizationInfo
	Folders       []orgsservice.FolderInfo
	Projects      []orgsservice.ProjectInfo
	Ancestry      [][]orgsservice.HierarchyNode
	LootMap       map[string]*internal.LootFile
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type OrganizationsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o OrganizationsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o OrganizationsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPOrganizationsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ORGANIZATIONS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &OrganizationsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Organizations: []orgsservice.OrganizationInfo{},
		Folders:       []orgsservice.FolderInfo{},
		Projects:      []orgsservice.ProjectInfo{},
		Ancestry:      [][]orgsservice.HierarchyNode{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *OrganizationsModule) Execute(ctx context.Context, logger internal.Logger) {
	orgsSvc := orgsservice.New()

	// Check if org cache is available (auto-loaded at startup)
	if orgCache := gcpinternal.GetOrgCacheFromContext(ctx); orgCache != nil && orgCache.IsPopulated() {
		logger.InfoM("Using cached organization data", globals.GCP_ORGANIZATIONS_MODULE_NAME)

		// Convert cached data to module format
		for _, org := range orgCache.Organizations {
			m.Organizations = append(m.Organizations, orgsservice.OrganizationInfo{
				Name:        org.Name,
				DisplayName: org.DisplayName,
				DirectoryID: org.DirectoryID,
				State:       org.State,
			})
		}
		for _, folder := range orgCache.Folders {
			m.Folders = append(m.Folders, orgsservice.FolderInfo{
				Name:        folder.Name,
				DisplayName: folder.DisplayName,
				Parent:      folder.Parent,
				State:       folder.State,
			})
		}
		for _, project := range orgCache.AllProjects {
			m.Projects = append(m.Projects, orgsservice.ProjectInfo{
				Name:        project.Name,
				ProjectID:   project.ID,
				DisplayName: project.DisplayName,
				Parent:      project.Parent,
				State:       project.State,
			})
		}
	} else {
		// No context cache, try loading from disk cache
		diskCache, metadata, err := gcpinternal.LoadOrgCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			logger.InfoM(fmt.Sprintf("Using disk cache (created: %s, %d projects)",
				metadata.CreatedAt.Format("2006-01-02 15:04:05"), metadata.TotalProjects), globals.GCP_ORGANIZATIONS_MODULE_NAME)

			// Convert cached data to module format
			for _, org := range diskCache.Organizations {
				m.Organizations = append(m.Organizations, orgsservice.OrganizationInfo{
					Name:        org.Name,
					DisplayName: org.DisplayName,
					DirectoryID: org.DirectoryID,
					State:       org.State,
				})
			}
			for _, folder := range diskCache.Folders {
				m.Folders = append(m.Folders, orgsservice.FolderInfo{
					Name:        folder.Name,
					DisplayName: folder.DisplayName,
					Parent:      folder.Parent,
					State:       folder.State,
				})
			}
			for _, project := range diskCache.AllProjects {
				m.Projects = append(m.Projects, orgsservice.ProjectInfo{
					Name:        project.Name,
					ProjectID:   project.ID,
					DisplayName: project.DisplayName,
					Parent:      project.Parent,
					State:       project.State,
				})
			}
		} else {
			// No disk cache either, enumerate directly and save
			logger.InfoM("Enumerating organizations, folders, and projects...", globals.GCP_ORGANIZATIONS_MODULE_NAME)

			// Get organizations
			orgs, err := orgsSvc.SearchOrganizations()
			if err != nil {
				logger.InfoM(fmt.Sprintf("Could not enumerate organizations: %v", err), globals.GCP_ORGANIZATIONS_MODULE_NAME)
			} else {
				m.Organizations = orgs
			}

			// Get all folders
			folders, err := orgsSvc.SearchAllFolders()
			if err != nil {
				logger.InfoM(fmt.Sprintf("Could not enumerate folders: %v", err), globals.GCP_ORGANIZATIONS_MODULE_NAME)
			} else {
				m.Folders = folders
			}

			// Get all projects
			projects, err := orgsSvc.SearchProjects("")
			if err != nil {
				logger.InfoM(fmt.Sprintf("Could not enumerate projects: %v", err), globals.GCP_ORGANIZATIONS_MODULE_NAME)
			} else {
				m.Projects = projects
			}

			// Save to disk cache for future use
			m.saveToOrgCache(logger)
		}
	}

	// Get ancestry for each specified project
	for _, projectID := range m.ProjectIDs {
		ancestry, err := orgsSvc.GetProjectAncestry(projectID)
		if err != nil {
			logger.InfoM(fmt.Sprintf("Could not get ancestry for project %s: %v", projectID, err), globals.GCP_ORGANIZATIONS_MODULE_NAME)
		} else {
			m.Ancestry = append(m.Ancestry, ancestry)
		}
	}

	// Generate loot
	m.generateLoot()

	// Report findings
	logger.SuccessM(fmt.Sprintf("Found %d organization(s), %d folder(s), %d project(s)",
		len(m.Organizations), len(m.Folders), len(m.Projects)), globals.GCP_ORGANIZATIONS_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *OrganizationsModule) initializeLootFiles() {
	m.LootMap["org-commands"] = &internal.LootFile{
		Name:     "org-commands",
		Contents: "# GCP Organization Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["org-map"] = &internal.LootFile{
		Name:     "org-map",
		Contents: "",
	}
	m.LootMap["org-tree"] = &internal.LootFile{
		Name:     "org-tree",
		Contents: "",
	}
	m.LootMap["org-scope-hierarchy"] = &internal.LootFile{
		Name:     "org-scope-hierarchy",
		Contents: "",
	}
}

func (m *OrganizationsModule) generateLoot() {
	// Generate expandable markdown tree view (org map)
	m.generateMarkdownTreeView()

	// Generate standard ASCII tree view
	m.generateTextTreeView()

	// Generate linear hierarchy for scoped projects only
	m.generateScopeHierarchy()

	// Gcloud commands for organizations
	m.LootMap["org-commands"].Contents += "# =============================================================================\n"
	m.LootMap["org-commands"].Contents += "# ORGANIZATION COMMANDS\n"
	m.LootMap["org-commands"].Contents += "# =============================================================================\n\n"

	for _, org := range m.Organizations {
		orgID := strings.TrimPrefix(org.Name, "organizations/")
		m.LootMap["org-commands"].Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# ORGANIZATION: %s (%s)\n"+
				"# =============================================================================\n"+
				"gcloud organizations describe %s\n"+
				"gcloud organizations get-iam-policy %s\n"+
				"gcloud resource-manager folders list --organization=%s\n"+
				"gcloud projects list --filter='parent.id=%s'\n\n",
			org.DisplayName, orgID,
			orgID,
			orgID,
			orgID,
			orgID,
		)
	}

	// Gcloud commands for folders
	if len(m.Folders) > 0 {
		m.LootMap["org-commands"].Contents += "# =============================================================================\n"
		m.LootMap["org-commands"].Contents += "# FOLDER COMMANDS\n"
		m.LootMap["org-commands"].Contents += "# =============================================================================\n\n"

		for _, folder := range m.Folders {
			folderID := strings.TrimPrefix(folder.Name, "folders/")
			m.LootMap["org-commands"].Contents += fmt.Sprintf(
				"# =============================================================================\n"+
					"# FOLDER: %s (%s)\n"+
					"# =============================================================================\n"+
					"gcloud resource-manager folders describe %s\n"+
					"gcloud resource-manager folders get-iam-policy %s\n"+
					"gcloud resource-manager folders list --folder=%s\n"+
					"gcloud projects list --filter='parent.id=%s'\n\n",
				folder.DisplayName, folderID,
				folderID,
				folderID,
				folderID,
				folderID,
			)
		}
	}
}

// generateMarkdownTreeView creates a beautified expandable markdown tree of the organization hierarchy
func (m *OrganizationsModule) generateMarkdownTreeView() {
	tree := &m.LootMap["org-map"].Contents

	*tree += "# GCP Organization Hierarchy\n\n"

	for _, org := range m.Organizations {
		orgID := strings.TrimPrefix(org.Name, "organizations/")
		displayName := org.DisplayName
		if displayName == "" {
			displayName = orgID
		}

		// Get direct children (folders and projects) of this org
		childFolders := m.getChildFolders(org.Name)
		childProjects := m.getChildProjects(org.Name)

		// Start expandable section for organization
		*tree += fmt.Sprintf("<details open>\n<summary>🏢 <strong>Organization:</strong> %s (%s)</summary>\n\n", displayName, orgID)

		// Add folders as expandable sections
		for _, folder := range childFolders {
			m.addFolderToMarkdownTree(tree, folder, 1)
		}

		// Add projects directly under org
		if len(childProjects) > 0 {
			for _, proj := range childProjects {
				projDisplayName := proj.DisplayName
				if projDisplayName == "" {
					projDisplayName = proj.ProjectID
				}
				*tree += fmt.Sprintf("- 📁 **Project:** %s (`%s`)\n", projDisplayName, proj.ProjectID)
			}
			*tree += "\n"
		}

		*tree += "</details>\n\n"
	}

	// Handle standalone projects (no org parent)
	standaloneProjects := m.getStandaloneProjects()
	if len(standaloneProjects) > 0 {
		*tree += "<details>\n<summary>📦 <strong>Standalone Projects</strong> (no organization)</summary>\n\n"
		for _, proj := range standaloneProjects {
			displayName := proj.DisplayName
			if displayName == "" {
				displayName = proj.ProjectID
			}
			*tree += fmt.Sprintf("- 📁 **Project:** %s (`%s`)\n", displayName, proj.ProjectID)
		}
		*tree += "\n</details>\n"
	}
}

// addFolderToMarkdownTree recursively adds a folder and its children as expandable markdown
func (m *OrganizationsModule) addFolderToMarkdownTree(tree *string, folder orgsservice.FolderInfo, depth int) {
	folderID := strings.TrimPrefix(folder.Name, "folders/")
	displayName := folder.DisplayName
	if displayName == "" {
		displayName = folderID
	}

	// Get children of this folder
	childFolders := m.getChildFolders(folder.Name)
	childProjects := m.getChildProjects(folder.Name)

	hasChildren := len(childFolders) > 0 || len(childProjects) > 0

	if hasChildren {
		// Folder with children - make it expandable
		*tree += fmt.Sprintf("<details>\n<summary>📂 <strong>Folder:</strong> %s (%s)</summary>\n\n", displayName, folderID)

		// Add child folders
		for _, childFolder := range childFolders {
			m.addFolderToMarkdownTree(tree, childFolder, depth+1)
		}

		// Add child projects
		for _, proj := range childProjects {
			projDisplayName := proj.DisplayName
			if projDisplayName == "" {
				projDisplayName = proj.ProjectID
			}
			*tree += fmt.Sprintf("- 📁 **Project:** %s (`%s`)\n", projDisplayName, proj.ProjectID)
		}

		*tree += "\n</details>\n\n"
	} else {
		// Empty folder - just a list item
		*tree += fmt.Sprintf("- 📂 **Folder:** %s (`%s`) *(empty)*\n", displayName, folderID)
	}
}

// generateTextTreeView creates a standard ASCII tree of the organization hierarchy
func (m *OrganizationsModule) generateTextTreeView() {
	tree := &m.LootMap["org-tree"].Contents

	for _, org := range m.Organizations {
		orgID := strings.TrimPrefix(org.Name, "organizations/")
		displayName := org.DisplayName
		if displayName == "" {
			displayName = orgID
		}
		*tree += fmt.Sprintf("Organization: %s (%s)\n", displayName, orgID)

		// Get direct children (folders and projects) of this org
		childFolders := m.getChildFolders(org.Name)
		childProjects := m.getChildProjects(org.Name)

		totalChildren := len(childFolders) + len(childProjects)
		childIndex := 0

		// Add folders
		for _, folder := range childFolders {
			childIndex++
			isLast := childIndex == totalChildren
			m.addFolderToTextTree(tree, folder, "", isLast)
		}

		// Add projects directly under org
		for _, proj := range childProjects {
			childIndex++
			isLast := childIndex == totalChildren
			prefix := "├── "
			if isLast {
				prefix = "└── "
			}
			projDisplayName := proj.DisplayName
			if projDisplayName == "" {
				projDisplayName = proj.ProjectID
			}
			*tree += fmt.Sprintf("%sProject: %s (%s)\n", prefix, projDisplayName, proj.ProjectID)
		}

		*tree += "\n"
	}

	// Handle standalone projects (no org parent)
	standaloneProjects := m.getStandaloneProjects()
	if len(standaloneProjects) > 0 {
		*tree += "Standalone Projects (no organization):\n"
		for i, proj := range standaloneProjects {
			isLast := i == len(standaloneProjects)-1
			prefix := "├── "
			if isLast {
				prefix = "└── "
			}
			displayName := proj.DisplayName
			if displayName == "" {
				displayName = proj.ProjectID
			}
			*tree += fmt.Sprintf("%sProject: %s (%s)\n", prefix, displayName, proj.ProjectID)
		}
	}
}

// addFolderToTextTree recursively adds a folder and its children to the ASCII tree
func (m *OrganizationsModule) addFolderToTextTree(tree *string, folder orgsservice.FolderInfo, indent string, isLast bool) {
	folderID := strings.TrimPrefix(folder.Name, "folders/")
	displayName := folder.DisplayName
	if displayName == "" {
		displayName = folderID
	}

	// Determine the prefix for this item
	prefix := "├── "
	if isLast {
		prefix = "└── "
	}

	*tree += fmt.Sprintf("%s%sFolder: %s (%s)\n", indent, prefix, displayName, folderID)

	// Determine the indent for children
	childIndent := indent + "│   "
	if isLast {
		childIndent = indent + "    "
	}

	// Get children of this folder
	childFolders := m.getChildFolders(folder.Name)
	childProjects := m.getChildProjects(folder.Name)

	totalChildren := len(childFolders) + len(childProjects)
	childIndex := 0

	// Add child folders
	for _, childFolder := range childFolders {
		childIndex++
		childIsLast := childIndex == totalChildren
		m.addFolderToTextTree(tree, childFolder, childIndent, childIsLast)
	}

	// Add child projects
	for _, proj := range childProjects {
		childIndex++
		childIsLast := childIndex == totalChildren
		childPrefix := "├── "
		if childIsLast {
			childPrefix = "└── "
		}
		projDisplayName := proj.DisplayName
		if projDisplayName == "" {
			projDisplayName = proj.ProjectID
		}
		*tree += fmt.Sprintf("%s%sProject: %s (%s)\n", childIndent, childPrefix, projDisplayName, proj.ProjectID)
	}
}

// generateScopeHierarchy creates a linear hierarchy view for only the projects in scope (-p or -l)
func (m *OrganizationsModule) generateScopeHierarchy() {
	hierarchy := &m.LootMap["org-scope-hierarchy"].Contents

	*hierarchy = "# GCP Scope Hierarchy\n"
	*hierarchy += "# Linear hierarchy paths for projects in scope\n"
	*hierarchy += "# Generated by CloudFox\n\n"

	if len(m.ProjectIDs) == 0 {
		*hierarchy += "No projects in scope.\n"
		return
	}

	// For each project in scope, show its full hierarchy path
	for _, projectID := range m.ProjectIDs {
		// Find the project info
		var projectInfo *orgsservice.ProjectInfo
		for i := range m.Projects {
			if m.Projects[i].ProjectID == projectID {
				projectInfo = &m.Projects[i]
				break
			}
		}

		if projectInfo == nil {
			*hierarchy += fmt.Sprintf("Project: %s (not found in hierarchy)\n\n", projectID)
			continue
		}

		// Build the hierarchy path from project up to org
		path := m.buildHierarchyPath(projectInfo)

		// Output the linear path
		projectName := projectInfo.DisplayName
		if projectName == "" {
			projectName = projectID
		}

		*hierarchy += fmt.Sprintf("## %s (%s)\n", projectName, projectID)

		// Show path from org down to project
		for i, node := range path {
			indent := strings.Repeat("  ", i)
			*hierarchy += fmt.Sprintf("%s%s\n", indent, node)
		}
		*hierarchy += "\n"
	}
}

// buildHierarchyPath builds the hierarchy path from org down to project
func (m *OrganizationsModule) buildHierarchyPath(project *orgsservice.ProjectInfo) []string {
	var path []string

	// Start from the project and work up
	var reversePath []string

	// Add project
	projectName := project.DisplayName
	if projectName == "" {
		projectName = project.ProjectID
	}
	reversePath = append(reversePath, fmt.Sprintf("└── Project: %s (%s)", projectName, project.ProjectID))

	// Traverse up the hierarchy
	currentParent := project.Parent
	for currentParent != "" {
		if strings.HasPrefix(currentParent, "folders/") {
			folderID := strings.TrimPrefix(currentParent, "folders/")
			folderName := m.getFolderName(folderID)
			reversePath = append(reversePath, fmt.Sprintf("└── Folder: %s (%s)", folderName, folderID))

			// Find the folder's parent
			for _, folder := range m.Folders {
				if folder.Name == currentParent {
					currentParent = folder.Parent
					break
				}
			}
		} else if strings.HasPrefix(currentParent, "organizations/") {
			orgID := strings.TrimPrefix(currentParent, "organizations/")
			orgName := m.getOrgName(orgID)
			reversePath = append(reversePath, fmt.Sprintf("Organization: %s (%s)", orgName, orgID))
			break
		} else {
			break
		}
	}

	// Reverse to get org -> folder -> project order
	for i := len(reversePath) - 1; i >= 0; i-- {
		path = append(path, reversePath[i])
	}

	return path
}

// getChildFolders returns folders that are direct children of the given parent
func (m *OrganizationsModule) getChildFolders(parentName string) []orgsservice.FolderInfo {
	var children []orgsservice.FolderInfo
	for _, folder := range m.Folders {
		if folder.Parent == parentName {
			children = append(children, folder)
		}
	}
	return children
}

// getChildProjects returns projects that are direct children of the given parent
func (m *OrganizationsModule) getChildProjects(parentName string) []orgsservice.ProjectInfo {
	var children []orgsservice.ProjectInfo
	for _, proj := range m.Projects {
		if proj.Parent == parentName {
			children = append(children, proj)
		}
	}
	return children
}

// getStandaloneProjects returns projects that don't belong to any organization
func (m *OrganizationsModule) getStandaloneProjects() []orgsservice.ProjectInfo {
	var standalone []orgsservice.ProjectInfo
	for _, proj := range m.Projects {
		// Check if parent is not an org or folder
		if !strings.HasPrefix(proj.Parent, "organizations/") && !strings.HasPrefix(proj.Parent, "folders/") {
			standalone = append(standalone, proj)
		}
	}
	return standalone
}

// getFolderName returns the display name for a folder ID
func (m *OrganizationsModule) getFolderName(folderID string) string {
	for _, folder := range m.Folders {
		id := strings.TrimPrefix(folder.Name, "folders/")
		if id == folderID {
			if folder.DisplayName != "" {
				return folder.DisplayName
			}
			return folderID
		}
	}
	return folderID
}

// getOrgName returns the display name for an organization ID
func (m *OrganizationsModule) getOrgName(orgID string) string {
	for _, org := range m.Organizations {
		id := strings.TrimPrefix(org.Name, "organizations/")
		if id == orgID {
			if org.DisplayName != "" {
				return org.DisplayName
			}
			return orgID
		}
	}
	return orgID
}

// saveToOrgCache saves enumerated org data to disk cache
func (m *OrganizationsModule) saveToOrgCache(logger internal.Logger) {
	cache := gcpinternal.NewOrgCache()

	// Convert module data to cache format
	for _, org := range m.Organizations {
		orgID := strings.TrimPrefix(org.Name, "organizations/")
		cache.AddOrganization(gcpinternal.CachedOrganization{
			ID:          orgID,
			Name:        org.Name,
			DisplayName: org.DisplayName,
			DirectoryID: org.DirectoryID,
			State:       org.State,
		})
	}
	for _, folder := range m.Folders {
		folderID := strings.TrimPrefix(folder.Name, "folders/")
		cache.AddFolder(gcpinternal.CachedFolder{
			ID:          folderID,
			Name:        folder.Name,
			DisplayName: folder.DisplayName,
			Parent:      folder.Parent,
			State:       folder.State,
		})
	}
	for _, project := range m.Projects {
		// Extract project number from Name (format: "projects/123456789")
		projectNumber := ""
		if strings.HasPrefix(project.Name, "projects/") {
			projectNumber = strings.TrimPrefix(project.Name, "projects/")
		}
		cache.AddProject(gcpinternal.CachedProject{
			ID:          project.ProjectID,
			Number:      projectNumber,
			Name:        project.Name,
			DisplayName: project.DisplayName,
			Parent:      project.Parent,
			State:       project.State,
		})
	}
	cache.MarkPopulated()

	// Save to disk
	err := gcpinternal.SaveOrgCacheToFile(cache, m.OutputDirectory, m.Account, "1.0")
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not save org cache: %v", err), globals.GCP_ORGANIZATIONS_MODULE_NAME)
	} else {
		logger.InfoM(fmt.Sprintf("Saved org cache to disk (%d orgs, %d folders, %d projects)",
			len(m.Organizations), len(m.Folders), len(m.Projects)), globals.GCP_ORGANIZATIONS_MODULE_NAME)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *OrganizationsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *OrganizationsModule) buildTables() []internal.TableFile {
	// Organizations table
	orgsHeader := []string{
		"Organization ID",
		"Display Name",
		"State",
		"Directory ID",
	}

	var orgsBody [][]string
	for _, org := range m.Organizations {
		orgID := strings.TrimPrefix(org.Name, "organizations/")
		orgsBody = append(orgsBody, []string{
			orgID,
			org.DisplayName,
			org.State,
			org.DirectoryID,
		})
	}

	// Folders table
	foldersHeader := []string{
		"Folder ID",
		"Display Name",
		"Parent",
		"State",
	}

	var foldersBody [][]string
	for _, folder := range m.Folders {
		folderID := strings.TrimPrefix(folder.Name, "folders/")
		foldersBody = append(foldersBody, []string{
			folderID,
			folder.DisplayName,
			folder.Parent,
			folder.State,
		})
	}

	// Projects table
	projectsHeader := []string{
		"Project ID",
		"Project Name",
		"Display Name",
		"Parent",
		"State",
	}

	var projectsBody [][]string
	for _, proj := range m.Projects {
		projectsBody = append(projectsBody, []string{
			proj.ProjectID,
			m.GetProjectName(proj.ProjectID),
			proj.DisplayName,
			proj.Parent,
			proj.State,
		})
	}

	// Ancestry table
	ancestryHeader := []string{
		"Project ID",
		"Project Name",
		"Ancestry Path",
	}

	var ancestryBody [][]string
	for _, ancestry := range m.Ancestry {
		if len(ancestry) > 0 {
			// Build ancestry path string with names
			var path []string
			projectID := ""
			for _, node := range ancestry {
				if node.Type == "project" {
					projectID = node.ID
					projName := m.GetProjectName(node.ID)
					if projName != "" && projName != node.ID {
						path = append(path, fmt.Sprintf("project:%s (%s)", projName, node.ID))
					} else {
						path = append(path, fmt.Sprintf("project:%s", node.ID))
					}
				} else if node.Type == "folder" {
					folderName := m.getFolderName(node.ID)
					if folderName != "" && folderName != node.ID {
						path = append(path, fmt.Sprintf("folder:%s (%s)", folderName, node.ID))
					} else {
						path = append(path, fmt.Sprintf("folder:%s", node.ID))
					}
				} else if node.Type == "organization" {
					orgName := m.getOrgName(node.ID)
					if orgName != "" && orgName != node.ID {
						path = append(path, fmt.Sprintf("organization:%s (%s)", orgName, node.ID))
					} else {
						path = append(path, fmt.Sprintf("organization:%s", node.ID))
					}
				} else {
					path = append(path, fmt.Sprintf("%s:%s", node.Type, node.ID))
				}
			}
			ancestryBody = append(ancestryBody, []string{
				projectID,
				m.GetProjectName(projectID),
				strings.Join(path, " -> "),
			})
		}
	}

	// Build tables
	var tables []internal.TableFile

	if len(orgsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "organizations",
			Header: orgsHeader,
			Body:   orgsBody,
		})
	}

	if len(foldersBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "org-folders",
			Header: foldersHeader,
			Body:   foldersBody,
		})
	}

	if len(projectsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "org-projects",
			Header: projectsHeader,
			Body:   projectsBody,
		})
	}

	if len(ancestryBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "org-ancestry",
			Header: ancestryHeader,
			Body:   ancestryBody,
		})
	}

	return tables
}

func (m *OrganizationsModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *OrganizationsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// For organizations module, output at org level since it enumerates the whole hierarchy
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := OrganizationsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output location - prefer org-level, fall back to project-level
	orgID := ""

	// First, try to get org ID from the hierarchy
	if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	} else if len(m.Organizations) > 0 {
		// Fall back to enumerated organizations if hierarchy not available
		orgID = strings.TrimPrefix(m.Organizations[0].Name, "organizations/")
	}

	// Ensure hierarchy has display names from our enumeration
	// This handles the case where the hierarchy was built before we enumerated orgs
	if m.Hierarchy != nil && len(m.Organizations) > 0 {
		for _, org := range m.Organizations {
			numericID := strings.TrimPrefix(org.Name, "organizations/")
			// Update display name in hierarchy if we have a better one
			for i := range m.Hierarchy.Organizations {
				if m.Hierarchy.Organizations[i].ID == numericID {
					if m.Hierarchy.Organizations[i].DisplayName == "" && org.DisplayName != "" {
						m.Hierarchy.Organizations[i].DisplayName = org.DisplayName
					}
					break
				}
			}
		}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_ORGANIZATIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *OrganizationsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := OrganizationsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
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
		"project",           // scopeType
		m.ProjectIDs,        // scopeIdentifiers
		scopeNames,          // scopeNames
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ORGANIZATIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
