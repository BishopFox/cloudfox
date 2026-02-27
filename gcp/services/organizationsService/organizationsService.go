package organizationsservice

import (
	"context"
	"fmt"
	"strings"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"google.golang.org/api/iterator"
)

type OrganizationsService struct {
	session *gcpinternal.SafeSession
}

// New creates a new OrganizationsService
func New() *OrganizationsService {
	return &OrganizationsService{}
}

// NewWithSession creates an OrganizationsService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *OrganizationsService {
	return &OrganizationsService{session: session}
}

// OrganizationInfo represents organization details
type OrganizationInfo struct {
	Name         string `json:"name"`         // organizations/ORGANIZATION_ID
	DisplayName  string `json:"displayName"`
	DirectoryID  string `json:"directoryId"`  // Cloud Identity directory ID
	State        string `json:"state"`        // ACTIVE, DELETE_REQUESTED
	CreateTime   string `json:"createTime"`
	UpdateTime   string `json:"updateTime"`
	DeleteTime   string `json:"deleteTime"`
}

// FolderInfo represents folder details
type FolderInfo struct {
	Name         string `json:"name"`         // folders/FOLDER_ID
	DisplayName  string `json:"displayName"`
	Parent       string `json:"parent"`       // organizations/X or folders/X
	State        string `json:"state"`        // ACTIVE, DELETE_REQUESTED
	CreateTime   string `json:"createTime"`
	UpdateTime   string `json:"updateTime"`
	DeleteTime   string `json:"deleteTime"`
}

// ProjectInfo represents project details
type ProjectInfo struct {
	Name         string            `json:"name"`         // projects/PROJECT_ID
	ProjectID    string            `json:"projectId"`
	DisplayName  string            `json:"displayName"`
	Parent       string            `json:"parent"`       // organizations/X or folders/X
	State        string            `json:"state"`        // ACTIVE, DELETE_REQUESTED
	Labels       map[string]string `json:"labels"`
	CreateTime   string            `json:"createTime"`
	UpdateTime   string            `json:"updateTime"`
	DeleteTime   string            `json:"deleteTime"`
}

// HierarchyNode represents a node in the resource hierarchy
type HierarchyNode struct {
	Type        string          `json:"type"`     // organization, folder, project
	ID          string          `json:"id"`
	DisplayName string          `json:"displayName"`
	Parent      string          `json:"parent"`
	Children    []HierarchyNode `json:"children"`
	Depth       int             `json:"depth"`
}

// SearchOrganizations searches for organizations accessible to the caller
func (s *OrganizationsService) SearchOrganizations() ([]OrganizationInfo, error) {
	ctx := context.Background()
	var client *resourcemanager.OrganizationsClient
	var err error

	if s.session != nil {
		client, err = resourcemanager.NewOrganizationsClient(ctx, s.session.GetClientOption())
	} else {
		client, err = resourcemanager.NewOrganizationsClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer client.Close()

	var orgs []OrganizationInfo

	req := &resourcemanagerpb.SearchOrganizationsRequest{}
	it := client.SearchOrganizations(ctx, req)
	for {
		org, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
		}

		orgInfo := OrganizationInfo{
			Name:        org.Name,
			DisplayName: org.DisplayName,
			DirectoryID: org.GetDirectoryCustomerId(),
			State:       org.State.String(),
		}
		if org.CreateTime != nil {
			orgInfo.CreateTime = org.CreateTime.AsTime().String()
		}
		if org.UpdateTime != nil {
			orgInfo.UpdateTime = org.UpdateTime.AsTime().String()
		}
		if org.DeleteTime != nil {
			orgInfo.DeleteTime = org.DeleteTime.AsTime().String()
		}

		orgs = append(orgs, orgInfo)
	}

	return orgs, nil
}

// SearchFolders searches for folders under a given parent
func (s *OrganizationsService) SearchFolders(parent string) ([]FolderInfo, error) {
	ctx := context.Background()
	var client *resourcemanager.FoldersClient
	var err error

	if s.session != nil {
		client, err = resourcemanager.NewFoldersClient(ctx, s.session.GetClientOption())
	} else {
		client, err = resourcemanager.NewFoldersClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer client.Close()

	var folders []FolderInfo

	// Search for folders under the given parent
	query := fmt.Sprintf("parent=%s", parent)
	req := &resourcemanagerpb.SearchFoldersRequest{
		Query: query,
	}
	it := client.SearchFolders(ctx, req)
	for {
		folder, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
		}

		folderInfo := FolderInfo{
			Name:        folder.Name,
			DisplayName: folder.DisplayName,
			Parent:      folder.Parent,
			State:       folder.State.String(),
		}
		if folder.CreateTime != nil {
			folderInfo.CreateTime = folder.CreateTime.AsTime().String()
		}
		if folder.UpdateTime != nil {
			folderInfo.UpdateTime = folder.UpdateTime.AsTime().String()
		}
		if folder.DeleteTime != nil {
			folderInfo.DeleteTime = folder.DeleteTime.AsTime().String()
		}

		folders = append(folders, folderInfo)
	}

	return folders, nil
}

// SearchAllFolders searches for all accessible folders
func (s *OrganizationsService) SearchAllFolders() ([]FolderInfo, error) {
	ctx := context.Background()
	var client *resourcemanager.FoldersClient
	var err error

	if s.session != nil {
		client, err = resourcemanager.NewFoldersClient(ctx, s.session.GetClientOption())
	} else {
		client, err = resourcemanager.NewFoldersClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer client.Close()

	var folders []FolderInfo

	req := &resourcemanagerpb.SearchFoldersRequest{}
	it := client.SearchFolders(ctx, req)
	for {
		folder, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
		}

		folderInfo := FolderInfo{
			Name:        folder.Name,
			DisplayName: folder.DisplayName,
			Parent:      folder.Parent,
			State:       folder.State.String(),
		}
		if folder.CreateTime != nil {
			folderInfo.CreateTime = folder.CreateTime.AsTime().String()
		}
		if folder.UpdateTime != nil {
			folderInfo.UpdateTime = folder.UpdateTime.AsTime().String()
		}
		if folder.DeleteTime != nil {
			folderInfo.DeleteTime = folder.DeleteTime.AsTime().String()
		}

		folders = append(folders, folderInfo)
	}

	return folders, nil
}

// SearchProjects searches for projects
func (s *OrganizationsService) SearchProjects(parent string) ([]ProjectInfo, error) {
	ctx := context.Background()
	var client *resourcemanager.ProjectsClient
	var err error

	if s.session != nil {
		client, err = resourcemanager.NewProjectsClient(ctx, s.session.GetClientOption())
	} else {
		client, err = resourcemanager.NewProjectsClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer client.Close()

	var projects []ProjectInfo

	query := ""
	if parent != "" {
		query = fmt.Sprintf("parent=%s", parent)
	}
	req := &resourcemanagerpb.SearchProjectsRequest{
		Query: query,
	}
	it := client.SearchProjects(ctx, req)
	for {
		project, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
		}

		projectInfo := ProjectInfo{
			Name:        project.Name,
			ProjectID:   project.ProjectId,
			DisplayName: project.DisplayName,
			Parent:      project.Parent,
			State:       project.State.String(),
			Labels:      project.Labels,
		}
		if project.CreateTime != nil {
			projectInfo.CreateTime = project.CreateTime.AsTime().String()
		}
		if project.UpdateTime != nil {
			projectInfo.UpdateTime = project.UpdateTime.AsTime().String()
		}
		if project.DeleteTime != nil {
			projectInfo.DeleteTime = project.DeleteTime.AsTime().String()
		}

		projects = append(projects, projectInfo)
	}

	return projects, nil
}

// GetProjectAncestry returns the ancestry path from project to organization
func (s *OrganizationsService) GetProjectAncestry(projectID string) ([]HierarchyNode, error) {
	ctx := context.Background()

	var projectsClient *resourcemanager.ProjectsClient
	var foldersClient *resourcemanager.FoldersClient
	var orgsClient *resourcemanager.OrganizationsClient
	var err error

	if s.session != nil {
		projectsClient, err = resourcemanager.NewProjectsClient(ctx, s.session.GetClientOption())
	} else {
		projectsClient, err = resourcemanager.NewProjectsClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer projectsClient.Close()

	if s.session != nil {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx, s.session.GetClientOption())
	} else {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer foldersClient.Close()

	if s.session != nil {
		orgsClient, err = resourcemanager.NewOrganizationsClient(ctx, s.session.GetClientOption())
	} else {
		orgsClient, err = resourcemanager.NewOrganizationsClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer orgsClient.Close()

	var ancestry []HierarchyNode
	resourceID := "projects/" + projectID

	// Track inaccessible folder IDs so we can try to find org via search
	var inaccessibleFolderID string

	for {
		if strings.HasPrefix(resourceID, "organizations/") {
			orgID := strings.TrimPrefix(resourceID, "organizations/")
			displayName := orgID // Default to numeric ID if we can't get display name

			// Try to get the org's display name
			org, err := orgsClient.GetOrganization(ctx, &resourcemanagerpb.GetOrganizationRequest{Name: resourceID})
			if err == nil && org.DisplayName != "" {
				displayName = org.DisplayName
			}

			ancestry = append(ancestry, HierarchyNode{
				Type:        "organization",
				ID:          orgID,
				DisplayName: displayName,
			})
			break
		} else if strings.HasPrefix(resourceID, "folders/") {
			folder, err := foldersClient.GetFolder(ctx, &resourcemanagerpb.GetFolderRequest{Name: resourceID})
			if err != nil {
				// Permission denied on folder - skip this folder and try to find the org
				// Don't add the inaccessible folder to ancestry, just try to find the org
				inaccessibleFolderID = strings.TrimPrefix(resourceID, "folders/")

				// Try to find the org by searching accessible orgs
				orgsIter := orgsClient.SearchOrganizations(ctx, &resourcemanagerpb.SearchOrganizationsRequest{})
				for {
					org, iterErr := orgsIter.Next()
					if iterErr == iterator.Done {
						break
					}
					if iterErr != nil {
						break
					}
					// Add the first accessible org (best effort)
					// The project likely belongs to one of the user's accessible orgs
					orgID := strings.TrimPrefix(org.Name, "organizations/")
					ancestry = append(ancestry, HierarchyNode{
						Type:        "organization",
						ID:          orgID,
						DisplayName: org.DisplayName,
					})
					break
				}
				break
			}
			folderID := strings.TrimPrefix(folder.Name, "folders/")
			ancestry = append(ancestry, HierarchyNode{
				Type:        "folder",
				ID:          folderID,
				DisplayName: folder.DisplayName,
				Parent:      folder.Parent,
			})
			resourceID = folder.Parent
		} else if strings.HasPrefix(resourceID, "projects/") {
			project, err := projectsClient.GetProject(ctx, &resourcemanagerpb.GetProjectRequest{Name: resourceID})
			if err != nil {
				break
			}
			ancestry = append(ancestry, HierarchyNode{
				Type:        "project",
				ID:          project.ProjectId,
				DisplayName: project.DisplayName,
				Parent:      project.Parent,
			})
			resourceID = project.Parent
		} else {
			break
		}
	}

	// Suppress unused variable warning
	_ = inaccessibleFolderID

	// Reverse to go from organization to project
	for i, j := 0, len(ancestry)-1; i < j; i, j = i+1, j-1 {
		ancestry[i], ancestry[j] = ancestry[j], ancestry[i]
	}

	// Set depth
	for i := range ancestry {
		ancestry[i].Depth = i
	}

	return ancestry, nil
}

// GetOrganizationIDFromProject returns the organization ID for a given project
// by walking up the resource hierarchy until it finds an organization
func (s *OrganizationsService) GetOrganizationIDFromProject(projectID string) (string, error) {
	ancestry, err := s.GetProjectAncestry(projectID)
	if err != nil {
		return "", err
	}

	for _, node := range ancestry {
		if node.Type == "organization" {
			return node.ID, nil
		}
	}

	return "", fmt.Errorf("no organization found in ancestry for project %s", projectID)
}

// ------------------------------
// HierarchyDataProvider Implementation
// ------------------------------

// GetProjectAncestryForHierarchy returns ancestry in the format needed by BuildScopeHierarchy
func (s *OrganizationsService) GetProjectAncestryForHierarchy(projectID string) ([]gcpinternal.AncestryNode, error) {
	ancestry, err := s.GetProjectAncestry(projectID)
	if err != nil {
		return nil, err
	}

	result := make([]gcpinternal.AncestryNode, len(ancestry))
	for i, node := range ancestry {
		result[i] = gcpinternal.AncestryNode{
			Type:        node.Type,
			ID:          node.ID,
			DisplayName: node.DisplayName,
			Parent:      node.Parent,
			Depth:       node.Depth,
		}
	}
	return result, nil
}

// SearchOrganizationsForHierarchy returns orgs in the format needed by BuildScopeHierarchy
func (s *OrganizationsService) SearchOrganizationsForHierarchy() ([]gcpinternal.OrganizationData, error) {
	orgs, err := s.SearchOrganizations()
	if err != nil {
		return nil, err
	}

	result := make([]gcpinternal.OrganizationData, len(orgs))
	for i, org := range orgs {
		result[i] = gcpinternal.OrganizationData{
			Name:        org.Name,
			DisplayName: org.DisplayName,
		}
	}
	return result, nil
}

// HierarchyProvider wraps OrganizationsService to implement HierarchyDataProvider
type HierarchyProvider struct {
	svc *OrganizationsService
}

// NewHierarchyProvider creates a HierarchyProvider from an OrganizationsService
func NewHierarchyProvider(svc *OrganizationsService) *HierarchyProvider {
	return &HierarchyProvider{svc: svc}
}

// GetProjectAncestry implements HierarchyDataProvider
func (p *HierarchyProvider) GetProjectAncestry(projectID string) ([]gcpinternal.AncestryNode, error) {
	return p.svc.GetProjectAncestryForHierarchy(projectID)
}

// SearchOrganizations implements HierarchyDataProvider
func (p *HierarchyProvider) SearchOrganizations() ([]gcpinternal.OrganizationData, error) {
	return p.svc.SearchOrganizationsForHierarchy()
}

// BuildHierarchy builds a complete hierarchy tree
func (s *OrganizationsService) BuildHierarchy() ([]HierarchyNode, error) {
	// Get organizations
	orgs, err := s.SearchOrganizations()
	if err != nil {
		return nil, err
	}

	var roots []HierarchyNode

	for _, org := range orgs {
		orgID := strings.TrimPrefix(org.Name, "organizations/")
		orgNode := HierarchyNode{
			Type:        "organization",
			ID:          orgID,
			DisplayName: org.DisplayName,
			Depth:       0,
			Children:    []HierarchyNode{},
		}

		// Get folders under this org
		s.buildFolderTree(&orgNode, org.Name, 1)

		// Get projects directly under org
		projects, err := s.SearchProjects(org.Name)
		if err == nil {
			for _, proj := range projects {
				projNode := HierarchyNode{
					Type:        "project",
					ID:          proj.ProjectID,
					DisplayName: proj.DisplayName,
					Parent:      proj.Parent,
					Depth:       1,
				}
				orgNode.Children = append(orgNode.Children, projNode)
			}
		}

		roots = append(roots, orgNode)
	}

	return roots, nil
}

// buildFolderTree recursively builds folder tree
func (s *OrganizationsService) buildFolderTree(parent *HierarchyNode, parentName string, depth int) {
	folders, err := s.SearchFolders(parentName)
	if err != nil {
		return
	}

	for _, folder := range folders {
		folderID := strings.TrimPrefix(folder.Name, "folders/")
		folderNode := HierarchyNode{
			Type:        "folder",
			ID:          folderID,
			DisplayName: folder.DisplayName,
			Parent:      folder.Parent,
			Depth:       depth,
			Children:    []HierarchyNode{},
		}

		// Recursively get child folders
		s.buildFolderTree(&folderNode, folder.Name, depth+1)

		// Get projects under this folder
		projects, err := s.SearchProjects(folder.Name)
		if err == nil {
			for _, proj := range projects {
				projNode := HierarchyNode{
					Type:        "project",
					ID:          proj.ProjectID,
					DisplayName: proj.DisplayName,
					Parent:      proj.Parent,
					Depth:       depth + 1,
				}
				folderNode.Children = append(folderNode.Children, projNode)
			}
		}

		parent.Children = append(parent.Children, folderNode)
	}
}
