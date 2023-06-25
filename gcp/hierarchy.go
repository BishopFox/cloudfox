package gcp

import (
	"fmt"
	"context"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"google.golang.org/api/iterator"

	// tree stuff
	"github.com/shivamMg/ppds/tree"
)

type HierarchyModule struct {
	Client gcp.GCPClient
	
	// Filtering data
	Organizations []string
	Folders []string
	Projects []string
}

type Node struct {
	data string
	c    []*Node
}

func (n *Node) Data() interface{} {
	return n.data
}

func (n *Node) Children() (children []tree.Node) {
	for _, c := range n.c {
		children = append(children, tree.Node(c))
	}
	return
}

func (n *Node) Add(child Node) {
	n.c = append(n.c, &child)
	return
}

func (m *HierarchyModule) DisplayHierarchy() error {
	GCPLogger.InfoM(fmt.Sprintf("Fetching GCP resources and hierarchy with account %s...", m.Client.Name), globals.GCP_HIERARCHY_MODULE_NAME)
	//client.CloudresourcemanagerService.Organizations.List().Fields("nextPageToken", "projects/projectId", "projects/projectNumber", "projects/name", "projects/parent.id", "projects/parent.type").Do()
	var (
		root Node
		current *Node
	)

	ctx := context.Background()

	// create the root resource node, which is the current user account
	root = Node{data: m.Client.Name}

	// iterate over available organizations
	organizationIterator := m.Client.OrganizationsClient.SearchOrganizations(ctx, &resourcemanagerpb.SearchOrganizationsRequest{})
	for {
		organization, err := organizationIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			GCPLogger.FatalM(fmt.Sprintf("An error occurred when listing organizations: %v", err), globals.GCP_HIERARCHY_MODULE_NAME)
		}
		current = &Node{data: fmt.Sprintf("%s (%s)", organization.DisplayName, organization.Name)}
		//GCPLogger.Success(fmt.Sprintf("Listing stuff in organization %s", organization.DisplayName))
		// get childs (projects & folders) within current orgnization
		m.getChilds(current, organization.Name)
		root.Add(*current)
	}

	// now look for resources (projects) that do not have a parent and that live in the user' account directly
	// might need to investigate later but it looks like we can't have folders under a user account
	projectsListResponse, _ := m.Client.CloudresourcemanagerService.Projects.List().Do()
	for _, project := range projectsListResponse.Projects {
		if project.Parent == nil {
			current = &Node{data: fmt.Sprintf("%s (%s)", project.Name, project.ProjectId)}
			root.Add(*current)
		}
	}

	// To Print vertically: tree.Print(&root)
	tree.PrintHr(&root)
	return nil
}

func (m *HierarchyModule) getChilds(current *Node, parentName string){
	//GCPLogger.Success(fmt.Sprintf("Listing stuff in parent %s", parentName))
	var child Node
	ctx := context.Background()
	folderIterator := m.Client.FoldersClient.SearchFolders(ctx, &resourcemanagerpb.SearchFoldersRequest{Query: fmt.Sprintf("parent=%s", parentName)})
	for {
		folder, err := folderIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			GCPLogger.FatalM(fmt.Sprintf("An error occurred when listing folders in parent %s: %v", parentName, err), globals.GCP_HIERARCHY_MODULE_NAME)
		}
		child = Node{data: fmt.Sprintf("%s (%s)", folder.DisplayName, folder.Name)}
		m.getChilds(&child, folder.Name)
		(*current).Add(child)
	}
	projectIterator := m.Client.ProjectsClient.SearchProjects(ctx, &resourcemanagerpb.SearchProjectsRequest{Query: fmt.Sprintf("parent=%s", parentName)})
	for {
		project, err := projectIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			GCPLogger.FatalM(fmt.Sprintf("An error occurred when listing projects in parent %s: %v", parentName, err), globals.GCP_HIERARCHY_MODULE_NAME)
		}
		child = Node{data: fmt.Sprintf("%s (%s)", project.DisplayName, project.ProjectId)}
		(*current).Add(child)
	}
}
