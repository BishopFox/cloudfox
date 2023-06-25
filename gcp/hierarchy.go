package gcp

import (
	"fmt"
	"log"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"

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
	GCPLogger.InfoM(fmt.Sprintf("Fetching GCP resources and hierarchy with account %s...\n", m.Client.Name), globals.GCP_HIERARCHY_MODULE_NAME)
	//client.CloudresourcemanagerService.Organizations.List().Fields("nextPageToken", "projects/projectId", "projects/projectNumber", "projects/name", "projects/parent.id", "projects/parent.type").Do()
	var (
		root Node
		current *Node
	)

	root = Node{data: m.Client.Name}
	organizationListResponse, _ := m.Client.CloudresourcemanagerService.Organizations.Search().Do()
	for _, organization := range organizationListResponse.Organizations {
		current = &Node{data: fmt.Sprintf("%s (%s)", organization.DisplayName, organization.Name)}
		m.getChilds(current, organization.Name)
		root.Add(*current)
	}
	// To Print vertically: tree.Print(&root)
	tree.PrintHr(&root)
	return nil
}

func (m *HierarchyModule) getChilds(current *Node, parentName string){
	var child Node
	foldersListResponse, err := m.Client.CloudresourcemanagerService.Folders.List().Parent(parentName).Do()
	if err != nil{
		log.Fatalf("%v\n", err)
	}
	for _, folder := range foldersListResponse.Folders {
		child = Node{data: fmt.Sprintf("%s (%s)", folder.DisplayName, folder.Name)}
		m.getChilds(&child, folder.Name)
		(*current).Add(child)
	}
	projectsListResponse, err := m.Client.CloudresourcemanagerService.Projects.List().Parent(parentName).Do()
	if err != nil{
		log.Fatalf("%v\n", err)
	}
	for _, project := range projectsListResponse.Projects {
		child = Node{data: fmt.Sprintf("%s (%s)", project.DisplayName, project.ProjectId)}
		(*current).Add(child)
	}
}
