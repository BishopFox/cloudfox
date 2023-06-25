package gcp

import (
	"fmt"
	"log"
	"github.com/fatih/color"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/kyokomi/emoji"
	"github.com/BishopFox/cloudfox/globals"

	// tree stuff
	"github.com/shivamMg/ppds/tree"
)

type HierarchyModule struct {
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

func (m *HierarchyModule) DisplayHierarchy(version string) error {
	fmt.Printf("[%s][%s] Fetching GCP resources and hierarchy...\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.GCP_HIERARCHY_MODULE_NAME))
	var client gcp.GCPClient = *gcp.NewGCPClient()
	//client.CloudresourcemanagerService.Organizations.List().Fields("nextPageToken", "projects/projectId", "projects/projectNumber", "projects/name", "projects/parent.id", "projects/parent.type").Do()
	var (
		root Node
		current *Node
	)

	root = Node{data: "root"}
	organizationListResponse, _ := client.CloudresourcemanagerService.Organizations.Search().Do()
	for _, organization := range organizationListResponse.Organizations {
		current = &Node{data: fmt.Sprintf("%s (%s)", organization.DisplayName, organization.Name)}
		getChilds(current, organization.Name, client)
		root.Add(*current)
	}
	// To Print vertically: tree.Print(&root)
	tree.PrintHr(&root)
	return nil
}

func getChilds(current *Node, parentName string, client gcp.GCPClient){
	var child Node
	foldersListResponse, err := client.CloudresourcemanagerService.Folders.List().Parent(parentName).Do()
	if err != nil{
		log.Fatalf("%v\n", err)
	}
	for _, folder := range foldersListResponse.Folders {
		child = Node{data: fmt.Sprintf("%s (%s)", folder.DisplayName, folder.Name)}
		getChilds(&child, folder.Name, client)
		(*current).Add(child)
	}
	projectsListResponse, err := client.CloudresourcemanagerService.Projects.List().Parent(parentName).Do()
	if err != nil{
		log.Fatalf("%v\n", err)
	}
	for _, project := range projectsListResponse.Projects {
		child = Node{data: fmt.Sprintf("%s (%s)", project.DisplayName, project.ProjectId)}
		(*current).Add(child)
	}
}