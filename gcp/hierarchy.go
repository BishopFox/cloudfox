package gcp

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/kyokomi/emoji"
	"github.com/BishopFox/cloudfox/globals"
)

type HierarchyModule struct {
	// Filtering data
	Organizations []string
	Folders []string
	Projects []string
}

func (m *HierarchyModule) DisplayHierarchy(version string) error {
	fmt.Printf("[%s][%s] Fetching GCP resources and hierarchy...\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.GCP_WHOAMI_MODULE_NAME))
	var client gcp.GCPClient = *gcp.NewGCPClient()
	//client.CloudresourcemanagerService.Organizations.List().Fields("nextPageToken", "projects/projectId", "projects/projectNumber", "projects/name", "projects/parent.id", "projects/parent.type").Do()
	organizationListResponse, _ := client.CloudresourcemanagerService.Organizations.Search().Do()
	for _, organization := range organizationListResponse.Organizations {
		fmt.Print(organization)
		foldersListResponse, _ := client.CloudresourcemanagerService.Folders.List().Parent(organization.Name).Do()
		for _, folder := range foldersListResponse.Folders {
			fmt.Println(folder)
		}
		projectsListResponse, _ := client.CloudresourcemanagerService.Projects.List().Parent(organization.Name).Do()
		for _, project := range projectsListResponse.Projects {
			fmt.Println(project)
		}
	}
	return nil
}
