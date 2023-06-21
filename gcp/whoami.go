package gcp

import (
	"fmt"
	"log"
	"strconv"
	"github.com/fatih/color"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/kyokomi/emoji"
	"github.com/BishopFox/cloudfox/globals"
)

//func GCPPermissionsCommand(

func GCPWhoamiCommand(version string, GCPWrapTable bool) error {
	fmt.Printf("[%s][%s] Enumerating GCP projects through SDK application credentials...\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.GCP_WHOAMI_MODULE_NAME))
	var client gcpp.GCPClient = *gcpp.NewGCPClient()
	/*
	orgInfo, err := cloudresourcemanagerService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{}).Do()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", orgInfo)*/
	//projectListResponse, err := client.cloudresourcemanagerService.Projects.List().Fields("nextPageToken", "projects/projectId", "projects/projectNumber", "projects/name", "projects/parent.id", "projects/parent.type").Do()
	projectListResponse, err := client.CloudresourcemanagerService.Projects.List().Fields("nextPageToken", "projects/projectId", "projects/projectNumber", "projects/name", "projects/parent.id", "projects/parent.type").Do()
	if err != nil {
		log.Fatal(err)
	}

	tableHead := []string{"Project Name", "Project ID", "Project Number", "Parent ID", "Parent Type"}
	var tableBody [][]string
	for _, project := range projectListResponse.Projects {
		if project.Parent != nil {
			tableBody = append(
				tableBody,
				[]string{
					project.Name,
					project.ProjectId,
					strconv.FormatInt(project.ProjectNumber, 10),
					project.Parent.Id,
					project.Parent.Type,
				})
		} else {
			tableBody = append(
				tableBody,
				[]string{
					project.Name,
					project.ProjectId,
					strconv.FormatInt(project.ProjectNumber, 10),
					//client.tokenInfo.Email,
					client.TokenInfo.Email,
					"user",
				})
		}
	}
	internal.PrintTableToScreen(tableHead, tableBody, GCPWrapTable)
	
	return nil
}
