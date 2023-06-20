package gcp

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"github.com/fatih/color"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/kyokomi/emoji"
	"github.com/BishopFox/cloudfox/globals"
	"google.golang.org/api/cloudresourcemanager/v1"
)

func GCPWhoamiCommand(version string, GCPWrapTable bool) error {
	fmt.Printf("[%s][%s] Enumerating GCP projects through SDK application credentials...\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", version)), color.CyanString(globals.GCP_WHOAMI_MODULE_NAME))
	ctx := context.Background()
	ts, err := google.DefaultTokenSource(ctx)
	oauth2Service, err := oauth2.NewService(ctx, option.WithTokenSource(ts))
	cloudresourcemanagerService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(ts))

	if err != nil {
		log.Fatal(err)
	}
	tokenInfo, err := oauth2Service.Tokeninfo().Do()
	if err != nil {
		log.Fatal(err)
	}
	/*
	orgInfo, err := cloudresourcemanagerService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{}).Do()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", orgInfo)*/
	projectListResponse, err := cloudresourcemanagerService.Projects.List().Fields("nextPageToken", "projects/projectId", "projects/projectNumber", "projects/name", "projects/parent.id", "projects/parent.type").Do()
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
					tokenInfo.Email,
					"user",
				})
		}
	}
	internal.PrintTableToScreen(tableHead, tableBody, GCPWrapTable)
	
	return nil
}
