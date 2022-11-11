package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/fatih/color"
)

var GetAzureADUsers = getAzureADUsers

func getAzureADUsers(tenantID string) []graphrbac.User {
	var users []graphrbac.User
	client := utils.GetAADUsersClient(tenantID)
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[%s] Could not enumerate users for tenant %s. Skipping it.\n", color.New(color.FgCyan).Sprint(constants.AZ_RBAC_MODULE_NAME), tenantID)
			continue
		}
		users = append(users, page.Values()...)
	}
	return users
}

var GetRoleDefinitions = getRoleDefinitions

func getRoleDefinitions(subscriptionID string) []authorization.RoleDefinition {
	client := utils.GetRoleDefinitionsClient(subscriptionID)
	var roleDefinitions []authorization.RoleDefinition
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[%s] Could not enumerate roles for subscription %s. Skipping it.\n", color.New(color.FgCyan).Sprint(constants.AZ_RBAC_MODULE_NAME), subscriptionID)
			continue
		}
		roleDefinitions = append(roleDefinitions, page.Values()...)
	}
	return roleDefinitions
}

var GetRoleAssignments = getRoleAssignments

func getRoleAssignments(subscriptionID string) []authorization.RoleAssignment {
	var roleAssignments []authorization.RoleAssignment
	client := utils.GetRoleAssignmentsClient(subscriptionID)
	for page, err := client.List(context.TODO(), ""); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[%s] Could not role assignments for subscription %s. Skipping it.\n", color.New(color.FgCyan).Sprint(constants.AZ_RBAC_MODULE_NAME), subscriptionID)
			continue
		}
		roleAssignments = append(roleAssignments, page.Values()...)
	}
	return roleAssignments
}
