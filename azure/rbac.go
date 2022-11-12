package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

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

/************* MOCKED FUNCTIONS BELOW (USE IT FOR UNIT TESTING) *************/

func MockedGetAzureADUsers(testFile string) []graphrbac.User {
	var users AzureADUsersTestFile
	file, err := os.ReadFile(testFile)
	if err != nil {
		log.Fatalf("could not read file %s", testFile)
	}
	err = json.Unmarshal(file, &users)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", testFile)
	}
	return users.AzureADUsers
}

func GenerateAzureADUsersTestFIle(tenantID string) {
	// The READ-ONLY ObjectID attribute needs to be included manually in the test file
	// ObjectID *string `json:"objectId,omitempty"`

	usersJSON, err := json.Marshal(AzureADUsersTestFile{AzureADUsers: getAzureADUsers(tenantID)})
	if err != nil {
		log.Fatalf("could not marshall json for azure ad users in tenant %s", tenantID)
	}
	err = os.WriteFile(constants.AAD_USERS_TEST_FILE, usersJSON, os.ModeAppend)
	if err != nil {
		log.Fatalf("could not write to azure ad users test file %s", constants.AAD_USERS_TEST_FILE)
	}
}

type AzureADUsersTestFile struct {
	AzureADUsers []graphrbac.User `json:"azureADUsers"`
}

func MockedGetRoleDefinitions(testFile string) []authorization.RoleDefinition {
	var roleDefinitions RoleDefinitionTestFile
	file, err := os.ReadFile(testFile)
	if err != nil {
		log.Fatalf("could not read file %s", testFile)
	}
	err = json.Unmarshal(file, &roleDefinitions)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", testFile)
	}
	return roleDefinitions.RoleDefinitions
}

func GenerateRoleDefinitionsTestFile(subscriptionID string) {
	// The READ-ONLY Name attribute needs to be included manually in the test file
	// This attribute is the unique identifier for the role (e.g. "fbc52c3f-28ad-4303-a892-8a056630b8f1")
	// Name *string `json:"name,omitempty"`

	rolesjson, err := json.Marshal(
		RoleDefinitionTestFile{RoleDefinitions: getRoleDefinitions(subscriptionID)})
	if err != nil {
		log.Fatalf("could not marshall json for role definitions in subscription %s", subscriptionID)
	}
	err = os.WriteFile(constants.ROLE_DEFINITIONS_TEST_FILE, rolesjson, os.ModeAppend)
	if err != nil {
		log.Fatalf("could not write to role definitions test file %s", constants.ROLE_DEFINITIONS_TEST_FILE)
	}
}

type RoleDefinitionTestFile struct {
	RoleDefinitions []authorization.RoleDefinition `json:"roleDefinitions"`
}

func MockedGetRoleAssignments(testFile string) []authorization.RoleAssignment {
	var roleAssignments RoleAssignmentsTestFile
	file, err := os.ReadFile(testFile)
	if err != nil {
		log.Fatalf("could not read file %s", testFile)
	}
	err = json.Unmarshal(file, &roleAssignments)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", testFile)
	}
	return roleAssignments.RoleAssignments
}

func GenerateRoleAssignmentsTestFIle(subscriptionID string) {
	roleAssginments, err := json.Marshal(RoleAssignmentsTestFile{RoleAssignments: getRoleAssignments(subscriptionID)})
	if err != nil {
		log.Fatalf("could not marshall json for role assignments in subscription %s", subscriptionID)
	}
	err = os.WriteFile(constants.ROLE_ASSIGNMENTS_TEST_FILE, roleAssginments, os.ModeAppend)
	if err != nil {
		log.Fatalf("could not write to azure ad users test file %s", constants.ROLE_ASSIGNMENTS_TEST_FILE)
	}
}

type RoleAssignmentsTestFile struct {
	RoleAssignments []authorization.RoleAssignment `json:"RoleAssignments"`
}
