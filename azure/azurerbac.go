package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

var GetAzureADUsers = getAzureADUsers

func getAzureADUsers(tenantID string) []graphrbac.User {
	var users []graphrbac.User
	client := utils.GetAADUsersClient(tenantID)
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[%s] Could not enumerate users for tenant %s. Skipping it.\n", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), tenantID)
			continue
		}
		users = append(users, page.Values()...)
	}
	return users
}

var GetRoleDefinitions = getRoleDefinitions

func getRoleDefinitions(subscriptionName string) []authorization.RoleDefinition {
	client := utils.GetRoleDefinitionsClient(subscriptionName)
	var roleDefinitions []authorization.RoleDefinition
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[%s] Could not enumerate roles for subscription %s. Skipping it.\n", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), subscriptionName)
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
			fmt.Printf("[%s] Could not role assignments for subscription %s. Skipping it.\n", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), subscriptionID)
			continue
		}
		roleAssignments = append(roleAssignments, page.Values()...)
	}
	return roleAssignments
}

/************* MOCKED FUNCTIONS BELOW (USE IT FOR UNIT TESTING) *************/

func MockedGetAzureADUsers(tenantID string) []graphrbac.User {
	var users AzureADUsersTestFile

	file, err := os.ReadFile(globals.AAD_USERS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", globals.AAD_USERS_TEST_FILE)
	}
	err = json.Unmarshal(file, &users)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.AAD_USERS_TEST_FILE)
	}
	return users.AzureADUsers
}

func GenerateAzureADUsersTestFIle(tenantID string) {
	// The READ-ONLY ObjectID attribute needs to be included manually in the test file
	// ObjectID *string `json:"objectId,omitempty"`
	users := getAzureADUsers(tenantID)
	usersJSON, err := json.Marshal(AzureADUsersTestFile{AzureADUsers: users})
	if err != nil {
		log.Fatalf("could not marshall json for azure ad users in tenant %s", tenantID)
	}
	err = os.WriteFile(globals.AAD_USERS_TEST_FILE, usersJSON, os.ModeAppend)
	if err != nil {
		log.Fatalf("could not write to azure ad users test file %s", globals.AAD_USERS_TEST_FILE)
	}
}

type AzureADUsersTestFile struct {
	AzureADUsers []graphrbac.User `json:"azureADUsers"`
}

func MockedGetRoleDefinitions(subscriptionName string) []authorization.RoleDefinition {
	var roleDefinitions RoleDefinitionTestFile
	file, err := os.ReadFile(globals.ROLE_DEFINITIONS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", globals.ROLE_DEFINITIONS_TEST_FILE)
	}
	err = json.Unmarshal(file, &roleDefinitions)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.ROLE_DEFINITIONS_TEST_FILE)
	}
	return roleDefinitions.RoleDefinitions
}

func GenerateRoleDefinitionsTestFile(subscriptionName string) {
	// The READ-ONLY ID attribute needs to be included manually in the test file.
	// This attribute is the unique identifier for the role.
	// ID *string `json:"id,omitempty"`.

	roleDefinitions := getRoleDefinitions(subscriptionName)
	roleAssignments := getRoleAssignments(subscriptionName)
	var roleDefinitionsResults []authorization.RoleDefinition

	for _, rd := range roleDefinitions {
		for _, ra := range roleAssignments {
			want := strings.Split(ptr.ToString(ra.Properties.RoleDefinitionID), "/")[len(strings.Split(ptr.ToString(ra.Properties.RoleDefinitionID), "/"))-1]

			got := strings.Split(ptr.ToString(rd.ID), "/")[len(strings.Split(ptr.ToString(rd.ID), "/"))-1]

			if want == got {
				roleDefinitionsResults = append(roleDefinitionsResults, rd)
			}
		}
	}

	tf := RoleDefinitionTestFile{
		RoleDefinitions: roleDefinitionsResults,
	}

	rolesjson, err := json.Marshal(tf)
	if err != nil {
		log.Fatalf("could not marshall json for role definitions in subscription %s", subscriptionName)
	}

	err = os.WriteFile(globals.ROLE_DEFINITIONS_TEST_FILE, rolesjson, os.ModeAppend)
	if err != nil {
		log.Fatalf("could not write to role definitions test file %s", globals.ROLE_DEFINITIONS_TEST_FILE)
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
	err = os.WriteFile(globals.ROLE_ASSIGNMENTS_TEST_FILE, roleAssginments, os.ModeAppend)
	if err != nil {
		log.Fatalf("could not write to azure ad users test file %s", globals.ROLE_ASSIGNMENTS_TEST_FILE)
	}
}

type RoleAssignmentsTestFile struct {
	RoleAssignments []authorization.RoleAssignment `json:"RoleAssignments"`
}
