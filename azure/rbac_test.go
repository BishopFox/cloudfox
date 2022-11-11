package azure

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"

	"github.com/BishopFox/cloudfox/constants"
)

func TestRBACCommand(t *testing.T) {
	GetAzureADUsers = MockedGetAzureADUsers
	GetRoleDefinitions = MockedGetRoleDefinitions
	GetRoleAssignments = MockedGetRoleAssignments

}

type InstancesClient struct {
}

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
