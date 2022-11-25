package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
)

func TestRBACCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure RBAC Command")

	// Test case parameters
	//utils.MockFileSystem(true)
	subtests := []struct {
		Name                    string
		AzTenantID              string
		AzSubscriptionID        string
		AzRGName                string
		AZSub                   string
		AzVerbosity             int
		AzOutputFormat          string
		resourcesTestFile       string
		usersTestFile           string
		roleDefinitionsTestFile string
		roleAssignmentsTestFile string
	}{
		{
			Name:                    "basic acceptance: rbacs in a single resource group",
			AzTenantID:              "11111111-1111-1111-1111-11111111",
			AzSubscriptionID:        "ResourceGroupA1",
			AzVerbosity:             2,
			AzOutputFormat:          "table",
			resourcesTestFile:       "./test-data/resources.json",
			usersTestFile:           "./test-data/users.json",
			roleDefinitionsTestFile: "./test-data/role-definitions.json",
			roleAssignmentsTestFile: "./test-data/role-assignments.json",
		},
	}
	utils.MockFileSystem(true)
	// Mocked functions to simulate Azure calls and responses
	GetSubscriptions = MockedGetSubscriptions
	GetAzureADUsers = MockedGetAzureADUsers
	GetRoleDefinitions = MockedGetRoleDefinitions
	GetRoleAssignments = MockedGetRoleAssignments

	for _, s := range subtests {
		fmt.Printf("[subtest] %s\n", s.Name)
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.AAD_USERS_TEST_FILE = s.usersTestFile
		globals.ROLE_DEFINITIONS_TEST_FILE = s.roleDefinitionsTestFile
		globals.ROLE_ASSIGNMENTS_TEST_FILE = s.roleAssignmentsTestFile
		AzRbacCommand(CloudFoxRBACclient{}, s.AzTenantID, "", s.AzOutputFormat, s.AzVerbosity)
	}
	fmt.Println()
}
