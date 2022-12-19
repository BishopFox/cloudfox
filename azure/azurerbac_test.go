package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
)

func TestAzRBACCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure RBAC Command")

	// Test case parameters
	subtests := []struct {
		Name                    string
		AzTenantID              string
		AzSubscriptionID        string
		AzRGName                string
		AzVerbosity             int
		AzOutputFormat          string
		resourcesTestFile       string
		usersTestFile           string
		roleDefinitionsTestFile string
		roleAssignmentsTestFile string
	}{
		{
			Name:                    "./cloudfox azure rbac --tenant 11111111-1111-1111-1111-11111111",
			AzTenantID:              "11111111-1111-1111-1111-11111111",
			AzSubscriptionID:        "",
			AzOutputFormat:          "table",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			usersTestFile:           "./test-data/users.json",
			roleDefinitionsTestFile: "./test-data/role-definitions.json",
			roleAssignmentsTestFile: "./test-data/role-assignments.json",
		},
		{
			Name:                    "./cloudfox azure rbac --subscription AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			AzTenantID:              "",
			AzSubscriptionID:        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			AzOutputFormat:          "table",
			AzVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			usersTestFile:           "./test-data/users.json",
			roleDefinitionsTestFile: "./test-data/role-definitions.json",
			roleAssignmentsTestFile: "./test-data/role-assignments.json",
		},
	}
	utils.MockFileSystem(true)
	// Mocked functions to simulate Azure calls and responses
	getSubscriptions = mockedGetSubscriptions
	getAzureADUsers = mockedGetAzureADUsers
	getRoleDefinitions = mockedGetRoleDefinitions
	getRoleAssignments = mockedGetRoleAssignments

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.Name)

		// Test files used by mocked functions
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.AAD_USERS_TEST_FILE = s.usersTestFile
		globals.ROLE_DEFINITIONS_TEST_FILE = s.roleDefinitionsTestFile
		globals.ROLE_ASSIGNMENTS_TEST_FILE = s.roleAssignmentsTestFile

		if err := AzRBACCommand(s.AzTenantID, s.AzSubscriptionID, s.AzOutputFormat, s.AzVerbosity); err != nil {
			fmt.Println(err)
		}
	}
	fmt.Println()
}
