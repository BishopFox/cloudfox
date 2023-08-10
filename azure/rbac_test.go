package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

func TestAzRBACCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure RBAC Command")

	// Test case parameters
	subtests := []struct {
		name                    string
		azTenantID              string
		azSubscriptionID        string
		azRGName                string
		azVerbosity             int
		azOutputFormat          string
		azOutputDirectory       string
		version                 string
		resourcesTestFile       string
		usersTestFile           string
		roleDefinitionsTestFile string
		roleAssignmentsTestFile string
		wrapTableOutput         bool
		azMergedTable           bool
	}{
		{
			name:                    "./cloudfox azure rbac --tenant 11111111-1111-1111-1111-11111111",
			azTenantID:              "11111111-1111-1111-1111-11111111",
			azSubscriptionID:        "",
			azOutputFormat:          "all",
			azOutputDirectory:       "~/.cloudfox",
			azVerbosity:             2,
			resourcesTestFile:       "./test-data/resources.json",
			usersTestFile:           "./test-data/users.json",
			roleDefinitionsTestFile: "./test-data/role-definitions.json",
			roleAssignmentsTestFile: "./test-data/role-assignments.json",
			version:                 "DEV",
			wrapTableOutput:         false,
			azMergedTable:           false,
		},
		{
			name:                    "./cloudfox azure rbac --subscription AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			azTenantID:              "",
			azSubscriptionID:        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			azOutputFormat:          "all",
			azOutputDirectory:       "~/.cloudfox",
			azVerbosity:             2,
			version:                 "DEV",
			resourcesTestFile:       "./test-data/resources.json",
			usersTestFile:           "./test-data/users.json",
			roleDefinitionsTestFile: "./test-data/role-definitions.json",
			roleAssignmentsTestFile: "./test-data/role-assignments.json",
			wrapTableOutput:         false,
			azMergedTable:           false,
		},
		{
			name:                    "./cloudfox azure rbac",
			azOutputFormat:          "all",
			azVerbosity:             2,
			azOutputDirectory:       "~/.cloudfox",
			version:                 "DEV",
			resourcesTestFile:       "./test-data/resources.json",
			usersTestFile:           "./test-data/users.json",
			roleDefinitionsTestFile: "./test-data/role-definitions.json",
			roleAssignmentsTestFile: "./test-data/role-assignments.json",
			wrapTableOutput:         false,
			azMergedTable:           false,
		},
	}
	internal.MockFileSystem(true)
	// Mocked functions to simulate Azure calls and responses
	GetSubscriptions = mockedGetSubscriptions
	getAzureADUsers = mockedGetAzureADUsers
	getRoleDefinitions = mockedGetRoleDefinitions
	getRoleAssignments = mockedGetRoleAssignments

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.name)

		// Test files used by mocked functions
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.AAD_USERS_TEST_FILE = s.usersTestFile
		globals.ROLE_DEFINITIONS_TEST_FILE = s.roleDefinitionsTestFile
		globals.ROLE_ASSIGNMENTS_TEST_FILE = s.roleAssignmentsTestFile

		if err := AzRBACCommand(s.azTenantID, s.azSubscriptionID, s.azOutputFormat, s.azOutputDirectory, s.version, 2, s.wrapTableOutput, s.azMergedTable); err != nil {
			fmt.Println(err)
		}
	}
	fmt.Println()
}
