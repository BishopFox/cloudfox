package azure

import (
	"fmt"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
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
		usersTestFile           string
		roleDefinitionsTestFile string
		roleAssignmentsTestFile string
	}{
		{
			Name:                    "basic acceptance",
			AzTenantID:              "11111111-1111-1111-1111-11111111",
			AzSubscriptionID:        "AAAA",
			AzRGName:                "",
			AzVerbosity:             2,
			AzOutputFormat:          "table",
			usersTestFile:           "./test-data/users.json",
			roleDefinitionsTestFile: "./test-data/role-definitions.json",
			roleAssignmentsTestFile: "./test-data/role-assignments.json",
		},
	}
	// Mocked functions to simulate Azure calls and responses
	GetAzureADUsers = MockedGetAzureADUsers
	GetRoleDefinitions = MockedGetRoleDefinitions
	GetRoleAssignments = MockedGetRoleAssignments

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.Name)
		globals.AAD_USERS_TEST_FILE = s.usersTestFile
		globals.ROLE_DEFINITIONS_TEST_FILE = s.roleDefinitionsTestFile
		globals.ROLE_ASSIGNMENTS_TEST_FILE = s.roleAssignmentsTestFile
		ra := getRoleAssignments("ede6a6a8-1ecc-4810-a4dc-9c78ebdc0820")
		fmt.Println(ra)
	}
}
