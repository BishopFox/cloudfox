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
	utils.MockFileSystem(true)
	// Mocked functions to simulate Azure calls and responses
	GetAzureADUsers = MockedGetAzureADUsers
	GetRoleDefinitions = MockedGetRoleDefinitions
	GetRoleAssignments = MockedGetRoleAssignments

	for _, s := range subtests {
		fmt.Printf("[subtest] %s\n", s.Name)
		globals.AAD_USERS_TEST_FILE = s.usersTestFile
		globals.ROLE_DEFINITIONS_TEST_FILE = s.roleDefinitionsTestFile
		globals.ROLE_ASSIGNMENTS_TEST_FILE = s.roleAssignmentsTestFile

		c := CloudFoxRBACclient{}
		c.initialize(s.AzTenantID, s.AzSubscriptionID)
		header, body := c.GetRelevantRBACData(s.AzTenantID, s.AzSubscriptionID)

		outputFile := fmt.Sprintf("%s-test-file", globals.AZ_RBAC_MODULE_NAME)
		utils.OutputSelector(
			s.AzVerbosity,
			s.AzOutputFormat,
			header,
			body,
			globals.AZ_OUTPUT_DIRECTORY,
			outputFile,
			globals.AZ_RBAC_MODULE_NAME,
			"unitTest")
	}
	fmt.Println()
}
