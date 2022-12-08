package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

func AzRBACCommand(c CloudFoxRBACclient, tenantID, subscriptionID, outputFormat string, verbosity int) error {

	var header []string
	var body [][]string
	var fileNameWithoutExtension, controlMessagePrefix string
	outputDirectory := filepath.Join(globals.CLOUDFOX_BASE_OUTPUT_DIRECTORY, globals.AZ_OUTPUT_DIRECTORY)

	switch tenantID {
	case "": // TO-DO: add an option for the interactive menu: ./cloudfox azure rbac
		return fmt.Errorf(
			"[%s] please select a valid tenant ID",
			color.CyanString(globals.AZ_RBAC_MODULE_NAME))

	default:
		switch subscriptionID {
		case "": // ./cloudfox azure rbac -t TENANT_ID
			fmt.Printf(
				"[%s] Enumerating Azure RBAC assignments for all subscriptions in tenant %s\n",
				color.CyanString(globals.AZ_RBAC_MODULE_NAME),
				tenantID)

			subIDs := getSubscriptionIDsForTenant(tenantID)
			c.initialize(tenantID, subIDs)
			var b [][]string
			for _, subID := range subIDs {
				header, b = c.GetRelevantRBACData(tenantID, subID)
				body = append(body, b...)
			}
			fileNameWithoutExtension = fmt.Sprintf("rbac-tenant-%s", tenantID)
			controlMessagePrefix = fmt.Sprintf("ten-%s", tenantID)

		default: // ./cloudfox azure rbac -t TENANT_ID -s SUBSCRIPTION_ID
			fmt.Printf(
				"[%s] Enumerating Azure RBAC assignments for the single subscription %s\n",
				color.CyanString(globals.AZ_RBAC_MODULE_NAME),
				subscriptionID)
			c.initialize(tenantID, []string{subscriptionID})
			header, body = c.GetRelevantRBACData(tenantID, subscriptionID)
			fileNameWithoutExtension = fmt.Sprintf("rbac-sub-%s", subscriptionID)
			controlMessagePrefix = fmt.Sprintf("sub-%s", subscriptionID)
		}
	}

	utils.OutputSelector(verbosity, outputFormat, header, body, outputDirectory, fileNameWithoutExtension, globals.AZ_RBAC_MODULE_NAME, controlMessagePrefix)
	return nil
}

type CloudFoxRBACclient struct {
	roleAssignments []authorization.RoleAssignment
	roleDefinitions []authorization.RoleDefinition
	AADUsers        []graphrbac.User
}

func (c *CloudFoxRBACclient) initialize(tenantID string, subscriptionIDs []string) error {
	var err error
	var u []graphrbac.User
	var rd []authorization.RoleDefinition
	var ra []authorization.RoleAssignment

	for _, subID := range subscriptionIDs {
		u, err = getAzureADUsers(tenantID)
		if err != nil {
			return fmt.Errorf(
				"[%s] failed to get users for tenant %s: %s",
				color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME),
				tenantID,
				err)
		}
		c.AADUsers = append(c.AADUsers, u...)
		rd, err = getRoleDefinitions(subID)
		if err != nil {
			fmt.Printf(
				"[%s] failed to get role definitions for subscription %s: %s. Skipping it.\n",
				color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME),
				subID,
				err)
		}
		c.roleDefinitions = append(c.roleDefinitions, rd...)
		ra, err = getRoleAssignments(subID)
		if err != nil {
			fmt.Printf(
				"[%s] failed to get role assignments for subscription %s: %s. Skipping it.\n",
				color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME),
				subID,
				err)
		}
		c.roleAssignments = append(c.roleAssignments, ra...)
	}
	return nil
}

func (c *CloudFoxRBACclient) GetRelevantRBACData(tenantID, subscriptionID string) ([]string, [][]string) {
	header := []string{"Tenant ID", "Tenant Name", "Domain", "User Name", "Role Name", "Role Scope"}
	var body [][]string
	var extract RoleBindingRelevantData
	var results []RoleBindingRelevantData

	for _, ra := range c.roleAssignments {
		extract.tenantID = tenantID
		extract.subscriptionID = subscriptionID
		extract.roleScope = ptr.ToString(ra.Properties.Scope)
		findUser(c.AADUsers, ra, &extract)
		findRole(c.roleDefinitions, ra, &extract)
		results = append(results, extract)
	}

	for _, r := range results {
		body = append(body,
			[]string{
				r.tenantID,
				r.userDisplayName,
				r.roleName,
				r.roleScope,
			})
	}
	return header, body
}

func findUser(users []graphrbac.User, roleAssignment authorization.RoleAssignment, extract *RoleBindingRelevantData) {
	for _, u := range users {
		principalID := ptr.ToString(roleAssignment.Properties.PrincipalID)
		if ptr.ToString(u.ObjectID) == principalID {
			// Extract user data here
			extract.userDisplayName = ptr.ToString(u.DisplayName)
		}
	}
}

func findRole(roleDefinitions []authorization.RoleDefinition, roleAssignment authorization.RoleAssignment, extract *RoleBindingRelevantData) {
	// Find the role
	for _, rd := range roleDefinitions {
		roleDefinitionID := strings.Split(ptr.ToString(roleAssignment.Properties.RoleDefinitionID), "/")[len(strings.Split(ptr.ToString(roleAssignment.Properties.RoleDefinitionID), "/"))-1]
		rdID := strings.Split(ptr.ToString(rd.ID), "/")[len(strings.Split(ptr.ToString(rd.ID), "/"))-1]
		// Extract role data here
		if rdID == roleDefinitionID {
			extract.roleName = ptr.ToString(rd.RoleName)
		}
	}
}

type RoleBindingRelevantData struct {
	tenantID        string
	subscriptionID  string
	roleScope       string
	userDisplayName string
	roleName        string
}

var getAzureADUsers = getAzureADUsersOriginal

func getAzureADUsersOriginal(tenantID string) ([]graphrbac.User, error) {
	var users []graphrbac.User
	client := utils.GetAADUsersClient(tenantID)
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf(
				"[%s] could not enumerate users for tenant %s: %s",
				color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME),
				tenantID,
				err)
		}
		users = append(users, page.Values()...)
	}
	return users, nil
}

func mockedGetAzureADUsers(tenantID string) ([]graphrbac.User, error) {
	var users AzureADUsersTestFile

	file, err := os.ReadFile(globals.AAD_USERS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", globals.AAD_USERS_TEST_FILE)
	}
	err = json.Unmarshal(file, &users)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.AAD_USERS_TEST_FILE)
	}
	return users.AzureADUsers, nil
}

func generateAzureADUsersTestFIle(tenantID string) {
	// The READ-ONLY ObjectID attribute needs to be included manually in the test file
	// ObjectID *string `json:"objectId,omitempty"`
	users, err := getAzureADUsers(tenantID)
	if err != nil {
		log.Fatalf("could not enumerate users for tenant %s", tenantID)
	}
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

var getRoleDefinitions = getRoleDefinitionsOriginal

func getRoleDefinitionsOriginal(subscriptionID string) ([]authorization.RoleDefinition, error) {
	client := utils.GetRoleDefinitionsClient(subscriptionID)
	var roleDefinitions []authorization.RoleDefinition
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf(
				"[%s] could not fetch role definitions for subscription %s: %s",
				color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME),
				subscriptionID,
				err)
		}
		roleDefinitions = append(roleDefinitions, page.Values()...)
	}
	return roleDefinitions, nil
}

func mockedGetRoleDefinitions(subscriptionID string) ([]authorization.RoleDefinition, error) {
	var roleDefinitions RoleDefinitionTestFile
	file, err := os.ReadFile(globals.ROLE_DEFINITIONS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", globals.ROLE_DEFINITIONS_TEST_FILE)
	}
	err = json.Unmarshal(file, &roleDefinitions)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.ROLE_DEFINITIONS_TEST_FILE)
	}
	return roleDefinitions.RoleDefinitions, nil
}

func generateRoleDefinitionsTestFile(subscriptionID string) {
	// The READ-ONLY ID attribute needs to be included manually in the test file.
	// This attribute is the unique identifier for the role.
	// ID *string `json:"id,omitempty"`.

	roleDefinitions, err := getRoleDefinitions(subscriptionID)
	if err != nil {
		log.Fatal(err)
	}
	roleAssignments, err := getRoleAssignments(subscriptionID)
	if err != nil {
		log.Fatal(err)
	}
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
		log.Fatalf("could not marshall json for role definitions in subscription %s", subscriptionID)
	}

	err = os.WriteFile(globals.ROLE_DEFINITIONS_TEST_FILE, rolesjson, os.ModeAppend)
	if err != nil {
		log.Fatalf("could not write to role definitions test file %s", globals.ROLE_DEFINITIONS_TEST_FILE)
	}
}

type RoleDefinitionTestFile struct {
	RoleDefinitions []authorization.RoleDefinition `json:"roleDefinitions"`
}

var getRoleAssignments = getRoleAssignmentsOriginal

func getRoleAssignmentsOriginal(subscriptionID string) ([]authorization.RoleAssignment, error) {
	var roleAssignments []authorization.RoleAssignment
	client := utils.GetRoleAssignmentsClient(subscriptionID)
	for page, err := client.List(context.TODO(), ""); page.NotDone(); page.Next() {
		if err != nil {
			return nil, fmt.Errorf(
				"[%s] could not fetch role assignments for subscription %s",
				color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME),
				subscriptionID)
		}
		roleAssignments = append(roleAssignments, page.Values()...)
	}
	return roleAssignments, nil
}

func mockedGetRoleAssignments(subscriptionID string) ([]authorization.RoleAssignment, error) {
	var allRoleAssignments, roleAssignmentsResults []authorization.RoleAssignment
	file, err := os.ReadFile(globals.ROLE_ASSIGNMENTS_TEST_FILE)
	if err != nil {
		log.Fatalf("could not read file %s", globals.ROLE_ASSIGNMENTS_TEST_FILE)
	}
	err = json.Unmarshal(file, &allRoleAssignments)
	if err != nil {
		log.Fatalf("could not unmarshall file %s", globals.ROLE_ASSIGNMENTS_TEST_FILE)
	}
	for _, ra := range allRoleAssignments {
		roleAssignmentSubscriptionID := strings.Split(ptr.ToString(ra.Properties.RoleDefinitionID), "/")[2]
		if roleAssignmentSubscriptionID == subscriptionID {
			roleAssignmentsResults = append(roleAssignmentsResults, ra)
		}
	}
	return roleAssignmentsResults, nil
}

func generateRoleAssignmentsTestFile(subscriptionID string) {
	ra, err := getRoleAssignments(subscriptionID)
	if err != nil {
		log.Fatalf("could not generate role assignments for subscription %s", subscriptionID)
	}
	roleAssginments, err := json.Marshal(RoleAssignmentsTestFile{RoleAssignments: ra})
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
