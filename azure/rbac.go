package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/graphrbac/graphrbac"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
)

func AzRBACCommand(AzTenantID, AzSubscription, AzOutputFormat, AzOutputDirectory, Version string, AzVerbosity int, AzWrapTable bool, AzMergedTable bool) error {
	// setup logging client
	o := internal.OutputClient{
		Verbosity:     AzVerbosity,
		CallingModule: globals.AZ_RBAC_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: AzWrapTable,
		},
	}
	// initiate command specific client
	var c CloudFoxRBACclient
	// set up table vars
	var header []string
	var body [][]string

	var AzSubscriptionInfo SubsriptionInfo

	if AzTenantID != "" && AzSubscription == "" {
		// cloudfox azure rbac --tenant [TENANT_ID | PRIMARY_DOMAIN]

		var err error
		tenantInfo := populateTenant(AzTenantID)
		if err != nil {
			return err
		}
		o.PrefixIdentifier = ptr.ToString(tenantInfo.DefaultDomain)
		o.Table.DirectoryName = filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), "1-tenant-level")

		fmt.Printf("[%s][%s] Enumerating RBAC permissions for tenant %s\n",
			color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)), color.CyanString(globals.AZ_RBAC_MODULE_NAME),
			fmt.Sprintf("%s (%s)", ptr.ToString(tenantInfo.DefaultDomain), ptr.ToString(tenantInfo.ID)))

		header, body, err = getRBACperTenant(ptr.ToString(tenantInfo.ID), c)
		if err != nil {
			return err
		}
		o.Table.TableFiles = append(o.Table.TableFiles,
			internal.TableFile{
				Header: header,
				Body:   body,
				Name:   fmt.Sprintf(globals.AZ_RBAC_MODULE_NAME)})

	} else if AzTenantID == "" && AzSubscription != "" {
		// cloudfox azure rbac --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		tenantID := ptr.ToString(GetTenantIDPerSubscription(AzSubscription))
		tenantInfo := populateTenant(tenantID)
		AzSubscriptionInfo = PopulateSubsriptionType(AzSubscription)
		o.PrefixIdentifier = AzSubscriptionInfo.Name
		o.Table.DirectoryName = filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), AzSubscriptionInfo.Name)

		fmt.Printf("[%s][%s] Enumerating RBAC permissions for subscription %s\n", color.CyanString(emoji.Sprintf(":fox:cloudfox %s :fox:", Version)), color.CyanString(globals.AZ_RBAC_MODULE_NAME),
			fmt.Sprintf("%s (%s)", AzSubscriptionInfo.Name, AzSubscriptionInfo.ID))
		header, body = getRBACperSubscription(ptr.ToString(tenantInfo.ID), AzSubscriptionInfo.ID, c)
		o.Table.TableFiles = append(o.Table.TableFiles,
			internal.TableFile{
				Header: header,
				Body:   body,
				Name:   fmt.Sprintf(globals.AZ_RBAC_MODULE_NAME)})

	} else {
		// Error: please make a valid flag selection
		fmt.Println("Please enter a valid input with a valid flag. Use --help for info.")
	}

	if body != nil {
		//internal.OutputSelector(AzVerbosity, AzOutputFormat, header, body, outputDirectory, fileNameWithoutExtension, globals.AZ_RBAC_MODULE_NAME, AzWrapTable, controlMessagePrefix)
		o.WriteFullOutput(o.Table.TableFiles, nil)

	}
	return nil
}

func getRBACperTenant(AzTenantID string, c CloudFoxRBACclient) ([]string, [][]string, error) {
	var selectedSubs, resultsHeader []string
	var resultsBody, b [][]string
	for _, s := range GetSubscriptions() {
		if ptr.ToString(s.TenantID) == AzTenantID {
			selectedSubs = append(selectedSubs, ptr.ToString(s.SubscriptionID))
		}
	}
	err := c.initialize(AzTenantID, selectedSubs)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range selectedSubs {
		resultsHeader, b = c.GetRelevantRBACData(AzTenantID, s)
		resultsBody = append(resultsBody, b...)
	}
	return resultsHeader, resultsBody, nil
}

func getRBACperSubscription(AzTenantID, AzSubscriptionID string, c CloudFoxRBACclient) ([]string, [][]string) {
	var resultsHeader []string
	var resultsBody [][]string
	for _, s := range GetSubscriptions() {
		if ptr.ToString(s.SubscriptionID) == AzSubscriptionID {
			c.initialize(AzTenantID, []string{ptr.ToString(s.SubscriptionID)})
			resultsHeader, resultsBody = c.GetRelevantRBACData(AzTenantID, ptr.ToString(s.SubscriptionID))
		}
	}
	return resultsHeader, resultsBody
}

type CloudFoxRBACclient struct {
	roleAssignments []authorization.RoleAssignment
	roleDefinitions []authorization.RoleDefinition
	AADUsers        []graphrbac.User
}

func (c *CloudFoxRBACclient) initialize(tenantID string, subscriptionIDs []string) error {
	var err error
	c.AADUsers = nil
	c.roleAssignments = nil
	c.roleDefinitions = nil

	c.AADUsers, err = getAzureADUsers(tenantID)
	if err != nil {
		return fmt.Errorf("[%s] failed to get users for tenant %s: %s", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), tenantID, err)
	}

	for _, subID := range subscriptionIDs {
		rd, err := getRoleDefinitions(subID)
		if err != nil {
			fmt.Printf("[%s] failed to get role definitions for subscription %s: %s. Skipping it.\n", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), subID, err)
		}
		c.roleDefinitions = append(c.roleDefinitions, rd...)

		ra, err := getRoleAssignments(subID)
		if err != nil {
			fmt.Printf("[%s] failed to get role assignments for subscription %s: %s. Skipping it.\n", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), subID, err)
		}
		c.roleAssignments = append(c.roleAssignments, ra...)
	}
	return nil
}

func (c *CloudFoxRBACclient) GetRelevantRBACData(tenantID, subscriptionID string) ([]string, [][]string) {
	header := []string{"User Name", "Role Name", "Role Scope"}
	var body [][]string
	var roleAssignmentRelevantData RoleAssignmentRelevantData
	var results []RoleAssignmentRelevantData

	for _, rb := range c.roleAssignments {
		roleAssignmentRelevantData.tenantID = tenantID
		roleAssignmentRelevantData.subscriptionID = subscriptionID
		roleAssignmentRelevantData.roleScope = ptr.ToString(rb.Properties.Scope)
		findUser(c.AADUsers, rb, &roleAssignmentRelevantData)
		findRole(c.roleDefinitions, rb, &roleAssignmentRelevantData)
		results = append(results, roleAssignmentRelevantData)
	}
	// Sort the results by userDisplayName using slice.Sort
	sortedResults := results
	sort.Slice(sortedResults, func(i, j int) bool {
		return sortedResults[i].userDisplayName < sortedResults[j].userDisplayName
	})

	for _, r := range sortedResults {
		body = append(body,
			[]string{
				r.userDisplayName,
				r.roleName,
				r.roleScope,
			})
	}
	return header, body
}

func findUser(users []graphrbac.User, roleAssignment authorization.RoleAssignment, roleAssignmentRelevantData *RoleAssignmentRelevantData) {
	for _, u := range users {
		principalID := ptr.ToString(roleAssignment.Properties.PrincipalID)
		if ptr.ToString(u.ObjectID) == principalID {
			// roleBindingRelevantData user data here
			roleAssignmentRelevantData.userDisplayName = ptr.ToString(u.DisplayName)
		}
	}
}

func findRole(roleDefinitions []authorization.RoleDefinition, roleAssignment authorization.RoleAssignment, roleAssignmentRelevantData *RoleAssignmentRelevantData) {
	// Find the role
	for _, rd := range roleDefinitions {
		roleDefinitionID := strings.Split(ptr.ToString(roleAssignment.Properties.RoleDefinitionID), "/")[len(strings.Split(ptr.ToString(roleAssignment.Properties.RoleDefinitionID), "/"))-1]
		rdID := strings.Split(ptr.ToString(rd.ID), "/")[len(strings.Split(ptr.ToString(rd.ID), "/"))-1]
		// roleBindingRelevantData role data here
		if rdID == roleDefinitionID {
			roleAssignmentRelevantData.roleName = ptr.ToString(rd.RoleName)
		}
	}
}

type RoleAssignmentRelevantData struct {
	tenantID        string
	subscriptionID  string
	roleScope       string
	userDisplayName string
	roleName        string
}

var getAzureADUsers = getAzureADUsersOriginal

func getAzureADUsersOriginal(tenantID string) ([]graphrbac.User, error) {
	var users []graphrbac.User
	client := internal.GetAADUsersClient(tenantID)
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
	client := internal.GetRoleDefinitionsClient(subscriptionID)
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
	client := internal.GetRoleAssignmentsClient(subscriptionID)
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
