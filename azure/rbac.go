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
)

type AzRBACModule struct {
	AzClient            *internal.AzureClient
	Log                 *internal.Logger
}

func (m *AzRBACModule) AzRBACCommand() error {
	// setup logging client
	o := internal.OutputClient{
		Verbosity:     m.AzClient.AzVerbosity,
		CallingModule: globals.AZ_RBAC_MODULE_NAME,
		Table: internal.TableClient{
			Wrap: m.AzClient.AzWrapTable,
		},
	}
	// initiate command specific client
	var c CloudFoxRBACclient
	c.RBACModule = m
	// set up table vars
	var header []string
	var body [][]string


	if len(m.AzClient.AzTenants) > 0 {
		// cloudfox azure rbac --tenant [TENANT_ID | PRIMARY_DOMAIN]
		for _, AzTenant := range m.AzClient.AzTenants {

			var err error
			if err != nil {
				return err
			}
			o.PrefixIdentifier = *AzTenant.DefaultDomain
			o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, *AzTenant.DefaultDomain, "1-tenant-level")

			m.Log.Infof(nil, "Enumerating RBAC permissions for tenant %s (%s)", *AzTenant.DefaultDomain, *AzTenant.TenantID)
			header, body, err = m.getRBACperTenant(ptr.ToString(AzTenant.TenantID), c)
			if err != nil {
				return err
			}
			o.Table.TableFiles = append(o.Table.TableFiles,
				internal.TableFile{
					Header: header,
					Body:   body,
					Name:   fmt.Sprintf(globals.AZ_RBAC_MODULE_NAME)})

		}
	} else {
		// cloudfox azure rbac --subscription [SUBSCRIPTION_ID | SUBSCRIPTION_NAME]
		for _, AzSubscription := range m.AzClient.AzSubscriptions {
			tenantInfo := populateTenant(*AzSubscription.TenantID)
			o.PrefixIdentifier = ptr.ToString(AzSubscription.DisplayName)
			o.Table.DirectoryName = filepath.Join(m.AzClient.AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, ptr.ToString(tenantInfo.DefaultDomain), *AzSubscription.DisplayName)

			m.Log.Infof(nil, "Enumerating RBAC permissions for subscription %s (%s)", ptr.ToString(AzSubscription.DisplayName), *AzSubscription.SubscriptionID)
			header, body = m.getRBACperSubscription(ptr.ToString(tenantInfo.ID), *AzSubscription.SubscriptionID, c)
			o.Table.TableFiles = append(o.Table.TableFiles,
				internal.TableFile{
					Header: header,
					Body:   body,
					Name:   fmt.Sprintf(globals.AZ_RBAC_MODULE_NAME)})
		}

	}

	if body != nil {
		//internal.OutputSelector(m.AzClient.AzVerbosity, AzOutputFormat, header, body, outputDirectory, fileNameWithoutExtension, globals.AZ_RBAC_MODULE_NAME, AzWrapTable, controlMessagePrefix)
		o.WriteFullOutput(o.Table.TableFiles, nil)

	}
	return nil
}

func (m *AzRBACModule) getRBACperTenant(AzTenantID string, c CloudFoxRBACclient) ([]string, [][]string, error) {
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

func (m *AzRBACModule) getRBACperSubscription(AzTenantID, AzSubscriptionID string, c CloudFoxRBACclient) ([]string, [][]string) {
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
	RBACModule      *AzRBACModule
}

func (c *CloudFoxRBACclient) initialize(tenantID string, subscriptionIDs []string) error {
	var err error
	c.AADUsers = nil
	c.roleAssignments = nil
	c.roleDefinitions = nil

	c.AADUsers, err = c.RBACModule.getAzureADUsers(tenantID)
	if err != nil {
		return fmt.Errorf("[%s] failed to get users for tenant %s: %s", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), tenantID, err)
	}

	for _, subID := range subscriptionIDs {
		rd, err := c.RBACModule.getRoleDefinitions(subID)
		if err != nil {
			fmt.Printf("[%s] failed to get role definitions for subscription %s: %s. Skipping it.\n", color.New(color.FgCyan).Sprint(globals.AZ_RBAC_MODULE_NAME), subID, err)
		}
		c.roleDefinitions = append(c.roleDefinitions, rd...)

		ra, err := c.RBACModule.getRoleAssignments(subID)
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
	sort.Slice(sortedResults, func (i, j int) bool {
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

func (m *AzRBACModule) getAzureADUsers(tenantID string) ([]graphrbac.User, error) {
	return m.getAzureADUsersOriginal(tenantID)
}

func (m *AzRBACModule) getAzureADUsersOriginal(tenantID string) ([]graphrbac.User, error) {
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

func (m *AzRBACModule) mockedGetAzureADUsers(tenantID string) ([]graphrbac.User, error) {
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

func (m *AzRBACModule) generateAzureADUsersTestFIle(tenantID string) {
	// The READ-ONLY ObjectID attribute needs to be included manually in the test file
	// ObjectID *string `json:"objectId,omitempty"`
	users, err := m.getAzureADUsers(tenantID)
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

func (m *AzRBACModule) getRoleDefinitions(subscriptionID string) ([]authorization.RoleDefinition, error) {
	return m.getRoleDefinitionsOriginal(subscriptionID)
}

func (m *AzRBACModule) getRoleDefinitionsOriginal(subscriptionID string) ([]authorization.RoleDefinition, error) {
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

func (m *AzRBACModule) mockedGetRoleDefinitions(subscriptionID string) ([]authorization.RoleDefinition, error) {
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

func (m *AzRBACModule) generateRoleDefinitionsTestFile(subscriptionID string) {
	// The READ-ONLY ID attribute needs to be included manually in the test file.
	// This attribute is the unique identifier for the role.
	// ID *string `json:"id,omitempty"`.

	roleDefinitions, err := m.getRoleDefinitions(subscriptionID)
	if err != nil {
		log.Fatal(err)
	}
	roleAssignments, err := m.getRoleAssignments(subscriptionID)
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

func (m *AzRBACModule) getRoleAssignments(subscriptionID string) ([]authorization.RoleAssignment, error) {
	return m.getRoleAssignmentsOriginal(subscriptionID)
}

func (m *AzRBACModule) getRoleAssignmentsOriginal(subscriptionID string) ([]authorization.RoleAssignment, error) {
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

func (m *AzRBACModule) mockedGetRoleAssignments(subscriptionID string) ([]authorization.RoleAssignment, error) {
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

func (m *AzRBACModule) generateRoleAssignmentsTestFile(subscriptionID string) {
	ra, err := m.getRoleAssignments(subscriptionID)
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
