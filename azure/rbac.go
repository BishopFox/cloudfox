package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
)

/****************** REFACTORED CODE ******************/

var GetAzureADUsers = getAzureADUsers

func getAzureADUsers(tenantID string) []graphrbac.User {
	var users []graphrbac.User
	client := utils.GetAADUsersClient(tenantID)
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[%s] Could not enumerate users for tenant %s. Skipping it.\n", color.New(color.FgCyan).Sprint(constants.AZ_RBAC_MODULE_NAME), tenantID)
			continue
		}
		users = append(users, page.Values()...)
	}
	return users
}

var GetRoleDefinitions = getRoleDefinitions

func getRoleDefinitions(subscriptionID string) []authorization.RoleDefinition {
	client := utils.GetRoleDefinitionsClient(subscriptionID)
	var roleDefinitions []authorization.RoleDefinition
	for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {
		if err != nil {
			fmt.Printf("[%s] Could not enumerate roles for subscription %s. Skipping it.\n", color.New(color.FgCyan).Sprint(constants.AZ_RBAC_MODULE_NAME), subscriptionID)
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
			fmt.Printf("[%s] Could not role assignments for subscription %s. Skipping it.\n", color.New(color.FgCyan).Sprint(constants.AZ_RBAC_MODULE_NAME), subscriptionID)
			continue
		}
		roleAssignments = append(roleAssignments, page.Values()...)
	}
	return roleAssignments
}

/****************** LEGACY CODE ******************/

type RBACMapModule struct {
	// Tenants, Subs and RGs: map[TenantID]map[SubscriptionID][]ResourceGroups
	Scope map[string]map[string][]string
	// Module's Results
	Users           map[string]userObject
	Roles           map[string]roleDefinitionObject
	RoleAssignments []roleAssignmentObject
	// Used to store output data for pretty printing
}

func (m *RBACMapModule) RBACMap(verbosity int, outputFormat string, outputDirectory string, userFilter string) {
	m.getADUsers()
	m.getRoleDefinitions()
	m.getRoleAssignments()
	m.printRoleAssginments(verbosity, outputFormat, outputDirectory, userFilter)
}

func (m *RBACMapModule) printRoleAssginments(verbosity int, outputFormat string, outputDirectory string, userFilter string) {
	// Prepare table headers
	header := []string{
		"PRINCIPAL_NAME",
		"PRINCIPAL_ID",
		"PRINCIPAL_TYPE",
		"ROLE_NAME",
		"SCOPE_LEVEL",
		"SCOPE_NAME",
	}

	// Prepare table body
	var body [][]string
	for _, result := range m.RoleAssignments {
		if userFilter == "all" || userFilter == result.principalDisplayName {
			body = append(
				body, []string{
					result.principalDisplayName,
					result.principalID,
					result.principalType,
					result.roleName,
					result.scopeLevel,
					result.scopeLevelName,
				},
			)
		}
	}
	// Pretty prints output
	//m.output.OutputSelector(outputFormat)
	utils.OutputSelector(
		verbosity,
		outputFormat,
		header,
		body,
		outputDirectory,
		"rbac",
		constants.AZ_RBAC_MODULE_NAME,
		"RG_PLACEHOLDER",
	)
}

type userObject struct {
	displayName string
}

func (m *RBACMapModule) getADUsers() {
	m.Users = make(map[string]userObject)
	for tenantID := range m.Scope {
		// Scope: Tenant
		client := graphrbac.NewUsersClient(tenantID)
		client.Authorizer = utils.AzNewGraphAuthorizer(tenantID)
		fmt.Printf("[*] Entering tenant: %s\n", tenantID)
		for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {

			if err != nil {
				fmt.Printf("[-] Could not enumerate users for tenant %s. Skipping it. %s\n", tenantID, err)
				continue
			}

			fmt.Printf("[*] Enumerating %v users...\n", len(page.Values()))
			for _, user := range page.Values() {
				m.Users[ptr.ToString(user.ObjectID)] = userObject{
					displayName: ptr.ToString(user.DisplayName),
				}
			}
		}
		fmt.Printf("[*] Done!\n")
	}
}

type roleDefinitionObject struct {
	displayName string
}

func (m *RBACMapModule) getRoleDefinitions() {
	m.Roles = make(map[string]roleDefinitionObject)
	authorizer := utils.AzNewResourceManagerAuthorizer()
	for _, subscriptions := range m.Scope {
		// Scope: Tenant
		for sub := range subscriptions {
			// Scope: Subscription
			client := authorization.NewRoleDefinitionsClient(sub)
			client.Authorizer = authorizer

			for page, err := client.List(context.TODO(), "", ""); page.NotDone(); page.Next() {

				if err != nil {
					fmt.Printf("[-] Could not enumerate roles for subscription %s. Skipping it. %s\n", sub, err)
					continue
				}
				fmt.Printf("[*] Enumerating %v roles in subscription %s...\n", len(page.Values()), sub)
				for _, role := range page.Values() {
					m.Roles[ptr.ToString(role.Name)] = roleDefinitionObject{
						displayName: ptr.ToString(role.RoleDefinitionProperties.RoleName),
					}
				}
			}
		}
		fmt.Printf("[*] Done!\n")
	}
}

type roleAssignmentObject struct {
	roleName             string
	principalID          string
	principalType        string
	principalDisplayName string
	scopeLevel           string
	scopeLevelName       string
}

func (m *RBACMapModule) getRoleAssignments() {
	authorizer := utils.AzNewResourceManagerAuthorizer()

	for _, subscriptions := range m.Scope {
		// Scope: Tenant
		for sub := range subscriptions {
			// Scope: Subscription
			client := authorization.NewRoleAssignmentsClient(sub)
			client.Authorizer = authorizer

			for page, err := client.List(context.TODO(), ""); page.NotDone(); page.Next() {

				if err != nil {
					fmt.Printf("[-] Could not enumerate role assignments for subscription %s. Skipping it. %s\n", sub, err)
					continue
				}

				fmt.Printf("[*] Enumerating %v role assignments in subscription %s...\n", len(page.Values()), sub)
				for _, roleAssignment := range page.Values() {
					m.parseRoleAssignments(roleAssignment)
				}
			}
		}
		fmt.Printf("[*] Done!\n")
	}
}

func (m *RBACMapModule) parseRoleAssignments(roleAssignment authorization.RoleAssignment) {
	if roleAssignment.Properties != nil {
		// This API call only returns UUIDs for users and roles. It sucks.
		principalID := ptr.ToString(roleAssignment.Properties.PrincipalID)
		userName := m.Users[principalID].displayName
		var principalType string
		if userName == "" {
			userName = "None"
			principalType = "Other"
		} else {
			principalType = "User"
		}
		roleDefID := ptr.ToString(roleAssignment.Properties.RoleDefinitionID)
		roleID := strings.Split(roleDefID, "/")[len(strings.Split(roleDefID, "/"))-1]
		roleName := m.Roles[roleID].displayName
		scope := ptr.ToString(roleAssignment.Properties.Scope)
		scopeLevel := strings.Split(scope, "/")[len(strings.Split(scope, "/"))-2]
		scopeLevelName := strings.Split(scope, "/")[len(strings.Split(scope, "/"))-1]

		m.RoleAssignments = append(
			m.RoleAssignments,
			roleAssignmentObject{
				roleName:             roleName,
				principalID:          principalID,
				principalType:        principalType,
				principalDisplayName: userName,
				scopeLevel:           scopeLevel,
				scopeLevelName:       scopeLevelName,
			})
	}
}
