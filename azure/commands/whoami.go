package commands

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armauthorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzWhoamiCommand = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{"who"},
	Short:   "Show Azure session details",
	Long: `
Show information about the current Azure identity, including:
- Email / UPN
- Tenant
- Subscriptions
- Role assignments (and whether they are PIM eligible)
- Optionally resource groups

Examples:
./cloudfox az whoami --tenant TENANT_ID
./cloudfox az whoami --subscription SUBSCRIPTION_ID`,
	Run: ListWhoami,
}

func init() {
	AzWhoamiCommand.Flags().BoolP("list-rgs", "l", false, "Drill down to the resource group level")
}

// ------------------------------
// Module struct (hybrid AWS/Azure pattern)
// ------------------------------
type WhoamiModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	UserType string
	ListRGs  bool
	RoleRows [][]string
	RGRows   [][]string
	LootMap  map[string]*internal.LootFile
}

// ------------------------------
// Output struct
// ------------------------------
type WhoamiOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o WhoamiOutput) TableFiles() []internal.TableFile { return o.Table }
func (o WhoamiOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListWhoami(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_WHOAMI_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Extract whoami-specific flags --------------------
	listRGs, _ := cmd.Flags().GetBool("list-rgs")

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		cmdCtx.Logger.InfoM(fmt.Sprintf("Whoami-specific flag - listRGs: %v", listRGs), globals.AZ_WHOAMI_MODULE_NAME)
	}

	// -------------------- Get user type (whoami-specific) --------------------
	userType := azinternal.GetUserType(cmdCtx.UserObjectID)

	// -------------------- Initialize module --------------------
	module := &WhoamiModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		UserType:        userType,
		ListRGs:         listRGs,
		RoleRows:        [][]string{},
		RGRows:          [][]string{},
		LootMap: map[string]*internal.LootFile{
			"whoami-commands": {Name: "whoami-commands", Contents: ""},
		},
	}

	// -------------------- Execute module (sequential for consolidated output) --------------------
	module.PrintWhoami(cmdCtx.Ctx, cmdCtx.Logger, cmdCtx.Subscriptions)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *WhoamiModule) PrintWhoami(ctx context.Context, logger internal.Logger, subscriptions []string) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_WHOAMI_MODULE_NAME)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_WHOAMI_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			for _, subID := range tenantCtx.Subscriptions {
				m.CommandCounter.Total++
				m.processSubscription(ctx, subID, logger)
			}

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating whoami for %d subscription(s)", len(subscriptions)), globals.AZ_WHOAMI_MODULE_NAME)
		for _, subID := range subscriptions {
			m.CommandCounter.Total++
			m.processSubscription(ctx, subID, logger)
		}
	}

	// -------------------- Write output --------------------
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *WhoamiModule) processSubscription(ctx context.Context, subscriptionID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subscriptionID)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get token for subscription %s: %v", subscriptionID, err), globals.AZ_WHOAMI_MODULE_NAME)
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}

	// -------------------- Role Assignments --------------------
	raClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create RoleAssignments client: %v", err), globals.AZ_WHOAMI_MODULE_NAME)
		}
		return
	}

	// Use API filter to automatically resolve group memberships and inherited assignments
	// Check management group hierarchy first (role assignments can be inherited from parent scopes)
	mgHierarchy := azinternal.GetManagementGroupHierarchy(ctx, m.Session, subscriptionID)

	// Get user's group memberships to check for group-based role assignments
	// The principalId filter does NOT expand group memberships - we must check them explicitly
	groupIDs := azinternal.GetUserGroupMemberships(ctx, m.Session, m.UserObjectID)
	//if len(groupIDs) > 0 {
	//	logger.InfoM(fmt.Sprintf("User is member of %d group(s), will check role assignments for all principals", len(groupIDs)), globals.AZ_WHOAMI_MODULE_NAME)
	//}

	// Build list of all principal IDs to check (user + all groups)
	principalIDs := []string{m.UserObjectID}
	principalIDs = append(principalIDs, groupIDs...)

	// Check role assignments at multiple scopes:
	// 1. Tenant root (/) - highest level, applies to all subscriptions
	// 2. Management group hierarchy - inherited by child subscriptions
	// 3. Subscription scope - direct subscription assignments

	// -------------------- Check Tenant Root Scope --------------------
	// Role assignments at "/" are inherited by all subscriptions but won't show up
	// in management group or subscription scope queries
	//logger.InfoM("Checking tenant root scope (/) for role assignments", globals.AZ_WHOAMI_MODULE_NAME)

	for _, principalID := range principalIDs {
		tenantRootPager := raClient.NewListForScopePager("/", &armauthorization.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalID)),
		})

		for tenantRootPager.More() {
			page, err := tenantRootPager.NextPage(ctx)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to get role assignments at tenant root for principal %s: %v", principalID, err), globals.AZ_WHOAMI_MODULE_NAME)
				}
				break
			}

			for _, ra := range page.Value {
				if ra.Properties == nil || ra.Properties.PrincipalID == nil {
					continue
				}

				roleDefID := azinternal.SafeStringPtr(ra.Properties.RoleDefinitionID)
				scope := azinternal.SafeStringPtr(ra.Properties.Scope)
				roleName := azinternal.GetRoleNameFromDefinitionID(ctx, m.Session, subscriptionID, roleDefID)

				assignedVia := "Direct"
				if *ra.Properties.PrincipalID != m.UserObjectID {
					assignedVia = "Group"
				}

				//logger.InfoM(fmt.Sprintf("Found role assignment at TENANT ROOT scope (%s): role=%s, scope=%s, principalID=%s",
				//	assignedVia, azinternal.SafeString(roleName), scope, *ra.Properties.PrincipalID), globals.AZ_WHOAMI_MODULE_NAME)

				m.RoleRows = append(m.RoleRows, []string{
					m.TenantName,
					m.TenantID,
					m.UserUPN,
					m.UserDisplayName,
					m.UserType,
					subscriptionID,
					subName,
					azinternal.SafeString(roleName),
					scope,
					assignedVia,
				})

				m.LootMap["whoami-commands"].Contents += fmt.Sprintf(
					"az role assignment list --assignee %s --scope %s\nGet-AzRoleAssignment -ObjectId %s -Scope %s\n\n",
					*ra.Properties.PrincipalID, scope, *ra.Properties.PrincipalID, scope)
			}
		}
	}

	// Check management group hierarchy first (role assignments can be inherited from parent scopes)
	mgHierarchy = azinternal.GetManagementGroupHierarchy(ctx, m.Session, subscriptionID)

	//if len(mgHierarchy) > 0 {
	//	logger.InfoM(fmt.Sprintf("Found %d management group(s) in hierarchy for subscription %s", len(mgHierarchy), subscriptionID), globals.AZ_WHOAMI_MODULE_NAME)
	//}

	// Enumerate role assignments at management group scopes (if any)
	// Check for each principal (user + all groups)
	// 	// Use API filter to check role assignments for user and all their groups
	for _, mgID := range mgHierarchy {
		mgScope := fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID)

		for _, principalID := range principalIDs {
			mgPager := raClient.NewListForScopePager(mgScope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
				Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalID)),
			})

			for mgPager.More() {
				page, err := mgPager.NextPage(ctx)
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to get role assignments at management group %s for principal %s: %v", mgID, principalID, err), globals.AZ_WHOAMI_MODULE_NAME)
					}
					break
				}

				for _, ra := range page.Value {
					if ra.Properties == nil || ra.Properties.PrincipalID == nil {
						continue
					}

					roleDefID := azinternal.SafeStringPtr(ra.Properties.RoleDefinitionID)
					scope := azinternal.SafeStringPtr(ra.Properties.Scope)
					roleName := azinternal.GetRoleNameFromDefinitionID(ctx, m.Session, subscriptionID, roleDefID)

					assignedVia := "Direct"
					if *ra.Properties.PrincipalID != m.UserObjectID {
						assignedVia = "Group"
					}

					//logger.InfoM(fmt.Sprintf("Found role assignment at MG scope (%s): role=%s, scope=%s, principalID=%s",
					//	assignedVia, azinternal.SafeString(roleName), scope, *ra.Properties.PrincipalID), globals.AZ_WHOAMI_MODULE_NAME)

					m.RoleRows = append(m.RoleRows, []string{
						m.UserUPN,
						m.UserDisplayName,
						m.UserType,
						subscriptionID,
						subName,
						azinternal.SafeString(roleName),
						scope,
						assignedVia,
					})

					m.LootMap["whoami-commands"].Contents += fmt.Sprintf(
						"az role assignment list --assignee %s --scope %s\nGet-AzRoleAssignment -ObjectId %s -Scope %s\n\n",
						*ra.Properties.PrincipalID, scope, *ra.Properties.PrincipalID, scope)
				}
			}
		}
	}

	// Enumerate role assignments at subscription scope (includes resource group and resource level assignments)
	// Check for each principal (user + all groups)
	subscriptionScope := fmt.Sprintf("/subscriptions/%s", subscriptionID)

	for _, principalID := range principalIDs {
		raPager := raClient.NewListForScopePager(subscriptionScope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalID)),
		})

		for raPager.More() {
			page, err := raPager.NextPage(ctx)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to list role assignments for sub %s, principal %s: %v", subscriptionID, principalID, err), globals.AZ_WHOAMI_MODULE_NAME)
				}
				break
			}

			for _, ra := range page.Value {
				if ra.Properties == nil || ra.Properties.PrincipalID == nil {
					continue
				}

				roleDefID := azinternal.SafeStringPtr(ra.Properties.RoleDefinitionID)
				scope := azinternal.SafeStringPtr(ra.Properties.Scope)
				roleName := azinternal.GetRoleNameFromDefinitionID(ctx, m.Session, subscriptionID, roleDefID)

				assignedVia := "Direct"
				if *ra.Properties.PrincipalID != m.UserObjectID {
					assignedVia = "Group"
				}

				//logger.InfoM(fmt.Sprintf("Found role assignment at subscription scope (%s): role=%s, scope=%s, principalID=%s",
				//	assignedVia, azinternal.SafeString(roleName), scope, *ra.Properties.PrincipalID), globals.AZ_WHOAMI_MODULE_NAME)

				m.RoleRows = append(m.RoleRows, []string{
					m.TenantName,
					m.TenantID,
					m.UserUPN,
					m.UserDisplayName,
					m.UserType,
					subscriptionID,
					subName,
					azinternal.SafeString(roleName),
					scope,
					assignedVia,
				})

				m.LootMap["whoami-commands"].Contents += fmt.Sprintf(
					"az role assignment list --assignee %s --subscription %s\nGet-AzRoleAssignment -ObjectId %s -Scope /subscriptions/%s\n\n",
					*ra.Properties.PrincipalID, subscriptionID, *ra.Properties.PrincipalID, subscriptionID)
			}

		}
	}

	// -------------------- Check PIM (Privileged Identity Management) Assignments --------------------
	// PIM-eligible and active role assignments are tracked separately from permanent RBAC assignments
	//logger.InfoM("Checking PIM role eligibility and active assignments", globals.AZ_WHOAMI_MODULE_NAME)

	// Check role eligibility (what roles user is eligible to activate)
	pimEligibilityURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subscriptionID)
	pimEligibilityBody, err := azinternal.HTTPRequestWithRetry(ctx, "GET", pimEligibilityURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err == nil {
		var pimData struct {
			Value []struct {
				Properties struct {
					PrincipalID        string `json:"principalId"`
					RoleDefinitionID   string `json:"roleDefinitionId"`
					Scope              string `json:"scope"`
					Status             string `json:"status"`
					ExpandedProperties struct {
						Principal struct {
							DisplayName string `json:"displayName"`
							Type        string `json:"type"`
						} `json:"principal"`
						RoleDefinition struct {
							DisplayName string `json:"displayName"`
						} `json:"roleDefinition"`
					} `json:"expandedProperties"`
				} `json:"properties"`
			} `json:"value"`
		}

		if json.Unmarshal(pimEligibilityBody, &pimData) == nil {
			for _, pimAssignment := range pimData.Value {
				// Check if this PIM assignment is for the user or one of their groups
				principalID := pimAssignment.Properties.PrincipalID
				isRelevant := principalID == m.UserObjectID
				for _, groupID := range groupIDs {
					if principalID == groupID {
						isRelevant = true
						break
					}
				}

				if !isRelevant {
					continue
				}

				roleName := pimAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName
				scope := pimAssignment.Properties.Scope
				//status := pimAssignment.Properties.Status
				principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

				assignedVia := "Direct (PIM Eligible)"
				if principalType == "Group" {
					assignedVia = "Group (PIM Eligible)"
				}

				//logger.InfoM(fmt.Sprintf("Found PIM role eligibility (%s): role=%s, scope=%s, status=%s, principalID=%s",
				//	assignedVia, roleName, scope, status, principalID), globals.AZ_WHOAMI_MODULE_NAME)

				m.RoleRows = append(m.RoleRows, []string{
					m.UserUPN,
					m.UserDisplayName,
					m.UserType,
					subscriptionID,
					subName,
					roleName,
					scope,
					assignedVia,
				})

				m.LootMap["whoami-commands"].Contents += fmt.Sprintf(
					"# PIM Eligible Role - Activate with Azure Portal or:\naz rest --method post --url 'https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/new?api-version=2020-10-01' --body '{\"properties\":{\"principalId\":\"%s\",\"roleDefinitionId\":\"%s\",\"requestType\":\"SelfActivate\"}}'\n\n",
					scope, m.UserObjectID, pimAssignment.Properties.RoleDefinitionID)
			}
		}
	}

	// Check active PIM assignments (currently activated roles)
	pimActiveURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subscriptionID)
	pimActiveBody, err := azinternal.HTTPRequestWithRetry(ctx, "GET", pimActiveURL, token, nil, azinternal.DefaultRateLimitConfig())
	if err == nil {
		var pimData struct {
			Value []struct {
				Properties struct {
					PrincipalID        string `json:"principalId"`
					RoleDefinitionID   string `json:"roleDefinitionId"`
					Scope              string `json:"scope"`
					ExpandedProperties struct {
						Principal struct {
							DisplayName string `json:"displayName"`
							Type        string `json:"type"`
						} `json:"principal"`
						RoleDefinition struct {
							DisplayName string `json:"displayName"`
						} `json:"roleDefinition"`
					} `json:"expandedProperties"`
				} `json:"properties"`
			} `json:"value"`
		}

		if json.Unmarshal(pimActiveBody, &pimData) == nil {
			for _, pimAssignment := range pimData.Value {
				// Check if this PIM assignment is for the user or one of their groups
				principalID := pimAssignment.Properties.PrincipalID
				isRelevant := principalID == m.UserObjectID
				for _, groupID := range groupIDs {
					if principalID == groupID {
						isRelevant = true
						break
					}
				}

				if !isRelevant {
					continue
				}

				roleName := pimAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName
				scope := pimAssignment.Properties.Scope
				principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

				assignedVia := "Direct (PIM Active)"
				if principalType == "Group" {
					assignedVia = "Group (PIM Active)"
				}

				//logger.InfoM(fmt.Sprintf("Found active PIM role assignment (%s): role=%s, scope=%s, principalID=%s",
				//	assignedVia, roleName, scope, principalID), globals.AZ_WHOAMI_MODULE_NAME)

				m.RoleRows = append(m.RoleRows, []string{
					m.UserUPN,
					m.UserDisplayName,
					m.UserType,
					subscriptionID,
					subName,
					roleName,
					scope,
					assignedVia,
				})

				m.LootMap["whoami-commands"].Contents += fmt.Sprintf(
					"az role assignment list --assignee %s --subscription %s\nGet-AzRoleAssignment -ObjectId %s -Scope /subscriptions/%s\n\n",
					principalID, subscriptionID, principalID, subscriptionID)
			}
		}
	}

	// -------------------- Resource Groups (optional) --------------------
	if m.ListRGs {
		rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to create RG client for sub %s: %v", subscriptionID, err), globals.AZ_WHOAMI_MODULE_NAME)
			}
			return
		}

		rgPager := rgClient.NewListPager(nil)
		for rgPager.More() {
			page, err := rgPager.NextPage(ctx)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to list resource groups for sub %s: %v", subscriptionID, err), globals.AZ_WHOAMI_MODULE_NAME)
				}
				break
			}

			for _, rg := range page.Value {
				rgName := azinternal.SafeStringPtr(rg.Name)

				m.RGRows = append(m.RGRows, []string{
					m.TenantName,
					m.TenantID,
					m.UserUPN,
					m.UserDisplayName,
					m.UserType,
					subscriptionID,
					subName,
					rgName,
					azinternal.SafeStringPtr(rg.Location),
				})

				m.LootMap["whoami-commands"].Contents += fmt.Sprintf(
					"az group show --name %s --subscription %s\nGet-AzResourceGroup -Name %s -SubscriptionId %s\n\n",
					rgName, subscriptionID, rgName, subscriptionID)
			}
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *WhoamiModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Always include role assignments table
	roleTable := internal.TableFile{
		Name:   "whoami-roles",
		Header: []string{"Tenant Name", "Tenant ID", "Email / UPN", "Display Name", "User Type", "Subscription ID", "Subscription Name", "Role", "Scope", "Assigned Via"},
		Body:   m.RoleRows,
	}

	// Build list of tables conditionally
	tables := []internal.TableFile{roleTable}

	if m.ListRGs {
		rgTable := internal.TableFile{
			Name:   "whoami-rgs",
			Header: []string{"Tenant Name", "Tenant ID", "Email / UPN", "Display Name", "User Type", "Subscription ID", "Subscription Name", "Resource Group", "Region"},
			Body:   m.RGRows,
		}
		tables = append(tables, rgTable)
	}

	output := WhoamiOutput{
		Table: tables,
		Loot:  loot,
	}

	// Tenant-level module - always use tenant scope
	// Use nil for scopeNames to force usage of tenant GUID instead of tenant name
	scopeType := "tenant"
	scopeIDs := []string{m.TenantID}
	scopeNames := []string(nil)

	if err := internal.HandleOutputSmart("Azure", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable, scopeType, scopeIDs, scopeNames, m.UserUPN, output); err != nil {
		logger.ErrorM(fmt.Sprintf("Error handling output: %v", err), globals.AZ_WHOAMI_MODULE_NAME)
		m.CommandCounter.Error++
	} else if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Output handled successfully", globals.AZ_WHOAMI_MODULE_NAME)
	}
}
