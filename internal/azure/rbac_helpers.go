package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	armauthorizationv2 "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// RBACRow is the enriched RBAC row
type RBACRow struct {
	SubscriptionID                   string
	SubscriptionName                 string
	Principal                        string
	PrincipalType                    string
	RoleName                         string
	Scope                            string
	PrincipalUPN                     string
	PrincipalName                    string
	TenantScope                      string
	tenantID                         string
	tenantName                       string
	SubscriptionScope                string
	ResourceGroupScope               string
	ProvidersResources               string
	FullScope                        string
	Condition                        string
	DelegatedManagedIdentityResource string
	DangerLevel                      string
	RawRoleDefinition                *armauthorizationv2.RoleDefinition
	RawRoleAssignment                *armauthorizationv2.RoleAssignment
}

type RBACOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

var RBACHeader = []string{
	"Principal GUID",
	"Principal Name / Application Name",
	"Principal UPN / Application ID",
	"Principal Type",
	"Role Name",
	"Providers/Resources",
	"Tenant Scope",
	"Subscription Scope",
	"Resource Group Scope",
	"Full Scope",
	"Condition",
	"Delegated Managed Identity Resource",
}

// GroupByUserSubscriptionRole groups RBAC rows hierarchically: User → Subscription → Role
func GroupByUserSubscriptionRole(rows []RBACRow) []internal.TableFile {
	// Map: user → subscription → []RBACRow
	userMap := make(map[string]map[string][]RBACRow)
	for _, row := range rows {
		if _, ok := userMap[row.Principal]; !ok {
			userMap[row.Principal] = make(map[string][]RBACRow)
		}
		userMap[row.Principal][row.SubscriptionID] = append(userMap[row.Principal][row.SubscriptionID], row)
	}

	// Sort principals alphabetically
	principals := make([]string, 0, len(userMap))
	for p := range userMap {
		principals = append(principals, p)
	}
	sort.Strings(principals)

	tableFiles := []internal.TableFile{}
	header := []string{
		"Principal Name",
		"Principal UPN",
		"Principal",
		"Principal Type",
		"Role Name",
		"Scope",
		"Subscription ID",
	}

	for _, principal := range principals {
		subMap := userMap[principal]

		// Sort subscriptions alphabetically
		subscriptions := make([]string, 0, len(subMap))
		for sub := range subMap {
			subscriptions = append(subscriptions, sub)
		}
		sort.Strings(subscriptions)

		for _, subID := range subscriptions {
			rowsForSub := subMap[subID]

			// Sort roles alphabetically
			sort.Slice(rowsForSub, func(i, j int) bool {
				return rowsForSub[i].RoleName < rowsForSub[j].RoleName
			})

			// Build table rows
			tableRows := [][]string{}
			for _, r := range rowsForSub {
				tableRows = append(tableRows, []string{
					r.PrincipalName,
					r.PrincipalUPN,
					r.Principal,
					r.PrincipalType,
					r.RoleName,
					r.Scope,
					r.SubscriptionID,
				})
			}

			tf := internal.TableFile{
				Name:   "rbac-" + principal + "-" + subID,
				Header: header,
				Body:   tableRows,
			}

			tableFiles = append(tableFiles, tf)
		}
	}

	return tableFiles
}

// GroupByRole groups RBAC rows hierarchically: Role → Subscription → Principal
func GroupByRole(rows []RBACRow) []internal.TableFile {
	// Map: role → subscription → []RBACRow
	roleMap := make(map[string]map[string][]RBACRow)
	for _, row := range rows {
		if _, ok := roleMap[row.RoleName]; !ok {
			roleMap[row.RoleName] = make(map[string][]RBACRow)
		}
		roleMap[row.RoleName][row.SubscriptionID] = append(roleMap[row.RoleName][row.SubscriptionID], row)
	}

	// Sort roles alphabetically
	roles := make([]string, 0, len(roleMap))
	for r := range roleMap {
		roles = append(roles, r)
	}
	sort.Strings(roles)

	tableFiles := []internal.TableFile{}
	header := []string{
		"Principal Name",
		"Principal UPN",
		"Principal",
		"Principal Type",
		"Role Name",
		"Scope",
		"Subscription ID",
	}

	for _, role := range roles {
		subMap := roleMap[role]

		// Sort subscriptions alphabetically
		subscriptions := make([]string, 0, len(subMap))
		for sub := range subMap {
			subscriptions = append(subscriptions, sub)
		}
		sort.Strings(subscriptions)

		for _, subID := range subscriptions {
			rowsForSub := subMap[subID]

			// Sort principals alphabetically
			sort.Slice(rowsForSub, func(i, j int) bool {
				return rowsForSub[i].Principal < rowsForSub[j].Principal
			})

			// Build table rows
			tableRows := [][]string{}
			for _, r := range rowsForSub {
				tableRows = append(tableRows, []string{
					r.PrincipalName,
					r.PrincipalUPN,
					r.Principal,
					r.PrincipalType,
					r.RoleName,
					r.Scope,
					r.SubscriptionID,
				})
			}

			tf := internal.TableFile{
				Name:   "rbac-role-" + role + "-" + subID,
				Header: header,
				Body:   tableRows,
			}

			tableFiles = append(tableFiles, tf)
		}
	}

	return tableFiles
}

// GroupByScope groups RBAC rows hierarchically: Scope → Subscription → Principal → Role
func GroupByScope(rows []RBACRow) []internal.TableFile {
	// Map: scope → subscription → []RBACRow
	scopeMap := make(map[string]map[string][]RBACRow)
	for _, row := range rows {
		if _, ok := scopeMap[row.Scope]; !ok {
			scopeMap[row.Scope] = make(map[string][]RBACRow)
		}
		scopeMap[row.Scope][row.SubscriptionID] = append(scopeMap[row.Scope][row.SubscriptionID], row)
	}

	// Sort scopes alphabetically
	scopes := make([]string, 0, len(scopeMap))
	for s := range scopeMap {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)

	tableFiles := []internal.TableFile{}
	header := []string{
		"Principal Name",
		"Principal UPN",
		"Principal",
		"Principal Type",
		"Role Name",
		"Scope",
		"Subscription ID",
	}

	for _, scope := range scopes {
		subMap := scopeMap[scope]

		// Sort subscriptions alphabetically
		subscriptions := make([]string, 0, len(subMap))
		for sub := range subMap {
			subscriptions = append(subscriptions, sub)
		}
		sort.Strings(subscriptions)

		for _, subID := range subscriptions {
			rowsForSub := subMap[subID]

			// Sort principals alphabetically
			sort.Slice(rowsForSub, func(i, j int) bool {
				if rowsForSub[i].Principal == rowsForSub[j].Principal {
					return rowsForSub[i].RoleName < rowsForSub[j].RoleName
				}
				return rowsForSub[i].Principal < rowsForSub[j].Principal
			})

			tableRows := [][]string{}
			for _, r := range rowsForSub {
				tableRows = append(tableRows, []string{
					r.PrincipalName,
					r.PrincipalUPN,
					r.Principal,
					r.PrincipalType,
					r.RoleName,
					r.Scope,
					r.SubscriptionID,
				})
			}

			tf := internal.TableFile{
				Name:   "rbac-scope-" + scope + "-" + subID,
				Header: header,
				Body:   tableRows,
			}

			tableFiles = append(tableFiles, tf)
		}
	}

	return tableFiles
}

// ResolvePrincipalType returns a human-readable principal type given a principal ID.
func ResolvePrincipalType(principalID string) string {
	if principalID == "" {
		return "Unknown"
	}

	principalID = strings.ToLower(principalID)

	switch {
	case strings.HasPrefix(principalID, "sp-") || strings.HasPrefix(principalID, "serviceprincipal"):
		return "ServicePrincipal"
	case strings.HasPrefix(principalID, "mi-") || strings.HasPrefix(principalID, "managedidentity"):
		return "ManagedIdentity"
	case strings.HasPrefix(principalID, "b2b-") || strings.HasSuffix(principalID, "#ext#@"):
		return "GuestUser"
	case strings.HasPrefix(principalID, "g-") || strings.HasPrefix(principalID, "group"):
		return "Group"
	default:
		return "User"
	}
}

// GetDangerLevel returns a string representing how "dangerous" a role is
func GetDangerLevel(roleName string) string {
	if roleName == "" {
		return "Unknown"
	}

	roleNameLower := strings.ToLower(roleName)

	switch roleNameLower {
	case "owner":
		return "High/Owner"
	case "contributor":
		return "Medium/Contributor"
	case "user access administrator":
		return "High/User access administrator"
	default:
		// For custom roles, you could enhance this later by inspecting the role's Actions
		if strings.Contains(roleNameLower, "write") || strings.Contains(roleNameLower, "delete") || strings.Contains(roleNameLower, "roleassignment") {
			return "Medium"
		}
		return "Low"
	}
}

// GetPrincipalInfo resolves an Azure AD principal ID to UPN and display name
// Directory.Read.All or similar Graph API permissions required
func GetPrincipalInfo(session *SafeSession, principalID string) (PrincipalInfo, error) {
	if principalID == "" {
		return PrincipalInfo{}, fmt.Errorf("principalID is empty")
	}

	// Get a token for Microsoft Graph
	//cred, _ := azidentity.NewDefaultAzureCredential(nil)
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		return PrincipalInfo{}, fmt.Errorf("failed to get ARM token for principal %s: %v", principalID, err)
	}

	//	cred := &StaticTokenCredential{Token: token}

	// Query Graph API for directory object with retry logic
	url := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/directoryObjects/%s?$select=displayName,userPrincipalName,mail,appId,onPremisesSamAccountName",
		principalID,
	)

	// Use GraphAPIRequestWithRetry for automatic throttle handling
	body, err := GraphAPIRequestWithRetry(context.Background(), "GET", url, token)
	if err != nil {
		return PrincipalInfo{}, fmt.Errorf("failed to query Graph API: %v", err)
	}

	var data struct {
		ODataType            string `json:"@odata.type"`
		DisplayName          string `json:"displayName"`
		UserPrincipalName    string `json:"userPrincipalName"`
		Mail                 string `json:"mail"`
		AppID                string `json:"appId"`
		OnPremisesSamAccount string `json:"onPremisesSamAccountName"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return PrincipalInfo{}, fmt.Errorf("failed to decode Graph API response: %v", err)
	}

	// Determine object type
	objectType := "Unknown"
	switch data.ODataType {
	case "#microsoft.graph.user":
		objectType = "User"
	case "#microsoft.graph.group":
		objectType = "Group"
	case "#microsoft.graph.servicePrincipal":
		objectType = "ServicePrincipal"
	}

	// Fallback logic for UPN
	upn := data.UserPrincipalName
	if upn == "" {
		if data.Mail != "" {
			upn = data.Mail
		} else if data.AppID != "" {
			upn = data.AppID // Service principal fallback
		} else if data.OnPremisesSamAccount != "" {
			upn = data.OnPremisesSamAccount
		} else {
			upn = principalID // Last resort: use the ID itself
		}
	}

	// Fallback for Name
	name := data.DisplayName
	if name == "" {
		name = upn
	}

	return PrincipalInfo{
		UserPrincipalName: upn,
		DisplayName:       name,
		UserType:          objectType,
	}, nil
}

func DedupeRBACRows(rows []RBACRow) []RBACRow {
	seen := make(map[string]struct{})
	result := []RBACRow{}

	for _, r := range rows {
		key := fmt.Sprintf("%s|%s|%s", r.Principal, r.RoleName, r.Scope)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

// NormalizeScope converts a raw Azure scope into human-friendly components.
// Example: /subscriptions/1234/resourceGroups/myRG → Tenant="", Subscription="SubName (1234)", RG="myRG"
func NormalizeScope(raw string, tenantName string, subNameMap map[string]string) (tenant, subscription, rg string) {
	if raw == "/" {
		return "*", "*", "*"
	}

	parts := strings.Split(strings.Trim(raw, "/"), "/")
	if len(parts) == 0 {
		return "", "", ""
	}

	// subscription-level
	if len(parts) >= 2 && parts[0] == "subscriptions" {
		subID := parts[1]
		subName := subNameMap[subID]
		if subName == "" {
			subName = subID
		}
		subscription = fmt.Sprintf("%s (%s)", subName, subID)

		// resource group-level
		if len(parts) >= 4 && parts[2] == "resourceGroups" {
			rg = parts[3]
		}
	}

	// tenant-level
	if raw == "/" || strings.HasPrefix(raw, "/providers/Microsoft.Management/managementGroups/") {
		tenant = tenantName
	}

	return tenant, subscription, rg
}

// AddRowsAndLoot adds RBAC rows and loot entries to the RBACOutput
func (o *RBACOutput) AddRowsAndLoot(rows []RBACRow, lootEntries []string, tenantName string) {
	// Build table rows
	if len(rows) > 0 {
		body := [][]string{}
		for _, r := range rows {
			body = append(body, []string{
				r.Principal,
				r.PrincipalName,
				r.PrincipalUPN,
				r.PrincipalType,
				r.RoleName,
				r.ProvidersResources,
				r.TenantScope,
				r.SubscriptionScope,
				r.ResourceGroupScope,
				r.FullScope,
				r.Condition,
				r.DelegatedManagedIdentityResource,
			})
		}

		o.Table = append(o.Table, internal.TableFile{
			Name:   fmt.Sprintf("rbac-%s", tenantName),
			Header: RBACHeader,
			Body:   body,
		})
	}

	// Add loot entries
	for _, l := range lootEntries {
		o.Loot = append(o.Loot, internal.LootFile{
			Name:     fmt.Sprintf("rbac-commands-%s", tenantName),
			Contents: l,
		})
	}
}

// AddRow adds a row + its loot commands to the output.
func (o *RBACOutput) AddRow(row RBACRow, lootCmds []string, tableName string) {
	// Convert the RBACRow into a single row for TableFile.Body
	body := [][]string{{
		row.Principal,
		row.PrincipalName,
		row.PrincipalUPN,
		row.PrincipalType,
		row.RoleName,
		row.ProvidersResources,
		row.TenantScope,
		row.SubscriptionScope,
		row.ResourceGroupScope,
		row.FullScope,
		row.Condition,
		row.DelegatedManagedIdentityResource,
	}}

	// Append to the Table slice
	o.Table = append(o.Table, internal.TableFile{
		Name:   tableName,
		Header: RBACHeader,
		Body:   body,
	})

	// Append each loot command to the Loot slice
	for _, cmd := range lootCmds {
		o.Loot = append(o.Loot, internal.LootFile{
			Name:     tableName + "-loot",
			Contents: cmd,
		})
	}
}

// TableFiles returns the table-ready rows.
func (o *RBACOutput) TableFiles() []internal.TableFile {
	return o.Table
}

// LootFiles returns the loot commands grouped by filename.
func (o *RBACOutput) LootFiles() []internal.LootFile {
	return o.Loot
}

// GetRoleAssignmentsForSubscription retrieves all role assignments for a given subscription
// Returns role assignments using the modern Azure SDK
func GetRoleAssignmentsForSubscription(ctx context.Context, session *SafeSession, subscriptionID string) ([]*armauthorizationv2.RoleAssignment, error) {
	// Get ARM token
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subscriptionID, err)
	}

	// Create credential
	cred := NewStaticTokenCredential(token)

	// Create role assignments client
	client, err := armauthorizationv2.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %v", err)
	}

	// List all role assignments for the subscription scope
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	pager := client.NewListForScopePager(scope, nil)

	var roleAssignments []*armauthorizationv2.RoleAssignment
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list role assignments: %v", err)
		}
		roleAssignments = append(roleAssignments, page.Value...)
	}

	return roleAssignments, nil
}
