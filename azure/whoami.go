package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/aws/smithy-go/ptr"
)

func AzWhoamiCommand(AzOutputDirectory, version string, AzWrapTable bool, AzVerbosity int) error {
	o := internal.OutputClient{
		Verbosity:     AzVerbosity,
		CallingModule: globals.AZ_WHOAMI_MODULE_NAME,
		Table: internal.TableClient{
			Wrap:          AzWrapTable,
			DirectoryName: filepath.Join(AzOutputDirectory, globals.CLOUDFOX_BASE_DIRECTORY, globals.AZ_DIR_BASE, "whoami-data"),
		},
	}

	fileTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
	o.PrefixIdentifier = "N/A"
	azureLogger.InfoM("Enumerating caller's Entra ID roles", globals.AZ_WHOAMI_MODULE_NAME)
	roleHeader, roleBody, roleErrors := getWhoamiEntraRoles()
	for _, err := range roleErrors {
		azureLogger.WarnM(fmt.Sprintf("Could not enumerate Entra ID roles: %s", err), globals.AZ_WHOAMI_MODULE_NAME)
	}
	if len(roleBody) > 0 {
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header: roleHeader,
			Body:   roleBody,
			Name:   globals.AZ_WHOAMI_MODULE_NAME + "-entra-memberships-" + fileTimestamp,
		})
	}

	azureLogger.InfoM("Enumerating caller's Azure RBAC roles", globals.AZ_WHOAMI_MODULE_NAME)
	rbacHeader, rbacBody, rbacErrors := getWhoamiAzureRBAC()
	for _, err := range rbacErrors {
		azureLogger.WarnM(fmt.Sprintf("Could not enumerate Azure RBAC roles: %s", err), globals.AZ_WHOAMI_MODULE_NAME)
	}
	if len(rbacBody) > 0 {
		o.Table.TableFiles = append(o.Table.TableFiles, internal.TableFile{
			Header: rbacHeader,
			Body:   rbacBody,
			Name:   globals.AZ_WHOAMI_MODULE_NAME + "-azure-rbac-" + fileTimestamp,
		})
	}
	//internal.PrintTableToScreen(header, body, AzWrapTable)

	o.WriteFullOutput(o.Table.TableFiles, nil)

	return nil
}

const microsoftGraphScope = "https://graph.microsoft.com/.default"

var (
	graphBaseURL        = "https://graph.microsoft.com/v1.0"
	graphHTTPClient     = http.DefaultClient
	getWhoamiEntraRoles = getWhoamiEntraRolesOriginal
	getWhoamiAzureRBAC  = getWhoamiAzureRBACOriginal
)

type entraRole struct {
	ODataType   string `json:"@odata.type"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

type entraRolePage struct {
	Value    []entraRole `json:"value"`
	NextLink string      `json:"@odata.nextLink"`
}

type graphErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type tokenClaims struct {
	ObjectID          string `json:"oid"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	AppID             string `json:"appid"`
	IdentityType      string `json:"idtyp"`
}

func getWhoamiEntraRolesOriginal() ([]string, [][]string, []error) {
	header := []string{"Tenant ID", "Tenant Primary Domain", "Principal ID", "Principal Name", "Principal Type", "Membership Type", "Membership Name", "Description"}
	var body [][]string
	var errs []error

	for _, tenant := range getTenants() {
		tenantID := ptr.ToString(tenant.TenantID)
		cred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: tenantID})
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: create Azure CLI credential: %w", tenantID, err))
			continue
		}

		claims, memberships, err := getCallerDirectoryMemberships(context.Background(), cred)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tenantID, err))
			continue
		}

		principalName := claims.PreferredUsername
		if principalName == "" {
			principalName = claims.Name
		}
		principalType := "User"
		if claims.IdentityType == "app" || (claims.PreferredUsername == "" && claims.AppID != "") {
			principalType = "Service Principal"
		}
		foundRole := false
		for _, membership := range memberships {
			membershipType := directoryMembershipType(membership.ODataType)
			if membershipType == "" {
				continue
			}
			membershipName := membership.DisplayName
			if membershipName == "" {
				membershipName = membership.ID
			}
			body = append(body, []string{tenantID, ptr.ToString(tenant.DefaultDomain), claims.ObjectID, principalName, principalType, membershipType, membershipName, membership.Description})
			foundRole = foundRole || membershipType == "Directory Role"
		}
		if !foundRole {
			body = append(body, []string{tenantID, ptr.ToString(tenant.DefaultDomain), claims.ObjectID, principalName, principalType, "Directory Role", "(none)", "No active Entra ID directory roles found"})
		}
	}

	sort.Slice(body, func(i, j int) bool {
		if body[i][0] == body[j][0] {
			if body[i][5] == body[j][5] {
				return body[i][6] < body[j][6]
			}
			return body[i][5] < body[j][5]
		}
		return body[i][0] < body[j][0]
	})
	return header, body, errs
}

func getCallerEntraRoles(ctx context.Context, cred azcore.TokenCredential) (tokenClaims, []entraRole, error) {
	claims, memberships, err := getCallerDirectoryMemberships(ctx, cred)
	if err != nil {
		return tokenClaims{}, nil, err
	}
	var roles []entraRole
	for _, object := range memberships {
		if directoryMembershipType(object.ODataType) == "Directory Role" {
			roles = append(roles, object)
		}
	}
	return claims, roles, nil
}

func directoryMembershipType(odataType string) string {
	switch {
	case strings.EqualFold(odataType, "#microsoft.graph.directoryRole"), strings.EqualFold(odataType, "#Microsoft.DirectoryServices.DirectoryRole"):
		return "Directory Role"
	case strings.EqualFold(odataType, "#microsoft.graph.group"), strings.EqualFold(odataType, "#Microsoft.DirectoryServices.Group"):
		return "Group"
	default:
		return ""
	}
}

func getCallerDirectoryMemberships(ctx context.Context, cred azcore.TokenCredential) (tokenClaims, []entraRole, error) {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{microsoftGraphScope}})
	if err != nil {
		return tokenClaims{}, nil, fmt.Errorf("get Microsoft Graph access token: %w", err)
	}

	claims, err := parseTokenClaims(token.Token)
	if err != nil {
		return tokenClaims{}, nil, err
	}

	nextLink := fmt.Sprintf("%s/directoryObjects/%s/transitiveMemberOf", strings.TrimRight(graphBaseURL, "/"), url.PathEscape(claims.ObjectID))
	var memberships []entraRole
	for nextLink != "" {
		page, err := getEntraRolePage(ctx, token.Token, nextLink)
		if err != nil {
			return tokenClaims{}, nil, err
		}
		memberships = append(memberships, page.Value...)
		nextLink = page.NextLink
	}
	return claims, memberships, nil
}

type rbacPrincipal struct {
	ID             string
	Name           string
	AssignmentType string
}

func getWhoamiAzureRBACOriginal() ([]string, [][]string, []error) {
	header := []string{"Tenant ID", "Subscription ID", "Subscription Name", "Principal ID", "Principal Name", "Assignment Via", "Azure RBAC Role", "Scope"}
	var body [][]string
	var errs []error

	for _, tenant := range getTenants() {
		tenantID := ptr.ToString(tenant.TenantID)
		cred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: tenantID})
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: create Azure CLI credential: %w", tenantID, err))
			continue
		}
		claims, memberships, err := getCallerDirectoryMemberships(context.Background(), cred)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: get caller's groups: %w", tenantID, err))
			continue
		}

		callerName := claims.PreferredUsername
		if callerName == "" {
			callerName = claims.Name
		}
		principals := map[string]rbacPrincipal{
			strings.ToLower(claims.ObjectID): {ID: claims.ObjectID, Name: callerName, AssignmentType: "Direct"},
		}
		for _, object := range memberships {
			if directoryMembershipType(object.ODataType) != "Group" {
				continue
			}
			groupName := object.DisplayName
			if groupName == "" {
				groupName = object.ID
			}
			principals[strings.ToLower(object.ID)] = rbacPrincipal{ID: object.ID, Name: groupName, AssignmentType: "Group"}
		}

		foundAssignment := false
		for _, subscription := range GetSubscriptionsPerTenantID(tenantID) {
			subscriptionID := ptr.ToString(subscription.SubscriptionID)
			assignments, err := getRoleAssignments(subscriptionID)
			if err != nil {
				errs = append(errs, fmt.Errorf("subscription %s: %w", subscriptionID, err))
				continue
			}
			definitions, err := getRoleDefinitions(subscriptionID)
			if err != nil {
				errs = append(errs, fmt.Errorf("subscription %s: %w", subscriptionID, err))
			}
			roleNames := roleDefinitionNames(definitions)
			rows := azureRBACRowsForSubscription(tenantID, subscriptionID, ptr.ToString(subscription.DisplayName), principals, roleNames, assignments)
			body = append(body, rows...)
			foundAssignment = foundAssignment || len(rows) > 0
		}
		if !foundAssignment {
			body = append(body, []string{tenantID, "", "", claims.ObjectID, callerName, "Direct or Group", "(none)", "No Azure RBAC assignments found in accessible subscriptions"})
		}
	}

	sort.Slice(body, func(i, j int) bool {
		for _, column := range []int{0, 1, 6, 5, 4} {
			if body[i][column] != body[j][column] {
				return body[i][column] < body[j][column]
			}
		}
		return body[i][7] < body[j][7]
	})
	return header, body, errs
}

func azureRBACRowsForSubscription(tenantID, subscriptionID, subscriptionName string, principals map[string]rbacPrincipal, roleNames map[string]string, assignments []authorization.RoleAssignment) [][]string {
	var rows [][]string
	for _, assignment := range assignments {
		principal, ok := principals[strings.ToLower(ptr.ToString(assignment.Properties.PrincipalID))]
		if !ok {
			continue
		}
		roleDefinitionID := lastResourceIDSegment(ptr.ToString(assignment.Properties.RoleDefinitionID))
		roleName := roleNames[strings.ToLower(roleDefinitionID)]
		if roleName == "" {
			roleName = roleDefinitionID
		}
		rows = append(rows, []string{tenantID, subscriptionID, subscriptionName, principal.ID, principal.Name, principal.AssignmentType, roleName, ptr.ToString(assignment.Properties.Scope)})
	}
	return rows
}

func roleDefinitionNames(definitions []authorization.RoleDefinition) map[string]string {
	names := make(map[string]string, len(definitions))
	for _, definition := range definitions {
		names[strings.ToLower(lastResourceIDSegment(ptr.ToString(definition.ID)))] = ptr.ToString(definition.RoleName)
	}
	return names
}

func lastResourceIDSegment(id string) string {
	id = strings.TrimRight(id, "/")
	if index := strings.LastIndex(id, "/"); index >= 0 {
		return id[index+1:]
	}
	return id
}

func parseTokenClaims(token string) (tokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenClaims{}, fmt.Errorf("Microsoft Graph returned a malformed access token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenClaims{}, fmt.Errorf("decode Microsoft Graph access token claims: %w", err)
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return tokenClaims{}, fmt.Errorf("decode Microsoft Graph access token claims: %w", err)
	}
	if claims.ObjectID == "" {
		return tokenClaims{}, fmt.Errorf("Microsoft Graph access token has no oid claim")
	}
	return claims, nil
}

func getEntraRolePage(ctx context.Context, accessToken, endpoint string) (entraRolePage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return entraRolePage{}, fmt.Errorf("create Microsoft Graph request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")
	req.Header.Set("User-Agent", globals.CLOUDFOX_USER_AGENT)

	resp, err := graphHTTPClient.Do(req)
	if err != nil {
		return entraRolePage{}, fmt.Errorf("query Microsoft Graph: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return entraRolePage{}, fmt.Errorf("read Microsoft Graph response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var graphErr graphErrorResponse
		if json.Unmarshal(responseBody, &graphErr) == nil && graphErr.Error.Message != "" {
			return entraRolePage{}, fmt.Errorf("Microsoft Graph returned %s (%s): %s", resp.Status, graphErr.Error.Code, graphErr.Error.Message)
		}
		return entraRolePage{}, fmt.Errorf("Microsoft Graph returned %s", resp.Status)
	}

	var page entraRolePage
	if err := json.Unmarshal(responseBody, &page); err != nil {
		return entraRolePage{}, fmt.Errorf("decode Microsoft Graph response: %w", err)
	}
	return page, nil
}

var getTenants = getTenantsOriginal

func getTenantsOriginal() []subscriptions.TenantIDDescription {
	tenantsClient := internal.GetTenantsClient()
	var results []subscriptions.TenantIDDescription
	for page, err := tenantsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			azureLogger.FatalM("Could not get tenants for active session", globals.AZ_WHOAMI_MODULE_NAME)
		}
		results = append(results, page.Values()...)
	}
	return results
}

func mockedGetTenants() []subscriptions.TenantIDDescription {
	var results []subscriptions.TenantIDDescription
	for _, tenant := range loadTestFile(globals.RESOURCES_TEST_FILE).Tenants {
		results = append(results, subscriptions.TenantIDDescription{
			TenantID:      tenant.TenantID,
			DisplayName:   tenant.DisplayName,
			DefaultDomain: tenant.DefaultDomain,
		})
	}
	return results
}

var GetSubscriptions = getSubscriptionsOriginal

func getSubscriptionsOriginal() []subscriptions.Subscription {
	var results []subscriptions.Subscription
	subsClient := internal.GetSubscriptionsClient()
	for page, err := subsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			azureLogger.FatalM("Could not get subscriptions for active session", globals.AZ_WHOAMI_MODULE_NAME)
		}
		results = append(results, page.Values()...)
	}
	return results
}

func mockedGetSubscriptions() []subscriptions.Subscription {
	var results []subscriptions.Subscription
	tenants := loadTestFile(globals.RESOURCES_TEST_FILE).Tenants
	for _, tenant := range tenants {
		for _, sub := range tenant.Subscriptions {
			results = append(results, subscriptions.Subscription{
				TenantID:       tenant.TenantID,
				SubscriptionID: sub.SubscriptionId,
				DisplayName:    sub.DisplayName,
			})
		}
	}
	return results
}

var getResourceGroups = getResourceGroupsOriginal

func getResourceGroupsOriginal(subscriptionID string) []resources.Group {
	var results []resources.Group
	rgClient := internal.GetResourceGroupsClient(subscriptionID)

	for page, err := rgClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {
		if err != nil {
			azureLogger.FatalM(fmt.Sprintf("Error reading resource groups for subscription %s", subscriptionID), globals.AZ_WHOAMI_MODULE_NAME)
		}
		results = append(results, page.Values()...)
	}
	return results
}

func mockedGetResourceGroups(subscriptionID string) []resources.Group {
	var results []resources.Group
	for _, tenant := range loadTestFile(globals.RESOURCES_TEST_FILE).Tenants {
		for _, sub := range tenant.Subscriptions {
			if ptr.ToString(sub.SubscriptionId) == subscriptionID {
				for _, rg := range sub.ResourceGroups {
					results = append(results, resources.Group{
						ID:       rg.ID,
						Name:     rg.Name,
						Location: rg.Location,
					})
				}
			}
		}
	}
	return results
}

func loadTestFile(fileName string) ResourcesTestFile {
	file, err := os.ReadFile(fileName)
	if err != nil {
		azureLogger.FatalM(fmt.Sprintf("Could not read file %s", globals.RESOURCES_TEST_FILE), globals.AZ_WHOAMI_MODULE_NAME)
	}
	var testFile ResourcesTestFile
	err = json.Unmarshal(file, &testFile)
	if err != nil {
		azureLogger.FatalM(fmt.Sprintf("Could not unmarshal file %s", globals.RESOURCES_TEST_FILE), globals.AZ_WHOAMI_MODULE_NAME)
	}
	return testFile
}

type ResourcesTestFile struct {
	Tenants []struct {
		DisplayName   *string `json:"displayName"`
		TenantID      *string `json:"tenantId"`
		DefaultDomain *string `json:"defaultDomain,omitempty"`
		Subscriptions []struct {
			DisplayName    *string `json:"displayName"`
			SubscriptionId *string `json:"subscriptionId"`
			ResourceGroups []struct {
				Name     *string `json:"Name"`
				ID       *string `json:"id"`
				Location *string `json:"location"`
			} `json:"ResourceGroups"`
		} `json:"Subscriptions"`
	} `json:"Tenants"`
}
