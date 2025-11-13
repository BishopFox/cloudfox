package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armauthorizationv2 "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	armmanagementgroups "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	armmi "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	msgraphsdkmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
)

type ServicePrincipal struct {
	DisplayName *string
	AppId       *string
	ObjectId    *string
	Permissions []string
}

// CredentialInfo holds normalized credential details
type CredentialInfo struct {
	Type      string // "Key" or "Password"
	KeyID     string
	StartDate time.Time
	EndDate   time.Time
}

type Secret struct {
	DisplayName string
	KeyID       string
	EndDate     string
}

type Certificate struct {
	Name       string
	Thumbprint string
	ExpiryDate string
}

type PrincipalInfo struct {
	ObjectID          string
	UserPrincipalName string
	DisplayName       string
	UserType          string
	AppID             string
}

// ManagedIdentity holds the principal ID of a user-assigned managed identity
type ManagedIdentity struct {
	Name           string
	Type           string
	Roles          []string
	ClientID       string
	PrincipalID    string
	ResourceID     string
	SubscriptionID string
}

type PrincipalPermissions struct {
	RBAC  string
	Graph string
}

// GetServicePrincipalsPerSubscription lists SPs in a subscription
func GetServicePrincipalsPerSubscription(ctx context.Context, session *SafeSession, subscriptionID string) []PrincipalInfo {
	out := []PrincipalInfo{}

	// Get token for Microsoft Graph
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil || token == "" {
		return out
	}

	// Helper to do Graph GET requests with retry logic
	doGraphGet := func(url string) ([]map[string]interface{}, error) {
		body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
		if err != nil {
			return nil, err
		}

		var data struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, err
		}
		return data.Value, nil
	}

	// ---- Get Service Principals ----
	spURL := "https://graph.microsoft.com/v1.0/servicePrincipals"
	sps, err := doGraphGet(spURL)
	if err == nil && sps != nil {
		for _, sp := range sps {
			display := SafeValueString(sp["displayName"])
			appID := SafeValueString(sp["appId"])
			objectID := SafeValueString(sp["id"])

			if display == "" && appID == "" && objectID == "" {
				continue
			}

			out = append(out, PrincipalInfo{
				DisplayName: display,
				AppID:       appID,
				ObjectID:    objectID,
				UserType:    "ServicePrincipal",
			})
		}
	}

	// ---- Get Users ----
	userURL := "https://graph.microsoft.com/v1.0/users"
	users, err := doGraphGet(userURL)
	if err == nil && users != nil {
		for _, u := range users {
			display := SafeValueString(u["displayName"])
			objectID := SafeValueString(u["id"])
			userPrincipal := SafeValueString(u["userPrincipalName"])

			// Use UPN if display is empty
			if display == "" && userPrincipal != "" {
				display = userPrincipal
			}

			out = append(out, PrincipalInfo{
				DisplayName: display,
				AppID:       "", // users don't have AppID
				ObjectID:    objectID,
				UserType:    "User",
			})
		}
	}

	return out
}

// helper to convert msgraph ServicePrincipal objects to our struct
func convertSPs(spObjs []msgraphsdkmodels.ServicePrincipalable) []ServicePrincipal {
	result := []ServicePrincipal{}
	for _, sp := range spObjs {
		result = append(result, ServicePrincipal{
			DisplayName: SafePtr(sp.GetDisplayName()),
			AppId:       SafePtr(sp.GetAppId()),
			ObjectId:    SafePtr(sp.GetId()),
		})
	}
	return result
}

func GetServicePrincipalSecrets(ctx context.Context, session *SafeSession, appID string) []Secret {
	// Here we assume appID == objectId for Graph query
	creds, err := GetServicePrincipalCredentials(ctx, session, appID)
	if err != nil {
		return nil
	}

	secrets := []Secret{}
	for _, c := range creds {
		if c.Type == "Password" {
			secrets = append(secrets, Secret{
				DisplayName: c.KeyID,
				KeyID:       c.KeyID,
				EndDate:     c.EndDate.Format("2006-01-02"),
			})
		}
	}

	return secrets
}

func GetServicePrincipalCertificates(ctx context.Context, session *SafeSession, appID string) []Certificate {
	creds, err := GetServicePrincipalCredentials(ctx, session, appID)
	if err != nil {
		return nil
	}

	certs := []Certificate{}
	for _, c := range creds {
		if c.Type == "Key" {
			certs = append(certs, Certificate{
				Name:       c.KeyID,
				Thumbprint: c.KeyID,
				ExpiryDate: c.EndDate.Format("2006-01-02"),
			})
		}
	}

	return certs
}

// GetServicePrincipalCredentials retrieves certs & passwords for a given Service Principal objectId
func GetServicePrincipalCredentials(ctx context.Context, session *SafeSession, objectID string) ([]CredentialInfo, error) {
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		return nil, fmt.Errorf("failed to get Graph token: %w", err)
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=keyCredentials,passwordCredentials", objectID)

	// Use retry logic for Graph API
	body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err != nil {
		return nil, fmt.Errorf("failed to query Graph API: %w", err)
	}

	var sp struct {
		KeyCredentials []struct {
			KeyID         string     `json:"keyId"`
			StartDateTime *time.Time `json:"startDateTime"`
			EndDateTime   *time.Time `json:"endDateTime"`
		} `json:"keyCredentials"`
		PasswordCredentials []struct {
			KeyID         string     `json:"keyId"`
			StartDateTime *time.Time `json:"startDateTime"`
			EndDateTime   *time.Time `json:"endDateTime"`
		} `json:"passwordCredentials"`
	}

	if err := json.Unmarshal(body, &sp); err != nil {
		return nil, fmt.Errorf("failed to decode Graph response: %w", err)
	}

	var creds []CredentialInfo

	for _, k := range sp.KeyCredentials {
		ci := CredentialInfo{
			Type:  "Key",
			KeyID: k.KeyID,
		}
		if k.StartDateTime != nil {
			ci.StartDate = *k.StartDateTime
		}
		if k.EndDateTime != nil {
			ci.EndDate = *k.EndDateTime
		}
		creds = append(creds, ci)
	}

	for _, p := range sp.PasswordCredentials {
		ci := CredentialInfo{
			Type:  "Password",
			KeyID: p.KeyID,
		}
		if p.StartDateTime != nil {
			ci.StartDate = *p.StartDateTime
		}
		if p.EndDateTime != nil {
			ci.EndDate = *p.EndDateTime
		}
		creds = append(creds, ci)
	}

	return creds, nil
}

func deref[T any](v *T) T {
	if v == nil {
		var zero T
		return zero
	}
	return *v
}

// ListPrincipals retrieves both Entra users and service principals for a given tenant.
func ListPrincipals(ctx context.Context, session *SafeSession, tenantID string) ([]PrincipalInfo, error) {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating all principals (users + service principals) for tenant: %v", tenantID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph
	if err != nil {
		return nil, fmt.Errorf("failed to get Graph token: %w", err)
	}

	principals := []PrincipalInfo{}

	// ------------------- Fetch Users -------------------
	userURL := "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,userType"
	err = GraphAPIPagedRequest(ctx, userURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID                   string `json:"id"`
				DisplayName          string `json:"displayName"`
				UserPrincipalName    string `json:"userPrincipalName"`
				Mail                 string `json:"mail"`
				OnPremisesSamAccount string `json:"onPremisesSamAccountName"`
				UserType             string `json:"userType"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode user page: %v", err)
		}

		for _, u := range data.Value {
			upn := u.UserPrincipalName
			if upn == "" {
				if u.Mail != "" {
					upn = u.Mail
				} else {
					upn = u.OnPremisesSamAccount
				}
			}
			name := u.DisplayName
			if name == "" {
				name = upn
			}
			// Use actual userType from API, default to "User" if empty
			userType := u.UserType
			if userType == "" {
				userType = "User"
			}
			principals = append(principals, PrincipalInfo{
				ObjectID:          u.ID,
				UserPrincipalName: upn,
				DisplayName:       name,
				UserType:          userType,
			})
		}

		return data.NextLink != "", data.NextLink, nil
	})
	if err != nil {
		return principals, fmt.Errorf("failed to query users: %v", err)
	}

	// ------------------- Fetch Service Principals -------------------
	spURL := "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId"
	err = GraphAPIPagedRequest(ctx, spURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				AppID       string `json:"appId"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode SP page: %v", err)
		}

		for _, sp := range data.Value {
			name := sp.DisplayName
			if name == "" {
				name = sp.AppID
			}
			principals = append(principals, PrincipalInfo{
				ObjectID:          sp.ID,
				UserPrincipalName: sp.AppID,
				DisplayName:       name,
				UserType:          "ServicePrincipal",
				AppID:             sp.AppID,
			})
		}

		return data.NextLink != "", data.NextLink, nil
	})
	if err != nil {
		return principals, fmt.Errorf("failed to query service principals: %v", err)
	}

	return principals, nil
}

// ListEntraUsers returns all users in the tenant via Microsoft Graph
func ListEntraUsers(ctx context.Context, session *SafeSession, tenantID string) ([]PrincipalInfo, error) {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Entra users for tenant: %v", tenantID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return nil, err
	}

	users := []PrincipalInfo{}
	initialURL := "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,userType"

	// Use GraphAPIPagedRequest for automatic retry logic
	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID                   string `json:"id"`
				DisplayName          string `json:"displayName"`
				UserPrincipalName    string `json:"userPrincipalName"`
				Mail                 string `json:"mail"`
				OnPremisesSamAccount string `json:"onPremisesSamAccountName"`
				UserType             string `json:"userType"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode Graph response: %v", err)
		}

		for _, u := range data.Value {
			upn := u.UserPrincipalName
			if upn == "" {
				if u.Mail != "" {
					upn = u.Mail
				} else {
					upn = u.OnPremisesSamAccount
				}
			}
			name := u.DisplayName
			if name == "" {
				name = upn
			}
			// Use actual userType from API, default to "User" if empty
			userType := u.UserType
			if userType == "" {
				userType = "User"
			}
			users = append(users, PrincipalInfo{
				UserPrincipalName: upn,
				DisplayName:       name,
				UserType:          userType,
				ObjectID:          u.ID,
			})
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to enumerate users: %v", err)
	}

	return users, nil
}

// ListServicePrincipals returns all service principals in the tenant
func ListServicePrincipals(ctx context.Context, session *SafeSession, tenantID string) ([]PrincipalInfo, error) {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating service principals for tenant: %v", tenantID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return nil, err
	}

	sps := []PrincipalInfo{}
	initialURL := "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId"

	// Use GraphAPIPagedRequest for automatic retry logic
	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				AppID       string `json:"appId"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode Graph response: %v", err)
		}

		for _, sp := range data.Value {
			name := sp.DisplayName
			if name == "" {
				name = sp.AppID
			}

			sps = append(sps, PrincipalInfo{
				ObjectID:          sp.ID,    // Actual Object ID
				UserPrincipalName: sp.AppID, // AppID in UPN field for reference
				DisplayName:       name,
				UserType:          "ServicePrincipal",
				AppID:             sp.AppID,
			})
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to enumerate service principals: %v", err)
	}

	return sps, nil
}

// ListUserAssignedManagedIdentities enumerates all user-assigned managed identities in the provided subscriptions
func ListUserAssignedManagedIdentities(ctx context.Context, session *SafeSession, subscriptionIDs []string) ([]ManagedIdentity, error) {
	allMIs := []ManagedIdentity{}
	logger := internal.NewLogger()

	for _, subID := range subscriptionIDs {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Enumerating user assigned managed identities for subscriptions: %v", subID), globals.AZ_PRINCIPALS_MODULE_NAME)
		}

		// Get a token for ARM
		token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
		if err != nil {
			return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subID, err)
		}

		// Create a credential wrapper for the ARM SDK using the token
		cred := &StaticTokenCredential{Token: token}

		client, err := armmi.NewUserAssignedIdentitiesClient(subID, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create MI client for subscription %s: %v", subID, err)
		}

		pager := client.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list managed identities for subscription %s: %v", subID, err)
			}

			for _, mi := range page.Value {
				allMIs = append(allMIs, ManagedIdentity{
					Name:           SafeStringPtr(mi.Name),
					Type:           SafeStringPtr(mi.Type),
					ClientID:       SafeStringPtr(mi.Properties.ClientID),
					PrincipalID:    SafeStringPtr(mi.Properties.PrincipalID),
					ResourceID:     SafeStringPtr(mi.ID),
					SubscriptionID: subID,
				})
			}
		}
	}

	return allMIs, nil
}

// getSPPermissions retrieves roles/permissions for a SP
func GetSPPermissions(ctx context.Context, session *SafeSession, spObjectID string) []string {
	permissions := []string{}
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating service principal permissions for: %v", spObjectID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	// ------------------- Get Graph Token -------------------
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get Graph token: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		return permissions
	}

	// Helper function to make a GET request with the Graph token using retry logic
	getGraph := func(url string) []byte {
		body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Graph API request failed for %s: %v", url, err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
			return nil
		}
		return body
	}

	// ------------------- App Role Assignments -------------------
	urlAssignments := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignments?$top=999", spObjectID)
	body := getGraph(urlAssignments)
	if body != nil {
		var result struct {
			Value []struct {
				AppRoleId *string `json:"appRoleId"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &result); err == nil {
			for _, a := range result.Value {
				if a.AppRoleId != nil {
					permissions = append(permissions, *a.AppRoleId)
				}
			}
		}
	}

	// ------------------- OAuth2 Permission Grants -------------------
	urlGrants := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/oauth2PermissionGrants?$top=999", spObjectID)
	body = getGraph(urlGrants)
	if body != nil {
		var result struct {
			Value []struct {
				Scope *string `json:"scope"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &result); err == nil {
			for _, g := range result.Value {
				if g.Scope != nil {
					permissions = append(permissions, *g.Scope)
				}
			}
		}
	}

	return permissions
}

// -------------------- Utility Helpers --------------------

func ExtractSPNames(sps []*ServicePrincipal) []string {
	names := []string{}
	for _, sp := range sps {
		if sp.DisplayName != nil {
			names = append(names, *sp.DisplayName)
		}
	}
	return names
}

func ExtractSPIDs(sps []*ServicePrincipal) []string {
	ids := []string{}
	for _, sp := range sps {
		if sp.ObjectId != nil {
			ids = append(ids, *sp.ObjectId)
		}
	}
	return ids
}

func FormatSPPermissions(sps []*ServicePrincipal) string {
	var perms []string
	for _, sp := range sps {
		if sp.Permissions != nil && len(sp.Permissions) > 0 {
			perms = append(perms, strings.Join(sp.Permissions, "; "))
		}
	}
	return strings.Join(perms, " | ")
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// GetPrincipalPermissions retrieves both Graph and RBAC permissions for a given principal ID.
func GetPrincipalPermissions(ctx context.Context, session *SafeSession, principal string) PrincipalPermissions {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating principal permissions for: %v", principal), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	result := PrincipalPermissions{}
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph
	if err != nil {
		return result
	}

	objectID := ""
	isSP := false

	// ----------------- Determine type of principal -----------------
	// Always try to determine the actual type, even if it's a UUID
	// (both users and service principals have UUID object IDs)

	if isUUID(principal) {
		// It's a UUID - try as user first, then service principal
		url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s?$select=id", principal)
		body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
		if err == nil {
			var userData struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(body, &userData) == nil && userData.ID != "" {
				objectID = userData.ID
				isSP = false
			}
		}

		// If not found as user, try as service principal (includes managed identities)
		if objectID == "" {
			url = fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=id", principal)
			body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
			if err == nil {
				var spData struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(body, &spData) == nil && spData.ID != "" {
					objectID = spData.ID
					isSP = true
				}
			}
		}
	} else {
		// It's not a UUID - try to resolve as UPN/email or displayName
		url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s?$select=id", principal)
		body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
		if err == nil {
			var userData struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(body, &userData) == nil && userData.ID != "" {
				objectID = userData.ID
				isSP = false
			}
		}

		// If not resolved as user, try as service principal displayName
		if objectID == "" {
			url = fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals?$filter=displayName eq '%s'&$select=id", principal)
			body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
			if err == nil {
				var spData struct {
					Value []struct {
						ID string `json:"id"`
					} `json:"value"`
				}
				if json.Unmarshal(body, &spData) == nil && len(spData.Value) > 0 {
					objectID = spData.Value[0].ID
					isSP = true
				}
			}
		}
	}

	if objectID == "" {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("[GetPrincipalPermissions] Could not resolve principal: %s", principal), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return result
	}

	graphPerms := []string{}

	// ----------------- Fetch permissions based on type -----------------
	if isSP {
		// Service Principal: appRoleAssignments with pagination
		initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignments", objectID)

		err := GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
			var data struct {
				Value []struct {
					ResourceDisplayName string  `json:"resourceDisplayName"`
					ResourceId          string  `json:"resourceId"`
					AppRoleId           *string `json:"appRoleId"`
				} `json:"value"`
				NextLink string `json:"@odata.nextLink"`
			}

			if err := json.Unmarshal(body, &data); err != nil {
				return false, "", fmt.Errorf("failed to decode appRoleAssignments: %v", err)
			}

			for _, a := range data.Value {
				appRoleName := "(unknown)"
				if a.AppRoleId != nil && a.ResourceId != "" {
					roleURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoles", a.ResourceId)
					roleBody, err := GraphAPIRequestWithRetry(ctx, "GET", roleURL, token)
					if err != nil {
						if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
							logger.ErrorM(fmt.Sprintf("Failed to fetch appRoles for resource %s (%s): %v", a.ResourceDisplayName, a.ResourceId, err), globals.AZ_PRINCIPALS_MODULE_NAME)
						}
					} else {
						var roleData struct {
							Value []struct {
								ID          string `json:"id"`
								Value       string `json:"value"`
								DisplayName string `json:"displayName"`
							} `json:"value"`
						}
						if json.Unmarshal(roleBody, &roleData) == nil {
							found := false
							for _, r := range roleData.Value {
								if strings.EqualFold(r.ID, *a.AppRoleId) {
									if r.Value != "" {
										appRoleName = r.Value
									} else if r.DisplayName != "" {
										appRoleName = r.DisplayName
									}
									found = true
									break
								}
							}
							if !found && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
								logger.ErrorM(fmt.Sprintf("AppRole ID %s not found in resource %s (%s) appRoles list (found %d roles)", *a.AppRoleId, a.ResourceDisplayName, a.ResourceId, len(roleData.Value)), globals.AZ_PRINCIPALS_MODULE_NAME)
							}
						} else if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
							logger.ErrorM(fmt.Sprintf("Failed to decode appRoles JSON for resource %s (%s)", a.ResourceDisplayName, a.ResourceId), globals.AZ_PRINCIPALS_MODULE_NAME)
						}
					}
				} else if a.AppRoleId == nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("AppRoleAssignment has nil AppRoleId for resource %s (%s)", a.ResourceDisplayName, a.ResourceId), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
				graphPerms = append(graphPerms, fmt.Sprintf("%s (%s)", a.ResourceDisplayName, appRoleName))
			}

			hasMore := data.NextLink != ""
			nextURL := data.NextLink
			return hasMore, nextURL, nil
		})

		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("[GetPrincipalPermissions] Failed to fetch appRoleAssignments: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
			// Return partial results instead of empty result
		}

	} else {
		// User: memberOf groups with pagination
		initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf", objectID)

		err := GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
			var data struct {
				Value []struct {
					DisplayName string `json:"displayName"`
				} `json:"value"`
				NextLink string `json:"@odata.nextLink"`
			}

			if err := json.Unmarshal(body, &data); err != nil {
				return false, "", fmt.Errorf("failed to decode memberOf: %v", err)
			}

			for _, g := range data.Value {
				graphPerms = append(graphPerms, fmt.Sprintf("%s (group)", g.DisplayName))
			}

			hasMore := data.NextLink != ""
			nextURL := data.NextLink
			return hasMore, nextURL, nil
		})

		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("[GetPrincipalPermissions] Failed to fetch memberOf: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
			// Return partial results instead of empty result
		}
	}

	result.Graph = strings.Join(graphPerms, ", ")
	return result
}

// ----------------- helper -----------------
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// GetUserGroupMemberships returns all group object IDs that the user is a member of (including nested groups)
// This is essential for checking group-based role assignments since the Azure RBAC API
// principalId filter does NOT expand group memberships automatically.
// Uses transitiveMemberOf to capture ALL group memberships including nested group inheritance.
func GetUserGroupMemberships(ctx context.Context, session *SafeSession, userObjectID string) []string {
	logger := internal.NewLogger()
	groupIDs := []string{}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for group membership enumeration: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return groupIDs
	}

	// Use Microsoft Graph to get user's group memberships (including nested groups via transitive query)
	initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/transitiveMemberOf?$select=id", userObjectID)

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode memberOf response: %v", err)
		}

		for _, group := range data.Value {
			if group.ID != "" {
				groupIDs = append(groupIDs, group.ID)
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate group memberships for user %s: %v", userObjectID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return groupIDs
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(groupIDs) > 0 {
		logger.InfoM(fmt.Sprintf("User %s is a member of %d group(s) (including nested groups)", userObjectID, len(groupIDs)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return groupIDs
}

// getGraphPermissions aggregates delegated and app permissions from Graph.
func getGraphPermissions(ctx context.Context, token string, principalID string) []string {
	perms := []string{}

	// Use retry logic for Graph API requests
	doRequest := func(url string) ([]byte, error) {
		return GraphAPIRequestWithRetry(ctx, "GET", url, token)
	}

	// --- 1) AppRoleAssignments (application permissions on resources) ---
	if body, err := doRequest(fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/appRoleAssignments", principalID)); err == nil {
		var data struct {
			Value []struct {
				ResourceDisplayName string `json:"resourceDisplayName"`
				AppRoleDisplayName  string `json:"appRoleDisplayName"`
			} `json:"value"`
		}
		if json.Unmarshal(body, &data) == nil {
			for _, a := range data.Value {
				perms = append(perms, fmt.Sprintf("Graph AppRole: %s (%s)", a.ResourceDisplayName, a.AppRoleDisplayName))
			}
		}
	}

	// --- 2) OAuth2PermissionGrants (delegated permissions) ---
	if body, err := doRequest(fmt.Sprintf("https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '%s'", principalID)); err == nil {
		var data struct {
			Value []struct {
				ResourceID string `json:"resourceId"`
				Scope      string `json:"scope"`
			} `json:"value"`
		}
		if json.Unmarshal(body, &data) == nil {
			for _, g := range data.Value {
				perms = append(perms, fmt.Sprintf("Graph Delegated: %s (Scopes: %s)", g.ResourceID, g.Scope))
			}
		}
	}

	// --- 3) ServicePrincipal AppRoleAssignments (application-to-application perms) ---
	if body, err := doRequest(fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignments", principalID)); err == nil {
		var data struct {
			Value []struct {
				ResourceDisplayName string `json:"resourceDisplayName"`
				AppRoleDisplayName  string `json:"appRoleDisplayName"`
			} `json:"value"`
		}
		if json.Unmarshal(body, &data) == nil {
			for _, a := range data.Value {
				perms = append(perms, fmt.Sprintf("SP AppRole: %s (%s)", a.ResourceDisplayName, a.AppRoleDisplayName))
			}
		}
	}

	return perms
}

// RoleAssignment models a simplified Azure RBAC assignment.
type RoleAssignment struct {
	RoleName string
	Scope    string
}

// GetRoleAssignments queries Azure Management for role assignments.
func GetRoleAssignments(ctx context.Context, session *SafeSession, principalID string) ([]RoleAssignment, error) {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating principal: %v", principalID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to acquire ARM token: %w", err)
	}

	// Configure retry for ARM API
	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	url := fmt.Sprintf("https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=assignedTo('%s')", principalID)
	body, err := HTTPRequestWithRetry(ctx, "GET", url, token, nil, config)
	if err != nil {
		return nil, fmt.Errorf("roleAssignments query failed: %w", err)
	}

	var payload struct {
		Value []struct {
			Properties struct {
				RoleDefinitionName string `json:"roleDefinitionName"`
				Scope              string `json:"scope"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	assignments := []RoleAssignment{}
	for _, v := range payload.Value {
		assignments = append(assignments, RoleAssignment{
			RoleName: v.Properties.RoleDefinitionName,
			Scope:    v.Properties.Scope,
		})
	}

	return assignments, nil
}

func GetDelegatedOAuth2Grants(ctx context.Context, session *SafeSession, appObjectID string) []string {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating OAuth2 Grants for app: %v", appObjectID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for OAuth2 grants enumeration: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return []string{}
	}

	var scopesFormatted []string
	grantCount := 0
	adminConsentCount := 0
	userConsentCount := 0

	// Use REST API with API-level filtering for efficiency
	// Only retrieve grants for this specific client instead of all grants in tenant
	initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '%s'", appObjectID)

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ClientID    *string `json:"clientId"`
				ConsentType *string `json:"consentType"`
				ResourceID  *string `json:"resourceId"`
				Scope       *string `json:"scope"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode OAuth2 permission grants: %v", err)
		}

		for _, grant := range data.Value {
			// API filter ensures only this client's grants are returned
			if grant.ClientID == nil || grant.Scope == nil {
				continue
			}

			grantCount++
			consentType := "Unknown"
			if grant.ConsentType != nil {
				consentType = *grant.ConsentType
				if strings.EqualFold(consentType, "AllPrincipals") {
					adminConsentCount++
				} else if strings.EqualFold(consentType, "Principal") {
					userConsentCount++
				}
			}

			// Get resource name (the service principal receiving the permission)
			resourceName := "Unknown Resource"
			if grant.ResourceID != nil {
				resourceID := *grant.ResourceID
				// Try to get the resource service principal display name using retry logic
				spURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=displayName", resourceID)
				spBody, err := GraphAPIRequestWithRetry(ctx, "GET", spURL, token)
				if err == nil {
					var spData struct {
						DisplayName string `json:"displayName"`
					}
					if json.Unmarshal(spBody, &spData) == nil && spData.DisplayName != "" {
						resourceName = spData.DisplayName
					}
				}
			}

			// Format scopes with consent type and resource name
			scopes := strings.Split(*grant.Scope, " ")
			for _, scope := range scopes {
				if scope != "" {
					// Format: "Resource: scope (ConsentType)"
					formatted := fmt.Sprintf("%s: %s (%s)", resourceName, scope, consentType)
					scopesFormatted = append(scopesFormatted, formatted)
				}
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate OAuth2 permission grants for app %s: %v", appObjectID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		// Return partial results instead of empty result
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d OAuth2 permission grant(s) for app %s: %d admin consent, %d user consent, %d total permissions",
			grantCount, appObjectID, adminConsentCount, userConsentCount, len(scopesFormatted)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return scopesFormatted
}

// ------------------------------
// Enhanced Consent Grants (for consent-centric module)
// ------------------------------

// OAuth2PermissionGrantDetails represents a complete OAuth2 consent grant
type OAuth2PermissionGrantDetails struct {
	ID                  string
	ClientID            string // Service principal receiving the permission
	ClientDisplayName   string
	ConsentType         string // "AllPrincipals" (admin) or "Principal" (user)
	PrincipalID         string // User who granted consent (for user consent)
	PrincipalName       string // UPN of user
	ResourceID          string // Service principal being accessed (usually Microsoft Graph)
	ResourceDisplayName string
	Scope               string   // Space-separated list of permissions
	Scopes              []string // Individual permissions
	StartTime           string
	ExpiryTime          string
	RiskyPermissions    []string // List of risky permissions in this grant
	IsRisky             bool     // True if contains any risky permissions
	IsExternal          bool     // True if client is multi-tenant/external
}

// RiskyOAuth2Permissions defines dangerous delegated permissions
var RiskyOAuth2Permissions = map[string]string{
	// Mail permissions
	"Mail.ReadWrite":     "Read and write user mailboxes",
	"Mail.ReadWrite.All": "Read and write all mailboxes",
	"Mail.Send":          "Send mail as any user",
	"Mail.Send.All":      "Send mail as any user",

	// Files and SharePoint
	"Files.ReadWrite.All":   "Read and write all files",
	"Sites.ReadWrite.All":   "Read and write all site collections",
	"Sites.FullControl.All": "Full control of all site collections",

	// Users and directory
	"User.ReadWrite.All":           "Read and write all users",
	"Directory.ReadWrite.All":      "Read and write directory data",
	"Directory.AccessAsUser.All":   "Access directory as signed-in user",
	"RoleManagement.ReadWrite.All": "Read and write all role assignments",

	// Groups
	"Group.ReadWrite.All":       "Read and write all groups",
	"GroupMember.ReadWrite.All": "Read and write all group memberships",

	// Applications
	"Application.ReadWrite.All":       "Read and write all applications",
	"AppRoleAssignment.ReadWrite.All": "Manage app permission grants",

	// Privileged access
	"PrivilegedAccess.ReadWrite.AzureAD":        "Read and write privileged access",
	"PrivilegedAccess.ReadWrite.AzureResources": "Read and write Azure resource access",

	// Compliance and security
	"SecurityEvents.ReadWrite.All":       "Read and write security events",
	"ThreatIndicators.ReadWrite.OwnedBy": "Manage threat indicators",
}

// GetAllOAuth2PermissionGrants retrieves all OAuth2 consent grants in the tenant
func GetAllOAuth2PermissionGrants(ctx context.Context, session *SafeSession) ([]OAuth2PermissionGrantDetails, error) {
	logger := internal.NewLogger()
	var grants []OAuth2PermissionGrantDetails

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for consent grants: %v", err), "consent-grants")
		}
		return grants, err
	}

	// Get all OAuth2 permission grants in the tenant
	initialURL := "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID          string  `json:"id"`
				ClientID    string  `json:"clientId"`
				ConsentType string  `json:"consentType"`
				PrincipalID *string `json:"principalId"`
				ResourceID  string  `json:"resourceId"`
				Scope       string  `json:"scope"`
				StartTime   string  `json:"startTime"`
				ExpiryTime  string  `json:"expiryTime"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode OAuth2 permission grants: %v", err)
		}

		for _, grant := range data.Value {
			details := OAuth2PermissionGrantDetails{
				ID:          grant.ID,
				ClientID:    grant.ClientID,
				ConsentType: grant.ConsentType,
				ResourceID:  grant.ResourceID,
				Scope:       grant.Scope,
				StartTime:   grant.StartTime,
				ExpiryTime:  grant.ExpiryTime,
			}

			// Get principal ID for user consent
			if grant.PrincipalID != nil {
				details.PrincipalID = *grant.PrincipalID
			}

			// Parse scopes
			if grant.Scope != "" {
				details.Scopes = strings.Fields(grant.Scope)
			}

			// Identify risky permissions
			for _, scope := range details.Scopes {
				if description, isRisky := RiskyOAuth2Permissions[scope]; isRisky {
					details.RiskyPermissions = append(details.RiskyPermissions, fmt.Sprintf("%s (%s)", scope, description))
					details.IsRisky = true
				}
			}

			// Get client service principal display name
			if details.ClientID != "" {
				spURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=displayName,appId,appOwnerOrganizationId", details.ClientID)
				spBody, err := GraphAPIRequestWithRetry(ctx, "GET", spURL, token)
				if err == nil {
					var spData struct {
						DisplayName            string  `json:"displayName"`
						AppID                  string  `json:"appId"`
						AppOwnerOrganizationID *string `json:"appOwnerOrganizationId"`
					}
					if json.Unmarshal(spBody, &spData) == nil {
						details.ClientDisplayName = spData.DisplayName
						// Check if external/multi-tenant
						if spData.AppOwnerOrganizationID != nil && *spData.AppOwnerOrganizationID != "" {
							// Compare with current tenant - if different, it's external
							details.IsExternal = true // Simplified - could compare tenant IDs
						}
					}
				}
			}

			// Get resource service principal display name
			if details.ResourceID != "" {
				spURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=displayName", details.ResourceID)
				spBody, err := GraphAPIRequestWithRetry(ctx, "GET", spURL, token)
				if err == nil {
					var spData struct {
						DisplayName string `json:"displayName"`
					}
					if json.Unmarshal(spBody, &spData) == nil && spData.DisplayName != "" {
						details.ResourceDisplayName = spData.DisplayName
					}
				}
			}

			// Get principal name for user consent
			if details.PrincipalID != "" && details.ConsentType == "Principal" {
				userURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s?$select=userPrincipalName", details.PrincipalID)
				userBody, err := GraphAPIRequestWithRetry(ctx, "GET", userURL, token)
				if err == nil {
					var userData struct {
						UserPrincipalName string `json:"userPrincipalName"`
					}
					if json.Unmarshal(userBody, &userData) == nil && userData.UserPrincipalName != "" {
						details.PrincipalName = userData.UserPrincipalName
					}
				}
			}

			grants = append(grants, details)
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate OAuth2 permission grants: %v", err), "consent-grants")
		}
		return grants, err
	}

	return grants, nil
}

// GetConsentGrantsForClient retrieves consent grants for a specific client application
func GetConsentGrantsForClient(ctx context.Context, session *SafeSession, clientID string) ([]OAuth2PermissionGrantDetails, error) {
	logger := internal.NewLogger()
	var grants []OAuth2PermissionGrantDetails

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return grants, err
	}

	// Filter by clientId
	initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '%s'", clientID)

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID          string  `json:"id"`
				ClientID    string  `json:"clientId"`
				ConsentType string  `json:"consentType"`
				PrincipalID *string `json:"principalId"`
				ResourceID  string  `json:"resourceId"`
				Scope       string  `json:"scope"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode OAuth2 permission grants: %v", err)
		}

		for _, grant := range data.Value {
			details := OAuth2PermissionGrantDetails{
				ID:          grant.ID,
				ClientID:    grant.ClientID,
				ConsentType: grant.ConsentType,
				ResourceID:  grant.ResourceID,
				Scope:       grant.Scope,
			}

			if grant.PrincipalID != nil {
				details.PrincipalID = *grant.PrincipalID
			}

			// Parse scopes
			if grant.Scope != "" {
				details.Scopes = strings.Fields(grant.Scope)
			}

			// Identify risky permissions
			for _, scope := range details.Scopes {
				if description, isRisky := RiskyOAuth2Permissions[scope]; isRisky {
					details.RiskyPermissions = append(details.RiskyPermissions, fmt.Sprintf("%s (%s)", scope, description))
					details.IsRisky = true
				}
			}

			// Get resource display name
			if details.ResourceID != "" {
				spURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=displayName", details.ResourceID)
				spBody, err := GraphAPIRequestWithRetry(ctx, "GET", spURL, token)
				if err == nil {
					var spData struct {
						DisplayName string `json:"displayName"`
					}
					if json.Unmarshal(spBody, &spData) == nil && spData.DisplayName != "" {
						details.ResourceDisplayName = spData.DisplayName
					}
				}
			}

			grants = append(grants, details)
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate consent grants for client %s: %v", clientID, err), "consent-grants")
		}
		return grants, err
	}

	return grants, nil
}

// FormatConsentGrantSummary formats consent grants for Enterprise Apps display
func FormatConsentGrantSummary(grants []OAuth2PermissionGrantDetails) (adminCount int, userCount int, riskyCount int, topPermissions string) {
	if len(grants) == 0 {
		return 0, 0, 0, "None"
	}

	permissionMap := make(map[string]int)

	for _, grant := range grants {
		if grant.ConsentType == "AllPrincipals" {
			adminCount++
		} else if grant.ConsentType == "Principal" {
			userCount++
		}

		if grant.IsRisky {
			riskyCount++
		}

		// Count permissions
		for _, scope := range grant.Scopes {
			permissionMap[scope]++
		}
	}

	// Get top 5 most common permissions
	type permCount struct {
		perm  string
		count int
	}
	var permCounts []permCount
	for perm, count := range permissionMap {
		permCounts = append(permCounts, permCount{perm, count})
	}

	// Sort by count (simple bubble sort for small lists)
	for i := 0; i < len(permCounts); i++ {
		for j := i + 1; j < len(permCounts); j++ {
			if permCounts[j].count > permCounts[i].count {
				permCounts[i], permCounts[j] = permCounts[j], permCounts[i]
			}
		}
	}

	// Take top 5
	topPerms := []string{}
	for i := 0; i < len(permCounts) && i < 5; i++ {
		topPerms = append(topPerms, permCounts[i].perm)
	}

	if len(topPerms) > 0 {
		topPermissions = strings.Join(topPerms, ", ")
	} else {
		topPermissions = "None"
	}

	return adminCount, userCount, riskyCount, topPermissions
}

// ------------------------------
// Sign-in Activity (for Principals module enhancement)
// ------------------------------

// SignInActivity represents sign-in activity for a user
type SignInActivity struct {
	LastSignInDateTime               string
	LastNonInteractiveSignInDateTime string
	LastSuccessfulSignInDateTime     string
	DaysSinceLastSignIn              int
	IsStale                          bool // True if >90 days or never signed in
	StaleReason                      string
}

// GetUserSignInActivity retrieves sign-in activity for a user
func GetUserSignInActivity(ctx context.Context, session *SafeSession, userObjectID string) (SignInActivity, error) {
	result := SignInActivity{
		LastSignInDateTime:               "Never",
		LastNonInteractiveSignInDateTime: "Never",
		LastSuccessfulSignInDateTime:     "Never",
		DaysSinceLastSignIn:              -1,
		IsStale:                          false,
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return result, fmt.Errorf("failed to get Graph token: %w", err)
	}

	// Get user with signInActivity property
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s?$select=signInActivity", userObjectID)

	body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err != nil {
		// Sign-in activity may not be available for all users (requires Azure AD Premium P1/P2)
		return result, nil // Return default values instead of error
	}

	var data struct {
		SignInActivity struct {
			LastSignInDateTime               string `json:"lastSignInDateTime"`
			LastNonInteractiveSignInDateTime string `json:"lastNonInteractiveSignInDateTime"`
			LastSuccessfulSignInDateTime     string `json:"lastSuccessfulSignInDateTime"`
		} `json:"signInActivity"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return result, fmt.Errorf("failed to parse sign-in activity: %w", err)
	}

	// Parse last sign-in datetime
	if data.SignInActivity.LastSignInDateTime != "" {
		result.LastSignInDateTime = data.SignInActivity.LastSignInDateTime
		// Try to parse and calculate days since last sign-in
		if t, err := time.Parse(time.RFC3339, data.SignInActivity.LastSignInDateTime); err == nil {
			daysSince := int(time.Since(t).Hours() / 24)
			result.DaysSinceLastSignIn = daysSince

			// Flag stale accounts (>90 days)
			if daysSince > 90 {
				result.IsStale = true
				result.StaleReason = fmt.Sprintf("Last sign-in %d days ago", daysSince)
			}
		}
	} else {
		result.IsStale = true
		result.StaleReason = "Never signed in"
	}

	// Parse last non-interactive sign-in
	if data.SignInActivity.LastNonInteractiveSignInDateTime != "" {
		result.LastNonInteractiveSignInDateTime = data.SignInActivity.LastNonInteractiveSignInDateTime
	}

	// Parse last successful sign-in
	if data.SignInActivity.LastSuccessfulSignInDateTime != "" {
		result.LastSuccessfulSignInDateTime = data.SignInActivity.LastSuccessfulSignInDateTime
	}

	return result, nil
}

// ------------------------------
// Application Owners and Publisher Verification
// ------------------------------

// ApplicationOwners represents owners of an application
type ApplicationOwners struct {
	OwnerCount int
	OwnerUPNs  []string
	OwnerIDs   []string
}

// GetApplicationOwners retrieves owners for an application
func GetApplicationOwners(ctx context.Context, session *SafeSession, appObjectID string) (ApplicationOwners, error) {
	result := ApplicationOwners{
		OwnerCount: 0,
		OwnerUPNs:  []string{},
		OwnerIDs:   []string{},
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return result, fmt.Errorf("failed to get Graph token: %w", err)
	}

	// Get application owners
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s/owners", appObjectID)

	body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err != nil {
		// Application may not exist or no access
		return result, nil // Return empty instead of error
	}

	var data struct {
		Value []struct {
			UserPrincipalName string `json:"userPrincipalName"`
			ID                string `json:"id"`
			DisplayName       string `json:"displayName"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return result, fmt.Errorf("failed to parse owners: %w", err)
	}

	result.OwnerCount = len(data.Value)

	for _, owner := range data.Value {
		if owner.UserPrincipalName != "" {
			result.OwnerUPNs = append(result.OwnerUPNs, owner.UserPrincipalName)
			result.OwnerIDs = append(result.OwnerIDs, owner.ID)
		} else if owner.DisplayName != "" {
			// Service principal or group owner
			result.OwnerUPNs = append(result.OwnerUPNs, owner.DisplayName)
			result.OwnerIDs = append(result.OwnerIDs, owner.ID)
		} else {
			result.OwnerIDs = append(result.OwnerIDs, owner.ID)
		}
	}

	return result, nil
}

// PublisherVerification represents publisher verification status
type PublisherVerification struct {
	IsVerified        bool
	VerifiedPublisher string
	VerificationDate  string
}

// GetPublisherVerification retrieves publisher verification status for an application
func GetPublisherVerification(ctx context.Context, session *SafeSession, appObjectID string) (PublisherVerification, error) {
	result := PublisherVerification{
		IsVerified:        false,
		VerifiedPublisher: "",
		VerificationDate:  "",
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return result, fmt.Errorf("failed to get Graph token: %w", err)
	}

	// Get application with verifiedPublisher property
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s?$select=verifiedPublisher", appObjectID)

	body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err != nil {
		// Application may not exist or no access
		return result, nil // Return default instead of error
	}

	var data struct {
		VerifiedPublisher struct {
			DisplayName         string `json:"displayName"`
			VerifiedPublisherID string `json:"verifiedPublisherId"`
			AddedDateTime       string `json:"addedDateTime"`
		} `json:"verifiedPublisher"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return result, fmt.Errorf("failed to parse publisher verification: %w", err)
	}

	// Check if publisher is verified
	if data.VerifiedPublisher.VerifiedPublisherID != "" || data.VerifiedPublisher.DisplayName != "" {
		result.IsVerified = true
		result.VerifiedPublisher = data.VerifiedPublisher.DisplayName
		result.VerificationDate = data.VerifiedPublisher.AddedDateTime
	}

	return result, nil
}

// Diagnostic function to test Graph API access
func TestGraphAPIAccess(ctx context.Context, session *SafeSession, tenantID string) error {
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		return fmt.Errorf("Failed to get token: %w", err)
	}

	fmt.Println("Token acquired successfully")
	fmt.Printf("Token prefix: %s...\n", token[:20])

	// Try a simple Graph API call with retry logic
	body, err := GraphAPIRequestWithRetry(ctx, "GET", "https://graph.microsoft.com/v1.0/me", token)
	if err != nil {
		return fmt.Errorf("Failed to call Graph API: %w", err)
	}

	fmt.Println("Successfully called /me endpoint")
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("Failed to parse response: %w", err)
	}
	fmt.Printf("Current user: %v\n", result["userPrincipalName"])
	return nil
}

// GetRBACAssignments fetches all role assignments for a principal (objectId) and expands each
// role into its exact actions/resources, returning RBACRows ready for CloudFox output.
// Captures role assignments at management group, subscription, resource group, and resource scopes.
func GetRBACAssignments(ctx context.Context, session *SafeSession, subscriptionID, principalObjectID string, tenantName string, subNameMap map[string]string) ([]RBACRow, error) {
	logger := internal.NewLogger()

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %v", err)
	}

	cred := &StaticTokenCredential{Token: token}

	// Role Assignments client
	assignClient, err := armauthorizationv2.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %v", err)
	}

	// Role Definitions client
	roleClient, err := armauthorizationv2.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %v", err)
	}

	var rows []RBACRow
	assignmentCount := 0

	// Get management group hierarchy for this subscription
	mgHierarchy := GetManagementGroupHierarchy(ctx, session, subscriptionID)
	if len(mgHierarchy) > 0 && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d management group(s) in hierarchy for subscription %s", len(mgHierarchy), subscriptionID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	// Enumerate role assignments at management group scopes (parent scopes)
	for _, mgID := range mgHierarchy {
		mgScope := fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID)
		mgPager := assignClient.NewListForScopePager(mgScope, &armauthorizationv2.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalObjectID)),
		})

		for mgPager.More() {
			page, err := mgPager.NextPage(ctx)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to get role assignments at management group scope %s: %v", mgScope, err), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
				break
			}

			for _, assignment := range page.Value {
				// API filter ensures only this principal's assignments are returned
				if assignment.Properties == nil || assignment.Properties.PrincipalID == nil {
					continue
				}
				assignmentCount++
				row := processRoleAssignment(ctx, assignment, subscriptionID, principalObjectID, tenantName, subNameMap, roleClient, session, logger)
				if row != nil {
					rows = append(rows, *row)
				}
			}
		}
	}

	// List assignments at subscription scope (includes inherited from RG and resource levels)
	pager := assignClient.NewListForScopePager(
		fmt.Sprintf("/subscriptions/%s", subscriptionID),
		&armauthorizationv2.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalObjectID)),
		},
	)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to get next page of role assignments for subscription %s: %v", subscriptionID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
			break // Stop pagination but return what we have so far
		}

		for _, assignment := range page.Value {
			// API filter ensures only this principal's assignments are returned
			if assignment.Properties == nil || assignment.Properties.PrincipalID == nil {
				continue
			}

			assignmentCount++
			row := processRoleAssignment(ctx, assignment, subscriptionID, principalObjectID, tenantName, subNameMap, roleClient, session, logger)
			if row != nil {
				rows = append(rows, *row)
			}
		}
	}

	// Log summary
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		mgSuffix := ""
		if len(mgHierarchy) > 0 {
			mgSuffix = fmt.Sprintf(" including %d management group(s)", len(mgHierarchy))
		}
		logger.InfoM(fmt.Sprintf("Found %d role assignment(s) for principal %s in subscription %s across all scopes (management groups, subscription, resource groups, resources)%s", assignmentCount, principalObjectID, subscriptionID, mgSuffix), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return DedupeRBACRows(rows), nil
}

// processRoleAssignment processes a single role assignment and returns an RBACRow
func processRoleAssignment(ctx context.Context, assignment *armauthorizationv2.RoleAssignment, subscriptionID, principalObjectID, tenantName string, subNameMap map[string]string, roleClient *armauthorizationv2.RoleDefinitionsClient, session *SafeSession, logger internal.Logger) *RBACRow {
	scope := ""
	if assignment.Properties.Scope != nil {
		scope = *assignment.Properties.Scope
	}

	roleDefID := ""
	if assignment.Properties.RoleDefinitionID != nil {
		roleDefID = *assignment.Properties.RoleDefinitionID
	}

	// Default placeholders
	var roleDefResp *armauthorizationv2.RoleDefinition
	roleName := "(role assignment exists but unreadable)"
	actions := []string{}

	// Attempt to fetch role definition if valid ID
	if roleDefID != "" {
		// Extract role GUID from full resource ID using existing helper
		roleGUID := ParseRoleDefinitionID(roleDefID)

		// Try multiple scopes to find the role definition (role definitions exist at subscription or tenant root, not resource-specific scopes)
		scopes := []string{
			fmt.Sprintf("/subscriptions/%s", subscriptionID),
			"/", // fallback to tenant root
		}

		for _, defScope := range scopes {
			resp, err := roleClient.Get(ctx, defScope, roleGUID, nil)
			if err == nil && resp.RoleDefinition.Properties != nil {
				roleDefResp = &resp.RoleDefinition
				roleName = *resp.RoleDefinition.Properties.RoleName
				for _, perm := range resp.RoleDefinition.Properties.Permissions {
					for _, a := range perm.Actions {
						actions = append(actions, *a)
					}
					for _, na := range perm.NotActions {
						actions = append(actions, fmt.Sprintf("!%s", *na))
					}
				}
				break // Found it, stop trying other scopes
			}
		}

		// If all scopes failed, use GUID as fallback
		if roleName == "(role assignment exists but unreadable)" {
			roleName = fmt.Sprintf("Role-%s", roleGUID)
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to resolve role definition %s at any scope", roleGUID), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
		}
	}

	// If we couldn't fetch definition and no meaningful ID exists, skip this assignment
	if roleDefID == "" && len(actions) == 0 {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Skipping role assignment with no role definition ID at scope %s", scope), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return nil
	}

	// Resolve principal info
	principalInfo, _ := GetPrincipalInfo(session, principalObjectID)

	tenantScope, subScope, rgScope := NormalizeScope(scope, tenantName, subNameMap)

	row := RBACRow{
		SubscriptionID:     subscriptionID,
		SubscriptionScope:  subScope,
		ResourceGroupScope: rgScope,
		TenantScope:        tenantScope,
		Principal:          principalObjectID,
		PrincipalName:      principalInfo.DisplayName,
		PrincipalUPN:       principalInfo.UserPrincipalName,
		PrincipalType:      principalInfo.UserType,
		RoleName:           roleName,
		ProvidersResources: strings.Join(actions, ", "),
		FullScope:          scope,
		DangerLevel:        GetDangerLevel(roleName),
		RawRoleDefinition:  roleDefResp,
		RawRoleAssignment:  assignment,
	}

	return &row
}

// GetManagementGroupHierarchy returns the management group IDs in the hierarchy for a subscription
// Returns an array of management group IDs from immediate parent to root
func GetManagementGroupHierarchy(ctx context.Context, session *SafeSession, subscriptionID string) []string {
	logger := internal.NewLogger()
	var hierarchy []string

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for management group enumeration: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return hierarchy
	}

	cred := &StaticTokenCredential{Token: token}

	// Use entities API to find the subscription and its parent management group
	entitiesClient, err := armmanagementgroups.NewEntitiesClient(cred, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create entities client: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return hierarchy
	}

	// List all entities to find our subscription
	pager := entitiesClient.NewListPager(nil)
	var parentMgID string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list entities: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
			return hierarchy
		}

		for _, entity := range page.Value {
			if entity.Name != nil && *entity.Name == subscriptionID && entity.Properties != nil && entity.Properties.Parent != nil && entity.Properties.Parent.ID != nil {
				// Extract management group ID from parent ID
				// Format: /providers/Microsoft.Management/managementGroups/{mgId}
				parentID := *entity.Properties.Parent.ID
				parts := strings.Split(parentID, "/")
				if len(parts) > 0 {
					parentMgID = parts[len(parts)-1]
				}
				break
			}
		}
		if parentMgID != "" {
			break
		}
	}

	if parentMgID == "" {
		// Subscription has no parent management group (or we don't have permissions to see it)
		return hierarchy
	}

	// Now walk up the management group hierarchy
	mgClient, err := armmanagementgroups.NewClient(cred, nil)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create management groups client: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return hierarchy
	}

	currentMgID := parentMgID
	visited := make(map[string]bool)

	for currentMgID != "" && !visited[currentMgID] {
		visited[currentMgID] = true
		hierarchy = append(hierarchy, currentMgID)

		// Get the management group to find its parent
		recurse := false
		mg, err := mgClient.Get(ctx, currentMgID, &armmanagementgroups.ClientGetOptions{
			Recurse: &recurse,
		})
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to get management group %s: %v", currentMgID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
			break
		}

		// Check if there's a parent
		if mg.Properties != nil && mg.Properties.Details != nil && mg.Properties.Details.Parent != nil && mg.Properties.Details.Parent.ID != nil {
			parentID := *mg.Properties.Details.Parent.ID
			parts := strings.Split(parentID, "/")
			if len(parts) > 0 {
				currentMgID = parts[len(parts)-1]
			} else {
				break
			}
		} else {
			// Reached the root
			break
		}
	}

	return hierarchy
}

func scope(subscriptionID string) string {
	return fmt.Sprintf("/subscriptions/%s", subscriptionID)
}

// AppRegistrationCertificate represents an app registration with certificate credentials
type AppRegistrationCertificate struct {
	DisplayName      string
	ApplicationID    string // App ID (client ID)
	ObjectID         string // Object ID in Entra
	CreatedDateTime  string
	HasCertificates  bool
	CertificateCount int
	Certificates     []KeyCredential
}

// KeyCredential represents a certificate credential from the manifest
type KeyCredential struct {
	KeyID         string
	Type          string // "AsymmetricX509Cert"
	Usage         string // "Verify" or "Sign"
	DisplayName   string
	StartDateTime string
	EndDateTime   string
	Key           string // Base64-encoded certificate (PFX)
	KeySize       int    // Size of the key in bytes
}

// EnumerateAppRegistrationCertificates enumerates app registrations with certificate credentials
func EnumerateAppRegistrationCertificates(session *SafeSession, lootMap map[string]*internal.LootFile) error {
	if lootMap == nil {
		return nil
	}

	certLoot, ok := lootMap["app-registration-certificates"]
	if !ok {
		return nil
	}

	// Get Graph API token
	token, err := session.GetTokenForResource(globals.CommonScopes[1])
	if err != nil {
		return fmt.Errorf("failed to get Graph token: %v", err)
	}

	// Build request URL - get app registrations with keyCredentials
	initialURL := "https://graph.microsoft.com/v1.0/myorganization/applications?$select=displayName,id,appId,createdDateTime,keyCredentials"

	var allAppsWithCerts []AppRegistrationCertificate

	// Use GraphAPIPagedRequest for automatic retry logic
	err = GraphAPIPagedRequest(context.Background(), initialURL, token, func(body []byte) (bool, string, error) {
		// Parse response
		var result struct {
			Value []struct {
				DisplayName     *string `json:"displayName"`
				ID              *string `json:"id"`
				AppID           *string `json:"appId"`
				CreatedDateTime *string `json:"createdDateTime"`
				KeyCredentials  []struct {
					KeyID         *string `json:"keyId"`
					Type          *string `json:"type"`
					Usage         *string `json:"usage"`
					DisplayName   *string `json:"displayName"`
					StartDateTime *string `json:"startDateTime"`
					EndDateTime   *string `json:"endDateTime"`
					Key           *string `json:"key"` // Base64-encoded certificate
				} `json:"keyCredentials"`
			} `json:"value"`
			NextLink *string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			return false, "", fmt.Errorf("failed to parse app registrations: %v", err)
		}

		// Process each app registration
		for _, app := range result.Value {
			// Skip if no key credentials
			if len(app.KeyCredentials) == 0 {
				continue
			}

			appInfo := AppRegistrationCertificate{
				DisplayName:      SafeStringPtr(app.DisplayName),
				ApplicationID:    SafeStringPtr(app.AppID),
				ObjectID:         SafeStringPtr(app.ID),
				CreatedDateTime:  SafeStringPtr(app.CreatedDateTime),
				HasCertificates:  false,
				CertificateCount: 0,
				Certificates:     []KeyCredential{},
			}

			// Check each key credential
			for _, keyCred := range app.KeyCredentials {
				// Only interested in certificates (not keys)
				credType := SafeStringPtr(keyCred.Type)
				if credType != "AsymmetricX509Cert" {
					continue
				}

				// Check if this is a PFX (has private key embedded)
				keyData := SafeStringPtr(keyCred.Key)
				if len(keyData) > 2000 { // PFX files are typically large
					cert := KeyCredential{
						KeyID:         SafeStringPtr(keyCred.KeyID),
						Type:          credType,
						Usage:         SafeStringPtr(keyCred.Usage),
						DisplayName:   SafeStringPtr(keyCred.DisplayName),
						StartDateTime: SafeStringPtr(keyCred.StartDateTime),
						EndDateTime:   SafeStringPtr(keyCred.EndDateTime),
						Key:           keyData,
						KeySize:       len(keyData),
					}
					appInfo.Certificates = append(appInfo.Certificates, cert)
					appInfo.HasCertificates = true
					appInfo.CertificateCount++
				}
			}

			// Only add if certificates found
			if appInfo.HasCertificates {
				allAppsWithCerts = append(allAppsWithCerts, appInfo)
			}
		}

		// Check for next page
		hasMore := result.NextLink != nil
		nextURL := ""
		if hasMore {
			nextURL = *result.NextLink
		}
		return hasMore, nextURL, nil
	})

	if err != nil {
		return fmt.Errorf("failed to enumerate app registration certificates: %v", err)
	}

	// Generate loot output
	if len(allAppsWithCerts) > 0 {
		certLoot.Contents += GenerateAppRegistrationCertificateLoot(allAppsWithCerts)
	}

	return nil
}

// GenerateAppRegistrationCertificateLoot generates loot file content for app registration certificates
func GenerateAppRegistrationCertificateLoot(apps []AppRegistrationCertificate) string {
	var output string

	output += fmt.Sprintf("# App Registration Certificate Credentials\n\n")
	output += fmt.Sprintf("**SECURITY NOTE**: App Registrations with embedded PFX certificates can be used for authentication!\n")
	output += fmt.Sprintf("PFX files contain private keys and can be used to authenticate as the application.\n\n")
	output += fmt.Sprintf("Found %d app registration(s) with certificate credentials:\n\n", len(apps))

	for i, app := range apps {
		output += fmt.Sprintf("## App %d: %s\n\n", i+1, app.DisplayName)
		output += fmt.Sprintf("- **Application (Client) ID**: %s\n", app.ApplicationID)
		output += fmt.Sprintf("- **Object ID**: %s\n", app.ObjectID)
		output += fmt.Sprintf("- **Created**: %s\n", app.CreatedDateTime)
		output += fmt.Sprintf("- **Certificate Count**: %d\n\n", app.CertificateCount)

		for j, cert := range app.Certificates {
			output += fmt.Sprintf("### Certificate %d\n\n", j+1)
			output += fmt.Sprintf("- **Key ID**: %s\n", cert.KeyID)
			output += fmt.Sprintf("- **Type**: %s\n", cert.Type)
			output += fmt.Sprintf("- **Usage**: %s\n", cert.Usage)
			if cert.DisplayName != "" {
				output += fmt.Sprintf("- **Display Name**: %s\n", cert.DisplayName)
			}
			output += fmt.Sprintf("- **Valid From**: %s\n", cert.StartDateTime)
			output += fmt.Sprintf("- **Valid To**: %s\n", cert.EndDateTime)
			output += fmt.Sprintf("- **Key Size**: %d bytes\n\n", cert.KeySize)

			output += fmt.Sprintf("**Extract Certificate to File**:\n")
			output += fmt.Sprintf("```bash\n")
			output += fmt.Sprintf("# Save base64 certificate data to file\n")
			output += fmt.Sprintf("echo '%s' | base64 -d > %s_%s.pfx\n\n", cert.Key[:50]+"...", app.ObjectID, cert.KeyID[:8])
			output += fmt.Sprintf("# Verify it's a valid PFX\n")
			output += fmt.Sprintf("openssl pkcs12 -info -in %s_%s.pfx -noout\n", app.ObjectID, cert.KeyID[:8])
			output += fmt.Sprintf("```\n\n")

			output += fmt.Sprintf("**Authenticate with Certificate**:\n")
			output += fmt.Sprintf("```bash\n")
			output += fmt.Sprintf("# Azure CLI\n")
			output += fmt.Sprintf("az login --service-principal \\\n")
			output += fmt.Sprintf("  --username %s \\\n", app.ApplicationID)
			output += fmt.Sprintf("  --tenant <TENANT_ID> \\\n")
			output += fmt.Sprintf("  --password %s_%s.pfx\n\n", app.ObjectID, cert.KeyID[:8])

			output += fmt.Sprintf("# PowerShell\n")
			output += fmt.Sprintf("$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(\"%s_%s.pfx\")\n", app.ObjectID, cert.KeyID[:8])
			output += fmt.Sprintf("Connect-AzAccount -ServicePrincipal -ApplicationId \"%s\" -TenantId \"<TENANT_ID>\" -CertificateThumbprint $cert.Thumbprint\n", app.ApplicationID)
			output += fmt.Sprintf("```\n\n")

			output += fmt.Sprintf("---\n\n")
		}
	}

	output += fmt.Sprintf("## Security Implications\n\n")
	output += fmt.Sprintf("- **Authentication Bypass**: Certificate credentials allow authentication without passwords\n")
	output += fmt.Sprintf("- **Long-Lived**: Certificates often have multi-year validity periods\n")
	output += fmt.Sprintf("- **Privilege Escalation**: App registrations may have high-privilege role assignments\n")
	output += fmt.Sprintf("- **Persistence**: Attackers can use extracted certificates for persistent access\n\n")

	output += fmt.Sprintf("## Remediation\n\n")
	output += fmt.Sprintf("1. Review app registration permissions and reduce unnecessary privileges\n")
	output += fmt.Sprintf("2. Rotate certificate credentials regularly\n")
	output += fmt.Sprintf("3. Use shorter validity periods for certificates\n")
	output += fmt.Sprintf("4. Enable conditional access policies for service principals\n")
	output += fmt.Sprintf("5. Monitor authentication logs for unusual app registration activity\n\n")

	return output
}

// AppRegistrationCredential represents a single credential from an app registration
type AppRegistrationCredential struct {
	AppID            string
	AppName          string
	CredType         string // "Password" or "Certificate"
	CredName         string // DisplayName or KeyID
	ClientSecretHint string // Only for passwords
	Thumbprint       string // Only for certificates
	StartDateTime    string
	EndDateTime      string
	Permissions      string // API permissions (e.g., "Microsoft Graph: User.Read.All, Mail.Send")
}

// formatAppPermissions formats the requiredResourceAccess into a human-readable string
func formatAppPermissions(resourceAccess []struct {
	ResourceAppID  *string `json:"resourceAppId"`
	ResourceAccess []struct {
		ID   *string `json:"id"`
		Type *string `json:"type"`
	} `json:"resourceAccess"`
}) string {
	if len(resourceAccess) == 0 {
		return "None"
	}

	// Map well-known resource app IDs to friendly names
	resourceNames := map[string]string{
		"00000003-0000-0000-c000-000000000000": "Microsoft Graph",
		"00000002-0000-0000-c000-000000000000": "Azure AD Graph",
		"797f4846-ba00-4fd7-ba43-dac1f8f63013": "Azure Service Management",
		"e406a681-f3d4-42a8-90b6-c2b029497af1": "Office 365 Management APIs",
	}

	var permissions []string
	for _, res := range resourceAccess {
		resourceAppID := SafeStringPtr(res.ResourceAppID)
		if resourceAppID == "" {
			continue
		}

		// Get friendly name or use App ID
		resourceName := resourceNames[resourceAppID]
		if resourceName == "" {
			resourceName = resourceAppID
		}

		// Count permissions by type
		scopeCount := 0
		roleCount := 0
		for _, access := range res.ResourceAccess {
			accessType := SafeStringPtr(access.Type)
			if accessType == "Scope" {
				scopeCount++
			} else if accessType == "Role" {
				roleCount++
			}
		}

		// Format: "Microsoft Graph (3 delegated, 2 app)"
		var parts []string
		if scopeCount > 0 {
			parts = append(parts, fmt.Sprintf("%d delegated", scopeCount))
		}
		if roleCount > 0 {
			parts = append(parts, fmt.Sprintf("%d app", roleCount))
		}

		if len(parts) > 0 {
			permissions = append(permissions, fmt.Sprintf("%s (%s)", resourceName, strings.Join(parts, ", ")))
		}
	}

	if len(permissions) == 0 {
		return "None"
	}

	return strings.Join(permissions, " | ")
}

// GetAppRegistrationCredentials enumerates all app registrations and their credentials
func GetAppRegistrationCredentials(ctx context.Context, session *SafeSession) ([]AppRegistrationCredential, error) {
	logger := internal.NewLogger()
	var credentials []AppRegistrationCredential

	// Get Graph API token
	token, err := session.GetTokenForResource(globals.CommonScopes[1])
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for app registrations: %v", err), globals.AZ_ACCESSKEYS_MODULE_NAME)
		}
		return nil, fmt.Errorf("failed to get Graph token: %v", err)
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Successfully obtained Graph API token for app registrations", globals.AZ_ACCESSKEYS_MODULE_NAME)
	}

	// Query app registrations with credentials and API permissions using the new paged request utility
	initialURL := "https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,id,keyCredentials,passwordCredentials,requiredResourceAccess"
	pageCount := 0

	processPage := func(body []byte) (hasMore bool, nextURL string, err error) {
		pageCount++
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Processing app registrations page %d", pageCount), globals.AZ_ACCESSKEYS_MODULE_NAME)
		}

		// Parse response
		var result struct {
			Value []struct {
				DisplayName    *string `json:"displayName"`
				AppID          *string `json:"appId"`
				ID             *string `json:"id"`
				KeyCredentials []struct {
					KeyID               *string `json:"keyId"`
					Type                *string `json:"type"`
					DisplayName         *string `json:"displayName"`
					StartDateTime       *string `json:"startDateTime"`
					EndDateTime         *string `json:"endDateTime"`
					CustomKeyIdentifier []byte  `json:"customKeyIdentifier"`
				} `json:"keyCredentials"`
				PasswordCredentials []struct {
					KeyID         *string `json:"keyId"`
					DisplayName   *string `json:"displayName"`
					Hint          *string `json:"hint"`
					StartDateTime *string `json:"startDateTime"`
					EndDateTime   *string `json:"endDateTime"`
				} `json:"passwordCredentials"`
				RequiredResourceAccess []struct {
					ResourceAppID  *string `json:"resourceAppId"`
					ResourceAccess []struct {
						ID   *string `json:"id"`
						Type *string `json:"type"`
					} `json:"resourceAccess"`
				} `json:"requiredResourceAccess"`
			} `json:"value"`
			NextLink *string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to parse JSON response: %v", err), globals.AZ_ACCESSKEYS_MODULE_NAME)
			}
			return false, "", fmt.Errorf("failed to parse response: %v", err)
		}

		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Found %d app registration(s) on page %d", len(result.Value), pageCount), globals.AZ_ACCESSKEYS_MODULE_NAME)
		}

		// Process each app registration
		for _, app := range result.Value {
			appID := SafeStringPtr(app.AppID)
			appName := SafeStringPtr(app.DisplayName)
			if appName == "" {
				appName = appID
			}

			passwordCount := len(app.PasswordCredentials)
			keyCount := len(app.KeyCredentials)

			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && (passwordCount > 0 || keyCount > 0) {
				logger.InfoM(fmt.Sprintf("App '%s' has %d password(s) and %d certificate(s)", appName, passwordCount, keyCount), globals.AZ_ACCESSKEYS_MODULE_NAME)
			}

			// Format API permissions for this app
			permissions := formatAppPermissions(app.RequiredResourceAccess)

			// Process password credentials (client secrets)
			for _, pwd := range app.PasswordCredentials {
				cred := AppRegistrationCredential{
					AppID:            appID,
					AppName:          appName,
					CredType:         "Password",
					CredName:         SafeStringPtr(pwd.DisplayName),
					ClientSecretHint: SafeStringPtr(pwd.Hint),
					StartDateTime:    SafeStringPtr(pwd.StartDateTime),
					EndDateTime:      SafeStringPtr(pwd.EndDateTime),
					Permissions:      permissions,
				}
				if cred.CredName == "" {
					cred.CredName = SafeStringPtr(pwd.KeyID)
				}
				credentials = append(credentials, cred)
			}

			// Process key credentials (certificates)
			for _, key := range app.KeyCredentials {
				// Only process X.509 certificates
				credType := SafeStringPtr(key.Type)
				if credType != "AsymmetricX509Cert" {
					continue
				}

				// Calculate thumbprint from customKeyIdentifier if available
				thumbprint := ""
				if len(key.CustomKeyIdentifier) > 0 {
					thumbprint = fmt.Sprintf("%X", key.CustomKeyIdentifier)
				}

				cred := AppRegistrationCredential{
					AppID:         appID,
					AppName:       appName,
					CredType:      "Certificate",
					CredName:      SafeStringPtr(key.DisplayName),
					Thumbprint:    thumbprint,
					StartDateTime: SafeStringPtr(key.StartDateTime),
					EndDateTime:   SafeStringPtr(key.EndDateTime),
					Permissions:   permissions,
				}
				if cred.CredName == "" {
					cred.CredName = SafeStringPtr(key.KeyID)
				}
				credentials = append(credentials, cred)
			}
		}

		// Determine if there are more pages
		hasMore = result.NextLink != nil
		nextURL = ""
		if hasMore {
			nextURL = SafeStringPtr(result.NextLink)
		}

		return hasMore, nextURL, nil
	}

	// Use the new paged request utility with intelligent retry logic
	err = GraphAPIPagedRequest(ctx, initialURL, token, processPage)
	if err != nil {
		return credentials, err
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Successfully enumerated %d total credential(s) from app registrations", len(credentials)), globals.AZ_ACCESSKEYS_MODULE_NAME)
	}

	return credentials, nil
}

// ------------------------------
// PIM (Privileged Identity Management) Support
// ------------------------------

// PIMRoleAssignment represents a PIM role assignment (eligible or active)
type PIMRoleAssignment struct {
	PrincipalID      string
	PrincipalType    string // "User" or "Group"
	RoleDefinitionID string
	RoleName         string
	Scope            string
	Status           string // "Provisioned" for eligible roles
	AssignedVia      string // "Direct (PIM Eligible)", "Group (PIM Eligible)", "Direct (PIM Active)", "Group (PIM Active)"
}

// GetPIMEligibleRoles retrieves PIM-eligible role assignments for a subscription
// These are roles that can be activated but are not currently active
func GetPIMEligibleRoles(ctx context.Context, session *SafeSession, subscriptionID string, principalIDs []string) ([]PIMRoleAssignment, error) {
	logger := internal.NewLogger()
	var assignments []PIMRoleAssignment

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for PIM eligibility: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return assignments, err
	}

	pimEligibilityURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subscriptionID)
	body, err := HTTPRequestWithRetry(ctx, "GET", pimEligibilityURL, token, nil, DefaultRateLimitConfig())
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query PIM eligibility for subscription %s: %v", subscriptionID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return assignments, err
	}

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

	if err := json.Unmarshal(body, &pimData); err != nil {
		return assignments, fmt.Errorf("failed to parse PIM eligibility response: %v", err)
	}

	// Create a map for quick principal ID lookups
	principalMap := make(map[string]bool)
	for _, pid := range principalIDs {
		principalMap[pid] = true
	}

	for _, pimAssignment := range pimData.Value {
		principalID := pimAssignment.Properties.PrincipalID

		// Only include assignments for principals in our list
		if !principalMap[principalID] {
			continue
		}

		roleName := pimAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName
		scope := pimAssignment.Properties.Scope
		status := pimAssignment.Properties.Status
		principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

		assignedVia := "Direct (PIM Eligible)"
		if principalType == "Group" {
			assignedVia = "Group (PIM Eligible)"
		}

		assignments = append(assignments, PIMRoleAssignment{
			PrincipalID:      principalID,
			PrincipalType:    principalType,
			RoleDefinitionID: pimAssignment.Properties.RoleDefinitionID,
			RoleName:         roleName,
			Scope:            scope,
			Status:           status,
			AssignedVia:      assignedVia,
		})
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(assignments) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d PIM-eligible role assignment(s) for subscription %s", len(assignments), subscriptionID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return assignments, nil
}

// GetPIMActiveRoles retrieves currently active PIM role assignments for a subscription
// These are roles that have been activated through PIM
func GetPIMActiveRoles(ctx context.Context, session *SafeSession, subscriptionID string, principalIDs []string) ([]PIMRoleAssignment, error) {
	logger := internal.NewLogger()
	var assignments []PIMRoleAssignment

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for active PIM roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return assignments, err
	}

	pimActiveURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subscriptionID)
	body, err := HTTPRequestWithRetry(ctx, "GET", pimActiveURL, token, nil, DefaultRateLimitConfig())
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to query active PIM roles for subscription %s: %v", subscriptionID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return assignments, err
	}

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

	if err := json.Unmarshal(body, &pimData); err != nil {
		return assignments, fmt.Errorf("failed to parse active PIM response: %v", err)
	}

	// Create a map for quick principal ID lookups
	principalMap := make(map[string]bool)
	for _, pid := range principalIDs {
		principalMap[pid] = true
	}

	for _, pimAssignment := range pimData.Value {
		principalID := pimAssignment.Properties.PrincipalID

		// Only include assignments for principals in our list
		if !principalMap[principalID] {
			continue
		}

		roleName := pimAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName
		scope := pimAssignment.Properties.Scope
		principalType := pimAssignment.Properties.ExpandedProperties.Principal.Type

		assignedVia := "Direct (PIM Active)"
		if principalType == "Group" {
			assignedVia = "Group (PIM Active)"
		}

		assignments = append(assignments, PIMRoleAssignment{
			PrincipalID:      principalID,
			PrincipalType:    principalType,
			RoleDefinitionID: pimAssignment.Properties.RoleDefinitionID,
			RoleName:         roleName,
			Scope:            scope,
			Status:           "Active",
			AssignedVia:      assignedVia,
		})
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(assignments) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d active PIM role assignment(s) for subscription %s", len(assignments), subscriptionID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return assignments, nil
}

// ------------------------------
// Groups Enumeration
// ------------------------------

// ListEntraGroups returns all security groups in the tenant via Microsoft Graph
func ListEntraGroups(ctx context.Context, session *SafeSession, tenantID string) ([]PrincipalInfo, error) {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Entra security groups for tenant: %v", tenantID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return nil, err
	}

	groups := []PrincipalInfo{}
	initialURL := "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mailNickname,securityEnabled"

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID              string `json:"id"`
				DisplayName     string `json:"displayName"`
				MailNickname    string `json:"mailNickname"`
				SecurityEnabled *bool  `json:"securityEnabled"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode Graph response: %v", err)
		}

		for _, g := range data.Value {
			// Only include security-enabled groups
			if g.SecurityEnabled != nil && *g.SecurityEnabled {
				name := g.DisplayName
				if name == "" {
					name = g.MailNickname
				}
				groups = append(groups, PrincipalInfo{
					ObjectID:          g.ID,
					UserPrincipalName: g.MailNickname,
					DisplayName:       name,
					UserType:          "Group",
				})
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to enumerate groups: %v", err)
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d security group(s)", len(groups)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return groups, nil
}

// GetGroupMembershipsForDisplay retrieves group memberships and returns display names
// Returns a formatted string of group names for display in output
func GetGroupMembershipsForDisplay(ctx context.Context, session *SafeSession, principalObjectID string) string {
	groupIDs := GetUserGroupMemberships(ctx, session, principalObjectID)
	if len(groupIDs) == 0 {
		return ""
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return ""
	}

	var groupNames []string
	for _, groupID := range groupIDs {
		url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s?$select=displayName", groupID)
		body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
		if err == nil {
			var groupData struct {
				DisplayName string `json:"displayName"`
			}
			if json.Unmarshal(body, &groupData) == nil && groupData.DisplayName != "" {
				groupNames = append(groupNames, groupData.DisplayName)
			}
		}
	}

	if len(groupNames) == 0 {
		return ""
	}

	return strings.Join(groupNames, ", ")
}

// ------------------------------
// Conditional Access Policies
// ------------------------------

// ConditionalAccessPolicy represents a CA policy assignment
type ConditionalAccessPolicy struct {
	ID          string
	DisplayName string
	State       string // "enabled", "disabled", "enabledForReportingButNotEnforced"
}

// GetConditionalAccessPoliciesForPrincipal retrieves CA policies that apply to a principal
func GetConditionalAccessPoliciesForPrincipal(ctx context.Context, session *SafeSession, principalObjectID string) ([]ConditionalAccessPolicy, error) {
	logger := internal.NewLogger()
	var policies []ConditionalAccessPolicy

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for CA policies: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return policies, err
	}

	// Get all conditional access policies
	initialURL := "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				State       string `json:"state"`
				Conditions  struct {
					Users struct {
						IncludeUsers  []string `json:"includeUsers"`
						IncludeGroups []string `json:"includeGroups"`
					} `json:"users"`
				} `json:"conditions"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode CA policies: %v", err)
		}

		for _, policy := range data.Value {
			// Check if the principal is included in this policy
			isPrincipalIncluded := false

			// Check if principal is directly included
			for _, userID := range policy.Conditions.Users.IncludeUsers {
				if userID == principalObjectID || userID == "All" {
					isPrincipalIncluded = true
					break
				}
			}

			// Check if any of principal's groups are included
			if !isPrincipalIncluded {
				groupIDs := GetUserGroupMemberships(ctx, session, principalObjectID)
				for _, groupID := range groupIDs {
					for _, includedGroupID := range policy.Conditions.Users.IncludeGroups {
						if groupID == includedGroupID {
							isPrincipalIncluded = true
							break
						}
					}
					if isPrincipalIncluded {
						break
					}
				}
			}

			if isPrincipalIncluded {
				policies = append(policies, ConditionalAccessPolicy{
					ID:          policy.ID,
					DisplayName: policy.DisplayName,
					State:       policy.State,
				})
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate CA policies: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return policies, err
	}

	return policies, nil
}

// FormatConditionalAccessPolicies formats CA policies for display
func FormatConditionalAccessPolicies(policies []ConditionalAccessPolicy) string {
	if len(policies) == 0 {
		return ""
	}

	var formatted []string
	for _, policy := range policies {
		formatted = append(formatted, fmt.Sprintf("%s (%s)", policy.DisplayName, policy.State))
	}

	return strings.Join(formatted, "\n")
}

// ------------------------------
// Admin Role Checking
// ------------------------------

// IsAdminRole checks if a role name indicates admin/privileged access
// This includes both Entra ID roles and Azure RBAC roles
func IsAdminRole(roleName string) bool {
	if roleName == "" {
		return false
	}

	roleNameLower := strings.ToLower(roleName)

	// Entra ID admin roles
	entraAdminRoles := []string{
		"global administrator",
		"privileged role administrator",
		"security administrator",
		"user administrator",
		"cloud application administrator",
		"application administrator",
		"authentication administrator",
		"privileged authentication administrator",
		"global reader",
		"intune administrator",
		"exchange administrator",
		"sharepoint administrator",
		"teams administrator",
		"billing administrator",
		"helpdesk administrator",
		"password administrator",
	}

	// Azure RBAC admin roles
	azureAdminRoles := []string{
		"owner",
		"contributor",
		"user access administrator",
		"role based access control administrator",
		"security admin",
		"key vault administrator",
		"managed identity operator",
		"managed identity contributor",
		"virtual machine administrator login",
		"virtual machine contributor",
	}

	// Check Entra ID roles
	for _, adminRole := range entraAdminRoles {
		if strings.Contains(roleNameLower, adminRole) {
			return true
		}
	}

	// Check Azure RBAC roles
	for _, adminRole := range azureAdminRoles {
		if roleNameLower == adminRole {
			return true
		}
	}

	// Check for "admin" or "administrator" in role name as fallback
	if strings.Contains(roleNameLower, "admin") {
		return true
	}

	return false
}

// IsPrincipalAdmin checks if a principal has any admin roles across all subscriptions
// This function is designed to be used by managed identity modules to add an "Admin?" column
func IsPrincipalAdmin(ctx context.Context, session *SafeSession, principalObjectID string, subscriptionIDs []string) bool {
	logger := internal.NewLogger()

	// Check Entra ID directory roles first (Global Admin, etc.)
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err == nil {
		url := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s/memberOf", principalObjectID)
		body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
		if err == nil {
			var data struct {
				Value []struct {
					OdataType   string `json:"@odata.type"`
					DisplayName string `json:"displayName"`
				} `json:"value"`
			}
			if json.Unmarshal(body, &data) == nil {
				for _, membership := range data.Value {
					if membership.OdataType == "#microsoft.graph.directoryRole" {
						if IsAdminRole(membership.DisplayName) {
							if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
								logger.InfoM(fmt.Sprintf("Principal %s has admin Entra ID role: %s", principalObjectID, membership.DisplayName), globals.AZ_PRINCIPALS_MODULE_NAME)
							}
							return true
						}
					}
				}
			}
		}
	}

	// Check Azure RBAC roles across all subscriptions
	for _, subID := range subscriptionIDs {
		roleNames, err := GetRoleAssignmentsForPrincipal(ctx, session, principalObjectID, subID)
		if err != nil {
			continue
		}

		for _, roleName := range roleNames {
			if IsAdminRole(roleName) {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.InfoM(fmt.Sprintf("Principal %s has admin RBAC role: %s in subscription %s", principalObjectID, roleName, subID), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
				return true
			}
		}
	}

	return false
}

// ------------------------------
// Enhanced RBAC with Inheritance Tracking
// ------------------------------

// RBACAssignmentWithInheritance represents an RBAC role assignment with inheritance information
type RBACAssignmentWithInheritance struct {
	RoleName         string
	Scope            string
	ScopeType        string // "TenantRoot", "ManagementGroup", "Subscription", "ResourceGroup", "Resource"
	ScopeDisplayName string
	AssignedVia      string // "Direct", "Group"
	InheritedFrom    string // Empty if direct assignment, otherwise shows parent scope
	PrincipalID      string
}

// GetEnhancedRBACAssignments retrieves RBAC assignments with full scope hierarchy and inheritance tracking
func GetEnhancedRBACAssignments(ctx context.Context, session *SafeSession, principalObjectID string, subscriptionID string) ([]RBACAssignmentWithInheritance, error) {
	logger := internal.NewLogger()
	var assignments []RBACAssignmentWithInheritance

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return assignments, err
	}

	cred := &StaticTokenCredential{Token: token}
	raClient, err := armauthorizationv2.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return assignments, err
	}

	// Get user's group memberships for group-based assignment tracking
	groupIDs := GetUserGroupMemberships(ctx, session, principalObjectID)
	principalIDs := []string{principalObjectID}
	principalIDs = append(principalIDs, groupIDs...)

	// Define scopes to check in order of hierarchy (top to bottom)
	scopes := []struct {
		Path        string
		Type        string
		DisplayName string
	}{
		{"/", "TenantRoot", "Tenant Root"},
	}

	// Add management group hierarchy
	mgHierarchy := GetManagementGroupHierarchy(ctx, session, subscriptionID)
	for _, mgID := range mgHierarchy {
		scopes = append(scopes, struct {
			Path        string
			Type        string
			DisplayName string
		}{
			fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID),
			"ManagementGroup",
			mgID,
		})
	}

	// Add subscription scope
	scopes = append(scopes, struct {
		Path        string
		Type        string
		DisplayName string
	}{
		fmt.Sprintf("/subscriptions/%s", subscriptionID),
		"Subscription",
		subscriptionID,
	})

	// Track assignments by role+scope to detect inheritance
	assignmentMap := make(map[string]RBACAssignmentWithInheritance)

	// Check each scope
	for _, scope := range scopes {
		for _, principalID := range principalIDs {
			pager := raClient.NewListForScopePager(scope.Path, &armauthorizationv2.RoleAssignmentsClientListForScopeOptions{
				Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalID)),
			})

			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to get role assignments at scope %s: %v", scope.Path, err), globals.AZ_PRINCIPALS_MODULE_NAME)
					}
					break
				}

				for _, ra := range page.Value {
					if ra.Properties == nil || ra.Properties.RoleDefinitionID == nil {
						continue
					}

					roleDefID := *ra.Properties.RoleDefinitionID
					roleName := GetRoleNameFromDefinitionID(ctx, session, subscriptionID, roleDefID)
					assignmentScope := SafeStringPtr(ra.Properties.Scope)

					assignedVia := "Direct"
					if principalID != principalObjectID {
						assignedVia = "Group"
					}

					// Determine if this is an inherited assignment
					inheritedFrom := ""
					if assignmentScope != scope.Path {
						// Assignment is at a different scope than what we're checking
						// This means it's inherited from a parent scope
						inheritedFrom = assignmentScope
					}

					assignment := RBACAssignmentWithInheritance{
						RoleName:         roleName,
						Scope:            assignmentScope,
						ScopeType:        scope.Type,
						ScopeDisplayName: scope.DisplayName,
						AssignedVia:      assignedVia,
						InheritedFrom:    inheritedFrom,
						PrincipalID:      principalID,
					}

					// Use role+scope as key to avoid duplicates
					key := fmt.Sprintf("%s|%s|%s", roleName, assignmentScope, principalID)
					if _, exists := assignmentMap[key]; !exists {
						assignmentMap[key] = assignment
						assignments = append(assignments, assignment)
					}
				}
			}
		}
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(assignments) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d RBAC assignment(s) with inheritance tracking for principal %s", len(assignments), principalObjectID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return assignments, nil
}

// ------------------------------
// Entra ID Directory Roles
// ------------------------------

// DirectoryRole represents an Entra ID directory role assignment
type DirectoryRole struct {
	RoleID         string
	RoleTemplateID string
	DisplayName    string
	Description    string
	AssignedVia    string // "Direct" or "Group"
	PIMStatus      string // "", "PIM Eligible", "PIM Active"
}

// GetDirectoryRolesForPrincipal retrieves Entra ID directory roles (Global Admin, User Admin, etc.)
// These are different from Azure RBAC roles - they control access to Entra ID itself
func GetDirectoryRolesForPrincipal(ctx context.Context, session *SafeSession, principalObjectID string) ([]DirectoryRole, error) {
	logger := internal.NewLogger()
	var roles []DirectoryRole

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for directory roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return roles, err
	}

	// Get directory roles the principal is a member of
	// This works for users, service principals, and groups
	initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s/memberOf", principalObjectID)

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				OdataType      string `json:"@odata.type"`
				ID             string `json:"id"`
				DisplayName    string `json:"displayName"`
				Description    string `json:"description"`
				RoleTemplateID string `json:"roleTemplateId"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode directory roles: %v", err)
		}

		for _, membership := range data.Value {
			// Only process directory roles (not groups or other objects)
			if membership.OdataType == "#microsoft.graph.directoryRole" {
				roles = append(roles, DirectoryRole{
					RoleID:         membership.ID,
					RoleTemplateID: membership.RoleTemplateID,
					DisplayName:    membership.DisplayName,
					Description:    membership.Description,
					AssignedVia:    "Direct",
					PIMStatus:      "", // Will be enriched with PIM info later
				})
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate directory roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return roles, err
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(roles) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d directory role(s) for principal %s", len(roles), principalObjectID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return roles, nil
}

// GetPIMEligibleDirectoryRoles retrieves PIM-eligible Entra ID directory role assignments
func GetPIMEligibleDirectoryRoles(ctx context.Context, session *SafeSession, principalObjectID string) ([]DirectoryRole, error) {
	logger := internal.NewLogger()
	var roles []DirectoryRole

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for PIM directory roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return roles, err
	}

	// Get PIM-eligible directory role assignments
	// Using the roleEligibilityScheduleInstances endpoint
	initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '%s'&$expand=roleDefinition", principalObjectID)

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID             string `json:"id"`
				PrincipalID    string `json:"principalId"`
				RoleDefinition struct {
					ID          string `json:"id"`
					DisplayName string `json:"displayName"`
					Description string `json:"description"`
					TemplateID  string `json:"templateId"`
				} `json:"roleDefinition"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode PIM eligible directory roles: %v", err)
		}

		for _, assignment := range data.Value {
			if assignment.PrincipalID == principalObjectID {
				roles = append(roles, DirectoryRole{
					RoleID:         assignment.RoleDefinition.ID,
					RoleTemplateID: assignment.RoleDefinition.TemplateID,
					DisplayName:    assignment.RoleDefinition.DisplayName,
					Description:    assignment.RoleDefinition.Description,
					AssignedVia:    "Direct",
					PIMStatus:      "PIM Eligible",
				})
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate PIM eligible directory roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		// Don't return error - PIM might not be configured
		return roles, nil
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(roles) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d PIM-eligible directory role(s) for principal %s", len(roles), principalObjectID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return roles, nil
}

// GetPIMActiveDirectoryRoles retrieves currently active PIM directory role assignments
func GetPIMActiveDirectoryRoles(ctx context.Context, session *SafeSession, principalObjectID string) ([]DirectoryRole, error) {
	logger := internal.NewLogger()
	var roles []DirectoryRole

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for active PIM directory roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return roles, err
	}

	// Get active PIM directory role assignments
	// Using the roleAssignmentScheduleInstances endpoint
	initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '%s'&$expand=roleDefinition", principalObjectID)

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID             string `json:"id"`
				PrincipalID    string `json:"principalId"`
				AssignmentType string `json:"assignmentType"`
				MemberType     string `json:"memberType"`
				RoleDefinition struct {
					ID          string `json:"id"`
					DisplayName string `json:"displayName"`
					Description string `json:"description"`
					TemplateID  string `json:"templateId"`
				} `json:"roleDefinition"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode active PIM directory roles: %v", err)
		}

		for _, assignment := range data.Value {
			if assignment.PrincipalID == principalObjectID {
				// Check if this is an activated (time-limited) assignment vs permanent
				pimStatus := ""
				if assignment.AssignmentType == "Activated" {
					pimStatus = "PIM Active"
				}

				assignedVia := "Direct"
				if assignment.MemberType == "Group" {
					assignedVia = "Group"
					if pimStatus != "" {
						pimStatus = "PIM Active (via Group)"
					}
				}

				roles = append(roles, DirectoryRole{
					RoleID:         assignment.RoleDefinition.ID,
					RoleTemplateID: assignment.RoleDefinition.TemplateID,
					DisplayName:    assignment.RoleDefinition.DisplayName,
					Description:    assignment.RoleDefinition.Description,
					AssignedVia:    assignedVia,
					PIMStatus:      pimStatus,
				})
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate active PIM directory roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		// Don't return error - PIM might not be configured
		return roles, nil
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(roles) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d active PIM directory role(s) for principal %s", len(roles), principalObjectID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	return roles, nil
}

// FormatDirectoryRoles formats directory roles for display
func FormatDirectoryRoles(roles []DirectoryRole) string {
	if len(roles) == 0 {
		return ""
	}

	var formatted []string
	for _, role := range roles {
		display := role.DisplayName
		if role.PIMStatus != "" {
			display += fmt.Sprintf(" (%s)", role.PIMStatus)
		}
		if role.AssignedVia == "Group" && role.PIMStatus == "" {
			display += " (via Group)"
		}
		formatted = append(formatted, display)
	}

	return strings.Join(formatted, "\n")
}

// ------------------------------
// Nested Group Memberships
// ------------------------------

// GetNestedGroupMemberships retrieves all group memberships including nested groups
// Returns both direct and transitive (nested) group memberships
func GetNestedGroupMemberships(ctx context.Context, session *SafeSession, principalObjectID string) (directGroups []string, allGroups []string, err error) {
	logger := internal.NewLogger()

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for nested groups: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return nil, nil, err
	}

	// Get direct group memberships
	directGroupsMap := make(map[string]string) // ID -> DisplayName
	directURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s/memberOf?$select=id,displayName", principalObjectID)

	err = GraphAPIPagedRequest(ctx, directURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				OdataType   string `json:"@odata.type"`
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode direct groups: %v", err)
		}

		for _, membership := range data.Value {
			// Only process groups
			if membership.OdataType == "#microsoft.graph.group" {
				directGroupsMap[membership.ID] = membership.DisplayName
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		return nil, nil, err
	}

	// Get transitive group memberships (includes nested groups)
	allGroupsMap := make(map[string]string) // ID -> DisplayName
	// Use directoryObjects endpoint which works for all principal types (users, service principals, groups)
	transitiveURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s/transitiveMemberOf?$select=id,displayName", principalObjectID)

	err = GraphAPIPagedRequest(ctx, transitiveURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				OdataType   string `json:"@odata.type"`
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode transitive groups: %v", err)
		}

		for _, membership := range data.Value {
			// Only process groups
			if membership.OdataType == "#microsoft.graph.group" {
				allGroupsMap[membership.ID] = membership.DisplayName
			}
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		// If transitive query fails, fall back to direct groups only
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get transitive groups, using direct groups only: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		allGroupsMap = directGroupsMap
	}

	// Convert maps to slices of display names
	for _, displayName := range directGroupsMap {
		directGroups = append(directGroups, displayName)
	}
	for _, displayName := range allGroupsMap {
		allGroups = append(allGroups, displayName)
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		if len(directGroups) > 0 || len(allGroups) > 0 {
			logger.InfoM(fmt.Sprintf("Principal %s: %d direct group(s), %d total group(s) including nested", principalObjectID, len(directGroups), len(allGroups)), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	return directGroups, allGroups, nil
}

// FormatNestedGroupMemberships formats group memberships with nested group indication
// Shows all group names with (nested) indicator for transitive memberships
// Example: "AdminGroup, ComplianceGroup, GroupA (nested), GroupB (nested)"
func FormatNestedGroupMemberships(directGroups []string, allGroups []string) string {
	if len(allGroups) == 0 {
		return ""
	}

	// Create a map for quick lookup of direct groups
	directMap := make(map[string]bool)
	for _, g := range directGroups {
		directMap[g] = true
	}

	// Format: direct groups first, then nested groups with (nested) indicator
	var formatted []string

	// Add direct groups first (without any indicator)
	for _, g := range directGroups {
		formatted = append(formatted, g)
	}

	// Add nested groups with (nested) indicator to show actual group names
	for _, g := range allGroups {
		if !directMap[g] {
			formatted = append(formatted, fmt.Sprintf("%s (nested)", g))
		}
	}

	return strings.Join(formatted, ", ")
}

// ========================================
// MFA Authentication Methods
// ========================================

// MFAAuthenticationMethods holds MFA status for a user
type MFAAuthenticationMethods struct {
	MFAEnabled       bool
	Methods          []string
	DefaultMethod    string
	HasPhoneAuth     bool
	HasAuthenticator bool
	HasFIDO2         bool
	HasEmail         bool
	HasTemporaryPass bool
}

// GetUserMFAAuthenticationMethods retrieves MFA authentication methods for a user
func GetUserMFAAuthenticationMethods(ctx context.Context, session *SafeSession, userObjectID string) (MFAAuthenticationMethods, error) {
	result := MFAAuthenticationMethods{
		MFAEnabled: false,
		Methods:    []string{},
	}

	// Get token for Microsoft Graph
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		return result, fmt.Errorf("failed to get Graph token: %w", err)
	}

	// Query user's authentication methods
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/authentication/methods", userObjectID)

	body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err != nil {
		// User might not have permission or MFA not configured
		return result, nil
	}

	var data struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return result, fmt.Errorf("failed to parse auth methods response: %w", err)
	}

	// Track default method
	defaultMethodID := ""
	for _, method := range data.Value {
		// Get the @odata.type to determine method type
		odataType, ok := method["@odata.type"].(string)
		if !ok {
			continue
		}

		// Get method ID
		methodID, _ := method["id"].(string)

		// Check if this is the default method
		// Note: The API doesn't explicitly mark default, but we track the first strong method
		switch odataType {
		case "#microsoft.graph.phoneAuthenticationMethod":
			result.Methods = append(result.Methods, "Phone")
			result.HasPhoneAuth = true
			if defaultMethodID == "" {
				defaultMethodID = "Phone"
			}
		case "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
			result.Methods = append(result.Methods, "Authenticator")
			result.HasAuthenticator = true
			if defaultMethodID == "" {
				defaultMethodID = "Authenticator"
			}
		case "#microsoft.graph.fido2AuthenticationMethod":
			result.Methods = append(result.Methods, "FIDO2")
			result.HasFIDO2 = true
			if defaultMethodID == "" {
				defaultMethodID = "FIDO2"
			}
		case "#microsoft.graph.emailAuthenticationMethod":
			result.Methods = append(result.Methods, "Email")
			result.HasEmail = true
		case "#microsoft.graph.temporaryAccessPassAuthenticationMethod":
			result.Methods = append(result.Methods, "TemporaryAccessPass")
			result.HasTemporaryPass = true
		case "#microsoft.graph.passwordAuthenticationMethod":
			// Password is always present, don't count it as MFA
			continue
		default:
			// Other methods like softwareOathAuthenticationMethod
			if methodID != "" {
				methodType := strings.TrimPrefix(odataType, "#microsoft.graph.")
				methodType = strings.TrimSuffix(methodType, "AuthenticationMethod")
				result.Methods = append(result.Methods, methodType)
			}
		}
	}

	// MFA is considered enabled if user has any strong authentication method beyond password
	if len(result.Methods) > 0 {
		result.MFAEnabled = true
	}

	// Set default method
	if defaultMethodID != "" {
		result.DefaultMethod = defaultMethodID
	} else if len(result.Methods) > 0 {
		result.DefaultMethod = result.Methods[0]
	}

	return result, nil
}

// ------------------------------
// Enhanced Conditional Access Policy (for policy-centric module)
// ------------------------------

// ConditionalAccessPolicyDetails represents a complete CA policy configuration
type ConditionalAccessPolicyDetails struct {
	ID               string
	DisplayName      string
	State            string // "enabled", "disabled", "enabledForReportingButNotEnforced"
	CreatedDateTime  string
	ModifiedDateTime string

	// Conditions
	IncludedUsers     []string
	ExcludedUsers     []string
	IncludedGroups    []string
	ExcludedGroups    []string
	IncludedRoles     []string
	ExcludedRoles     []string
	IncludedApps      []string
	ExcludedApps      []string
	IncludedLocations []string
	ExcludedLocations []string
	IncludedPlatforms []string
	ExcludedPlatforms []string
	ClientAppTypes    []string
	UserRiskLevels    []string
	SignInRiskLevels  []string
	DeviceStates      []string

	// Grant Controls
	GrantOperator string   // "AND" or "OR"
	GrantControls []string // "mfa", "compliantDevice", "domainJoinedDevice", "approvedApplication", etc.

	// Session Controls
	ApplicationEnforcedRestrictions bool
	CloudAppSecurity                string
	SignInFrequency                 string
	PersistentBrowser               string

	// Additional metadata
	Description string
}

// GetAllConditionalAccessPolicies retrieves all CA policies in the tenant with full details
func GetAllConditionalAccessPolicies(ctx context.Context, session *SafeSession) ([]ConditionalAccessPolicyDetails, error) {
	logger := internal.NewLogger()
	var policies []ConditionalAccessPolicyDetails

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for CA policies: %v", err), "conditional-access")
		}
		return policies, err
	}

	// Get all conditional access policies
	initialURL := "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID               string `json:"id"`
				DisplayName      string `json:"displayName"`
				State            string `json:"state"`
				CreatedDateTime  string `json:"createdDateTime"`
				ModifiedDateTime string `json:"modifiedDateTime"`
				Conditions       struct {
					Users struct {
						IncludeUsers  []string `json:"includeUsers"`
						ExcludeUsers  []string `json:"excludeUsers"`
						IncludeGroups []string `json:"includeGroups"`
						ExcludeGroups []string `json:"excludeGroups"`
						IncludeRoles  []string `json:"includeRoles"`
						ExcludeRoles  []string `json:"excludeRoles"`
					} `json:"users"`
					Applications struct {
						IncludeApplications []string `json:"includeApplications"`
						ExcludeApplications []string `json:"excludeApplications"`
					} `json:"applications"`
					Locations struct {
						IncludeLocations []string `json:"includeLocations"`
						ExcludeLocations []string `json:"excludeLocations"`
					} `json:"locations"`
					Platforms struct {
						IncludePlatforms []string `json:"includePlatforms"`
						ExcludePlatforms []string `json:"excludePlatforms"`
					} `json:"platforms"`
					ClientAppTypes   []string `json:"clientAppTypes"`
					UserRiskLevels   []string `json:"userRiskLevels"`
					SignInRiskLevels []string `json:"signInRiskLevels"`
					DeviceStates     struct {
						IncludeStates []string `json:"includeStates"`
						ExcludeStates []string `json:"excludeStates"`
					} `json:"deviceStates"`
				} `json:"conditions"`
				GrantControls struct {
					Operator        string   `json:"operator"`
					BuiltInControls []string `json:"builtInControls"`
				} `json:"grantControls"`
				SessionControls struct {
					ApplicationEnforcedRestrictions struct {
						IsEnabled bool `json:"isEnabled"`
					} `json:"applicationEnforcedRestrictions"`
					CloudAppSecurity struct {
						IsEnabled            bool   `json:"isEnabled"`
						CloudAppSecurityType string `json:"cloudAppSecurityType"`
					} `json:"cloudAppSecurity"`
					SignInFrequency struct {
						IsEnabled bool   `json:"isEnabled"`
						Type      string `json:"type"`
						Value     int    `json:"value"`
					} `json:"signInFrequency"`
					PersistentBrowser struct {
						IsEnabled bool   `json:"isEnabled"`
						Mode      string `json:"mode"`
					} `json:"persistentBrowser"`
				} `json:"sessionControls"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", fmt.Errorf("failed to decode CA policies: %v", err)
		}

		for _, policy := range data.Value {
			details := ConditionalAccessPolicyDetails{
				ID:               policy.ID,
				DisplayName:      policy.DisplayName,
				State:            policy.State,
				CreatedDateTime:  policy.CreatedDateTime,
				ModifiedDateTime: policy.ModifiedDateTime,

				// Conditions - Users
				IncludedUsers:  policy.Conditions.Users.IncludeUsers,
				ExcludedUsers:  policy.Conditions.Users.ExcludeUsers,
				IncludedGroups: policy.Conditions.Users.IncludeGroups,
				ExcludedGroups: policy.Conditions.Users.ExcludeGroups,
				IncludedRoles:  policy.Conditions.Users.IncludeRoles,
				ExcludedRoles:  policy.Conditions.Users.ExcludeRoles,

				// Conditions - Applications
				IncludedApps: policy.Conditions.Applications.IncludeApplications,
				ExcludedApps: policy.Conditions.Applications.ExcludeApplications,

				// Conditions - Locations
				IncludedLocations: policy.Conditions.Locations.IncludeLocations,
				ExcludedLocations: policy.Conditions.Locations.ExcludeLocations,

				// Conditions - Platforms
				IncludedPlatforms: policy.Conditions.Platforms.IncludePlatforms,
				ExcludedPlatforms: policy.Conditions.Platforms.ExcludePlatforms,

				// Conditions - Client App Types
				ClientAppTypes:   policy.Conditions.ClientAppTypes,
				UserRiskLevels:   policy.Conditions.UserRiskLevels,
				SignInRiskLevels: policy.Conditions.SignInRiskLevels,

				// Conditions - Device States
				DeviceStates: policy.Conditions.DeviceStates.IncludeStates,

				// Grant Controls
				GrantOperator: policy.GrantControls.Operator,
				GrantControls: policy.GrantControls.BuiltInControls,
			}

			// Session Controls
			if policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled {
				details.ApplicationEnforcedRestrictions = true
			}
			if policy.SessionControls.CloudAppSecurity.IsEnabled {
				details.CloudAppSecurity = policy.SessionControls.CloudAppSecurity.CloudAppSecurityType
			}
			if policy.SessionControls.SignInFrequency.IsEnabled {
				details.SignInFrequency = fmt.Sprintf("%d %s", policy.SessionControls.SignInFrequency.Value, policy.SessionControls.SignInFrequency.Type)
			}
			if policy.SessionControls.PersistentBrowser.IsEnabled {
				details.PersistentBrowser = policy.SessionControls.PersistentBrowser.Mode
			}

			policies = append(policies, details)
		}

		hasMore := data.NextLink != ""
		nextURL := data.NextLink
		return hasMore, nextURL, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate CA policies: %v", err), "conditional-access")
		}
		return policies, err
	}

	return policies, nil
}

// FormatConditionalAccessPolicyDetails formats CA policy details for display
func FormatConditionalAccessPolicyDetails(details ConditionalAccessPolicyDetails) map[string]string {
	result := make(map[string]string)

	// Users
	if len(details.IncludedUsers) > 0 {
		result["IncludedUsers"] = strings.Join(details.IncludedUsers, ", ")
	} else {
		result["IncludedUsers"] = "None"
	}

	if len(details.ExcludedUsers) > 0 {
		result["ExcludedUsers"] = strings.Join(details.ExcludedUsers, ", ")
	} else {
		result["ExcludedUsers"] = "None"
	}

	// Groups
	if len(details.IncludedGroups) > 0 {
		result["IncludedGroups"] = strings.Join(details.IncludedGroups, ", ")
	} else {
		result["IncludedGroups"] = "None"
	}

	if len(details.ExcludedGroups) > 0 {
		result["ExcludedGroups"] = strings.Join(details.ExcludedGroups, ", ")
	} else {
		result["ExcludedGroups"] = "None"
	}

	// Applications
	if len(details.IncludedApps) > 0 {
		result["IncludedApps"] = strings.Join(details.IncludedApps, ", ")
	} else {
		result["IncludedApps"] = "None"
	}

	// Grant Controls
	if len(details.GrantControls) > 0 {
		result["GrantControls"] = fmt.Sprintf("%s (%s)", strings.Join(details.GrantControls, ", "), details.GrantOperator)
	} else {
		result["GrantControls"] = "None"
	}

	return result
}
