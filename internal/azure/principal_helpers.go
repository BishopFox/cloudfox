package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armauthorizationv2 "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	armmanagementgroups "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	armresources "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
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
	// Check in-memory cache first
	cacheKey := AzCacheKey("entra-users", tenantID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]PrincipalInfo), nil
	}

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

	// Cache the result before returning
	AzureDataCache.Set(cacheKey, users, 0)
	return users, nil
}

// ListServicePrincipals returns all service principals in the tenant
func ListServicePrincipals(ctx context.Context, session *SafeSession, tenantID string) ([]PrincipalInfo, error) {
	// Check in-memory cache first
	cacheKey := AzCacheKey("service-principals", tenantID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]PrincipalInfo), nil
	}

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

	// Cache the result before returning
	AzureDataCache.Set(cacheKey, sps, 0)
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

		client, err := armmi.NewUserAssignedIdentitiesClient(subID, cred, DefaultARMClientOptions())
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

// GetPrincipalPermissions retrieves Graph permissions for a given principal.
// When principalType is provided (e.g., "User", "ServicePrincipal"), it skips the
// type-detection API calls. Pass "" to fall back to auto-detection.
func GetPrincipalPermissions(ctx context.Context, session *SafeSession, principal string, principalType ...string) PrincipalPermissions {
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

	// If caller provides the type, skip the type-detection API calls entirely
	knownType := ""
	if len(principalType) > 0 {
		knownType = principalType[0]
	}

	if knownType != "" {
		objectID = principal
		switch knownType {
		case "ServicePrincipal", "UserAssignedManagedIdentity":
			isSP = true
		default:
			isSP = false
		}
	} else {
		// Auto-detect: try as user first, then service principal (1-2 API calls)
		if isUUID(principal) {
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
		// Check bulk SP appRoleAssignments cache first
		bulkKey := AzCacheKey("sp-approle-assignments-all", "tenant")
		bulkHit := false
		if cached, found := AzureDataCache.Get(bulkKey); found {
			bulkData := cached.(map[string][]CachedSPAppRoleAssignment)
			if assignments, ok := bulkData[objectID]; ok {
				for _, a := range assignments {
					graphPerms = append(graphPerms, fmt.Sprintf("%s (%s)", a.ResourceDisplayName, a.AppRoleName))
				}
				bulkHit = true
			}
		}
		if !bulkHit {
			// Fall back to per-SP API call (bulk cache not available or principal missing)
			initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignments", objectID)
			var cachedAssignments []CachedSPAppRoleAssignment

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
						appRoleName = resolveAppRoleName(ctx, token, a.ResourceId, a.ResourceDisplayName, *a.AppRoleId, logger)
					} else if a.AppRoleId == nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("AppRoleAssignment has nil AppRoleId for resource %s (%s)", a.ResourceDisplayName, a.ResourceId), globals.AZ_PRINCIPALS_MODULE_NAME)
					}
					graphPerms = append(graphPerms, fmt.Sprintf("%s (%s)", a.ResourceDisplayName, appRoleName))
					cachedAssignments = append(cachedAssignments, CachedSPAppRoleAssignment{
						ResourceDisplayName: a.ResourceDisplayName,
						AppRoleName:         appRoleName,
					})
				}

				hasMore := data.NextLink != ""
				nextURL := data.NextLink
				return hasMore, nextURL, nil
			})

			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.InfoM(fmt.Sprintf("[GetPrincipalPermissions] Failed to fetch appRoleAssignments: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
			}

			// Backfill bulk cache so other callers benefit
			BackfillBulkCache(bulkKey, objectID, cachedAssignments)
		}

	} else {
		// User: check bulk group cache first, fall back to memberOf API
		bulkKey := AzCacheKey("group-memberships-all", "tenant")
		bulkHit := false
		if cached, found := AzureDataCache.Get(bulkKey); found {
			bulkData := cached.(map[string]CachedGroupMembership)
			if membership, ok := bulkData[objectID]; ok {
				for _, g := range membership.AllGroupNames {
					graphPerms = append(graphPerms, fmt.Sprintf("%s (group)", g))
				}
				bulkHit = true
			}
		}
		if !bulkHit {
			// Fall back to per-principal memberOf API
			initialURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf", objectID)
			var groupNames []string

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
					groupNames = append(groupNames, g.DisplayName)
				}

				hasMore := data.NextLink != ""
				nextURL := data.NextLink
				return hasMore, nextURL, nil
			})

			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.InfoM(fmt.Sprintf("[GetPrincipalPermissions] Failed to fetch memberOf: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
			}

			// Backfill bulk cache so other callers benefit
			BackfillBulkCache(bulkKey, objectID, CachedGroupMembership{
				AllGroupNames: groupNames,
			})
		}
	}

	result.Graph = strings.Join(graphPerms, ", ")
	return result
}

// resolveAppRoleName looks up an appRole display name for a given resource SP + role ID.
// Results are cached in AzureDataCache so repeated lookups across principals are free.
func resolveAppRoleName(ctx context.Context, token, resourceID, resourceDisplayName, appRoleID string, logger internal.Logger) string {
	// Cache key: appRoles for this resource SP
	cacheKey := AzCacheKey("approles", resourceID)

	// Check cache: map[appRoleID] -> roleName
	if cached, found := AzureDataCache.Get(cacheKey); found {
		roleMap := cached.(map[string]string)
		if name, ok := roleMap[strings.ToLower(appRoleID)]; ok {
			return name
		}
		return "(unknown)"
	}

	// Fetch from API and cache the entire appRoles list for this resource
	roleURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoles", resourceID)
	roleBody, err := GraphAPIRequestWithRetry(ctx, "GET", roleURL, token)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to fetch appRoles for resource %s (%s): %v", resourceDisplayName, resourceID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		// Cache empty map to avoid retrying a failing resource
		AzureDataCache.Set(cacheKey, map[string]string{}, 0)
		return "(unknown)"
	}

	var roleData struct {
		Value []struct {
			ID          string `json:"id"`
			Value       string `json:"value"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.Unmarshal(roleBody, &roleData); err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to decode appRoles JSON for resource %s (%s)", resourceDisplayName, resourceID), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		AzureDataCache.Set(cacheKey, map[string]string{}, 0)
		return "(unknown)"
	}

	roleMap := make(map[string]string, len(roleData.Value))
	for _, r := range roleData.Value {
		name := r.DisplayName
		if r.Value != "" {
			name = r.Value
		}
		roleMap[strings.ToLower(r.ID)] = name
	}
	AzureDataCache.Set(cacheKey, roleMap, 0)

	if name, ok := roleMap[strings.ToLower(appRoleID)]; ok {
		return name
	}
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("AppRole ID %s not found in resource %s (%s) appRoles list (found %d roles)", appRoleID, resourceDisplayName, resourceID, len(roleData.Value)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	return "(unknown)"
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
	// Check bulk group memberships cache first (returns AllGroupIDs)
	bulkKey := AzCacheKey("group-memberships-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		bulkData := cached.(map[string]CachedGroupMembership)
		if membership, ok := bulkData[userObjectID]; ok {
			return membership.AllGroupIDs
		}
		// Principal not in bulk cache - fall through to per-principal API
	}

	// Fall back to per-principal cache / API
	cacheKey := AzCacheKey("group-memberships", userObjectID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]string)
	}

	logger := internal.NewLogger()
	groupIDs := []string{}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for group membership enumeration: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		AzureDataCache.Set(cacheKey, groupIDs, 0)
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
		AzureDataCache.Set(cacheKey, groupIDs, 0)
		return groupIDs
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS && len(groupIDs) > 0 {
		logger.InfoM(fmt.Sprintf("User %s is a member of %d group(s) (including nested groups)", userObjectID, len(groupIDs)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}

	AzureDataCache.Set(cacheKey, groupIDs, 0)

	// Backfill bulk cache so other callers benefit
	BackfillBulkCache(bulkKey, userObjectID, CachedGroupMembership{
		AllGroupIDs: groupIDs,
	})

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
	// Check bulk OAuth2 grants cache first
	bulkKey := AzCacheKey("oauth2-grants-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		bulkData := cached.(map[string][]CachedOAuth2Grant)
		if grants, ok := bulkData[appObjectID]; ok {
			var scopesFormatted []string
			for _, grant := range grants {
				for _, scope := range grant.Scopes {
					scopesFormatted = append(scopesFormatted, fmt.Sprintf("%s: %s (%s)", grant.ResourceName, scope, grant.ConsentType))
				}
			}
			return scopesFormatted
		}
		// Principal not in bulk cache - fall through to per-principal API
	}

	// Fall back to per-principal API
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
	var cachedGrants []CachedOAuth2Grant
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
			var nonEmptyScopes []string
			for _, scope := range scopes {
				if scope != "" {
					formatted := fmt.Sprintf("%s: %s (%s)", resourceName, scope, consentType)
					scopesFormatted = append(scopesFormatted, formatted)
					nonEmptyScopes = append(nonEmptyScopes, scope)
				}
			}

			// Collect for bulk cache backfill
			cachedGrants = append(cachedGrants, CachedOAuth2Grant{
				ClientID:    appObjectID,
				ConsentType: consentType,
				ResourceName: resourceName,
				Scopes:      nonEmptyScopes,
			})
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

	// Backfill bulk cache so other callers benefit
	BackfillBulkCache(bulkKey, appObjectID, cachedGrants)

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

	// Build SP display name lookup map from in-memory cache (avoids per-grant API calls).
	// If the cache isn't populated, we fall back to per-grant API lookups.
	spNameMap := make(map[string]string) // objectID -> displayName
	var spCacheAvailable bool
	for key, item := range AzureDataCache.Items() {
		if strings.HasPrefix(key, "az-service-principals-") {
			if sps, ok := item.Object.([]PrincipalInfo); ok {
				for _, sp := range sps {
					spNameMap[sp.ObjectID] = sp.DisplayName
				}
				spCacheAvailable = true
			}
			break
		}
	}

	// Build user UPN lookup map from in-memory cache
	userUPNMap := make(map[string]string) // objectID -> UPN
	var userCacheAvailable bool
	for key, item := range AzureDataCache.Items() {
		if strings.HasPrefix(key, "az-entra-users-") {
			if users, ok := item.Object.([]PrincipalInfo); ok {
				for _, u := range users {
					userUPNMap[u.ObjectID] = u.UserPrincipalName
				}
				userCacheAvailable = true
			}
			break
		}
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

			if grant.PrincipalID != nil {
				details.PrincipalID = *grant.PrincipalID
			}

			if grant.Scope != "" {
				details.Scopes = strings.Fields(grant.Scope)
			}

			for _, scope := range details.Scopes {
				if description, isRisky := RiskyOAuth2Permissions[scope]; isRisky {
					details.RiskyPermissions = append(details.RiskyPermissions, fmt.Sprintf("%s (%s)", scope, description))
					details.IsRisky = true
				}
			}

			// Resolve client SP display name: cache first, API fallback
			if details.ClientID != "" {
				if spCacheAvailable {
					details.ClientDisplayName = spNameMap[details.ClientID]
				} else {
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
							if spData.AppOwnerOrganizationID != nil && *spData.AppOwnerOrganizationID != "" {
								details.IsExternal = true
							}
						}
					}
				}
			}

			// Resolve resource SP display name: cache first, API fallback
			if details.ResourceID != "" {
				if spCacheAvailable {
					details.ResourceDisplayName = spNameMap[details.ResourceID]
				} else {
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
			}

			// Resolve principal UPN for user consent: cache first, API fallback
			if details.PrincipalID != "" && details.ConsentType == "Principal" {
				if userCacheAvailable {
					details.PrincipalName = userUPNMap[details.PrincipalID]
				} else {
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

// GetConsentGrantsForClient retrieves consent grants for a specific client application.
// Checks the bulk OAuth2 grants cache first, falls back to per-client API if not cached.
func GetConsentGrantsForClient(ctx context.Context, session *SafeSession, clientID string) ([]OAuth2PermissionGrantDetails, error) {
	// Check bulk OAuth2 grants cache (populated by PreFetchOAuth2Grants)
	bulkKey := AzCacheKey("oauth2-grants-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		bulkData := cached.(map[string][]CachedOAuth2Grant)
		if cachedGrants, ok := bulkData[clientID]; ok {
			var grants []OAuth2PermissionGrantDetails
			for _, cg := range cachedGrants {
				details := OAuth2PermissionGrantDetails{
					ClientID:            cg.ClientID,
					ConsentType:         cg.ConsentType,
					ResourceDisplayName: cg.ResourceName,
					Scopes:              cg.Scopes,
					Scope:               strings.Join(cg.Scopes, " "),
				}
				for _, scope := range cg.Scopes {
					if description, isRisky := RiskyOAuth2Permissions[scope]; isRisky {
						details.RiskyPermissions = append(details.RiskyPermissions, fmt.Sprintf("%s (%s)", scope, description))
						details.IsRisky = true
					}
				}
				grants = append(grants, details)
			}
			return grants, nil
		}
		// Client not in bulk cache - fall through to per-client API
	}

	// Fall back to per-client API
	logger := internal.NewLogger()
	var grants []OAuth2PermissionGrantDetails

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		return grants, err
	}

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

			if grant.Scope != "" {
				details.Scopes = strings.Fields(grant.Scope)
			}

			for _, scope := range details.Scopes {
				if description, isRisky := RiskyOAuth2Permissions[scope]; isRisky {
					details.RiskyPermissions = append(details.RiskyPermissions, fmt.Sprintf("%s (%s)", scope, description))
					details.IsRisky = true
				}
			}

			// Resolve resource display name via API
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

	// Backfill bulk cache so other callers benefit
	var cached []CachedOAuth2Grant
	for _, g := range grants {
		cached = append(cached, CachedOAuth2Grant{
			ClientID:     g.ClientID,
			ConsentType:  g.ConsentType,
			ResourceName: g.ResourceDisplayName,
			Scopes:       g.Scopes,
		})
	}
	BackfillBulkCache(bulkKey, clientID, cached)

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

	// Check bulk sign-in activity cache first
	bulkKey := AzCacheKey("sign-in-activity-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		bulkData := cached.(map[string]SignInActivity)
		if activity, ok := bulkData[userObjectID]; ok {
			return activity, nil
		}
		// User not in bulk cache - fall through to per-principal API
	}

	// Fall back to per-principal API
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

	// Backfill bulk cache so other callers benefit
	BackfillBulkCache(bulkKey, userObjectID, result)

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
	assignClient, err := armauthorizationv2.NewRoleAssignmentsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %v", err)
	}

	// Role Definitions client
	roleClient, err := armauthorizationv2.NewRoleDefinitionsClient(cred, DefaultARMClientOptions())
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
				if !IsAccessDenied(err) && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to get role assignments at MG scope %s: %s", mgID, AzureAPIErrorSummary(err)), globals.AZ_PRINCIPALS_MODULE_NAME)
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
			if !IsAccessDenied(err) && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list role assignments for subscription %s: %s", subscriptionID, AzureAPIErrorSummary(err)), globals.AZ_PRINCIPALS_MODULE_NAME)
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
	// Check in-memory cache first
	cacheKey := AzCacheKey("mg-hierarchy", subscriptionID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]string)
	}

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
	entitiesClient, err := armmanagementgroups.NewEntitiesClient(cred, DefaultARMClientOptions())
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
	mgClient, err := armmanagementgroups.NewClient(cred, DefaultARMClientOptions())
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

	// Cache the result before returning
	AzureDataCache.Set(cacheKey, hierarchy, 0)
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

// PreFetchPIMRolesForSubscription fetches all PIM eligible and active role assignments
// for a subscription and caches them. Call once per subscription before enrichment.
// Results are persisted to disk so subsequent runs (or other modules) can reuse them.
func PreFetchPIMRolesForSubscription(ctx context.Context, session *SafeSession, subscriptionID, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	logger := internal.NewLogger()

	eligibleKey := AzCacheKey("pim-eligible-all", subscriptionID)
	activeKey := AzCacheKey("pim-active-all", subscriptionID)

	// 1. Check in-memory cache
	_, eligibleFound := AzureDataCache.Get(eligibleKey)
	_, activeFound := AzureDataCache.Get(activeKey)
	if eligibleFound && activeFound {
		return
	}

	// 2. Check disk cache
	diskFile := fmt.Sprintf("pim-sub-%s.gob", subscriptionID)
	var diskCache PIMSubCache
	if loadPrefetchCache(baseDir, tenantID, diskFile, DefaultAzureCacheExpiration, &diskCache) {
		if diskCache.Eligible != nil {
			AzureDataCache.Set(eligibleKey, diskCache.Eligible, 0)
		}
		if diskCache.Active != nil {
			AzureDataCache.Set(activeKey, diskCache.Active, 0)
		}
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Loaded PIM cache from disk for subscription %s", subscriptionID), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	// 3. Fetch from API
	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for PIM pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	var eligibleMap map[string][]PIMRoleAssignment
	var activeMap map[string][]PIMRoleAssignment

	// Pre-fetch eligible
	if _, found := AzureDataCache.Get(eligibleKey); !found {
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subscriptionID)
		body, err := HTTPRequestWithRetry(ctx, "GET", url, token, nil, DefaultRateLimitConfig())
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
			if json.Unmarshal(body, &pimData) == nil {
				// Build map: principalID -> []PIMRoleAssignment
				eligibleMap = make(map[string][]PIMRoleAssignment)
				for _, pa := range pimData.Value {
					pid := pa.Properties.PrincipalID
					principalType := pa.Properties.ExpandedProperties.Principal.Type
					assignedVia := "Direct (PIM Eligible)"
					if principalType == "Group" {
						assignedVia = "Group (PIM Eligible)"
					}
					eligibleMap[pid] = append(eligibleMap[pid], PIMRoleAssignment{
						PrincipalID:      pid,
						PrincipalType:    principalType,
						RoleDefinitionID: pa.Properties.RoleDefinitionID,
						RoleName:         pa.Properties.ExpandedProperties.RoleDefinition.DisplayName,
						Scope:            pa.Properties.Scope,
						Status:           pa.Properties.Status,
						AssignedVia:      assignedVia,
					})
				}
				AzureDataCache.Set(eligibleKey, eligibleMap, 0)
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					total := 0
					for _, v := range eligibleMap {
						total += len(v)
					}
					logger.InfoM(fmt.Sprintf("Pre-fetched %d PIM-eligible assignments for subscription %s", total, subscriptionID), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
			}
		} else if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to pre-fetch PIM eligibility for subscription %s: %v", subscriptionID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// Pre-fetch active
	if _, found := AzureDataCache.Get(activeKey); !found {
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()", subscriptionID)
		body, err := HTTPRequestWithRetry(ctx, "GET", url, token, nil, DefaultRateLimitConfig())
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
			if json.Unmarshal(body, &pimData) == nil {
				activeMap = make(map[string][]PIMRoleAssignment)
				for _, pa := range pimData.Value {
					pid := pa.Properties.PrincipalID
					principalType := pa.Properties.ExpandedProperties.Principal.Type
					assignedVia := "Direct (PIM Active)"
					if principalType == "Group" {
						assignedVia = "Group (PIM Active)"
					}
					activeMap[pid] = append(activeMap[pid], PIMRoleAssignment{
						PrincipalID:      pid,
						PrincipalType:    principalType,
						RoleDefinitionID: pa.Properties.RoleDefinitionID,
						RoleName:         pa.Properties.ExpandedProperties.RoleDefinition.DisplayName,
						Scope:            pa.Properties.Scope,
						Status:           "Active",
						AssignedVia:      assignedVia,
					})
				}
				AzureDataCache.Set(activeKey, activeMap, 0)
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					total := 0
					for _, v := range activeMap {
						total += len(v)
					}
					logger.InfoM(fmt.Sprintf("Pre-fetched %d PIM-active assignments for subscription %s", total, subscriptionID), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
			}
		} else if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to pre-fetch active PIM roles for subscription %s: %v", subscriptionID, err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// 4. Save to disk
	if eligibleMap != nil || activeMap != nil {
		if eligibleMap == nil {
			eligibleMap = make(map[string][]PIMRoleAssignment)
		}
		if activeMap == nil {
			activeMap = make(map[string][]PIMRoleAssignment)
		}
		savePrefetchCache(baseDir, tenantID, diskFile, PIMSubCache{Eligible: eligibleMap, Active: activeMap})
	}
}

// GetPIMEligibleRoles retrieves PIM-eligible role assignments for a subscription.
// Uses cached data if available (from PreFetchPIMRolesForSubscription).
func GetPIMEligibleRoles(ctx context.Context, session *SafeSession, subscriptionID string, principalIDs []string) ([]PIMRoleAssignment, error) {
	// Try cached path
	eligibleKey := AzCacheKey("pim-eligible-all", subscriptionID)
	if cached, found := AzureDataCache.Get(eligibleKey); found {
		eligibleMap := cached.(map[string][]PIMRoleAssignment)
		var assignments []PIMRoleAssignment
		for _, pid := range principalIDs {
			assignments = append(assignments, eligibleMap[pid]...)
		}
		return assignments, nil
	}

	// Fallback: fetch from API
	logger := internal.NewLogger()
	var assignments []PIMRoleAssignment

	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
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

	principalMap := make(map[string]bool, len(principalIDs))
	for _, pid := range principalIDs {
		principalMap[pid] = true
	}

	for _, pa := range pimData.Value {
		pid := pa.Properties.PrincipalID
		if !principalMap[pid] {
			continue
		}
		principalType := pa.Properties.ExpandedProperties.Principal.Type
		assignedVia := "Direct (PIM Eligible)"
		if principalType == "Group" {
			assignedVia = "Group (PIM Eligible)"
		}
		assignments = append(assignments, PIMRoleAssignment{
			PrincipalID:      pid,
			PrincipalType:    principalType,
			RoleDefinitionID: pa.Properties.RoleDefinitionID,
			RoleName:         pa.Properties.ExpandedProperties.RoleDefinition.DisplayName,
			Scope:            pa.Properties.Scope,
			Status:           pa.Properties.Status,
			AssignedVia:      assignedVia,
		})
	}

	return assignments, nil
}

// GetPIMActiveRoles retrieves currently active PIM role assignments for a subscription.
// Uses cached data if available (from PreFetchPIMRolesForSubscription).
func GetPIMActiveRoles(ctx context.Context, session *SafeSession, subscriptionID string, principalIDs []string) ([]PIMRoleAssignment, error) {
	// Try cached path
	activeKey := AzCacheKey("pim-active-all", subscriptionID)
	if cached, found := AzureDataCache.Get(activeKey); found {
		activeMap := cached.(map[string][]PIMRoleAssignment)
		var assignments []PIMRoleAssignment
		for _, pid := range principalIDs {
			assignments = append(assignments, activeMap[pid]...)
		}
		return assignments, nil
	}

	// Fallback: fetch from API
	logger := internal.NewLogger()
	var assignments []PIMRoleAssignment

	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
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

	principalMap := make(map[string]bool, len(principalIDs))
	for _, pid := range principalIDs {
		principalMap[pid] = true
	}

	for _, pa := range pimData.Value {
		pid := pa.Properties.PrincipalID
		if !principalMap[pid] {
			continue
		}
		principalType := pa.Properties.ExpandedProperties.Principal.Type
		assignedVia := "Direct (PIM Active)"
		if principalType == "Group" {
			assignedVia = "Group (PIM Active)"
		}
		assignments = append(assignments, PIMRoleAssignment{
			PrincipalID:      pid,
			PrincipalType:    principalType,
			RoleDefinitionID: pa.Properties.RoleDefinitionID,
			RoleName:         pa.Properties.ExpandedProperties.RoleDefinition.DisplayName,
			Scope:            pa.Properties.Scope,
			Status:           "Active",
			AssignedVia:      assignedVia,
		})
	}

	return assignments, nil
}

// ------------------------------
// Groups Enumeration
// ------------------------------

// ListEntraGroups returns all security groups in the tenant via Microsoft Graph
func ListEntraGroups(ctx context.Context, session *SafeSession, tenantID string) ([]PrincipalInfo, error) {
	// Check in-memory cache first
	cacheKey := AzCacheKey("entra-groups", tenantID)
	if cached, found := AzureDataCache.Get(cacheKey); found {
		return cached.([]PrincipalInfo), nil
	}

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

	// Cache the result before returning
	AzureDataCache.Set(cacheKey, groups, 0)
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

// cachedCAPolicy holds a CA policy with its targeting conditions for client-side filtering.
type cachedCAPolicy struct {
	ID            string
	DisplayName   string
	State         string
	IncludeUsers  []string
	IncludeGroups []string
}

// PreFetchConditionalAccessPolicies fetches all CA policies once and caches them.
// Call this before the per-principal enrichment loop.
// Results are persisted to disk so subsequent runs (or other modules) can reuse them.
// Stores two caches: minimal (for per-principal matching) and full details (for the CA module).
func PreFetchConditionalAccessPolicies(ctx context.Context, session *SafeSession, baseDir, tenantID string) error {
	SetBulkCacheContext(baseDir, tenantID)
	cacheKey := AzCacheKey("ca-policies-all", "tenant")
	fullCacheKey := AzCacheKey("ca-policies-full", "tenant")
	if _, found := AzureDataCache.Get(cacheKey); found {
		return nil // Already in memory
	}

	// Check disk cache (minimal)
	var diskCache CAPoliciesCache
	if loadPrefetchCache(baseDir, tenantID, "ca-policies.gob", DefaultAzureCacheExpiration, &diskCache) {
		AzureDataCache.Set(cacheKey, diskCache.Policies, 0)
		// Also try to load the full details cache
		var fullDiskCache CAPoliciesFullCache
		if loadPrefetchCache(baseDir, tenantID, "ca-policies-full.gob", DefaultAzureCacheExpiration, &fullDiskCache) {
			AzureDataCache.Set(fullCacheKey, fullDiskCache.Policies, 0)
		}
		return nil
	}

	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1])
	if err != nil {
		return fmt.Errorf("failed to get Graph token for CA policies: %w", err)
	}

	var allPolicies []cachedCAPolicy
	var allFullPolicies []ConditionalAccessPolicyDetails
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

		for _, p := range data.Value {
			// Minimal cache for per-principal matching
			allPolicies = append(allPolicies, cachedCAPolicy{
				ID:            p.ID,
				DisplayName:   p.DisplayName,
				State:         p.State,
				IncludeUsers:  p.Conditions.Users.IncludeUsers,
				IncludeGroups: p.Conditions.Users.IncludeGroups,
			})

			// Full details for the conditional-access module
			details := ConditionalAccessPolicyDetails{
				ID:               p.ID,
				DisplayName:      p.DisplayName,
				State:            p.State,
				CreatedDateTime:  p.CreatedDateTime,
				ModifiedDateTime: p.ModifiedDateTime,
				IncludedUsers:    p.Conditions.Users.IncludeUsers,
				ExcludedUsers:    p.Conditions.Users.ExcludeUsers,
				IncludedGroups:   p.Conditions.Users.IncludeGroups,
				ExcludedGroups:   p.Conditions.Users.ExcludeGroups,
				IncludedRoles:    p.Conditions.Users.IncludeRoles,
				ExcludedRoles:    p.Conditions.Users.ExcludeRoles,
				IncludedApps:     p.Conditions.Applications.IncludeApplications,
				ExcludedApps:     p.Conditions.Applications.ExcludeApplications,
				IncludedLocations: p.Conditions.Locations.IncludeLocations,
				ExcludedLocations: p.Conditions.Locations.ExcludeLocations,
				IncludedPlatforms: p.Conditions.Platforms.IncludePlatforms,
				ExcludedPlatforms: p.Conditions.Platforms.ExcludePlatforms,
				ClientAppTypes:    p.Conditions.ClientAppTypes,
				UserRiskLevels:    p.Conditions.UserRiskLevels,
				SignInRiskLevels:  p.Conditions.SignInRiskLevels,
				DeviceStates:      p.Conditions.DeviceStates.IncludeStates,
				GrantOperator:     p.GrantControls.Operator,
				GrantControls:     p.GrantControls.BuiltInControls,
			}
			if p.SessionControls.ApplicationEnforcedRestrictions.IsEnabled {
				details.ApplicationEnforcedRestrictions = true
			}
			if p.SessionControls.CloudAppSecurity.IsEnabled {
				details.CloudAppSecurity = p.SessionControls.CloudAppSecurity.CloudAppSecurityType
			}
			if p.SessionControls.SignInFrequency.IsEnabled {
				details.SignInFrequency = fmt.Sprintf("%d %s", p.SessionControls.SignInFrequency.Value, p.SessionControls.SignInFrequency.Type)
			}
			if p.SessionControls.PersistentBrowser.IsEnabled {
				details.PersistentBrowser = p.SessionControls.PersistentBrowser.Mode
			}
			allFullPolicies = append(allFullPolicies, details)
		}

		return data.NextLink != "", data.NextLink, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to pre-fetch CA policies: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return err
	}

	AzureDataCache.Set(cacheKey, allPolicies, 0)
	AzureDataCache.Set(fullCacheKey, allFullPolicies, 0)
	savePrefetchCache(baseDir, tenantID, "ca-policies.gob", CAPoliciesCache{Policies: allPolicies})
	savePrefetchCache(baseDir, tenantID, "ca-policies-full.gob", CAPoliciesFullCache{Policies: allFullPolicies})
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched %d conditional access policies", len(allPolicies)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
	return nil
}

// PreFetchPIMDirectoryRoles fetches ALL PIM eligible and active directory role assignments
// at the tenant level (no per-principal filter) and caches them as map[principalID][]DirectoryRole.
// This replaces per-principal Graph calls for PIM directory roles.
func PreFetchPIMDirectoryRoles(ctx context.Context, session *SafeSession, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	eligibleKey := AzCacheKey("pim-dir-eligible-all", "tenant")
	activeKey := AzCacheKey("pim-dir-active-all", "tenant")

	// 1. Check in-memory cache
	_, eligibleFound := AzureDataCache.Get(eligibleKey)
	_, activeFound := AzureDataCache.Get(activeKey)
	if eligibleFound && activeFound {
		return
	}

	// 2. Check disk cache
	var diskCache PIMDirectoryCache
	if loadPrefetchCache(baseDir, tenantID, "pim-directory.gob", DefaultAzureCacheExpiration, &diskCache) {
		if diskCache.Eligible != nil {
			AzureDataCache.Set(eligibleKey, diskCache.Eligible, 0)
		}
		if diskCache.Active != nil {
			AzureDataCache.Set(activeKey, diskCache.Active, 0)
		}
		return
	}

	// 3. Fetch from API
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for PIM directory roles pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	var eligibleMap map[string][]DirectoryRole
	var activeMap map[string][]DirectoryRole

	// Eligible directory roles
	eligibleMap = make(map[string][]DirectoryRole)
	eligibleURL := "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition"
	_ = GraphAPIPagedRequest(ctx, eligibleURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
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
			return false, "", err
		}
		for _, a := range data.Value {
			eligibleMap[a.PrincipalID] = append(eligibleMap[a.PrincipalID], DirectoryRole{
				RoleID:         a.RoleDefinition.ID,
				RoleTemplateID: a.RoleDefinition.TemplateID,
				DisplayName:    a.RoleDefinition.DisplayName,
				Description:    a.RoleDefinition.Description,
				AssignedVia:    "Direct",
				PIMStatus:      "PIM Eligible",
			})
		}
		return data.NextLink != "", data.NextLink, nil
	})
	AzureDataCache.Set(eligibleKey, eligibleMap, 0)

	// Active directory roles
	activeMap = make(map[string][]DirectoryRole)
	activeURL := "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=roleDefinition"
	_ = GraphAPIPagedRequest(ctx, activeURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
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
			return false, "", err
		}
		for _, a := range data.Value {
			pimStatus := ""
			if a.AssignmentType == "Activated" {
				pimStatus = "PIM Active"
			}
			assignedVia := "Direct"
			if a.MemberType == "Group" {
				assignedVia = "Group"
				if pimStatus != "" {
					pimStatus = "PIM Active (via Group)"
				}
			}
			activeMap[a.PrincipalID] = append(activeMap[a.PrincipalID], DirectoryRole{
				RoleID:         a.RoleDefinition.ID,
				RoleTemplateID: a.RoleDefinition.TemplateID,
				DisplayName:    a.RoleDefinition.DisplayName,
				Description:    a.RoleDefinition.Description,
				AssignedVia:    assignedVia,
				PIMStatus:      pimStatus,
			})
		}
		return data.NextLink != "", data.NextLink, nil
	})
	AzureDataCache.Set(activeKey, activeMap, 0)

	// Save to disk
	savePrefetchCache(baseDir, tenantID, "pim-directory.gob", PIMDirectoryCache{Eligible: eligibleMap, Active: activeMap})

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		totalEligible, totalActive := 0, 0
		for _, v := range eligibleMap {
			totalEligible += len(v)
		}
		for _, v := range activeMap {
			totalActive += len(v)
		}
		logger.InfoM(fmt.Sprintf("Pre-fetched PIM directory roles: %d eligible, %d active", totalEligible, totalActive), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
}

// GetConditionalAccessPoliciesForPrincipal retrieves CA policies that apply to a principal.
// Uses cached tenant-level CA policies if available (from PreFetchConditionalAccessPolicies),
// otherwise falls back to fetching from API.
func GetConditionalAccessPoliciesForPrincipal(ctx context.Context, session *SafeSession, principalObjectID string) ([]ConditionalAccessPolicy, error) {
	var policies []ConditionalAccessPolicy

	// Try cached path first
	cacheKey := AzCacheKey("ca-policies-all", "tenant")
	if cached, found := AzureDataCache.Get(cacheKey); found {
		allPolicies := cached.([]cachedCAPolicy)
		groupIDs := GetUserGroupMemberships(ctx, session, principalObjectID)
		groupSet := make(map[string]bool, len(groupIDs))
		for _, gid := range groupIDs {
			groupSet[gid] = true
		}

		for _, p := range allPolicies {
			included := false
			for _, uid := range p.IncludeUsers {
				if uid == principalObjectID || uid == "All" {
					included = true
					break
				}
			}
			if !included {
				for _, gid := range p.IncludeGroups {
					if groupSet[gid] {
						included = true
						break
					}
				}
			}
			if included {
				policies = append(policies, ConditionalAccessPolicy{
					ID:          p.ID,
					DisplayName: p.DisplayName,
					State:       p.State,
				})
			}
		}
		return policies, nil
	}

	// Fallback: fetch from API (pre-fetch not called)
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1])
	if err != nil {
		return policies, err
	}

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
			isPrincipalIncluded := false
			for _, userID := range policy.Conditions.Users.IncludeUsers {
				if userID == principalObjectID || userID == "All" {
					isPrincipalIncluded = true
					break
				}
			}
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

		return data.NextLink != "", data.NextLink, nil
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

// cachedRBACRawAssignment holds a raw role assignment from the ARM API,
// stored per-scope in the cache for client-side principal filtering.
type cachedRBACRawAssignment struct {
	PrincipalID                        string
	RoleDefinitionID                   string
	RoleName                           string
	Scope                              string // actual assignment scope (may differ from query scope if inherited)
	PrincipalType                      string // e.g. "User", "Group", "ServicePrincipal"
	Condition                          string // ABAC condition expression
	DelegatedManagedIdentityResourceID string // cross-tenant delegated MI
}

// PreFetchRBACAssignmentsForSubscription fetches ALL role assignments at the tenant root,
// management group hierarchy, and subscription scope. Results are cached per scope path
// as map[principalID][]cachedRBACRawAssignment for O(1) per-principal lookups.
// Also pre-resolves all role definition IDs to names.
// Results are persisted to disk so subsequent runs (or other modules) can reuse them.
func PreFetchRBACAssignmentsForSubscription(ctx context.Context, session *SafeSession, subscriptionID, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	logger := internal.NewLogger()

	// Check disk cache first
	diskFile := fmt.Sprintf("rbac-sub-%s.gob", subscriptionID)
	var diskCache RBACSubCache
	if loadPrefetchCache(baseDir, tenantID, diskFile, DefaultAzureCacheExpiration, &diskCache) {
		// Load all scopes into in-memory cache
		for scopePath, scopeMap := range diskCache.Scopes {
			cacheKey := AzCacheKey("rbac-scope-all", scopePath)
			AzureDataCache.Set(cacheKey, scopeMap, 0)
		}
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Loaded RBAC cache from disk for subscription %s (%d scopes)", subscriptionID, len(diskCache.Scopes)), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	// Build scope list (same hierarchy as GetEnhancedRBACAssignments)
	type scopeInfo struct {
		Path        string
		Type        string
		DisplayName string
	}
	scopes := []scopeInfo{
		{"/", "TenantRoot", "Tenant Root"},
	}

	mgHierarchy := GetManagementGroupHierarchy(ctx, session, subscriptionID)
	for _, mgID := range mgHierarchy {
		scopes = append(scopes, scopeInfo{
			fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID),
			"ManagementGroup",
			mgID,
		})
	}
	scopes = append(scopes, scopeInfo{
		fmt.Sprintf("/subscriptions/%s", subscriptionID),
		"Subscription",
		subscriptionID,
	})

	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for RBAC pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	cred := &StaticTokenCredential{Token: token}
	raClient, err := armauthorizationv2.NewRoleAssignmentsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create role assignments client for RBAC pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	totalAssignments := 0
	roleDefIDs := make(map[string]bool) // collect unique role def IDs for batch name resolution
	allScopeData := make(map[string]map[string][]cachedRBACRawAssignment) // for disk save

	for _, scope := range scopes {
		cacheKey := AzCacheKey("rbac-scope-all", scope.Path)
		if _, found := AzureDataCache.Get(cacheKey); found {
			continue // already cached
		}

		scopeMap := make(map[string][]cachedRBACRawAssignment) // principalID -> assignments
		scopeFailed := false
		pagesReceived := 0

		pager := raClient.NewListForScopePager(scope.Path, &armauthorizationv2.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr("atScope()"),
		})

		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				if IsAccessDenied(err) {
					// 403 on first page = no permission at this scope (expected for tenant root / MG scopes).
					// Cache empty map so we don't retry, and only log at verbose level.
					if pagesReceived == 0 {
						if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
							logger.InfoM(fmt.Sprintf("No access to RBAC at %s scope %s (need Microsoft.Authorization/roleAssignments/read)", scope.Type, scope.DisplayName), globals.AZ_PRINCIPALS_MODULE_NAME)
						}
						AzureDataCache.Set(cacheKey, scopeMap, 0)
					} else {
						// 403 mid-pagination is unexpected; don't cache partial data
						logger.ErrorM(fmt.Sprintf("Access denied mid-pagination at scope %s after %d pages (partial data NOT cached)", scope.Path, pagesReceived), globals.AZ_PRINCIPALS_MODULE_NAME)
						scopeFailed = true
					}
				} else {
					if pagesReceived == 0 {
						logger.ErrorM(fmt.Sprintf("Failed to pre-fetch RBAC at scope %s: %s", scope.Path, AzureAPIErrorSummary(err)), globals.AZ_PRINCIPALS_MODULE_NAME)
					} else {
						logger.ErrorM(fmt.Sprintf("Failed to pre-fetch RBAC at scope %s after %d pages: %s (partial data NOT cached)", scope.Path, pagesReceived, AzureAPIErrorSummary(err)), globals.AZ_PRINCIPALS_MODULE_NAME)
						scopeFailed = true
					}
				}
				break
			}
			pagesReceived++

			for _, ra := range page.Value {
				if ra.Properties == nil || ra.Properties.RoleDefinitionID == nil || ra.Properties.PrincipalID == nil {
					continue
				}
				pid := *ra.Properties.PrincipalID
				roleDefID := *ra.Properties.RoleDefinitionID
				assignmentScope := SafeStringPtr(ra.Properties.Scope)

				principalType := ""
				if ra.Properties.PrincipalType != nil {
					principalType = string(*ra.Properties.PrincipalType)
				}
				condition := SafeStringPtr(ra.Properties.Condition)
				delegatedMI := SafeStringPtr(ra.Properties.DelegatedManagedIdentityResourceID)

				roleDefIDs[roleDefID] = true

				scopeMap[pid] = append(scopeMap[pid], cachedRBACRawAssignment{
					PrincipalID:                        pid,
					RoleDefinitionID:                   roleDefID,
					Scope:                              assignmentScope,
					PrincipalType:                      principalType,
					Condition:                          condition,
					DelegatedManagedIdentityResourceID: delegatedMI,
				})
			}
		}

		// Don't cache partial data from interrupted pagination (would mask missing assignments)
		if scopeFailed {
			continue
		}

		count := 0
		for _, v := range scopeMap {
			count += len(v)
		}
		totalAssignments += count

		AzureDataCache.Set(cacheKey, scopeMap, 0)
		allScopeData[scope.Path] = scopeMap
	}

	// Pre-resolve all role definition IDs to names (populates individual cache entries)
	for roleDefID := range roleDefIDs {
		GetRoleNameFromDefinitionID(ctx, session, subscriptionID, roleDefID)
	}

	// Save to disk
	if len(allScopeData) > 0 {
		savePrefetchCache(baseDir, tenantID, diskFile, RBACSubCache{Scopes: allScopeData})
	}

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched %d RBAC assignments across %d scopes for subscription %s", totalAssignments, len(scopes), subscriptionID), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
}

// PreFetchRBACAssignmentsForResourceGroups fetches role assignments at all resource group
// scopes within a subscription and caches them using the same rbac-scope-all/{path} keys.
// This extends the pre-fetch to cover RG-level scopes so checkPrincipalAtScopes gets cache hits.
// Results are NOT saved to the per-subscription disk cache (RG data can be large and changes frequently).
func PreFetchRBACAssignmentsForResourceGroups(ctx context.Context, session *SafeSession, subscriptionID string) {
	logger := internal.NewLogger()

	token, err := session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &StaticTokenCredential{Token: token}

	// List all resource groups
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		return
	}

	var rgScopes []string
	pager := rgClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, rg := range page.Value {
			if rg.ID != nil {
				rgScopes = append(rgScopes, *rg.ID)
			}
		}
	}

	if len(rgScopes) == 0 {
		return
	}

	raClient, err := armauthorizationv2.NewRoleAssignmentsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		return
	}

	// Fetch RBAC assignments for each RG scope concurrently
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	totalAssignments := int64(0)

	for _, rgScope := range rgScopes {
		cacheKey := AzCacheKey("rbac-scope-all", rgScope)
		if _, found := AzureDataCache.Get(cacheKey); found {
			continue
		}

		wg.Add(1)
		go func(scope string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			scopeMap := make(map[string][]cachedRBACRawAssignment)
			scopeFailed := false
			pagesReceived := 0
			p := raClient.NewListForScopePager(scope, &armauthorizationv2.RoleAssignmentsClientListForScopeOptions{
				Filter: to.Ptr("atScope()"),
			})

			for p.More() {
				page, err := p.NextPage(ctx)
				if err != nil {
					if IsAccessDenied(err) {
						if pagesReceived == 0 {
							if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
								logger.InfoM(fmt.Sprintf("No access to RBAC at RG scope %s", scope), globals.AZ_PERMISSIONS_MODULE_NAME)
							}
							// Cache empty map so we don't retry
							AzureDataCache.Set(AzCacheKey("rbac-scope-all", scope), scopeMap, 0)
						} else {
							scopeFailed = true
						}
					} else {
						if pagesReceived > 0 {
							logger.ErrorM(fmt.Sprintf("Failed to pre-fetch RBAC at RG scope %s after %d pages: %s (partial data NOT cached)", scope, pagesReceived, AzureAPIErrorSummary(err)), globals.AZ_PERMISSIONS_MODULE_NAME)
							scopeFailed = true
						} else {
							logger.ErrorM(fmt.Sprintf("Failed to pre-fetch RBAC at RG scope %s: %s", scope, AzureAPIErrorSummary(err)), globals.AZ_PERMISSIONS_MODULE_NAME)
						}
					}
					break
				}
				pagesReceived++
				for _, ra := range page.Value {
					if ra.Properties == nil || ra.Properties.RoleDefinitionID == nil || ra.Properties.PrincipalID == nil {
						continue
					}
					pid := *ra.Properties.PrincipalID
					roleDefID := *ra.Properties.RoleDefinitionID
					assignmentScope := SafeStringPtr(ra.Properties.Scope)

					principalType := ""
					if ra.Properties.PrincipalType != nil {
						principalType = string(*ra.Properties.PrincipalType)
					}
					condition := SafeStringPtr(ra.Properties.Condition)
					delegatedMI := SafeStringPtr(ra.Properties.DelegatedManagedIdentityResourceID)

					scopeMap[pid] = append(scopeMap[pid], cachedRBACRawAssignment{
						PrincipalID:                        pid,
						RoleDefinitionID:                   roleDefID,
						RoleName:                           GetRoleNameFromDefinitionID(ctx, session, subscriptionID, roleDefID),
						Scope:                              assignmentScope,
						PrincipalType:                      principalType,
						Condition:                          condition,
						DelegatedManagedIdentityResourceID: delegatedMI,
					})
				}
			}

			// Don't cache partial data from interrupted pagination
			if scopeFailed {
				return
			}

			count := 0
			for _, v := range scopeMap {
				count += len(v)
			}
			atomic.AddInt64(&totalAssignments, int64(count))
			AzureDataCache.Set(AzCacheKey("rbac-scope-all", scope), scopeMap, 0)
		}(rgScope)
	}
	wg.Wait()

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched %d RBAC assignments across %d resource groups for subscription %s", totalAssignments, len(rgScopes), subscriptionID), globals.AZ_PERMISSIONS_MODULE_NAME)
	}
}

// CachedRBACEntry is the exported view of a cached RBAC role assignment for external callers.
type CachedRBACEntry struct {
	PrincipalID                        string
	RoleDefinitionID                   string
	RoleName                           string
	Scope                              string
	PrincipalType                      string
	Condition                          string
	DelegatedManagedIdentityResourceID string
}

// LookupRBACCacheForScope checks the in-memory RBAC cache for a specific scope path
// and returns any cached assignments for the given principal IDs.
// Returns nil if the scope is not cached (caller should fall back to API).
func LookupRBACCacheForScope(scopePath string, principalIDs []string) []CachedRBACEntry {
	cacheKey := AzCacheKey("rbac-scope-all", scopePath)
	cached, found := AzureDataCache.Get(cacheKey)
	if !found {
		return nil
	}
	scopeMap := cached.(map[string][]cachedRBACRawAssignment)

	var results []CachedRBACEntry
	for _, pid := range principalIDs {
		for _, raw := range scopeMap[pid] {
			results = append(results, CachedRBACEntry{
				PrincipalID:                        raw.PrincipalID,
				RoleDefinitionID:                   raw.RoleDefinitionID,
				RoleName:                           raw.RoleName,
				Scope:                              raw.Scope,
				PrincipalType:                      raw.PrincipalType,
				Condition:                          raw.Condition,
				DelegatedManagedIdentityResourceID: raw.DelegatedManagedIdentityResourceID,
			})
		}
	}
	return results
}

// ListRBACPrincipalIDsForScope returns all principal IDs that have RBAC assignments
// at the given scope, from the in-memory cache. Returns nil if the scope is not cached.
func ListRBACPrincipalIDsForScope(scopePath string) []string {
	cacheKey := AzCacheKey("rbac-scope-all", scopePath)
	cached, found := AzureDataCache.Get(cacheKey)
	if !found {
		return nil
	}
	scopeMap := cached.(map[string][]cachedRBACRawAssignment)
	ids := make([]string, 0, len(scopeMap))
	for pid, assignments := range scopeMap {
		if len(assignments) > 0 {
			ids = append(ids, pid)
		}
	}
	return ids
}

// ListAllRBACForScope returns ALL cached RBAC assignments at the given scope
// (not filtered by principal ID). Returns nil if the scope is not cached.
// Used by the RBAC module's scope-based enumeration.
func ListAllRBACForScope(scopePath string) []CachedRBACEntry {
	cacheKey := AzCacheKey("rbac-scope-all", scopePath)
	cached, found := AzureDataCache.Get(cacheKey)
	if !found {
		return nil
	}
	scopeMap := cached.(map[string][]cachedRBACRawAssignment)
	var results []CachedRBACEntry
	for _, assignments := range scopeMap {
		for _, raw := range assignments {
			results = append(results, CachedRBACEntry{
				PrincipalID:                        raw.PrincipalID,
				RoleDefinitionID:                   raw.RoleDefinitionID,
				RoleName:                           raw.RoleName,
				Scope:                              raw.Scope,
				PrincipalType:                      raw.PrincipalType,
				Condition:                          raw.Condition,
				DelegatedManagedIdentityResourceID: raw.DelegatedManagedIdentityResourceID,
			})
		}
	}
	return results
}

// ListAllPIMForSubscription returns ALL PIM eligible and active assignments
// for a subscription from the in-memory cache. The cached return value is true
// if the PIM cache was populated for this subscription (even if zero assignments exist).
// Used by the RBAC module's scope-based enumeration.
func ListAllPIMForSubscription(subscriptionID string) (eligible []PIMRoleAssignment, active []PIMRoleAssignment, cached bool) {
	eligibleKey := AzCacheKey("pim-eligible-all", subscriptionID)
	if c, found := AzureDataCache.Get(eligibleKey); found {
		cached = true
		for _, assignments := range c.(map[string][]PIMRoleAssignment) {
			eligible = append(eligible, assignments...)
		}
	}

	activeKey := AzCacheKey("pim-active-all", subscriptionID)
	if c, found := AzureDataCache.Get(activeKey); found {
		cached = true
		for _, assignments := range c.(map[string][]PIMRoleAssignment) {
			active = append(active, assignments...)
		}
	}
	return
}

// ListPIMPrincipalIDsForSubscription returns all principal IDs that have PIM
// eligible or active role assignments for the given subscription, from the in-memory cache.
// Returns nil if the PIM cache is not populated for this subscription.
func ListPIMPrincipalIDsForSubscription(subscriptionID string) []string {
	seen := make(map[string]bool)

	eligibleKey := AzCacheKey("pim-eligible-all", subscriptionID)
	if cached, found := AzureDataCache.Get(eligibleKey); found {
		for pid := range cached.(map[string][]PIMRoleAssignment) {
			seen[pid] = true
		}
	}

	activeKey := AzCacheKey("pim-active-all", subscriptionID)
	if cached, found := AzureDataCache.Get(activeKey); found {
		for pid := range cached.(map[string][]PIMRoleAssignment) {
			seen[pid] = true
		}
	}

	if len(seen) == 0 {
		return nil
	}
	ids := make([]string, 0, len(seen))
	for pid := range seen {
		ids = append(ids, pid)
	}
	return ids
}

// ---------------------------------------------------------------------------
// Bulk RBAC index builder (zero API calls, pure cache iteration)
// ---------------------------------------------------------------------------

// BuildRBACIndexFromCaches pre-computes RBAC assignments for ALL principals across
// all subscriptions using only the in-memory scope caches. Returns four indexes:
//   - rbacIndex: principalID -> formatted RBAC display strings
//   - inheritedIndex: principalID -> formatted inherited assignment strings
//   - pimSubEligibleIndex: principalID -> formatted PIM eligible strings
//   - pimSubActiveIndex: principalID -> formatted PIM active strings
//
// This replaces per-principal GetEnhancedRBACAssignments calls which could trigger
// API calls via GetUserGroupMemberships. Instead, group expansion uses the pre-fetched
// groupCache directly.
func BuildRBACIndexFromCaches(
	subscriptions []string,
	subNameMap map[string]string,
	groupCache map[string]CachedGroupMembership,
	principalIDs []string,
) (rbacIndex, inheritedIndex, pimSubEligibleIndex, pimSubActiveIndex map[string][]string) {

	rbacIndex = make(map[string][]string)
	inheritedIndex = make(map[string][]string)
	pimSubEligibleIndex = make(map[string][]string)
	pimSubActiveIndex = make(map[string][]string)

	// Build a set of all principal IDs for fast lookup
	principalSet := make(map[string]bool, len(principalIDs))
	for _, pid := range principalIDs {
		principalSet[pid] = true
	}

	// Pre-compute: principalID -> all group IDs (from bulk cache)
	// This is the key optimization: we use the groupCache directly instead of
	// calling GetUserGroupMemberships which falls through to per-principal API.
	groupIDsFor := make(map[string][]string, len(principalIDs))
	if groupCache != nil {
		for _, pid := range principalIDs {
			if gm, ok := groupCache[pid]; ok {
				groupIDsFor[pid] = gm.AllGroupIDs
			}
		}
	}

	for _, sub := range subscriptions {
		subDisplayName := subNameMap[sub]
		if subDisplayName == "" {
			subDisplayName = sub
		}

		// Build scope list from cached management group hierarchy
		type scopeInfo struct {
			Path        string
			Type        string
			DisplayName string
		}
		scopes := []scopeInfo{
			{"/", "TenantRoot", "Tenant Root"},
		}

		// Get MG hierarchy from cache (GetManagementGroupHierarchy caches per-sub)
		mgKey := AzCacheKey("mg-hierarchy", sub)
		if cached, found := AzureDataCache.Get(mgKey); found {
			for _, mgID := range cached.([]string) {
				scopes = append(scopes, scopeInfo{
					fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID),
					"ManagementGroup",
					mgID,
				})
			}
		}
		scopes = append(scopes, scopeInfo{
			fmt.Sprintf("/subscriptions/%s", sub),
			"Subscription",
			sub,
		})

		// For each scope, iterate all assignments in the cache and match to our principals
		for _, scope := range scopes {
			cacheKey := AzCacheKey("rbac-scope-all", scope.Path)
			cached, found := AzureDataCache.Get(cacheKey)
			if !found {
				continue
			}
			scopeMap := cached.(map[string][]cachedRBACRawAssignment)

			// For each principal, check direct + group-based assignments
			for _, pid := range principalIDs {
				// Direct assignments
				for _, rawRA := range scopeMap[pid] {
					roleName := rawRA.RoleName
					if roleName == "" {
						// Try in-memory role name cache
						roleKey := AzCacheKey("role-name", rawRA.RoleDefinitionID)
						if rn, found := AzureDataCache.Get(roleKey); found {
							roleName = rn.(string)
						} else {
							roleName = "Unknown"
						}
					}

					rbacDisplay := fmt.Sprintf("%s: %s", subDisplayName, roleName)
					if scope.Type == "TenantRoot" {
						rbacDisplay += " [Tenant Root]"
					} else if scope.Type == "ManagementGroup" {
						rbacDisplay += fmt.Sprintf(" [MG: %s]", scope.DisplayName)
					}
					rbacIndex[pid] = append(rbacIndex[pid], rbacDisplay)

					if rawRA.Scope != scope.Path {
						inheritedIndex[pid] = append(inheritedIndex[pid],
							fmt.Sprintf("%s: %s (inherited from %s)", subDisplayName, roleName, scope.Type))
					}
				}

				// Group-based assignments
				for _, gid := range groupIDsFor[pid] {
					for _, rawRA := range scopeMap[gid] {
						roleName := rawRA.RoleName
						if roleName == "" {
							roleKey := AzCacheKey("role-name", rawRA.RoleDefinitionID)
							if rn, found := AzureDataCache.Get(roleKey); found {
								roleName = rn.(string)
							} else {
								roleName = "Unknown"
							}
						}

						rbacDisplay := fmt.Sprintf("%s: %s (via Group)", subDisplayName, roleName)
						if scope.Type == "TenantRoot" {
							rbacDisplay += " [Tenant Root]"
						} else if scope.Type == "ManagementGroup" {
							rbacDisplay += fmt.Sprintf(" [MG: %s]", scope.DisplayName)
						}
						rbacIndex[pid] = append(rbacIndex[pid], rbacDisplay)

						if rawRA.Scope != scope.Path {
							inheritedIndex[pid] = append(inheritedIndex[pid],
								fmt.Sprintf("%s: %s (inherited from %s)", subDisplayName, roleName, scope.Type))
						}
					}
				}
			}
		}

		// PIM: subscription-scoped, also uses groupIDsFor instead of GetUserGroupMemberships
		eligibleKey := AzCacheKey("pim-eligible-all", sub)
		if cached, found := AzureDataCache.Get(eligibleKey); found {
			eligibleMap := cached.(map[string][]PIMRoleAssignment)
			for _, pid := range principalIDs {
				// Direct PIM
				for _, pa := range eligibleMap[pid] {
					pimSubEligibleIndex[pid] = append(pimSubEligibleIndex[pid],
						fmt.Sprintf("%s: %s (%s)", subDisplayName, pa.RoleName, pa.AssignedVia))
				}
				// Group-based PIM
				for _, gid := range groupIDsFor[pid] {
					for _, pa := range eligibleMap[gid] {
						pimSubEligibleIndex[pid] = append(pimSubEligibleIndex[pid],
							fmt.Sprintf("%s: %s (via Group)", subDisplayName, pa.RoleName))
					}
				}
			}
		}

		activeKey := AzCacheKey("pim-active-all", sub)
		if cached, found := AzureDataCache.Get(activeKey); found {
			activeMap := cached.(map[string][]PIMRoleAssignment)
			for _, pid := range principalIDs {
				// Direct PIM
				for _, pa := range activeMap[pid] {
					pimSubActiveIndex[pid] = append(pimSubActiveIndex[pid],
						fmt.Sprintf("%s: %s (%s)", subDisplayName, pa.RoleName, pa.AssignedVia))
				}
				// Group-based PIM
				for _, gid := range groupIDsFor[pid] {
					for _, pa := range activeMap[gid] {
						pimSubActiveIndex[pid] = append(pimSubActiveIndex[pid],
							fmt.Sprintf("%s: %s (via Group)", subDisplayName, pa.RoleName))
					}
				}
			}
		}
	}

	return
}

// ---------------------------------------------------------------------------
// Bulk CA policy index builder (zero API calls, pure cache iteration)
// ---------------------------------------------------------------------------

// BuildCAPolicyIndex pre-computes conditional access policy matches for all principals
// using only the in-memory CA policy cache and group cache. Returns a map of
// principalID -> formatted CA policy strings.
func BuildCAPolicyIndex(
	groupCache map[string]CachedGroupMembership,
	principalIDs []string,
) map[string]string {
	caIndex := make(map[string]string)

	cacheKey := AzCacheKey("ca-policies-all", "tenant")
	cached, found := AzureDataCache.Get(cacheKey)
	if !found {
		return caIndex
	}
	allPolicies := cached.([]cachedCAPolicy)
	if len(allPolicies) == 0 {
		return caIndex
	}

	// For policies that target "All" users, pre-compute the list
	var allUserPolicies []ConditionalAccessPolicy
	// For group-targeted policies, build groupID -> []policy index
	groupPolicyIndex := make(map[string][]ConditionalAccessPolicy)
	// For user-targeted policies, build userID -> []policy index
	userPolicyIndex := make(map[string][]ConditionalAccessPolicy)

	for _, p := range allPolicies {
		cap := ConditionalAccessPolicy{ID: p.ID, DisplayName: p.DisplayName, State: p.State}
		isAllUsers := false
		for _, uid := range p.IncludeUsers {
			if uid == "All" {
				isAllUsers = true
				allUserPolicies = append(allUserPolicies, cap)
				break
			}
			userPolicyIndex[uid] = append(userPolicyIndex[uid], cap)
		}
		if !isAllUsers {
			for _, gid := range p.IncludeGroups {
				groupPolicyIndex[gid] = append(groupPolicyIndex[gid], cap)
			}
		}
	}

	// For each principal, collect matching policies via direct + group memberships
	for _, pid := range principalIDs {
		seen := make(map[string]bool)
		var matched []ConditionalAccessPolicy

		// All-user policies
		for _, p := range allUserPolicies {
			if !seen[p.ID] {
				seen[p.ID] = true
				matched = append(matched, p)
			}
		}

		// User-targeted policies
		for _, p := range userPolicyIndex[pid] {
			if !seen[p.ID] {
				seen[p.ID] = true
				matched = append(matched, p)
			}
		}

		// Group-targeted policies (via group memberships from bulk cache)
		if groupCache != nil {
			if gm, ok := groupCache[pid]; ok {
				for _, gid := range gm.AllGroupIDs {
					for _, p := range groupPolicyIndex[gid] {
						if !seen[p.ID] {
							seen[p.ID] = true
							matched = append(matched, p)
						}
					}
				}
			}
		}

		if len(matched) > 0 {
			caIndex[pid] = FormatConditionalAccessPolicies(matched)
		}
	}

	return caIndex
}

// GetEnhancedRBACAssignments retrieves RBAC assignments with full scope hierarchy and inheritance tracking.
// Uses cached data if available (from PreFetchRBACAssignmentsForSubscription).
func GetEnhancedRBACAssignments(ctx context.Context, session *SafeSession, principalObjectID string, subscriptionID string) ([]RBACAssignmentWithInheritance, error) {
	logger := internal.NewLogger()
	var assignments []RBACAssignmentWithInheritance

	// Get user's group memberships for group-based assignment tracking
	groupIDs := GetUserGroupMemberships(ctx, session, principalObjectID)
	principalIDs := []string{principalObjectID}
	principalIDs = append(principalIDs, groupIDs...)

	// Define scopes to check in order of hierarchy (top to bottom)
	type scopeInfo struct {
		Path        string
		Type        string
		DisplayName string
	}
	scopes := []scopeInfo{
		{"/", "TenantRoot", "Tenant Root"},
	}

	mgHierarchy := GetManagementGroupHierarchy(ctx, session, subscriptionID)
	for _, mgID := range mgHierarchy {
		scopes = append(scopes, scopeInfo{
			fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID),
			"ManagementGroup",
			mgID,
		})
	}
	scopes = append(scopes, scopeInfo{
		fmt.Sprintf("/subscriptions/%s", subscriptionID),
		"Subscription",
		subscriptionID,
	})

	// Track assignments by role+scope to avoid duplicates
	assignmentMap := make(map[string]RBACAssignmentWithInheritance)

	// Try cached path: check if ALL scopes are cached
	allCached := true
	for _, scope := range scopes {
		cacheKey := AzCacheKey("rbac-scope-all", scope.Path)
		if _, found := AzureDataCache.Get(cacheKey); !found {
			allCached = false
			break
		}
	}

	if allCached {
		// Use cached data: filter client-side by principalIDs
		principalSet := make(map[string]bool, len(principalIDs))
		for _, pid := range principalIDs {
			principalSet[pid] = true
		}

		for _, scope := range scopes {
			cacheKey := AzCacheKey("rbac-scope-all", scope.Path)
			cached, _ := AzureDataCache.Get(cacheKey)
			scopeMap := cached.(map[string][]cachedRBACRawAssignment)

			for _, pid := range principalIDs {
				for _, rawRA := range scopeMap[pid] {
					roleName := GetRoleNameFromDefinitionID(ctx, session, subscriptionID, rawRA.RoleDefinitionID)

					assignedVia := "Direct"
					if pid != principalObjectID {
						assignedVia = "Group"
					}

					inheritedFrom := ""
					if rawRA.Scope != scope.Path {
						inheritedFrom = rawRA.Scope
					}

					assignment := RBACAssignmentWithInheritance{
						RoleName:         roleName,
						Scope:            rawRA.Scope,
						ScopeType:        scope.Type,
						ScopeDisplayName: scope.DisplayName,
						AssignedVia:      assignedVia,
						InheritedFrom:    inheritedFrom,
						PrincipalID:      pid,
					}

					key := fmt.Sprintf("%s|%s|%s", roleName, rawRA.Scope, pid)
					if _, exists := assignmentMap[key]; !exists {
						assignmentMap[key] = assignment
						assignments = append(assignments, assignment)
					}
				}
			}
		}

		return assignments, nil
	}

	// Fallback: fetch from API per-principal per-scope (original path)
	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return assignments, err
	}

	cred := &StaticTokenCredential{Token: token}
	raClient, err := armauthorizationv2.NewRoleAssignmentsClient(subscriptionID, cred, DefaultARMClientOptions())
	if err != nil {
		return assignments, err
	}

	for _, scope := range scopes {
		for _, principalID := range principalIDs {
			pager := raClient.NewListForScopePager(scope.Path, &armauthorizationv2.RoleAssignmentsClientListForScopeOptions{
				Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalID)),
			})

			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					if !IsAccessDenied(err) && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("Failed to get role assignments at scope %s for principal %s: %s", scope.Path, principalID, AzureAPIErrorSummary(err)), globals.AZ_PRINCIPALS_MODULE_NAME)
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

					inheritedFrom := ""
					if assignmentScope != scope.Path {
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
	// Check bulk directory role members cache first
	bulkKey := AzCacheKey("directory-role-members-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		bulkData := cached.(map[string][]DirectoryRole)
		if roles, ok := bulkData[principalObjectID]; ok {
			return roles, nil
		}
		// Principal not in bulk cache - fall through to per-principal API
	}

	// Fall back to per-principal API
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

	// Backfill bulk cache so other callers benefit
	BackfillBulkCache(bulkKey, principalObjectID, roles)

	return roles, nil
}

// GetPIMEligibleDirectoryRoles retrieves PIM-eligible Entra ID directory role assignments
func GetPIMEligibleDirectoryRoles(ctx context.Context, session *SafeSession, principalObjectID string) ([]DirectoryRole, error) {
	// Check pre-fetched tenant-level cache first
	bulkKey := AzCacheKey("pim-dir-eligible-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		eligibleMap := cached.(map[string][]DirectoryRole)
		if roles, ok := eligibleMap[principalObjectID]; ok {
			return roles, nil
		}
		// Principal not in bulk cache, fall through to per-principal API
	}

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

	// Backfill bulk cache so other callers benefit
	BackfillBulkCache(bulkKey, principalObjectID, roles)

	return roles, nil
}

// GetPIMActiveDirectoryRoles retrieves currently active PIM directory role assignments
func GetPIMActiveDirectoryRoles(ctx context.Context, session *SafeSession, principalObjectID string) ([]DirectoryRole, error) {
	// Check pre-fetched tenant-level cache first
	bulkKey := AzCacheKey("pim-dir-active-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		activeMap := cached.(map[string][]DirectoryRole)
		if roles, ok := activeMap[principalObjectID]; ok {
			return roles, nil
		}
		// Principal not in bulk cache, fall through to per-principal API
	}

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

	// Backfill bulk cache so other callers benefit
	BackfillBulkCache(bulkKey, principalObjectID, roles)

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
	// Check bulk group memberships cache first
	bulkKey := AzCacheKey("group-memberships-all", "tenant")
	if cached, found := AzureDataCache.Get(bulkKey); found {
		bulkData := cached.(map[string]CachedGroupMembership)
		if membership, ok := bulkData[principalObjectID]; ok {
			return membership.DirectGroupNames, membership.AllGroupNames, nil
		}
		// Principal not in bulk cache - fall through to per-principal API
	}

	// Fall back to per-principal cache / API
	directKey := AzCacheKey("nested-direct-groups", principalObjectID)
	allKey := AzCacheKey("nested-all-groups", principalObjectID)
	if cachedDirect, found := AzureDataCache.Get(directKey); found {
		cachedAll, _ := AzureDataCache.Get(allKey)
		return cachedDirect.([]string), cachedAll.([]string), nil
	}

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

	AzureDataCache.Set(directKey, directGroups, 0)
	AzureDataCache.Set(allKey, allGroups, 0)

	// Backfill bulk cache so other callers benefit
	var allGroupIDs []string
	for id := range allGroupsMap {
		allGroupIDs = append(allGroupIDs, id)
	}
	BackfillBulkCache(bulkKey, principalObjectID, CachedGroupMembership{
		DirectGroupNames: directGroups,
		AllGroupNames:    allGroups,
		AllGroupIDs:      allGroupIDs,
	})

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

// PreFetchMFABulk uses the Graph $batch API to fetch MFA authentication methods
// for all users in parallel batches of 20. This is ~60x faster than per-user calls.
// Results are stored in the bulk MFA cache (az-mfa-all-tenant).
func PreFetchMFABulk(ctx context.Context, session *SafeSession, baseDir, tenantID string, userIDs []string) {
	SetBulkCacheContext(baseDir, tenantID)
	cacheKey := AzCacheKey("mfa-all", "tenant")

	// 1. Check in-memory cache
	if _, found := AzureDataCache.Get(cacheKey); found {
		return
	}

	// 2. Check disk cache
	var diskCache MFABulkCache
	if loadPrefetchCache(baseDir, tenantID, "mfa-bulk.gob", DefaultAzureCacheExpiration, &diskCache) && diskCache.Data != nil {
		AzureDataCache.Set(cacheKey, diskCache.Data, 0)
		return
	}

	logger := internal.NewLogger()

	if len(userIDs) == 0 {
		AzureDataCache.Set(cacheKey, map[string]MFAAuthenticationMethods{}, 0)
		savePrefetchCache(baseDir, tenantID, "mfa-bulk.gob", MFABulkCache{Data: map[string]MFAAuthenticationMethods{}})
		return
	}

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for MFA bulk pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	mfaMap := make(map[string]MFAAuthenticationMethods, len(userIDs))
	var mu sync.Mutex

	// Chunk userIDs into batches of 20 (Graph $batch limit)
	const batchSize = 20
	sem := make(chan struct{}, 5) // limit concurrent batch requests
	var wg sync.WaitGroup

	for i := 0; i < len(userIDs); i += batchSize {
		end := i + batchSize
		if end > len(userIDs) {
			end = len(userIDs)
		}
		chunk := userIDs[i:end]

		wg.Add(1)
		go func(chunk []string, batchNum int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Build sub-requests
			subReqs := make([]GraphBatchSubRequest, len(chunk))
			for j, uid := range chunk {
				subReqs[j] = GraphBatchSubRequest{
					ID:     uid,
					Method: "GET",
					URL:    fmt.Sprintf("/users/%s/authentication/methods", uid),
				}
			}

			responses, err := GraphBatchRequest(ctx, token, subReqs)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("MFA batch request failed (batch %d): %v", batchNum, err), globals.AZ_PRINCIPALS_MODULE_NAME)
				}
				return
			}

			// Parse each sub-response
			for _, resp := range responses {
				userID := resp.ID
				mfa := MFAAuthenticationMethods{
					MFAEnabled: false,
					Methods:    []string{},
				}

				if resp.Status != 200 {
					// User might lack permissions or MFA not configured
					mu.Lock()
					mfaMap[userID] = mfa
					mu.Unlock()
					continue
				}

				var data struct {
					Value []map[string]interface{} `json:"value"`
				}
				if err := json.Unmarshal(resp.Body, &data); err != nil {
					mu.Lock()
					mfaMap[userID] = mfa
					mu.Unlock()
					continue
				}

				// Parse authentication methods (same logic as GetUserMFAAuthenticationMethods)
				defaultMethodID := ""
				for _, method := range data.Value {
					odataType, ok := method["@odata.type"].(string)
					if !ok {
						continue
					}

					switch odataType {
					case "#microsoft.graph.phoneAuthenticationMethod":
						mfa.Methods = append(mfa.Methods, "Phone")
						mfa.HasPhoneAuth = true
						if defaultMethodID == "" {
							defaultMethodID = "Phone"
						}
					case "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
						mfa.Methods = append(mfa.Methods, "Authenticator")
						mfa.HasAuthenticator = true
						if defaultMethodID == "" {
							defaultMethodID = "Authenticator"
						}
					case "#microsoft.graph.fido2AuthenticationMethod":
						mfa.Methods = append(mfa.Methods, "FIDO2")
						mfa.HasFIDO2 = true
						if defaultMethodID == "" {
							defaultMethodID = "FIDO2"
						}
					case "#microsoft.graph.emailAuthenticationMethod":
						mfa.Methods = append(mfa.Methods, "Email")
						mfa.HasEmail = true
					case "#microsoft.graph.temporaryAccessPassAuthenticationMethod":
						mfa.Methods = append(mfa.Methods, "TemporaryAccessPass")
						mfa.HasTemporaryPass = true
					case "#microsoft.graph.passwordAuthenticationMethod":
						continue // Password is always present, don't count as MFA
					default:
						methodID, _ := method["id"].(string)
						if methodID != "" {
							methodType := strings.TrimPrefix(odataType, "#microsoft.graph.")
							methodType = strings.TrimSuffix(methodType, "AuthenticationMethod")
							mfa.Methods = append(mfa.Methods, methodType)
						}
					}
				}

				if len(mfa.Methods) > 0 {
					mfa.MFAEnabled = true
				}
				if defaultMethodID != "" {
					mfa.DefaultMethod = defaultMethodID
				} else if len(mfa.Methods) > 0 {
					mfa.DefaultMethod = mfa.Methods[0]
				}

				mu.Lock()
				mfaMap[userID] = mfa
				mu.Unlock()
			}

			// Incremental disk save every 500 users processed
			mu.Lock()
			processed := len(mfaMap)
			mu.Unlock()
			if processed%500 < batchSize {
				mu.Lock()
				partial := make(map[string]MFAAuthenticationMethods, len(mfaMap))
				for k, v := range mfaMap {
					partial[k] = v
				}
				mu.Unlock()
				savePrefetchCache(baseDir, tenantID, "mfa-bulk.gob", MFABulkCache{Data: partial})
			}
		}(chunk, i/batchSize)
	}

	wg.Wait()

	AzureDataCache.Set(cacheKey, mfaMap, 0)
	savePrefetchCache(baseDir, tenantID, "mfa-bulk.gob", MFABulkCache{Data: mfaMap})

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched MFA methods for %d users via batch API", len(mfaMap)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
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

// GetAllConditionalAccessPolicies retrieves all CA policies in the tenant with full details.
// Checks the bulk pre-fetch cache first, falls back to API if not cached.
func GetAllConditionalAccessPolicies(ctx context.Context, session *SafeSession) ([]ConditionalAccessPolicyDetails, error) {
	// Check bulk cache first (populated by PreFetchConditionalAccessPolicies)
	fullCacheKey := AzCacheKey("ca-policies-full", "tenant")
	if cached, found := AzureDataCache.Get(fullCacheKey); found {
		return cached.([]ConditionalAccessPolicyDetails), nil
	}

	// Fall back to API
	logger := internal.NewLogger()
	var policies []ConditionalAccessPolicyDetails

	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for CA policies: %v", err), "conditional-access")
		}
		return policies, err
	}

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
				IncludedUsers:    policy.Conditions.Users.IncludeUsers,
				ExcludedUsers:    policy.Conditions.Users.ExcludeUsers,
				IncludedGroups:   policy.Conditions.Users.IncludeGroups,
				ExcludedGroups:   policy.Conditions.Users.ExcludeGroups,
				IncludedRoles:    policy.Conditions.Users.IncludeRoles,
				ExcludedRoles:    policy.Conditions.Users.ExcludeRoles,
				IncludedApps:     policy.Conditions.Applications.IncludeApplications,
				ExcludedApps:     policy.Conditions.Applications.ExcludeApplications,
				IncludedLocations: policy.Conditions.Locations.IncludeLocations,
				ExcludedLocations: policy.Conditions.Locations.ExcludeLocations,
				IncludedPlatforms: policy.Conditions.Platforms.IncludePlatforms,
				ExcludedPlatforms: policy.Conditions.Platforms.ExcludePlatforms,
				ClientAppTypes:    policy.Conditions.ClientAppTypes,
				UserRiskLevels:    policy.Conditions.UserRiskLevels,
				SignInRiskLevels:  policy.Conditions.SignInRiskLevels,
				DeviceStates:      policy.Conditions.DeviceStates.IncludeStates,
				GrantOperator:     policy.GrantControls.Operator,
				GrantControls:     policy.GrantControls.BuiltInControls,
			}
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

		return data.NextLink != "", data.NextLink, nil
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

// ========================================
// Bulk Tenant-Level Pre-Fetch Functions
// ========================================

// PreFetchGroupMemberships fetches ALL group memberships at the tenant level by iterating
// all groups and fetching their members + transitiveMembers. Builds an inverted index:
// principalID -> CachedGroupMembership for O(1) lookup per principal.
func PreFetchGroupMemberships(ctx context.Context, session *SafeSession, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	cacheKey := AzCacheKey("group-memberships-all", "tenant")

	// 1. Check in-memory cache
	if _, found := AzureDataCache.Get(cacheKey); found {
		return
	}

	// 2. Check disk cache
	var diskCache GroupMembershipsCache
	if loadPrefetchCache(baseDir, tenantID, "group-memberships.gob", DefaultAzureCacheExpiration, &diskCache) {
		AzureDataCache.Set(cacheKey, diskCache.Data, 0)
		// Rebuild group name map from membership data for GetGroupDisplayName lookups
		nameMap := make(map[string]string)
		for _, membership := range diskCache.Data {
			for i, gid := range membership.AllGroupIDs {
				if i < len(membership.AllGroupNames) {
					nameMap[gid] = membership.AllGroupNames[i]
				}
			}
		}
		AzureDataCache.Set(AzCacheKey("group-names-all", "tenant"), nameMap, 0)
		return
	}

	// 3. Fetch from API
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for group memberships pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	// Get ALL groups (not just security-enabled) with displayName for name resolution
	type groupInfo struct {
		ID          string
		DisplayName string
	}
	var allGroups []groupInfo
	groupsURL := "https://graph.microsoft.com/v1.0/groups?$select=id,displayName"
	err = GraphAPIPagedRequest(ctx, groupsURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", err
		}
		for _, g := range data.Value {
			allGroups = append(allGroups, groupInfo{ID: g.ID, DisplayName: g.DisplayName})
		}
		return data.NextLink != "", data.NextLink, nil
	})
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list groups for membership pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	if len(allGroups) == 0 {
		AzureDataCache.Set(cacheKey, map[string]CachedGroupMembership{}, 0)
		savePrefetchCache(baseDir, tenantID, "group-memberships.gob", GroupMembershipsCache{Data: map[string]CachedGroupMembership{}})
		return
	}

	// Build group ID -> displayName map
	groupNameMap := make(map[string]string, len(allGroups))
	for _, g := range allGroups {
		groupNameMap[g.ID] = g.DisplayName
	}

	// For each group, fetch direct members and transitive members concurrently.
	// Results are collected via a channel for incremental progress saving.
	type groupMemberResult struct {
		GroupID         string
		DirectMemberIDs []string
		TransMemberIDs  []string
	}

	// Load partial cache from a previous interrupted run (if any).
	// The partial GOB uses the same GroupMembershipsPartialCache struct.
	type partialCacheOnDisk struct {
		ProcessedGroupIDs []string
		Data              map[string]CachedGroupMembership
	}
	processedGroupSet := make(map[string]bool)
	var partialDisk partialCacheOnDisk
	if loadPrefetchCache(baseDir, tenantID, "group-memberships-partial.gob", DefaultAzureCacheExpiration, &partialDisk) && partialDisk.Data != nil {
		for _, gid := range partialDisk.ProcessedGroupIDs {
			processedGroupSet[gid] = true
		}
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Resuming group membership pre-fetch: %d/%d groups already processed", len(processedGroupSet), len(allGroups)), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
	}

	// Filter out already-processed groups
	var pendingGroups []groupInfo
	for _, g := range allGroups {
		if !processedGroupSet[g.ID] {
			pendingGroups = append(pendingGroups, g)
		}
	}

	// Collect results via channel for incremental saving
	resultsCh := make(chan groupMemberResult, len(pendingGroups))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30) // concurrency limit (raised from 10; AIMD rate limiter is the real gate)

	for _, g := range pendingGroups {
		wg.Add(1)
		go func(grp groupInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var directIDs, transIDs []string

			// Direct members
			directURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members?$select=id", grp.ID)
			_ = GraphAPIPagedRequest(ctx, directURL, token, func(body []byte) (bool, string, error) {
				var data struct {
					Value    []struct{ ID string `json:"id"` } `json:"value"`
					NextLink string                            `json:"@odata.nextLink"`
				}
				if err := json.Unmarshal(body, &data); err != nil {
					return false, "", err
				}
				for _, m := range data.Value {
					directIDs = append(directIDs, m.ID)
				}
				return data.NextLink != "", data.NextLink, nil
			})

			// Transitive members
			transURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/transitiveMembers?$select=id", grp.ID)
			_ = GraphAPIPagedRequest(ctx, transURL, token, func(body []byte) (bool, string, error) {
				var data struct {
					Value    []struct{ ID string `json:"id"` } `json:"value"`
					NextLink string                            `json:"@odata.nextLink"`
				}
				if err := json.Unmarshal(body, &data); err != nil {
					return false, "", err
				}
				for _, m := range data.Value {
					transIDs = append(transIDs, m.ID)
				}
				return data.NextLink != "", data.NextLink, nil
			})

			resultsCh <- groupMemberResult{
				GroupID:         grp.ID,
				DirectMemberIDs: directIDs,
				TransMemberIDs:  transIDs,
			}
		}(g)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Build inverted index: principalID -> CachedGroupMembership
	// Track: for each principal, which groups they are direct members of vs transitive
	accumMap := make(map[string]*groupMembershipAccum)

	// Seed from partial cache
	if partialDisk.Data != nil {
		for pid, cached := range partialDisk.Data {
			a := &groupMembershipAccum{
				DirectGroupIDs: make(map[string]bool),
				AllGroupIDs:    make(map[string]bool),
			}
			for _, name := range cached.DirectGroupNames {
				// Reverse-lookup group ID from name (best-effort)
				for gid, gname := range groupNameMap {
					if gname == name {
						a.DirectGroupIDs[gid] = true
						break
					}
				}
			}
			for _, gid := range cached.AllGroupIDs {
				a.AllGroupIDs[gid] = true
			}
			accumMap[pid] = a
		}
	}

	getOrCreate := func(pid string) *groupMembershipAccum {
		if a, ok := accumMap[pid]; ok {
			return a
		}
		a := &groupMembershipAccum{
			DirectGroupIDs: make(map[string]bool),
			AllGroupIDs:    make(map[string]bool),
		}
		accumMap[pid] = a
		return a
	}

	// Collect results and save incrementally every 200 groups
	groupsProcessed := len(processedGroupSet)
	for r := range resultsCh {
		for _, memberID := range r.DirectMemberIDs {
			a := getOrCreate(memberID)
			a.DirectGroupIDs[r.GroupID] = true
			a.AllGroupIDs[r.GroupID] = true
		}
		for _, memberID := range r.TransMemberIDs {
			a := getOrCreate(memberID)
			a.AllGroupIDs[r.GroupID] = true
		}
		processedGroupSet[r.GroupID] = true
		groupsProcessed++

		// Incremental save every 200 groups
		if groupsProcessed%200 == 0 {
			partialData := buildGroupMembershipCache(accumMap, groupNameMap)
			processedIDs := make([]string, 0, len(processedGroupSet))
			for gid := range processedGroupSet {
				processedIDs = append(processedIDs, gid)
			}
			savePrefetchCache(baseDir, tenantID, "group-memberships-partial.gob", partialCacheOnDisk{
				ProcessedGroupIDs: processedIDs,
				Data:              partialData,
			})
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Group membership progress: %d/%d groups processed", groupsProcessed, len(allGroups)), globals.AZ_PRINCIPALS_MODULE_NAME)
			}
		}
	}

	// Convert to final cache structure
	cacheData := buildGroupMembershipCache(accumMap, groupNameMap)

	AzureDataCache.Set(cacheKey, cacheData, 0)
	AzureDataCache.Set(AzCacheKey("group-names-all", "tenant"), groupNameMap, 0)
	savePrefetchCache(baseDir, tenantID, "group-memberships.gob", GroupMembershipsCache{Data: cacheData})

	// Clean up partial cache now that full cache is saved
	deletePrefetchCache(baseDir, tenantID, "group-memberships-partial.gob")

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched group memberships: %d groups, %d principals with memberships", len(allGroups), len(cacheData)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
}

// groupMembershipAccum tracks group membership accumulation for a single principal.
type groupMembershipAccum struct {
	DirectGroupIDs map[string]bool
	AllGroupIDs    map[string]bool
}

// buildGroupMembershipCache converts the accumulator map to the final cache structure.
func buildGroupMembershipCache(accumMap map[string]*groupMembershipAccum, groupNameMap map[string]string) map[string]CachedGroupMembership {
	cacheData := make(map[string]CachedGroupMembership, len(accumMap))
	for pid, a := range accumMap {
		var directNames, allNames, allIDs []string
		for gid := range a.DirectGroupIDs {
			directNames = append(directNames, groupNameMap[gid])
		}
		for gid := range a.AllGroupIDs {
			allNames = append(allNames, groupNameMap[gid])
			allIDs = append(allIDs, gid)
		}
		cacheData[pid] = CachedGroupMembership{
			DirectGroupNames: directNames,
			AllGroupNames:    allNames,
			AllGroupIDs:      allIDs,
		}
	}
	return cacheData
}

// GetGroupDisplayName returns a group's display name from the bulk group names cache.
// Returns (name, true) on cache hit, ("", false) if the bulk cache is not populated.
func GetGroupDisplayName(groupID string) (string, bool) {
	if cached, found := AzureDataCache.Get(AzCacheKey("group-names-all", "tenant")); found {
		nameMap := cached.(map[string]string)
		name, ok := nameMap[groupID]
		return name, ok
	}
	return "", false
}

// PreFetchDirectoryRoleMembers fetches ALL activated directory roles and their members,
// building an inverted index: principalID -> []DirectoryRole for O(1) lookup.
func PreFetchDirectoryRoleMembers(ctx context.Context, session *SafeSession, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	cacheKey := AzCacheKey("directory-role-members-all", "tenant")

	// 1. Check in-memory cache
	if _, found := AzureDataCache.Get(cacheKey); found {
		return
	}

	// 2. Check disk cache
	var diskCache DirectoryRoleMembersCache
	if loadPrefetchCache(baseDir, tenantID, "directory-role-members.gob", DefaultAzureCacheExpiration, &diskCache) {
		AzureDataCache.Set(cacheKey, diskCache.Data, 0)
		return
	}

	// 3. Fetch from API
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for directory roles pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	// List all activated directory roles
	type roleInfo struct {
		ID             string
		DisplayName    string
		Description    string
		RoleTemplateID string
	}
	var roles []roleInfo

	rolesURL := "https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName,description,roleTemplateId"
	err = GraphAPIPagedRequest(ctx, rolesURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID             string `json:"id"`
				DisplayName    string `json:"displayName"`
				Description    string `json:"description"`
				RoleTemplateID string `json:"roleTemplateId"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", err
		}
		for _, r := range data.Value {
			roles = append(roles, roleInfo{
				ID:             r.ID,
				DisplayName:    r.DisplayName,
				Description:    r.Description,
				RoleTemplateID: r.RoleTemplateID,
			})
		}
		return data.NextLink != "", data.NextLink, nil
	})
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to list directory roles: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	// For each role, fetch members
	invertedMap := make(map[string][]DirectoryRole) // principalID -> roles

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10)

	for _, role := range roles {
		wg.Add(1)
		go func(r roleInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			membersURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryRoles/%s/members?$select=id", r.ID)
			_ = GraphAPIPagedRequest(ctx, membersURL, token, func(body []byte) (bool, string, error) {
				var data struct {
					Value    []struct{ ID string `json:"id"` } `json:"value"`
					NextLink string                            `json:"@odata.nextLink"`
				}
				if err := json.Unmarshal(body, &data); err != nil {
					return false, "", err
				}

				mu.Lock()
				for _, m := range data.Value {
					invertedMap[m.ID] = append(invertedMap[m.ID], DirectoryRole{
						RoleID:         r.ID,
						RoleTemplateID: r.RoleTemplateID,
						DisplayName:    r.DisplayName,
						Description:    r.Description,
						AssignedVia:    "Direct",
						PIMStatus:      "",
					})
				}
				mu.Unlock()

				return data.NextLink != "", data.NextLink, nil
			})
		}(role)
	}
	wg.Wait()

	AzureDataCache.Set(cacheKey, invertedMap, 0)
	savePrefetchCache(baseDir, tenantID, "directory-role-members.gob", DirectoryRoleMembersCache{Data: invertedMap})

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		totalMembers := 0
		for _, v := range invertedMap {
			totalMembers += len(v)
		}
		logger.InfoM(fmt.Sprintf("Pre-fetched directory role members: %d roles, %d total assignments", len(roles), totalMembers), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
}

// PreFetchSignInActivity fetches sign-in activity for ALL users in one paged request.
// Requires AuditLog.Read.All permission; logs a warning and skips on 403.
func PreFetchSignInActivity(ctx context.Context, session *SafeSession, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	cacheKey := AzCacheKey("sign-in-activity-all", "tenant")

	// 1. Check in-memory cache
	if _, found := AzureDataCache.Get(cacheKey); found {
		return
	}

	// 2. Check disk cache
	var diskCache SignInActivityCache
	if loadPrefetchCache(baseDir, tenantID, "sign-in-activity.gob", DefaultAzureCacheExpiration, &diskCache) {
		AzureDataCache.Set(cacheKey, diskCache.Data, 0)
		return
	}

	// 3. Fetch from API
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for sign-in activity pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	activityMap := make(map[string]SignInActivity)
	initialURL := "https://graph.microsoft.com/v1.0/users?$select=id,signInActivity"

	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID            string `json:"id"`
				SignInActivity struct {
					LastSignInDateTime               string `json:"lastSignInDateTime"`
					LastNonInteractiveSignInDateTime string `json:"lastNonInteractiveSignInDateTime"`
					LastSuccessfulSignInDateTime     string `json:"lastSuccessfulSignInDateTime"`
				} `json:"signInActivity"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", err
		}

		for _, u := range data.Value {
			activity := SignInActivity{
				LastSignInDateTime:               "Never",
				LastNonInteractiveSignInDateTime: "Never",
				LastSuccessfulSignInDateTime:     "Never",
				DaysSinceLastSignIn:              -1,
			}

			if u.SignInActivity.LastSignInDateTime != "" {
				activity.LastSignInDateTime = u.SignInActivity.LastSignInDateTime
				if t, err := time.Parse(time.RFC3339, u.SignInActivity.LastSignInDateTime); err == nil {
					daysSince := int(time.Since(t).Hours() / 24)
					activity.DaysSinceLastSignIn = daysSince
					if daysSince > 90 {
						activity.IsStale = true
						activity.StaleReason = fmt.Sprintf("Last sign-in %d days ago", daysSince)
					}
				}
			} else {
				activity.IsStale = true
				activity.StaleReason = "Never signed in"
			}

			if u.SignInActivity.LastNonInteractiveSignInDateTime != "" {
				activity.LastNonInteractiveSignInDateTime = u.SignInActivity.LastNonInteractiveSignInDateTime
			}
			if u.SignInActivity.LastSuccessfulSignInDateTime != "" {
				activity.LastSuccessfulSignInDateTime = u.SignInActivity.LastSuccessfulSignInDateTime
			}

			activityMap[u.ID] = activity
		}

		return data.NextLink != "", data.NextLink, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Sign-in activity pre-fetch failed (requires AuditLog.Read.All): %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		// Still cache empty map so we don't retry and fall through to per-principal
		if len(activityMap) == 0 {
			return
		}
	}

	AzureDataCache.Set(cacheKey, activityMap, 0)
	savePrefetchCache(baseDir, tenantID, "sign-in-activity.gob", SignInActivityCache{Data: activityMap})

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched sign-in activity for %d users", len(activityMap)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
}

// PreFetchOAuth2Grants fetches ALL OAuth2 permission grants in the tenant with one paged
// request, resolves resource display names, and builds a map: clientID -> []CachedOAuth2Grant.
func PreFetchOAuth2Grants(ctx context.Context, session *SafeSession, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	cacheKey := AzCacheKey("oauth2-grants-all", "tenant")

	// 1. Check in-memory cache
	if _, found := AzureDataCache.Get(cacheKey); found {
		return
	}

	// 2. Check disk cache
	var diskCache OAuth2GrantsCache
	if loadPrefetchCache(baseDir, tenantID, "oauth2-grants.gob", DefaultAzureCacheExpiration, &diskCache) {
		AzureDataCache.Set(cacheKey, diskCache.Data, 0)
		return
	}

	// 3. Fetch from API
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for OAuth2 grants pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	// Collect all grants and unique resourceIds
	type rawGrant struct {
		ClientID    string
		ConsentType string
		ResourceID  string
		Scopes      []string
	}
	var allGrants []rawGrant
	resourceIDs := make(map[string]bool)

	initialURL := "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
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
			return false, "", err
		}
		for _, g := range data.Value {
			if g.ClientID == nil || g.Scope == nil {
				continue
			}
			consentType := "Unknown"
			if g.ConsentType != nil {
				consentType = *g.ConsentType
			}
			var scopes []string
			for _, s := range strings.Split(*g.Scope, " ") {
				if s != "" {
					scopes = append(scopes, s)
				}
			}
			resourceID := ""
			if g.ResourceID != nil {
				resourceID = *g.ResourceID
				resourceIDs[resourceID] = true
			}
			allGrants = append(allGrants, rawGrant{
				ClientID:    *g.ClientID,
				ConsentType: consentType,
				ResourceID:  resourceID,
				Scopes:      scopes,
			})
		}
		return data.NextLink != "", data.NextLink, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to pre-fetch OAuth2 grants: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		if len(allGrants) == 0 {
			return
		}
	}

	// Resolve resource IDs to display names (batch with concurrency)
	resourceNameMap := make(map[string]string)
	var rnWg sync.WaitGroup
	var rnMu sync.Mutex
	rnSem := make(chan struct{}, 10)

	for rid := range resourceIDs {
		rnWg.Add(1)
		go func(resourceID string) {
			defer rnWg.Done()
			rnSem <- struct{}{}
			defer func() { <-rnSem }()

			spURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=displayName", resourceID)
			spBody, err := GraphAPIRequestWithRetry(ctx, "GET", spURL, token)
			if err == nil {
				var spData struct {
					DisplayName string `json:"displayName"`
				}
				if json.Unmarshal(spBody, &spData) == nil && spData.DisplayName != "" {
					rnMu.Lock()
					resourceNameMap[resourceID] = spData.DisplayName
					rnMu.Unlock()
				}
			}
		}(rid)
	}
	rnWg.Wait()

	// Build clientID -> []CachedOAuth2Grant map
	grantsMap := make(map[string][]CachedOAuth2Grant)
	for _, g := range allGrants {
		resourceName := resourceNameMap[g.ResourceID]
		if resourceName == "" {
			resourceName = "Unknown Resource"
		}
		grantsMap[g.ClientID] = append(grantsMap[g.ClientID], CachedOAuth2Grant{
			ClientID:     g.ClientID,
			ConsentType:  g.ConsentType,
			ResourceName: resourceName,
			Scopes:       g.Scopes,
		})
	}

	AzureDataCache.Set(cacheKey, grantsMap, 0)
	savePrefetchCache(baseDir, tenantID, "oauth2-grants.gob", OAuth2GrantsCache{Data: grantsMap})

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched %d OAuth2 grants for %d service principals (%d unique resources)", len(allGrants), len(grantsMap), len(resourceIDs)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
}

// PreFetchSPAppRoleAssignments pre-fetches all service principal appRoleAssignments
// at the tenant level using $expand=appRoleAssignments on the servicePrincipals endpoint.
// This replaces N per-SP API calls with a single paged tenant-level fetch.
func PreFetchSPAppRoleAssignments(ctx context.Context, session *SafeSession, baseDir, tenantID string) {
	SetBulkCacheContext(baseDir, tenantID)
	cacheKey := AzCacheKey("sp-approle-assignments-all", "tenant")

	// 1. Check in-memory cache
	if _, found := AzureDataCache.Get(cacheKey); found {
		return
	}

	// 2. Check disk cache
	var diskCache SPAppRoleAssignmentsCache
	if loadPrefetchCache(baseDir, tenantID, "sp-approle-assignments.gob", DefaultAzureCacheExpiration, &diskCache) {
		AzureDataCache.Set(cacheKey, diskCache.Data, 0)
		return
	}

	// 3. Fetch from API
	logger := internal.NewLogger()
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Graph scope
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Graph token for SP appRoleAssignments pre-fetch: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		return
	}

	// Collect raw assignments and unique resource IDs for appRole name resolution
	type rawAssignment struct {
		SPID                string
		ResourceID          string
		ResourceDisplayName string
		AppRoleID           string
	}
	var allAssignments []rawAssignment
	resourceIDs := make(map[string]string) // resourceID -> displayName (from expand)

	initialURL := "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id&$expand=appRoleAssignments"
	err = GraphAPIPagedRequest(ctx, initialURL, token, func(body []byte) (bool, string, error) {
		var data struct {
			Value []struct {
				ID                 string `json:"id"`
				AppRoleAssignments []struct {
					ResourceDisplayName string  `json:"resourceDisplayName"`
					ResourceId          string  `json:"resourceId"`
					AppRoleId           *string `json:"appRoleId"`
				} `json:"appRoleAssignments"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return false, "", err
		}
		for _, sp := range data.Value {
			for _, a := range sp.AppRoleAssignments {
				if a.AppRoleId == nil || a.ResourceId == "" {
					continue
				}
				allAssignments = append(allAssignments, rawAssignment{
					SPID:                sp.ID,
					ResourceID:          a.ResourceId,
					ResourceDisplayName: a.ResourceDisplayName,
					AppRoleID:           *a.AppRoleId,
				})
				if _, seen := resourceIDs[a.ResourceId]; !seen {
					resourceIDs[a.ResourceId] = a.ResourceDisplayName
				}
			}
		}
		return data.NextLink != "", data.NextLink, nil
	})

	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to pre-fetch SP appRoleAssignments: %v", err), globals.AZ_PRINCIPALS_MODULE_NAME)
		}
		if len(allAssignments) == 0 {
			return
		}
	}

	// Resolve appRole names for all unique resources (concurrent, semaphore 10)
	// This populates the per-resource appRoles cache used by resolveAppRoleName
	var arWg sync.WaitGroup
	arSem := make(chan struct{}, 10)

	for rid, displayName := range resourceIDs {
		arWg.Add(1)
		go func(resourceID, resourceDisplayName string) {
			defer arWg.Done()
			arSem <- struct{}{}
			defer func() { <-arSem }()
			// resolveAppRoleName populates the per-resource appRoles cache on first call.
			// Use a dummy appRoleID; we just need the cache to be warm.
			resolveAppRoleName(ctx, token, resourceID, resourceDisplayName, "00000000-0000-0000-0000-000000000000", logger)
		}(rid, displayName)
	}
	arWg.Wait()

	// Build spObjectID -> []CachedSPAppRoleAssignment using the now-warm appRoles cache
	assignmentsMap := make(map[string][]CachedSPAppRoleAssignment)
	for _, a := range allAssignments {
		roleName := resolveAppRoleName(ctx, token, a.ResourceID, a.ResourceDisplayName, a.AppRoleID, logger)
		assignmentsMap[a.SPID] = append(assignmentsMap[a.SPID], CachedSPAppRoleAssignment{
			ResourceDisplayName: a.ResourceDisplayName,
			AppRoleName:         roleName,
		})
	}

	AzureDataCache.Set(cacheKey, assignmentsMap, 0)
	savePrefetchCache(baseDir, tenantID, "sp-approle-assignments.gob", SPAppRoleAssignmentsCache{Data: assignmentsMap})

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Pre-fetched %d appRoleAssignments for %d service principals (%d unique resources)", len(allAssignments), len(assignmentsMap), len(resourceIDs)), globals.AZ_PRINCIPALS_MODULE_NAME)
	}
}

// PreFetchTenantGraphData runs all tenant-level bulk pre-fetches in parallel.
// This is idempotent: each sub-function checks in-memory cache first, so calling
// this multiple times (e.g., from both principals and permissions modules) is free.
// Modules should call this before any per-principal enrichment that uses
// GetUserGroupMemberships, GetNestedGroupMemberships, GetDirectoryRolesForPrincipal,
// GetUserSignInActivity, or GetDelegatedOAuth2Grants.
func PreFetchTenantGraphData(ctx context.Context, session *SafeSession, baseDir, tenantID string) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		PreFetchGroupMemberships(ctx, session, baseDir, tenantID)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		PreFetchDirectoryRoleMembers(ctx, session, baseDir, tenantID)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		PreFetchSignInActivity(ctx, session, baseDir, tenantID)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		PreFetchOAuth2Grants(ctx, session, baseDir, tenantID)
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// BuildPermissionIndex: assignment-first bulk architecture for permissions module
// ---------------------------------------------------------------------------

// PermAssignment is a flattened, cache-derived role assignment (RBAC or PIM).
type PermAssignment struct {
	RoleDefinitionID string
	RoleName         string
	Scope            string
	SubID            string
	SubName          string
	PrincipalID      string // The actual assignee (could be principal or group)
	Condition        string
	Source           string // "RBAC", "PIM-Eligible", "PIM-Active"
}

// BuildPermissionIndex iterates the pre-fetched RBAC and PIM caches for the given
// subscriptions and returns a principalID -> []PermAssignment index with zero API calls.
// The caller controls which scope levels to include via tenantLevel, subLevel, rgLevel.
func BuildPermissionIndex(
	ctx context.Context,
	session *SafeSession,
	subscriptions []string,
	tenantLevel, subLevel, rgLevel bool,
) map[string][]PermAssignment {
	index := make(map[string][]PermAssignment)

	for _, subID := range subscriptions {
		subName := GetSubscriptionNameFromID(ctx, session, subID)

		// --- RBAC: iterate scope caches ---
		var scopes []string

		if tenantLevel {
			scopes = append(scopes, "/")
		}

		// Management group hierarchy (already cached by PreFetchRBACAssignmentsForSubscription)
		mgKey := AzCacheKey("mg-hierarchy", subID)
		if cached, found := AzureDataCache.Get(mgKey); found {
			for _, mgID := range cached.([]string) {
				scopes = append(scopes, fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", mgID))
			}
		}

		if subLevel {
			scopes = append(scopes, fmt.Sprintf("/subscriptions/%s", subID))
		}

		if rgLevel {
			// Discover RG scopes from cache: iterate AzureDataCache items matching this subscription
			prefix := AzCacheKey("rbac-scope-all", fmt.Sprintf("/subscriptions/%s/resourceGroups/", subID))
			for key := range AzureDataCache.Items() {
				if strings.HasPrefix(key, prefix) {
					// Extract the scope path from the cache key: "az-rbac-scope-all-<scopePath>"
					scopePath := strings.TrimPrefix(key, "az-rbac-scope-all-")
					scopes = append(scopes, scopePath)
				}
			}
		}

		for _, scope := range scopes {
			entries := ListAllRBACForScope(scope)
			for _, e := range entries {
				index[e.PrincipalID] = append(index[e.PrincipalID], PermAssignment{
					RoleDefinitionID: e.RoleDefinitionID,
					RoleName:         e.RoleName,
					Scope:            e.Scope,
					SubID:            subID,
					SubName:          subName,
					PrincipalID:      e.PrincipalID,
					Condition:        e.Condition,
					Source:           "RBAC",
				})
			}
		}

		// --- PIM: iterate subscription PIM caches ---
		eligible, active, _ := ListAllPIMForSubscription(subID)
		for _, pa := range eligible {
			index[pa.PrincipalID] = append(index[pa.PrincipalID], PermAssignment{
				RoleDefinitionID: pa.RoleDefinitionID,
				RoleName:         pa.RoleName,
				Scope:            pa.Scope,
				SubID:            subID,
				SubName:          subName,
				PrincipalID:      pa.PrincipalID,
				Source:           "PIM-Eligible",
			})
		}
		for _, pa := range active {
			index[pa.PrincipalID] = append(index[pa.PrincipalID], PermAssignment{
				RoleDefinitionID: pa.RoleDefinitionID,
				RoleName:         pa.RoleName,
				Scope:            pa.Scope,
				SubID:            subID,
				SubName:          subName,
				PrincipalID:      pa.PrincipalID,
				Source:           "PIM-Active",
			})
		}
	}

	return index
}
