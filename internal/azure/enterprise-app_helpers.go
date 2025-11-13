package azure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// -------------------- Auth Provider Wrapper --------------------

// GraphAuthProvider wraps an azcore.TokenCredential for MS Graph
//type GraphAuthProvider struct {
//	cred azcore.TokenCredential
//}
//
//// GraphSession caches the Azure credential and Graph API token with automatic refresh
//type GraphSession struct {
//	cred       azcore.TokenCredential
//	token      string
//	expiry     time.Time
//	mu         sync.Mutex
//	httpClient *http.Client
//}
//
//func (g *GraphAuthProvider) GetAuthorizationToken(ctx context.Context, request *http.Request) (string, error) {
//	token, err := g.cred.GetToken(ctx, policy.TokenRequestOptions{
//		Scopes: []string{"https://graph.microsoft.com/.default"},
//	})
//	if err != nil {
//		return "", err
//	}
//	return token.Token, nil
//}
//
//// NewGraphSession initializes the credential and fetches an initial Graph token
//func NewGraphSession(ctx context.Context) (*GraphSession, error) {
//	cred, err := azidentity.NewDefaultAzureCredential(nil)
//	if err != nil {
//		return nil, fmt.Errorf("failed to initialize credential: %w", err)
//	}
//
//	session := &GraphSession{
//		cred:       cred,
//		httpClient: &http.Client{},
//	}
//
//	// Fetch the initial token
//	if err := session.refreshToken(ctx); err != nil {
//		return nil, fmt.Errorf("failed to obtain initial token: %w", err)
//	}
//
//	return session, nil
//}
//
//// refreshToken retrieves a new token and updates expiry
//func (s *GraphSession) refreshToken(ctx context.Context) error {
//	s.mu.Lock()
//	defer s.mu.Unlock()
//
//	token, err := s.cred.GetToken(ctx, policy.TokenRequestOptions{
//		Scopes: []string{"https://graph.microsoft.com/.default"},
//	})
//	if err != nil {
//		return fmt.Errorf("failed to refresh Graph token: %w", err)
//	}
//
//	s.token = token.Token
//	s.expiry = token.ExpiresOn
//
//	return nil
//}
//
//// ensureValidToken checks if token is close to expiry and refreshes it if needed
//func (s *GraphSession) ensureValidToken(ctx context.Context) error {
//	s.mu.Lock()
//	needsRefresh := time.Until(s.expiry) < 2*time.Minute // refresh if less than 2 mins left
//	s.mu.Unlock()
//
//	if needsRefresh {
//		return s.refreshToken(ctx)
//	}
//	return nil
//}
//
//// Get performs a GET request with an automatically refreshed token
//func (s *GraphSession) Get(ctx context.Context, url string) ([]byte, error) {
//	// Ensure token is valid before request
//	if err := s.ensureValidToken(ctx); err != nil {
//		return nil, err
//	}
//
//	s.mu.Lock()
//	token := s.token
//	s.mu.Unlock()
//
//	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
//	if err != nil {
//		return nil, fmt.Errorf("failed to create request: %w", err)
//	}
//
//	req.Header.Set("Authorization", "Bearer "+token)
//	req.Header.Set("Accept", "application/json")
//
//	resp, err := s.httpClient.Do(req)
//	if err != nil {
//		return nil, fmt.Errorf("failed to call Graph API: %w", err)
//	}
//	defer resp.Body.Close()
//
//	body, _ := ioutil.ReadAll(resp.Body)
//	if resp.StatusCode >= 400 {
//		return nil, fmt.Errorf("Graph API error (%d): %s", resp.StatusCode, string(body))
//	}
//
//	return body, nil
//}

// -------------------- Enterprise Applications --------------------

type Application struct {
	DisplayName string
	ObjectID    string
	AppID       string
}

// GetEnterpriseAppsPerResourceGroup enumerates all enterprise applications in a subscription/rg
func GetEnterpriseAppsPerResourceGroup(ctx context.Context, session *SafeSession, subscriptionID, resourceGroup string) []Application {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Getting Enterprise Apps Per Resource Group %s", resourceGroup), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
	}

	apps := []Application{}

	// ------------------- Get Graph Token -------------------
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get Graph token: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		return apps
	}

	// ------------------- Make Graph API Call with Retry Logic -------------------
	// Use servicePrincipals endpoint for Enterprise Applications, not applications
	url := "https://graph.microsoft.com/v1.0/servicePrincipals?$top=999"
	body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Graph API request failed: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		return apps
	}

	if len(body) == 0 {
		return apps
	}

	// ------------------- Parse Response -------------------
	var result struct {
		Value []struct {
			DisplayName *string `json:"displayName"`
			Id          *string `json:"id"`
			AppId       *string `json:"appId"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to parse Graph response: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		return apps
	}

	for _, appRaw := range result.Value {
		apps = append(apps, Application{
			DisplayName: SafeStringPtr(appRaw.DisplayName),
			ObjectID:    SafeStringPtr(appRaw.Id),
			AppID:       SafeStringPtr(appRaw.AppId),
		})
	}

	return apps
}

// -------------------- Service Principals --------------------

// GetServicePrincipalsForApp returns user-managed and system-managed SPs for a given app objectID
func GetServicePrincipalsForApp(ctx context.Context, session *SafeSession, appObjectID string) (userSPs []*ServicePrincipal, systemSPs []*ServicePrincipal) {
	logger := internal.NewLogger()
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Getting service principals for app %s", appObjectID), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
	}

	userSPs = []*ServicePrincipal{}
	systemSPs = []*ServicePrincipal{}

	// ------------------- Get Graph Token -------------------
	token, err := session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph scope
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get Graph token: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		return userSPs, systemSPs
	}

	// ------------------- Make Graph API Call with Retry Logic -------------------
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '%s'&$top=999", appObjectID)
	body, err := GraphAPIRequestWithRetry(ctx, "GET", url, token)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Graph API request failed: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		return userSPs, systemSPs
	}

	if len(body) == 0 {
		return userSPs, systemSPs
	}

	// ------------------- Parse Response -------------------
	var result struct {
		Value []struct {
			DisplayName *string  `json:"displayName"`
			Id          *string  `json:"id"`
			AppId       *string  `json:"appId"`
			Tags        []string `json:"tags"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to parse Graph response: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		return userSPs, systemSPs
	}

	// ------------------- Build Service Principal Lists -------------------
	for _, spRaw := range result.Value {
		if spRaw.AppId == nil || *spRaw.AppId != appObjectID {
			continue
		}

		sp := &ServicePrincipal{
			DisplayName: spRaw.DisplayName,
			AppId:       spRaw.AppId,
			ObjectId:    spRaw.Id,
			Permissions: GetSPPermissions(ctx, session, SafeStringPtr(spRaw.Id)),
		}

		if contains(spRaw.Tags, "WindowsAzureActiveDirectoryIntegratedApp") {
			systemSPs = append(systemSPs, sp)
		} else {
			userSPs = append(userSPs, sp)
		}
	}

	return userSPs, systemSPs
}
