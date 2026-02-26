// Package graphservice provides Microsoft Graph API service abstractions
//
// This service layer abstracts Microsoft Graph API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package graphservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for graph service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "graphservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// GraphService provides methods for interacting with Microsoft Graph API
type GraphService struct {
	session *azinternal.SafeSession
}

// New creates a new GraphService instance
func New(session *azinternal.SafeSession) *GraphService {
	return &GraphService{
		session: session,
	}
}

// NewWithSession creates a new GraphService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *GraphService {
	return New(session)
}

// UserInfo represents an Entra ID user
type UserInfo struct {
	ID                string
	DisplayName       string
	UserPrincipalName string
	Mail              string
	JobTitle          string
	Department        string
	AccountEnabled    bool
	UserType          string
}

// GroupInfo represents an Entra ID group
type GroupInfo struct {
	ID              string
	DisplayName     string
	Description     string
	SecurityEnabled bool
	MailEnabled     bool
	GroupTypes      []string
}

// ServicePrincipalInfo represents an Entra ID service principal
type ServicePrincipalInfo struct {
	ID                     string
	AppID                  string
	DisplayName            string
	ServicePrincipalType   string
	AccountEnabled         bool
	AppOwnerOrganizationID string
}

// ApplicationInfo represents an Entra ID application registration
type ApplicationInfo struct {
	ID              string
	AppID           string
	DisplayName     string
	SignInAudience  string
	PublisherDomain string
}

// ConsentGrantInfo represents an OAuth2 permission grant
type ConsentGrantInfo struct {
	ID          string
	ClientID    string
	ConsentType string
	PrincipalID string
	ResourceID  string
	Scope       string
}

// GraphResponse represents a generic Graph API response with pagination
type GraphResponse struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"@odata.nextLink"`
}

// getGraphToken returns a token for Microsoft Graph API
func (s *GraphService) getGraphToken() (string, error) {
	token, err := s.session.GetTokenForResource("https://graph.microsoft.com/")
	if err != nil {
		return "", fmt.Errorf("failed to get Graph token: %w", err)
	}
	return token, nil
}

// makeGraphRequest makes a request to the Graph API
func (s *GraphService) makeGraphRequest(ctx context.Context, url string) ([]byte, error) {
	token, err := s.getGraphToken()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Graph API error (status %d): %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ListUsers returns all users in the tenant
func (s *GraphService) ListUsers(ctx context.Context) ([]UserInfo, error) {
	url := "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,userType"
	var allUsers []UserInfo

	for url != "" {
		body, err := s.makeGraphRequest(ctx, url)
		if err != nil {
			return allUsers, err
		}

		var response GraphResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return allUsers, fmt.Errorf("failed to parse response: %w", err)
		}

		var users []UserInfo
		if err := json.Unmarshal(response.Value, &users); err != nil {
			return allUsers, fmt.Errorf("failed to parse users: %w", err)
		}

		allUsers = append(allUsers, users...)
		url = response.NextLink
	}

	return allUsers, nil
}

// GetUser returns a specific user by ID or UPN
func (s *GraphService) GetUser(ctx context.Context, userIDOrUPN string) (*UserInfo, error) {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s?$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,userType", userIDOrUPN)

	body, err := s.makeGraphRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var user UserInfo
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user: %w", err)
	}

	return &user, nil
}

// ListGroups returns all groups in the tenant
func (s *GraphService) ListGroups(ctx context.Context) ([]GroupInfo, error) {
	url := "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description,securityEnabled,mailEnabled,groupTypes"
	var allGroups []GroupInfo

	for url != "" {
		body, err := s.makeGraphRequest(ctx, url)
		if err != nil {
			return allGroups, err
		}

		var response GraphResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return allGroups, fmt.Errorf("failed to parse response: %w", err)
		}

		var groups []GroupInfo
		if err := json.Unmarshal(response.Value, &groups); err != nil {
			return allGroups, fmt.Errorf("failed to parse groups: %w", err)
		}

		allGroups = append(allGroups, groups...)
		url = response.NextLink
	}

	return allGroups, nil
}

// ListGroupMembers returns all members of a group
func (s *GraphService) ListGroupMembers(ctx context.Context, groupID string) ([]UserInfo, error) {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members?$select=id,displayName,userPrincipalName,mail", groupID)
	var allMembers []UserInfo

	for url != "" {
		body, err := s.makeGraphRequest(ctx, url)
		if err != nil {
			return allMembers, err
		}

		var response GraphResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return allMembers, fmt.Errorf("failed to parse response: %w", err)
		}

		var members []UserInfo
		if err := json.Unmarshal(response.Value, &members); err != nil {
			return allMembers, fmt.Errorf("failed to parse members: %w", err)
		}

		allMembers = append(allMembers, members...)
		url = response.NextLink
	}

	return allMembers, nil
}

// ListServicePrincipals returns all service principals in the tenant
func (s *GraphService) ListServicePrincipals(ctx context.Context) ([]ServicePrincipalInfo, error) {
	url := "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId"
	var allSPs []ServicePrincipalInfo

	for url != "" {
		body, err := s.makeGraphRequest(ctx, url)
		if err != nil {
			return allSPs, err
		}

		var response GraphResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return allSPs, fmt.Errorf("failed to parse response: %w", err)
		}

		var sps []ServicePrincipalInfo
		if err := json.Unmarshal(response.Value, &sps); err != nil {
			return allSPs, fmt.Errorf("failed to parse service principals: %w", err)
		}

		allSPs = append(allSPs, sps...)
		url = response.NextLink
	}

	return allSPs, nil
}

// ListApplications returns all application registrations in the tenant
func (s *GraphService) ListApplications(ctx context.Context) ([]ApplicationInfo, error) {
	url := "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,signInAudience,publisherDomain"
	var allApps []ApplicationInfo

	for url != "" {
		body, err := s.makeGraphRequest(ctx, url)
		if err != nil {
			return allApps, err
		}

		var response GraphResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return allApps, fmt.Errorf("failed to parse response: %w", err)
		}

		var apps []ApplicationInfo
		if err := json.Unmarshal(response.Value, &apps); err != nil {
			return allApps, fmt.Errorf("failed to parse applications: %w", err)
		}

		allApps = append(allApps, apps...)
		url = response.NextLink
	}

	return allApps, nil
}

// ListOAuth2PermissionGrants returns all OAuth2 permission grants in the tenant
func (s *GraphService) ListOAuth2PermissionGrants(ctx context.Context) ([]ConsentGrantInfo, error) {
	url := "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
	var allGrants []ConsentGrantInfo

	for url != "" {
		body, err := s.makeGraphRequest(ctx, url)
		if err != nil {
			return allGrants, err
		}

		var response GraphResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return allGrants, fmt.Errorf("failed to parse response: %w", err)
		}

		var grants []ConsentGrantInfo
		if err := json.Unmarshal(response.Value, &grants); err != nil {
			return allGrants, fmt.Errorf("failed to parse grants: %w", err)
		}

		allGrants = append(allGrants, grants...)
		url = response.NextLink
	}

	return allGrants, nil
}

// GetMe returns the current user's profile
func (s *GraphService) GetMe(ctx context.Context) (*UserInfo, error) {
	url := "https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,userType"

	body, err := s.makeGraphRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var user UserInfo
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user: %w", err)
	}

	return &user, nil
}

// ============================================================================
// CACHED METHODS - Use these in command modules for better performance
// ============================================================================

// CachedListUsers returns cached Entra ID users
func (s *GraphService) CachedListUsers(ctx context.Context) ([]UserInfo, error) {
	key := cacheKey("users")

	if cached, found := serviceCache.Get(key); found {
		return cached.([]UserInfo), nil
	}

	result, err := s.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListGroups returns cached Entra ID groups
func (s *GraphService) CachedListGroups(ctx context.Context) ([]GroupInfo, error) {
	key := cacheKey("groups")

	if cached, found := serviceCache.Get(key); found {
		return cached.([]GroupInfo), nil
	}

	result, err := s.ListGroups(ctx)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListServicePrincipals returns cached service principals
func (s *GraphService) CachedListServicePrincipals(ctx context.Context) ([]ServicePrincipalInfo, error) {
	key := cacheKey("serviceprincipals")

	if cached, found := serviceCache.Get(key); found {
		return cached.([]ServicePrincipalInfo), nil
	}

	result, err := s.ListServicePrincipals(ctx)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListApplications returns cached application registrations
func (s *GraphService) CachedListApplications(ctx context.Context) ([]ApplicationInfo, error) {
	key := cacheKey("applications")

	if cached, found := serviceCache.Get(key); found {
		return cached.([]ApplicationInfo), nil
	}

	result, err := s.ListApplications(ctx)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListOAuth2PermissionGrants returns cached OAuth2 permission grants
func (s *GraphService) CachedListOAuth2PermissionGrants(ctx context.Context) ([]ConsentGrantInfo, error) {
	key := cacheKey("oauth2grants")

	if cached, found := serviceCache.Get(key); found {
		return cached.([]ConsentGrantInfo), nil
	}

	result, err := s.ListOAuth2PermissionGrants(ctx)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
