// Package rbacservice provides Azure RBAC service abstractions
//
// This service layer abstracts Azure Authorization API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package rbacservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for RBAC service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "rbacservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// RBACService provides methods for interacting with Azure RBAC
type RBACService struct {
	session *azinternal.SafeSession
}

// New creates a new RBACService instance
func New(session *azinternal.SafeSession) *RBACService {
	return &RBACService{
		session: session,
	}
}

// NewWithSession creates a new RBACService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *RBACService {
	return New(session)
}

// RoleAssignmentInfo represents an Azure role assignment with security-relevant fields
type RoleAssignmentInfo struct {
	ID               string
	Name             string
	PrincipalID      string
	PrincipalType    string
	RoleDefinitionID string
	Scope            string
	Condition        string
	CreatedOn        string
	UpdatedOn        string
}

// RoleDefinitionInfo represents an Azure role definition
type RoleDefinitionInfo struct {
	ID          string
	Name        string
	DisplayName string
	Type        string
	Description string
	Permissions []PermissionInfo
	IsCustom    bool
}

// PermissionInfo represents permissions in a role definition
type PermissionInfo struct {
	Actions        []string
	NotActions     []string
	DataActions    []string
	NotDataActions []string
}

// getARMCredential returns ARM credential from session
func (s *RBACService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListRoleAssignments returns all role assignments at a scope
func (s *RBACService) ListRoleAssignments(ctx context.Context, scope string) ([]*armauthorization.RoleAssignment, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armauthorization.NewRoleAssignmentsClient("", cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	pager := client.NewListForScopePager(scope, nil)
	var assignments []*armauthorization.RoleAssignment

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return assignments, fmt.Errorf("failed to list role assignments: %w", err)
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments, nil
}

// ListRoleAssignmentsForSubscription returns all role assignments in a subscription
func (s *RBACService) ListRoleAssignmentsForSubscription(ctx context.Context, subID string) ([]*armauthorization.RoleAssignment, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armauthorization.NewRoleAssignmentsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	pager := client.NewListForSubscriptionPager(nil)
	var assignments []*armauthorization.RoleAssignment

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return assignments, fmt.Errorf("failed to list role assignments: %w", err)
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments, nil
}

// GetRoleAssignment returns a specific role assignment
func (s *RBACService) GetRoleAssignment(ctx context.Context, scope, roleAssignmentName string) (*armauthorization.RoleAssignment, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armauthorization.NewRoleAssignmentsClient("", cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	resp, err := client.Get(ctx, scope, roleAssignmentName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get role assignment: %w", err)
	}

	return &resp.RoleAssignment, nil
}

// ListRoleDefinitions returns all role definitions at a scope
func (s *RBACService) ListRoleDefinitions(ctx context.Context, scope string) ([]*armauthorization.RoleDefinition, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %w", err)
	}

	pager := client.NewListPager(scope, nil)
	var definitions []*armauthorization.RoleDefinition

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return definitions, fmt.Errorf("failed to list role definitions: %w", err)
		}
		definitions = append(definitions, page.Value...)
	}

	return definitions, nil
}

// GetRoleDefinition returns a specific role definition
func (s *RBACService) GetRoleDefinition(ctx context.Context, scope, roleDefinitionID string) (*armauthorization.RoleDefinition, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %w", err)
	}

	resp, err := client.Get(ctx, scope, roleDefinitionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get role definition: %w", err)
	}

	return &resp.RoleDefinition, nil
}

// ListEligibleRoleAssignments returns eligible PIM role assignments (if PIM is enabled)
func (s *RBACService) ListEligibleRoleAssignments(ctx context.Context, scope string) ([]*armauthorization.RoleEligibilityScheduleInstance, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armauthorization.NewRoleEligibilityScheduleInstancesClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create eligible role assignments client: %w", err)
	}

	pager := client.NewListForScopePager(scope, nil)
	var assignments []*armauthorization.RoleEligibilityScheduleInstance

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// PIM may not be enabled - return empty list without error
			return assignments, nil
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ============================================================================
// CACHED METHODS - Use these in command modules for better performance
// ============================================================================

// CachedListRoleAssignments returns cached role assignments at a scope
func (s *RBACService) CachedListRoleAssignments(ctx context.Context, scope string) ([]*armauthorization.RoleAssignment, error) {
	key := cacheKey("assignments", scope)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armauthorization.RoleAssignment), nil
	}

	result, err := s.ListRoleAssignments(ctx, scope)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListRoleAssignmentsForSubscription returns cached role assignments for a subscription
func (s *RBACService) CachedListRoleAssignmentsForSubscription(ctx context.Context, subID string) ([]*armauthorization.RoleAssignment, error) {
	key := cacheKey("assignments-sub", subID)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armauthorization.RoleAssignment), nil
	}

	result, err := s.ListRoleAssignmentsForSubscription(ctx, subID)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListRoleDefinitions returns cached role definitions at a scope
func (s *RBACService) CachedListRoleDefinitions(ctx context.Context, scope string) ([]*armauthorization.RoleDefinition, error) {
	key := cacheKey("definitions", scope)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armauthorization.RoleDefinition), nil
	}

	result, err := s.ListRoleDefinitions(ctx, scope)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListEligibleRoleAssignments returns cached eligible PIM role assignments
func (s *RBACService) CachedListEligibleRoleAssignments(ctx context.Context, scope string) ([]*armauthorization.RoleEligibilityScheduleInstance, error) {
	key := cacheKey("eligible", scope)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armauthorization.RoleEligibilityScheduleInstance), nil
	}

	result, err := s.ListEligibleRoleAssignments(ctx, scope)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
