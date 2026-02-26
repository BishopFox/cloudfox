// Package policyservice provides Azure Policy service abstractions
//
// This service layer abstracts Azure Policy API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package policyservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for policy service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "policyservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// PolicyService provides methods for interacting with Azure Policy
type PolicyService struct {
	session *azinternal.SafeSession
}

// New creates a new PolicyService instance
func New(session *azinternal.SafeSession) *PolicyService {
	return &PolicyService{
		session: session,
	}
}

// NewWithSession creates a new PolicyService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *PolicyService {
	return New(session)
}

// PolicyDefinitionInfo represents an Azure Policy definition
type PolicyDefinitionInfo struct {
	ID          string
	Name        string
	DisplayName string
	Description string
	PolicyType  string
	Mode        string
	Category    string
}

// PolicyAssignmentInfo represents a policy assignment
type PolicyAssignmentInfo struct {
	ID                   string
	Name                 string
	DisplayName          string
	Description          string
	Scope                string
	PolicyDefinitionID   string
	EnforcementMode      string
	NonComplianceMessage string
}

// PolicySetDefinitionInfo represents a policy initiative (set)
type PolicySetDefinitionInfo struct {
	ID          string
	Name        string
	DisplayName string
	Description string
	PolicyType  string
	Category    string
	PolicyCount int
}

// ComplianceStateInfo represents compliance state
type ComplianceStateInfo struct {
	PolicyAssignmentID string
	ResourceID         string
	ComplianceState    string
	Timestamp          string
}

// getARMCredential returns ARM credential from session
func (s *PolicyService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListPolicyDefinitions returns all policy definitions in a subscription
func (s *PolicyService) ListPolicyDefinitions(ctx context.Context, subID string) ([]*armpolicy.Definition, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewDefinitionsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy definitions client: %w", err)
	}

	pager := client.NewListPager(nil)
	var definitions []*armpolicy.Definition

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return definitions, fmt.Errorf("failed to list policy definitions: %w", err)
		}
		definitions = append(definitions, page.Value...)
	}

	return definitions, nil
}

// ListBuiltInPolicyDefinitions returns all built-in policy definitions
func (s *PolicyService) ListBuiltInPolicyDefinitions(ctx context.Context, subID string) ([]*armpolicy.Definition, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewDefinitionsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy definitions client: %w", err)
	}

	pager := client.NewListBuiltInPager(nil)
	var definitions []*armpolicy.Definition

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return definitions, fmt.Errorf("failed to list built-in policy definitions: %w", err)
		}
		definitions = append(definitions, page.Value...)
	}

	return definitions, nil
}

// GetPolicyDefinition returns a specific policy definition
func (s *PolicyService) GetPolicyDefinition(ctx context.Context, subID, policyName string) (*armpolicy.Definition, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewDefinitionsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy definitions client: %w", err)
	}

	resp, err := client.Get(ctx, policyName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy definition: %w", err)
	}

	return &resp.Definition, nil
}

// ListPolicyAssignments returns all policy assignments in a subscription
func (s *PolicyService) ListPolicyAssignments(ctx context.Context, subID string) ([]*armpolicy.Assignment, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewAssignmentsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy assignments client: %w", err)
	}

	pager := client.NewListPager(nil)
	var assignments []*armpolicy.Assignment

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return assignments, fmt.Errorf("failed to list policy assignments: %w", err)
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments, nil
}

// ListPolicyAssignmentsForResourceGroup returns policy assignments for a resource group
func (s *PolicyService) ListPolicyAssignmentsForResourceGroup(ctx context.Context, subID, rgName string) ([]*armpolicy.Assignment, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewAssignmentsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy assignments client: %w", err)
	}

	pager := client.NewListForResourceGroupPager(rgName, nil)
	var assignments []*armpolicy.Assignment

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return assignments, fmt.Errorf("failed to list policy assignments: %w", err)
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments, nil
}

// GetPolicyAssignment returns a specific policy assignment
func (s *PolicyService) GetPolicyAssignment(ctx context.Context, scope, assignmentName string) (*armpolicy.Assignment, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewAssignmentsClient("", cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy assignments client: %w", err)
	}

	resp, err := client.Get(ctx, scope, assignmentName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy assignment: %w", err)
	}

	return &resp.Assignment, nil
}

// ListPolicySetDefinitions returns all policy set definitions (initiatives) in a subscription
func (s *PolicyService) ListPolicySetDefinitions(ctx context.Context, subID string) ([]*armpolicy.SetDefinition, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewSetDefinitionsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy set definitions client: %w", err)
	}

	pager := client.NewListPager(nil)
	var setDefinitions []*armpolicy.SetDefinition

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return setDefinitions, fmt.Errorf("failed to list policy set definitions: %w", err)
		}
		setDefinitions = append(setDefinitions, page.Value...)
	}

	return setDefinitions, nil
}

// ListPolicyExemptions returns all policy exemptions in a subscription
func (s *PolicyService) ListPolicyExemptions(ctx context.Context, subID string) ([]*armpolicy.Exemption, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armpolicy.NewExemptionsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy exemptions client: %w", err)
	}

	pager := client.NewListPager(nil)
	var exemptions []*armpolicy.Exemption

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return exemptions, fmt.Errorf("failed to list policy exemptions: %w", err)
		}
		exemptions = append(exemptions, page.Value...)
	}

	return exemptions, nil
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// =============================================================================
// Cached Methods
// =============================================================================

// CachedListPolicyDefinitions returns all policy definitions with caching
func (s *PolicyService) CachedListPolicyDefinitions(ctx context.Context, subID string) ([]*armpolicy.Definition, error) {
	key := cacheKey("definitions", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armpolicy.Definition), nil
	}
	result, err := s.ListPolicyDefinitions(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPolicyAssignments returns all policy assignments with caching
func (s *PolicyService) CachedListPolicyAssignments(ctx context.Context, subID string) ([]*armpolicy.Assignment, error) {
	key := cacheKey("assignments", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armpolicy.Assignment), nil
	}
	result, err := s.ListPolicyAssignments(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPolicySetDefinitions returns all policy set definitions with caching
func (s *PolicyService) CachedListPolicySetDefinitions(ctx context.Context, subID string) ([]*armpolicy.SetDefinition, error) {
	key := cacheKey("setdefinitions", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armpolicy.SetDefinition), nil
	}
	result, err := s.ListPolicySetDefinitions(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPolicyExemptions returns all policy exemptions with caching
func (s *PolicyService) CachedListPolicyExemptions(ctx context.Context, subID string) ([]*armpolicy.Exemption, error) {
	key := cacheKey("exemptions", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armpolicy.Exemption), nil
	}
	result, err := s.ListPolicyExemptions(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
