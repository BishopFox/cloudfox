// Package logicappservice provides Azure Logic Apps service abstractions
//
// This service layer abstracts Azure Logic Apps API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package logicappservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for Logic App service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "logicappservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// LogicAppService provides methods for interacting with Azure Logic Apps
type LogicAppService struct {
	session *azinternal.SafeSession
}

// New creates a new LogicAppService instance
func New(session *azinternal.SafeSession) *LogicAppService {
	return &LogicAppService{
		session: session,
	}
}

// NewWithSession creates a new LogicAppService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *LogicAppService {
	return New(session)
}

// WorkflowInfo represents a Logic App workflow
type WorkflowInfo struct {
	Name              string
	ResourceGroup     string
	Location          string
	State             string
	Version           string
	AccessEndpoint    string
	ProvisioningState string
	CreatedTime       string
	ChangedTime       string
}

// TriggerInfo represents a workflow trigger
type TriggerInfo struct {
	Name         string
	WorkflowName string
	State        string
	Type         string
	CallbackURL  string
}

// RunInfo represents a workflow run
type RunInfo struct {
	Name         string
	WorkflowName string
	Status       string
	StartTime    string
	EndTime      string
}

// IntegrationAccountInfo represents an integration account
type IntegrationAccountInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	SKU           string
	State         string
}

// getARMCredential returns ARM credential from session
func (s *LogicAppService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListWorkflows returns all Logic App workflows in a subscription
func (s *LogicAppService) ListWorkflows(ctx context.Context, subID string) ([]*armlogic.Workflow, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armlogic.NewWorkflowsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create workflows client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var workflows []*armlogic.Workflow

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return workflows, fmt.Errorf("failed to list workflows: %w", err)
		}
		workflows = append(workflows, page.Value...)
	}

	return workflows, nil
}

// ListWorkflowsByResourceGroup returns all workflows in a resource group
func (s *LogicAppService) ListWorkflowsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armlogic.Workflow, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armlogic.NewWorkflowsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create workflows client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var workflows []*armlogic.Workflow

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return workflows, fmt.Errorf("failed to list workflows: %w", err)
		}
		workflows = append(workflows, page.Value...)
	}

	return workflows, nil
}

// GetWorkflow returns a specific workflow
func (s *LogicAppService) GetWorkflow(ctx context.Context, subID, rgName, workflowName string) (*armlogic.Workflow, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armlogic.NewWorkflowsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create workflows client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, workflowName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow: %w", err)
	}

	return &resp.Workflow, nil
}

// ListTriggers returns all triggers for a workflow
func (s *LogicAppService) ListTriggers(ctx context.Context, subID, rgName, workflowName string) ([]*armlogic.WorkflowTrigger, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armlogic.NewWorkflowTriggersClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create triggers client: %w", err)
	}

	pager := client.NewListPager(rgName, workflowName, nil)
	var triggers []*armlogic.WorkflowTrigger

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return triggers, fmt.Errorf("failed to list triggers: %w", err)
		}
		triggers = append(triggers, page.Value...)
	}

	return triggers, nil
}

// GetTriggerCallbackURL returns the callback URL for a trigger
func (s *LogicAppService) GetTriggerCallbackURL(ctx context.Context, subID, rgName, workflowName, triggerName string) (string, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return "", err
	}

	client, err := armlogic.NewWorkflowTriggersClient(subID, cred, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create triggers client: %w", err)
	}

	resp, err := client.ListCallbackURL(ctx, rgName, workflowName, triggerName, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get callback URL: %w", err)
	}

	if resp.Value != nil {
		return *resp.Value, nil
	}
	return "", nil
}

// ListRuns returns recent runs for a workflow
func (s *LogicAppService) ListRuns(ctx context.Context, subID, rgName, workflowName string) ([]*armlogic.WorkflowRun, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armlogic.NewWorkflowRunsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create runs client: %w", err)
	}

	pager := client.NewListPager(rgName, workflowName, nil)
	var runs []*armlogic.WorkflowRun

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return runs, fmt.Errorf("failed to list runs: %w", err)
		}
		runs = append(runs, page.Value...)
	}

	return runs, nil
}

// ListIntegrationAccounts returns all integration accounts in a subscription
func (s *LogicAppService) ListIntegrationAccounts(ctx context.Context, subID string) ([]*armlogic.IntegrationAccount, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armlogic.NewIntegrationAccountsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create integration accounts client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var accounts []*armlogic.IntegrationAccount

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list integration accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
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

// CachedListWorkflows returns all Logic App workflows with caching
func (s *LogicAppService) CachedListWorkflows(ctx context.Context, subID string) ([]*armlogic.Workflow, error) {
	key := cacheKey("workflows", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armlogic.Workflow), nil
	}
	result, err := s.ListWorkflows(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListTriggers returns all triggers for a workflow with caching
func (s *LogicAppService) CachedListTriggers(ctx context.Context, subID, rgName, workflowName string) ([]*armlogic.WorkflowTrigger, error) {
	key := cacheKey("triggers", subID, rgName, workflowName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armlogic.WorkflowTrigger), nil
	}
	result, err := s.ListTriggers(ctx, subID, rgName, workflowName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListIntegrationAccounts returns all integration accounts with caching
func (s *LogicAppService) CachedListIntegrationAccounts(ctx context.Context, subID string) ([]*armlogic.IntegrationAccount, error) {
	key := cacheKey("integrationaccounts", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armlogic.IntegrationAccount), nil
	}
	result, err := s.ListIntegrationAccounts(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
