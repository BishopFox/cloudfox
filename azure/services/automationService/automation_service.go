// Package automationservice provides Azure Automation service abstractions
//
// This service layer abstracts Azure Automation API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package automationservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for automation service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "automationservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// AutomationService provides methods for interacting with Azure Automation
type AutomationService struct {
	session *azinternal.SafeSession
}

// New creates a new AutomationService instance
func New(session *azinternal.SafeSession) *AutomationService {
	return &AutomationService{
		session: session,
	}
}

// NewWithSession creates a new AutomationService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *AutomationService {
	return New(session)
}

// AccountInfo represents an Azure Automation account
type AccountInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	State         string
	SKU           string
	LastModified  string
}

// RunbookInfo represents an Automation runbook
type RunbookInfo struct {
	Name           string
	AccountName    string
	ResourceGroup  string
	RunbookType    string
	State          string
	Location       string
	LastModified   string
}

// CredentialInfo represents an Automation credential
type CredentialInfo struct {
	Name        string
	AccountName string
	UserName    string
	Description string
}

// VariableInfo represents an Automation variable
type VariableInfo struct {
	Name        string
	AccountName string
	IsEncrypted bool
	Value       string
	Description string
}

// ScheduleInfo represents an Automation schedule
type ScheduleInfo struct {
	Name        string
	AccountName string
	Frequency   string
	StartTime   string
	IsEnabled   bool
}

// getARMCredential returns ARM credential from session
func (s *AutomationService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListAccounts returns all Automation accounts in a subscription
func (s *AutomationService) ListAccounts(ctx context.Context, subID string) ([]*armautomation.Account, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armautomation.NewAccountClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create automation client: %w", err)
	}

	pager := client.NewListPager(nil)
	var accounts []*armautomation.Account

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list automation accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// ListAccountsByResourceGroup returns all Automation accounts in a resource group
func (s *AutomationService) ListAccountsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armautomation.Account, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armautomation.NewAccountClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create automation client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var accounts []*armautomation.Account

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return accounts, fmt.Errorf("failed to list automation accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	return accounts, nil
}

// ListRunbooks returns all runbooks in an Automation account
func (s *AutomationService) ListRunbooks(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Runbook, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armautomation.NewRunbookClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create runbook client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	var runbooks []*armautomation.Runbook

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return runbooks, fmt.Errorf("failed to list runbooks: %w", err)
		}
		runbooks = append(runbooks, page.Value...)
	}

	return runbooks, nil
}

// GetRunbook returns a specific runbook
func (s *AutomationService) GetRunbook(ctx context.Context, subID, rgName, accountName, runbookName string) (*armautomation.Runbook, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armautomation.NewRunbookClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create runbook client: %w", err)
	}

	resp, err := client.Get(ctx, rgName, accountName, runbookName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get runbook: %w", err)
	}

	return &resp.Runbook, nil
}

// ListCredentials returns all credentials in an Automation account
func (s *AutomationService) ListCredentials(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Credential, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armautomation.NewCredentialClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	var credentials []*armautomation.Credential

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return credentials, fmt.Errorf("failed to list credentials: %w", err)
		}
		credentials = append(credentials, page.Value...)
	}

	return credentials, nil
}

// ListVariables returns all variables in an Automation account
func (s *AutomationService) ListVariables(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Variable, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armautomation.NewVariableClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create variable client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	var variables []*armautomation.Variable

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return variables, fmt.Errorf("failed to list variables: %w", err)
		}
		variables = append(variables, page.Value...)
	}

	return variables, nil
}

// ListSchedules returns all schedules in an Automation account
func (s *AutomationService) ListSchedules(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Schedule, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armautomation.NewScheduleClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create schedule client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(rgName, accountName, nil)
	var schedules []*armautomation.Schedule

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return schedules, fmt.Errorf("failed to list schedules: %w", err)
		}
		schedules = append(schedules, page.Value...)
	}

	return schedules, nil
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

// CachedListAccounts returns all Automation accounts with caching
func (s *AutomationService) CachedListAccounts(ctx context.Context, subID string) ([]*armautomation.Account, error) {
	key := cacheKey("accounts", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armautomation.Account), nil
	}
	result, err := s.ListAccounts(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListRunbooks returns all runbooks in an Automation account with caching
func (s *AutomationService) CachedListRunbooks(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Runbook, error) {
	key := cacheKey("runbooks", subID, rgName, accountName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armautomation.Runbook), nil
	}
	result, err := s.ListRunbooks(ctx, subID, rgName, accountName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListCredentials returns all credentials in an Automation account with caching
func (s *AutomationService) CachedListCredentials(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Credential, error) {
	key := cacheKey("credentials", subID, rgName, accountName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armautomation.Credential), nil
	}
	result, err := s.ListCredentials(ctx, subID, rgName, accountName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListVariables returns all variables in an Automation account with caching
func (s *AutomationService) CachedListVariables(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Variable, error) {
	key := cacheKey("variables", subID, rgName, accountName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armautomation.Variable), nil
	}
	result, err := s.ListVariables(ctx, subID, rgName, accountName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListSchedules returns all schedules in an Automation account with caching
func (s *AutomationService) CachedListSchedules(ctx context.Context, subID, rgName, accountName string) ([]*armautomation.Schedule, error) {
	key := cacheKey("schedules", subID, rgName, accountName)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armautomation.Schedule), nil
	}
	result, err := s.ListSchedules(ctx, subID, rgName, accountName)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
