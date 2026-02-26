// Package monitoringservice provides Azure Monitor service abstractions
//
// This service layer abstracts Azure Monitor API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package monitoringservice

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/BishopFox/cloudfox/globals"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for monitoring service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "monitoringservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// MonitoringService provides methods for interacting with Azure Monitor
type MonitoringService struct {
	session *azinternal.SafeSession
}

// New creates a new MonitoringService instance
func New(session *azinternal.SafeSession) *MonitoringService {
	return &MonitoringService{
		session: session,
	}
}

// NewWithSession creates a new MonitoringService with the given session (alias for New)
func NewWithSession(session *azinternal.SafeSession) *MonitoringService {
	return New(session)
}

// DiagnosticSettingInfo represents a diagnostic setting
type DiagnosticSettingInfo struct {
	Name                  string
	ResourceID            string
	StorageAccountID      string
	LogAnalyticsWorkspaceID string
	EventHubAuthRuleID    string
	Logs                  []string
	Metrics               []string
}

// AlertRuleInfo represents a metric alert rule
type AlertRuleInfo struct {
	Name          string
	ResourceGroup string
	Location      string
	Description   string
	Severity      int32
	Enabled       bool
	TargetResource string
}

// ActionGroupInfo represents an action group
type ActionGroupInfo struct {
	Name           string
	ResourceGroup  string
	ShortName      string
	Enabled        bool
	EmailReceivers []string
	SMSReceivers   []string
	WebhookReceivers []string
}

// LogProfileInfo represents a log profile
type LogProfileInfo struct {
	Name              string
	Location          string
	StorageAccountID  string
	ServiceBusRuleID  string
	Categories        []string
	Locations         []string
	RetentionDays     int32
}

// ActivityLogAlertInfo represents an activity log alert
type ActivityLogAlertInfo struct {
	Name          string
	ResourceGroup string
	Description   string
	Enabled       bool
	Scopes        []string
	Condition     string
}

// getARMCredential returns ARM credential from session
func (s *MonitoringService) getARMCredential() (*azinternal.StaticTokenCredential, error) {
	token, err := s.session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token: %w", err)
	}
	return &azinternal.StaticTokenCredential{Token: token}, nil
}

// ListDiagnosticSettings returns diagnostic settings for a resource
func (s *MonitoringService) ListDiagnosticSettings(ctx context.Context, resourceID string) ([]*armmonitor.DiagnosticSettingsResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmonitor.NewDiagnosticSettingsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create diagnostic settings client: %w", err)
	}

	pager := client.NewListPager(resourceID, nil)
	var settings []*armmonitor.DiagnosticSettingsResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return settings, fmt.Errorf("failed to list diagnostic settings: %w", err)
		}
		settings = append(settings, page.Value...)
	}

	return settings, nil
}

// ListMetricAlerts returns all metric alerts in a subscription
func (s *MonitoringService) ListMetricAlerts(ctx context.Context, subID string) ([]*armmonitor.MetricAlertResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmonitor.NewMetricAlertsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric alerts client: %w", err)
	}

	pager := client.NewListBySubscriptionPager(nil)
	var alerts []*armmonitor.MetricAlertResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return alerts, fmt.Errorf("failed to list metric alerts: %w", err)
		}
		alerts = append(alerts, page.Value...)
	}

	return alerts, nil
}

// ListMetricAlertsByResourceGroup returns all metric alerts in a resource group
func (s *MonitoringService) ListMetricAlertsByResourceGroup(ctx context.Context, subID, rgName string) ([]*armmonitor.MetricAlertResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmonitor.NewMetricAlertsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric alerts client: %w", err)
	}

	pager := client.NewListByResourceGroupPager(rgName, nil)
	var alerts []*armmonitor.MetricAlertResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return alerts, fmt.Errorf("failed to list metric alerts: %w", err)
		}
		alerts = append(alerts, page.Value...)
	}

	return alerts, nil
}

// ListActionGroups returns all action groups in a subscription
func (s *MonitoringService) ListActionGroups(ctx context.Context, subID string) ([]*armmonitor.ActionGroupResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmonitor.NewActionGroupsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create action groups client: %w", err)
	}

	pager := client.NewListBySubscriptionIDPager(nil)
	var groups []*armmonitor.ActionGroupResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return groups, fmt.Errorf("failed to list action groups: %w", err)
		}
		groups = append(groups, page.Value...)
	}

	return groups, nil
}

// ListActivityLogAlerts returns all activity log alerts in a subscription
func (s *MonitoringService) ListActivityLogAlerts(ctx context.Context, subID string) ([]*armmonitor.ActivityLogAlertResource, error) {
	cred, err := s.getARMCredential()
	if err != nil {
		return nil, err
	}

	client, err := armmonitor.NewActivityLogAlertsClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create activity log alerts client: %w", err)
	}

	pager := client.NewListBySubscriptionIDPager(nil)
	var alerts []*armmonitor.ActivityLogAlertResource

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return alerts, fmt.Errorf("failed to list activity log alerts: %w", err)
		}
		alerts = append(alerts, page.Value...)
	}

	return alerts, nil
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

// CachedListMetricAlerts returns all metric alerts with caching
func (s *MonitoringService) CachedListMetricAlerts(ctx context.Context, subID string) ([]*armmonitor.MetricAlertResource, error) {
	key := cacheKey("metricalerts", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armmonitor.MetricAlertResource), nil
	}
	result, err := s.ListMetricAlerts(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListActionGroups returns all action groups with caching
func (s *MonitoringService) CachedListActionGroups(ctx context.Context, subID string) ([]*armmonitor.ActionGroupResource, error) {
	key := cacheKey("actiongroups", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armmonitor.ActionGroupResource), nil
	}
	result, err := s.ListActionGroups(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListActivityLogAlerts returns all activity log alerts with caching
func (s *MonitoringService) CachedListActivityLogAlerts(ctx context.Context, subID string) ([]*armmonitor.ActivityLogAlertResource, error) {
	key := cacheKey("activitylogalerts", subID)
	if cached, found := serviceCache.Get(key); found {
		return cached.([]*armmonitor.ActivityLogAlertResource), nil
	}
	result, err := s.ListActivityLogAlerts(ctx, subID)
	if err != nil {
		return nil, err
	}
	serviceCache.Set(key, result, 0)
	return result, nil
}
