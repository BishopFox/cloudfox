package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzMonitorCommand = &cobra.Command{
	Use:     "monitor",
	Aliases: []string{"monitoring", "log-analytics"},
	Short:   "Enumerate Azure Monitor resources and observability coverage",
	Long: `
Enumerate Azure Monitor resources for a specific tenant:
./cloudfox az monitor --tenant TENANT_ID

Enumerate Azure Monitor resources for a specific subscription:
./cloudfox az monitor --subscription SUBSCRIPTION_ID

This module enumerates:
- Log Analytics workspaces (central logging repositories)
- Diagnostic settings (resource-level logging configuration)
- Metric alerts (monitoring alerts)
- Action groups (alert notification/response)

Security Analysis:
- HIGH: Resources without diagnostic settings (blind spots)
- MEDIUM: Workspaces with low retention (compliance risk)
- LOW: Missing alerts for critical resources`,
	Run: ListMonitor,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type MonitorModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions      []string
	WorkspaceRows      [][]string
	DiagnosticRows     [][]string
	AlertRows          [][]string
	ActionGroupRows    [][]string
	LootMap            map[string]*internal.LootFile
	mu                 sync.Mutex
	workspaceRetention map[string]int32 // Track workspace retention for analysis
}

// ------------------------------
// Output struct
// ------------------------------
type MonitorOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o MonitorOutput) TableFiles() []internal.TableFile { return o.Table }
func (o MonitorOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListMonitor(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_MONITOR_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &MonitorModule{
		BaseAzureModule:    azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:      cmdCtx.Subscriptions,
		WorkspaceRows:      [][]string{},
		DiagnosticRows:     [][]string{},
		AlertRows:          [][]string{},
		ActionGroupRows:    [][]string{},
		workspaceRetention: make(map[string]int32),
		LootMap: map[string]*internal.LootFile{
			"monitor-no-diagnostics":      {Name: "monitor-no-diagnostics", Contents: ""},
			"monitor-low-retention":       {Name: "monitor-low-retention", Contents: ""},
			"monitor-missing-alerts":      {Name: "monitor-missing-alerts", Contents: ""},
			"monitor-disabled-workspaces": {Name: "monitor-disabled-workspaces", Contents: ""},
			"monitor-setup-commands":      {Name: "monitor-setup-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintMonitor(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *MonitorModule) PrintMonitor(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_MONITOR_MODULE_NAME)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_MONITOR_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_MONITOR_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Azure Monitor resources for %d subscription(s)", len(m.Subscriptions)), globals.AZ_MONITOR_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_MONITOR_MODULE_NAME, m.processSubscription)
	}

	// Generate setup commands loot
	m.generateSetupCommands()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *MonitorModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Process in parallel:
	// 1. Log Analytics workspaces
	// 2. Metric alerts
	// 3. Action groups
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		m.processLogAnalyticsWorkspaces(ctx, subID, subName, logger)
	}()

	go func() {
		defer wg.Done()
		m.processMetricAlerts(ctx, subID, subName, logger)
	}()

	go func() {
		defer wg.Done()
		m.processActionGroups(ctx, subID, subName, logger)
	}()

	wg.Wait()

	// After workspaces are enumerated, sample diagnostic settings
	// (We'll sample a few resource types to check logging coverage)
	m.sampleDiagnosticSettings(ctx, subID, subName, logger)
}

// ------------------------------
// Process Log Analytics workspaces
// ------------------------------
func (m *MonitorModule) processLogAnalyticsWorkspaces(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
		}
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// Create Operational Insights client
	client, err := armoperationalinsights.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Log Analytics client for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
		}
		return
	}

	// List all Log Analytics workspaces
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing Log Analytics workspaces for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
			}
			return
		}

		for _, workspace := range page.Value {
			if workspace == nil || workspace.Name == nil {
				continue
			}

			workspaceName := *workspace.Name
			workspaceID := ""
			customerID := ""
			location := ""
			sku := "Unknown"
			retentionDays := int32(0)
			dailyQuotaGB := "Unlimited"
			provisioningState := "Unknown"
			publicNetworkAccess := "Enabled"

			if workspace.ID != nil {
				workspaceID = *workspace.ID
			}
			if workspace.Location != nil {
				location = *workspace.Location
			}
			if workspace.Properties != nil {
				if workspace.Properties.CustomerID != nil {
					customerID = *workspace.Properties.CustomerID
				}
				if workspace.Properties.RetentionInDays != nil {
					retentionDays = *workspace.Properties.RetentionInDays
				}
				if workspace.Properties.ProvisioningState != nil {
					provisioningState = string(*workspace.Properties.ProvisioningState)
				}
				if workspace.Properties.PublicNetworkAccessForIngestion != nil {
					publicNetworkAccess = string(*workspace.Properties.PublicNetworkAccessForIngestion)
				}
				if workspace.Properties.WorkspaceCapping != nil && workspace.Properties.WorkspaceCapping.DailyQuotaGb != nil {
					dailyQuotaGB = fmt.Sprintf("%.2f GB", *workspace.Properties.WorkspaceCapping.DailyQuotaGb)
				}
			}
			if workspace.Properties != nil && workspace.Properties.SKU != nil && workspace.Properties.SKU.Name != nil {
				sku = string(*workspace.Properties.SKU.Name)
			}

			// Determine risk level
			riskLevel := "INFO"
			securityIssues := []string{}

			// Check retention (compliance requirement: typically 90+ days)
			if retentionDays < 90 && retentionDays > 0 {
				riskLevel = "MEDIUM"
				securityIssues = append(securityIssues, fmt.Sprintf("Low retention: %d days", retentionDays))
			}

			// Check public network access
			if publicNetworkAccess == "Enabled" {
				securityIssues = append(securityIssues, "Public network access enabled")
			}

			// Check provisioning state
			if provisioningState != "Succeeded" {
				riskLevel = "MEDIUM"
				securityIssues = append(securityIssues, fmt.Sprintf("Provisioning state: %s", provisioningState))
			}

			securityIssuesStr := "None"
			if len(securityIssues) > 0 {
				securityIssuesStr = strings.Join(securityIssues, "; ")
			}

			// Build row
			row := []string{
				subID,
				subName,
				workspaceName,
				customerID,
				location,
				sku,
				fmt.Sprintf("%d", retentionDays),
				dailyQuotaGB,
				provisioningState,
				publicNetworkAccess,
				securityIssuesStr,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.WorkspaceRows = append(m.WorkspaceRows, row)
			m.workspaceRetention[workspaceID] = retentionDays

			// Add to loot if issues found
			if retentionDays < 90 && retentionDays > 0 {
				lootEntry := fmt.Sprintf("[LOW RETENTION] Workspace: %s, Retention: %d days (Subscription: %s)\n", workspaceName, retentionDays, subName)
				m.LootMap["monitor-low-retention"].Contents += lootEntry
			}
			if provisioningState != "Succeeded" {
				lootEntry := fmt.Sprintf("[DISABLED] Workspace: %s, State: %s (Subscription: %s)\n", workspaceName, provisioningState, subName)
				m.LootMap["monitor-disabled-workspaces"].Contents += lootEntry
			}
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Process metric alerts
// ------------------------------
func (m *MonitorModule) processMetricAlerts(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
		}
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// Create Metric Alerts client
	client, err := armmonitor.NewMetricAlertsClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Metric Alerts client for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
		}
		return
	}

	// List all metric alerts for the subscription
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing metric alerts for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
			}
			return
		}

		for _, alert := range page.Value {
			if alert == nil || alert.Name == nil {
				continue
			}

			alertName := *alert.Name
			location := ""
			enabled := "No"
			severity := "Unknown"
			targetResourceType := ""
			targetResourceCount := 0
			evaluationFrequency := ""
			windowSize := ""
			actionGroupCount := 0
			description := ""

			if alert.Location != nil {
				location = *alert.Location
			}
			if alert.Properties != nil {
				if alert.Properties.Enabled != nil && *alert.Properties.Enabled {
					enabled = "Yes"
				}
				if alert.Properties.Severity != nil {
					severity = fmt.Sprintf("%d", *alert.Properties.Severity)
				}
				if alert.Properties.Description != nil {
					description = *alert.Properties.Description
				}
				if alert.Properties.TargetResourceType != nil {
					targetResourceType = *alert.Properties.TargetResourceType
				}
				if alert.Properties.Scopes != nil {
					targetResourceCount = len(alert.Properties.Scopes)
				}
				if alert.Properties.EvaluationFrequency != nil {
					evaluationFrequency = *alert.Properties.EvaluationFrequency
				}
				if alert.Properties.WindowSize != nil {
					windowSize = *alert.Properties.WindowSize
				}
				if alert.Properties.Actions != nil {
					actionGroupCount = len(alert.Properties.Actions)
				}
			}

			// Determine risk level
			riskLevel := "INFO"
			if enabled == "No" {
				riskLevel = "LOW"
			}
			if actionGroupCount == 0 {
				riskLevel = "MEDIUM"
			}

			// Build row
			row := []string{
				subID,
				subName,
				alertName,
				enabled,
				severity,
				targetResourceType,
				fmt.Sprintf("%d", targetResourceCount),
				evaluationFrequency,
				windowSize,
				fmt.Sprintf("%d", actionGroupCount),
				location,
				description,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.AlertRows = append(m.AlertRows, row)

			// Add to loot if no action groups
			if actionGroupCount == 0 && enabled == "Yes" {
				lootEntry := fmt.Sprintf("[NO ACTIONS] Alert: %s (no notification configured) - Subscription: %s\n", alertName, subName)
				m.LootMap["monitor-missing-alerts"].Contents += lootEntry
			}
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Process action groups
// ------------------------------
func (m *MonitorModule) processActionGroups(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
		}
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// Create Action Groups client
	client, err := armmonitor.NewActionGroupsClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Action Groups client for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
		}
		return
	}

	// List all action groups for the subscription
	pager := client.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing action groups for subscription %s: %v", subID, err), globals.AZ_MONITOR_MODULE_NAME)
			}
			return
		}

		for _, actionGroup := range page.Value {
			if actionGroup == nil || actionGroup.Name == nil {
				continue
			}

			groupName := *actionGroup.Name
			location := ""
			enabled := "Yes"
			emailReceivers := 0
			smsReceivers := 0
			webhookReceivers := 0
			azureFunctionReceivers := 0
			logicAppReceivers := 0

			if actionGroup.Location != nil {
				location = *actionGroup.Location
			}
			if actionGroup.Properties != nil {
				if actionGroup.Properties.Enabled != nil && !*actionGroup.Properties.Enabled {
					enabled = "No"
				}
				if actionGroup.Properties.EmailReceivers != nil {
					emailReceivers = len(actionGroup.Properties.EmailReceivers)
				}
				if actionGroup.Properties.SmsReceivers != nil {
					smsReceivers = len(actionGroup.Properties.SmsReceivers)
				}
				if actionGroup.Properties.WebhookReceivers != nil {
					webhookReceivers = len(actionGroup.Properties.WebhookReceivers)
				}
				if actionGroup.Properties.AzureFunctionReceivers != nil {
					azureFunctionReceivers = len(actionGroup.Properties.AzureFunctionReceivers)
				}
				if actionGroup.Properties.LogicAppReceivers != nil {
					logicAppReceivers = len(actionGroup.Properties.LogicAppReceivers)
				}
			}

			totalReceivers := emailReceivers + smsReceivers + webhookReceivers + azureFunctionReceivers + logicAppReceivers

			// Determine risk level
			riskLevel := "INFO"
			if enabled == "No" {
				riskLevel = "LOW"
			}
			if totalReceivers == 0 {
				riskLevel = "MEDIUM"
			}

			// Build row
			row := []string{
				subID,
				subName,
				groupName,
				enabled,
				fmt.Sprintf("%d", emailReceivers),
				fmt.Sprintf("%d", smsReceivers),
				fmt.Sprintf("%d", webhookReceivers),
				fmt.Sprintf("%d", azureFunctionReceivers),
				fmt.Sprintf("%d", logicAppReceivers),
				fmt.Sprintf("%d", totalReceivers),
				location,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.ActionGroupRows = append(m.ActionGroupRows, row)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Sample diagnostic settings for coverage analysis
// ------------------------------
func (m *MonitorModule) sampleDiagnosticSettings(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Sample a few critical resource types to check diagnostic settings coverage
	// We'll check: VMs, Storage Accounts, Key Vaults, SQL Servers
	// This gives us a sense of overall logging coverage without enumerating every resource

	resourceTypes := []string{
		"Microsoft.Compute/virtualMachines",
		"Microsoft.Storage/storageAccounts",
		"Microsoft.KeyVault/vaults",
		"Microsoft.Sql/servers",
	}

	for _, resourceType := range resourceTypes {
		// Sample up to 5 resources of each type
		resources := m.sampleResourcesByType(ctx, subID, resourceType, 5)

		for _, resourceID := range resources {
			hasLogging := m.checkDiagnosticSettings(ctx, subID, resourceID)

			if !hasLogging {
				resourceName := resourceID
				parts := strings.Split(resourceID, "/")
				if len(parts) > 0 {
					resourceName = parts[len(parts)-1]
				}

				// Build row
				row := []string{
					subID,
					subName,
					resourceName,
					resourceType,
					resourceID,
					"No",
					"HIGH",
				}

				// Add tenant info if multi-tenant
				if m.IsMultiTenant {
					row = append([]string{m.TenantName, m.TenantID}, row...)
				}

				// Thread-safe append
				m.mu.Lock()
				m.DiagnosticRows = append(m.DiagnosticRows, row)

				// Add to loot
				lootEntry := fmt.Sprintf("[NO LOGGING] Resource: %s (%s) - ID: %s\n", resourceName, resourceType, resourceID)
				m.LootMap["monitor-no-diagnostics"].Contents += lootEntry
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Sample resources by type (helper)
// ------------------------------
func (m *MonitorModule) sampleResourcesByType(ctx context.Context, subID, resourceType string, limit int) []string {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		return []string{}
	}

	// Make REST API call to list resources of this type
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resources?$filter=resourceType eq '%s'&api-version=2021-04-01&$top=%d",
		subID, resourceType, limit)

	req, err := azinternal.NewAuthenticatedRequest("GET", url, token, nil)
	if err != nil {
		return []string{}
	}

	resp, err := azinternal.SendAuthenticatedRequest(req)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}

	if err := azinternal.UnmarshalResponseBody(resp, &result); err != nil {
		return []string{}
	}

	resourceIDs := make([]string, 0, len(result.Value))
	for _, r := range result.Value {
		resourceIDs = append(resourceIDs, r.ID)
	}

	return resourceIDs
}

// ------------------------------
// Check diagnostic settings (helper)
// ------------------------------
func (m *MonitorModule) checkDiagnosticSettings(ctx context.Context, subID, resourceID string) bool {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		return false
	}

	// Make REST API call to check diagnostic settings
	url := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview",
		resourceID)

	req, err := azinternal.NewAuthenticatedRequest("GET", url, token, nil)
	if err != nil {
		return false
	}

	resp, err := azinternal.SendAuthenticatedRequest(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Value []interface{} `json:"value"`
	}

	if err := azinternal.UnmarshalResponseBody(resp, &result); err != nil {
		return false
	}

	// If there are any diagnostic settings, consider it as having logging
	return len(result.Value) > 0
}

// ------------------------------
// Generate setup commands loot
// ------------------------------
func (m *MonitorModule) generateSetupCommands() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var commands strings.Builder
	commands.WriteString("# Azure Monitor Setup Commands\n\n")

	// Commands to create Log Analytics workspace
	commands.WriteString("## Create Log Analytics Workspace\n\n")
	seenSubs := make(map[string]bool)
	for _, row := range m.WorkspaceRows {
		var subID, subName string
		if m.IsMultiTenant {
			if len(row) >= 4 {
				subID, subName = row[2], row[3]
			}
		} else {
			if len(row) >= 2 {
				subID, subName = row[0], row[1]
			}
		}

		if !seenSubs[subID] {
			seenSubs[subID] = true
			commands.WriteString(fmt.Sprintf("# Create Log Analytics workspace for subscription %s (%s)\n", subName, subID))
			commands.WriteString(fmt.Sprintf("az monitor log-analytics workspace create \\\n"))
			commands.WriteString(fmt.Sprintf("  --resource-group <resource-group> \\\n"))
			commands.WriteString(fmt.Sprintf("  --workspace-name cloudfox-logs-%s \\\n", subName))
			commands.WriteString(fmt.Sprintf("  --subscription %s \\\n", subID))
			commands.WriteString(fmt.Sprintf("  --retention-time 90 \\\n"))
			commands.WriteString(fmt.Sprintf("  --location <region>\n\n"))
		}
	}

	// Commands to enable diagnostic settings
	commands.WriteString("\n## Enable Diagnostic Settings\n\n")
	seenResources := make(map[string]bool)
	for _, row := range m.DiagnosticRows {
		var resourceID, resourceName string
		if m.IsMultiTenant {
			if len(row) >= 7 {
				resourceID, resourceName = row[6], row[4]
			}
		} else {
			if len(row) >= 5 {
				resourceID, resourceName = row[4], row[2]
			}
		}

		if !seenResources[resourceID] {
			seenResources[resourceID] = true
			commands.WriteString(fmt.Sprintf("# Enable logging for %s\n", resourceName))
			commands.WriteString(fmt.Sprintf("az monitor diagnostic-settings create \\\n"))
			commands.WriteString(fmt.Sprintf("  --name default-logging \\\n"))
			commands.WriteString(fmt.Sprintf("  --resource %s \\\n", resourceID))
			commands.WriteString(fmt.Sprintf("  --workspace <log-analytics-workspace-id> \\\n"))
			commands.WriteString(fmt.Sprintf("  --logs '[{\"category\":\"allLogs\",\"enabled\":true}]' \\\n"))
			commands.WriteString(fmt.Sprintf("  --metrics '[{\"category\":\"AllMetrics\",\"enabled\":true}]'\n\n"))
		}
	}

	m.LootMap["monitor-setup-commands"].Contents = commands.String()
}

// ------------------------------
// Write output
// ------------------------------
func (m *MonitorModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// -------------------- TABLE 1: Log Analytics Workspaces --------------------
	workspaceHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Workspace Name",
		"Customer ID",
		"Location",
		"SKU",
		"Retention Days",
		"Daily Quota",
		"Provisioning State",
		"Public Network Access",
		"Security Issues",
		"Risk Level",
	}
	if m.IsMultiTenant {
		workspaceHeader = append([]string{"Tenant Name", "Tenant ID"}, workspaceHeader...)
	}

	// Sort workspace rows by subscription
	sort.Slice(m.WorkspaceRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.WorkspaceRows[i]) > iOffset && len(m.WorkspaceRows[j]) > jOffset {
			return m.WorkspaceRows[i][iOffset] < m.WorkspaceRows[j][jOffset]
		}
		return false
	})

	workspaceTable := internal.TableFile{
		Name:      "log-analytics-workspaces",
		Header:    workspaceHeader,
		Body:      m.WorkspaceRows,
		TableCols: workspaceHeader,
	}

	// -------------------- TABLE 2: Metric Alerts --------------------
	alertHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Alert Name",
		"Enabled",
		"Severity",
		"Target Resource Type",
		"Target Count",
		"Evaluation Frequency",
		"Window Size",
		"Action Groups",
		"Location",
		"Description",
		"Risk Level",
	}
	if m.IsMultiTenant {
		alertHeader = append([]string{"Tenant Name", "Tenant ID"}, alertHeader...)
	}

	// Sort alert rows by subscription
	sort.Slice(m.AlertRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.AlertRows[i]) > iOffset && len(m.AlertRows[j]) > jOffset {
			return m.AlertRows[i][iOffset] < m.AlertRows[j][jOffset]
		}
		return false
	})

	alertTable := internal.TableFile{
		Name:      "metric-alerts",
		Header:    alertHeader,
		Body:      m.AlertRows,
		TableCols: alertHeader,
	}

	// -------------------- TABLE 3: Action Groups --------------------
	actionGroupHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Action Group Name",
		"Enabled",
		"Email Receivers",
		"SMS Receivers",
		"Webhook Receivers",
		"Azure Function Receivers",
		"Logic App Receivers",
		"Total Receivers",
		"Location",
		"Risk Level",
	}
	if m.IsMultiTenant {
		actionGroupHeader = append([]string{"Tenant Name", "Tenant ID"}, actionGroupHeader...)
	}

	// Sort action group rows by subscription
	sort.Slice(m.ActionGroupRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.ActionGroupRows[i]) > iOffset && len(m.ActionGroupRows[j]) > jOffset {
			return m.ActionGroupRows[i][iOffset] < m.ActionGroupRows[j][jOffset]
		}
		return false
	})

	actionGroupTable := internal.TableFile{
		Name:      "action-groups",
		Header:    actionGroupHeader,
		Body:      m.ActionGroupRows,
		TableCols: actionGroupHeader,
	}

	// -------------------- TABLE 4: Resources Without Diagnostic Settings (Sample) --------------------
	diagnosticHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Resource Name",
		"Resource Type",
		"Resource ID",
		"Has Logging",
		"Risk Level",
	}
	if m.IsMultiTenant {
		diagnosticHeader = append([]string{"Tenant Name", "Tenant ID"}, diagnosticHeader...)
	}

	// Sort diagnostic rows by resource type
	sort.Slice(m.DiagnosticRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.DiagnosticRows[i]) > iOffset+3 && len(m.DiagnosticRows[j]) > jOffset+3 {
			return m.DiagnosticRows[i][iOffset+3] < m.DiagnosticRows[j][jOffset+3]
		}
		return false
	})

	diagnosticTable := internal.TableFile{
		Name:      "diagnostic-coverage-sample",
		Header:    diagnosticHeader,
		Body:      m.DiagnosticRows,
		TableCols: diagnosticHeader,
	}

	// -------------------- Combine tables --------------------
	tables := []internal.TableFile{
		workspaceTable,
		alertTable,
		actionGroupTable,
		diagnosticTable,
	}

	// -------------------- Convert loot map to slice --------------------
	var loot []internal.LootFile
	lootOrder := []string{
		"monitor-no-diagnostics",
		"monitor-low-retention",
		"monitor-missing-alerts",
		"monitor-disabled-workspaces",
		"monitor-setup-commands",
	}
	for _, key := range lootOrder {
		if lootFile, exists := m.LootMap[key]; exists && lootFile.Contents != "" {
			loot = append(loot, *lootFile)
		}
	}

	// -------------------- Generate output --------------------
	output := MonitorOutput{
		Table: tables,
		Loot:  loot,
	}
	_ = output // Avoid unused warning

	// -------------------- Write files using helper --------------------
	summary := fmt.Sprintf("%d subscriptions, %d workspaces, %d alerts, %d action groups, %d resources without logging (sample)",
		len(m.Subscriptions),
		len(m.WorkspaceRows),
		len(m.AlertRows),
		len(m.ActionGroupRows),
		len(m.DiagnosticRows))

	// TODO: Implement WriteTableAndLootFiles
	logger.InfoM(fmt.Sprintf("Monitor enumeration complete. Summary: %s", summary), globals.AZ_MONITOR_MODULE_NAME)
}
