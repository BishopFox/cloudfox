package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

type SentinelModule struct {
	azinternal.BaseAzureModule

	Subscriptions      []string
	WorkspaceRows      [][]string
	AnalyticsRuleRows  [][]string
	AutomationRuleRows [][]string
	DataConnectorRows  [][]string
	IncidentRows       [][]string
	LootMap            map[string]*internal.LootFile
	mu                 sync.Mutex
	workspaceRegistry  map[string]workspaceInfo // Map workspace ID to info for cross-referencing

	// Output fields
	TableFiles *internal.TableFiles
	output     string
	modLog     internal.Logger
	Caller     string
}

type workspaceInfo struct {
	SubscriptionID string
	ResourceGroup  string
	WorkspaceName  string
	WorkspaceID    string
	HasSentinel    bool
}

func (m *SentinelModule) PrintSentinelCommand(ctx context.Context, logger internal.Logger) {
	m.modLog = logger

	// Tables (TableFiles not needed with new writeOutput approach)

	// Initialize loot file contents (LootMap already initialized in Run function)
	m.LootMap["sentinel-disabled-rules"].Contents += "# Disabled Analytics Rules\n" +
		"# Sentinel Analytics Rules that are disabled and may not be detecting threats\n\n"
	m.LootMap["sentinel-unconnected-sources"].Contents += "# Disconnected Data Connectors\n" +
		"# Sentinel data connectors that are not connected or disabled\n\n"
	m.LootMap["sentinel-setup-commands"].Contents += "# Setup Commands\n" +
		"# Commands to investigate and remediate Sentinel security issues\n\n"

	m.workspaceRegistry = make(map[string]workspaceInfo)

	m.modLog.Info("Enumerating Microsoft Sentinel (SIEM) instances and configuration...")
	fmt.Printf("[azure] Enumerating Microsoft Sentinel workspaces and rules.\n")

	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_SENTINEL_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			// Save tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Set current tenant
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_SENTINEL_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_SENTINEL_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing
		logger.InfoM(fmt.Sprintf("Enumerating for %d subscription(s)", len(m.Subscriptions)), globals.AZ_SENTINEL_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_SENTINEL_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// processSubscription processes a single subscription (callback for RunSubscriptionEnumeration)
func (m *SentinelModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)
	m.processSentinelWorkspaces(ctx, subID, subName, logger)
}

func (m *SentinelModule) processSentinelWorkspaces(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get Log Analytics workspaces and check if Sentinel is enabled
	workspaces := azinternal.GetLogAnalyticsWorkspacesPerSubscription(m.Session, subID)

	for _, ws := range workspaces {
		wsName := azinternal.ExtractResourceName(ws)
		wsRG := azinternal.GetResourceGroupFromID(ws)
		wsID := ws

		// Store workspace info
		wsInfo := workspaceInfo{
			SubscriptionID: subID,
			ResourceGroup:  wsRG,
			WorkspaceName:  wsName,
			WorkspaceID:    wsID,
			HasSentinel:    false,
		}

		// Check if Sentinel is enabled by trying to get Sentinel metadata
		if m.checkSentinelEnabled(ctx, subID, wsRG, wsName, logger) {
			wsInfo.HasSentinel = true
			m.mu.Lock()
			m.workspaceRegistry[wsID] = wsInfo
			m.mu.Unlock()

			// If Sentinel is enabled, enumerate its components
			m.processAnalyticsRules(ctx, subID, subName, wsRG, wsName, logger)
			automationRuleCount := m.processAutomationRules(ctx, subID, subName, wsRG, wsName, logger)
			m.processDataConnectors(ctx, subID, subName, wsRG, wsName, logger)
			incidentCount := m.processIncidents(ctx, subID, subName, wsRG, wsName, logger)

			// Build workspace summary row
			riskLevel := "INFO"
			securityIssues := []string{}

			if automationRuleCount == 0 {
				riskLevel = "MEDIUM"
				securityIssues = append(securityIssues, "No automation rules")
				m.LootMap["sentinel-no-automation"].Contents += fmt.Sprintf(
					"Subscription: %s (%s)\nResource Group: %s\nWorkspace: %s\nIssue: No automation rules configured for incident response\n\n",
					subName, subID, wsRG, wsName)
			}

			if incidentCount > 10 {
				if riskLevel == "INFO" {
					riskLevel = "LOW"
				}
				securityIssues = append(securityIssues, fmt.Sprintf("%d active incidents", incidentCount))
			}

			issuesStr := strings.Join(securityIssues, "; ")
			if issuesStr == "" {
				issuesStr = "None"
			}

			row := []string{
			m.TenantName,
			m.TenantID,
				m.TenantName,
				m.TenantID,
				subName,
				subID,
				wsRG,
				wsName,
				wsID,
				"Enabled",
				fmt.Sprintf("%d", automationRuleCount),
				fmt.Sprintf("%d", incidentCount),
				riskLevel,
				issuesStr,
			}

			m.mu.Lock()
			m.WorkspaceRows = append(m.WorkspaceRows, row)
			m.mu.Unlock()

		} else {
			// Workspace exists but Sentinel is not enabled
			row := []string{
			m.TenantName,
			m.TenantID,
				subName,
				subID,
				wsRG,
				wsName,
				wsID,
				"Not Enabled",
				"0",
				"0",
				"INFO",
				"Sentinel not enabled on this workspace",
			}

			m.mu.Lock()
			m.WorkspaceRows = append(m.WorkspaceRows, row)
			m.mu.Unlock()
		}
	}
}

func (m *SentinelModule) checkSentinelEnabled(ctx context.Context, subID, rgName, wsName string, logger internal.Logger) bool {
	// Create Security Insights client
	token, err := m.Session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return false
	}

	cred := azinternal.NewStaticTokenCredential(token)
	client, err := armsecurityinsights.NewSentinelOnboardingStatesClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to create Sentinel client for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return false
	}

	// Try to get the Sentinel onboarding state
	_, err = client.Get(ctx, rgName, wsName, "default", nil)
	if err != nil {
		// If we get an error, Sentinel is likely not enabled
		return false
	}

	return true
}

func (m *SentinelModule) processAnalyticsRules(ctx context.Context, subID, subName, rgName, wsName string, logger internal.Logger) {
	token, err := m.Session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return
	}

	cred := azinternal.NewStaticTokenCredential(token)
	client, err := armsecurityinsights.NewAlertRulesClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to create Analytics Rules client for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return
	}

	pager := client.NewListPager(rgName, wsName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Failed to list analytics rules for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
			}
			return
		}

		for _, ruleIntf := range page.Value {
			if ruleIntf == nil {
				continue
			}

			// Type assertion for different rule types
			var ruleName, ruleID, ruleType, severity, enabled, tactics, techniques, query string
			riskLevel := "INFO"
			securityIssues := []string{}

			switch rule := ruleIntf.(type) {
			case *armsecurityinsights.ScheduledAlertRule:
				if rule.Properties != nil {
					if rule.Properties.DisplayName != nil {
						ruleName = *rule.Properties.DisplayName
					}
					if rule.Name != nil {
						ruleID = *rule.Name
					}
					ruleType = "Scheduled"
					if rule.Properties.Severity != nil {
						severity = string(*rule.Properties.Severity)
					}
					if rule.Properties.Enabled != nil {
						enabled = fmt.Sprintf("%v", *rule.Properties.Enabled)
						if !*rule.Properties.Enabled {
							riskLevel = "MEDIUM"
							securityIssues = append(securityIssues, "Rule disabled")
							m.LootMap["sentinel-disabled-rules"].Contents += fmt.Sprintf(
								"Subscription: %s (%s)\nWorkspace: %s/%s\nRule: %s\nSeverity: %s\nType: %s\n\n",
								subName, subID, rgName, wsName, ruleName, severity, ruleType)
						}
					}
					if rule.Properties.Tactics != nil {
						tacticsList := make([]string, 0, len(rule.Properties.Tactics))
						for _, t := range rule.Properties.Tactics {
							if t != nil {
								tacticsList = append(tacticsList, string(*t))
							}
						}
						tactics = strings.Join(tacticsList, ", ")
					}
					// TODO: Techniques property not available in current SDK version
					techniques = "N/A"
					if rule.Properties.Query != nil {
						query = *rule.Properties.Query
						if len(query) > 100 {
							query = query[:100] + "..."
						}
					}
				}

			case *armsecurityinsights.MicrosoftSecurityIncidentCreationAlertRule:
				if rule.Properties != nil {
					if rule.Properties.DisplayName != nil {
						ruleName = *rule.Properties.DisplayName
					}
					if rule.Name != nil {
						ruleID = *rule.Name
					}
					ruleType = "Microsoft Security"
					if rule.Properties.Enabled != nil {
						enabled = fmt.Sprintf("%v", *rule.Properties.Enabled)
						if !*rule.Properties.Enabled {
							riskLevel = "MEDIUM"
							securityIssues = append(securityIssues, "Rule disabled")
						}
					}
				}

			case *armsecurityinsights.FusionAlertRule:
				if rule.Properties != nil {
					if rule.Properties.AlertRuleTemplateName != nil {
						ruleName = *rule.Properties.AlertRuleTemplateName
					}
					if rule.Name != nil {
						ruleID = *rule.Name
					}
					ruleType = "Fusion (ML)"
					enabled = "true"  // Fusion rules are always enabled
					severity = "High" // Fusion rules are typically high severity
				}

			default:
				// Unknown rule type
				continue
			}

			issuesStr := strings.Join(securityIssues, "; ")
			if issuesStr == "" {
				issuesStr = "None"
			}

			row := []string{
			m.TenantName,
			m.TenantID,
				subName,
				subID,
				rgName,
				wsName,
				ruleName,
				ruleID,
				ruleType,
				severity,
				enabled,
				tactics,
				techniques,
				riskLevel,
				issuesStr,
			}

			m.mu.Lock()
			m.AnalyticsRuleRows = append(m.AnalyticsRuleRows, row)
			m.mu.Unlock()

			// Add setup command
			if riskLevel != "INFO" {
				m.LootMap["sentinel-setup-commands"].Contents += fmt.Sprintf(
					"# Review disabled analytics rule: %s\naz sentinel alert-rule show --resource-group %s --workspace-name %s --rule-id %s\n\n",
					ruleName, rgName, wsName, ruleID)
			}
		}
	}
}

func (m *SentinelModule) processAutomationRules(ctx context.Context, subID, subName, rgName, wsName string, logger internal.Logger) int {
	token, err := m.Session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return 0
	}

	cred := azinternal.NewStaticTokenCredential(token)
	client, err := armsecurityinsights.NewAutomationRulesClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to create Automation Rules client for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return 0
	}

	count := 0
	pager := client.NewListPager(rgName, wsName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Failed to list automation rules for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
			}
			return count
		}

		for _, rule := range page.Value {
			if rule == nil || rule.Properties == nil {
				continue
			}

			count++

			var ruleName, ruleID, order, enabled, triggerConditions, actions string
			riskLevel := "INFO"
			securityIssues := []string{}

			if rule.Properties.DisplayName != nil {
				ruleName = *rule.Properties.DisplayName
			}
			if rule.Name != nil {
				ruleID = *rule.Name
			}
			if rule.Properties.Order != nil {
				order = fmt.Sprintf("%d", *rule.Properties.Order)
			}

			// Check if enabled
			if rule.Properties.TriggeringLogic != nil && rule.Properties.TriggeringLogic.IsEnabled != nil {
				enabled = fmt.Sprintf("%v", *rule.Properties.TriggeringLogic.IsEnabled)
				if !*rule.Properties.TriggeringLogic.IsEnabled {
					riskLevel = "LOW"
					securityIssues = append(securityIssues, "Automation disabled")
				}

				// Get trigger conditions count
				if rule.Properties.TriggeringLogic.Conditions != nil {
					triggerConditions = fmt.Sprintf("%d conditions", len(rule.Properties.TriggeringLogic.Conditions))
				}
			}

			// Get actions count
			if rule.Properties.Actions != nil {
				actions = fmt.Sprintf("%d actions", len(rule.Properties.Actions))
			}

			issuesStr := strings.Join(securityIssues, "; ")
			if issuesStr == "" {
				issuesStr = "None"
			}

			row := []string{
			m.TenantName,
			m.TenantID,
				subName,
				subID,
				rgName,
				wsName,
				ruleName,
				ruleID,
				order,
				enabled,
				triggerConditions,
				actions,
				riskLevel,
				issuesStr,
			}

			m.mu.Lock()
			m.AutomationRuleRows = append(m.AutomationRuleRows, row)
			m.mu.Unlock()
		}
	}

	return count
}

func (m *SentinelModule) processDataConnectors(ctx context.Context, subID, subName, rgName, wsName string, logger internal.Logger) {
	token, err := m.Session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return
	}

	cred := azinternal.NewStaticTokenCredential(token)
	client, err := armsecurityinsights.NewDataConnectorsClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to create Data Connectors client for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return
	}

	pager := client.NewListPager(rgName, wsName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Failed to list data connectors for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
			}
			return
		}

		for _, connectorIntf := range page.Value {
			if connectorIntf == nil {
				continue
			}

			var connectorName, connectorID, connectorType, state, dataTypes string
			riskLevel := "INFO"
			securityIssues := []string{}

			// Type assertion for different connector types
			switch connector := connectorIntf.(type) {
			case *armsecurityinsights.AADDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "Azure Active Directory"
				if connector.Properties != nil {
					// TODO: State property not available in current SDK version
					state = "Unknown"
					/*
					if state != "Connected" {
						riskLevel = "MEDIUM"
						securityIssues = append(securityIssues, fmt.Sprintf("State: %s", state))
						m.LootMap["sentinel-unconnected-sources"].Contents += fmt.Sprintf(
							"Subscription: %s (%s)\nWorkspace: %s/%s\nConnector: %s\nType: %s\nState: %s\n\n",
							subName, subID, rgName, wsName, connectorName, connectorType, state)
					}
					*/
					if connector.Properties.DataTypes != nil {
						dataTypes = "AAD logs"
					}
				}

			case *armsecurityinsights.AATPDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "Azure ATP"
				if connector.Properties != nil {
					if connector.Properties.DataTypes != nil {
						dataTypes = "ATP alerts"
					}
				}

			case *armsecurityinsights.ASCDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "Azure Security Center"
				if connector.Properties != nil {
					// TODO: State property not available in current SDK version
					state = "Unknown"
					if connector.Properties.DataTypes != nil {
						dataTypes = "ASC alerts"
					}
				}

			case *armsecurityinsights.AwsCloudTrailDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "AWS CloudTrail"
				if connector.Properties != nil {
					if connector.Properties.DataTypes != nil {
						dataTypes = "CloudTrail logs"
					}
				}

			case *armsecurityinsights.MCASDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "Microsoft Cloud App Security"
				if connector.Properties != nil {
					// TODO: State property not available in current SDK version
					state = "Unknown"
					if connector.Properties.DataTypes != nil {
						dataTypes = "MCAS alerts and logs"
					}
				}

			case *armsecurityinsights.MDATPDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "Microsoft Defender ATP"
				if connector.Properties != nil {
					if connector.Properties.DataTypes != nil {
						dataTypes = "MDATP alerts"
					}
				}

			case *armsecurityinsights.OfficeDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "Office 365"
				if connector.Properties != nil {
					if connector.Properties.DataTypes != nil {
						dataTypesArr := []string{}
						if connector.Properties.DataTypes.Exchange != nil {
							dataTypesArr = append(dataTypesArr, "Exchange")
						}
						if connector.Properties.DataTypes.SharePoint != nil {
							dataTypesArr = append(dataTypesArr, "SharePoint")
						}
						if connector.Properties.DataTypes.Teams != nil {
							dataTypesArr = append(dataTypesArr, "Teams")
						}
						dataTypes = strings.Join(dataTypesArr, ", ")
					}
				}

			case *armsecurityinsights.TIDataConnector:
				if connector.Name != nil {
					connectorName = *connector.Name
					connectorID = *connector.Name
				}
				connectorType = "Threat Intelligence"
				if connector.Properties != nil {
					if connector.Properties.DataTypes != nil {
						dataTypes = "TI indicators"
					}
				}

			default:
				// Generic data connector
				continue
			}

			if state == "" {
				state = "Unknown"
			}

			issuesStr := strings.Join(securityIssues, "; ")
			if issuesStr == "" {
				issuesStr = "None"
			}

			row := []string{
			m.TenantName,
			m.TenantID,
				subName,
				subID,
				rgName,
				wsName,
				connectorName,
				connectorID,
				connectorType,
				state,
				dataTypes,
				riskLevel,
				issuesStr,
			}

			m.mu.Lock()
			m.DataConnectorRows = append(m.DataConnectorRows, row)
			m.mu.Unlock()

			// Add setup command for disconnected connectors
			if riskLevel != "INFO" {
				m.LootMap["sentinel-setup-commands"].Contents += fmt.Sprintf(
					"# Review disconnected data connector: %s\naz sentinel data-connector show --resource-group %s --workspace-name %s --data-connector-id %s\n\n",
					connectorName, rgName, wsName, connectorID)
			}
		}
	}
}

func (m *SentinelModule) processIncidents(ctx context.Context, subID, subName, rgName, wsName string, logger internal.Logger) int {
	token, err := m.Session.GetTokenForResource("https://management.azure.com/")
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to get token for subscription %s: %v", subID, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return 0
	}

	cred := azinternal.NewStaticTokenCredential(token)
	client, err := armsecurityinsights.NewIncidentsClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Failed to create Incidents client for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
		}
		return 0
	}

	count := 0
	// Filter for active incidents only
	filter := "properties/status ne 'Closed'"
	pager := client.NewListPager(rgName, wsName, &armsecurityinsights.IncidentsClientListOptions{
		Filter: to.Ptr(filter),
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Failed to list incidents for %s/%s: %v", rgName, wsName, err), globals.AZ_SENTINEL_MODULE_NAME)
			}
			return count
		}

		for _, incident := range page.Value {
			if incident == nil || incident.Properties == nil {
				continue
			}

			count++

			var incidentName, incidentID, title, severity, status, createdTime, alertsCount string
			riskLevel := "INFO"
			securityIssues := []string{}

			if incident.Name != nil {
				incidentName = *incident.Name
				incidentID = *incident.Name
			}
			if incident.Properties.Title != nil {
				title = *incident.Properties.Title
			}
			if incident.Properties.Severity != nil {
				severity = string(*incident.Properties.Severity)
				if severity == "High" {
					riskLevel = "HIGH"
					securityIssues = append(securityIssues, "High severity incident")
					m.LootMap["sentinel-high-severity"].Contents += fmt.Sprintf(
						"Subscription: %s (%s)\nWorkspace: %s/%s\nIncident: %s\nTitle: %s\nSeverity: %s\nStatus: %s\nCreated: %s\n\n",
						subName, subID, rgName, wsName, incidentName, title, severity, status, createdTime)
				} else if severity == "Medium" {
					riskLevel = "MEDIUM"
				}
			}
			if incident.Properties.Status != nil {
				status = string(*incident.Properties.Status)
			}
			if incident.Properties.CreatedTimeUTC != nil {
				createdTime = incident.Properties.CreatedTimeUTC.Format("2006-01-02 15:04:05")
			}
			if incident.Properties.AdditionalData != nil && incident.Properties.AdditionalData.AlertsCount != nil {
				alertsCount = fmt.Sprintf("%d", *incident.Properties.AdditionalData.AlertsCount)
			}

			issuesStr := strings.Join(securityIssues, "; ")
			if issuesStr == "" {
				issuesStr = "None"
			}

			row := []string{
			m.TenantName,
			m.TenantID,
				subName,
				subID,
				rgName,
				wsName,
				incidentName,
				title,
				severity,
				status,
				createdTime,
				alertsCount,
				riskLevel,
				issuesStr,
			}

			m.mu.Lock()
			m.IncidentRows = append(m.IncidentRows, row)
			m.mu.Unlock()

			// Add setup command for high severity incidents
			if riskLevel == "HIGH" {
				m.LootMap["sentinel-setup-commands"].Contents += fmt.Sprintf(
					"# Investigate high severity incident: %s\naz sentinel incident show --resource-group %s --workspace-name %s --incident-id %s\n\n",
					title, rgName, wsName, incidentID)
			}
		}
	}

	return count
}

func (m *SentinelModule) generateSummary() {
	m.modLog.Info("Generating Sentinel summary...")

	totalWorkspaces := len(m.WorkspaceRows)
	enabledWorkspaces := 0
	totalRules := len(m.AnalyticsRuleRows)
	disabledRules := 0
	totalAutomationRules := len(m.AutomationRuleRows)
	totalDataConnectors := len(m.DataConnectorRows)
	disconnectedConnectors := 0
	totalIncidents := len(m.IncidentRows)
	highSeverityIncidents := 0

	for _, row := range m.WorkspaceRows {
		if row[5] == "Enabled" {
			enabledWorkspaces++
		}
	}

	for _, row := range m.AnalyticsRuleRows {
		if row[8] == "false" {
			disabledRules++
		}
	}

	for _, row := range m.DataConnectorRows {
		if row[7] != "Connected" && row[7] != "Unknown" {
			disconnectedConnectors++
		}
	}

	for _, row := range m.IncidentRows {
		if row[6] == "High" {
			highSeverityIncidents++
		}
	}

	fmt.Printf("\n[azure] Microsoft Sentinel Summary:\n")
	fmt.Printf("  Sentinel Workspaces: %d total (%d enabled)\n", totalWorkspaces, enabledWorkspaces)
	fmt.Printf("  Analytics Rules: %d total (%d disabled)\n", totalRules, disabledRules)
	fmt.Printf("  Automation Rules: %d total\n", totalAutomationRules)
	fmt.Printf("  Data Connectors: %d total (%d disconnected)\n", totalDataConnectors, disconnectedConnectors)
	fmt.Printf("  Active Incidents: %d total (%d high severity)\n", totalIncidents, highSeverityIncidents)
}

// writeOutput generates and writes output files using HandleOutputSmart
func (m *SentinelModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Generate summary first
	m.generateSummary()

	// Early return if no data
	if len(m.WorkspaceRows) == 0 {
		logger.InfoM("No Sentinel workspaces found", globals.AZ_SENTINEL_MODULE_NAME)
		return
	}

	// Build headers for main table
	var workspaceHeaders []string
	for _, col := range sentinelTableCols {
		workspaceHeaders = append(workspaceHeaders, col.Name)
	}

	// Check multi-tenant splitting FIRST
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.WorkspaceRows, workspaceHeaders,
			"sentinel", globals.AZ_SENTINEL_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check multi-subscription splitting SECOND
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.WorkspaceRows, workspaceHeaders,
			"sentinel", globals.AZ_SENTINEL_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot (only non-empty)
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create tables for multiple outputs
	tables := []internal.TableFile{
		{
			Name:   "sentinel",
			Header: workspaceHeaders,
			Body:   m.WorkspaceRows,
		},
	}

	// Add analytics rules table if we have data
	if len(m.AnalyticsRuleRows) > 0 {
		var analyticsHeaders []string
		for _, col := range analyticsRulesTableCols {
			analyticsHeaders = append(analyticsHeaders, col.Name)
		}
		tables = append(tables, internal.TableFile{
			Name:   "sentinel-analytics-rules",
			Header: analyticsHeaders,
			Body:   m.AnalyticsRuleRows,
		})
	}

	// Add automation rules table if we have data
	if len(m.AutomationRuleRows) > 0 {
		var automationHeaders []string
		for _, col := range automationRulesTableCols {
			automationHeaders = append(automationHeaders, col.Name)
		}
		tables = append(tables, internal.TableFile{
			Name:   "sentinel-automation-rules",
			Header: automationHeaders,
			Body:   m.AutomationRuleRows,
		})
	}

	// Add data connectors table if we have data
	if len(m.DataConnectorRows) > 0 {
		var connectorHeaders []string
		for _, col := range dataConnectorsTableCols {
			connectorHeaders = append(connectorHeaders, col.Name)
		}
		tables = append(tables, internal.TableFile{
			Name:   "sentinel-data-connectors",
			Header: connectorHeaders,
			Body:   m.DataConnectorRows,
		})
	}

	// Add incidents table if we have data
	if len(m.IncidentRows) > 0 {
		var incidentHeaders []string
		for _, col := range incidentsTableCols {
			incidentHeaders = append(incidentHeaders, col.Name)
		}
		tables = append(tables, internal.TableFile{
			Name:   "sentinel-incidents",
			Header: incidentHeaders,
			Body:   m.IncidentRows,
		})
	}

	// Create output struct
	output := SentinelOutput{
		Table: tables,
		Loot:  loot,
	}

	// Determine scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart
	if err := internal.HandleOutputSmart(
		"Azure",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIDs,
		scopeNames,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_SENTINEL_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Sentinel workspace(s) across %d subscription(s)",
		len(m.WorkspaceRows), len(m.Subscriptions)), globals.AZ_SENTINEL_MODULE_NAME)
}

// SentinelOutput implements the output interface
type SentinelOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SentinelOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SentinelOutput) LootFiles() []internal.LootFile   { return o.Loot }

// Table column definitions
var sentinelTableCols = []internal.TableCol{
	{Name: "Tenant Name", Width: 25},
	{Name: "Tenant ID", Width: 36},
	{Name: "Subscription", Width: 25},
	{Name: "SubscriptionID", Width: 36},
	{Name: "ResourceGroup", Width: 30},
	{Name: "WorkspaceName", Width: 30},
	{Name: "WorkspaceID", Width: 50},
	{Name: "SentinelStatus", Width: 15},
	{Name: "AutomationRules", Width: 15},
	{Name: "ActiveIncidents", Width: 15},
	{Name: "RiskLevel", Width: 10},
	{Name: "SecurityIssues", Width: 60},
}

var analyticsRulesTableCols = []internal.TableCol{
	{Name: "Tenant Name", Width: 25},
	{Name: "Tenant ID", Width: 36},
	{Name: "Subscription", Width: 25},
	{Name: "SubscriptionID", Width: 36},
	{Name: "ResourceGroup", Width: 30},
	{Name: "WorkspaceName", Width: 30},
	{Name: "RuleName", Width: 40},
	{Name: "RuleID", Width: 36},
	{Name: "RuleType", Width: 20},
	{Name: "Severity", Width: 10},
	{Name: "Enabled", Width: 10},
	{Name: "Tactics", Width: 40},
	{Name: "Techniques", Width: 30},
	{Name: "RiskLevel", Width: 10},
	{Name: "SecurityIssues", Width: 60},
}

var automationRulesTableCols = []internal.TableCol{
	{Name: "Tenant Name", Width: 25},
	{Name: "Tenant ID", Width: 36},
	{Name: "Subscription", Width: 25},
	{Name: "SubscriptionID", Width: 36},
	{Name: "ResourceGroup", Width: 30},
	{Name: "WorkspaceName", Width: 30},
	{Name: "RuleName", Width: 40},
	{Name: "RuleID", Width: 36},
	{Name: "Order", Width: 10},
	{Name: "Enabled", Width: 10},
	{Name: "TriggerConditions", Width: 20},
	{Name: "Actions", Width: 20},
	{Name: "RiskLevel", Width: 10},
	{Name: "SecurityIssues", Width: 60},
}

var dataConnectorsTableCols = []internal.TableCol{
	{Name: "Tenant Name", Width: 25},
	{Name: "Tenant ID", Width: 36},
	{Name: "Subscription", Width: 25},
	{Name: "SubscriptionID", Width: 36},
	{Name: "ResourceGroup", Width: 30},
	{Name: "WorkspaceName", Width: 30},
	{Name: "ConnectorName", Width: 40},
	{Name: "ConnectorID", Width: 36},
	{Name: "ConnectorType", Width: 30},
	{Name: "State", Width: 15},
	{Name: "DataTypes", Width: 40},
	{Name: "RiskLevel", Width: 10},
	{Name: "SecurityIssues", Width: 60},
}

var incidentsTableCols = []internal.TableCol{
	{Name: "Tenant Name", Width: 25},
	{Name: "Tenant ID", Width: 36},
	{Name: "Subscription", Width: 25},
	{Name: "SubscriptionID", Width: 36},
	{Name: "ResourceGroup", Width: 30},
	{Name: "WorkspaceName", Width: 30},
	{Name: "IncidentID", Width: 36},
	{Name: "Title", Width: 50},
	{Name: "Severity", Width: 10},
	{Name: "Status", Width: 15},
	{Name: "CreatedTime", Width: 20},
	{Name: "AlertsCount", Width: 12},
	{Name: "RiskLevel", Width: 10},
	{Name: "SecurityIssues", Width: 60},
}

var AzSentinelCommand = &cobra.Command{
	Use:   "sentinel",
	Short: "Enumerate Microsoft Sentinel (SIEM) workspaces, analytics rules, automation, and incidents",
	Long: `
Enumerate Microsoft Sentinel (Azure's cloud-native SIEM/SOAR solution) configuration:
  - Sentinel-enabled Log Analytics workspaces
  - Analytics rules (detection rules) and their configuration
  - Automation rules for incident response
  - Data connectors and their connection status
  - Active security incidents

Examples:
  cloudfox azure sentinel --profile test_tenant
  cloudfox azure sentinel --tenant-id <tenant-id> --subscription-id <sub-id>

Security Focus:
  - Identifies disabled analytics rules that may miss threats
  - Finds workspaces without automation rules configured
  - Lists disconnected data connectors reducing visibility
  - Highlights high-severity active incidents requiring response
  - Assesses overall SIEM coverage and effectiveness
`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize command context
		cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_SENTINEL_MODULE_NAME)
		if err != nil {
			return // error already logged by helper
		}
		defer cmdCtx.Session.StopMonitoring()

		// Initialize module
		m := &SentinelModule{
			BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
			Subscriptions:   cmdCtx.Subscriptions, // Use pre-fetched subscriptions from context
			Caller:          "sentinel",
			LootMap: map[string]*internal.LootFile{
				"sentinel-disabled-rules":      {Name: "sentinel-disabled-rules.txt", Contents: ""},
				"sentinel-unconnected-sources": {Name: "sentinel-unconnected-sources.txt", Contents: ""},
				"sentinel-setup-commands":      {Name: "sentinel-setup-commands.txt", Contents: ""},
			},
		}

		m.PrintSentinelCommand(cmdCtx.Ctx, cmdCtx.Logger)
	},
}

func init() {
	// Flags are handled by parent command (cli.AzCommands.PersistentFlags)
}
