package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"google.golang.org/api/iterator"
)

// Module name constant
const GCP_MONITORINGALERTS_MODULE_NAME string = "monitoring-alerts"

var GCPMonitoringAlertsCommand = &cobra.Command{
	Use:     GCP_MONITORINGALERTS_MODULE_NAME,
	Aliases: []string{"alerts", "monitoring", "alerting"},
	Hidden:  true,
	Short:   "Enumerate Cloud Monitoring alerting policies and notification channels",
	Long: `Analyze Cloud Monitoring alerting policies and notification channels for security gaps.

Features:
- Lists all alerting policies and their conditions
- Identifies disabled or misconfigured alerts
- Enumerates notification channels and their verification status
- Detects missing critical security alerts
- Identifies uptime check configurations
- Analyzes alert policy coverage gaps

Required Security Alerts to Check:
- IAM policy changes
- Firewall rule changes
- VPC network changes
- Service account key creation
- Custom role changes
- Audit log configuration changes
- Cloud SQL authorization changes

Requires appropriate IAM permissions:
- roles/monitoring.viewer
- roles/monitoring.alertPolicyViewer`,
	Run: runGCPMonitoringAlertsCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type AlertPolicy struct {
	Name                 string
	DisplayName          string
	ProjectID            string
	Enabled              bool
	Combiner             string
	Documentation        string
	Conditions           []AlertCondition
	NotificationChannels []string // Channel resource names
}

type AlertCondition struct {
	Name            string
	DisplayName     string
	ResourceType    string
	MetricType      string
	Filter          string
	ThresholdValue  float64
	Duration        string
	Comparison      string
	Aggregation     string
}

type NotificationChannel struct {
	Name         string
	DisplayName  string
	ProjectID    string
	Type         string // email, slack, pagerduty, webhook, sms, pubsub
	Enabled      bool
	Verified     bool
	Labels       map[string]string
	CreationTime string
	MutationTime string
}

type UptimeCheck struct {
	Name           string
	DisplayName    string
	ProjectID      string
	MonitoredHost  string
	ResourceType   string
	Protocol       string
	Port           int32
	Path           string
	Period         string
	Timeout        string
	SelectedRegion []string
	Enabled        bool
	SSLEnabled     bool
}


// ------------------------------
// Module Struct
// ------------------------------
type MonitoringAlertsModule struct {
	gcpinternal.BaseGCPModule

	ProjectAlertPolicies        map[string][]AlertPolicy           // projectID -> policies
	ProjectNotificationChannels map[string][]NotificationChannel   // projectID -> channels
	ProjectUptimeChecks         map[string][]UptimeCheck           // projectID -> checks
	LootMap                     map[string]map[string]*internal.LootFile // projectID -> loot files
	mu                          sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type MonitoringAlertsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o MonitoringAlertsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o MonitoringAlertsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPMonitoringAlertsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_MONITORINGALERTS_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &MonitoringAlertsModule{
		BaseGCPModule:               gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectAlertPolicies:        make(map[string][]AlertPolicy),
		ProjectNotificationChannels: make(map[string][]NotificationChannel),
		ProjectUptimeChecks:         make(map[string][]UptimeCheck),
		LootMap:                     make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *MonitoringAlertsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Create Monitoring client
	alertClient, err := monitoring.NewAlertPolicyClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Alert Policy client: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		return
	}
	defer alertClient.Close()

	channelClient, err := monitoring.NewNotificationChannelClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Notification Channel client: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		return
	}
	defer channelClient.Close()

	uptimeClient, err := monitoring.NewUptimeCheckClient(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Uptime Check client: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		}
	}
	if uptimeClient != nil {
		defer uptimeClient.Close()
	}

	// Process each project
	for _, projectID := range m.ProjectIDs {
		m.processProject(ctx, projectID, alertClient, channelClient, uptimeClient, logger)
	}

	// Check results
	allPolicies := m.getAllAlertPolicies()
	allChannels := m.getAllNotificationChannels()
	allChecks := m.getAllUptimeChecks()

	if len(allPolicies) == 0 && len(allChannels) == 0 {
		logger.InfoM("No monitoring alerts or notification channels found", GCP_MONITORINGALERTS_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d alert policy(ies), %d notification channel(s), %d uptime check(s)",
		len(allPolicies), len(allChannels), len(allChecks)), GCP_MONITORINGALERTS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *MonitoringAlertsModule) getAllAlertPolicies() []AlertPolicy {
	var all []AlertPolicy
	for _, policies := range m.ProjectAlertPolicies {
		all = append(all, policies...)
	}
	return all
}

func (m *MonitoringAlertsModule) getAllNotificationChannels() []NotificationChannel {
	var all []NotificationChannel
	for _, channels := range m.ProjectNotificationChannels {
		all = append(all, channels...)
	}
	return all
}

func (m *MonitoringAlertsModule) getAllUptimeChecks() []UptimeCheck {
	var all []UptimeCheck
	for _, checks := range m.ProjectUptimeChecks {
		all = append(all, checks...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *MonitoringAlertsModule) processProject(ctx context.Context, projectID string, alertClient *monitoring.AlertPolicyClient, channelClient *monitoring.NotificationChannelClient, uptimeClient *monitoring.UptimeCheckClient, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating monitoring for project: %s", projectID), GCP_MONITORINGALERTS_MODULE_NAME)
	}

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["monitoring-alerts-commands"] = &internal.LootFile{
			Name:     "monitoring-alerts-commands",
			Contents: "# Monitoring Alerts Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
	m.mu.Unlock()

	// List alert policies
	m.enumerateAlertPolicies(ctx, projectID, alertClient, logger)

	// List notification channels
	m.enumerateNotificationChannels(ctx, projectID, channelClient, logger)

	// List uptime checks
	if uptimeClient != nil {
		m.enumerateUptimeChecks(ctx, projectID, uptimeClient, logger)
	}
}

func (m *MonitoringAlertsModule) enumerateAlertPolicies(ctx context.Context, projectID string, client *monitoring.AlertPolicyClient, logger internal.Logger) {
	parent := fmt.Sprintf("projects/%s", projectID)

	req := &monitoringpb.ListAlertPoliciesRequest{
		Name: parent,
	}

	it := client.ListAlertPolicies(ctx, req)
	for {
		policy, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_MONITORINGALERTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate alert policies in project %s", projectID))
			break
		}

		alertPolicy := AlertPolicy{
			Name:                 policy.Name,
			DisplayName:          policy.DisplayName,
			ProjectID:            projectID,
			Enabled:              policy.Enabled.GetValue(),
			Combiner:             policy.Combiner.String(),
			NotificationChannels: policy.NotificationChannels,
		}

		if policy.Documentation != nil {
			alertPolicy.Documentation = policy.Documentation.Content
		}

		// Parse conditions
		for _, cond := range policy.Conditions {
			condition := AlertCondition{
				Name:        cond.Name,
				DisplayName: cond.DisplayName,
			}

			// Parse based on condition type
			switch c := cond.Condition.(type) {
			case *monitoringpb.AlertPolicy_Condition_ConditionThreshold:
				if c.ConditionThreshold != nil {
					condition.Filter = c.ConditionThreshold.Filter
					condition.Comparison = c.ConditionThreshold.Comparison.String()
					condition.ThresholdValue = c.ConditionThreshold.ThresholdValue

					if c.ConditionThreshold.Duration != nil {
						condition.Duration = c.ConditionThreshold.Duration.String()
					}

					condition.MetricType = m.extractMetricType(c.ConditionThreshold.Filter)
				}
			case *monitoringpb.AlertPolicy_Condition_ConditionAbsent:
				if c.ConditionAbsent != nil {
					condition.Filter = c.ConditionAbsent.Filter
					condition.MetricType = m.extractMetricType(c.ConditionAbsent.Filter)
				}
			case *monitoringpb.AlertPolicy_Condition_ConditionMonitoringQueryLanguage:
				if c.ConditionMonitoringQueryLanguage != nil {
					condition.Filter = c.ConditionMonitoringQueryLanguage.Query
				}
			}

			alertPolicy.Conditions = append(alertPolicy.Conditions, condition)
		}

		m.mu.Lock()
		m.ProjectAlertPolicies[projectID] = append(m.ProjectAlertPolicies[projectID], alertPolicy)
		m.mu.Unlock()
	}
}

func (m *MonitoringAlertsModule) enumerateNotificationChannels(ctx context.Context, projectID string, client *monitoring.NotificationChannelClient, logger internal.Logger) {
	parent := fmt.Sprintf("projects/%s", projectID)

	req := &monitoringpb.ListNotificationChannelsRequest{
		Name: parent,
	}

	it := client.ListNotificationChannels(ctx, req)
	for {
		channel, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_MONITORINGALERTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate notification channels in project %s", projectID))
			break
		}

		notifChannel := NotificationChannel{
			Name:        channel.Name,
			DisplayName: channel.DisplayName,
			ProjectID:   projectID,
			Type:        channel.Type,
			Enabled:     channel.Enabled.GetValue(),
			Labels:      channel.Labels,
		}

		// Check verification status
		if channel.VerificationStatus == monitoringpb.NotificationChannel_VERIFIED {
			notifChannel.Verified = true
		}

		if channel.CreationRecord != nil {
			notifChannel.CreationTime = channel.CreationRecord.MutateTime.AsTime().String()
		}

		// MutationRecords is a slice - get the most recent one
		if len(channel.MutationRecords) > 0 {
			lastMutation := channel.MutationRecords[len(channel.MutationRecords)-1]
			if lastMutation != nil {
				notifChannel.MutationTime = lastMutation.MutateTime.AsTime().String()
			}
		}

		m.mu.Lock()
		m.ProjectNotificationChannels[projectID] = append(m.ProjectNotificationChannels[projectID], notifChannel)
		m.mu.Unlock()
	}
}

func (m *MonitoringAlertsModule) enumerateUptimeChecks(ctx context.Context, projectID string, client *monitoring.UptimeCheckClient, logger internal.Logger) {
	parent := fmt.Sprintf("projects/%s", projectID)

	req := &monitoringpb.ListUptimeCheckConfigsRequest{
		Parent: parent,
	}

	it := client.ListUptimeCheckConfigs(ctx, req)
	for {
		check, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_MONITORINGALERTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate uptime checks in project %s", projectID))
			break
		}

		uptimeCheck := UptimeCheck{
			Name:        check.Name,
			DisplayName: check.DisplayName,
			ProjectID:   projectID,
			Enabled:     !check.IsInternal, // Active checks returned by API are enabled; internal checks are system-managed
		}

		// Parse resource type
		switch r := check.Resource.(type) {
		case *monitoringpb.UptimeCheckConfig_MonitoredResource:
			if r.MonitoredResource != nil {
				uptimeCheck.ResourceType = r.MonitoredResource.Type
				if host, ok := r.MonitoredResource.Labels["host"]; ok {
					uptimeCheck.MonitoredHost = host
				}
			}
		}

		// Parse check request details
		switch cr := check.CheckRequestType.(type) {
		case *monitoringpb.UptimeCheckConfig_HttpCheck_:
			if cr.HttpCheck != nil {
				uptimeCheck.Protocol = "HTTP"
				uptimeCheck.Port = cr.HttpCheck.Port
				uptimeCheck.Path = cr.HttpCheck.Path
				if cr.HttpCheck.UseSsl {
					uptimeCheck.Protocol = "HTTPS"
					uptimeCheck.SSLEnabled = true
				}
			}
		case *monitoringpb.UptimeCheckConfig_TcpCheck_:
			if cr.TcpCheck != nil {
				uptimeCheck.Protocol = "TCP"
				uptimeCheck.Port = cr.TcpCheck.Port
			}
		}

		if check.Period != nil {
			uptimeCheck.Period = check.Period.String()
		}

		if check.Timeout != nil {
			uptimeCheck.Timeout = check.Timeout.String()
		}

		// Check regions
		for _, region := range check.SelectedRegions {
			uptimeCheck.SelectedRegion = append(uptimeCheck.SelectedRegion, region.String())
		}

		m.mu.Lock()
		m.ProjectUptimeChecks[projectID] = append(m.ProjectUptimeChecks[projectID], uptimeCheck)
		m.mu.Unlock()
	}
}


// ------------------------------
// Helper Functions
// ------------------------------
func (m *MonitoringAlertsModule) extractMetricType(filter string) string {
	// Extract metric type from filter string
	// Format: metric.type="..." or resource.type="..."
	if strings.Contains(filter, "metric.type=") {
		parts := strings.Split(filter, "metric.type=")
		if len(parts) > 1 {
			metricPart := strings.Split(parts[1], " ")[0]
			return strings.Trim(metricPart, "\"")
		}
	}
	return ""
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *MonitoringAlertsModule) addPolicyToLoot(projectID string, p AlertPolicy) {
	lootFile := m.LootMap[projectID]["monitoring-alerts-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# POLICY: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe alert policy:\n"+
			"gcloud alpha monitoring policies describe %s --project=%s\n\n",
		p.DisplayName,
		p.ProjectID,
		extractResourceName(p.Name), p.ProjectID,
	)
}

func (m *MonitoringAlertsModule) addChannelToLoot(projectID string, c NotificationChannel) {
	lootFile := m.LootMap[projectID]["monitoring-alerts-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# CHANNEL: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe notification channel:\n"+
			"gcloud alpha monitoring channels describe %s --project=%s\n\n",
		c.DisplayName,
		c.ProjectID,
		extractResourceName(c.Name), c.ProjectID,
	)
}

func (m *MonitoringAlertsModule) addUptimeCheckToLoot(projectID string, u UptimeCheck) {
	lootFile := m.LootMap[projectID]["monitoring-alerts-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# UPTIME CHECK: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe uptime check:\n"+
			"gcloud alpha monitoring uptime describe %s --project=%s\n\n",
		u.DisplayName,
		u.ProjectID,
		extractResourceName(u.Name), u.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *MonitoringAlertsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *MonitoringAlertsModule) getPoliciesHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Policy Name",
		"Enabled",
		"Condition Name",
		"Metric Type",
		"Comparison",
		"Threshold",
		"Duration",
		"Notification Channels",
	}
}

func (m *MonitoringAlertsModule) getChannelsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Channel Name",
		"Type",
		"Enabled",
		"Verified",
		"Destination",
	}
}

func (m *MonitoringAlertsModule) getUptimeHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Check Name",
		"Enabled",
		"Host",
		"Protocol",
		"Port",
		"Path",
		"Period",
		"Timeout",
		"SSL Enabled",
	}
}

func (m *MonitoringAlertsModule) policiesToTableBody(policies []AlertPolicy, channelNameMap map[string]string) [][]string {
	var body [][]string
	for _, p := range policies {
		// Resolve notification channel names
		var channelNames []string
		for _, channelRef := range p.NotificationChannels {
			if name, ok := channelNameMap[channelRef]; ok {
				channelNames = append(channelNames, name)
			} else {
				parts := strings.Split(channelRef, "/")
				if len(parts) > 0 {
					channelNames = append(channelNames, parts[len(parts)-1])
				}
			}
		}
		notificationChannelsStr := "-"
		if len(channelNames) > 0 {
			notificationChannelsStr = strings.Join(channelNames, ", ")
		}

		if len(p.Conditions) > 0 {
			for _, cond := range p.Conditions {
				metricType := cond.MetricType
				if metricType == "" {
					metricType = "-"
				}
				comparison := cond.Comparison
				if comparison == "" {
					comparison = "-"
				}
				threshold := "-"
				if cond.ThresholdValue != 0 {
					threshold = fmt.Sprintf("%.2f", cond.ThresholdValue)
				}
				duration := cond.Duration
				if duration == "" {
					duration = "-"
				}

				body = append(body, []string{
					m.GetProjectName(p.ProjectID),
					p.ProjectID,
					p.DisplayName,
					shared.BoolToYesNo(p.Enabled),
					cond.DisplayName,
					metricType,
					comparison,
					threshold,
					duration,
					notificationChannelsStr,
				})
			}
		} else {
			body = append(body, []string{
				m.GetProjectName(p.ProjectID),
				p.ProjectID,
				p.DisplayName,
				shared.BoolToYesNo(p.Enabled),
				"-",
				"-",
				"-",
				"-",
				"-",
				notificationChannelsStr,
			})
		}
	}
	return body
}

func (m *MonitoringAlertsModule) channelsToTableBody(channels []NotificationChannel) [][]string {
	var body [][]string
	for _, c := range channels {
		destination := extractChannelDestination(c.Type, c.Labels)
		body = append(body, []string{
			m.GetProjectName(c.ProjectID),
			c.ProjectID,
			c.DisplayName,
			c.Type,
			shared.BoolToYesNo(c.Enabled),
			shared.BoolToYesNo(c.Verified),
			destination,
		})
	}
	return body
}

func (m *MonitoringAlertsModule) uptimeToTableBody(checks []UptimeCheck) [][]string {
	var body [][]string
	for _, u := range checks {
		host := u.MonitoredHost
		if host == "" {
			host = "-"
		}
		path := u.Path
		if path == "" {
			path = "-"
		}
		timeout := u.Timeout
		if timeout == "" {
			timeout = "-"
		}

		body = append(body, []string{
			m.GetProjectName(u.ProjectID),
			u.ProjectID,
			u.DisplayName,
			shared.BoolToYesNo(u.Enabled),
			host,
			u.Protocol,
			fmt.Sprintf("%d", u.Port),
			path,
			u.Period,
			timeout,
			shared.BoolToYesNo(u.SSLEnabled),
		})
	}
	return body
}

func (m *MonitoringAlertsModule) buildTablesForProject(projectID string, channelNameMap map[string]string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if policies, ok := m.ProjectAlertPolicies[projectID]; ok && len(policies) > 0 {
		sort.Slice(policies, func(i, j int) bool {
			return policies[i].DisplayName < policies[j].DisplayName
		})
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "alerting-policies",
			Header: m.getPoliciesHeader(),
			Body:   m.policiesToTableBody(policies, channelNameMap),
		})
		for _, p := range policies {
			m.addPolicyToLoot(projectID, p)
		}
	}

	if channels, ok := m.ProjectNotificationChannels[projectID]; ok && len(channels) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "notification-channels",
			Header: m.getChannelsHeader(),
			Body:   m.channelsToTableBody(channels),
		})
		for _, c := range channels {
			m.addChannelToLoot(projectID, c)
		}
	}

	if checks, ok := m.ProjectUptimeChecks[projectID]; ok && len(checks) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "uptime-checks",
			Header: m.getUptimeHeader(),
			Body:   m.uptimeToTableBody(checks),
		})
		for _, u := range checks {
			m.addUptimeCheckToLoot(projectID, u)
		}
	}

	return tableFiles
}

func (m *MonitoringAlertsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// Build notification channel name map
	channelNameMap := make(map[string]string)
	for _, channels := range m.ProjectNotificationChannels {
		for _, c := range channels {
			channelNameMap[c.Name] = c.DisplayName
		}
	}

	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectAlertPolicies {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectNotificationChannels {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectUptimeChecks {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		tableFiles := m.buildTablesForProject(projectID, channelNameMap)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = MonitoringAlertsOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
	}
}

func (m *MonitoringAlertsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	// Build notification channel name map
	channelNameMap := make(map[string]string)
	for _, channels := range m.ProjectNotificationChannels {
		for _, c := range channels {
			channelNameMap[c.Name] = c.DisplayName
		}
	}

	allPolicies := m.getAllAlertPolicies()
	allChannels := m.getAllNotificationChannels()
	allChecks := m.getAllUptimeChecks()

	sort.Slice(allPolicies, func(i, j int) bool {
		return allPolicies[i].DisplayName < allPolicies[j].DisplayName
	})

	var tables []internal.TableFile

	if len(allPolicies) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "alerting-policies",
			Header: m.getPoliciesHeader(),
			Body:   m.policiesToTableBody(allPolicies, channelNameMap),
		})
	}

	if len(allChannels) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "notification-channels",
			Header: m.getChannelsHeader(),
			Body:   m.channelsToTableBody(allChannels),
		})
	}

	if len(allChecks) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "uptime-checks",
			Header: m.getUptimeHeader(),
			Body:   m.uptimeToTableBody(allChecks),
		})
	}

	// Populate loot for flat output
	for projectID, policies := range m.ProjectAlertPolicies {
		for _, p := range policies {
			m.addPolicyToLoot(projectID, p)
		}
	}
	for projectID, channels := range m.ProjectNotificationChannels {
		for _, c := range channels {
			m.addChannelToLoot(projectID, c)
		}
	}
	for projectID, checks := range m.ProjectUptimeChecks {
		for _, u := range checks {
			m.addUptimeCheckToLoot(projectID, u)
		}
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := MonitoringAlertsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// extractChannelDestination extracts the destination info from channel labels
func extractChannelDestination(channelType string, labels map[string]string) string {
	if labels == nil {
		return "-"
	}

	switch channelType {
	case "email":
		if email, ok := labels["email_address"]; ok {
			return email
		}
	case "slack":
		if channel, ok := labels["channel_name"]; ok {
			return channel
		}
	case "pagerduty":
		if key, ok := labels["service_key"]; ok {
			// Truncate service key for display
			if len(key) > 12 {
				return key[:12] + "..."
			}
			return key
		}
	case "webhook_tokenauth", "webhook_basicauth":
		if url, ok := labels["url"]; ok {
			return url
		}
	case "pubsub":
		if topic, ok := labels["topic"]; ok {
			return topic
		}
	case "sms":
		if number, ok := labels["number"]; ok {
			return number
		}
	}

	// Try common label keys
	for _, key := range []string{"url", "address", "endpoint", "target"} {
		if val, ok := labels[key]; ok {
			return val
		}
	}

	return "-"
}
