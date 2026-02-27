package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	LoggingService "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPLoggingCommand = &cobra.Command{
	Use:     globals.GCP_LOGGING_MODULE_NAME,
	Aliases: []string{"logs", "sinks", "log-sinks", "logging-gaps"},
	Short:   "Enumerate Cloud Logging configuration including sinks, metrics, and logging gaps",
	Long: `Enumerate Cloud Logging configuration across projects including sinks, metrics, and logging gaps.

Features:
- Lists all logging sinks (log exports)
- Shows sink destinations (Storage, BigQuery, Pub/Sub, Logging buckets)
- Identifies cross-project log exports
- Shows sink filters and exclusions
- Lists log-based metrics for alerting
- Identifies resources with missing or incomplete logging
- Generates gcloud commands for logging enumeration

Log Sinks:
- Destination: Where logs are exported (bucket, dataset, topic)
- CrossProject: Whether logs are exported to another project
- WriterIdentity: Service account used for export
- Filter: What logs are included/excluded

Logging Gaps (resources with incomplete logging):
- Cloud Storage buckets without access logging
- VPC subnets without flow logs
- GKE clusters with incomplete logging configuration
- Cloud SQL instances without query/connection logging

Security Considerations:
- Cross-project exports may leak logs to external projects
- Sink writer identity may have excessive permissions
- Disabled sinks may indicate log evasion
- Missing logging on resources creates detection blind spots`,
	Run: runGCPLoggingCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type LoggingModule struct {
	gcpinternal.BaseGCPModule

	ProjectSinks   map[string][]LoggingService.SinkInfo      // projectID -> sinks
	ProjectMetrics map[string][]LoggingService.MetricInfo    // projectID -> metrics
	ProjectGaps    map[string][]LoggingService.LoggingGap    // projectID -> logging gaps
	LootMap        map[string]map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type LoggingOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LoggingOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LoggingOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPLoggingCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_LOGGING_MODULE_NAME)
	if err != nil {
		return
	}

	module := &LoggingModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectSinks:   make(map[string][]LoggingService.SinkInfo),
		ProjectMetrics: make(map[string][]LoggingService.MetricInfo),
		ProjectGaps:    make(map[string][]LoggingService.LoggingGap),
		LootMap:        make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LoggingModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_LOGGING_MODULE_NAME, m.processProject)

	allSinks := m.getAllSinks()
	allMetrics := m.getAllMetrics()
	allGaps := m.getAllGaps()

	if len(allSinks) == 0 && len(allMetrics) == 0 && len(allGaps) == 0 {
		logger.InfoM("No logging configuration found", globals.GCP_LOGGING_MODULE_NAME)
		return
	}

	// Count interesting sinks
	crossProjectCount := 0
	disabledCount := 0
	for _, sink := range allSinks {
		if sink.IsCrossProject {
			crossProjectCount++
		}
		if sink.Disabled {
			disabledCount++
		}
	}

	msg := fmt.Sprintf("Found %d sink(s), %d metric(s), %d logging gap(s)", len(allSinks), len(allMetrics), len(allGaps))
	if crossProjectCount > 0 {
		msg += fmt.Sprintf(" [%d cross-project]", crossProjectCount)
	}
	if disabledCount > 0 {
		msg += fmt.Sprintf(" [%d disabled]", disabledCount)
	}
	logger.SuccessM(msg, globals.GCP_LOGGING_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllSinks returns all sinks from all projects
func (m *LoggingModule) getAllSinks() []LoggingService.SinkInfo {
	var all []LoggingService.SinkInfo
	for _, sinks := range m.ProjectSinks {
		all = append(all, sinks...)
	}
	return all
}

// getAllMetrics returns all metrics from all projects
func (m *LoggingModule) getAllMetrics() []LoggingService.MetricInfo {
	var all []LoggingService.MetricInfo
	for _, metrics := range m.ProjectMetrics {
		all = append(all, metrics...)
	}
	return all
}

// getAllGaps returns all logging gaps from all projects
func (m *LoggingModule) getAllGaps() []LoggingService.LoggingGap {
	var all []LoggingService.LoggingGap
	for _, gaps := range m.ProjectGaps {
		all = append(all, gaps...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LoggingModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Logging in project: %s", projectID), globals.GCP_LOGGING_MODULE_NAME)
	}

	ls := LoggingService.New()

	var projectSinks []LoggingService.SinkInfo
	var projectMetrics []LoggingService.MetricInfo
	var projectGaps []LoggingService.LoggingGap

	// Get sinks
	sinks, err := ls.Sinks(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_LOGGING_MODULE_NAME,
			fmt.Sprintf("Could not enumerate logging sinks in project %s", projectID))
	} else {
		projectSinks = append(projectSinks, sinks...)
	}

	// Get metrics
	metrics, err := ls.Metrics(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_LOGGING_MODULE_NAME,
			fmt.Sprintf("Could not enumerate log metrics in project %s", projectID))
	} else {
		projectMetrics = append(projectMetrics, metrics...)
	}

	// Get logging gaps
	gaps, err := ls.LoggingGaps(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_LOGGING_MODULE_NAME,
				fmt.Sprintf("Could not enumerate logging gaps in project %s", projectID))
		}
	} else {
		projectGaps = append(projectGaps, gaps...)
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectSinks[projectID] = projectSinks
	m.ProjectMetrics[projectID] = projectMetrics
	m.ProjectGaps[projectID] = projectGaps

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["logging-commands"] = &internal.LootFile{
			Name:     "logging-commands",
			Contents: "# Cloud Logging Enumeration Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	m.generateLootCommands(projectID, projectSinks, projectMetrics, projectGaps)
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d sink(s), %d metric(s), %d gap(s) in project %s", len(projectSinks), len(projectMetrics), len(projectGaps), projectID), globals.GCP_LOGGING_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LoggingModule) generateLootCommands(projectID string, sinks []LoggingService.SinkInfo, metrics []LoggingService.MetricInfo, gaps []LoggingService.LoggingGap) {
	lootFile := m.LootMap[projectID]["logging-commands"]
	if lootFile == nil {
		return
	}

	// Project-level logging enumeration
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# PROJECT: %s\n"+
			"# =============================================================================\n\n", projectID)

	// Sinks enumeration commands
	lootFile.Contents += "# === LOG SINKS ===\n\n"
	lootFile.Contents += fmt.Sprintf("gcloud logging sinks list --project=%s\n\n", projectID)

	for _, sink := range sinks {
		lootFile.Contents += fmt.Sprintf("# Sink: %s (%s)\n", sink.Name, sink.DestinationType)
		lootFile.Contents += fmt.Sprintf("gcloud logging sinks describe %s --project=%s\n", sink.Name, projectID)

		// Add destination-specific enumeration commands
		switch sink.DestinationType {
		case "storage":
			if sink.DestinationBucket != "" {
				lootFile.Contents += fmt.Sprintf("# Check bucket logging destination:\ngsutil ls gs://%s/\n", sink.DestinationBucket)
			}
		case "bigquery":
			if sink.DestinationDataset != "" {
				destProject := sink.DestinationProject
				if destProject == "" {
					destProject = projectID
				}
				lootFile.Contents += fmt.Sprintf("# Check BigQuery logging destination:\nbq ls %s:%s\n", destProject, sink.DestinationDataset)
			}
		case "pubsub":
			if sink.DestinationTopic != "" {
				destProject := sink.DestinationProject
				if destProject == "" {
					destProject = projectID
				}
				lootFile.Contents += fmt.Sprintf("# Check Pub/Sub logging destination:\ngcloud pubsub topics describe %s --project=%s\n", sink.DestinationTopic, destProject)
			}
		}

		if sink.IsCrossProject {
			lootFile.Contents += fmt.Sprintf("# NOTE: Cross-project export to %s\n", sink.DestinationProject)
		}
		lootFile.Contents += "\n"
	}

	// Metrics enumeration commands
	if len(metrics) > 0 {
		lootFile.Contents += "# === LOG-BASED METRICS ===\n\n"
		lootFile.Contents += fmt.Sprintf("gcloud logging metrics list --project=%s\n\n", projectID)

		for _, metric := range metrics {
			lootFile.Contents += fmt.Sprintf("# Metric: %s\n", metric.Name)
			lootFile.Contents += fmt.Sprintf("gcloud logging metrics describe %s --project=%s\n\n", metric.Name, projectID)
		}
	}

	// Logging gaps enumeration commands
	if len(gaps) > 0 {
		lootFile.Contents += "# === LOGGING GAPS ===\n\n"
		lootFile.Contents += "# Commands to verify logging configuration on resources with gaps\n\n"

		for _, gap := range gaps {
			lootFile.Contents += fmt.Sprintf("# %s: %s (%s) - %s\n", gap.ResourceType, gap.ResourceName, gap.Location, gap.LoggingStatus)
			lootFile.Contents += fmt.Sprintf("# Missing: %s\n", strings.Join(gap.MissingLogs, ", "))

			switch gap.ResourceType {
			case "bucket":
				lootFile.Contents += fmt.Sprintf("gsutil logging get gs://%s\n", gap.ResourceName)
			case "subnet":
				lootFile.Contents += fmt.Sprintf("gcloud compute networks subnets describe %s --region=%s --project=%s --format='value(logConfig)'\n", gap.ResourceName, gap.Location, projectID)
			case "gke":
				lootFile.Contents += fmt.Sprintf("gcloud container clusters describe %s --location=%s --project=%s --format='value(loggingService,loggingConfig)'\n", gap.ResourceName, gap.Location, projectID)
			case "cloudsql":
				lootFile.Contents += fmt.Sprintf("gcloud sql instances describe %s --project=%s --format='value(settings.databaseFlags)'\n", gap.ResourceName, projectID)
			}
			lootFile.Contents += "\n"
		}
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LoggingModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getSinksHeader returns the header for sinks table
func (m *LoggingModule) getSinksHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Sink Name",
		"Destination Type",
		"Destination",
		"Cross-Project",
		"Disabled",
		"Writer Identity",
		"Filter",
	}
}

// getMetricsHeader returns the header for metrics table
func (m *LoggingModule) getMetricsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Metric Name",
		"Description",
		"Filter",
		"Type",
	}
}

// getGapsHeader returns the header for logging gaps table
func (m *LoggingModule) getGapsHeader() []string {
	return []string{
		"Project",
		"Type",
		"Resource",
		"Location",
		"Status",
		"Missing Logs",
	}
}

// sinksToTableBody converts sinks to table body rows
func (m *LoggingModule) sinksToTableBody(sinks []LoggingService.SinkInfo) [][]string {
	var body [][]string
	for _, sink := range sinks {
		// Format destination
		destination := getDestinationName(sink)

		// Format cross-project
		crossProject := "No"
		if sink.IsCrossProject {
			crossProject = fmt.Sprintf("Yes -> %s", sink.DestinationProject)
		}

		// Format disabled
		disabled := "No"
		if sink.Disabled {
			disabled = "Yes"
		}

		// Format filter (no truncation)
		filter := "-"
		if sink.Filter != "" {
			filter = normalizeFilter(sink.Filter)
		}

		// Format writer identity
		writerIdentity := "-"
		if sink.WriterIdentity != "" {
			writerIdentity = sink.WriterIdentity
		}

		body = append(body, []string{
			m.GetProjectName(sink.ProjectID),
			sink.ProjectID,
			sink.Name,
			sink.DestinationType,
			destination,
			crossProject,
			disabled,
			writerIdentity,
			filter,
		})
	}
	return body
}

// metricsToTableBody converts metrics to table body rows
func (m *LoggingModule) metricsToTableBody(metrics []LoggingService.MetricInfo) [][]string {
	var body [][]string
	for _, metric := range metrics {
		// Format filter (no truncation)
		filter := "-"
		if metric.Filter != "" {
			filter = normalizeFilter(metric.Filter)
		}

		// Format type
		metricType := metric.MetricKind
		if metric.ValueType != "" {
			metricType += "/" + metric.ValueType
		}

		// Format description (no truncation)
		description := metric.Description
		if description == "" {
			description = "-"
		}

		body = append(body, []string{
			m.GetProjectName(metric.ProjectID),
			metric.ProjectID,
			metric.Name,
			description,
			filter,
			metricType,
		})
	}
	return body
}

// gapsToTableBody converts logging gaps to table body rows
func (m *LoggingModule) gapsToTableBody(gaps []LoggingService.LoggingGap) [][]string {
	var body [][]string
	for _, gap := range gaps {
		missingLogs := strings.Join(gap.MissingLogs, "; ")

		location := gap.Location
		if location == "" {
			location = "-"
		}

		body = append(body, []string{
			m.GetProjectName(gap.ProjectID),
			gap.ResourceType,
			gap.ResourceName,
			location,
			gap.LoggingStatus,
			missingLogs,
		})
	}
	return body
}

// buildTablesForProject builds table files for a project
func (m *LoggingModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if sinks, ok := m.ProjectSinks[projectID]; ok && len(sinks) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-sinks",
			Header: m.getSinksHeader(),
			Body:   m.sinksToTableBody(sinks),
		})
	}

	if metrics, ok := m.ProjectMetrics[projectID]; ok && len(metrics) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-metrics",
			Header: m.getMetricsHeader(),
			Body:   m.metricsToTableBody(metrics),
		})
	}

	if gaps, ok := m.ProjectGaps[projectID]; ok && len(gaps) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-gaps",
			Header: m.getGapsHeader(),
			Body:   m.gapsToTableBody(gaps),
		})
	}

	return tableFiles
}

// writeHierarchicalOutput writes output to per-project directories
func (m *LoggingModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all projects that have data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectSinks {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectMetrics {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectGaps {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		tableFiles := m.buildTablesForProject(projectID)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = LoggingOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_LOGGING_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *LoggingModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allSinks := m.getAllSinks()
	allMetrics := m.getAllMetrics()
	allGaps := m.getAllGaps()

	// Build table files
	tableFiles := []internal.TableFile{}

	if len(allSinks) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-sinks",
			Header: m.getSinksHeader(),
			Body:   m.sinksToTableBody(allSinks),
		})
	}

	if len(allMetrics) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-metrics",
			Header: m.getMetricsHeader(),
			Body:   m.metricsToTableBody(allMetrics),
		})
	}

	if len(allGaps) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-gaps",
			Header: m.getGapsHeader(),
			Body:   m.gapsToTableBody(allGaps),
		})
	}

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := LoggingOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_LOGGING_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// getDestinationName returns a human-readable destination name
func getDestinationName(sink LoggingService.SinkInfo) string {
	switch sink.DestinationType {
	case "storage":
		return sink.DestinationBucket
	case "bigquery":
		return sink.DestinationDataset
	case "pubsub":
		return sink.DestinationTopic
	case "logging":
		// Extract bucket name from full path
		parts := strings.Split(sink.Destination, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
		return sink.Destination
	default:
		return sink.Destination
	}
}

// normalizeFilter normalizes a log filter for display (removes newlines but no truncation)
func normalizeFilter(filter string) string {
	// Remove newlines
	filter = strings.ReplaceAll(filter, "\n", " ")
	filter = strings.ReplaceAll(filter, "\t", " ")

	// Collapse multiple spaces
	for strings.Contains(filter, "  ") {
		filter = strings.ReplaceAll(filter, "  ", " ")
	}

	return strings.TrimSpace(filter)
}
