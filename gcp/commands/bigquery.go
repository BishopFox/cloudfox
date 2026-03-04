package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	BigQueryService "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPBigQueryCommand = &cobra.Command{
	Use:     globals.GCP_BIGQUERY_MODULE_NAME,
	Aliases: []string{"bq"},
	Short:   "Enumerate GCP BigQuery datasets and tables with security analysis",
	Long: `Enumerate GCP BigQuery datasets and tables across projects with security-focused analysis.

Features:
- Lists all BigQuery datasets with security-relevant columns
- Shows tables within each dataset with encryption and type info
- Enumerates dataset access control entries (IAM-like)
- Identifies publicly accessible datasets (allUsers/allAuthenticatedUsers)
- Shows encryption status (Google-managed vs CMEK)
- Generates bq commands for data enumeration
- Generates exploitation commands for data access`,
	Run: runGCPBigQueryCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type BigQueryModule struct {
	gcpinternal.BaseGCPModule

	// Per-project data for hierarchical output
	ProjectDatasets map[string][]BigQueryService.BigqueryDataset
	ProjectTables   map[string][]BigQueryService.BigqueryTable
	LootMap         map[string]map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type BigQueryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BigQueryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BigQueryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPBigQueryCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_BIGQUERY_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &BigQueryModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectDatasets: make(map[string][]BigQueryService.BigqueryDataset),
		ProjectTables:   make(map[string][]BigQueryService.BigqueryTable),
		LootMap:         make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *BigQueryModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_BIGQUERY_MODULE_NAME, m.processProject)

	// Get all data for stats
	allDatasets := m.getAllDatasets()
	allTables := m.getAllTables()

	// Check results
	if len(allDatasets) == 0 && len(allTables) == 0 {
		logger.InfoM("No BigQuery datasets found", globals.GCP_BIGQUERY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d dataset(s) with %d table(s)", len(allDatasets), len(allTables)), globals.GCP_BIGQUERY_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllDatasets returns all datasets from all projects
func (m *BigQueryModule) getAllDatasets() []BigQueryService.BigqueryDataset {
	var all []BigQueryService.BigqueryDataset
	for _, datasets := range m.ProjectDatasets {
		all = append(all, datasets...)
	}
	return all
}

// getAllTables returns all tables from all projects
func (m *BigQueryModule) getAllTables() []BigQueryService.BigqueryTable {
	var all []BigQueryService.BigqueryTable
	for _, tables := range m.ProjectTables {
		all = append(all, tables...)
	}
	return all
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *BigQueryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating BigQuery in project: %s", projectID), globals.GCP_BIGQUERY_MODULE_NAME)
	}

	// Create service and fetch data
	bqService := BigQueryService.New()
	result, err := bqService.BigqueryDatasetsAndTables(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_BIGQUERY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate BigQuery in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectDatasets[projectID] = result.Datasets
	m.ProjectTables[projectID] = result.Tables

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["bigquery-commands"] = &internal.LootFile{
			Name:     "bigquery-commands",
			Contents: "# GCP BigQuery Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	// Generate loot for each dataset and table
	for _, dataset := range result.Datasets {
		m.addDatasetToLoot(projectID, dataset)
	}
	for _, table := range result.Tables {
		m.addTableToLoot(projectID, table)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d dataset(s) and %d table(s) in project %s", len(result.Datasets), len(result.Tables), projectID), globals.GCP_BIGQUERY_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *BigQueryModule) addDatasetToLoot(projectID string, dataset BigQueryService.BigqueryDataset) {
	lootFile := m.LootMap[projectID]["bigquery-commands"]
	if lootFile == nil {
		return
	}

	// All commands for this dataset
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# DATASET: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Location: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Show dataset info\n"+
			"bq show --project_id=%s %s\n"+
			"bq show --format=prettyjson %s:%s\n\n"+
			"# List tables in dataset\n"+
			"bq ls --project_id=%s %s\n\n",
		dataset.DatasetID, dataset.ProjectID, dataset.Location,
		dataset.ProjectID, dataset.DatasetID,
		dataset.ProjectID, dataset.DatasetID,
		dataset.ProjectID, dataset.DatasetID,
	)
}

func (m *BigQueryModule) addTableToLoot(projectID string, table BigQueryService.BigqueryTable) {
	lootFile := m.LootMap[projectID]["bigquery-commands"]
	if lootFile == nil {
		return
	}

	// Table info and query commands
	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# TABLE: %s.%s (Dataset: %s)\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Project: %s\n"+
			"# Type: %s, Size: %d bytes, Rows: %d\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Show table schema:\n"+
			"bq show --schema --project_id=%s %s:%s.%s\n\n"+
			"# === EXPLOIT COMMANDS ===\n\n"+
			"# Query first 100 rows:\n"+
			"bq query --project_id=%s --use_legacy_sql=false 'SELECT * FROM `%s.%s.%s` LIMIT 100'\n"+
			"# Export table to GCS:\n"+
			"bq extract --project_id=%s '%s:%s.%s' gs://<bucket>/export_%s_%s.json\n\n",
		table.DatasetID, table.TableID, table.DatasetID,
		table.ProjectID,
		table.TableType, table.NumBytes, table.NumRows,
		table.ProjectID, table.ProjectID, table.DatasetID, table.TableID,
		table.ProjectID, table.ProjectID, table.DatasetID, table.TableID,
		table.ProjectID, table.ProjectID, table.DatasetID, table.TableID, table.DatasetID, table.TableID,
	)

	// Views (may expose data from other datasets)
	if table.IsView {
		viewQuery := table.ViewQuery
		if len(viewQuery) > 200 {
			viewQuery = viewQuery[:200] + "..."
		}
		lootFile.Contents += fmt.Sprintf(
			"# VIEW DEFINITION: %s.%s\n"+
				"# Legacy SQL: %v\n"+
				"# Query:\n"+
				"# %s\n\n",
			table.DatasetID, table.TableID,
			table.UseLegacySQL,
			strings.ReplaceAll(viewQuery, "\n", "\n# "),
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *BigQueryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getDatasetHeader returns the dataset table header
func (m *BigQueryModule) getDatasetHeader() []string {
	return []string{
		"Project",
		"Dataset ID",
		"Location",
		"Public",
		"Encryption",
		"IAM Binding Role",
		"Principal Type",
		"IAM Binding Principal",
	}
}

// getTableHeader returns the table table header
func (m *BigQueryModule) getTableHeader() []string {
	return []string{
		"Project",
		"Dataset ID",
		"Table ID",
		"Type",
		"Encryption",
		"Rows",
		"Public",
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

// datasetsToTableBody converts datasets to table body rows
func (m *BigQueryModule) datasetsToTableBody(datasets []BigQueryService.BigqueryDataset) ([][]string, int) {
	var body [][]string
	publicCount := 0
	for _, dataset := range datasets {
		publicStatus := ""
		if dataset.IsPublic {
			publicStatus = dataset.PublicAccess
			publicCount++
		}

		if len(dataset.AccessEntries) > 0 {
			for _, entry := range dataset.AccessEntries {
				memberType := BigQueryService.GetMemberType(entry.EntityType, entry.Entity)
				role := entry.Role
				if role == "" {
					role = "READER"
				}
				body = append(body, []string{
					m.GetProjectName(dataset.ProjectID),
					dataset.DatasetID,
					dataset.Location,
					publicStatus,
					dataset.EncryptionType,
					role,
					memberType,
					entry.Entity,
				})
			}
		} else {
			body = append(body, []string{
				m.GetProjectName(dataset.ProjectID),
				dataset.DatasetID,
				dataset.Location,
				publicStatus,
				dataset.EncryptionType,
				"-",
				"-",
				"-",
			})
		}
	}
	return body, publicCount
}

// tablesToTableBody converts tables to table body rows
func (m *BigQueryModule) tablesToTableBody(tables []BigQueryService.BigqueryTable) [][]string {
	var body [][]string
	for _, table := range tables {
		publicStatus := ""
		if table.IsPublic {
			publicStatus = table.PublicAccess
		}

		if len(table.IAMBindings) == 0 {
			body = append(body, []string{
				m.GetProjectName(table.ProjectID),
				table.DatasetID,
				table.TableID,
				table.TableType,
				table.EncryptionType,
				fmt.Sprintf("%d", table.NumRows),
				publicStatus,
				"-",
				"-",
			})
		} else {
			for _, binding := range table.IAMBindings {
				for _, member := range binding.Members {
					body = append(body, []string{
						m.GetProjectName(table.ProjectID),
						table.DatasetID,
						table.TableID,
						table.TableType,
						table.EncryptionType,
						fmt.Sprintf("%d", table.NumRows),
						publicStatus,
						binding.Role,
						member,
					})
				}
			}
		}
	}
	return body
}

// writeHierarchicalOutput writes output to per-project directories
func (m *BigQueryModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all projects with data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectDatasets {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectTables {
		projectsWithData[projectID] = true
	}

	totalPublicCount := 0
	for projectID := range projectsWithData {
		datasets := m.ProjectDatasets[projectID]
		tables := m.ProjectTables[projectID]

		datasetBody, publicCount := m.datasetsToTableBody(datasets)
		totalPublicCount += publicCount
		tableBody := m.tablesToTableBody(tables)

		tableFiles := []internal.TableFile{
			{Name: "bigquery-datasets", Header: m.getDatasetHeader(), Body: datasetBody},
			{Name: "bigquery-tables", Header: m.getTableHeader(), Body: tableBody},
		}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = BigQueryOutput{Table: tableFiles, Loot: lootFiles}
	}

	if totalPublicCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d publicly accessible dataset(s)!", totalPublicCount), globals.GCP_BIGQUERY_MODULE_NAME)
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_BIGQUERY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *BigQueryModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allDatasets := m.getAllDatasets()
	allTables := m.getAllTables()

	datasetBody, publicCount := m.datasetsToTableBody(allDatasets)
	tableBody := m.tablesToTableBody(allTables)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tableFiles := []internal.TableFile{
		{Name: "bigquery-datasets", Header: m.getDatasetHeader(), Body: datasetBody},
		{Name: "bigquery-tables", Header: m.getTableHeader(), Body: tableBody},
	}

	if publicCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d publicly accessible dataset(s)!", publicCount), globals.GCP_BIGQUERY_MODULE_NAME)
	}

	output := BigQueryOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_BIGQUERY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
