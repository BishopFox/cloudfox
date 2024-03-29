package commands

import (
	"fmt"
	"time"

	BigQueryService "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	"github.com/BishopFox/cloudfox/globals"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPBigQueryCommand = &cobra.Command{
	Use:     "bigquery",
	Aliases: []string{},
	Short:   "Display Bigauery datasets and tables information",
	Args:    cobra.MinimumNArgs(0),
	Long: `
Display available Bigauery datasets and tables resource information:
cloudfox gcp bigquery`,
	Run: runGCPBigQueryCommand,
}

// GCPBigQueryResults struct that implements the internal.OutputInterface
type GCPBigQueryResults struct {
	DatasetsData []BigQueryService.BigqueryDataset
	TablesData   []BigQueryService.BigqueryTable
}

// Define the format for CSV & JSON output
func (g GCPBigQueryResults) TableFiles() []internal.TableFile {
	var tableFiles []internal.TableFile

	// For Datasets
	datasetHeader := []string{"Name", "DatasetID", "Description", "CreationTime", "LastModifiedTime", "Location", "ProjectID"}
	var datasetBody [][]string
	for _, dataset := range g.DatasetsData {
		datasetBody = append(datasetBody, []string{
			dataset.Name,
			dataset.DatasetID,
			dataset.Description,
			dataset.CreationTime.Format(time.RFC3339),
			dataset.LastModifiedTime.Format(time.RFC3339),
			dataset.Location,
			dataset.ProjectID,
		})
	}
	datasetTableFile := internal.TableFile{
		Header: datasetHeader,
		Body:   datasetBody,
		Name:   "bigquery-datasets",
	}
	tableFiles = append(tableFiles, datasetTableFile)

	// For Tables
	tableHeader := []string{"TableID", "DatasetID", "Description", "CreationTime", "LastModifiedTime", "NumBytes", "Location", "ProjectID"}
	var tableBody [][]string
	for _, table := range g.TablesData {
		tableBody = append(tableBody, []string{
			table.TableID,
			table.DatasetID,
			table.Description,
			table.CreationTime.Format(time.RFC3339),
			table.LastModifiedTime.Format(time.RFC3339),
			fmt.Sprintf("%d", table.NumBytes),
			table.Location,
			table.ProjectID,
		})
	}
	tableTableFile := internal.TableFile{
		Header: tableHeader,
		Body:   tableBody,
		Name:   "bigquery-tables",
	}
	tableFiles = append(tableFiles, tableTableFile)

	return tableFiles
}

func (g GCPBigQueryResults) LootFiles() []internal.LootFile {
	// Implement if there's specific data considered as loot
	return []internal.LootFile{}
}

func runGCPBigQueryCommand(cmd *cobra.Command, args []string) {
	var projectIDs []string
	var account string
	parentCmd := cmd.Parent()
	ctx := cmd.Context()
	logger := internal.NewLogger()
	if value, ok := ctx.Value("projectIDs").([]string); ok && len(value) > 0 {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from flag value or value is empty", globals.GCP_BIGQUERY_MODULE_NAME)
		return
	}

	if value, ok := ctx.Value("account").(string); ok {
		account = value
	} else {
		logger.ErrorM("Could not retrieve account email from command", globals.GCP_BIGQUERY_MODULE_NAME)
	}

	bqService := BigQueryService.New()
	var datasetsResults []BigQueryService.BigqueryDataset
	var tablesResults []BigQueryService.BigqueryTable

	// Set output params leveraging parent (gcp) pflag values
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	for _, projectID := range projectIDs {
		logger.InfoM(fmt.Sprintf("Retrieving BigQuery datasets and tables from project: %s", projectID), globals.GCP_BIGQUERY_MODULE_NAME)
		result, err := bqService.BigqueryDatasetsAndTables(projectID)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_BIGQUERY_MODULE_NAME)
			return
		}

		datasetsResults = append(datasetsResults, result.Datasets...)
		tablesResults = append(tablesResults, result.Tables...)
		cloudfoxOutput := GCPBigQueryResults{DatasetsData: datasetsResults, TablesData: tablesResults}

		err = internal.HandleOutput(format, outputDirectory, verbosity, wrap, globals.GCP_BIGQUERY_MODULE_NAME, account, projectID, cloudfoxOutput)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_BIGQUERY_MODULE_NAME)
			return
		}
		logger.InfoM(fmt.Sprintf("Done writing output for project %s", projectID), globals.GCP_BIGQUERY_MODULE_NAME)
	}
}
