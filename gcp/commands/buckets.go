package commands

import (
	"fmt"

	CloudStorageService "github.com/BishopFox/cloudfox/gcp/services/cloudStorageService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPBucketsCommand = &cobra.Command{
	Use:     globals.GCP_BUCKETS_MODULE_NAME,
	Aliases: []string{},
	Short:   "Display GCP buckets information",
	Args:    cobra.MinimumNArgs(0),
	Long: `
Display available bucket information:
cloudfox gcp buckets`,
	Run: runGCPBucketsCommand,
}

// Code needed to output fields from buckets results using generic HandleOutput function

// Results struct that implements the internal.OutputInterface
type GCPBucketsResults struct {
	Data []CloudStorageService.BucketInfo
}

// Decide what format the name, header and body of the CSV & JSON files will be
func (g GCPBucketsResults) TableFiles() []internal.TableFile {
	var tableFiles []internal.TableFile

	header := []string{
		"Name",
		"Location",
		"ProjectID",
	}

	var body [][]string

	for _, value := range g.Data {
		body = append(
			body,
			[]string{
				value.Name,
				value.Location,
				value.ProjectID,
			},
		)
	}

	tableFile := internal.TableFile{
		Header: header,
		Body:   body,
		Name:   globals.GCP_BUCKETS_MODULE_NAME,
	}
	tableFiles = append(tableFiles, tableFile)

	return tableFiles
}

// Decide what is loot based on resource information
func (g GCPBucketsResults) LootFiles() []internal.LootFile {
	return []internal.LootFile{}
}

// Houses high-level logic that retrieves resources and writes to output
func runGCPBucketsCommand(cmd *cobra.Command, args []string) {
	// Retrieve projectIDs from parent (gcp command) ctx
	var projectIDs []string
	parentCmd := cmd.Parent()
	ctx := parentCmd.Context()
	logger := internal.NewLogger()
	if value, ok := ctx.Value("projectIDs").([]string); ok {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from flag value", globals.GCP_BUCKETS_MODULE_NAME)
	}

	// Get the bucket info using the projectIDs and CloudStorageService
	cs := CloudStorageService.New()
	var results []CloudStorageService.BucketInfo
	for _, projectID := range projectIDs {
		logger.InfoM(fmt.Sprintf("Retrieving all buckets from project: %s", projectID), globals.GCP_BUCKETS_MODULE_NAME)
		result, err := cs.Buckets(projectID)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_BUCKETS_MODULE_NAME)
			return
		}
		results = append(results, result...)
		logger.InfoM(fmt.Sprintf("Done retrieving all buckets from project: %s", projectID), globals.GCP_BUCKETS_MODULE_NAME)
	}

	// Produce output leveraging parent (gcp) pflag values
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	cloudfoxOutput := GCPBucketsResults{Data: results}

	err := internal.HandleOutput(format, outputDirectory, verbosity, wrap, globals.GCP_BUCKETS_MODULE_NAME, "principal-stub", "resultsID-stub", cloudfoxOutput)
	if err != nil {
		logger.ErrorM(err.Error(), globals.GCP_BUCKETS_MODULE_NAME)
		return
	}
	logger.InfoM("Done writing output", globals.GCP_BUCKETS_MODULE_NAME)
}
