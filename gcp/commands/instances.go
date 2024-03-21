package commands

import (
	"fmt"

	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPInstancesCommand = &cobra.Command{
	Use:     globals.GCP_INSTANCES_MODULE_NAME, // This should be defined in the globals package
	Aliases: []string{},
	Short:   "Display GCP Compute Engine instances information",
	Args:    cobra.MinimumNArgs(0),
	Long: `
Display available Compute Engine instances information:
cloudfox gcp instances`,
	Run: runGCPInstancesCommand,
}

// GCPInstancesResults implements internal.OutputInterface for Compute Engine instances
type GCPInstancesResults struct {
	Data []ComputeEngineService.ComputeEngineInfo
}

func (g GCPInstancesResults) TableFiles() []internal.TableFile {
	var tableFiles []internal.TableFile

	header := []string{
		"Name",
		"ID",
		"State",
		"ExternalIP",
		"InternalIP",
		"ServiceAccount", // Adding ServiceAccount to the header
		"Zone",
		"ProjectID",
	}

	var body [][]string
	for _, instance := range g.Data {
		// Initialize an empty string to aggregate service account emails
		var serviceAccountEmails string
		for _, serviceAccount := range instance.ServiceAccounts {
			// Assuming each instance can have multiple service accounts, concatenate their emails
			if serviceAccountEmails != "" {
				serviceAccountEmails += "; " // Use semicolon as a delimiter for multiple emails
			}
			serviceAccountEmails += serviceAccount.Email
		}

		body = append(body, []string{
			instance.Name,
			instance.ID,
			instance.State,
			instance.ExternalIP,
			instance.InternalIP,
			serviceAccountEmails, // Add the aggregated service account emails to the output
			instance.Zone,
			instance.ProjectID,
		})
	}

	tableFiles = append(tableFiles, internal.TableFile{
		Name:   globals.GCP_INSTANCES_MODULE_NAME,
		Header: header,
		Body:   body,
	})

	return tableFiles
}

func (g GCPInstancesResults) LootFiles() []internal.LootFile {
	// Define any loot files if applicable
	return []internal.LootFile{}
}

func runGCPInstancesCommand(cmd *cobra.Command, args []string) {
	var projectIDs []string
	var account string
	parentCmd := cmd.Parent()
	ctx := parentCmd.Context()
	logger := internal.NewLogger()

	if value, ok := ctx.Value("projectIDs").([]string); ok {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from flag value", globals.GCP_INSTANCES_MODULE_NAME)
		return
	}

	if value, ok := ctx.Value("account").(string); ok {
		account = value
	} else {
		logger.ErrorM("Could not retrieve account email from command", globals.GCP_IAM_MODULE_NAME)
	}

	ces := ComputeEngineService.New()
	var results []ComputeEngineService.ComputeEngineInfo
	for _, projectID := range projectIDs {
		logger.InfoM(fmt.Sprintf("Retrieving all instances from project: %s", projectID), globals.GCP_INSTANCES_MODULE_NAME)
		result, err := ces.Instances(projectID)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_INSTANCES_MODULE_NAME)
			return
		}
		results = append(results, result...)
		logger.InfoM(fmt.Sprintf("Done retrieving all instances from project: %s", projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}

	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	cloudfoxOutput := GCPInstancesResults{Data: results}

	err := internal.HandleOutput(format, outputDirectory, verbosity, wrap, globals.GCP_INSTANCES_MODULE_NAME, account, "resultsID-stub", cloudfoxOutput)
	if err != nil {
		logger.ErrorM(err.Error(), globals.GCP_INSTANCES_MODULE_NAME)
		return
	}
	logger.InfoM("Done writing output", globals.GCP_INSTANCES_MODULE_NAME)
}
