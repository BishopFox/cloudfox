package commands

import (
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	SecretsService "github.com/BishopFox/cloudfox/gcp/services/secretsService"
	"github.com/BishopFox/cloudfox/globals"

	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPSecretsCommand = &cobra.Command{
	Use:     globals.GCP_SECRETS_MODULE_NAME,
	Aliases: []string{},
	Short:   "Display GCP secrets information",
	Args:    cobra.MinimumNArgs(0),
	Long: `
Display available secrets information:
cloudfox gcp secrets`,
	Run: runGCPSecretsCommand,
}

// GCPSecretsResults struct that implements the internal.OutputInterface
type GCPSecretsResults struct {
	Data []SecretsService.SecretInfo
}

func (g GCPSecretsResults) TableFiles() []internal.TableFile {
	var tableFiles []internal.TableFile

	header := []string{
		"Name",
		"CreationTime",
		"Labels",
		"Rotation",
		"ProjectID",
		// Add more fields as necessary
	}

	var body [][]string
	for _, value := range g.Data {
		body = append(body, []string{
			value.Name,
			value.CreationTime,
			fmt.Sprintf("%v", value.Labels),
			value.Rotation,
			value.ProjectID,
		})
	}

	tableFile := internal.TableFile{
		Header: header,
		Body:   body,
		Name:   globals.GCP_SECRETS_MODULE_NAME,
	}
	tableFiles = append(tableFiles, tableFile)

	return tableFiles
}

func (g GCPSecretsResults) LootFiles() []internal.LootFile {
	// Define any specific data considered as loot
	return []internal.LootFile{}
}

func runGCPSecretsCommand(cmd *cobra.Command, args []string) {
	var projectIDs []string
	var account string
	parentCmd := cmd.Parent()
	ctx := cmd.Context()
	logger := internal.NewLogger()
	if value, ok := ctx.Value("projectIDs").([]string); ok && len(value) > 0 {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from flag value or value is empty", globals.GCP_SECRETS_MODULE_NAME)
		return
	}

	if value, ok := ctx.Value("account").(string); ok {
		account = value
	} else {
		logger.ErrorM("Could not retrieve account email from command", globals.GCP_IAM_MODULE_NAME)
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("failed to create secret manager client: %v", err), globals.GCP_SECRETS_MODULE_NAME)
		return
	}
	defer client.Close()

	ss := SecretsService.New(client)
	var results []SecretsService.SecretInfo

	// Set output params from parentCmd
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	for _, projectID := range projectIDs {
		logger.InfoM(fmt.Sprintf("Retrieving all secrets from project: %s", projectID), globals.GCP_SECRETS_MODULE_NAME)
		result, err := ss.Secrets(projectID)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_SECRETS_MODULE_NAME)
			return
		}
		results = append(results, result...)
		logger.InfoM(fmt.Sprintf("Done retrieving all secrets from project: %s", projectID), globals.GCP_SECRETS_MODULE_NAME)
		cloudfoxOutput := GCPSecretsResults{Data: results}
		err = internal.HandleOutput("gcp", format, outputDirectory, verbosity, wrap, globals.GCP_SECRETS_MODULE_NAME, account, projectID, cloudfoxOutput)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_SECRETS_MODULE_NAME)
			return
		}
		logger.InfoM(fmt.Sprintf("Done writing output for project %s", projectID), globals.GCP_SECRETS_MODULE_NAME)
	}
}
