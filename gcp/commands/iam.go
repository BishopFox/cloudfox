package commands

import (
	"fmt"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPIAMCommand = &cobra.Command{
	Use:     globals.GCP_IAM_MODULE_NAME,
	Aliases: []string{},
	Short:   "Display GCP IAM information",
	Args:    cobra.MinimumNArgs(0),
	Long: `
Display IAM principals and their roles information within GCP resources:
cloudfox gcp iam`,
	Run: runGCPIAMCommand,
}

// Results struct for IAM command that implements the internal.OutputInterface
type GCPIAMResults struct {
	Data []IAMService.PrincipalWithRoles
}

// TableFiles formats the data for table output, CSV & JSON files
func (g GCPIAMResults) TableFiles() []internal.TableFile {
	var tableFiles []internal.TableFile

	header := []string{
		"Name",
		"Principal Type",
		"Role",
		"PolicyResourceType",
		"PolicyResourceID",
	}

	var body [][]string

	for _, principal := range g.Data {
		for _, binding := range principal.PolicyBindings {
			body = append(body, []string{
				principal.Name,
				principal.Type,
				binding.Role,
				principal.ResourceType,
				principal.ResourceID,
			})
		}
	}

	tableFile := internal.TableFile{
		Header: header,
		Body:   body,
		Name:   globals.GCP_IAM_MODULE_NAME,
	}
	tableFiles = append(tableFiles, tableFile)

	return tableFiles
}

// LootFiles can be implemented if needed
func (g GCPIAMResults) LootFiles() []internal.LootFile {
	return []internal.LootFile{}
}

// Houses high-level logic that retrieves IAM information and writes to output
func runGCPIAMCommand(cmd *cobra.Command, args []string) {
	// Retrieve projectIDs and resource type from parent (gcp command) ctx
	var projectIDs []string
	var resourceType string
	var account string
	parentCmd := cmd.Parent()
	ctx := parentCmd.Context()
	logger := internal.NewLogger()
	if value, ok := ctx.Value("projectIDs").([]string); ok {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from flag value", globals.GCP_IAM_MODULE_NAME)
		return
	}

	if value, ok := ctx.Value("account").(string); ok {
		account = value
	} else {
		logger.ErrorM("Could not retrieve account email from command", globals.GCP_IAM_MODULE_NAME)
	}

	// TODO fix once folders or organizations are supported as input for project root
	resourceType = "project"

	// Initialize IAMService and fetch principals with roles for the given projectIDs and resource type
	iamService := IAMService.New()
	var results []IAMService.PrincipalWithRoles
	for _, projectID := range projectIDs {
		logger.InfoM(fmt.Sprintf("Retrieving IAM information for resource: %s of type %s", projectID, resourceType), globals.GCP_IAM_MODULE_NAME)
		principals, err := iamService.PrincipalsWithRoles(projectID, resourceType)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_IAM_MODULE_NAME)
			return
		}
		results = append(results, principals...)
		logger.InfoM(fmt.Sprintf("Done retrieving IAM information for resource: %s of type %s", projectID, resourceType), globals.GCP_IAM_MODULE_NAME)
	}

	// Produce output leveraging parent (gcp) pflag values
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	cloudfoxOutput := GCPIAMResults{Data: results}

	err := internal.HandleOutput(format, outputDirectory, verbosity, wrap, globals.GCP_IAM_MODULE_NAME, account, "resultsID-stub", cloudfoxOutput)
	if err != nil {
		logger.ErrorM(err.Error(), globals.GCP_IAM_MODULE_NAME)
		return
	}
	logger.InfoM("Done writing output", globals.GCP_IAM_MODULE_NAME)
}
