package commands

import (
	"fmt"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	ArtifactRegistryService "github.com/BishopFox/cloudfox/gcp/services/artifactRegistryService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPArtifactRegistryCommand = &cobra.Command{
	Use:     globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME,
	Aliases: []string{},
	Short:   "Display GCP artifact registry information",
	Args:    cobra.MinimumNArgs(0),
	Long: `
Display available artifact registry resource information:
cloudfox gcp artfact-registry`,
	Run: runGCPArtifactRegistryCommand,
}

// Code needed to output fields from buckets results using generic HandleOutput function

// Results struct that implements the internal.OutputInterface
type GCPArtifactRegistryResults struct {
	ArtifactData   []ArtifactRegistryService.ArtifactInfo
	RepositoryData []ArtifactRegistryService.RepositoryInfo
}

// Decide what format the name, header and body of the CSV & JSON files will be
func (g GCPArtifactRegistryResults) TableFiles() []internal.TableFile {
	var tableFiles []internal.TableFile

	repoHeader := []string{
		"Name",
		"Format",
		"Description",
		"Size",
		"Location",
		"ProjectID",
	}

	var repoBody [][]string

	for _, value := range g.RepositoryData {
		repoBody = append(
			repoBody,
			[]string{
				value.Name,
				value.Format,
				value.Description,
				value.SizeBytes,
				value.Location,
				value.ProjectID,
			},
		)
	}

	repoTableFile := internal.TableFile{
		Header: repoHeader,
		Body:   repoBody,
		Name:   fmt.Sprintf("%s-repos", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
	}

	tableFiles = append(tableFiles, repoTableFile)

	artifactHeader := []string{
		"Name",
		"Format",
		"Version",
		"Location",
		"Repository",
		"Size",
		"Updated",
		"ProjectID",
	}

	var artifactBody [][]string

	for _, value := range g.ArtifactData {
		artifactBody = append(
			artifactBody,
			[]string{
				value.Name,
				value.Format,
				value.Version,
				value.Location,
				value.Repository,
				value.SizeBytes,
				value.Updated,
				value.ProjectID,
			},
		)
	}

	artifactTableFile := internal.TableFile{
		Header: artifactHeader,
		Body:   artifactBody,
		Name:   fmt.Sprintf("%s-artifacts", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
	}

	tableFiles = append(tableFiles, artifactTableFile)

	return tableFiles
}

// Decide what is loot based on resource information
func (g GCPArtifactRegistryResults) LootFiles() []internal.LootFile {
	// TODO consider a loot file of the URLs to the all docker image artifacts. Maybe sample commands to pull the images
	return []internal.LootFile{}
}

// Houses high-level logic that retrieves resources and writes to output
func runGCPArtifactRegistryCommand(cmd *cobra.Command, args []string) {
	// Retrieve projectIDs from parent (gcp command) ctx
	var projectIDs []string
	var account string
	parentCmd := cmd.Parent()
	ctx := cmd.Context()
	logger := internal.NewLogger()
	if value, ok := ctx.Value("projectIDs").([]string); ok {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from flag value", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	if value, ok := ctx.Value("account").(string); ok {
		account = value
	} else {
		logger.ErrorM("Could not retrieve account email from command", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	client, err := artifactregistry.NewClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("failed to create secret manager client: %v", err), globals.GCP_SECRETS_MODULE_NAME)
		return
	}
	defer client.Close()

	// Get the artifact repositories and artifacts using the projectIDs and ArtifactRegistryService
	ars := ArtifactRegistryService.New(client)
	var artifactResults []ArtifactRegistryService.ArtifactInfo
	var repoRestuls []ArtifactRegistryService.RepositoryInfo
	for _, projectID := range projectIDs {
		logger.InfoM(fmt.Sprintf("Retrieving all artifact repositories and supported artifacts in all locations from project: %s", projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		result, err := ars.RepositoriesAndArtifacts(projectID)
		if err != nil {
			logger.ErrorM(err.Error(), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
			return
		}

		artifactResults = append(artifactResults, result.Artifacts...)
		repoRestuls = append(repoRestuls, result.Repositories...)
		logger.InfoM(fmt.Sprintf("Done retrieving artifact repository resource data from project: %s", projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	// Produce output leveraging parent (gcp) pflag values
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")
	cloudfoxOutput := GCPArtifactRegistryResults{ArtifactData: artifactResults, RepositoryData: repoRestuls}

	err = internal.HandleOutput(format, outputDirectory, verbosity, wrap, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME, account, "resultsID-stub", cloudfoxOutput)
	if err != nil {
		logger.ErrorM(err.Error(), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return
	}
	logger.InfoM("Done writing output", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
}
