package cli

import (
	"context"
	"fmt"

	"github.com/BishopFox/cloudfox/gcp/commands"
	oauthservice "github.com/BishopFox/cloudfox/gcp/services/oauthService"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var (
	// GCP resources filtering options
	GCPOrganization       string
	GCPProjectID          string
	GCPProjectIDsFilePath string
	GCPProjectIDs         []string

	// Output formatting options
	GCPOutputFormat    string
	GCPOutputDirectory string
	GCPVerbosity       int
	GCPWrapTable       bool

	// misc options
	// GCPIgnoreCache		bool

	// logger
	GCPLogger = internal.NewLogger()

	// GCP root command
	GCPCommands = &cobra.Command{
		Use:     "gcp",
		Aliases: []string{"gcloud"},
		Long:    `See "Available Commands" for GCP Modules below`,
		Short:   "See \"Available Commands\" for GCP Modules below",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if GCPProjectID != "" {
				GCPProjectIDs = append(GCPProjectIDs, GCPProjectID)
			} else if GCPProjectIDsFilePath != "" {
				GCPProjectIDs = internal.LoadFileLinesIntoArray(GCPProjectIDsFilePath)
			} else {
				GCPLogger.InfoM("project or project-list flags not given, using default project as target", "gcp")
			}
			// Create a context with this value to share it with subcommands at runtime
			ctx := context.WithValue(context.Background(), "projectIDs", GCPProjectIDs)

			// Set the context for this command which all subcommands can access via [SUBCMD].Parent().Context()
			// cmd.SetContext(ctx)
			os := oauthservice.NewOAuthService()
			email, err := os.WhoAmI()
			if err != nil {
				GCPLogger.FatalM("could not determine default user credential. Please use default applicatin default credentials: https://cloud.google.com/docs/authentication/application-default-credentials", "gcp")
			}
			ctx = context.WithValue(ctx, "account", email)
			cmd.SetContext(ctx)
		},
	}
)

// New RunAllGCPCommands function to execute all child commands
var GCPAllChecksCommand = &cobra.Command{
	Use:   "all-checks",
	Short: "Runs all available GCP commands",
	Long:  `Executes all available GCP commands to collect and display information from all supported GCP services.`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, childCmd := range GCPCommands.Commands() {
			if childCmd == cmd { // Skip the run-all command itself to avoid infinite recursion
				continue
			}

			GCPLogger.InfoM(fmt.Sprintf("Running command: %s", childCmd.Use), "all-checks")
			childCmd.Run(cmd, args)
		}
	},
}

func init() {
	// Globals flags for the GCP commands

	// Allow selection of non-default account to be used when accessing gcloud API
	// TODO

	// Resource filtering options
	// GCPCommands.PersistentFlags().StringVarP(&GCPOrganization, "organization", "o", "", "Organization name or number, repetable")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectID, "project", "p", "", "GCP project ID")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectIDsFilePath, "project-list", "l", "", "Path to a file containing a list of project IDs separated by newlines")
	// GCPCommands.PersistentFlags().BoolVarP(&GCPAllProjects, "all-projects", "a", false, "Use all project IDs available to activated gloud account or given gcloud account")
	// GCPCommands.PersistentFlags().BoolVarP(&GCPConfirm, "yes", "y", false, "Non-interactive mode (like apt/yum)")
	// GCPCommands.PersistentFlags().StringVarP(&GCPOutputFormat, "output", "", "brief", "[\"brief\" | \"wide\" ]")
	GCPCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 1, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	// defaultOutputDir is defined in cli.aws
	GCPCommands.PersistentFlags().StringVar(&GCPOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	// GCPCommands.PersistentFlags().IntVarP(&Goroutines, "max-goroutines", "g", 30, "Maximum number of concurrent goroutines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")

	// Available commands
	GCPCommands.AddCommand(
		commands.GCPBucketsCommand,
		commands.GCPArtifactRegistryCommand,
		commands.GCPBigQueryCommand,
		commands.GCPSecretsCommand,
		commands.GCPIAMCommand,
		commands.GCPInstancesCommand,
		commands.GCPWhoAmICommand,
		GCPAllChecksCommand,
	)
}
