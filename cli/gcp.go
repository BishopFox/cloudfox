package cli

import (
	"log"

	"github.com/BishopFox/cloudfox/gcp"
	"github.com/spf13/cobra"
)

var (
	GCPOrganizations	[]string
	GCPProjectIDs		[]string
	GCPFolderIDs		[]string
	GCPOutputFormat		string
	GCPOutputDirectory	string
	GCPVerbosity		int
	GCPWrapTable		bool
	GCPConfirm			bool
	GCPSkipAdminCheck	bool
	GCPIgnoreCache		bool

	GCPCommands = &cobra.Command{
		Use:     "gcp",
		Aliases: []string{"gcloud"},
		Long:    `See "Available Commands" for GCP Modules below`,
		Short:   "See \"Available Commands\" for GCP Modules below",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	GCPWhoamiCommand = &cobra.Command{
		Use:     "whoami",
		Aliases: []string{},
		Short:   "Display available GCP CLI sessions",
		Long: `
Display Available GCP projects:
./cloudfox gcp whoami`,
		Run: runGCPWhoamiCommand,
	}

	GCPInventoryCommand = &cobra.Command{
		Use:     "inventory",
		Aliases: []string{},
		Short:   "Display all available GCP resources",
		Long: `
Display available GCP resources:
./cloudfox gcp inventory`,
		Run: runGCPInventoryCommand,
	}

	GCPProfilesCommand = &cobra.Command{
		Use:     "profiles",
		Aliases: []string{},
		Short:   "Display all available local gcloud profiles",
		Long: `
Display available gcloud profiles:
./cloudfox gcp profiles`,
		Run: runGCPProfilesCommand,
	}
)

func runGCPProfilesCommand(cmd *cobra.Command, args []string) {
	m := gcp.ProfilesModule{
		Organizations:	GCPOrganizations,
		Projects:		GCPProjectIDs,
		Folders:		GCPFolderIDs,
	}
	err := m.PrintProfiles(cmd.Root().Version, GCPOutputFormat, GCPOutputDirectory, Verbosity)
	if err != nil {
		log.Fatal(err)
	}
}

func runGCPWhoamiCommand(cmd *cobra.Command, args []string) {
	err := gcp.GCPWhoamiCommand(cmd.Root().Version, GCPWrapTable)
	if err != nil {
		log.Fatal(err)
	}
}

func runGCPInventoryCommand(cmd *cobra.Command, args []string) {
	m := gcp.InventoryModule{
		Organizations:	GCPOrganizations,
		Projects:		GCPProjectIDs,
		Folders:		GCPFolderIDs,
	}
	err := m.PrintInventory(cmd.Root().Version, GCPOutputFormat, GCPOutputDirectory, Verbosity)
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	// Resource filtering options
	GCPCommands.PersistentFlags().StringArrayVarP(&GCPOrganizations, "organization", "o",[]string{}, "Organization name, repetable")
	GCPCommands.PersistentFlags().StringArrayVarP(&GCPProjectIDs, "projectid", "p", []string{}, "Project ID, repeatable")
	GCPCommands.PersistentFlags().StringArrayVarP(&GCPFolderIDs, "folderid", "f", []string{}, "Folder ID, repeatable")

	// Global flags for the GCP modules
	GCPCommands.PersistentFlags().BoolVarP(&GCPConfirm, "yes", "y", false, "Non-interactive mode (like apt/yum)")
	GCPCommands.PersistentFlags().StringVarP(&GCPOutputFormat, "output", "", "brief", "[\"brief\" | \"wide\" ]")
	GCPCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 1, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	GCPCommands.PersistentFlags().StringVar(&GCPOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	GCPCommands.PersistentFlags().IntVarP(&Goroutines, "max-goroutines", "g", 30, "Maximum number of concurrent goroutines")
	GCPCommands.PersistentFlags().BoolVar(&GCPSkipAdminCheck, "skip-admin-check", false, "Skip check to determine if role is an Admin")
	GCPCommands.PersistentFlags().BoolVarP(&GCPWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	GCPCommands.PersistentFlags().BoolVar(&GCPIgnoreCache, "ignore-cache", false, "Disable loading of cached data. Slower, but important if changes have been recently made")

	GCPCommands.AddCommand(
		GCPWhoamiCommand,
		GCPInventoryCommand,
		GCPProfilesCommand,
	)
}
