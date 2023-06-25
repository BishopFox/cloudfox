package cli

import (
	"log"
	"os"
	"github.com/BishopFox/cloudfox/gcp"
	internal_gcp "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var (
	// GCP resources filtering options
	GCPOrganizations	[]string
	GCPProjectIDs		[]string
	GCPFolderIDs		[]string

	// Output formatting options
	GCPOutputFormat		string
	GCPOutputDirectory	string
	GCPVerbosity		int
	GCPWrapTable		bool

	GCPProfilesList		string
	GCPAllProfiles		bool
	GCPProfiles			[]string


	// misc options
	GCPConfirm			bool
	GCPSkipAdminCheck	bool
	GCPIgnoreCache		bool

	// logger
	GCPLogger = internal.NewLogger()

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

	GCPAccessTokensCommand = &cobra.Command{
		Use:     "access-tokens",
		Aliases: []string{},
		Short:   "Display all available local gcloud access tokens",
		Long: `
Display available gcloud access tokens:
./cloudfox gcp access-tokens`,
		Run: runGCPAccessTokensCommand,
	}

	GCPBucketsCommand = &cobra.Command{
		Use:     "buckets",
		Aliases: []string{},
		Short:   "Display GCP bucket information",
		Long: `
Display available bucket information:
./cloudfox gcp buckets`,
		Run: runGCPBucketsCommand,
	}

	HierarchyIncludeIDs bool
	GCPHierarchyCommand = &cobra.Command{
		Use:     "hierarchy",
		Aliases: []string{},
		Short:   "Display GCP resources hierarchy",
		Long: `
Display available resources' hierarchy:
./cloudfox gcp hierarchy`,
		Run: runGCPHierarchyCommand,
	}
)

func initGCPProfiles() {
	// Ensure that profile selection is consistent
	if (len(GCPProfiles) != 0 || GCPProfilesList != "") && GCPAllProfiles {
		GCPLogger.Fatal("Error specifying GCP profiles. Choose only one of -p/--profile, -a/--all-profiles, -l/--profiles-list")
	
	}
	if GCPAllProfiles {
		GCPProfiles = internal_gcp.GetAllGCPProfiles()
	}

	if GCPProfilesList != "" {
		// Written like so to enable testing while still being readable
		GCPProfiles = append(GCPProfiles, internal_gcp.GetSelectedGCPProfiles(GCPProfilesList)...)
	}
	GCPProfiles = internal.RemoveDuplicateStr(GCPProfiles)
	if (len(GCPProfiles) == 0) {
		GCPLogger.Error("Could not find any usable GCP profile")
		os.Exit(1)
	}

	if !GCPConfirm {
		result := internal_gcp.ConfirmSelectedProfiles(GCPProfiles)
		if !result {
			os.Exit(1)
		}
	}
}

func runGCPHierarchyCommand(cmd *cobra.Command, args []string) {
	m := gcp.HierarchyModule{
		Organizations:	GCPOrganizations,
		Projects:		GCPProjectIDs,
		Folders:		GCPFolderIDs,
	}
	err := m.DisplayHierarchy(cmd.Root().Version)
	if err != nil {
		log.Fatal(err)
	}
}

func runGCPBucketsCommand(cmd *cobra.Command, args []string) {
	m := gcp.BucketsModule{
		Organizations:	GCPOrganizations,
		Projects:		GCPProjectIDs,
		Folders:		GCPFolderIDs,
	}
	err := m.GetData(cmd.Root().Version, []string{})
	if err != nil {
		log.Fatal(err)
	}
}

func runGCPAccessTokensCommand(cmd *cobra.Command, args []string) {
	m := gcp.AccessTokensModule{
		Organizations:	GCPOrganizations,
		Projects:		GCPProjectIDs,
		Folders:		GCPFolderIDs,
	}
	err := m.PrintAccessTokens(cmd.Root().Version, GCPOutputFormat, GCPOutputDirectory, Verbosity)
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
	cobra.OnInitialize(initGCPProfiles)
	GCPHierarchyCommand.Flags().BoolVarP(&HierarchyIncludeIDs, "ids", "i", false, "Use this flag to display resources IDs in the hierarchy tree")
	// Globals flags for the GCP modules

	GCPCommands.PersistentFlags().StringArrayVarP(&GCPProfiles, "profile", "",  []string{}, "GCloud CLI Profile Name")
	GCPCommands.PersistentFlags().StringVarP(&GCPProfilesList, "profiles-list", "l", "", "File containing a list of GCP CLI profile names separated by newlines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPAllProfiles, "all-profiles", "a", false, "Use all available and valid GCP CLI profiles")

	// Resource filtering options
	GCPCommands.PersistentFlags().StringArrayVarP(&GCPOrganizations, "organization", "o", []string{}, "Organization name, repetable")
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
		GCPAccessTokensCommand,
		GCPBucketsCommand,
		GCPHierarchyCommand,
	)
}
