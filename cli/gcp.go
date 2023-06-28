package cli

import (
	"log"
	"fmt"
	"os"
	"github.com/BishopFox/cloudfox/gcp"
	internal_gcp "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/BishopFox/cloudfox/globals"
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

	// command specific options
	GCPTreeFormat		string

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
		Args:    cobra.MinimumNArgs(0),
		Long: `
Display available bucket information:
./cloudfox gcp buckets [project [project...]]`,
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
	// bypass profile selection logic for commands that don't require authentication
	if GCPAccessTokensCommand.CalledAs() != "" {
		return
	} else if GCPAccessTokensCommand.CalledAs() != "" {
		return
	}
	// Ensure that profile selection is consistent
	if (len(GCPProfiles) != 0 || GCPProfilesList != "") && GCPAllProfiles {
		GCPLogger.Fatal("Error specifying GCP profiles. Choose only one of -p/--profile, -a/--all-profiles, -l/--profiles-list")
	
	}
	// at this point, GCPProfiles only contains the profiles submitted over the CLI

	// if the --all-profiles option is submitted, replacing the profiles with all existing ones
	if GCPAllProfiles {
		GCPProfiles = internal_gcp.GetAllGCPProfiles()
	}

	// if --profiles-list option is submitted, adding the profiles from the list to the existing ones
	if GCPProfilesList != "" {
		GCPProfiles = append(GCPProfiles, internal_gcp.GetSelectedGCPProfiles(GCPProfilesList)...)
	}

	// remove duplicate
	GCPProfiles = internal.RemoveDuplicateStr(GCPProfiles)

	if (len(GCPProfiles) == 0) {
		GCPLogger.Info("No GCP profile selection submitted, trying to find the default profile...")
		var allProfiles = internal_gcp.GetAllGCPProfiles()
		if len(allProfiles) > 0 {
			GCPProfiles = append(GCPProfiles, allProfiles[len(allProfiles) - 1])
		} else {
			GCPLogger.Fatal("Could not find any usable GCP profile")
		}
	}

	if !GCPConfirm {
		result := internal_gcp.ConfirmSelectedProfiles(GCPProfiles)
		if !result {
			os.Exit(1)
		}
	}
}

func runGCPHierarchyCommand(cmd *cobra.Command, args []string) {
	for _, profile := range GCPProfiles {
		var client = internal_gcp.NewGCPClient(profile)
		m := gcp.HierarchyModule{
			Organizations:	GCPOrganizations,
			Projects:		GCPProjectIDs,
			Folders:		GCPFolderIDs,
			Client:			*client,
		}
		err := m.DisplayHierarchy(GCPTreeFormat)
		if err != nil {
			GCPLogger.ErrorM(fmt.Sprintf("Error running %s module on profile %s", globals.GCP_HIERARCHY_MODULE_NAME, profile), globals.GCP_HIERARCHY_MODULE_NAME)
		}
	}
}

func runGCPBucketsCommand(cmd *cobra.Command, args []string) {
	for _, profile := range GCPProfiles {
		var client = internal_gcp.NewGCPClient(profile)
		m := gcp.BucketsModule{
			Organizations:	GCPOrganizations,
			Projects:		GCPProjectIDs,
			Folders:		GCPFolderIDs,
			Client:			*client,
		}
		err := m.ListBuckets(args)
		if err != nil {
			GCPLogger.ErrorM(fmt.Sprintf("Error running %s module on profile %s", globals.GCP_BUCKETS_MODULE_NAME, profile), globals.GCP_BUCKETS_MODULE_NAME)
		}
	}
}

func runGCPAccessTokensCommand(cmd *cobra.Command, args []string) {
	m := gcp.AccessTokensModule{
		Organizations:	GCPOrganizations,
		Projects:		GCPProjectIDs,
		Folders:		GCPFolderIDs,
	}
	err := m.PrintAccessTokens(GCPOutputFormat, GCPOutputDirectory, Verbosity)
	if err != nil {
		log.Fatal(err)
	}
}

func runGCPInventoryCommand(cmd *cobra.Command, args []string) {
	for _, profile := range GCPProfiles {
		var client = internal_gcp.NewGCPClient(profile)
		m := gcp.InventoryModule{
			Organizations:	GCPOrganizations,
			Projects:		GCPProjectIDs,
			Folders:		GCPFolderIDs,
			Client:			*client,
		}
		err := m.PrintInventory(GCPOutputFormat, GCPOutputDirectory, Verbosity)
		if err != nil {
			GCPLogger.ErrorM(fmt.Sprintf("Error running %s module on profile %s: %v", globals.GCP_INVENTORY_MODULE_NAME, profile, err), globals.GCP_INVENTORY_MODULE_NAME)
		}
	}
}

func init() {
	cobra.OnInitialize(initGCPProfiles)
	// Globals flags for the GCP modules

	GCPCommands.PersistentFlags().StringArrayVar(&GCPProfiles, "profile", []string{}, "GCloud CLI Profile Name")
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
	
	GCPHierarchyCommand.Flags().BoolVarP(&HierarchyIncludeIDs, "ids", "i", false, "Use this flag to display resources IDs in the hierarchy tree")
	GCPHierarchyCommand.Flags().StringVar(&GCPTreeFormat, "tree", "horizontal", "[\"horizontal\" | \"vertical\" ]")

	GCPCommands.AddCommand(
		GCPAccessTokensCommand,
		GCPHierarchyCommand,
		GCPInventoryCommand,
		GCPBucketsCommand,
	)
}
