package cli

import (
	"log"

	"github.com/BishopFox/cloudfox/gcp"
	"github.com/spf13/cobra"
)

var (
	GCPOrganization		[]string
	GCPProjectID		[]string
	GCPFolderName		[]string
	GCPOutputFormat		string
	GCPOutputDirectory	string
	GCPVerbosity		int
	GCPWrapTable		bool

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
		Run: func(cmd *cobra.Command, args []string) {
			err := gcp.GCPWhoamiCommand(cmd.Root().Version, GCPWrapTable)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
)

func init() {
	// Global flags
	GCPCommands.PersistentFlags().StringVarP(
		&GCPOutputFormat,
		"output",
		"o",
		"all",
		"[\"table\" | \"csv\" | \"all\" ]")
	GCPCommands.PersistentFlags().IntVarP(
		&GCPVerbosity,
		"verbosity",
		"v",
		2,
		"1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	GCPCommands.PersistentFlags().StringArrayVarP(
		&GCPOrganization,
		"organization",
		"g",
		[]string{},
		"Organization name, repetable")
	GCPCommands.PersistentFlags().StringArrayVarP(
		&GCPProjectID,
		"projectid",
		"p",
		[]string{},
		"Project ID, repeatable")
	GCPCommands.PersistentFlags().StringArrayVarP(
		&GCPFolderName,
		"folderid",
		"f",
		[]string{},
		"Folder ID, repeatable")
	GCPCommands.PersistentFlags().BoolVarP(
		&GCPWrapTable,
		"wrap",
		"w",
		false,
		"Wrap table to fit in terminal (complicates grepping)")

	GCPCommands.AddCommand(
		GCPWhoamiCommand,
		)
}
