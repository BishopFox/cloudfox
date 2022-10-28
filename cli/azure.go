package cli

import (
	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	AzResourceGroupFilter string
	AzOutputFormat        string
	AzOutputDirectory     string
	AzVerbosity           int
	AzCommands            = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long: `
See \"Available Commands\" for Azure Modules`,
		Short: "See \"Available Commands\" for Azure Modules",

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	AzInstancesMapCommand = &cobra.Command{
		Use:     "instances",
		Aliases: []string{"instances-map"},
		Short:   `Enumerates compute instances for specified Resource Group`,
		Long: `
Enumerates compute instances for specified Resource Group`,
		Run: func(cmd *cobra.Command, args []string) {
			color.Red("This command is under development! Use at your own risk!")
			for _, scopeItem := range azure.ScopeSelection(ptr.String("1")) {
				head, body := azure.GetComputeRelevantData(
					ptr.ToString(scopeItem.Sub.ID),
					ptr.ToString(scopeItem.Rg.Name))
				utils.OutputSelector(
					AzVerbosity,
					AzOutputFormat,
					head,
					body,
					AzOutputDirectory,
					"instances",
					azure.InstancesCallingModuleName)
			}
		},
	}
	AzUserFilter     string
	AzRBACMapCommand = &cobra.Command{
		Use:     "rbac-map",
		Aliases: []string{"rbac"},
		Short:   "Display all role assignemts for all principals",
		Long: `
Display all role assignemts for all principals`,
		Run: func(cmd *cobra.Command, args []string) {
			color.Red("This command is under development! Use at your own risk!")
			m := azure.RBACMapModule{Scope: utils.AzGetScopeInformation()}
			m.RBACMap(AzVerbosity, AzOutputFormat, AzOutputDirectory, AzUserFilter)
		},
	}
)

func init() {
	// Global flags for the Azure modules
	AzInstancesMapCommand.Flags().StringVarP(&AzResourceGroupFilter, "resource-group", "g", "all", "Name of Resource Group to query")
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().IntVarP(&AzVerbosity, "verbosity", "v", 1, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	AzCommands.PersistentFlags().StringVar(&AzOutputDirectory, utils.AzureOutputDirectory, "cloudfox-output", "Output Directory ")

	// Instances Map Module Flags
	//AzInstancesMapCommand.Flags().StringVarP(&AzInstancesMapRGFilter, "resource-group", "g", "all", "Name of Resource Group to query")

	// RBAC Map Module Flags
	AzRBACMapCommand.Flags().StringVarP(&AzUserFilter, "user", "u", "all", "Display name of user to query")

	AzCommands.AddCommand(AzInstancesMapCommand, AzRBACMapCommand)
}
