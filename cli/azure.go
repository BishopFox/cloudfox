package cli

import (
	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/spf13/cobra"
)

var (
	AzOutputFormat string
	AzCommands     = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long: `
See \"Available Commands\" for Azure Modules`,
		Short: "See \"Available Commands\" for Azure Modules",

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	AzInstancesMapRGFilter string
	AzInstancesMapCommand  = &cobra.Command{
		Use:     "instances-map",
		Aliases: []string{"instances"},
		Short:   `Enumerates compute instances for specified Resource Group`,
		Long: `
Enumerates compute instances for specified Resource Group`,
		Run: func(cmd *cobra.Command, args []string) {
			m := azure.InstancesMapModule{Scope: utils.AzGetScopeInformation()}
			m.InstancesMap(AzOutputFormat, AzInstancesMapRGFilter)
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
			m := azure.RBACMapModule{Scope: utils.AzGetScopeInformation()}
			m.RBACMapModule(AzOutputFormat, AzUserFilter)
		},
	}
)

func init() {

	// Instances Map Module Flags
	AzInstancesMapCommand.Flags().StringVarP(&AzInstancesMapRGFilter, "resource-group", "g", "all", "Name of Resource Group to query")

	// RBAC Map Module Flags
	AzRBACMapCommand.Flags().StringVarP(&AzUserFilter, "user", "u", "all", "Display name of user to query")

	// Global flags for the AWS modules
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "table", "[\"table\" | \"csv\"]")

	AzCommands.AddCommand(AzInstancesMapCommand, AzRBACMapCommand)
}
