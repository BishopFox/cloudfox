package cli

import (
	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/spf13/cobra"
)

var (
	AzSubFilter       string
	AzRGFilter        string
	AzOutputFormat    string
	AzOutputDirectory string
	AzVerbosity       int
	AzCommands        = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long:    `See "Available Commands" for Azure Modules`,
		Short:   "See \"Available Commands\" for Azure Modules",

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	AzInstancesCommand = &cobra.Command{
		Use:     "instances",
		Aliases: []string{},
		Short:   "Enumerates Azure Compute Instances",
		Long: `
Select scope from interactive menu:
./cloudfox az instances

Enumerate VMs from a specific resource group:
./cloudfox az instances --resource-group RESOURCE_GROU_NAME

Enumerate VMs for all resource groups in a subscription:
./cloudfox az instances --subscription SUBSCRIPTION_ID`,
		Run: func(cmd *cobra.Command, args []string) {
			azure.AzRunInstancesCommand(AzSubFilter, AzRGFilter, AzOutputFormat, AzVerbosity)
		},
	}

	AzRBACMapCommand = &cobra.Command{
		Use:     "rbac",
		Aliases: []string{},
		Short:   "Display all role assignemts for all Azure principals",
		Long: `
Select scope from interactive menu:
./cloudfox az rbac

Enumerate role assignments for a specific subscriptions:
./cloudfox az rbac --subscription SUBSCRIPTION_ID
`,
		Run: func(cmd *cobra.Command, args []string) {
			/*
				RBAC COMMAND LOGIC HERE
			*/
		},
	}
)

func init() {
	// Global flags for the Azure modules
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().IntVarP(&AzVerbosity, "verbosity", "v", 1, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	AzCommands.PersistentFlags().StringVar(&AzOutputDirectory, constants.CLOUDFOX_BASE_OUTPUT_DIRECTORY, "cloudfox-output", "Output Directory ")

	// Instance Command Flags
	AzInstancesCommand.Flags().StringVarP(&AzSubFilter, "subscription", "s", "interactive", "Subscription Name")
	AzInstancesCommand.Flags().StringVarP(&AzRGFilter, "resource-group", "g", "interactive", "Resource Group Name")

	AzCommands.AddCommand(AzInstancesCommand, AzRBACMapCommand)
}
