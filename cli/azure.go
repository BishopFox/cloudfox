package cli

import (
	"fmt"
	"path/filepath"

	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/constants"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
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
			AzRunInstancesCommand(AzSubFilter, AzRGFilter, AzOutputFormat, AzVerbosity)
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
				color.Red("This command is under development! Use at your own risk!")
				m := azure.RBACMapModule{Scope: utils.AzGetScopeInformation()}
				m.RBACMap(AzVerbosity, AzOutputFormat, AzOutputDirectory, AzUserFilter)
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
	AzInstancesCommand.Flags().StringVarP(&AzSubFilter, "subscription", "s", "interactive", "Subscription ID")
	AzInstancesCommand.Flags().StringVarP(&AzRGFilter, "resource-group", "g", "interactive", "Resource Group's Name")

	AzCommands.AddCommand(AzInstancesCommand, AzRBACMapCommand)
}

func AzRunInstancesCommand(AzSubFilter, AzRGFilter, AzOutputFormat string, AzVerbosity int) {
	if AzRGFilter == "interactive" && AzSubFilter == "interactive" {
		for _, scopeItem := range azure.ScopeSelection(nil) {
			tableHead, tableBody := azure.GetComputeRelevantData(
				ptr.ToString(scopeItem.Sub.ID),
				ptr.ToString(scopeItem.Rg.Name))

			utils.OutputSelector(
				AzVerbosity,
				AzOutputFormat,
				tableHead,
				tableBody,
				filepath.Join(
					constants.CLOUDFOX_BASE_OUTPUT_DIRECTORY,
					fmt.Sprintf("%s_%s",
						constants.AZ_OUTPUT_DIRECTORY,
						ptr.ToString(scopeItem.Rg.Name))),
				constants.AZ_INTANCES_MODULE_NAME,
				constants.AZ_INTANCES_MODULE_NAME,
				ptr.ToString(scopeItem.Rg.Name))
		}
	} else if AzRGFilter == "interactive" && AzSubFilter != "interactive" {
		fmt.Printf("[%s] Enumerating VMs for subscription: %s\n", cyan(constants.AZ_INTANCES_MODULE_NAME), AzSubFilter)

		for _, sub := range azure.GetSubscriptions() {
			if ptr.ToString(sub.SubscriptionID) == AzSubFilter {
				for _, rg := range azure.GetResourceGroupsPerSub(ptr.ToString(sub.SubscriptionID)) {
					tableHead, tableBody := azure.GetComputeRelevantData(
						ptr.ToString(sub.ID),
						ptr.ToString(rg.Name))

					if tableBody != nil {
						utils.OutputSelector(
							AzVerbosity,
							AzOutputFormat,
							tableHead,
							tableBody,
							filepath.Join(
								constants.CLOUDFOX_BASE_OUTPUT_DIRECTORY,
								fmt.Sprintf("%s_%s",
									constants.AZ_OUTPUT_DIRECTORY,
									ptr.ToString(rg.Name))),
							constants.AZ_INTANCES_MODULE_NAME,
							constants.AZ_INTANCES_MODULE_NAME,
							ptr.ToString(rg.Name))
					}
				}
			}
		}
	} else if AzRGFilter != "interactive" && AzSubFilter == "interactive" {
		fmt.Printf("[%s] Enumerating VMs for resource group: %s\n", cyan(constants.AZ_INTANCES_MODULE_NAME), AzRGFilter)

		sub := azure.GetSubscriptionForResourceGroup(AzRGFilter)
		tableHead, tableBody := azure.GetComputeRelevantData(
			ptr.ToString(sub.ID),
			AzRGFilter)

		utils.OutputSelector(
			AzVerbosity,
			AzOutputFormat,
			tableHead,
			tableBody,
			filepath.Join(
				constants.CLOUDFOX_BASE_OUTPUT_DIRECTORY,
				fmt.Sprintf("%s_%s",
					constants.AZ_OUTPUT_DIRECTORY,
					AzRGFilter)),
			constants.AZ_INTANCES_MODULE_NAME,
			constants.AZ_INTANCES_MODULE_NAME,
			AzRGFilter)
	}
}
