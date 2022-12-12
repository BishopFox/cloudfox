package cli

import (
	"log"

	"github.com/BishopFox/cloudfox/azure"
	"github.com/spf13/cobra"
)

var (
	AzTenantID        string
	AzSubscriptionID  string
	AzRGName          string
	AzOutputFormat    string
	AzOutputDirectory string
	AzVerbosity       int

	AzCommands = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long:    `See "Available Commands" for Azure Modules below`,
		Short:   "See \"Available Commands\" for Azure Modules below",

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	AzWhoamiCommand = &cobra.Command{
		Use:     "whoami",
		Aliases: []string{},
		Short:   "Display available Azure CLI sessions",
		Long: `
Display Available Azure CLI Sessions:
./cloudfox az whoami`,
		Run: func(cmd *cobra.Command, args []string) {
			azure.AzWhoamiCommand()
		},
	}
	AzRBACCommand = &cobra.Command{
		Use:     "rbac",
		Aliases: []string{},
		Short:   "Display role assignemts for Azure principals",
		Long: `
Enumerate role assignments for a all subscriptions in a specific tenant:
./cloudfox az rbac --tenant TENANT_ID

Enumerate role assignments for a specific subscription:
./cloudfox az rbac -t TENANT_ID -s SUBSCRIPTION_ID
`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzRBACCommand(azure.CloudFoxRBACclient{}, AzTenantID, AzSubscriptionID, AzOutputFormat, AzVerbosity)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	AzInstancesCommand = &cobra.Command{
		Use:     "instances",
		Aliases: []string{},
		Short:   "Enumerates Azure Compute instances",
		Long: `
Select scope from interactive menu:
./cloudfox az instances

Enumerate VMs for all resource groups in a subscription:
./cloudfox az instances --subscription SUBSCRIPTION_ID

Enumerate VMs from a specific resource group:
./cloudfox az instances -s SUBSCRIPTION_ID -g RESOURCE_GROUP_NAME`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzInstancesCommand(AzTenantID, AzSubscriptionID, AzOutputFormat, AzVerbosity)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	AzStorageCommand = &cobra.Command{
		Use:     "storage",
		Aliases: []string{},
		Short:   "Enumerates azure storage accounts",
		Long: `
Enumerate storage accounts for a specific tenant:
./cloudfox az storage --tenant TENANT_ID

Enumerate storage accounts for a specific subscription:
./cloudfox az storage -t TENANT_ID -s SUBSCRIPTION_ID

Enumerate storage accounts for a specific resource group:
./cloudfox az storage -t TENANT_ID -s SUBSCRIPTION_ID -g RESOURCE_GROUP_NAME
`,
		Run: func(cmd *cobra.Command, args []string) {
			azure.AzStorageCommand(AzTenantID, AzSubscriptionID, AzRGName, AzOutputFormat, AzVerbosity)
		},
	}
)

func init() {
	// Global flags
	AzCommands.PersistentFlags().StringVarP(
		&AzOutputFormat,
		"output",
		"o",
		"all",
		"[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().IntVarP(
		&AzVerbosity,
		"verbosity",
		"v",
		2,
		"1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	AzCommands.PersistentFlags().StringVarP(
		&AzTenantID,
		"tenant",
		"t",
		"",
		"Tenant name")
	AzCommands.PersistentFlags().StringVarP(
		&AzSubscriptionID,
		"subscription",
		"s",
		"",
		"Subscription Name")
	AzCommands.PersistentFlags().StringVarP(
		&AzRGName,
		"resource-group",
		"g",
		"",
		"Resource Group name")

	AzCommands.AddCommand(
		AzWhoamiCommand,
		AzRBACCommand,
		AzInstancesCommand,
		AzStorageCommand)
}
