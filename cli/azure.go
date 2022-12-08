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
	AzCommands        = &cobra.Command{
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
		Short:   "Display Available Azure CLI Sessions",
		Long: `
Display Available Azure CLI Sessions:
./cloudfox az whoami`,
		Run: func(cmd *cobra.Command, args []string) {
			azure.AzWhoamiCommand()
		},
	}

	AzInstancesCommand = &cobra.Command{
		Use:     "instances",
		Aliases: []string{},
		Short:   "Enumerates Azure Compute Instances",
		Long: `
Select scope from interactive menu:
./cloudfox az instances

Enumerate VMs for all resource groups in a subscription:
./cloudfox az instances --subscription SUBSCRIPTION_ID

Enumerate VMs from a specific resource group:
./cloudfox az instances -s SUBSCRIPTION_ID -g RESOURCE_GROUP_NAME`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzInstancesCommand(AzSubscriptionID, AzRGName, AzOutputFormat, AzVerbosity)
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	AzRBACCommand = &cobra.Command{
		Use:     "rbac",
		Aliases: []string{},
		Short:   "Display all role assignemts for all Azure principals",
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
)

func init() {
	// Global flags
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().IntVarP(&AzVerbosity, "verbosity", "v", 1, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	AzCommands.PersistentFlags().StringVarP(&AzTenantID, "tenant", "t", "", "Tenant name")
	AzCommands.PersistentFlags().StringVarP(&AzSubscriptionID, "subscription", "s", "", "Subscription Name")
	AzCommands.PersistentFlags().StringVarP(&AzRGName, "resource-group", "g", "", "Resource Group name")

	AzCommands.AddCommand(
		AzWhoamiCommand,
		AzInstancesCommand,
		AzRBACCommand)
}
