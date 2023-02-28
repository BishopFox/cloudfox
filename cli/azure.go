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
	AzWrapTable       bool

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
			azure.AzWhoamiCommand(cmd.Root().Version, AzWrapTable)
		},
	}
	AzInventoryCommand = &cobra.Command{
		Use:     "inventory",
		Aliases: []string{"inv"},
		Short:   "Display an inventory table of all resources per location",
		Long: `
Enumerate inventory for a specific tenant:
./cloudfox az inventory --tenant TENANT_ID

Enumerate inventory for a specific subscription:
./cloudfox az inventory --subscription SUBSCRIPTION_ID
`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzInventoryCommand(AzTenantID, AzSubscriptionID, cmd.Root().Version, AzVerbosity, AzWrapTable)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	AzRBACCommand = &cobra.Command{
		Use:     "rbac",
		Aliases: []string{},
		Short:   "Display role assignemts for Azure principals",
		Long: `
Enumerate role assignments for a specific tenant:
./cloudfox az rbac --tenant TENANT_ID

Enumerate role assignments for a specific subscription:
./cloudfox az rbac --subscription SUBSCRIPTION_ID
`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzRBACCommand(AzTenantID, AzSubscriptionID, AzOutputFormat, cmd.Root().Version, AzVerbosity, AzWrapTable)
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
Enumerate VMs for a specific tenant:
./cloudfox az instances --tenant TENANT_ID

Enumerate VMs for a specific subscription:
./cloudfox az instances --subscription SUBSCRIPTION_ID`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzInstancesCommand(AzTenantID, AzSubscriptionID, AzOutputFormat, cmd.Root().Version, AzVerbosity, AzWrapTable)
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
./cloudfox az storage --subscription SUBSCRIPTION_ID
`,
		Run: func(cmd *cobra.Command, args []string) {
			azure.AzStorageCommand(AzTenantID, AzSubscriptionID, AzOutputFormat, cmd.Root().Version, AzVerbosity, AzWrapTable)
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
		"Subscription name")
	AzCommands.PersistentFlags().StringVarP(
		&AzRGName,
		"resource-group",
		"g",
		"",
		"Resource Group name")
	AzCommands.PersistentFlags().BoolVarP(
		&AzWrapTable,
		"wrap",
		"w",
		false,
		"Wrap table to fit in terminal (complicates grepping)")

	AzCommands.AddCommand(
		AzWhoamiCommand,
		AzRBACCommand,
		AzInstancesCommand,
		AzStorageCommand,
		AzInventoryCommand)
}
