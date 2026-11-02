package cli

import (
	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var azureLogger = internal.NewLogger()

var (
	AzTenantID        string
	AzSubscription    string
	AzRGName          string
	AzOutputFormat    string
	AzOutputDirectory string
	AzVerbosity       int
	AzWrapTable       bool
	AzMergedTable     bool

	AzCommands = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long:    `See "Available Commands" for Azure Modules below`,
		Short:   "See \"Available Commands\" for Azure Modules below",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	AzTokenCacheListRGs bool
	AzWhoamiCommand     = &cobra.Command{
		Use:     "whoami",
		Aliases: []string{},
		Short:   "Display the caller's Entra ID memberships and Azure RBAC assignments",
		Long: `
Display the caller's Entra ID memberships and Azure RBAC assignments:
./cloudfox az whoami`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzWhoamiCommand(AzOutputDirectory, cmd.Root().Version, AzWrapTable, AzVerbosity)
			if err != nil {
				azureLogger.FatalM(err.Error(), "whoami")
			}
		},
	}
	AzTokenCacheCommand = &cobra.Command{
		Use:     "tokencache",
		Aliases: []string{"token-cache"},
		Short:   "Display available Azure CLI sessions",
		Long: `
Display available Azure CLI tenants and subscriptions:
./cloudfox az tokencache

Include resource groups:
./cloudfox az tokencache --list-rgs`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := azure.AzTokenCacheCommand(AzOutputDirectory, cmd.Root().Version, AzWrapTable, AzVerbosity, AzTokenCacheListRGs); err != nil {
				azureLogger.FatalM(err.Error(), "tokencache")
			}
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
			err := azure.AzInventoryCommand(AzTenantID, AzSubscription, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
			if err != nil {
				azureLogger.FatalM(err.Error(), "inventory")
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

			err := azure.AzRBACCommand(AzTenantID, AzSubscription, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
			if err != nil {
				azureLogger.FatalM(err.Error(), "rbac")
			}
		},
	}
	AzVMsCommand = &cobra.Command{
		Use:     "vms",
		Aliases: []string{"vms", "virtualmachines"},
		Short:   "Enumerates Azure Compute virtual machines",
		Long: `
Enumerate VMs for a specific tenant:
./cloudfox az vms --tenant TENANT_ID

Enumerate VMs for a specific subscription:
./cloudfox az vms --subscription SUBSCRIPTION_ID`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzVMsCommand(AzTenantID, AzSubscription, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
			if err != nil {
				azureLogger.FatalM(err.Error(), "vms")
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
			err := azure.AzStorageCommand(AzTenantID, AzSubscription, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
			if err != nil {
				azureLogger.FatalM(err.Error(), "storage")
			}
		},
	}
	AzACRCommand = &cobra.Command{
		Use:     "acr",
		Aliases: []string{"container-registries"},
		Short:   "Enumerates Azure Container Registries",
		Long: `
Enumerate container registries for a specific tenant:
./cloudfox az acr --tenant TENANT_ID

Enumerate container registries for a specific subscription:
./cloudfox az acr --subscription SUBSCRIPTION_ID
`,
		Run: func(cmd *cobra.Command, args []string) {
			err := azure.AzACRCommand(AzTenantID, AzSubscription, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
			if err != nil {
				azureLogger.FatalM(err.Error(), "acr")
			}
		},
	}
	AzFuncCommand = &cobra.Command{
		Use:     "func",
		Aliases: []string{"functions"},
		Short:   "Enumerates Azure Function Apps and their configuration",
		Run: func(cmd *cobra.Command, args []string) {
			if err := azure.AzFuncCommand(AzTenantID, AzSubscription, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable); err != nil {
				azureLogger.FatalM(err.Error(), "func")
			}
		},
	}
	AzAutomationCommand = &cobra.Command{
		Use:     "automation",
		Aliases: []string{"automations"},
		Short:   "Enumerates Azure Automation Accounts and their assets",
		Run: func(cmd *cobra.Command, args []string) {
			if err := azure.AzAutomationCommand(AzTenantID, AzSubscription, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable); err != nil {
				azureLogger.FatalM(err.Error(), "automation")
			}
		},
	}
)

func init() {

	AzTokenCacheCommand.Flags().BoolVarP(&AzTokenCacheListRGs, "list-rgs", "l", false, "Drill down to the resource group level")

	// Global flags
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().StringVar(&AzOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	AzCommands.PersistentFlags().IntVarP(&AzVerbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	AzCommands.PersistentFlags().StringVarP(&AzTenantID, "tenant", "t", "", "Tenant name")
	AzCommands.PersistentFlags().StringVarP(&AzSubscription, "subscription", "s", "", "Subscription ID or Name")
	AzCommands.PersistentFlags().StringVarP(&AzRGName, "resource-group", "g", "", "Resource Group name")
	AzCommands.PersistentFlags().BoolVarP(&AzWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	AzCommands.PersistentFlags().BoolVarP(&AzMergedTable, "merged-table", "m", false, "Writes a single table for all subscriptions in the tenant. Default writes a table per subscription.")

	AzCommands.AddCommand(
		AzWhoamiCommand,
		AzTokenCacheCommand,
		AzRBACCommand,
		AzVMsCommand,
		AzStorageCommand,
		AzACRCommand,
		AzFuncCommand,
		AzAutomationCommand,
		AzInventoryCommand)

}
