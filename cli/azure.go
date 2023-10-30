package cli

import (
	"log"

	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/internal"
	az "github.com/Azure/go-autorest/autorest/azure"
	"github.com/spf13/cobra"
	"github.com/kyokomi/emoji"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
)

func void(cmd *cobra.Command, args []string) {}

var (
	AzTenantID         string
	AzSubscription     string
	AzRGName           string
	AzOutputFormat     string
	AzOutputDirectory  string
	AzVerbosity        int
	AzWrapTable        bool
	AzMergedTable      bool

	AzTenantRefs       []string
	AzSubscriptionRefs []string
	AzRGRefs           []string
	AzResourceRefs     []string


	AzClient           *internal.AzureClient
	AzTenants          []*subscriptions.TenantIDDescription
	AzSubscriptions    []*subscriptions.Subscription
	AzRGs              []*resources.Group
	AzResources        []*az.Resource

	AzCommands = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long:    `See "Available Commands" for Azure Modules below`,
		Short:   "See \"Available Commands\" for Azure Modules below",
		PersistentPreRun:  azurePreRun,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	AzWhoamiListRGsAlso bool
	AzWhoamiCommand     = &cobra.Command{
		Use:     "whoami",
		Aliases: []string{},
		Short:   "Display available Azure CLI sessions",
		Long: `
Display Available Azure CLI Sessions:
./cloudfox az whoami`,
		Run: runAzWhoamiCommand,
		PersistentPreRun: void,
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
		Run: runAzInventoryCommand,
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
		Run: runAzRBACCommand,
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
		Run: runAzVMsCommand,
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
		Run: runAzStorageCommand,
	}
	AzNSGRulesCommand = &cobra.Command{
		Use:     "nsg-rules",
		Aliases: []string{},
		Short:   "Enumerates azure Network Securiy Group rules",
		Long: `
Enumerate Network Security Groups rules for a specific tenant:
./cloudfox az nsg-rukes --tenant TENANT_ID

Enumerate Network Security Groups rules for a specific subscription:
./cloudfox az nsg-rules --subscription SUBSCRIPTION_ID

Enumerate rules for a specific Network Security Group:
./cloudfox az nsg-rules --nsg NSG_ID
`,
		Run: runAzNSGRulesCommand,
	}
	AzNSGLinksCommand = &cobra.Command{
		Use:     "nsg-links",
		Aliases: []string{},
		Short:   "Enumerates azure Network Securiy Groups links",
		Long: `
Enumerate Network Security Groups links for a specific tenant:
./cloudfox az nsg-links --tenant TENANT_ID

Enumerate Network Security Groups links for a specific subscription:
./cloudfox az nsg-links --subscription SUBSCRIPTION_ID

Enumerate links for a specific Network Security Group:
./cloudfox az nsg-links --nsg NSG_ID
`,
		Run: runAzNSGLinksCommand,
	}
)

func runAzWhoamiCommand (cmd *cobra.Command, args []string) {
	err := azure.AzWhoamiCommand(AzOutputDirectory, cmd.Root().Version, AzWrapTable, AzVerbosity, AzWhoamiListRGsAlso)
	if err != nil {
		log.Fatal(err)
	}
}

func runAzInventoryCommand (cmd *cobra.Command, args []string) {
	m := azure.AzInventoryModule{
		AzClient: AzClient,
	}
	err := m.AzInventoryCommand()
	if err != nil {
		log.Fatal(err)
	}
}

func runAzRBACCommand (cmd *cobra.Command, args []string) {
	err := azure.AzRBACCommand(AzClient, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
	if err != nil {
		log.Fatal(err)
	}
}

func runAzVMsCommand (cmd *cobra.Command, args []string) {
	err := azure.AzVMsCommand(AzClient, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
	if err != nil {
		log.Fatal(err)
	}
}

func runAzStorageCommand (cmd *cobra.Command, args []string) {
	err := azure.AzStorageCommand(AzClient, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
	if err != nil {
		log.Fatal(err)
	}
}

func runAzNSGRulesCommand(cmd *cobra.Command, args []string) {
	err := azure.AzNSGRulesCommand(AzClient, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
	if err != nil {
		log.Fatal(err)
	}
}

func runAzNSGLinksCommand(cmd *cobra.Command, args []string) {
	err := azure.AzNSGLinksCommand(AzClient, AzOutputFormat, AzOutputDirectory, cmd.Root().Version, AzVerbosity, AzWrapTable, AzMergedTable)
	if err != nil {
		log.Fatal(err)
	}
}

func azurePreRun(cmd *cobra.Command, args []string) {
	AzClient = internal.NewAzureClient(AzVerbosity, AzWrapTable, AzMergedTable, AzTenantRefs, AzSubscriptionRefs, AzRGRefs, AzResourceRefs, cmd, AzOutputFormat, AzOutputDirectory)
	nTenants := len(AzClient.AzTenants)
	nSubscriptions := len(AzClient.AzSubscriptions)
	nRGs := len(AzClient.AzRGs)
	nResources := len(AzClient.AzResources)
	nTotal := nTenants + nSubscriptions + nRGs + nResources
	if nTotal == 0 {
		log.Fatalf("[%s] No valid target supplied, stopping\n", cyan(emoji.Sprintf(":fox:cloudfox v%s :fox:", cmd.Root().Version)))
	}
}

func init() {

	AzWhoamiCommand.Flags().BoolVarP(&AzWhoamiListRGsAlso, "list-rgs", "l", false, "Drill down to the resource group level")

	// Global flags
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().StringVar(&AzOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	AzCommands.PersistentFlags().IntVarP(&AzVerbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	AzCommands.PersistentFlags().StringVarP(&AzTenantID, "tenant", "t", "", "Tenant name")
	AzCommands.PersistentFlags().StringVarP(&AzSubscription, "subscription", "s", "", "Subscription ID or Name")
	AzCommands.PersistentFlags().StringVarP(&AzRGName, "resource-group", "g", "", "Resource Group name")

	AzCommands.PersistentFlags().StringSliceVar(&AzTenantRefs, "tenants", []string{}, "Tenant ID or name, repeatable")
	AzCommands.PersistentFlags().StringSliceVar(&AzSubscriptionRefs, "subs", []string{}, "Subscription ID or name, repeatable")
	AzCommands.PersistentFlags().StringSliceVar(&AzRGRefs, "rgs", []string{}, "Resource Group name or ID, repeatable")
	AzCommands.PersistentFlags().StringSliceVar(&AzResourceRefs, "resource-id", []string{}, "Resource ID (/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}), repeatable")

	AzCommands.PersistentFlags().BoolVarP(&AzWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	AzCommands.PersistentFlags().BoolVarP(&AzMergedTable, "merged-table", "m", false, "Writes a single table for all subscriptions in the tenant. Default writes a table per subscription.")

	AzCommands.AddCommand(
		AzWhoamiCommand,
		AzRBACCommand,
		AzVMsCommand,
		AzStorageCommand,
		AzNSGRulesCommand,
		AzNSGLinksCommand,
		AzInventoryCommand)

}
