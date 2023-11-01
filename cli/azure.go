package cli

import (
	"github.com/BishopFox/cloudfox/azure"
	"github.com/BishopFox/cloudfox/internal"
	az "github.com/Azure/go-autorest/autorest/azure"
	"github.com/spf13/cobra"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/subscriptions"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
)

var (
	AzTenantID         string
	AzSubscription     string
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
		PersistentPreRun: func (cmd *cobra.Command, args []string) {},
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
		Short:   "Enumerates azure Network Security Group rules",
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
		Short:   "Enumerates azure Network Security Groups links",
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
	AzClient = new(internal.AzureClient)
	AzClient.Log = internal.NewLogger("azure")
	AzClient.Log.Announce(nil, "Analyzing local Azure credentials")
	AzClient.Version = cmd.Root().Version
	AzClient.AzWrapTable = AzWrapTable
	AzClient.AzMergedTable = AzMergedTable
	AzClient.AzVerbosity = AzVerbosity
	AzClient.AzOutputFormat = AzOutputFormat
	AzClient.AzOutputDirectory = AzOutputDirectory

	m := azure.AzWhoamiModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("whoami"),
	}
	err := m.AzWhoamiCommand(AzWhoamiListRGsAlso)
	if err != nil {
		m.Log.Fatal(nil, err.Error())
	}
}

func runAzInventoryCommand (cmd *cobra.Command, args []string) {
	m := azure.AzInventoryModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("inventory"),
	}
	err := m.AzInventoryCommand()
	if err != nil {
		m.Log.Fatal(nil, err.Error())
	}
}

func runAzRBACCommand (cmd *cobra.Command, args []string) {
	m := azure.AzRBACModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("rbac"),
	}
	err := m.AzRBACCommand()
	if err != nil {
		m.Log.Fatal(nil, err.Error())
	}
}

func runAzVMsCommand (cmd *cobra.Command, args []string) {
	m := azure.AzVMsModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("vms"),
	}
	err := m.AzVMsCommand()
	if err != nil {
		m.Log.Fatal(nil, err.Error())
	}
}

func runAzStorageCommand (cmd *cobra.Command, args []string) {
	m := azure.AzStorageModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("storage"),
	}
	err := m.AzStorageCommand()
	if err != nil {
		m.Log.Fatal(nil, err.Error())
	}
}

func runAzNSGRulesCommand(cmd *cobra.Command, args []string) {
	m := azure.AzNSGModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("nsg"),
	}
	err := m.AzNSGCommand("rules")
	if err != nil {
		m.Log.Fatal([]string{"rules"}, err.Error())
	}
}

func runAzNSGLinksCommand(cmd *cobra.Command, args []string) {
	m := azure.AzNSGModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("nsg"),
	}
	err := m.AzNSGCommand("links")
	if err != nil {
		m.Log.Fatal([]string{"links"}, err.Error())
	}
}

func runAzNetScanCommand(cmd *cobra.Command, args []string) {
	m := azure.AzNetScanModule{
		AzClient: AzClient,
		Log:      internal.NewLogger("netscan"),
	}
	err := m.AzNetScanCommand()
	if err != nil {
		m.Log.Fatal(nil, err.Error())
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
		AzClient.Log.Fatal(nil, "No valid target supplied, stopping")
	}
}

func init() {

	AzWhoamiCommand.Flags().BoolVarP(&AzWhoamiListRGsAlso, "list-rgs", "l", false, "Drill down to the resource group level")

	// Global flags
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().StringVar(&AzOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	AzCommands.PersistentFlags().IntVarP(&AzVerbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")

	AzCommands.PersistentFlags().StringSliceVarP(&AzTenantRefs, "tenant", "t", []string{}, "Tenant ID or name, repeatable")
	AzCommands.PersistentFlags().StringSliceVarP(&AzSubscriptionRefs, "subscription", "s", []string{}, "Subscription ID or name, repeatable")
	AzCommands.PersistentFlags().StringSliceVarP(&AzRGRefs, "resource-group", "r", []string{}, "Resource Group name or ID, repeatable")
	AzCommands.PersistentFlags().StringSliceVarP(&AzResourceRefs, "resource-id", "i", []string{}, "Resource ID (/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}), repeatable")

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
