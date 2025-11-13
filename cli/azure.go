package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/BishopFox/cloudfox/azure/commands"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var (
	AzTenantID          string
	AzSubscription      string
	AzRGName            string
	AzOutputFormat      string
	AzOutputDirectory   string
	AzVerbosity         int
	AzWrapTable         bool
	AzMergedTable       bool
	AzWhoamiListRGsAlso bool

	logger = internal.NewLogger()

	AzCommands = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long:    `See "Available Commands" for Azure Modules below`,
		Short:   "See \"Available Commands\" for Azure Modules below",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !isAzureAuthenticated() {
				logger.ErrorM("[ERROR] You must authenticate to Azure first. Run: az login", globals.AZ_UTILS_MODULE_NAME)
				os.Exit(1)
			}
			globals.AZ_VERBOSITY = AzVerbosity
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	AzAllChecksCommand = &cobra.Command{
		Use:   "all-checks",
		Short: "Runs all available Azure commands",
		Long: `
Executes all available Azure commands for a specific tenant:
./cloudfox az kv --tenant TENANT_ID

Executes all available Azure commands for a specific subscription:
./cloudfox az kv --subscription SUBSCRIPTION_ID`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !isAzureAuthenticated() {
				logger.ErrorM("[ERROR] You must authenticate to Azure first. Run: az login", globals.AZ_UTILS_MODULE_NAME)
				os.Exit(1)
			}
			globals.AZ_VERBOSITY = AzVerbosity
		},
		Run: func(cmd *cobra.Command, args []string) {
			// ========== STEP 1: Run Principals FIRST ==========
			// This provides identity and RBAC role lookup for all subsequent commands
			logger.InfoM("Running command: principals", "all-checks")
			commands.AzPrincipalsCommand.Run(cmd, args)

			// ========== STEP 2: Run all other commands ==========
			// Commands we want to skip
			skip := map[string]bool{
				commands.AzDevOpsArtifactsCommand.Use: true,
				commands.AzDevOpsPipelinesCommand.Use: true,
				commands.AzDevOpsProjectsCommand.Use:  true,
				commands.AzDevOpsReposCommand.Use:     true,
				commands.AzDevOpsSecurityCommand.Use:  true,
				// commands.AzDevOpsAgentsCommand.Use:    true, // Disabled - compilation issues
				commands.AzPrincipalsCommand.Use:      true, // Skip since we ran it first
				commands.AzAccessKeysCommand.Use:      true, // Skip since we run it last
				//				commands.AzRBACCommand.Use:            true,
			}

			for _, childCmd := range AzCommands.Commands() {
				// Skip self and skip unwanted commands
				if childCmd == cmd || skip[childCmd.Use] {
					continue
				}

				logger.InfoM(fmt.Sprintf("Running command: %s", childCmd.Use), "all-checks")
				childCmd.Run(cmd, args)
			}
			// ========== STEP 3: Run Access Keys Last ==========
			// heavy graph API usage, so run last after graph API limiting resets
			logger.InfoM("Running command: access-keys", "all-checks")
			commands.AzAccessKeysCommand.Run(cmd, args)

		},
	}
)

func isAzureAuthenticated() bool {
	// Check for active account
	if err := exec.Command("az", "account", "show").Run(); err != nil {
		return false
	}

	// Check if session token can be acquired
	out, err := exec.Command("az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv").Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return false
	}

	return true
}

func init() {

	// Global flags
	AzCommands.PersistentFlags().StringVarP(&AzOutputFormat, "output", "o", "all", "[\"table\" | \"csv\" | \"all\" ]")
	AzCommands.PersistentFlags().StringVar(&AzOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	AzCommands.PersistentFlags().IntVarP(&AzVerbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n4 = Print debug and control messages, module output, and loot file output\n")
	AzCommands.PersistentFlags().StringVarP(&AzTenantID, "tenant", "t", "", "Tenant name")
	AzCommands.PersistentFlags().StringVarP(&AzSubscription, "subscription", "s", "", "Subscription ID or Name")
	AzCommands.PersistentFlags().StringVarP(&AzRGName, "resource-group", "g", "", "Resource Group name")
	AzCommands.PersistentFlags().BoolVarP(&AzWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	AzCommands.PersistentFlags().BoolVarP(&AzMergedTable, "merged-table", "m", false, "Writes a single table for all subscriptions in the tenant. Default writes a table per subscription.")

	AzCommands.AddCommand(
		commands.AzAccessKeysCommand,
		commands.AzAcrCommand,
		commands.AzAksCommand,
		commands.AzAPIManagementCommand,
		commands.AzAppConfigurationCommand,
		commands.AzAppGatewayCommand,
		commands.AzArcCommand,
		commands.AzAutomationCommand,
		commands.AzBackupInventoryCommand,
		commands.AzBastionCommand,
		commands.AzBatchCommand,
		commands.AzCDNCommand,
		commands.AzComplianceDashboardCommand,
		commands.AzConditionalAccessCommand,
		commands.AzConsentGrantsCommand,
		commands.AzCostSecurityCommand,
		commands.AzContainerJobsCommand,
		commands.AzDatabasesCommand,
		commands.AzDatabricksCommand,
		commands.AzDataExfiltrationCommand,
		commands.AzDataFactoryCommand,
		commands.AzDeploymentsCommand,
		commands.AzDisksCommand,
		// commands.AzDevOpsAgentsCommand, // Disabled - compilation issues
		commands.AzDevOpsArtifactsCommand,
		commands.AzDevOpsPipelinesCommand,
		commands.AzDevOpsProjectsCommand,
		commands.AzDevOpsReposCommand,
		commands.AzDevOpsSecurityCommand,
		commands.AzEndpointsCommand,
		commands.AzEnterpriseAppsCommand,
		commands.AzExpressRouteCommand,
		commands.AzFederatedCredentialsCommand,
		commands.AzFilesystemsCommand,
		commands.AzFirewallCommand,
		commands.AzFrontDoorCommand,
		commands.AzFunctionsCommand,
		commands.AzHDInsightCommand,
		// commands.AzIdentityProtectionCommand, // Disabled - compilation issues
		commands.AzInventoryCommand,
		commands.AzIoTHubCommand,
		commands.AzKeyVaultCommand,
		commands.AzKustoCommand,
		commands.AzLighthouseCommand,
		// commands.AzLateralMovementCommand, // Disabled - compilation issues
		commands.AzLoadBalancersCommand,
		commands.AzLoadTestingCommand,
		commands.AzLogicAppsCommand,
		commands.AzMachineLearningCommand,
		commands.AzMonitorCommand,
		commands.AzNetworkInterfacesCommand,
		// commands.AzNetworkExposureCommand, // Disabled - compilation issues
		commands.AzNetworkTopologyCommand,
		commands.AzNSGCommand,
		commands.AzPolicyCommand,
		commands.AzPrincipalsCommand,
		// commands.AzPrivilegeEscalationCommand, // Disabled - compilation issues
		commands.AzPermissionsCommand,
		commands.AzPrivateLinkCommand,
		commands.AzRBACCommand,
		// commands.AzRedisCommand, // Disabled - compilation issues
		commands.AzResourceGraphCommand,
		commands.AzRoutesCommand,
		// commands.AzSecurityCenterCommand, // Disabled - compilation issues
		// commands.AzSentinelCommand, // Disabled - compilation issues
		commands.AzServiceFabricCommand,
		commands.AzSignalRCommand,
		commands.AzStorageCommand,
		commands.AzSpringAppsCommand,
		commands.AzStreamAnalyticsCommand,
		commands.AzSynapseCommand,
		// commands.AzTrafficManagerCommand, // Disabled - compilation issues
		commands.AzVmsCommand,
		commands.AzVNetsCommand,
		// commands.AzVPNGatewayCommand, // Disabled - compilation issues
		commands.AzWebAppsCommand,
		commands.AzWhoamiCommand,

		AzAllChecksCommand,
	)
}
