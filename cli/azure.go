package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/azure/commands"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
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

	// Token flags
	AzARMToken   string // ARM token passed via --arm-token flag
	AzGraphToken string // Graph token passed via --graph-token flag

	// Cache flags
	AzRefreshCache bool

	logger = internal.NewLogger()

	AzCommands = &cobra.Command{
		Use:     "azure",
		Aliases: []string{"az"},
		Long:    `See "Available Commands" for Azure Modules below`,
		Short:   "See \"Available Commands\" for Azure Modules below",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			globals.AZ_VERBOSITY = AzVerbosity
			globals.AZ_REFRESH_CACHE = AzRefreshCache

			// If --refresh-cache, clear the in-memory cache
			if globals.AZ_REFRESH_CACHE {
				azinternal.ClearAzureCache()
			}

			// Load tenant cache from disk into in-memory cache (if available)
			// This benefits individual commands across separate invocations
			tenantID := loadTenantCacheFromDisk(AzOutputDirectory)
			loadRoleDefinitionCacheFromDisk(AzOutputDirectory, tenantID)

			// Check for bearer tokens from flags or environment variables
			armToken, graphToken := resolveAzureTokens()

			if armToken != "" || graphToken != "" {
				// Validate and set tokens
				if err := validateAndSetTokens(armToken, graphToken); err != nil {
					logger.ErrorM(fmt.Sprintf("[ERROR] %v", err), globals.AZ_UTILS_MODULE_NAME)
					os.Exit(1)
				}

				// Display token information
				displayDualTokenInfo(armToken, graphToken)
				return // Skip CLI auth check when using tokens
			}

			// Validate Azure CLI session with detailed feedback
			validation := azinternal.ValidateSession()
			if !validation.Valid {
				if validation.WarningMessage != "" {
					logger.ErrorM("[ERROR] "+validation.WarningMessage, globals.AZ_UTILS_MODULE_NAME)
				} else {
					logger.ErrorM("[ERROR] You must authenticate to Azure first. Run: az login", globals.AZ_UTILS_MODULE_NAME)
				}
				logger.ErrorM("        Or provide tokens via --arm-token and/or --graph-token flags", globals.AZ_UTILS_MODULE_NAME)
				os.Exit(1)
			}

			// Warn if running in limited mode (ARM only, no Graph)
			if !validation.FullAccess && validation.WarningMessage != "" {
				logger.InfoM("[WARNING] Running in LIMITED ACCESS mode:", globals.AZ_UTILS_MODULE_NAME)
				for _, line := range strings.Split(validation.WarningMessage, "\n") {
					logger.InfoM("[WARNING] "+line, globals.AZ_UTILS_MODULE_NAME)
				}
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			// Save caches to disk after command completes.
			// This allows subsequent individual commands to reuse Entra + role data.
			// resolveTenantID() handles both -t and -s flag scenarios.
			tenantID := resolveTenantID()
			saveTenantCacheToDisk(AzOutputDirectory, tenantID)
			saveRoleDefinitionCacheToDisk(AzOutputDirectory, tenantID)
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
./cloudfox az kv --subscription SUBSCRIPTION_ID

Authentication options:
  1. Azure CLI: az login (default)
  2. ARM token via flag: --arm-token <token>
  3. Graph token via flag: --graph-token <token>
  4. Environment variables: AZURE_ARM_TOKEN, AZURE_GRAPH_TOKEN`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			globals.AZ_VERBOSITY = AzVerbosity
			globals.AZ_REFRESH_CACHE = AzRefreshCache

			// If --refresh-cache, clear the in-memory cache
			if globals.AZ_REFRESH_CACHE {
				azinternal.ClearAzureCache()
			}

			// Check for bearer tokens from flags or environment variables
			armToken, graphToken := resolveAzureTokens()

			if armToken != "" || graphToken != "" {
				// Validate and set tokens
				if err := validateAndSetTokens(armToken, graphToken); err != nil {
					logger.ErrorM(fmt.Sprintf("[ERROR] %v", err), globals.AZ_UTILS_MODULE_NAME)
					os.Exit(1)
				}

				// Display token information
				displayDualTokenInfo(armToken, graphToken)
				return
			}

			// Validate Azure CLI session with detailed feedback
			validation := azinternal.ValidateSession()
			if !validation.Valid {
				if validation.WarningMessage != "" {
					logger.ErrorM("[ERROR] "+validation.WarningMessage, globals.AZ_UTILS_MODULE_NAME)
				} else {
					logger.ErrorM("[ERROR] You must authenticate to Azure first. Run: az login", globals.AZ_UTILS_MODULE_NAME)
				}
				logger.ErrorM("        Or provide tokens via --arm-token and/or --graph-token flags", globals.AZ_UTILS_MODULE_NAME)
				os.Exit(1)
			}

			// Warn if running in limited mode (ARM only, no Graph)
			if !validation.FullAccess && validation.WarningMessage != "" {
				logger.InfoM("[WARNING] Running in LIMITED ACCESS mode:", globals.AZ_UTILS_MODULE_NAME)
				for _, line := range strings.Split(validation.WarningMessage, "\n") {
					logger.InfoM("[WARNING] "+line, globals.AZ_UTILS_MODULE_NAME)
				}
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			startTime := time.Now()

			// ========== CACHE: Load from disk if available ==========
			tenantID := loadTenantCacheFromDisk(AzOutputDirectory)
			loadRoleDefinitionCacheFromDisk(AzOutputDirectory, tenantID)

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
				commands.AzDevOpsAgentsCommand.Use:    true,
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

			// ========== CACHE: Save to disk after all commands ==========
			saveTenantCacheToDisk(AzOutputDirectory, tenantID)
			saveRoleDefinitionCacheToDisk(AzOutputDirectory, tenantID)

			// Print execution summary
			duration := time.Since(startTime)
			cacheItems := azinternal.GetAzureCacheStats()
			logger.InfoM(fmt.Sprintf("All checks completed in %s (cached %d API responses)", formatDur(duration), cacheItems), "all-checks")
		},
	}
)

// resolveAzureTokens checks for ARM and Graph tokens from flags or environment variables
// Returns (armToken, graphToken)
func resolveAzureTokens() (string, string) {
	var armToken, graphToken string

	// ARM Token: flag > env var
	if AzARMToken != "" {
		armToken = strings.TrimSpace(AzARMToken)
	} else if token := os.Getenv("AZURE_ARM_TOKEN"); token != "" {
		armToken = strings.TrimSpace(token)
	}

	// Graph Token: flag > env var
	if AzGraphToken != "" {
		graphToken = strings.TrimSpace(AzGraphToken)
	} else if token := os.Getenv("AZURE_GRAPH_TOKEN"); token != "" {
		graphToken = strings.TrimSpace(token)
	}

	return armToken, graphToken
}

// validateAndSetTokens validates that tokens are scoped correctly and sets them in globals
func validateAndSetTokens(armToken, graphToken string) error {
	// Validate ARM token if provided
	if armToken != "" {
		tokenInfo, err := azinternal.DecodeJWTToken(armToken)
		if err != nil {
			return fmt.Errorf("invalid ARM token: %v", err)
		}

		// Check if token is expired
		if tokenInfo.IsExpired() {
			return fmt.Errorf("ARM token has expired (expired at %s)", tokenInfo.GetExpirationTime().Format("2006-01-02 15:04:05"))
		}

		// Validate audience - must be ARM
		if !isARMToken(tokenInfo) {
			return fmt.Errorf("ARM token has wrong audience: %s\n"+
				"        Expected: https://management.azure.com/ or https://management.core.windows.net/\n"+
				"        Get correct token with: az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv",
				tokenInfo.Audience)
		}

		globals.AZ_ARM_TOKEN = armToken
	}

	// Validate Graph token if provided
	if graphToken != "" {
		tokenInfo, err := azinternal.DecodeJWTToken(graphToken)
		if err != nil {
			return fmt.Errorf("invalid Graph token: %v", err)
		}

		// Check if token is expired
		if tokenInfo.IsExpired() {
			return fmt.Errorf("Graph token has expired (expired at %s)", tokenInfo.GetExpirationTime().Format("2006-01-02 15:04:05"))
		}

		// Validate audience - must be Graph
		if !isGraphToken(tokenInfo) {
			return fmt.Errorf("Graph token has wrong audience: %s\n"+
				"        Expected: https://graph.microsoft.com/\n"+
				"        Get correct token with: az account get-access-token --resource https://graph.microsoft.com/ --query accessToken -o tsv",
				tokenInfo.Audience)
		}

		globals.AZ_GRAPH_TOKEN = graphToken
	}

	// Set legacy bearer token for backward compatibility (prefer ARM if available)
	if armToken != "" {
		globals.AZ_BEARER_TOKEN = armToken
	} else if graphToken != "" {
		globals.AZ_BEARER_TOKEN = graphToken
	}

	return nil
}

// isARMToken checks if the token audience is for Azure Resource Manager
func isARMToken(tokenInfo *azinternal.TokenInfo) bool {
	aud := strings.ToLower(tokenInfo.Audience)
	return strings.Contains(aud, "management.azure.com") ||
		strings.Contains(aud, "management.core.windows.net")
}

// isGraphToken checks if the token audience is for Microsoft Graph
func isGraphToken(tokenInfo *azinternal.TokenInfo) bool {
	aud := strings.ToLower(tokenInfo.Audience)
	return strings.Contains(aud, "graph.microsoft.com")
}

// displayDualTokenInfo displays information about ARM and/or Graph tokens
func displayDualTokenInfo(armToken, graphToken string) {
	logger.InfoM("Using token-based authentication", globals.AZ_UTILS_MODULE_NAME)
	logger.InfoM("╔════════════════════════════════════════════════════════════╗", globals.AZ_UTILS_MODULE_NAME)
	logger.InfoM("║                    TOKEN CONFIGURATION                     ║", globals.AZ_UTILS_MODULE_NAME)
	logger.InfoM("╠════════════════════════════════════════════════════════════╣", globals.AZ_UTILS_MODULE_NAME)

	// Display ARM token info
	if armToken != "" {
		armInfo, _ := azinternal.DecodeJWTToken(armToken)
		if armInfo != nil {
			logger.InfoM("║ ARM Token (Azure Resource Manager):                        ║", globals.AZ_UTILS_MODULE_NAME)
			logger.InfoM(fmt.Sprintf("║   Identity:     %-42s║", truncateStr(armInfo.GetIdentity(), 42)), globals.AZ_UTILS_MODULE_NAME)
			logger.InfoM(fmt.Sprintf("║   Expires:      %-42s║", armInfo.GetExpirationTime().Format("2006-01-02 15:04:05")+" ("+formatDur(armInfo.TimeUntilExpiry())+")"), globals.AZ_UTILS_MODULE_NAME)
			logger.InfoM(fmt.Sprintf("║   Tenant:       %-42s║", armInfo.TenantID), globals.AZ_UTILS_MODULE_NAME)
		}
	} else {
		logger.InfoM("║ ARM Token:      ✗ Not provided                              ║", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("║   (Resource enumeration modules will not work)              ║", globals.AZ_UTILS_MODULE_NAME)
	}

	logger.InfoM("╠════════════════════════════════════════════════════════════╣", globals.AZ_UTILS_MODULE_NAME)

	// Display Graph token info
	if graphToken != "" {
		graphInfo, _ := azinternal.DecodeJWTToken(graphToken)
		if graphInfo != nil {
			logger.InfoM("║ Graph Token (Microsoft Graph):                              ║", globals.AZ_UTILS_MODULE_NAME)
			logger.InfoM(fmt.Sprintf("║   Identity:     %-42s║", truncateStr(graphInfo.GetIdentity(), 42)), globals.AZ_UTILS_MODULE_NAME)
			logger.InfoM(fmt.Sprintf("║   Expires:      %-42s║", graphInfo.GetExpirationTime().Format("2006-01-02 15:04:05")+" ("+formatDur(graphInfo.TimeUntilExpiry())+")"), globals.AZ_UTILS_MODULE_NAME)
			if graphInfo.Scopes != "" {
				logger.InfoM(fmt.Sprintf("║   Scopes:       %-42s║", truncateStr(graphInfo.Scopes, 42)), globals.AZ_UTILS_MODULE_NAME)
			}
		}
	} else {
		logger.InfoM("║ Graph Token:    ✗ Not provided                              ║", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("║   (User/principal enumeration will show 'UNKNOWN')          ║", globals.AZ_UTILS_MODULE_NAME)
	}

	logger.InfoM("╚════════════════════════════════════════════════════════════╝", globals.AZ_UTILS_MODULE_NAME)

	// Print prominent warning when only one token is provided
	if armToken == "" && graphToken != "" {
		logger.InfoM("", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] ══════════════════════════════════════════════════════════", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] RESULTS WILL BE LIMITED - Only Graph token provided!", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] Resource enumeration modules (vms, storage, aks, keyvaults,", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] databases, etc.) will FAIL without an ARM token.", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING]", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] To get an ARM token, run:", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING]   az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] ══════════════════════════════════════════════════════════", globals.AZ_UTILS_MODULE_NAME)
	}
	if graphToken == "" && armToken != "" {
		logger.InfoM("", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] ══════════════════════════════════════════════════════════", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] RESULTS WILL BE LIMITED - Only ARM token provided!", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] User/principal identity resolution will show 'UNKNOWN' for", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] role assignments and other identity-related data.", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING]", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] To get a Graph token, run:", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING]   az account get-access-token --resource https://graph.microsoft.com/ --query accessToken -o tsv", globals.AZ_UTILS_MODULE_NAME)
		logger.InfoM("[WARNING] ══════════════════════════════════════════════════════════", globals.AZ_UTILS_MODULE_NAME)
	}
}

// truncateStr truncates a string to maxLen characters
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// formatDur formats a duration for display
func formatDur(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
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

	// Token-based authentication flags
	AzCommands.PersistentFlags().StringVar(&AzARMToken, "arm-token", "", "Azure ARM token for resource enumeration (https://management.azure.com/). Can also use AZURE_ARM_TOKEN env var.")
	AzCommands.PersistentFlags().StringVar(&AzGraphToken, "graph-token", "", "Microsoft Graph token for user/principal info (https://graph.microsoft.com/). Can also use AZURE_GRAPH_TOKEN env var.")

	// Cache flags
	AzCommands.PersistentFlags().BoolVar(&AzRefreshCache, "refresh-cache", false, "Force re-enumeration of cached data (cache auto-expires after 24 hours)")

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
		commands.AzDevOpsAgentsCommand,
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
		commands.AzIdentityProtectionCommand, // Disabled - compilation issues
		commands.AzInventoryCommand,
		commands.AzIoTHubCommand,
		commands.AzKeyVaultCommand,
		commands.AzKustoCommand,
		commands.AzLighthouseCommand,
		commands.AzLateralMovementCommand,
		commands.AzLoadBalancersCommand,
		commands.AzLoadTestingCommand,
		commands.AzLogicAppsCommand,
		commands.AzMachineLearningCommand,
		commands.AzMonitorCommand,
		commands.AzNetworkInterfacesCommand,
		commands.AzNetworkExposureCommand,
		commands.AzNetworkTopologyCommand,
		commands.AzNSGCommand,
		commands.AzPolicyCommand,
		commands.AzPrincipalsCommand,
		commands.AzPrivilegeEscalationCommand,
		commands.AzPermissionsCommand,
		commands.AzPrivateLinkCommand,
		commands.AzRBACCommand,
		commands.AzRedisCommand,
		commands.AzResourceGraphCommand,
		commands.AzRoutesCommand,
		commands.AzSecurityCenterCommand,
		commands.AzSentinelCommand,
		commands.AzServiceFabricCommand,
		commands.AzSignalRCommand,
		commands.AzStorageCommand,
		commands.AzSpringAppsCommand,
		commands.AzStreamAnalyticsCommand,
		commands.AzSynapseCommand,
		commands.AzTrafficManagerCommand,
		commands.AzVmsCommand,
		commands.AzVNetsCommand,
		commands.AzVPNGatewayCommand,
		commands.AzWebAppsCommand,
		commands.AzWhoamiCommand,

		AzAllChecksCommand,
	)
}

// resolveTenantID returns the tenant ID from the -t flag, or resolves it from the -s flag
// using the Azure CLI. Returns empty string if neither flag is set or resolution fails.
func resolveTenantID() string {
	if AzTenantID != "" {
		return AzTenantID
	}
	if AzSubscription == "" {
		return ""
	}

	// Resolve tenant from subscription via Azure CLI (lightweight, no SafeSession needed)
	out, err := exec.Command("az", "account", "show",
		"--subscription", AzSubscription,
		"--query", "tenantId",
		"-o", "tsv").Output()
	if err != nil {
		return ""
	}
	tenantID := strings.TrimSpace(string(out))
	if tenantID != "" && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Resolved tenant %s from subscription %s for cache lookup", tenantID, AzSubscription), "cache")
	}
	return tenantID
}

// loadTenantCacheFromDisk attempts to load tenant cache from disk into the in-memory cache.
// Returns the tenant ID used (from -t flag, resolved from -s flag, or empty).
func loadTenantCacheFromDisk(outputDir string) string {
	tenantID := resolveTenantID()
	if tenantID == "" {
		return ""
	}

	// If --refresh-cache, delete existing disk cache
	if globals.AZ_REFRESH_CACHE {
		if azinternal.TenantCacheExists(outputDir, tenantID) {
			logger.InfoM("Deleting existing tenant cache (--refresh-cache)", "cache")
			azinternal.DeleteTenantCache(outputDir, tenantID)
		}
		return tenantID
	}

	// Check if disk cache exists
	if !azinternal.TenantCacheExists(outputDir, tenantID) {
		return tenantID
	}

	// Check staleness
	if azinternal.IsTenantCacheStale(outputDir, tenantID, azinternal.DefaultAzureCacheExpiration) {
		age, _ := azinternal.GetTenantCacheAge(outputDir, tenantID)
		logger.InfoM(fmt.Sprintf("Tenant cache expired (age: %s), will re-enumerate", formatDur(age)), "cache")
		azinternal.DeleteTenantCache(outputDir, tenantID)
		return tenantID
	}

	// Load from disk
	users, sps, groups, metadata, err := azinternal.LoadTenantCacheFromFile(outputDir, tenantID)
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not load tenant cache: %v, will re-enumerate", err), "cache")
		azinternal.DeleteTenantCache(outputDir, tenantID)
		return tenantID
	}
	if metadata == nil {
		return tenantID
	}

	// Populate in-memory cache from disk cache
	if len(users) > 0 {
		azinternal.AzureDataCache.Set(azinternal.AzCacheKey("entra-users", tenantID), users, 0)
	}
	if len(sps) > 0 {
		azinternal.AzureDataCache.Set(azinternal.AzCacheKey("service-principals", tenantID), sps, 0)
	}
	if len(groups) > 0 {
		azinternal.AzureDataCache.Set(azinternal.AzCacheKey("entra-groups", tenantID), groups, 0)
	}

	age, _ := azinternal.GetTenantCacheAge(outputDir, tenantID)
	logger.InfoM(fmt.Sprintf("Loaded tenant cache from disk (age: %s, %d users, %d SPs, %d groups)",
		formatDur(age), metadata.TotalUsers, metadata.TotalSPs, metadata.TotalGroups), "cache")

	// Staleness warning for caches between 12-24h
	if age > 12*time.Hour {
		logger.InfoM(fmt.Sprintf("Tenant cache is %s old. Use --refresh-cache to force refresh.", formatDur(age)), "cache")
	}

	return tenantID
}

// saveTenantCacheToDisk saves the current in-memory tenant data to disk for future runs.
func saveTenantCacheToDisk(outputDir, tenantID string) {
	if tenantID == "" {
		return
	}

	// Read slices directly from in-memory cache
	var users, sps, groups []azinternal.PrincipalInfo

	if cached, found := azinternal.AzureDataCache.Get(azinternal.AzCacheKey("entra-users", tenantID)); found {
		users = cached.([]azinternal.PrincipalInfo)
	}
	if cached, found := azinternal.AzureDataCache.Get(azinternal.AzCacheKey("service-principals", tenantID)); found {
		sps = cached.([]azinternal.PrincipalInfo)
	}
	if cached, found := azinternal.AzureDataCache.Get(azinternal.AzCacheKey("entra-groups", tenantID)); found {
		groups = cached.([]azinternal.PrincipalInfo)
	}

	if len(users) == 0 && len(sps) == 0 && len(groups) == 0 {
		return // Nothing to save
	}

	err := azinternal.SaveTenantCacheToFile(users, sps, groups, outputDir, tenantID, "", "1.0.0")
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not save tenant cache to disk: %v", err), "cache")
	} else {
		cacheDir := azinternal.GetAzureCacheDirectory(outputDir, tenantID)
		logger.InfoM(fmt.Sprintf("Tenant cache saved to %s (%d users, %d SPs, %d groups)",
			cacheDir, len(users), len(sps), len(groups)), "cache")
	}
}

// loadRoleDefinitionCacheFromDisk attempts to load role definition cache from disk into
// the in-memory cache. Role definitions are tenant-scoped and rarely change (7-day TTL).
func loadRoleDefinitionCacheFromDisk(outputDir, tenantID string) {
	if tenantID == "" {
		return
	}

	// If --refresh-cache, delete existing disk cache
	if globals.AZ_REFRESH_CACHE {
		if azinternal.RoleDefinitionCacheExists(outputDir, tenantID) {
			logger.InfoM("Deleting existing role definition cache (--refresh-cache)", "cache")
			azinternal.DeleteRoleDefinitionCache(outputDir, tenantID)
		}
		return
	}

	// Check if disk cache exists
	if !azinternal.RoleDefinitionCacheExists(outputDir, tenantID) {
		return
	}

	// Check staleness (7 days for role definitions)
	if azinternal.IsRoleDefinitionCacheStale(outputDir, tenantID, azinternal.RoleDefinitionCacheExpiration) {
		age, _ := azinternal.GetRoleDefinitionCacheAge(outputDir, tenantID)
		logger.InfoM(fmt.Sprintf("Role definition cache expired (age: %s), will re-enumerate", formatDur(age)), "cache")
		azinternal.DeleteRoleDefinitionCache(outputDir, tenantID)
		return
	}

	// Load from disk
	defs, metadata, err := azinternal.LoadRoleDefinitionCache(outputDir, tenantID)
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not load role definition cache: %v, will re-enumerate", err), "cache")
		azinternal.DeleteRoleDefinitionCache(outputDir, tenantID)
		return
	}
	if metadata == nil {
		return
	}

	// Populate in-memory cache from disk cache
	for roleDefID, roleName := range defs {
		azinternal.AzureDataCache.Set(azinternal.AzCacheKey("role-name", roleDefID), roleName, 0)
	}

	age, _ := azinternal.GetRoleDefinitionCacheAge(outputDir, tenantID)
	logger.InfoM(fmt.Sprintf("Loaded role definition cache from disk (age: %s, %d definitions)",
		formatDur(age), metadata.TotalDefs), "cache")
}

// saveRoleDefinitionCacheToDisk scans the in-memory cache for role definitions and
// persists them to disk for future runs.
func saveRoleDefinitionCacheToDisk(outputDir, tenantID string) {
	if tenantID == "" {
		return
	}

	// Scan in-memory cache for all role-name entries
	const prefix = "az-role-name-"
	defs := make(map[string]string)
	for key, item := range azinternal.AzureDataCache.Items() {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			roleDefID := key[len(prefix):]
			if roleName, ok := item.Object.(string); ok {
				defs[roleDefID] = roleName
			}
		}
	}

	if len(defs) == 0 {
		return // Nothing to save
	}

	err := azinternal.SaveRoleDefinitionCache(defs, outputDir, tenantID)
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not save role definition cache to disk: %v", err), "cache")
	} else {
		cacheDir := azinternal.GetAzureCacheDirectory(outputDir, tenantID)
		logger.InfoM(fmt.Sprintf("Role definition cache saved to %s (%d definitions)",
			cacheDir, len(defs)), "cache")
	}
}
