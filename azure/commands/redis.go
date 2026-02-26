package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzRedisCommand = &cobra.Command{
	Use:     "redis",
	Aliases: []string{"cache", "redis-cache"},
	Short:   "Enumerate Azure Cache for Redis instances",
	Long: `
Enumerate Azure Cache for Redis for a specific tenant:
  ./cloudfox az redis --tenant TENANT_ID

Enumerate Redis for a specific subscription:
  ./cloudfox az redis --subscription SUBSCRIPTION_ID`,
	Run: ListRedis,
}

// ------------------------------
// Module struct
// ------------------------------
type RedisModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions []string
	RedisRows     [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

type RedisInfo struct {
	SubscriptionID      string
	SubscriptionName    string
	ResourceGroup       string
	Region              string
	RedisName           string
	Endpoint            string
	SSLPort             string
	NonSSLPort          string
	SKU                 string
	PublicPrivate       string
	SSLEnabled          string
	PrimaryKey          string
	SecondaryKey        string
	SystemAssignedID    string
	UserAssignedIDs     string
	SystemAssignedRoles string
	UserAssignedRoles   string
}

// ------------------------------
// Output struct
// ------------------------------
type RedisOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o RedisOutput) TableFiles() []internal.TableFile { return o.Table }
func (o RedisOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListRedis(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_REDIS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &RedisModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		RedisRows:       [][]string{},
		LootMap: map[string]*internal.LootFile{
			"redis-commands":           {Name: "redis-commands", Contents: ""},
			"redis-connection-strings": {Name: "redis-connection-strings", Contents: ""},
		},
	}

	module.PrintRedis(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *RedisModule) PrintRedis(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_REDIS_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_REDIS_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *RedisModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_REDIS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	redisClient, err := armredis.NewClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Redis client: %v", err), globals.AZ_REDIS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	resourceGroups := m.ResolveResourceGroups(subID)

	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, redisClient, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *RedisModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, redisClient *armredis.Client, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	pager := redisClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list Redis in RG %s: %v", rgName, err), globals.AZ_REDIS_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, cache := range page.Value {
			m.processRedisCache(ctx, cache, subID, subName, rgName, region, redisClient, logger)
		}
	}
}

// ------------------------------
// Process single Redis cache
// ------------------------------
func (m *RedisModule) processRedisCache(ctx context.Context, cache *armredis.ResourceInfo, subID, subName, rgName, region string, redisClient *armredis.Client, logger internal.Logger) {
	cacheName := azinternal.SafeStringPtr(cache.Name)
	endpoint := "N/A"
	sslPort := "6380"
	nonSSLPort := "6379"
	sku := "N/A"
	publicPrivate := "Unknown"
	sslEnabled := "No"
	primaryKey := "N/A"
	secondaryKey := "N/A"
	minTLSVersion := "N/A"
	redisVersion := "N/A"
	firewallRules := "No rules (Allow all)"
	zoneRedundant := "No"

	if cache.Properties != nil {
		if cache.Properties.HostName != nil {
			endpoint = *cache.Properties.HostName
		}
		if cache.Properties.SSLPort != nil {
			sslPort = fmt.Sprintf("%d", *cache.Properties.SSLPort)
		}
		if cache.Properties.Port != nil {
			nonSSLPort = fmt.Sprintf("%d", *cache.Properties.Port)
		}
		if cache.Properties.EnableNonSSLPort != nil && !*cache.Properties.EnableNonSSLPort {
			sslEnabled = "Yes (non-SSL disabled)"
		} else if cache.Properties.EnableNonSSLPort != nil && *cache.Properties.EnableNonSSLPort {
			sslEnabled = "No (non-SSL enabled)"
		}

		// Determine public/private
		if cache.Properties.PublicNetworkAccess != nil {
			if *cache.Properties.PublicNetworkAccess == armredis.PublicNetworkAccessEnabled {
				publicPrivate = "Public"
			} else {
				publicPrivate = "Private"
			}
		}

		// NEW: Get Minimum TLS Version
		if cache.Properties.MinimumTLSVersion != nil {
			minTLSVersion = string(*cache.Properties.MinimumTLSVersion)
		}

		// NEW: Get Redis Version
		if cache.Properties.RedisVersion != nil {
			redisVersion = *cache.Properties.RedisVersion
		}

		// NEW: Check Firewall Rules
		if cache.Properties.PublicNetworkAccess != nil && *cache.Properties.PublicNetworkAccess == armredis.PublicNetworkAccessEnabled {
			// Get firewall rules count (use REST API or client)
			// Note: FirewallRulesClient requires separate initialization
			token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
			if err == nil {
				cred := &azinternal.StaticTokenCredential{Token: token}
				firewallClient, err := armredis.NewFirewallRulesClient(subID, cred, nil)
				if err == nil {
					// Get firewall rules from the cache
					firewallPager := firewallClient.NewListPager(rgName, cacheName, nil)
					ruleCount := 0
					var ruleNames []string
					for firewallPager.More() {
						page, err := firewallPager.NextPage(ctx)
						if err != nil {
							break
						}
						for _, rule := range page.Value {
							ruleCount++
							if rule.Name != nil {
								ruleNames = append(ruleNames, *rule.Name)
							}
						}
					}
					if ruleCount > 0 {
						firewallRules = fmt.Sprintf("%d rules configured", ruleCount)
						if ruleCount <= 3 && len(ruleNames) > 0 {
							firewallRules = strings.Join(ruleNames, ", ")
						}
					}
				}
			}
		} else if cache.Properties.PublicNetworkAccess != nil && *cache.Properties.PublicNetworkAccess == armredis.PublicNetworkAccessDisabled {
			firewallRules = "N/A (Private access only)"
		}
	}

	// NEW: Check Zone Redundancy
	if cache.Zones != nil && len(cache.Zones) > 0 {
		zoneRedundant = fmt.Sprintf("Yes (%d zones)", len(cache.Zones))
	}

	// Extract SKU
	if cache.Properties != nil && cache.Properties.SKU != nil {
		skuParts := []string{}
		if cache.Properties.SKU.Name != nil {
			skuParts = append(skuParts, string(*cache.Properties.SKU.Name))
		}
		if cache.Properties.SKU.Family != nil {
			skuParts = append(skuParts, string(*cache.Properties.SKU.Family))
		}
		if cache.Properties.SKU.Capacity != nil {
			skuParts = append(skuParts, fmt.Sprintf("C%d", *cache.Properties.SKU.Capacity))
		}
		if len(skuParts) > 0 {
			sku = strings.Join(skuParts, " ")
		}
	}

	// Get access keys
	keysResp, err := redisClient.ListKeys(ctx, rgName, cacheName, nil)
	if err == nil && keysResp.AccessKeys.PrimaryKey != nil {
		primaryKey = *keysResp.AccessKeys.PrimaryKey
		if keysResp.AccessKeys.SecondaryKey != nil {
			secondaryKey = *keysResp.AccessKeys.SecondaryKey
		}
	}

	// Extract managed identity information
	var systemAssignedIDs []string
	var userAssignedIDs []string

	if cache.Identity != nil {
		if cache.Identity.PrincipalID != nil {
			principalID := *cache.Identity.PrincipalID
			systemAssignedIDs = append(systemAssignedIDs, principalID)
		}

		if cache.Identity.UserAssignedIdentities != nil {
			for uaID := range cache.Identity.UserAssignedIdentities {
				userAssignedIDs = append(userAssignedIDs, uaID)
			}
		}
	}

	// Format identity fields
	sysID := "N/A"
	if len(systemAssignedIDs) > 0 {
		sysID = strings.Join(systemAssignedIDs, "\n")
	}
	userIDs := "N/A"
	if len(userAssignedIDs) > 0 {
		userIDs = strings.Join(userAssignedIDs, "\n")
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		cacheName,
		endpoint,
		sslPort,
		nonSSLPort,
		sku,
		publicPrivate,
		sslEnabled,
		minTLSVersion, // NEW: Minimum TLS Version
		firewallRules, // NEW: Firewall Rules
		redisVersion,  // NEW: Redis Version
		zoneRedundant, // NEW: Zone Redundancy
		"See redis-connection-strings loot file",
		sysID,
		userIDs,
	}

	m.mu.Lock()
	m.RedisRows = append(m.RedisRows, row)
	m.mu.Unlock()

	m.CommandCounter.Total++

	// Generate loot
	m.generateRedisCommands(subID, rgName, cacheName, endpoint, sslPort, primaryKey)
	m.generateRedisConnectionStrings(cacheName, endpoint, sslPort, primaryKey, secondaryKey)
}

// ------------------------------
// Generate Redis commands loot
// ------------------------------
func (m *RedisModule) generateRedisCommands(subID, rgName, cacheName, endpoint, sslPort, primaryKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["redis-commands"].Contents += fmt.Sprintf(
		"## Redis Cache: %s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Get Redis cache details\n"+
			"az redis show \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# Get access keys\n"+
			"az redis list-keys \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s\n"+
			"\n"+
			"# Connect using redis-cli (if installed)\n"+
			"redis-cli -h %s -p %s -a \"%s\" --tls\n"+
			"\n"+
			"# Export Redis cache data (requires redis-cli)\n"+
			"redis-cli -h %s -p %s -a \"%s\" --tls --rdb /tmp/%s-dump.rdb\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"\n"+
			"# Get Redis cache\n"+
			"Get-AzRedisCache -ResourceGroupName %s -Name %s\n"+
			"\n"+
			"# Get access keys\n"+
			"Get-AzRedisCacheKey -ResourceGroupName %s -Name %s\n\n",
		cacheName, rgName,
		subID,
		rgName, cacheName,
		rgName, cacheName,
		endpoint, sslPort, primaryKey,
		endpoint, sslPort, primaryKey, cacheName,
		subID,
		rgName, cacheName,
		rgName, cacheName,
	)
}

// ------------------------------
// Generate Redis connection strings loot
// ------------------------------
func (m *RedisModule) generateRedisConnectionStrings(cacheName, endpoint, sslPort, primaryKey, secondaryKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["redis-connection-strings"].Contents += fmt.Sprintf(
		"## Redis Cache: %s\n"+
			"Endpoint: %s\n"+
			"SSL Port: %s\n"+
			"\n"+
			"# Primary Connection String\n"+
			"%s:%s,password=%s,ssl=True,abortConnect=False\n"+
			"\n"+
			"# Secondary Connection String\n"+
			"%s:%s,password=%s,ssl=True,abortConnect=False\n"+
			"\n"+
			"# Primary Key (raw)\n"+
			"%s\n"+
			"\n"+
			"# Secondary Key (raw)\n"+
			"%s\n"+
			"\n"+
			"# redis-cli command (primary key)\n"+
			"redis-cli -h %s -p %s -a \"%s\" --tls\n"+
			"\n",
		cacheName,
		endpoint,
		sslPort,
		endpoint, sslPort, primaryKey,
		endpoint, sslPort, secondaryKey,
		primaryKey,
		secondaryKey,
		endpoint, sslPort, primaryKey,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *RedisModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.RedisRows) == 0 {
		logger.InfoM("No Redis caches found", globals.AZ_REDIS_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Redis Name",
		"Endpoint",
		"SSL Port",
		"Non-SSL Port",
		"SKU",
		"Public/Private",
		"SSL Enabled",
		"Minimum TLS Version", // NEW: Security - TLS version enforcement
		"Firewall Rules",      // NEW: Security - IP allowlist
		"Redis Version",       // NEW: Version tracking for vulnerabilities
		"Zone Redundant",      // NEW: High availability configuration
		"Access Keys",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.RedisRows, headers,
			"redis", globals.AZ_REDIS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.RedisRows, headers,
			"redis", globals.AZ_REDIS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := RedisOutput{
		Table: []internal.TableFile{{
			Name:   "redis",
			Header: headers,
			Body:   m.RedisRows,
		}},
		Loot: loot,
	}

	// Determine output scope (single subscription vs tenant-wide consolidation)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart (automatic streaming for large datasets)
	if err := internal.HandleOutputSmart(
		"Azure",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIDs,
		scopeNames,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_REDIS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Redis caches across %d subscription(s)", len(m.RedisRows), len(m.Subscriptions)), globals.AZ_REDIS_MODULE_NAME)
}
