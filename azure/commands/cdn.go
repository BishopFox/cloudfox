package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzCDNCommand = &cobra.Command{
	Use:     "cdn",
	Aliases: []string{},
	Short:   "Enumerate Azure CDN profiles with security analysis",
	Long: `
Enumerate Azure CDN (Content Delivery Network) for a specific tenant:
./cloudfox az cdn --tenant TENANT_ID

Enumerate Azure CDN for a specific subscription:
./cloudfox az cdn --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

SECURITY FEATURES ANALYZED:
- CDN profile SKUs and pricing tiers
- Endpoint HTTPS enforcement and custom HTTPS configuration
- Custom domain certificates and minimum TLS version
- Origin server HTTPS enforcement and health probes
- Caching behavior and query string handling
- Compression settings and content optimization
- Geo-filtering and access restrictions`,
	Run: ListCDN,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type CDNModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields - 3 separate tables for comprehensive analysis
	Subscriptions []string
	ProfileRows   [][]string // CDN profiles overview
	EndpointRows  [][]string // CDN endpoints (public-facing)
	OriginRows    [][]string // Origin servers
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type CDNOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CDNOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CDNOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListCDN(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_CDN_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &CDNModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		ProfileRows:     [][]string{},
		EndpointRows:    [][]string{},
		OriginRows:      [][]string{},
		LootMap: map[string]*internal.LootFile{
			"no-https-enforcement": {Name: "no-https-enforcement", Contents: "# CDN endpoints without HTTPS enforcement\n\n"},
			"insecure-origins":     {Name: "insecure-origins", Contents: "# CDN origins allowing HTTP (not HTTPS-only)\n\n"},
			"no-custom-https":      {Name: "no-custom-https", Contents: "# Custom domains without HTTPS configured\n\n"},
			"disabled-endpoints":   {Name: "disabled-endpoints", Contents: "# Disabled CDN endpoints\n\n"},
			"cdn-commands":         {Name: "cdn-commands", Contents: "# Azure CDN enumeration and testing commands\n\n"},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintCDN(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *CDNModule) PrintCDN(ctx context.Context, logger internal.Logger) {
	// Multi-tenant support: iterate over tenants if enabled
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			// Save current tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Switch to current tenant
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			// Process this tenant's subscriptions
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_CDN_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_CDN_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *CDNModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *CDNModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get token and create CDN profile client
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	profileClient, err := armcdn.NewProfilesClient(subID, cred, nil)
	if err != nil {
		return
	}

	// Enumerate CDN profiles in this resource group
	pager := profileClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, profile := range page.Value {
			if profile == nil || profile.Name == nil {
				continue
			}

			m.processCDNProfile(ctx, subID, subName, rgName, profile, cred)
		}
	}
}

// ------------------------------
// Process single CDN profile
// ------------------------------
func (m *CDNModule) processCDNProfile(ctx context.Context, subID, subName, rgName string, profile *armcdn.Profile, cred *azinternal.StaticTokenCredential) {
	profileName := azinternal.SafeStringPtr(profile.Name)
	region := azinternal.SafeStringPtr(profile.Location)

	// Extract SKU information
	sku := "N/A"
	skuName := "N/A"
	if profile.SKU != nil {
		if profile.SKU.Name != nil {
			skuName = string(*profile.SKU.Name)
			sku = skuName
		}
	}

	// Extract provisioning state
	provisioningState := "N/A"
	resourceState := "N/A"
	if profile.Properties != nil {
		if profile.Properties.ProvisioningState != nil {
			provisioningState = string(*profile.Properties.ProvisioningState)
		}
		if profile.Properties.ResourceState != nil {
			resourceState = string(*profile.Properties.ResourceState)
		}
	}

	// Get endpoint client for this profile
	endpointClient, err := armcdn.NewEndpointsClient(subID, cred, nil)
	if err != nil {
		return
	}

	// Count endpoints
	endpointCount := 0
	customDomainCount := 0
	originCount := 0

	endpointPager := endpointClient.NewListByProfilePager(rgName, profileName, nil)
	for endpointPager.More() {
		endpointPage, err := endpointPager.NextPage(ctx)
		if err != nil {
			break
		}
		endpointCount += len(endpointPage.Value)

		for _, endpoint := range endpointPage.Value {
			if endpoint.Properties != nil {
				if endpoint.Properties.CustomDomains != nil {
					customDomainCount += len(endpoint.Properties.CustomDomains)
				}
				if endpoint.Properties.Origins != nil {
					originCount += len(endpoint.Properties.Origins)
				}
			}
		}
	}

	// Determine risk level
	risk := "INFO"
	riskReasons := []string{}

	if resourceState == "Disabled" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "Profile disabled")
	}
	if provisioningState != "Succeeded" && provisioningState != "N/A" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, fmt.Sprintf("Provisioning state: %s", provisioningState))
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "Active profile"
	}

	// Thread-safe append to profile rows
	m.mu.Lock()
	m.ProfileRows = append(m.ProfileRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		profileName,
		sku,
		skuName,
		provisioningState,
		resourceState,
		fmt.Sprintf("%d", endpointCount),
		fmt.Sprintf("%d", customDomainCount),
		fmt.Sprintf("%d", originCount),
		risk,
		riskNote,
	})
	m.mu.Unlock()

	// Process endpoints
	endpointPager = endpointClient.NewListByProfilePager(rgName, profileName, nil)
	for endpointPager.More() {
		endpointPage, err := endpointPager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, endpoint := range endpointPage.Value {
			m.processCDNEndpoint(ctx, subID, subName, rgName, profileName, endpoint)
		}
	}

	// Add enumeration commands to loot
	m.mu.Lock()
	m.LootMap["cdn-commands"].Contents += fmt.Sprintf("# CDN Profile: %s\n", profileName)
	m.LootMap["cdn-commands"].Contents += fmt.Sprintf("az cdn profile show --name %s --resource-group %s\n", profileName, rgName)
	m.LootMap["cdn-commands"].Contents += fmt.Sprintf("az cdn endpoint list --profile-name %s --resource-group %s\n", profileName, rgName)
	m.LootMap["cdn-commands"].Contents += fmt.Sprintf("az cdn custom-domain list --endpoint-name ENDPOINT_NAME --profile-name %s --resource-group %s\n", profileName, rgName)
	m.LootMap["cdn-commands"].Contents += "\n"
	m.mu.Unlock()
}

// ------------------------------
// Process CDN endpoint
// ------------------------------
func (m *CDNModule) processCDNEndpoint(ctx context.Context, subID, subName, rgName, profileName string, endpoint *armcdn.Endpoint) {
	if endpoint == nil || endpoint.Properties == nil {
		return
	}

	endpointName := azinternal.SafeStringPtr(endpoint.Name)
	hostname := azinternal.SafeStringPtr(endpoint.Properties.HostName)

	// Extract endpoint state
	resourceState := "N/A"
	provisioningState := "N/A"
	if endpoint.Properties.ResourceState != nil {
		resourceState = string(*endpoint.Properties.ResourceState)
	}
	if endpoint.Properties.ProvisioningState != nil {
		provisioningState = string(*endpoint.Properties.ProvisioningState)
	}

	// Extract HTTPS settings
	httpsOnly := "Disabled"
	if endpoint.Properties.IsHTTPAllowed != nil && !*endpoint.Properties.IsHTTPAllowed {
		httpsOnly = "Enabled"
	}

	httpAllowed := "Yes"
	if endpoint.Properties.IsHTTPAllowed != nil && !*endpoint.Properties.IsHTTPAllowed {
		httpAllowed = "No"
	}

	// Extract compression settings
	compressionEnabled := "Disabled"
	if endpoint.Properties.IsCompressionEnabled != nil && *endpoint.Properties.IsCompressionEnabled {
		compressionEnabled = "Enabled"
	}

	// Extract query string caching behavior
	queryStringCaching := "N/A"
	if endpoint.Properties.QueryStringCachingBehavior != nil {
		queryStringCaching = string(*endpoint.Properties.QueryStringCachingBehavior)
	}

	// Extract optimization type
	optimizationType := "N/A"
	if endpoint.Properties.OptimizationType != nil {
		optimizationType = string(*endpoint.Properties.OptimizationType)
	}

	// Count custom domains
	customDomainCount := 0
	customDomains := []string{}
	if endpoint.Properties.CustomDomains != nil {
		customDomainCount = len(endpoint.Properties.CustomDomains)
		for _, domain := range endpoint.Properties.CustomDomains {
			if domain.Name != nil {
				customDomains = append(customDomains, *domain.Name)
			}
		}
	}

	customDomainsStr := "None"
	if len(customDomains) > 0 {
		if len(customDomains) <= 3 {
			customDomainsStr = strings.Join(customDomains, ", ")
		} else {
			customDomainsStr = fmt.Sprintf("%s... (%d total)", strings.Join(customDomains[:3], ", "), len(customDomains))
		}
	}

	// Count origins
	originCount := 0
	if endpoint.Properties.Origins != nil {
		originCount = len(endpoint.Properties.Origins)
	}

	// Extract geo-filtering
	geoFilters := "None"
	if endpoint.Properties.GeoFilters != nil && len(endpoint.Properties.GeoFilters) > 0 {
		geoFilters = fmt.Sprintf("%d filter(s)", len(endpoint.Properties.GeoFilters))
	}

	// Determine risk level
	risk := "INFO"
	riskReasons := []string{}

	if resourceState == "Disabled" || resourceState == "Stopped" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, fmt.Sprintf("Endpoint %s", resourceState))
	}
	if httpAllowed == "Yes" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "HTTP allowed (not HTTPS-only)")
	}
	if customDomainCount > 0 {
		// Check custom domain HTTPS in origin processing
		riskReasons = append(riskReasons, "Custom domains require HTTPS verification")
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "Secure configuration"
	}

	// Thread-safe append
	m.mu.Lock()
	m.EndpointRows = append(m.EndpointRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		profileName,
		endpointName,
		hostname,
		"Public", // CDN endpoints are always public-facing
		resourceState,
		provisioningState,
		httpsOnly,
		httpAllowed,
		compressionEnabled,
		queryStringCaching,
		optimizationType,
		customDomainsStr,
		fmt.Sprintf("%d", originCount),
		geoFilters,
		risk,
		riskNote,
	})

	// Add to loot files
	if resourceState == "Disabled" || resourceState == "Stopped" {
		m.LootMap["disabled-endpoints"].Contents += fmt.Sprintf("Endpoint: %s (Profile: %s, RG: %s)\n", endpointName, profileName, rgName)
		m.LootMap["disabled-endpoints"].Contents += fmt.Sprintf("  State: %s\n", resourceState)
		m.LootMap["disabled-endpoints"].Contents += fmt.Sprintf("  Hostname: %s\n", hostname)
		m.LootMap["disabled-endpoints"].Contents += fmt.Sprintf("  Command: az cdn endpoint start --name %s --profile-name %s --resource-group %s\n\n", endpointName, profileName, rgName)
	}
	if httpAllowed == "Yes" {
		m.LootMap["no-https-enforcement"].Contents += fmt.Sprintf("Endpoint: %s (Profile: %s, RG: %s)\n", endpointName, profileName, rgName)
		m.LootMap["no-https-enforcement"].Contents += fmt.Sprintf("  Risk: HTTP allowed - traffic not encrypted\n")
		m.LootMap["no-https-enforcement"].Contents += fmt.Sprintf("  Hostname: https://%s\n", hostname)
		m.LootMap["no-https-enforcement"].Contents += fmt.Sprintf("  Command: az cdn endpoint update --name %s --profile-name %s --resource-group %s --no-http\n\n", endpointName, profileName, rgName)
	}
	m.mu.Unlock()

	// Process origins
	if endpoint.Properties.Origins != nil {
		for _, origin := range endpoint.Properties.Origins {
			m.processCDNOrigin(subID, subName, rgName, profileName, endpointName, origin)
		}
	}
}

// ------------------------------
// Process CDN origin
// ------------------------------
func (m *CDNModule) processCDNOrigin(subID, subName, rgName, profileName, endpointName string, origin *armcdn.DeepCreatedOrigin) {
	if origin == nil {
		return
	}

	originName := azinternal.SafeStringPtr(origin.Name)
	originHostname := "N/A"
	httpPort := "N/A"
	httpsPort := "N/A"
	priority := "N/A"
	weight := "N/A"
	enabled := "N/A"
	privateLink := "No"

	if origin.Properties != nil {
		if origin.Properties.HostName != nil {
			originHostname = *origin.Properties.HostName
		}
		if origin.Properties.HTTPPort != nil {
			httpPort = fmt.Sprintf("%d", *origin.Properties.HTTPPort)
		}
		if origin.Properties.HTTPSPort != nil {
			httpsPort = fmt.Sprintf("%d", *origin.Properties.HTTPSPort)
		}
		if origin.Properties.Priority != nil {
			priority = fmt.Sprintf("%d", *origin.Properties.Priority)
		}
		if origin.Properties.Weight != nil {
			weight = fmt.Sprintf("%d", *origin.Properties.Weight)
		}
		if origin.Properties.Enabled != nil {
			if *origin.Properties.Enabled {
				enabled = "Yes"
			} else {
				enabled = "No"
			}
		}
		if origin.Properties.PrivateLinkAlias != nil || origin.Properties.PrivateLinkResourceID != nil {
			privateLink = "Yes"
		}
	}

	// Determine protocol support
	protocol := "N/A"
	if httpPort != "N/A" && httpsPort != "N/A" {
		protocol = "HTTP & HTTPS"
	} else if httpPort != "N/A" {
		protocol = "HTTP only"
	} else if httpsPort != "N/A" {
		protocol = "HTTPS only"
	}

	// Determine risk level
	risk := "INFO"
	riskReasons := []string{}

	if protocol == "HTTP only" || protocol == "HTTP & HTTPS" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "HTTP allowed to origin")
	}
	if enabled == "No" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "Origin disabled")
	}
	if privateLink == "Yes" {
		// Private Link is a security improvement
		riskReasons = append(riskReasons, "Private Link enabled (good)")
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "Secure configuration"
	}

	// Thread-safe append
	m.mu.Lock()
	m.OriginRows = append(m.OriginRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		profileName,
		endpointName,
		originName,
		originHostname,
		protocol,
		httpPort,
		httpsPort,
		priority,
		weight,
		enabled,
		privateLink,
		risk,
		riskNote,
	})

	// Add to loot files
	if protocol == "HTTP only" || protocol == "HTTP & HTTPS" {
		m.LootMap["insecure-origins"].Contents += fmt.Sprintf("Origin: %s (Endpoint: %s, Profile: %s, RG: %s)\n", originName, endpointName, profileName, rgName)
		m.LootMap["insecure-origins"].Contents += fmt.Sprintf("  Risk: HTTP allowed to origin - backend traffic not encrypted\n")
		m.LootMap["insecure-origins"].Contents += fmt.Sprintf("  Hostname: %s\n", originHostname)
		m.LootMap["insecure-origins"].Contents += fmt.Sprintf("  Recommendation: Configure HTTPS-only for origin communication\n\n")
	}
	m.mu.Unlock()
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *CDNModule) writeOutput(ctx context.Context, logger internal.Logger) {
	totalRows := len(m.ProfileRows) + len(m.EndpointRows) + len(m.OriginRows)
	if totalRows == 0 {
		logger.InfoM("No CDN profiles found", globals.AZ_CDN_MODULE_NAME)
		return
	}

	// Define headers
	profileHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Profile Name",
		"SKU",
		"SKU Name",
		"Provisioning State",
		"Resource State",
		"Endpoint Count",
		"Custom Domain Count",
		"Origin Count",
		"Risk",
		"Risk Note",
	}

	// -------------------- TABLE 1: CDN Profiles --------------------
	if len(m.ProfileRows) > 0 {
		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.ProfileRows, profileHeaders,
				"cdn-profiles", globals.AZ_CDN_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant CDN profiles", globals.AZ_CDN_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.ProfileRows, profileHeaders,
				"cdn-profiles", globals.AZ_CDN_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription CDN profiles", globals.AZ_CDN_MODULE_NAME)
			}
		}
		return
	}

	// -------------------- TABLE 2: CDN Endpoints --------------------
	endpointHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Profile Name",
		"Endpoint Name",
		"Hostname",
		"Exposure",
		"Resource State",
		"Provisioning State",
		"HTTPS Only",
		"HTTP Allowed",
		"Compression Enabled",
		"Query String Caching",
		"Optimization Type",
		"Custom Domains",
		"Origin Count",
		"Geo Filters",
		"Risk",
		"Risk Note",
	}

	if len(m.EndpointRows) > 0 && azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.EndpointRows, endpointHeaders,
			"cdn-endpoints", globals.AZ_CDN_MODULE_NAME,
		); err != nil {
			logger.ErrorM("Failed to write per-tenant endpoints", globals.AZ_CDN_MODULE_NAME)
		}
		return
	}

	if len(m.EndpointRows) > 0 && azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.EndpointRows, endpointHeaders,
			"cdn-endpoints", globals.AZ_CDN_MODULE_NAME,
		); err != nil {
			logger.ErrorM("Failed to write per-subscription endpoints", globals.AZ_CDN_MODULE_NAME)
		}
		return
	}

	// -------------------- TABLE 3: CDN Origins --------------------
	originHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Profile Name",
		"Endpoint Name",
		"Origin Name",
		"Origin Hostname",
		"Protocol",
		"HTTP Port",
		"HTTPS Port",
		"Priority",
		"Weight",
		"Enabled",
		"Private Link",
		"Risk",
		"Risk Note",
	}

	if len(m.OriginRows) > 0 && azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.OriginRows, originHeaders,
			"cdn-origins", globals.AZ_CDN_MODULE_NAME,
		); err != nil {
			logger.ErrorM("Failed to write per-tenant origins", globals.AZ_CDN_MODULE_NAME)
		}
		return
	}

	if len(m.OriginRows) > 0 && azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.OriginRows, originHeaders,
			"cdn-origins", globals.AZ_CDN_MODULE_NAME,
		); err != nil {
			logger.ErrorM("Failed to write per-subscription origins", globals.AZ_CDN_MODULE_NAME)
		}
		return
	}

	// -------------------- Build tables --------------------
	tables := []internal.TableFile{}

	if len(m.ProfileRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cdn-profiles",
			Header: profileHeaders,
			Body:   m.ProfileRows,
		})
	}

	if len(m.EndpointRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cdn-endpoints",
			Header: endpointHeaders,
			Body:   m.EndpointRows,
		})
	}

	if len(m.OriginRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cdn-origins",
			Header: originHeaders,
			Body:   m.OriginRows,
		})
	}

	// -------------------- Convert loot map to slice --------------------
	var loot []internal.LootFile
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// -------------------- Generate output --------------------
	output := CDNOutput{
		Table: tables,
		Loot:  loot,
	}

	// -------------------- Determine scope for output --------------------
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// -------------------- Write output using HandleOutputSmart --------------------
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_CDN_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// -------------------- Success summary --------------------
	logger.SuccessM(fmt.Sprintf("CDN enumeration complete: %d profiles, %d endpoints, %d origins",
		len(m.ProfileRows), len(m.EndpointRows), len(m.OriginRows)), globals.AZ_CDN_MODULE_NAME)
}
