package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzTrafficManagerCommand = &cobra.Command{
	Use:     "traffic-manager",
	Aliases: []string{"tm"},
	Short:   "Enumerate Azure Traffic Manager profiles with security analysis",
	Long: `
Enumerate Azure Traffic Manager (DNS-based load balancing) for a specific tenant:
./cloudfox az traffic-manager --tenant TENANT_ID

Enumerate Azure Traffic Manager for a specific subscription:
./cloudfox az traffic-manager --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

SECURITY FEATURES ANALYZED:
- DNS-based global traffic routing methods
- Endpoint health monitoring configuration (HTTP vs HTTPS)
- Endpoint health status and degradation detection
- DNS TTL configuration and availability impact
- Geographic routing and traffic distribution
- Priority and weight-based routing analysis
- Endpoint types: Azure, External, Nested profiles`,
	Run: ListTrafficManager,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type TrafficManagerModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields - 2 separate tables for comprehensive analysis
	Subscriptions []string
	ProfileRows   [][]string // Traffic Manager profiles overview
	EndpointRows  [][]string // Endpoints with health status
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type TrafficManagerOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o TrafficManagerOutput) TableFiles() []internal.TableFile { return o.Table }
func (o TrafficManagerOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListTrafficManager(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &TrafficManagerModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		ProfileRows:     [][]string{},
		EndpointRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"degraded-endpoints":       {Name: "degraded-endpoints", Contents: "# Traffic Manager endpoints with health issues\n\n"},
			"disabled-profiles":        {Name: "disabled-profiles", Contents: "# Disabled Traffic Manager profiles\n\n"},
			"insecure-monitoring":      {Name: "insecure-monitoring", Contents: "# Traffic Manager profiles using HTTP monitoring (not HTTPS)\n\n"},
			"high-ttl-profiles":        {Name: "high-ttl-profiles", Contents: "# Profiles with high DNS TTL (slow failover)\n\n"},
			"traffic-manager-commands": {Name: "traffic-manager-commands", Contents: "# Azure Traffic Manager enumeration commands\n\n"},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintTrafficManager(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *TrafficManagerModule) PrintTrafficManager(ctx context.Context, logger internal.Logger) {
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
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_TRAFFIC_MANAGER_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_TRAFFIC_MANAGER_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *TrafficManagerModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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
func (m *TrafficManagerModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get token and create Traffic Manager client
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	profileClient, err := armtrafficmanager.NewProfilesClient(subID, cred, nil)
	if err != nil {
		return
	}

	// Enumerate Traffic Manager profiles in this resource group
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

			m.processTrafficManagerProfile(ctx, subID, subName, rgName, profile)
		}
	}
}

// ------------------------------
// Process single Traffic Manager profile
// ------------------------------
func (m *TrafficManagerModule) processTrafficManagerProfile(ctx context.Context, subID, subName, rgName string, profile *armtrafficmanager.Profile) {
	profileName := azinternal.SafeStringPtr(profile.Name)
	region := azinternal.SafeStringPtr(profile.Location)

	// Extract profile status
	profileStatus := "N/A"
	if profile.Properties != nil && profile.Properties.ProfileStatus != nil {
		profileStatus = string(*profile.Properties.ProfileStatus)
	}

	// Extract DNS configuration
	dnsName := "N/A"
	dnsTTL := "N/A"
	if profile.Properties != nil && profile.Properties.DNSConfig != nil {
		if profile.Properties.DNSConfig.Fqdn != nil {
			dnsName = *profile.Properties.DNSConfig.Fqdn
		}
		if profile.Properties.DNSConfig.TTL != nil {
			dnsTTL = fmt.Sprintf("%d seconds", *profile.Properties.DNSConfig.TTL)
		}
	}

	// Extract routing method
	routingMethod := "N/A"
	if profile.Properties != nil && profile.Properties.TrafficRoutingMethod != nil {
		routingMethod = string(*profile.Properties.TrafficRoutingMethod)
	}

	// Extract monitoring configuration
	monitorProtocol := "N/A"
	monitorPort := "N/A"
	monitorPath := "N/A"
	monitorInterval := "N/A"
	monitorTimeout := "N/A"
	monitorTolerance := "N/A"
	expectedStatusCodes := "N/A"

	if profile.Properties != nil && profile.Properties.MonitorConfig != nil {
		mc := profile.Properties.MonitorConfig
		if mc.Protocol != nil {
			monitorProtocol = string(*mc.Protocol)
		}
		if mc.Port != nil {
			monitorPort = fmt.Sprintf("%d", *mc.Port)
		}
		if mc.Path != nil {
			monitorPath = *mc.Path
		}
		if mc.IntervalInSeconds != nil {
			monitorInterval = fmt.Sprintf("%d seconds", *mc.IntervalInSeconds)
		}
		if mc.TimeoutInSeconds != nil {
			monitorTimeout = fmt.Sprintf("%d seconds", *mc.TimeoutInSeconds)
		}
		if mc.ToleratedNumberOfFailures != nil {
			monitorTolerance = fmt.Sprintf("%d failures", *mc.ToleratedNumberOfFailures)
		}
		if mc.ExpectedStatusCodeRanges != nil && len(mc.ExpectedStatusCodeRanges) > 0 {
			codes := []string{}
			for _, codeRange := range mc.ExpectedStatusCodeRanges {
				if codeRange.Min != nil && codeRange.Max != nil {
					codes = append(codes, fmt.Sprintf("%d-%d", *codeRange.Min, *codeRange.Max))
				}
			}
			if len(codes) > 0 {
				expectedStatusCodes = strings.Join(codes, ", ")
			}
		}
	}

	// Count endpoints and their health status
	endpointCount := 0
	onlineEndpoints := 0
	degradedEndpoints := 0
	disabledEndpoints := 0

	if profile.Properties != nil && profile.Properties.Endpoints != nil {
		endpointCount = len(profile.Properties.Endpoints)
		for _, endpoint := range profile.Properties.Endpoints {
			if endpoint.Properties != nil {
				if endpoint.Properties.EndpointStatus != nil {
					status := string(*endpoint.Properties.EndpointStatus)
					switch status {
					case "Enabled":
						onlineEndpoints++
					case "Disabled":
						disabledEndpoints++
					case "Degraded", "CheckingEndpoint":
						degradedEndpoints++
					}
				}
				// Also check endpoint monitor status
				if endpoint.Properties.EndpointMonitorStatus != nil {
					monitorStatus := string(*endpoint.Properties.EndpointMonitorStatus)
					if monitorStatus == "Degraded" || monitorStatus == "Inactive" {
						degradedEndpoints++
					}
				}
			}
		}
	}

	// Determine risk level
	risk := "INFO"
	riskReasons := []string{}

	if profileStatus == "Disabled" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "Profile disabled")
	}
	if monitorProtocol == "HTTP" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "HTTP monitoring (not HTTPS)")
	}
	if degradedEndpoints > 0 {
		risk = "HIGH"
		riskReasons = append(riskReasons, fmt.Sprintf("%d degraded endpoint(s)", degradedEndpoints))
	}
	// High TTL means slow failover (> 60 seconds)
	if dnsTTL != "N/A" && strings.Contains(dnsTTL, "seconds") {
		var ttlValue int
		fmt.Sscanf(dnsTTL, "%d", &ttlValue)
		if ttlValue > 60 {
			risk = "MEDIUM"
			riskReasons = append(riskReasons, fmt.Sprintf("High DNS TTL (%d sec) = slow failover", ttlValue))
		}
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "Healthy configuration"
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
		dnsName,
		profileStatus,
		routingMethod,
		dnsTTL,
		monitorProtocol,
		monitorPort,
		monitorPath,
		monitorInterval,
		monitorTimeout,
		monitorTolerance,
		expectedStatusCodes,
		fmt.Sprintf("%d", endpointCount),
		fmt.Sprintf("%d", onlineEndpoints),
		fmt.Sprintf("%d", degradedEndpoints),
		fmt.Sprintf("%d", disabledEndpoints),
		risk,
		riskNote,
	})

	// Add to loot files
	if profileStatus == "Disabled" {
		m.LootMap["disabled-profiles"].Contents += fmt.Sprintf("Profile: %s (RG: %s)\n", profileName, rgName)
		m.LootMap["disabled-profiles"].Contents += fmt.Sprintf("  DNS: %s\n", dnsName)
		m.LootMap["disabled-profiles"].Contents += fmt.Sprintf("  Status: Disabled\n")
		m.LootMap["disabled-profiles"].Contents += fmt.Sprintf("  Command: az network traffic-manager profile update --name %s --resource-group %s --status Enabled\n\n", profileName, rgName)
	}
	if monitorProtocol == "HTTP" {
		m.LootMap["insecure-monitoring"].Contents += fmt.Sprintf("Profile: %s (RG: %s)\n", profileName, rgName)
		m.LootMap["insecure-monitoring"].Contents += fmt.Sprintf("  Risk: HTTP monitoring - health checks not encrypted\n")
		m.LootMap["insecure-monitoring"].Contents += fmt.Sprintf("  Recommendation: Use HTTPS for endpoint health monitoring\n")
		m.LootMap["insecure-monitoring"].Contents += fmt.Sprintf("  Command: az network traffic-manager profile update --name %s --resource-group %s --protocol HTTPS\n\n", profileName, rgName)
	}
	if dnsTTL != "N/A" && strings.Contains(dnsTTL, "seconds") {
		var ttlValue int
		fmt.Sscanf(dnsTTL, "%d", &ttlValue)
		if ttlValue > 60 {
			m.LootMap["high-ttl-profiles"].Contents += fmt.Sprintf("Profile: %s (RG: %s)\n", profileName, rgName)
			m.LootMap["high-ttl-profiles"].Contents += fmt.Sprintf("  TTL: %d seconds (slow failover)\n", ttlValue)
			m.LootMap["high-ttl-profiles"].Contents += fmt.Sprintf("  Impact: DNS resolution cached for %d seconds = slower endpoint failover\n", ttlValue)
			m.LootMap["high-ttl-profiles"].Contents += fmt.Sprintf("  Recommendation: Consider lower TTL (30-60 seconds) for faster failover\n\n")
		}
	}

	// Add enumeration commands to loot
	m.LootMap["traffic-manager-commands"].Contents += fmt.Sprintf("# Traffic Manager Profile: %s\n", profileName)
	m.LootMap["traffic-manager-commands"].Contents += fmt.Sprintf("az network traffic-manager profile show --name %s --resource-group %s\n", profileName, rgName)
	m.LootMap["traffic-manager-commands"].Contents += fmt.Sprintf("az network traffic-manager endpoint list --profile-name %s --resource-group %s\n", profileName, rgName)
	m.LootMap["traffic-manager-commands"].Contents += fmt.Sprintf("# Test DNS resolution: nslookup %s\n", dnsName)
	m.LootMap["traffic-manager-commands"].Contents += "\n"
	m.mu.Unlock()

	// Process endpoints
	if profile.Properties != nil && profile.Properties.Endpoints != nil {
		for _, endpoint := range profile.Properties.Endpoints {
			m.processTrafficManagerEndpoint(subID, subName, rgName, profileName, endpoint)
		}
	}
}

// ------------------------------
// Process Traffic Manager endpoint
// ------------------------------
func (m *TrafficManagerModule) processTrafficManagerEndpoint(subID, subName, rgName, profileName string, endpoint *armtrafficmanager.Endpoint) {
	if endpoint == nil {
		return
	}

	endpointName := azinternal.SafeStringPtr(endpoint.Name)

	// Extract endpoint type (Azure, External, Nested)
	endpointType := "Unknown"
	if endpoint.Type != nil {
		// Type format: Microsoft.Network/trafficManagerProfiles/azureEndpoints
		typeParts := strings.Split(*endpoint.Type, "/")
		if len(typeParts) > 0 {
			endpointType = typeParts[len(typeParts)-1]
		}
	}

	// Simplify endpoint type for readability
	endpointTypeSimple := endpointType
	switch endpointType {
	case "azureEndpoints":
		endpointTypeSimple = "Azure"
	case "externalEndpoints":
		endpointTypeSimple = "External"
	case "nestedEndpoints":
		endpointTypeSimple = "Nested"
	}

	// Extract endpoint properties
	target := "N/A"
	endpointStatus := "N/A"
	endpointMonitorStatus := "N/A"
	priority := "N/A"
	weight := "N/A"
	geoMapping := "N/A"
	minChildEndpoints := "N/A"
	targetResourceID := "N/A"

	if endpoint.Properties != nil {
		ep := endpoint.Properties
		if ep.Target != nil {
			target = *ep.Target
		}
		if ep.EndpointStatus != nil {
			endpointStatus = string(*ep.EndpointStatus)
		}
		if ep.EndpointMonitorStatus != nil {
			endpointMonitorStatus = string(*ep.EndpointMonitorStatus)
		}
		if ep.Priority != nil {
			priority = fmt.Sprintf("%d", *ep.Priority)
		}
		if ep.Weight != nil {
			weight = fmt.Sprintf("%d", *ep.Weight)
		}
		if ep.GeoMapping != nil && len(ep.GeoMapping) > 0 {
			if len(ep.GeoMapping) <= 3 {
				geoMapping = strings.Join(ep.GeoMapping, ", ")
			} else {
				geoMapping = fmt.Sprintf("%s... (%d regions)", strings.Join(ep.GeoMapping[:3], ", "), len(ep.GeoMapping))
			}
		}
		if ep.MinChildEndpoints != nil {
			minChildEndpoints = fmt.Sprintf("%d", *ep.MinChildEndpoints)
		}
		if ep.TargetResourceID != nil {
			targetResourceID = *ep.TargetResourceID
		}
	}

	// Extract endpoint location for external endpoints
	endpointLocation := "N/A"
	if endpoint.Properties != nil && endpoint.Properties.EndpointLocation != nil {
		endpointLocation = *endpoint.Properties.EndpointLocation
	}

	// Determine risk level
	risk := "INFO"
	riskReasons := []string{}

	if endpointStatus == "Disabled" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "Endpoint disabled")
	}
	if endpointMonitorStatus == "Degraded" || endpointMonitorStatus == "Inactive" || endpointMonitorStatus == "Stopped" {
		risk = "HIGH"
		riskReasons = append(riskReasons, fmt.Sprintf("Health: %s", endpointMonitorStatus))
	}
	if endpointTypeSimple == "External" && !strings.HasPrefix(target, "https://") {
		// Note: Traffic Manager targets are typically hostnames, not full URLs
		// This is just a warning for awareness
		riskReasons = append(riskReasons, "External endpoint (verify HTTPS)")
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "Healthy endpoint"
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
		endpointTypeSimple,
		target,
		endpointStatus,
		endpointMonitorStatus,
		priority,
		weight,
		geoMapping,
		endpointLocation,
		minChildEndpoints,
		targetResourceID,
		risk,
		riskNote,
	})

	// Add to loot files
	if endpointMonitorStatus == "Degraded" || endpointMonitorStatus == "Inactive" || endpointMonitorStatus == "Stopped" {
		m.LootMap["degraded-endpoints"].Contents += fmt.Sprintf("Endpoint: %s (Profile: %s, RG: %s)\n", endpointName, profileName, rgName)
		m.LootMap["degraded-endpoints"].Contents += fmt.Sprintf("  Status: %s\n", endpointStatus)
		m.LootMap["degraded-endpoints"].Contents += fmt.Sprintf("  Monitor Status: %s\n", endpointMonitorStatus)
		m.LootMap["degraded-endpoints"].Contents += fmt.Sprintf("  Target: %s\n", target)
		m.LootMap["degraded-endpoints"].Contents += fmt.Sprintf("  Type: %s\n", endpointTypeSimple)
		m.LootMap["degraded-endpoints"].Contents += fmt.Sprintf("  Action Required: Investigate endpoint health and connectivity\n\n")
	}
	m.mu.Unlock()
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *TrafficManagerModule) writeOutput(ctx context.Context, logger internal.Logger) {
	totalRows := len(m.ProfileRows) + len(m.EndpointRows)
	if totalRows == 0 {
		logger.InfoM("No Traffic Manager profiles found", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
		return
	}

	// -------------------- TABLE 1: Traffic Manager Profiles --------------------
	if len(m.ProfileRows) > 0 {
		profileHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"Region",
			"Profile Name",
			"DNS Name",
			"Profile Status",
			"Routing Method",
			"DNS TTL",
			"Monitor Protocol",
			"Monitor Port",
			"Monitor Path",
			"Monitor Interval",
			"Monitor Timeout",
			"Failure Tolerance",
			"Expected Status Codes",
			"Endpoint Count",
			"Online Endpoints",
			"Degraded Endpoints",
			"Disabled Endpoints",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.ProfileRows, profileHeaders,
				"traffic-manager-profiles", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant Traffic Manager profiles", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.IsCrossSubscription) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.ProfileRows, profileHeaders,
				"traffic-manager-profiles", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription Traffic Manager profiles", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
			}
		} else {
			m.WriteFullOutput(logger, m.ProfileRows, profileHeaders, "traffic-manager-profiles", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
		}
	}

	// -------------------- TABLE 2: Traffic Manager Endpoints --------------------
	if len(m.EndpointRows) > 0 {
		endpointHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"Profile Name",
			"Endpoint Name",
			"Endpoint Type",
			"Target",
			"Endpoint Status",
			"Monitor Status",
			"Priority",
			"Weight",
			"Geo Mapping",
			"Endpoint Location",
			"Min Child Endpoints",
			"Target Resource ID",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.EndpointRows, endpointHeaders,
				"traffic-manager-endpoints", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant endpoints", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.IsCrossSubscription) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.EndpointRows, endpointHeaders,
				"traffic-manager-endpoints", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription endpoints", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
			}
		} else {
			m.WriteFullOutput(logger, m.EndpointRows, endpointHeaders, "traffic-manager-endpoints", globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
		}
	}

	// -------------------- LOOT FILES --------------------
	m.WriteLoot(logger, m.LootMap, globals.AZ_TRAFFIC_MANAGER_MODULE_NAME)
}
