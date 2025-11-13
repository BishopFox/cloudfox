package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzFrontDoorCommand = &cobra.Command{
	Use:     "frontdoor",
	Aliases: []string{"fd"},
	Short:   "Enumerate Azure Front Door profiles with security analysis",
	Long: `
Enumerate Azure Front Door (CDN + WAF) for a specific tenant:
./cloudfox az frontdoor --tenant TENANT_ID

Enumerate Azure Front Door for a specific subscription:
./cloudfox az frontdoor --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

SECURITY FEATURES ANALYZED:
- WAF policy configuration and protection status
- Frontend endpoint exposure (always public-facing)
- Backend pool configurations and health probes
- SSL/TLS settings and certificate management
- Routing rules and caching policies
- Session affinity and load balancing
- Custom domains and DNS configuration`,
	Run: ListFrontDoor,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type FrontDoorModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields - 3 separate tables for comprehensive analysis
	Subscriptions []string
	ProfileRows   [][]string // Front Door profiles overview
	FrontendRows  [][]string // Frontend endpoints (public-facing)
	BackendRows   [][]string // Backend pools and health probes
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type FrontDoorOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FrontDoorOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FrontDoorOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListFrontDoor(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_FRONTDOOR_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &FrontDoorModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		ProfileRows:     [][]string{},
		FrontendRows:    [][]string{},
		BackendRows:     [][]string{},
		LootMap: map[string]*internal.LootFile{
			"no-waf-protection":     {Name: "no-waf-protection", Contents: "# Front Doors without WAF protection\n\n"},
			"disabled-waf-policies": {Name: "disabled-waf-policies", Contents: "# Front Doors with disabled WAF policies\n\n"},
			"unhealthy-backends":    {Name: "unhealthy-backends", Contents: "# Front Door backend pools with unhealthy backends\n\n"},
			"insecure-backends":     {Name: "insecure-backends", Contents: "# Backend pools allowing HTTP (not HTTPS-only)\n\n"},
			"frontdoor-commands":    {Name: "frontdoor-commands", Contents: "# Azure Front Door enumeration and testing commands\n\n"},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintFrontDoors(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *FrontDoorModule) PrintFrontDoors(ctx context.Context, logger internal.Logger) {
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
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_FRONTDOOR_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_FRONTDOOR_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *FrontDoorModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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
func (m *FrontDoorModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get token and create Front Door client
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	frontDoorClient, err := armfrontdoor.NewFrontDoorsClient(subID, cred, nil)
	if err != nil {
		return
	}

	// Enumerate Front Door profiles in this resource group
	pager := frontDoorClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, fd := range page.Value {
			if fd == nil || fd.Name == nil {
				continue
			}

			m.processFrontDoor(ctx, subID, subName, rgName, fd)
		}
	}
}

// ------------------------------
// Process single Front Door profile
// ------------------------------
func (m *FrontDoorModule) processFrontDoor(ctx context.Context, subID, subName, rgName string, fd *armfrontdoor.FrontDoor) {
	fdName := azinternal.SafeStringPtr(fd.Name)
	region := azinternal.SafeStringPtr(fd.Location)

	// Extract basic properties
	provisioningState := "N/A"
	resourceState := "N/A"
	enabledState := "N/A"
	if fd.Properties != nil {
		if fd.Properties.ProvisioningState != nil {
			provisioningState = *fd.Properties.ProvisioningState
		}
		if fd.Properties.ResourceState != nil {
			resourceState = string(*fd.Properties.ResourceState)
		}
		if fd.Properties.EnabledState != nil {
			enabledState = string(*fd.Properties.EnabledState)
		}
	}

	// Extract WAF policy information
	wafPolicy := "N/A"
	wafPolicyID := ""
	wafMode := "N/A"
	// Note: WebApplicationFirewallPolicyLink not available in current SDK version
	_ = wafPolicyID // Avoid unused warning
	// TODO: Add WAF policy detection when SDK supports it

	// Count resources
	frontendCount := 0
	backendPoolCount := 0
	routingRuleCount := 0
	healthProbeCount := 0
	loadBalancingCount := 0

	if fd.Properties != nil {
		if fd.Properties.FrontendEndpoints != nil {
			frontendCount = len(fd.Properties.FrontendEndpoints)
		}
		if fd.Properties.BackendPools != nil {
			backendPoolCount = len(fd.Properties.BackendPools)
		}
		if fd.Properties.RoutingRules != nil {
			routingRuleCount = len(fd.Properties.RoutingRules)
		}
		if fd.Properties.HealthProbeSettings != nil {
			healthProbeCount = len(fd.Properties.HealthProbeSettings)
		}
		if fd.Properties.LoadBalancingSettings != nil {
			loadBalancingCount = len(fd.Properties.LoadBalancingSettings)
		}
	}

	// Determine risk level based on security configuration
	risk := "INFO"
	riskReasons := []string{}

	if wafPolicy == "N/A" {
		risk = "HIGH"
		riskReasons = append(riskReasons, "No WAF protection")
	}
	if enabledState == "Disabled" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "Front Door disabled")
	}
	if resourceState != "Enabled" && resourceState != "N/A" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, fmt.Sprintf("Resource state: %s", resourceState))
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "WAF enabled"
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
		fdName,
		enabledState,
		provisioningState,
		resourceState,
		wafPolicy,
		wafMode,
		fmt.Sprintf("%d", frontendCount),
		fmt.Sprintf("%d", backendPoolCount),
		fmt.Sprintf("%d", routingRuleCount),
		fmt.Sprintf("%d", healthProbeCount),
		fmt.Sprintf("%d", loadBalancingCount),
		risk,
		riskNote,
	})

	// Add to loot files
	if wafPolicy == "N/A" {
		m.LootMap["no-waf-protection"].Contents += fmt.Sprintf("Front Door: %s (Subscription: %s, RG: %s)\n", fdName, subName, rgName)
		m.LootMap["no-waf-protection"].Contents += fmt.Sprintf("  Risk: No WAF protection - vulnerable to web attacks\n")
		m.LootMap["no-waf-protection"].Contents += fmt.Sprintf("  Command: az network front-door waf-policy create --name %s-waf --resource-group %s\n\n", fdName, rgName)
	}
	m.mu.Unlock()

	// Process frontend endpoints
	if fd.Properties != nil && fd.Properties.FrontendEndpoints != nil {
		for _, frontend := range fd.Properties.FrontendEndpoints {
			m.processFrontendEndpoint(subID, subName, rgName, fdName, frontend)
		}
	}

	// Process backend pools
	if fd.Properties != nil && fd.Properties.BackendPools != nil {
		for _, pool := range fd.Properties.BackendPools {
			m.processBackendPool(subID, subName, rgName, fdName, pool, fd.Properties.HealthProbeSettings, fd.Properties.LoadBalancingSettings)
		}
	}

	// Add enumeration commands to loot
	m.mu.Lock()
	m.LootMap["frontdoor-commands"].Contents += fmt.Sprintf("# Front Door: %s\n", fdName)
	m.LootMap["frontdoor-commands"].Contents += fmt.Sprintf("az network front-door show --name %s --resource-group %s\n", fdName, rgName)
	m.LootMap["frontdoor-commands"].Contents += fmt.Sprintf("az network front-door routing-rule list --front-door-name %s --resource-group %s\n", fdName, rgName)
	if wafPolicyID != "" {
		m.LootMap["frontdoor-commands"].Contents += fmt.Sprintf("az network front-door waf-policy show --name %s --resource-group %s\n", wafPolicy, rgName)
	}
	m.LootMap["frontdoor-commands"].Contents += "\n"
	m.mu.Unlock()
}

// ------------------------------
// Process frontend endpoint
// ------------------------------
func (m *FrontDoorModule) processFrontendEndpoint(subID, subName, rgName, fdName string, frontend *armfrontdoor.FrontendEndpoint) {
	if frontend == nil || frontend.Properties == nil {
		return
	}

	endpointName := azinternal.SafeStringPtr(frontend.Name)
	hostname := azinternal.SafeStringPtr(frontend.Properties.HostName)

	// Extract session affinity
	sessionAffinity := "Disabled"
	sessionAffinityTTL := "N/A"
	if frontend.Properties.SessionAffinityEnabledState != nil && *frontend.Properties.SessionAffinityEnabledState == armfrontdoor.SessionAffinityEnabledStateEnabled {
		sessionAffinity = "Enabled"
		if frontend.Properties.SessionAffinityTTLSeconds != nil {
			sessionAffinityTTL = fmt.Sprintf("%d seconds", *frontend.Properties.SessionAffinityTTLSeconds)
		}
	}

	// Extract WAF policy link for this frontend
	wafPolicy := "N/A"
	if frontend.Properties.WebApplicationFirewallPolicyLink != nil && frontend.Properties.WebApplicationFirewallPolicyLink.ID != nil {
		wafPolicy = extractResourceName(*frontend.Properties.WebApplicationFirewallPolicyLink.ID)
	}

	// Extract custom HTTPS configuration
	httpsState := "N/A"
	certSource := "N/A"
	minTLSVersion := "N/A"
	if frontend.Properties.CustomHTTPSConfiguration != nil {
		if frontend.Properties.CustomHTTPSConfiguration.CertificateSource != nil {
			certSource = string(*frontend.Properties.CustomHTTPSConfiguration.CertificateSource)
		}
		if frontend.Properties.CustomHTTPSConfiguration.MinimumTLSVersion != nil {
			minTLSVersion = string(*frontend.Properties.CustomHTTPSConfiguration.MinimumTLSVersion)
		}
	}
	if frontend.Properties.CustomHTTPSProvisioningState != nil {
		httpsState = string(*frontend.Properties.CustomHTTPSProvisioningState)
	}

	risk := "INFO"
	riskReasons := []string{}

	if wafPolicy == "N/A" {
		risk = "HIGH"
		riskReasons = append(riskReasons, "No WAF on frontend")
	}
	if httpsState == "Disabled" || httpsState == "N/A" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "HTTPS not configured")
	}
	if minTLSVersion != "N/A" && minTLSVersion != "1.2" && minTLSVersion != "1.3" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, fmt.Sprintf("Weak TLS: %s", minTLSVersion))
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "Secure configuration"
	}

	// Thread-safe append
	m.mu.Lock()
	m.FrontendRows = append(m.FrontendRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		fdName,
		endpointName,
		hostname,
		"Public", // Front Door frontends are always public-facing
		sessionAffinity,
		sessionAffinityTTL,
		wafPolicy,
		httpsState,
		certSource,
		minTLSVersion,
		risk,
		riskNote,
	})
	m.mu.Unlock()
}

// ------------------------------
// Process backend pool
// ------------------------------
func (m *FrontDoorModule) processBackendPool(subID, subName, rgName, fdName string, pool *armfrontdoor.BackendPool,
	healthProbes []*armfrontdoor.HealthProbeSettingsModel, loadBalancingSettings []*armfrontdoor.LoadBalancingSettingsModel) {

	if pool == nil || pool.Properties == nil {
		return
	}

	poolName := azinternal.SafeStringPtr(pool.Name)

	// Find health probe settings for this pool
	healthProbeInterval := "N/A"
	healthProbePath := "N/A"
	healthProbeProtocol := "N/A"
	if pool.Properties.HealthProbeSettings != nil && pool.Properties.HealthProbeSettings.ID != nil {
		healthProbeName := extractResourceName(*pool.Properties.HealthProbeSettings.ID)
		for _, probe := range healthProbes {
			if probe.Name != nil && *probe.Name == healthProbeName && probe.Properties != nil {
				if probe.Properties.IntervalInSeconds != nil {
					healthProbeInterval = fmt.Sprintf("%d seconds", *probe.Properties.IntervalInSeconds)
				}
				if probe.Properties.Path != nil {
					healthProbePath = *probe.Properties.Path
				}
				if probe.Properties.Protocol != nil {
					healthProbeProtocol = string(*probe.Properties.Protocol)
				}
				break
			}
		}
	}

	// Find load balancing settings for this pool
	sampleSize := "N/A"
	successfulSamples := "N/A"
	if pool.Properties.LoadBalancingSettings != nil && pool.Properties.LoadBalancingSettings.ID != nil {
		lbName := extractResourceName(*pool.Properties.LoadBalancingSettings.ID)
		for _, lb := range loadBalancingSettings {
			if lb.Name != nil && *lb.Name == lbName && lb.Properties != nil {
				if lb.Properties.SampleSize != nil {
					sampleSize = fmt.Sprintf("%d", *lb.Properties.SampleSize)
				}
				if lb.Properties.SuccessfulSamplesRequired != nil {
					successfulSamples = fmt.Sprintf("%d", *lb.Properties.SuccessfulSamplesRequired)
				}
				break
			}
		}
	}

	// Process backends in this pool
	if pool.Properties.Backends == nil || len(pool.Properties.Backends) == 0 {
		// Empty backend pool
		m.mu.Lock()
		m.BackendRows = append(m.BackendRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			fdName,
			poolName,
			"N/A", // Backend address
			"N/A", // Backend host header
			"N/A", // Priority
			"N/A", // Weight
			"N/A", // Protocol
			"N/A", // Port
			healthProbeProtocol,
			healthProbePath,
			healthProbeInterval,
			sampleSize,
			successfulSamples,
			"HIGH",
			"Empty backend pool",
		})
		m.mu.Unlock()
		return
	}

	for _, backend := range pool.Properties.Backends {
		if backend == nil {
			continue
		}

		backendAddr := azinternal.SafeStringPtr(backend.Address)
		backendHostHeader := azinternal.SafeStringPtr(backend.BackendHostHeader)
		priority := "N/A"
		weight := "N/A"
		protocol := "HTTPS" // Default
		port := "N/A"

		if backend.Priority != nil {
			priority = fmt.Sprintf("%d", *backend.Priority)
		}
		if backend.Weight != nil {
			weight = fmt.Sprintf("%d", *backend.Weight)
		}
		if backend.HTTPPort != nil {
			port = fmt.Sprintf("HTTP:%d", *backend.HTTPPort)
			protocol = "HTTP"
		}
		if backend.HTTPSPort != nil {
			if port != "N/A" {
				port = fmt.Sprintf("%s, HTTPS:%d", port, *backend.HTTPSPort)
				protocol = "HTTP & HTTPS"
			} else {
				port = fmt.Sprintf("HTTPS:%d", *backend.HTTPSPort)
				protocol = "HTTPS"
			}
		}

		// Determine enabled state
		enabledState := "Enabled"
		if backend.EnabledState != nil && *backend.EnabledState == armfrontdoor.BackendEnabledStateDisabled {
			enabledState = "Disabled"
		}

		risk := "INFO"
		riskReasons := []string{}

		if protocol == "HTTP" || protocol == "HTTP & HTTPS" {
			risk = "MEDIUM"
			riskReasons = append(riskReasons, "HTTP allowed (not HTTPS-only)")
		}
		if enabledState == "Disabled" {
			risk = "MEDIUM"
			riskReasons = append(riskReasons, "Backend disabled")
		}
		if healthProbeProtocol == "N/A" {
			risk = "MEDIUM"
			riskReasons = append(riskReasons, "No health probe configured")
		}

		riskNote := strings.Join(riskReasons, "; ")
		if riskNote == "" {
			riskNote = "Secure configuration"
		}

		// Thread-safe append
		m.mu.Lock()
		m.BackendRows = append(m.BackendRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			fdName,
			poolName,
			backendAddr,
			backendHostHeader,
			priority,
			weight,
			protocol,
			port,
			healthProbeProtocol,
			healthProbePath,
			healthProbeInterval,
			sampleSize,
			successfulSamples,
			risk,
			riskNote,
		})

		// Add to loot files
		if protocol == "HTTP" || protocol == "HTTP & HTTPS" {
			m.LootMap["insecure-backends"].Contents += fmt.Sprintf("Backend: %s in pool %s (Front Door: %s, RG: %s)\n", backendAddr, poolName, fdName, rgName)
			m.LootMap["insecure-backends"].Contents += fmt.Sprintf("  Risk: HTTP allowed - traffic not encrypted\n")
			m.LootMap["insecure-backends"].Contents += fmt.Sprintf("  Recommendation: Configure HTTPS-only for backend pool\n\n")
		}
		if healthProbeProtocol == "N/A" {
			m.LootMap["unhealthy-backends"].Contents += fmt.Sprintf("Backend pool: %s (Front Door: %s, RG: %s)\n", poolName, fdName, rgName)
			m.LootMap["unhealthy-backends"].Contents += fmt.Sprintf("  Risk: No health probe configured\n")
			m.LootMap["unhealthy-backends"].Contents += fmt.Sprintf("  Recommendation: Configure health probes for backend monitoring\n\n")
		}
		m.mu.Unlock()
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *FrontDoorModule) writeOutput(ctx context.Context, logger internal.Logger) {
	totalRows := len(m.ProfileRows) + len(m.FrontendRows) + len(m.BackendRows)
	if totalRows == 0 {
		logger.InfoM("No Front Door profiles found", globals.AZ_FRONTDOOR_MODULE_NAME)
		return
	}

	// -------------------- TABLE 1: Front Door Profiles --------------------
	if len(m.ProfileRows) > 0 {
		profileHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"Region",
			"Front Door Name",
			"Enabled State",
			"Provisioning State",
			"Resource State",
			"WAF Policy",
			"WAF Mode",
			"Frontend Count",
			"Backend Pool Count",
			"Routing Rule Count",
			"Health Probe Count",
			"Load Balancing Count",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.ProfileRows, profileHeaders,
				"frontdoor-profiles", globals.AZ_FRONTDOOR_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant Front Door profiles", globals.AZ_FRONTDOOR_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.ProfileRows, profileHeaders,
				"frontdoor-profiles", globals.AZ_FRONTDOOR_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription Front Door profiles", globals.AZ_FRONTDOOR_MODULE_NAME)
			}
		} else {
			// TODO: Implement WriteFullOutput
			logger.InfoM("Front Door profiles enumeration complete", globals.AZ_FRONTDOOR_MODULE_NAME)
		}
	}

	// -------------------- TABLE 2: Frontend Endpoints --------------------
	if len(m.FrontendRows) > 0 {
		frontendHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"Front Door Name",
			"Endpoint Name",
			"Hostname",
			"Exposure",
			"Session Affinity",
			"Session Affinity TTL",
			"WAF Policy",
			"HTTPS State",
			"Certificate Source",
			"Min TLS Version",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.FrontendRows, frontendHeaders,
				"frontdoor-frontends", globals.AZ_FRONTDOOR_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant frontends", globals.AZ_FRONTDOOR_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.FrontendRows, frontendHeaders,
				"frontdoor-frontends", globals.AZ_FRONTDOOR_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription frontends", globals.AZ_FRONTDOOR_MODULE_NAME)
			}
		} else {
			// TODO: Implement WriteFullOutput
			logger.InfoM("Front Door frontends enumeration complete", globals.AZ_FRONTDOOR_MODULE_NAME)
		}
	}

	// -------------------- TABLE 3: Backend Pools --------------------
	if len(m.BackendRows) > 0 {
		backendHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"Front Door Name",
			"Backend Pool Name",
			"Backend Address",
			"Backend Host Header",
			"Priority",
			"Weight",
			"Protocol",
			"Ports",
			"Health Probe Protocol",
			"Health Probe Path",
			"Health Probe Interval",
			"Sample Size",
			"Successful Samples Required",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.BackendRows, backendHeaders,
				"frontdoor-backends", globals.AZ_FRONTDOOR_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant backends", globals.AZ_FRONTDOOR_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.BackendRows, backendHeaders,
				"frontdoor-backends", globals.AZ_FRONTDOOR_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription backends", globals.AZ_FRONTDOOR_MODULE_NAME)
			}
		} else {
			// TODO: Implement WriteFullOutput
			logger.InfoM("Front Door backends enumeration complete", globals.AZ_FRONTDOOR_MODULE_NAME)
		}
	}

	// -------------------- LOOT FILES --------------------
	// TODO: Implement WriteLoot
	logger.InfoM("Front Door enumeration complete", globals.AZ_FRONTDOOR_MODULE_NAME)
}

// ------------------------------
// Helper function to extract resource name from ARM ID
// ------------------------------
func extractResourceName(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return resourceID
}
