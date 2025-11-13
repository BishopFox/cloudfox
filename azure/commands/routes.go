package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzRoutesCommand = &cobra.Command{
	Use:     "routes",
	Aliases: []string{"route-tables", "routing"},
	Short:   "Enumerate Azure Route Tables and custom routes",
	Long: `
Enumerate Azure Route Tables for a specific tenant:
./cloudfox az routes --tenant TENANT_ID

Enumerate Azure Route Tables for a specific subscription:
./cloudfox az routes --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListRoutes,
}

// ------------------------------
// Module struct
// ------------------------------
type RoutesModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	RouteRows     [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type RoutesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o RoutesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o RoutesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListRoutes(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_ROUTES_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &RoutesModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		RouteRows:       [][]string{},
		LootMap: map[string]*internal.LootFile{
			"route-commands":      {Name: "route-commands", Contents: ""},
			"route-custom-routes": {Name: "route-custom-routes", Contents: "# Custom Routes (Non-System Routes)\\n\\n"},
			"route-risks":         {Name: "route-risks", Contents: "# Route Table Security Risks\\n\\n"},
		},
	}

	module.PrintRoutes(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *RoutesModule) PrintRoutes(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_ROUTES_MODULE_NAME)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_ROUTES_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_ROUTES_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Route Tables for %d subscription(s)", len(m.Subscriptions)), globals.AZ_ROUTES_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_ROUTES_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *RoutesModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create Route Tables client
	rtClient, err := azinternal.GetRouteTablesClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Route Tables client for subscription %s: %v", subID, err), globals.AZ_ROUTES_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rg := range rgs {
		if rg.Name == nil {
			continue
		}
		rgName := *rg.Name

		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, rtClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *RoutesModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, rtClient *armnetwork.RouteTablesClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	for _, r := range rgs {
		if r.Name != nil && *r.Name == rgName && r.Location != nil {
			region = *r.Location
			break
		}
	}

	// List Route Tables in resource group
	pager := rtClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list Route Tables in %s/%s: %v", subID, rgName, err), globals.AZ_ROUTES_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, rt := range page.Value {
			m.processRouteTable(ctx, subID, subName, rgName, region, rt, logger)
		}
	}
}

// ------------------------------
// Process single Route Table
// ------------------------------
func (m *RoutesModule) processRouteTable(ctx context.Context, subID, subName, rgName, region string, rt *armnetwork.RouteTable, logger internal.Logger) {
	if rt == nil || rt.Name == nil {
		return
	}

	rtName := *rt.Name

	// Get BGP route propagation status
	bgpPropagation := "Disabled"
	if rt.Properties != nil && rt.Properties.DisableBgpRoutePropagation != nil {
		if *rt.Properties.DisableBgpRoutePropagation {
			bgpPropagation = "Disabled"
		} else {
			bgpPropagation = "Enabled"
		}
	}

	// Get associated subnets
	subnets := []string{}
	if rt.Properties != nil && rt.Properties.Subnets != nil {
		for _, subnet := range rt.Properties.Subnets {
			if subnet != nil && subnet.ID != nil {
				subnets = append(subnets, azinternal.ExtractResourceName(*subnet.ID))
			}
		}
	}
	subnetsStr := strings.Join(subnets, ", ")
	if subnetsStr == "" {
		subnetsStr = "None"
	}

	// Process routes
	if rt.Properties != nil && rt.Properties.Routes != nil {
		for _, route := range rt.Properties.Routes {
			if route == nil || route.Name == nil || route.Properties == nil {
				continue
			}

			routeName := *route.Name

			addressPrefix := azinternal.SafeStringPtr(route.Properties.AddressPrefix)

			nextHopType := "N/A"
			if route.Properties.NextHopType != nil {
				nextHopType = string(*route.Properties.NextHopType)
			}

			nextHopIP := azinternal.SafeStringPtr(route.Properties.NextHopIPAddress)
			if nextHopIP == "" {
				nextHopIP = "N/A"
			}

			row := []string{
				m.TenantName, // NEW: for multi-tenant support
				m.TenantID,   // NEW: for multi-tenant support
				subID,
				subName,
				rgName,
				region,
				rtName,
				routeName,
				addressPrefix,
				nextHopType,
				nextHopIP,
				bgpPropagation,
				subnetsStr,
			}

			m.mu.Lock()
			m.RouteRows = append(m.RouteRows, row)
			m.mu.Unlock()
			m.CommandCounter.Total++

			// Generate loot for custom routes
			m.generateLoot(subID, subName, rgName, rtName, routeName, addressPrefix, nextHopType, nextHopIP)
		}
	} else {
		// Route table with no routes (still worth recording)
		row := []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			region,
			rtName,
			"No Routes",
			"N/A",
			"N/A",
			"N/A",
			bgpPropagation,
			subnetsStr,
		}

		m.mu.Lock()
		m.RouteRows = append(m.RouteRows, row)
		m.mu.Unlock()
		m.CommandCounter.Total++
	}

	// Generate Azure CLI commands
	m.mu.Lock()
	m.LootMap["route-commands"].Contents += fmt.Sprintf("# Route Table: %s (Resource Group: %s)\\n", rtName, rgName)
	m.LootMap["route-commands"].Contents += fmt.Sprintf("az account set --subscription %s\\n", subID)
	m.LootMap["route-commands"].Contents += fmt.Sprintf("az network route-table show --name %s --resource-group %s\\n", rtName, rgName)
	m.LootMap["route-commands"].Contents += fmt.Sprintf("az network route-table route list --route-table-name %s --resource-group %s -o table\\n\\n", rtName, rgName)
	m.mu.Unlock()
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *RoutesModule) generateLoot(subID, subName, rgName, rtName, routeName, addressPrefix, nextHopType, nextHopIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Track custom routes (non-system routes)
	if nextHopType != "System" {
		m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("Route Table: %s/%s\\n", rgName, rtName)
		m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Route: %s\\n", routeName)
		m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Address Prefix: %s\\n", addressPrefix)
		m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Next Hop Type: %s\\n", nextHopType)
		m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Next Hop IP: %s\\n", nextHopIP)
		m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Subscription: %s\\n\\n", subName)
	}

	// Identify security risks
	risks := []string{}

	// Check for routes to virtual appliances
	if nextHopType == "VirtualAppliance" {
		risks = append(risks, "Traffic routed through virtual appliance - verify appliance security")
	}

	// Check for internet-bound routes
	if nextHopType == "Internet" {
		risks = append(risks, "Traffic routed directly to Internet - potential data exfiltration path")
	}

	// Check for overly broad routes
	if addressPrefix == "0.0.0.0/0" {
		risks = append(risks, "Default route (0.0.0.0/0) - all traffic affected")
	}

	// Check for routes to VNet gateways (potential cross-tenant traffic)
	if nextHopType == "VirtualNetworkGateway" {
		risks = append(risks, "Traffic routed through VPN/ExpressRoute gateway - verify destination security")
	}

	if len(risks) > 0 {
		m.LootMap["route-risks"].Contents += fmt.Sprintf("🚨 ROUTE RISK: Route Table %s/%s - Route %s\\n", rgName, rtName, routeName)
		m.LootMap["route-risks"].Contents += fmt.Sprintf("  Address Prefix: %s | Next Hop: %s (%s)\\n", addressPrefix, nextHopType, nextHopIP)
		for _, risk := range risks {
			m.LootMap["route-risks"].Contents += fmt.Sprintf("  ⚠️  %s\\n", risk)
		}
		m.LootMap["route-risks"].Contents += fmt.Sprintf("  Subscription: %s\\n", subName)
		m.LootMap["route-risks"].Contents += fmt.Sprintf("  Command: az network route-table route show --route-table-name %s --resource-group %s --name %s\\n\\n", rtName, rgName, routeName)
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *RoutesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.RouteRows) == 0 {
		logger.InfoM("No Route Tables found", globals.AZ_ROUTES_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Route Table Name",
		"Route Name",
		"Address Prefix",
		"Next Hop Type",
		"Next Hop IP",
		"BGP Route Propagation",
		"Associated Subnets",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.RouteRows,
			headers,
			"routes",
			globals.AZ_ROUTES_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.RouteRows, headers,
			"routes", globals.AZ_ROUTES_MODULE_NAME,
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
	output := RoutesOutput{
		Table: []internal.TableFile{{
			Name:   "routes",
			Header: headers,
			Body:   m.RouteRows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_ROUTES_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d routes across %d subscriptions", len(m.RouteRows), len(m.Subscriptions)), globals.AZ_ROUTES_MODULE_NAME)
}
