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
var AzVNetsCommand = &cobra.Command{
	Use:     "vnets",
	Aliases: []string{"virtual-networks", "networks"},
	Short:   "Enumerate Azure Virtual Networks, subnets, and peerings",
	Long: `
Enumerate Azure Virtual Networks for a specific tenant:
./cloudfox az vnets --tenant TENANT_ID

Enumerate Azure Virtual Networks for a specific subscription:
./cloudfox az vnets --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListVNets,
}

// ------------------------------
// Module struct
// ------------------------------
type VNetsModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	VNetRows      [][]string
	SubnetRows    [][]string
	PeeringRows   [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type VNetsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o VNetsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o VNetsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListVNets(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_VNETS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &VNetsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		VNetRows:        [][]string{},
		SubnetRows:      [][]string{},
		PeeringRows:     [][]string{},
		LootMap: map[string]*internal.LootFile{
			"vnet-commands":      {Name: "vnet-commands", Contents: ""},
			"vnet-peerings":      {Name: "vnet-peerings", Contents: "# VNet Peerings (Cross-Network Connections)\\n\\n"},
			"vnet-public-access": {Name: "vnet-public-access", Contents: "# VNets with Public Access\\n\\n"},
			"vnet-risks":         {Name: "vnet-risks", Contents: "# VNet Security Risks\\n\\n"},
		},
	}

	module.PrintVNets(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *VNetsModule) PrintVNets(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_VNETS_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_VNETS_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_VNETS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Virtual Networks for %d subscription(s)", len(m.Subscriptions)), globals.AZ_VNETS_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_VNETS_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *VNetsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create VNets client
	vnetClient, err := azinternal.GetVirtualNetworksClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create VNets client for subscription %s: %v", subID, err), globals.AZ_VNETS_MODULE_NAME)
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
		go m.processResourceGroup(ctx, subID, subName, rgName, vnetClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *VNetsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, vnetClient *armnetwork.VirtualNetworksClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
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

	// List VNets in resource group
	pager := vnetClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list VNets in %s/%s: %v", subID, rgName, err), globals.AZ_VNETS_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, vnet := range page.Value {
			m.processVNet(ctx, subID, subName, rgName, region, vnet, logger)
		}
	}
}

// ------------------------------
// Process single VNet
// ------------------------------
func (m *VNetsModule) processVNet(ctx context.Context, subID, subName, rgName, region string, vnet *armnetwork.VirtualNetwork, logger internal.Logger) {
	if vnet == nil || vnet.Name == nil {
		return
	}

	vnetName := *vnet.Name

	// Get address space
	addressSpace := []string{}
	if vnet.Properties != nil && vnet.Properties.AddressSpace != nil && vnet.Properties.AddressSpace.AddressPrefixes != nil {
		addressSpace = azinternal.SafeStringSlice(vnet.Properties.AddressSpace.AddressPrefixes)
	}
	addressSpaceStr := strings.Join(addressSpace, ", ")
	if addressSpaceStr == "" {
		addressSpaceStr = "N/A"
	}

	// Get DDoS protection status
	ddosProtection := "Disabled"
	if vnet.Properties != nil && vnet.Properties.EnableDdosProtection != nil && *vnet.Properties.EnableDdosProtection {
		ddosProtection = "Enabled"
	}

	// Get VM protection status
	vmProtection := "Disabled"
	if vnet.Properties != nil && vnet.Properties.EnableVMProtection != nil && *vnet.Properties.EnableVMProtection {
		vmProtection = "Enabled"
	}

	// Count subnets and peerings
	subnetCount := 0
	if vnet.Properties != nil && vnet.Properties.Subnets != nil {
		subnetCount = len(vnet.Properties.Subnets)
	}

	peeringCount := 0
	if vnet.Properties != nil && vnet.Properties.VirtualNetworkPeerings != nil {
		peeringCount = len(vnet.Properties.VirtualNetworkPeerings)
	}

	// VNet summary row
	vnetRow := []string{
		m.TenantName, // NEW: for multi-tenant support
		m.TenantID,   // NEW: for multi-tenant support
		subID,
		subName,
		rgName,
		region,
		vnetName,
		addressSpaceStr,
		ddosProtection,
		vmProtection,
		fmt.Sprintf("%d", subnetCount),
		fmt.Sprintf("%d", peeringCount),
	}

	m.mu.Lock()
	m.VNetRows = append(m.VNetRows, vnetRow)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Process subnets
	if vnet.Properties != nil && vnet.Properties.Subnets != nil {
		m.processSubnets(subID, subName, rgName, region, vnetName, vnet.Properties.Subnets)
	}

	// Process peerings
	if vnet.Properties != nil && vnet.Properties.VirtualNetworkPeerings != nil {
		m.processPeerings(subID, subName, rgName, vnetName, vnet.Properties.VirtualNetworkPeerings)
	}

	// Generate Azure CLI commands
	m.mu.Lock()
	m.LootMap["vnet-commands"].Contents += fmt.Sprintf("# VNet: %s (Resource Group: %s)\\n", vnetName, rgName)
	m.LootMap["vnet-commands"].Contents += fmt.Sprintf("az account set --subscription %s\\n", subID)
	m.LootMap["vnet-commands"].Contents += fmt.Sprintf("az network vnet show --name %s --resource-group %s\\n", vnetName, rgName)
	m.LootMap["vnet-commands"].Contents += fmt.Sprintf("az network vnet subnet list --vnet-name %s --resource-group %s -o table\\n", vnetName, rgName)
	if peeringCount > 0 {
		m.LootMap["vnet-commands"].Contents += fmt.Sprintf("az network vnet peering list --vnet-name %s --resource-group %s -o table\\n", vnetName, rgName)
	}
	m.LootMap["vnet-commands"].Contents += "\\n"
	m.mu.Unlock()

	// Check for security risks
	m.checkVNetRisks(subName, rgName, vnetName, ddosProtection, subnetCount, peeringCount)
}

// ------------------------------
// Process subnets
// ------------------------------
func (m *VNetsModule) processSubnets(subID, subName, rgName, region, vnetName string, subnets []*armnetwork.Subnet) {
	for _, subnet := range subnets {
		if subnet == nil || subnet.Name == nil || subnet.Properties == nil {
			continue
		}

		subnetName := *subnet.Name
		addressPrefix := azinternal.SafeStringPtr(subnet.Properties.AddressPrefix)

		// Check for NSG
		nsgName := "None"
		if subnet.Properties.NetworkSecurityGroup != nil && subnet.Properties.NetworkSecurityGroup.ID != nil {
			nsgName = azinternal.ExtractResourceName(*subnet.Properties.NetworkSecurityGroup.ID)
		}

		// Check for Route Table
		rtName := "None"
		if subnet.Properties.RouteTable != nil && subnet.Properties.RouteTable.ID != nil {
			rtName = azinternal.ExtractResourceName(*subnet.Properties.RouteTable.ID)
		}

		// Check for Service Endpoints
		serviceEndpoints := []string{}
		if subnet.Properties.ServiceEndpoints != nil {
			for _, se := range subnet.Properties.ServiceEndpoints {
				if se != nil && se.Service != nil {
					serviceEndpoints = append(serviceEndpoints, *se.Service)
				}
			}
		}
		serviceEndpointsStr := strings.Join(serviceEndpoints, ", ")
		if serviceEndpointsStr == "" {
			serviceEndpointsStr = "None"
		}

		// Check for Private Endpoints
		privateEndpointCount := 0
		if subnet.Properties.PrivateEndpoints != nil {
			privateEndpointCount = len(subnet.Properties.PrivateEndpoints)
		}

		subnetRow := []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			region,
			vnetName,
			subnetName,
			addressPrefix,
			nsgName,
			rtName,
			serviceEndpointsStr,
			fmt.Sprintf("%d", privateEndpointCount),
		}

		m.mu.Lock()
		m.SubnetRows = append(m.SubnetRows, subnetRow)
		m.mu.Unlock()

		// Check for subnets without NSGs
		if nsgName == "None" {
			m.mu.Lock()
			m.LootMap["vnet-public-access"].Contents += fmt.Sprintf("Subnet without NSG: %s/%s/%s\\n", rgName, vnetName, subnetName)
			m.LootMap["vnet-public-access"].Contents += fmt.Sprintf("  Address Prefix: %s\\n", addressPrefix)
			m.LootMap["vnet-public-access"].Contents += fmt.Sprintf("  Subscription: %s\\n\\n", subName)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Process peerings
// ------------------------------
func (m *VNetsModule) processPeerings(subID, subName, rgName, vnetName string, peerings []*armnetwork.VirtualNetworkPeering) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, peering := range peerings {
		if peering == nil || peering.Name == nil || peering.Properties == nil {
			continue
		}

		peeringName := *peering.Name

		// Get peering state
		peeringState := "N/A"
		if peering.Properties.PeeringState != nil {
			peeringState = string(*peering.Properties.PeeringState)
		}

		// Get remote VNet
		remoteVNet := "N/A"
		if peering.Properties.RemoteVirtualNetwork != nil && peering.Properties.RemoteVirtualNetwork.ID != nil {
			remoteVNet = *peering.Properties.RemoteVirtualNetwork.ID
		}

		// Get traffic forwarding settings
		allowForwarding := "Disabled"
		if peering.Properties.AllowForwardedTraffic != nil && *peering.Properties.AllowForwardedTraffic {
			allowForwarding = "Enabled"
		}

		allowGatewayTransit := "Disabled"
		if peering.Properties.AllowGatewayTransit != nil && *peering.Properties.AllowGatewayTransit {
			allowGatewayTransit = "Enabled"
		}

		useRemoteGateways := "Disabled"
		if peering.Properties.UseRemoteGateways != nil && *peering.Properties.UseRemoteGateways {
			useRemoteGateways = "Enabled"
		}

		peeringRow := []string{
			m.TenantName, // NEW: for multi-tenant support
			m.TenantID,   // NEW: for multi-tenant support
			subID,
			subName,
			rgName,
			vnetName,
			peeringName,
			peeringState,
			remoteVNet,
			allowForwarding,
			allowGatewayTransit,
			useRemoteGateways,
		}

		m.PeeringRows = append(m.PeeringRows, peeringRow)

		// Add to peerings loot
		m.LootMap["vnet-peerings"].Contents += fmt.Sprintf("Peering: %s/%s → %s\\n", rgName, vnetName, peeringName)
		m.LootMap["vnet-peerings"].Contents += fmt.Sprintf("  State: %s\\n", peeringState)
		m.LootMap["vnet-peerings"].Contents += fmt.Sprintf("  Remote VNet: %s\\n", remoteVNet)
		m.LootMap["vnet-peerings"].Contents += fmt.Sprintf("  Allow Forwarded Traffic: %s\\n", allowForwarding)
		m.LootMap["vnet-peerings"].Contents += fmt.Sprintf("  Allow Gateway Transit: %s\\n", allowGatewayTransit)
		m.LootMap["vnet-peerings"].Contents += fmt.Sprintf("  Use Remote Gateways: %s\\n", useRemoteGateways)
		m.LootMap["vnet-peerings"].Contents += fmt.Sprintf("  Subscription: %s\\n\\n", subName)

		// Check for peering risks
		if allowForwarding == "Enabled" {
			m.LootMap["vnet-risks"].Contents += fmt.Sprintf("🚨 PEERING RISK: %s/%s → %s\\n", rgName, vnetName, peeringName)
			m.LootMap["vnet-risks"].Contents += fmt.Sprintf("  ⚠️  Forwarded traffic allowed - traffic can be routed through this peering\\n")
			m.LootMap["vnet-risks"].Contents += fmt.Sprintf("  Remote VNet: %s\\n", remoteVNet)
			m.LootMap["vnet-risks"].Contents += fmt.Sprintf("  Subscription: %s\\n\\n", subName)
		}
	}
}

// ------------------------------
// Check VNet risks
// ------------------------------
func (m *VNetsModule) checkVNetRisks(subName, rgName, vnetName, ddosProtection string, subnetCount, peeringCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	risks := []string{}

	// Check for disabled DDoS protection
	if ddosProtection == "Disabled" {
		risks = append(risks, "DDoS Protection disabled - network vulnerable to DDoS attacks")
	}

	// Check for VNets with many peerings (potential lateral movement paths)
	if peeringCount > 3 {
		risks = append(risks, fmt.Sprintf("High number of peerings (%d) - multiple lateral movement paths", peeringCount))
	}

	// Check for VNets with no subnets
	if subnetCount == 0 {
		risks = append(risks, "No subnets configured - VNet not in use or misconfigured")
	}

	if len(risks) > 0 {
		m.LootMap["vnet-risks"].Contents += fmt.Sprintf("🚨 VNET RISK: %s/%s\\n", rgName, vnetName)
		for _, risk := range risks {
			m.LootMap["vnet-risks"].Contents += fmt.Sprintf("  ⚠️  %s\\n", risk)
		}
		m.LootMap["vnet-risks"].Contents += fmt.Sprintf("  Subscription: %s\\n\\n", subName)
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *VNetsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.VNetRows) == 0 {
		logger.InfoM("No Virtual Networks found", globals.AZ_VNETS_MODULE_NAME)
		return
	}

	// Define headers for all 3 tables
	vnetHeader := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"VNet Name",
		"Address Space",
		"DDoS Protection",
		"VM Protection",
		"Subnet Count",
		"Peering Count",
	}

	subnetHeader := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"VNet Name",
		"Subnet Name",
		"Address Prefix",
		"NSG",
		"Route Table",
		"Service Endpoints",
		"Private Endpoints",
	}

	peeringHeader := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"VNet Name",
		"Peering Name",
		"Peering State",
		"Remote VNet",
		"Allow Forwarded Traffic",
		"Allow Gateway Transit",
		"Use Remote Gateways",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.writePerTenant(ctx, logger, vnetHeader, subnetHeader, peeringHeader); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.writePerSubscription(ctx, logger, vnetHeader, subnetHeader, peeringHeader); err != nil {
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

	// Create table files
	tables := []internal.TableFile{
		{
			Name:   "vnets",
			Header: vnetHeader,
			Body:   m.VNetRows,
		},
	}

	// Add subnets table if we have subnets
	if len(m.SubnetRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vnets-subnets",
			Header: subnetHeader,
			Body:   m.SubnetRows,
		})
	}

	// Add peerings table if we have peerings
	if len(m.PeeringRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vnets-peerings",
			Header: peeringHeader,
			Body:   m.PeeringRows,
		})
	}

	// Create output
	output := VNetsOutput{
		Table: tables,
		Loot:  loot,
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_VNETS_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d VNets (%d subnets, %d peerings) across %d subscriptions",
		len(m.VNetRows), len(m.SubnetRows), len(m.PeeringRows), len(m.Subscriptions)), globals.AZ_VNETS_MODULE_NAME)
}

// ------------------------------
// Write per-subscription output (custom multi-table implementation)
// ------------------------------
func (m *VNetsModule) writePerSubscription(ctx context.Context, logger internal.Logger, vnetHeader, subnetHeader, peeringHeader []string) error {
	var lastErr error
	subscriptionColumnIndex := 3 // "Subscription Name" is at column 3 (after Tenant Name and Tenant ID)

	// Build loot array (same for all subscriptions in multi-sub mode)
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	for _, subID := range m.Subscriptions {
		subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

		// Filter rows for this subscription
		filteredVNets := m.filterRowsBySubscription(m.VNetRows, subscriptionColumnIndex, subName, subID)
		filteredSubnets := m.filterRowsBySubscription(m.SubnetRows, subscriptionColumnIndex, subName, subID)
		filteredPeerings := m.filterRowsBySubscription(m.PeeringRows, subscriptionColumnIndex, subName, subID)

		// Skip if no data for this subscription
		if len(filteredVNets) == 0 && len(filteredSubnets) == 0 && len(filteredPeerings) == 0 {
			continue
		}

		// Build tables (only include non-empty ones)
		tables := []internal.TableFile{}
		if len(filteredVNets) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "vnets",
				Header: vnetHeader,
				Body:   filteredVNets,
			})
		}
		if len(filteredSubnets) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "vnets-subnets",
				Header: subnetHeader,
				Body:   filteredSubnets,
			})
		}
		if len(filteredPeerings) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "vnets-peerings",
				Header: peeringHeader,
				Body:   filteredPeerings,
			})
		}

		output := VNetsOutput{
			Table: tables,
			Loot:  loot,
		}

		// Create output for this single subscription
		scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput([]string{subID}, m.TenantID, m.TenantName, false)
		scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

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
			logger.ErrorM(fmt.Sprintf("Error writing output for subscription %s: %v", subName, err), globals.AZ_VNETS_MODULE_NAME)
			m.CommandCounter.Error++
			lastErr = err
		}
	}

	return lastErr
}

// ------------------------------
// Filter rows by subscription
// ------------------------------
func (m *VNetsModule) filterRowsBySubscription(rows [][]string, columnIndex int, subName, subID string) [][]string {
	var filtered [][]string
	for _, row := range rows {
		if len(row) > columnIndex {
			if row[columnIndex] == subName || row[columnIndex] == subID {
				filtered = append(filtered, row)
			}
		}
	}
	return filtered
}

// ------------------------------
// Write output split by tenant (multi-tenant mode)
// ------------------------------
func (m *VNetsModule) writePerTenant(ctx context.Context, logger internal.Logger, vnetHeader, subnetHeader, peeringHeader []string) error {
	var lastErr error
	tenantNameColumnIndex := 0 // "Tenant Name" is at column 0 in all tables

	// Build loot array (same for all tenants in multi-tenant mode)
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	for _, tenantCtx := range m.Tenants {
		// Filter rows for this tenant
		filteredVNets := m.filterRowsByTenant(m.VNetRows, tenantNameColumnIndex, tenantCtx.TenantName)
		filteredSubnets := m.filterRowsByTenant(m.SubnetRows, tenantNameColumnIndex, tenantCtx.TenantName)
		filteredPeerings := m.filterRowsByTenant(m.PeeringRows, tenantNameColumnIndex, tenantCtx.TenantName)

		// Skip if no data for this tenant
		if len(filteredVNets) == 0 && len(filteredSubnets) == 0 && len(filteredPeerings) == 0 {
			continue
		}

		// Build tables (only include non-empty ones)
		tables := []internal.TableFile{}
		if len(filteredVNets) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "vnets",
				Header: vnetHeader,
				Body:   filteredVNets,
			})
		}
		if len(filteredSubnets) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "vnets-subnets",
				Header: subnetHeader,
				Body:   filteredSubnets,
			})
		}
		if len(filteredPeerings) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "vnets-peerings",
				Header: peeringHeader,
				Body:   filteredPeerings,
			})
		}

		output := VNetsOutput{
			Table: tables,
			Loot:  loot,
		}

		// Write output for this tenant
		if err := internal.HandleOutputSmart(
			"Azure",
			m.Format,
			m.OutputDirectory,
			m.Verbosity,
			m.WrapTable,
			"tenant",
			[]string{tenantCtx.TenantID},
			[]string{tenantCtx.TenantName},
			m.UserUPN,
			output,
		); err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for tenant %s: %v", tenantCtx.TenantName, err), globals.AZ_VNETS_MODULE_NAME)
			m.CommandCounter.Error++
			lastErr = err
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d VNet(s), %d subnet(s), %d peering(s) across %d tenant(s)",
		len(m.VNetRows), len(m.SubnetRows), len(m.PeeringRows), len(m.Tenants)), globals.AZ_VNETS_MODULE_NAME)

	return lastErr
}

// ------------------------------
// Filter rows by tenant
// ------------------------------
func (m *VNetsModule) filterRowsByTenant(rows [][]string, columnIndex int, tenantName string) [][]string {
	var filtered [][]string
	for _, row := range rows {
		if len(row) > columnIndex && row[columnIndex] == tenantName {
			filtered = append(filtered, row)
		}
	}
	return filtered
}
