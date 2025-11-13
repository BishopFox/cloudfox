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
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzExpressRouteCommand = &cobra.Command{
	Use:     "expressroute",
	Aliases: []string{"er", "express-route"},
	Short:   "Enumerate ExpressRoute circuits and their configurations",
	Long: `
Enumerate ExpressRoute circuits for a specific tenant:
./cloudfox az expressroute --tenant TENANT_ID

Enumerate ExpressRoute circuits for a specific subscription:
./cloudfox az expressroute --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

Analyzes ExpressRoute circuit configurations including:
- Circuit SKU (tier and family)
- Service provider and bandwidth
- Peering configurations (Private, Microsoft, Public)
- ExpressRoute Gateway connections
- Circuit provisioning state
`,
	Run: ListExpressRouteCircuits,
}

// ------------------------------
// Module struct
// ------------------------------
type ExpressRouteModule struct {
	azinternal.BaseAzureModule

	Subscriptions    []string
	ExpressRouteRows [][]string
	PeeringRows      [][]string
	LootMap          map[string]*internal.LootFile
	mu               sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ExpressRouteOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ExpressRouteOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ExpressRouteOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListExpressRouteCircuits(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_EXPRESSROUTE_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &ExpressRouteModule{
		BaseAzureModule:  azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:    cmdCtx.Subscriptions,
		ExpressRouteRows: [][]string{},
		PeeringRows:      [][]string{},
		LootMap: map[string]*internal.LootFile{
			"expressroute-commands": {Name: "expressroute-commands", Contents: "# ExpressRoute Commands\n\n"},
			"expressroute-peerings": {Name: "expressroute-peerings", Contents: "# ExpressRoute Peering Configurations\n\n"},
		},
	}

	module.PrintExpressRouteCircuits(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *ExpressRouteModule) PrintExpressRouteCircuits(ctx context.Context, logger internal.Logger) {
	// Multi-tenant support
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_EXPRESSROUTE_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_EXPRESSROUTE_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *ExpressRouteModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)
	resourceGroups := m.ResolveResourceGroups(subID)

	for _, rgName := range resourceGroups {
		m.processResourceGroup(ctx, subID, subName, rgName, logger)
	}
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *ExpressRouteModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, logger internal.Logger) {
	circuits, err := m.getExpressRouteCircuits(ctx, subID, rgName)
	if err != nil {
		return
	}

	for _, circuit := range circuits {
		m.processExpressRouteCircuit(ctx, subID, subName, rgName, circuit, logger)
	}
}

// ------------------------------
// Get ExpressRoute Circuits
// ------------------------------
func (m *ExpressRouteModule) getExpressRouteCircuits(ctx context.Context, subID, rgName string) ([]*armnetwork.ExpressRouteCircuit, error) {
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	erClient, err := armnetwork.NewExpressRouteCircuitsClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var circuits []*armnetwork.ExpressRouteCircuit
	pager := erClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		circuits = append(circuits, page.Value...)
	}

	return circuits, nil
}

// ------------------------------
// Process ExpressRoute Circuit
// ------------------------------
func (m *ExpressRouteModule) processExpressRouteCircuit(ctx context.Context, subID, subName, rgName string, circuit *armnetwork.ExpressRouteCircuit, logger internal.Logger) {
	if circuit == nil || circuit.Name == nil || circuit.Properties == nil {
		return
	}

	circuitName := *circuit.Name
	location := azinternal.SafeStringPtr(circuit.Location)

	// SKU details
	skuTier := "Unknown"
	skuFamily := "Unknown"
	if circuit.SKU != nil {
		if circuit.SKU.Tier != nil {
			skuTier = string(*circuit.SKU.Tier)
		}
		if circuit.SKU.Family != nil {
			skuFamily = string(*circuit.SKU.Family)
		}
	}

	// Service provider
	serviceProvider := "N/A"
	if circuit.Properties.ServiceProviderProperties != nil && circuit.Properties.ServiceProviderProperties.ServiceProviderName != nil {
		serviceProvider = *circuit.Properties.ServiceProviderProperties.ServiceProviderName
	}

	// Peering location
	peeringLocation := "N/A"
	if circuit.Properties.ServiceProviderProperties != nil && circuit.Properties.ServiceProviderProperties.PeeringLocation != nil {
		peeringLocation = *circuit.Properties.ServiceProviderProperties.PeeringLocation
	}

	// Bandwidth
	bandwidthMbps := "N/A"
	if circuit.Properties.ServiceProviderProperties != nil && circuit.Properties.ServiceProviderProperties.BandwidthInMbps != nil {
		bandwidthMbps = fmt.Sprintf("%d Mbps", *circuit.Properties.ServiceProviderProperties.BandwidthInMbps)
	}

	// Circuit provisioning state
	circuitProvisioningState := "Unknown"
	if circuit.Properties.CircuitProvisioningState != nil {
		circuitProvisioningState = *circuit.Properties.CircuitProvisioningState
	}

	// Service provider provisioning state
	providerProvisioningState := "Unknown"
	if circuit.Properties.ServiceProviderProvisioningState != nil {
		providerProvisioningState = string(*circuit.Properties.ServiceProviderProvisioningState)
	}

	// Global reach enabled
	globalReachEnabled := "No"
	if circuit.Properties.GlobalReachEnabled != nil && *circuit.Properties.GlobalReachEnabled {
		globalReachEnabled = "✓ Yes"
	}

	// Allow classic operations
	allowClassicOps := "No"
	if circuit.Properties.AllowClassicOperations != nil && *circuit.Properties.AllowClassicOperations {
		allowClassicOps = "✓ Yes"
	}

	// Service key (sensitive)
	serviceKey := "N/A"
	if circuit.Properties.ServiceKey != nil {
		serviceKey = "***REDACTED***"
	}
	_ = serviceKey // Use to avoid unused warning if not used elsewhere

	// Count peerings
	privatePeeringCount := 0
	microsoftPeeringCount := 0
	publicPeeringCount := 0

	if circuit.Properties.Peerings != nil {
		for _, peering := range circuit.Properties.Peerings {
			if peering != nil && peering.Properties != nil && peering.Properties.PeeringType != nil {
				switch *peering.Properties.PeeringType {
				case armnetwork.ExpressRoutePeeringTypeAzurePrivatePeering:
					privatePeeringCount++
					m.processPeering(subID, subName, rgName, location, circuitName, peering, "Private")
				case armnetwork.ExpressRoutePeeringTypeMicrosoftPeering:
					microsoftPeeringCount++
					m.processPeering(subID, subName, rgName, location, circuitName, peering, "Microsoft")
				case armnetwork.ExpressRoutePeeringTypeAzurePublicPeering:
					publicPeeringCount++
					m.processPeering(subID, subName, rgName, location, circuitName, peering, "Public")
				}
			}
		}
	}

	peeringSummary := fmt.Sprintf("Private:%d, Microsoft:%d, Public:%d", privatePeeringCount, microsoftPeeringCount, publicPeeringCount)

	// Main circuit row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		location,
		circuitName,
		skuTier,
		skuFamily,
		serviceProvider,
		peeringLocation,
		bandwidthMbps,
		circuitProvisioningState,
		providerProvisioningState,
		globalReachEnabled,
		allowClassicOps,
		peeringSummary,
	}

	m.mu.Lock()
	m.ExpressRouteRows = append(m.ExpressRouteRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Add to loot commands
	m.mu.Lock()
	m.LootMap["expressroute-commands"].Contents += fmt.Sprintf("# ExpressRoute Circuit: %s (Resource Group: %s)\n", circuitName, rgName)
	m.LootMap["expressroute-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["expressroute-commands"].Contents += fmt.Sprintf("az network express-route show --name %s --resource-group %s\n", circuitName, rgName)
	m.LootMap["expressroute-commands"].Contents += fmt.Sprintf("az network express-route peering list --circuit-name %s --resource-group %s\n", circuitName, rgName)
	m.LootMap["expressroute-commands"].Contents += fmt.Sprintf("# Service Provider: %s, Bandwidth: %s\n", serviceProvider, bandwidthMbps)
	m.LootMap["expressroute-commands"].Contents += "\n"
	m.mu.Unlock()
}

// ------------------------------
// Process Peering Configuration
// ------------------------------
func (m *ExpressRouteModule) processPeering(subID, subName, rgName, location, circuitName string, peering *armnetwork.ExpressRouteCircuitPeering, peeringTypeName string) {
	if peering == nil || peering.Name == nil || peering.Properties == nil {
		return
	}

	peeringName := *peering.Name

	// Peering state
	peeringState := "Unknown"
	if peering.Properties.State != nil {
		peeringState = string(*peering.Properties.State)
	}

	// VLAN ID
	vlanID := "N/A"
	if peering.Properties.VlanID != nil {
		vlanID = fmt.Sprintf("%d", *peering.Properties.VlanID)
	}

	// Peer ASN
	peerASN := "N/A"
	if peering.Properties.PeerASN != nil {
		peerASN = fmt.Sprintf("%d", *peering.Properties.PeerASN)
	}

	// Primary peer address prefix
	primaryPrefix := "N/A"
	if peering.Properties.PrimaryPeerAddressPrefix != nil {
		primaryPrefix = *peering.Properties.PrimaryPeerAddressPrefix
	}

	// Secondary peer address prefix
	secondaryPrefix := "N/A"
	if peering.Properties.SecondaryPeerAddressPrefix != nil {
		secondaryPrefix = *peering.Properties.SecondaryPeerAddressPrefix
	}

	// Microsoft peering config
	advertisedPublicPrefixes := "N/A"
	advertisedCommunities := "N/A"
	if peering.Properties.MicrosoftPeeringConfig != nil {
		if peering.Properties.MicrosoftPeeringConfig.AdvertisedPublicPrefixes != nil {
			prefixes := azinternal.SafeStringSlice(peering.Properties.MicrosoftPeeringConfig.AdvertisedPublicPrefixes)
			if len(prefixes) > 0 {
				advertisedPublicPrefixes = strings.Join(prefixes, ", ")
			}
		}
		if peering.Properties.MicrosoftPeeringConfig.AdvertisedCommunities != nil {
			communities := azinternal.SafeStringSlice(peering.Properties.MicrosoftPeeringConfig.AdvertisedCommunities)
			if len(communities) > 0 {
				advertisedCommunities = strings.Join(communities, ", ")
			}
		}
	}

	// Gateway Manager Etag (indicates gateway connection)
	gatewayConnected := "No"
	if peering.Properties.GatewayManagerEtag != nil && *peering.Properties.GatewayManagerEtag != "" {
		gatewayConnected = "✓ Yes"
	}

	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		location,
		circuitName,
		peeringName,
		peeringTypeName,
		peeringState,
		vlanID,
		peerASN,
		primaryPrefix,
		secondaryPrefix,
		advertisedPublicPrefixes,
		advertisedCommunities,
		gatewayConnected,
	}

	m.mu.Lock()
	m.PeeringRows = append(m.PeeringRows, row)
	m.mu.Unlock()

	// Add to peering loot file
	m.mu.Lock()
	m.LootMap["expressroute-peerings"].Contents += fmt.Sprintf("Circuit: %s/%s\n", rgName, circuitName)
	m.LootMap["expressroute-peerings"].Contents += fmt.Sprintf("  Peering: %s (%s)\n", peeringName, peeringTypeName)
	m.LootMap["expressroute-peerings"].Contents += fmt.Sprintf("  State: %s, VLAN: %s, Peer ASN: %s\n", peeringState, vlanID, peerASN)
	m.LootMap["expressroute-peerings"].Contents += fmt.Sprintf("  Primary: %s\n", primaryPrefix)
	m.LootMap["expressroute-peerings"].Contents += fmt.Sprintf("  Secondary: %s\n", secondaryPrefix)
	if advertisedPublicPrefixes != "N/A" {
		m.LootMap["expressroute-peerings"].Contents += fmt.Sprintf("  Advertised Prefixes: %s\n", advertisedPublicPrefixes)
	}
	m.LootMap["expressroute-peerings"].Contents += fmt.Sprintf("  Gateway Connected: %s\n\n", gatewayConnected)
	m.mu.Unlock()
}

// ------------------------------
// Write output
// ------------------------------
func (m *ExpressRouteModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.ExpressRouteRows) == 0 {
		logger.InfoM("No ExpressRoute circuits found", globals.AZ_EXPRESSROUTE_MODULE_NAME)
		return
	}

	// Main circuit headers
	circuitHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Location",
		"Circuit Name",
		"SKU Tier",
		"SKU Family",
		"Service Provider",
		"Peering Location",
		"Bandwidth",
		"Circuit Provisioning State",
		"Provider Provisioning State",
		"Global Reach Enabled",
		"Allow Classic Operations",
		"Peering Summary",
	}

	// Peering headers
	peeringHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Location",
		"Circuit Name",
		"Peering Name",
		"Peering Type",
		"Peering State",
		"VLAN ID",
		"Peer ASN",
		"Primary Peer Prefix",
		"Secondary Peer Prefix",
		"Advertised Public Prefixes",
		"Advertised Communities",
		"Gateway Connected",
	}

	// Build tables
	tables := []internal.TableFile{{
		Name:   "expressroute-circuits",
		Header: circuitHeaders,
		Body:   m.ExpressRouteRows,
	}}

	if len(m.PeeringRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "expressroute-peerings",
			Header: peeringHeaders,
			Body:   m.PeeringRows,
		})
	}

	// Check if we should split output by tenant
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.ExpressRouteRows,
			circuitHeaders,
			"expressroute-circuits",
			globals.AZ_EXPRESSROUTE_MODULE_NAME,
		); err != nil {
			return
		}

		if len(m.PeeringRows) > 0 {
			m.FilterAndWritePerTenantAuto(
				ctx,
				logger,
				m.Tenants,
				m.PeeringRows,
				peeringHeaders,
				"expressroute-peerings",
				globals.AZ_EXPRESSROUTE_MODULE_NAME,
			)
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.ExpressRouteRows, circuitHeaders,
			"expressroute-circuits", globals.AZ_EXPRESSROUTE_MODULE_NAME,
		); err != nil {
			return
		}

		if len(m.PeeringRows) > 0 {
			m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.PeeringRows, peeringHeaders,
				"expressroute-peerings", globals.AZ_EXPRESSROUTE_MODULE_NAME,
			)
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

	output := ExpressRouteOutput{
		Table: tables,
		Loot:  loot,
	}

	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_EXPRESSROUTE_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d ExpressRoute circuits with %d peering configurations across %d subscriptions",
		len(m.ExpressRouteRows), len(m.PeeringRows), len(m.Subscriptions)), globals.AZ_EXPRESSROUTE_MODULE_NAME)
}
