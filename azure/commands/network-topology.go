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
var AzNetworkTopologyCommand = &cobra.Command{
	Use:     "network-topology",
	Aliases: []string{"net-topo", "topology"},
	Short:   "Analyze Azure network topology and architecture patterns",
	Long: `
Analyze Azure network topology for a specific tenant:
./cloudfox az network-topology --tenant TENANT_ID

Analyze Azure network topology for a specific subscription:
./cloudfox az network-topology --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

TOPOLOGY ANALYSIS:
- Hub-spoke architecture detection and classification
- VNet connectivity mapping (peerings, gateways)
- Trust boundary identification
- Cross-subscription network connectivity
- Gateway transit configuration analysis
- Network segmentation scoring
- Isolated network detection`,
	Run: AnalyzeNetworkTopology,
}

// ------------------------------
// VNet topology information
// ------------------------------
type VNetTopology struct {
	SubscriptionID   string
	SubscriptionName string
	ResourceGroup    string
	VNetName         string
	VNetID           string
	AddressSpace     string
	SubnetCount      int
	PeeringCount     int
	Peerings         []PeeringInfo
	HasVPNGateway    bool
	HasERGateway     bool
	GatewayTransit   bool
	UseRemoteGateway bool
	Role             string // Hub, Spoke, Isolated, Mesh
	TrustZone        string // Production, Development, DMZ, Management, etc.
}

type PeeringInfo struct {
	PeeringName      string
	RemoteVNetID     string
	RemoteVNetName   string
	PeeringState     string
	AllowForwarding  bool
	GatewayTransit   bool
	UseRemoteGateway bool
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type NetworkTopologyModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	VNetMap       map[string]*VNetTopology // VNetID -> Topology
	HubRows       [][]string               // Hub VNets
	SpokeRows     [][]string               // Spoke VNets
	IsolatedRows  [][]string               // Isolated VNets
	TopologyRows  [][]string               // Overall topology summary
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type NetworkTopologyOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkTopologyOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkTopologyOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func AnalyzeNetworkTopology(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &NetworkTopologyModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		VNetMap:         make(map[string]*VNetTopology),
		HubRows:         [][]string{},
		SpokeRows:       [][]string{},
		IsolatedRows:    [][]string{},
		TopologyRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"hub-vnets":          {Name: "hub-vnets", Contents: "# Hub VNets (central connectivity points)\n\n"},
			"isolated-vnets":     {Name: "isolated-vnets", Contents: "# Isolated VNets (no peerings)\n\n"},
			"cross-sub-peerings": {Name: "cross-sub-peerings", Contents: "# Cross-subscription VNet peerings\n\n"},
			"gateway-transit":    {Name: "gateway-transit", Contents: "# Gateway transit configurations\n\n"},
			"topology-commands":  {Name: "topology-commands", Contents: "# Azure network topology analysis commands\n\n"},
		},
	}

	// -------------------- Execute module --------------------
	module.AnalyzeTopology(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *NetworkTopologyModule) AnalyzeTopology(ctx context.Context, logger internal.Logger) {
	// Step 1: Enumerate all VNets and build topology map
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME, m.processSubscription)
	}

	// Step 2: Analyze topology patterns
	m.analyzeTopologyPatterns()

	// Step 3: Generate output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *NetworkTopologyModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *NetworkTopologyModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get token and create network client
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subID, cred, nil)
	if err != nil {
		return
	}

	// Enumerate VNets
	pager := vnetClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, vnet := range page.Value {
			if vnet == nil || vnet.Name == nil || vnet.ID == nil {
				continue
			}

			m.processVNet(ctx, subID, subName, rgName, vnet)
		}
	}
}

// ------------------------------
// Process single VNet
// ------------------------------
func (m *NetworkTopologyModule) processVNet(ctx context.Context, subID, subName, rgName string, vnet *armnetwork.VirtualNetwork) {
	vnetName := azinternal.SafeStringPtr(vnet.Name)
	vnetID := azinternal.SafeStringPtr(vnet.ID)

	// Extract address space
	addressSpace := "N/A"
	if vnet.Properties != nil && vnet.Properties.AddressSpace != nil && vnet.Properties.AddressSpace.AddressPrefixes != nil {
		prefixes := []string{}
		for _, prefix := range vnet.Properties.AddressSpace.AddressPrefixes {
			if prefix != nil {
				prefixes = append(prefixes, *prefix)
			}
		}
		if len(prefixes) > 0 {
			addressSpace = strings.Join(prefixes, ", ")
		}
	}

	// Count subnets
	subnetCount := 0
	if vnet.Properties != nil && vnet.Properties.Subnets != nil {
		subnetCount = len(vnet.Properties.Subnets)
	}

	// Process peerings
	peerings := []PeeringInfo{}
	peeringCount := 0
	gatewayTransit := false
	useRemoteGateway := false

	if vnet.Properties != nil && vnet.Properties.VirtualNetworkPeerings != nil {
		peeringCount = len(vnet.Properties.VirtualNetworkPeerings)
		for _, peering := range vnet.Properties.VirtualNetworkPeerings {
			if peering == nil || peering.Name == nil {
				continue
			}

			peeringName := *peering.Name
			remoteVNetID := "N/A"
			remoteVNetName := "N/A"
			peeringState := "N/A"
			allowForwarding := false
			peerGatewayTransit := false
			peerUseRemoteGateway := false

			if peering.Properties != nil {
				if peering.Properties.RemoteVirtualNetwork != nil && peering.Properties.RemoteVirtualNetwork.ID != nil {
					remoteVNetID = *peering.Properties.RemoteVirtualNetwork.ID
					// Extract VNet name from ID
					parts := strings.Split(remoteVNetID, "/")
					if len(parts) > 0 {
						remoteVNetName = parts[len(parts)-1]
					}
				}
				if peering.Properties.PeeringState != nil {
					peeringState = string(*peering.Properties.PeeringState)
				}
				if peering.Properties.AllowForwardedTraffic != nil && *peering.Properties.AllowForwardedTraffic {
					allowForwarding = true
				}
				if peering.Properties.AllowGatewayTransit != nil && *peering.Properties.AllowGatewayTransit {
					peerGatewayTransit = true
					gatewayTransit = true
				}
				if peering.Properties.UseRemoteGateways != nil && *peering.Properties.UseRemoteGateways {
					peerUseRemoteGateway = true
					useRemoteGateway = true
				}
			}

			peerings = append(peerings, PeeringInfo{
				PeeringName:      peeringName,
				RemoteVNetID:     remoteVNetID,
				RemoteVNetName:   remoteVNetName,
				PeeringState:     peeringState,
				AllowForwarding:  allowForwarding,
				GatewayTransit:   peerGatewayTransit,
				UseRemoteGateway: peerUseRemoteGateway,
			})
		}
	}

	// Check for gateways (simplified - would need to query gateway subnets)
	hasVPNGateway := false
	hasERGateway := false
	// Note: This would require additional API calls to check for VPN/ER gateways

	// Create topology entry
	topology := &VNetTopology{
		SubscriptionID:   subID,
		SubscriptionName: subName,
		ResourceGroup:    rgName,
		VNetName:         vnetName,
		VNetID:           vnetID,
		AddressSpace:     addressSpace,
		SubnetCount:      subnetCount,
		PeeringCount:     peeringCount,
		Peerings:         peerings,
		HasVPNGateway:    hasVPNGateway,
		HasERGateway:     hasERGateway,
		GatewayTransit:   gatewayTransit,
		UseRemoteGateway: useRemoteGateway,
		Role:             "Unknown", // Will be determined in analysis phase
		TrustZone:        "Unknown",
	}

	// Thread-safe add to map
	m.mu.Lock()
	m.VNetMap[vnetID] = topology
	m.mu.Unlock()
}

// ------------------------------
// Analyze topology patterns
// ------------------------------
func (m *NetworkTopologyModule) analyzeTopologyPatterns() {
	// Hub detection: VNets with 3+ peerings
	// Spoke detection: VNets with 1-2 peerings using remote gateways
	// Isolated: VNets with 0 peerings

	for _, topology := range m.VNetMap {
		// Classify role based on peering patterns
		if topology.PeeringCount == 0 {
			topology.Role = "Isolated"
		} else if topology.PeeringCount >= 3 {
			topology.Role = "Hub"
		} else if topology.UseRemoteGateway {
			topology.Role = "Spoke"
		} else if topology.GatewayTransit {
			topology.Role = "Hub"
		} else if topology.PeeringCount == 2 {
			topology.Role = "Mesh"
		} else {
			topology.Role = "Spoke"
		}

		// Infer trust zone from naming conventions
		vnetNameLower := strings.ToLower(topology.VNetName)
		if strings.Contains(vnetNameLower, "prod") {
			topology.TrustZone = "Production"
		} else if strings.Contains(vnetNameLower, "dev") || strings.Contains(vnetNameLower, "test") {
			topology.TrustZone = "Development"
		} else if strings.Contains(vnetNameLower, "dmz") || strings.Contains(vnetNameLower, "perimeter") {
			topology.TrustZone = "DMZ"
		} else if strings.Contains(vnetNameLower, "mgmt") || strings.Contains(vnetNameLower, "management") {
			topology.TrustZone = "Management"
		} else {
			topology.TrustZone = "Unknown"
		}

		// Determine risk level
		risk := "INFO"
		riskReasons := []string{}

		if topology.Role == "Isolated" {
			risk = "MEDIUM"
			riskReasons = append(riskReasons, "Isolated VNet (no connectivity)")
		}
		if topology.Role == "Hub" && topology.PeeringCount > 10 {
			risk = "MEDIUM"
			riskReasons = append(riskReasons, fmt.Sprintf("Large hub (%d peerings)", topology.PeeringCount))
		}

		// Check for cross-subscription peerings
		crossSubPeerings := 0
		for _, peering := range topology.Peerings {
			if !strings.Contains(peering.RemoteVNetID, topology.SubscriptionID) && peering.RemoteVNetID != "N/A" {
				crossSubPeerings++
			}
		}
		if crossSubPeerings > 0 {
			riskReasons = append(riskReasons, fmt.Sprintf("%d cross-subscription peering(s)", crossSubPeerings))
		}

		riskNote := strings.Join(riskReasons, "; ")
		if riskNote == "" {
			riskNote = "Normal topology"
		}

		// Add to appropriate rows
		m.mu.Lock()

		switch topology.Role {
		case "Hub":
			m.HubRows = append(m.HubRows, []string{
				m.TenantName,
				m.TenantID,
				topology.SubscriptionID,
				topology.SubscriptionName,
				topology.ResourceGroup,
				topology.VNetName,
				topology.AddressSpace,
				fmt.Sprintf("%d", topology.PeeringCount),
				fmt.Sprintf("%d", topology.SubnetCount),
				fmt.Sprintf("%t", topology.GatewayTransit),
				fmt.Sprintf("%t", topology.HasVPNGateway),
				fmt.Sprintf("%t", topology.HasERGateway),
				topology.TrustZone,
				risk,
				riskNote,
			})

			// Add to loot
			m.LootMap["hub-vnets"].Contents += fmt.Sprintf("Hub VNet: %s (Subscription: %s, RG: %s)\n", topology.VNetName, topology.SubscriptionName, topology.ResourceGroup)
			m.LootMap["hub-vnets"].Contents += fmt.Sprintf("  Address Space: %s\n", topology.AddressSpace)
			m.LootMap["hub-vnets"].Contents += fmt.Sprintf("  Peerings: %d\n", topology.PeeringCount)
			m.LootMap["hub-vnets"].Contents += fmt.Sprintf("  Gateway Transit: %t\n", topology.GatewayTransit)
			m.LootMap["hub-vnets"].Contents += fmt.Sprintf("  Connected Spokes:\n")
			for _, peering := range topology.Peerings {
				m.LootMap["hub-vnets"].Contents += fmt.Sprintf("    - %s (State: %s)\n", peering.RemoteVNetName, peering.PeeringState)
			}
			m.LootMap["hub-vnets"].Contents += "\n"

		case "Spoke":
			m.SpokeRows = append(m.SpokeRows, []string{
				m.TenantName,
				m.TenantID,
				topology.SubscriptionID,
				topology.SubscriptionName,
				topology.ResourceGroup,
				topology.VNetName,
				topology.AddressSpace,
				fmt.Sprintf("%d", topology.PeeringCount),
				fmt.Sprintf("%d", topology.SubnetCount),
				fmt.Sprintf("%t", topology.UseRemoteGateway),
				topology.TrustZone,
				risk,
				riskNote,
			})

		case "Isolated":
			m.IsolatedRows = append(m.IsolatedRows, []string{
				m.TenantName,
				m.TenantID,
				topology.SubscriptionID,
				topology.SubscriptionName,
				topology.ResourceGroup,
				topology.VNetName,
				topology.AddressSpace,
				fmt.Sprintf("%d", topology.SubnetCount),
				topology.TrustZone,
				risk,
				riskNote,
			})

			// Add to loot
			m.LootMap["isolated-vnets"].Contents += fmt.Sprintf("Isolated VNet: %s (Subscription: %s, RG: %s)\n", topology.VNetName, topology.SubscriptionName, topology.ResourceGroup)
			m.LootMap["isolated-vnets"].Contents += fmt.Sprintf("  Address Space: %s\n", topology.AddressSpace)
			m.LootMap["isolated-vnets"].Contents += fmt.Sprintf("  Subnets: %d\n", topology.SubnetCount)
			m.LootMap["isolated-vnets"].Contents += fmt.Sprintf("  Risk: No connectivity to other VNets\n\n")
		}

		// Check for cross-subscription peerings and gateway transit
		for _, peering := range topology.Peerings {
			if !strings.Contains(peering.RemoteVNetID, topology.SubscriptionID) && peering.RemoteVNetID != "N/A" {
				m.LootMap["cross-sub-peerings"].Contents += fmt.Sprintf("Cross-Subscription Peering: %s -> %s\n", topology.VNetName, peering.RemoteVNetName)
				m.LootMap["cross-sub-peerings"].Contents += fmt.Sprintf("  Source: %s (Sub: %s)\n", topology.VNetName, topology.SubscriptionName)
				m.LootMap["cross-sub-peerings"].Contents += fmt.Sprintf("  Remote VNet ID: %s\n", peering.RemoteVNetID)
				m.LootMap["cross-sub-peerings"].Contents += fmt.Sprintf("  State: %s\n", peering.PeeringState)
				m.LootMap["cross-sub-peerings"].Contents += fmt.Sprintf("  Allow Forwarding: %t\n\n", peering.AllowForwarding)
			}

			if peering.GatewayTransit || peering.UseRemoteGateway {
				m.LootMap["gateway-transit"].Contents += fmt.Sprintf("Gateway Transit Configuration: %s\n", topology.VNetName)
				m.LootMap["gateway-transit"].Contents += fmt.Sprintf("  Peering: %s -> %s\n", topology.VNetName, peering.RemoteVNetName)
				m.LootMap["gateway-transit"].Contents += fmt.Sprintf("  Gateway Transit Enabled: %t\n", peering.GatewayTransit)
				m.LootMap["gateway-transit"].Contents += fmt.Sprintf("  Use Remote Gateway: %t\n\n", peering.UseRemoteGateway)
			}
		}

		m.mu.Unlock()
	}

	// Generate topology summary
	m.generateTopologySummary()
}

// ------------------------------
// Generate topology summary
// ------------------------------
func (m *NetworkTopologyModule) generateTopologySummary() {
	hubCount := len(m.HubRows)
	spokeCount := len(m.SpokeRows)
	isolatedCount := len(m.IsolatedRows)
	totalVNets := len(m.VNetMap)

	// Calculate architecture pattern
	architecturePattern := "Unknown"
	if hubCount > 0 && spokeCount > 0 {
		architecturePattern = "Hub-Spoke"
	} else if hubCount == 0 && spokeCount == 0 && isolatedCount == totalVNets {
		architecturePattern = "Isolated VNets"
	} else if hubCount == 0 && spokeCount > 0 {
		architecturePattern = "Mesh"
	}

	// Calculate segmentation score (0-100)
	segmentationScore := 0
	if totalVNets > 0 {
		// Higher score = better segmentation
		// Factors: number of VNets, hub-spoke ratio, isolated networks
		segmentationScore = (isolatedCount * 10) + (hubCount * 20) + (spokeCount * 15)
		if segmentationScore > 100 {
			segmentationScore = 100
		}
	}

	m.TopologyRows = append(m.TopologyRows, []string{
		m.TenantName,
		m.TenantID,
		fmt.Sprintf("%d", totalVNets),
		fmt.Sprintf("%d", hubCount),
		fmt.Sprintf("%d", spokeCount),
		fmt.Sprintf("%d", isolatedCount),
		architecturePattern,
		fmt.Sprintf("%d/100", segmentationScore),
		"See detailed tables below",
	})
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *NetworkTopologyModule) writeOutput(ctx context.Context, logger internal.Logger) {
	totalVNets := len(m.VNetMap)
	if totalVNets == 0 {
		logger.InfoM("No VNets found for topology analysis", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
		return
	}

	// -------------------- TABLE 1: Topology Summary --------------------
	if len(m.TopologyRows) > 0 {
		summaryHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Total VNets",
			"Hub VNets",
			"Spoke VNets",
			"Isolated VNets",
			"Architecture Pattern",
			"Segmentation Score",
			"Notes",
		}
		_ = summaryHeaders // Avoid unused warning

		// TODO: Implement WriteFullOutput
		logger.InfoM("Topology summary enumeration complete", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
	}

	// -------------------- TABLE 2: Hub VNets --------------------
	if len(m.HubRows) > 0 {
		hubHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"VNet Name",
			"Address Space",
			"Peering Count",
			"Subnet Count",
			"Gateway Transit",
			"Has VPN Gateway",
			"Has ER Gateway",
			"Trust Zone",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.HubRows, hubHeaders,
				"topology-hubs", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant hub VNets", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.HubRows, hubHeaders,
				"topology-hubs", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription hub VNets", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
			}
		} else {
			// TODO: Implement WriteFullOutput
			logger.InfoM("Hub VNets enumeration complete", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
		}
	}

	// -------------------- TABLE 3: Spoke VNets --------------------
	if len(m.SpokeRows) > 0 {
		spokeHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"VNet Name",
			"Address Space",
			"Peering Count",
			"Subnet Count",
			"Use Remote Gateway",
			"Trust Zone",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.SpokeRows, spokeHeaders,
				"topology-spokes", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant spoke VNets", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.SpokeRows, spokeHeaders,
				"topology-spokes", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription spoke VNets", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
			}
		} else {
			// TODO: Implement WriteFullOutput
			logger.InfoM("Spoke VNets enumeration complete", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
		}
	}

	// -------------------- TABLE 4: Isolated VNets --------------------
	if len(m.IsolatedRows) > 0 {
		isolatedHeaders := []string{
			"Tenant Name",
			"Tenant ID",
			"Subscription ID",
			"Subscription Name",
			"Resource Group",
			"VNet Name",
			"Address Space",
			"Subnet Count",
			"Trust Zone",
			"Risk",
			"Risk Note",
		}

		if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.IsolatedRows, isolatedHeaders,
				"topology-isolated", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant isolated VNets", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
			}
		} else if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.IsolatedRows, isolatedHeaders,
				"topology-isolated", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-subscription isolated VNets", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
			}
		} else {
			// TODO: Implement WriteFullOutput
			logger.InfoM("Isolated VNets enumeration complete", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
		}
	}

	// -------------------- LOOT FILES --------------------
	// TODO: Implement WriteLoot
	logger.InfoM("Network topology enumeration complete", globals.AZ_NETWORK_TOPOLOGY_MODULE_NAME)
}
