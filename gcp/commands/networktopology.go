package commands

import (
	"github.com/BishopFox/cloudfox/gcp/shared"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/compute/v1"
)

// Module name constant
const GCP_NETWORKTOPOLOGY_MODULE_NAME string = "network-topology"

var GCPNetworkTopologyCommand = &cobra.Command{
	Use:     GCP_NETWORKTOPOLOGY_MODULE_NAME,
	Aliases: []string{"topology", "network-map", "vpc-topology"},
	Short:   "Visualize VPC network topology, peering relationships, and trust boundaries",
	Long: `Analyze and visualize VPC network topology, peering relationships, and trust boundaries.

Features:
- Maps all VPC networks and their subnets
- Identifies VPC peering relationships
- Detects Shared VPC configurations
- Analyzes VPC Service Controls perimeters
- Maps Cloud NAT and Private Google Access
- Identifies potential trust boundary issues
- Detects cross-project network access paths

Requires appropriate IAM permissions:
- roles/compute.networkViewer
- roles/compute.viewer`,
	Run: runGCPNetworkTopologyCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type VPCNetwork struct {
	Name               string
	ProjectID          string
	SelfLink           string
	Description        string
	RoutingMode        string
	AutoCreateSubnets  bool
	SubnetCount        int
	PeeringCount       int
	IsSharedVPC        bool
	SharedVPCRole      string // "host" or "service"
	SharedVPCHost      string
	MTU                int64
	CreationTimestamp  string
	FirewallRuleCount  int
	PrivateGoogleAcces bool
}

type Subnet struct {
	Name                  string
	ProjectID             string
	Network               string
	Region                string
	IPCIDRRange           string
	SecondaryRanges       []string
	PrivateIPGoogleAccess bool
	FlowLogsEnabled       bool
	Purpose               string
	Role                  string
	StackType             string
	IAMBindings           []SubnetIAMBinding
}

type SubnetIAMBinding struct {
	Role   string
	Member string
}

type VPCPeering struct {
	Name              string
	Network           string
	PeerNetwork       string
	State             string
	StateDetails      string
	ExportCustomRoute bool
	ImportCustomRoute bool
	ExportSubnetRoute bool
	ImportSubnetRoute bool
	ProjectID         string
	PeerProjectID     string
	AutoCreateRoutes  bool
}

type SharedVPCConfig struct {
	HostProject     string
	ServiceProjects []string
	SharedSubnets   []string
	SharedNetworks  []string
}

type CloudNATConfig struct {
	Name                 string
	ProjectID            string
	Region               string
	Network              string
	Subnets              []string
	NATIPAddresses       []string
	MinPortsPerVM        int64
	SourceSubnetworkType string
	EnableLogging        bool
}


type NetworkRoute struct {
	Name        string
	ProjectID   string
	Network     string
	DestRange   string
	NextHop     string
	NextHopType string
	Priority    int64
	Tags        []string
}

// ------------------------------
// Module Struct
// ------------------------------
type NetworkTopologyModule struct {
	gcpinternal.BaseGCPModule

	ProjectNetworks map[string][]VPCNetwork                  // projectID -> networks
	ProjectSubnets  map[string][]Subnet                      // projectID -> subnets
	ProjectPeerings map[string][]VPCPeering                  // projectID -> peerings
	ProjectNATs     map[string][]CloudNATConfig              // projectID -> NATs
	ProjectRoutes   map[string][]NetworkRoute                // projectID -> routes
	SharedVPCs      map[string]*SharedVPCConfig              // hostProjectID -> config
	LootMap         map[string]map[string]*internal.LootFile // projectID -> loot files
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type NetworkTopologyOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkTopologyOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkTopologyOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPNetworkTopologyCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_NETWORKTOPOLOGY_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &NetworkTopologyModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectNetworks: make(map[string][]VPCNetwork),
		ProjectSubnets:  make(map[string][]Subnet),
		ProjectPeerings: make(map[string][]VPCPeering),
		ProjectNATs:     make(map[string][]CloudNATConfig),
		ProjectRoutes:   make(map[string][]NetworkRoute),
		SharedVPCs:      make(map[string]*SharedVPCConfig),
		LootMap:         make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *NetworkTopologyModule) Execute(ctx context.Context, logger internal.Logger) {
	// Create Compute client
	computeService, err := compute.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Compute service: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		return
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, computeService, logger)
		}(projectID)
	}
	wg.Wait()

	// Check results
	allNetworks := m.getAllNetworks()
	if len(allNetworks) == 0 {
		logger.InfoM("No VPC networks found", GCP_NETWORKTOPOLOGY_MODULE_NAME)
		return
	}

	allSubnets := m.getAllSubnets()
	allPeerings := m.getAllPeerings()
	allNATs := m.getAllNATs()

	logger.SuccessM(fmt.Sprintf("Found %d VPC network(s), %d subnet(s), %d peering(s), %d Cloud NAT(s)",
		len(allNetworks), len(allSubnets), len(allPeerings), len(allNATs)), GCP_NETWORKTOPOLOGY_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *NetworkTopologyModule) getAllNetworks() []VPCNetwork {
	var all []VPCNetwork
	for _, networks := range m.ProjectNetworks {
		all = append(all, networks...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllSubnets() []Subnet {
	var all []Subnet
	for _, subnets := range m.ProjectSubnets {
		all = append(all, subnets...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllPeerings() []VPCPeering {
	var all []VPCPeering
	for _, peerings := range m.ProjectPeerings {
		all = append(all, peerings...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllNATs() []CloudNATConfig {
	var all []CloudNATConfig
	for _, nats := range m.ProjectNATs {
		all = append(all, nats...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllRoutes() []NetworkRoute {
	var all []NetworkRoute
	for _, routes := range m.ProjectRoutes {
		all = append(all, routes...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *NetworkTopologyModule) processProject(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating networks for project: %s", projectID), GCP_NETWORKTOPOLOGY_MODULE_NAME)
	}

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["network-topology-commands"] = &internal.LootFile{
			Name:     "network-topology-commands",
			Contents: "# Network Topology Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n# See also: vpcnetworks-commands for quick enumeration and cross-project peering\n\n",
		}
	}
	m.mu.Unlock()

	// List networks
	m.enumerateNetworks(ctx, projectID, computeService, logger)

	// List subnets
	m.enumerateSubnets(ctx, projectID, computeService, logger)

	// List routes
	m.enumerateRoutes(ctx, projectID, computeService, logger)

	// List Cloud NAT
	m.enumerateCloudNAT(ctx, projectID, computeService, logger)
}

func (m *NetworkTopologyModule) enumerateNetworks(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Networks.List(projectID)
	err := req.Pages(ctx, func(page *compute.NetworkList) error {
		for _, network := range page.Items {
			vpc := VPCNetwork{
				Name:              network.Name,
				ProjectID:         projectID,
				SelfLink:          network.SelfLink,
				Description:       network.Description,
				RoutingMode: func() string {
				if network.RoutingConfig != nil {
					return network.RoutingConfig.RoutingMode
				}
				return ""
			}(),
				AutoCreateSubnets: network.AutoCreateSubnetworks,
				MTU:               network.Mtu,
				CreationTimestamp: network.CreationTimestamp,
				SubnetCount:       len(network.Subnetworks),
			}

			// Check for peerings
			for _, peering := range network.Peerings {
				vpc.PeeringCount++

				peeringRecord := VPCPeering{
					Name:              peering.Name,
					Network:           network.SelfLink,
					PeerNetwork:       peering.Network,
					State:             peering.State,
					StateDetails:      peering.StateDetails,
					ExportCustomRoute: peering.ExportCustomRoutes,
					ImportCustomRoute: peering.ImportCustomRoutes,
					ExportSubnetRoute: peering.ExportSubnetRoutesWithPublicIp,
					ImportSubnetRoute: peering.ImportSubnetRoutesWithPublicIp,
					ProjectID:         projectID,
					AutoCreateRoutes:  peering.AutoCreateRoutes,
				}

				// Extract peer project ID from peer network URL
				peeringRecord.PeerProjectID = m.extractProjectFromURL(peering.Network)

				m.mu.Lock()
				m.ProjectPeerings[projectID] = append(m.ProjectPeerings[projectID], peeringRecord)
				m.mu.Unlock()
			}

			m.mu.Lock()
			m.ProjectNetworks[projectID] = append(m.ProjectNetworks[projectID], vpc)
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list networks in project %s", projectID))
	}

	// Check for Shared VPC host project
	m.checkSharedVPCHost(ctx, projectID, computeService, logger)
}

func (m *NetworkTopologyModule) enumerateSubnets(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Subnetworks.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for region, subnetList := range page.Items {
			if subnetList.Subnetworks == nil {
				continue
			}
			regionName := m.extractRegionFromURL(region)
			for _, subnet := range subnetList.Subnetworks {
				subnetRecord := Subnet{
					Name:                  subnet.Name,
					ProjectID:             projectID,
					Network:               subnet.Network,
					Region:                regionName,
					IPCIDRRange:           subnet.IpCidrRange,
					PrivateIPGoogleAccess: subnet.PrivateIpGoogleAccess,
					Purpose:               subnet.Purpose,
					Role:                  subnet.Role,
					StackType:             subnet.StackType,
				}

				// Check for flow logs
				if subnet.LogConfig != nil {
					subnetRecord.FlowLogsEnabled = subnet.LogConfig.Enable
				}

				// Secondary ranges
				for _, sr := range subnet.SecondaryIpRanges {
					subnetRecord.SecondaryRanges = append(subnetRecord.SecondaryRanges,
						fmt.Sprintf("%s:%s", sr.RangeName, sr.IpCidrRange))
				}

				// Get IAM bindings for the subnet
				subnetRecord.IAMBindings = m.getSubnetIAMBindings(ctx, computeService, projectID, regionName, subnet.Name)

				m.mu.Lock()
				m.ProjectSubnets[projectID] = append(m.ProjectSubnets[projectID], subnetRecord)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list subnets in project %s", projectID))
	}
}

// getSubnetIAMBindings retrieves IAM bindings for a subnet
func (m *NetworkTopologyModule) getSubnetIAMBindings(ctx context.Context, computeService *compute.Service, projectID, region, subnetName string) []SubnetIAMBinding {
	policy, err := computeService.Subnetworks.GetIamPolicy(projectID, region, subnetName).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var bindings []SubnetIAMBinding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, SubnetIAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}
	return bindings
}

func (m *NetworkTopologyModule) enumerateRoutes(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Routes.List(projectID)
	err := req.Pages(ctx, func(page *compute.RouteList) error {
		for _, route := range page.Items {
			routeRecord := NetworkRoute{
				Name:      route.Name,
				ProjectID: projectID,
				Network:   route.Network,
				DestRange: route.DestRange,
				Priority:  route.Priority,
				Tags:      route.Tags,
			}

			// Determine next hop type
			switch {
			case route.NextHopGateway != "":
				routeRecord.NextHopType = "gateway"
				routeRecord.NextHop = route.NextHopGateway
			case route.NextHopInstance != "":
				routeRecord.NextHopType = "instance"
				routeRecord.NextHop = route.NextHopInstance
			case route.NextHopIp != "":
				routeRecord.NextHopType = "ip"
				routeRecord.NextHop = route.NextHopIp
			case route.NextHopNetwork != "":
				routeRecord.NextHopType = "network"
				routeRecord.NextHop = route.NextHopNetwork
			case route.NextHopPeering != "":
				routeRecord.NextHopType = "peering"
				routeRecord.NextHop = route.NextHopPeering
			case route.NextHopIlb != "":
				routeRecord.NextHopType = "ilb"
				routeRecord.NextHop = route.NextHopIlb
			case route.NextHopVpnTunnel != "":
				routeRecord.NextHopType = "vpn"
				routeRecord.NextHop = route.NextHopVpnTunnel
			}

			m.mu.Lock()
			m.ProjectRoutes[projectID] = append(m.ProjectRoutes[projectID], routeRecord)
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list routes in project %s", projectID))
	}
}

func (m *NetworkTopologyModule) enumerateCloudNAT(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	// List routers to find NAT configurations
	req := computeService.Routers.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.RouterAggregatedList) error {
		for region, routerList := range page.Items {
			if routerList.Routers == nil {
				continue
			}
			for _, router := range routerList.Routers {
				for _, nat := range router.Nats {
					natRecord := CloudNATConfig{
						Name:                 nat.Name,
						ProjectID:            projectID,
						Region:               m.extractRegionFromURL(region),
						Network:              router.Network,
						MinPortsPerVM:        nat.MinPortsPerVm,
						SourceSubnetworkType: nat.SourceSubnetworkIpRangesToNat,
					}

					// NAT IP addresses
					for _, natIP := range nat.NatIps {
						natRecord.NATIPAddresses = append(natRecord.NATIPAddresses, natIP)
					}

					// Subnets using this NAT
					for _, subnet := range nat.Subnetworks {
						natRecord.Subnets = append(natRecord.Subnets, subnet.Name)
					}

					// Logging
					if nat.LogConfig != nil {
						natRecord.EnableLogging = nat.LogConfig.Enable
					}

					m.mu.Lock()
					m.ProjectNATs[projectID] = append(m.ProjectNATs[projectID], natRecord)
					m.mu.Unlock()
				}
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud NAT in project %s", projectID))
	}
}

func (m *NetworkTopologyModule) checkSharedVPCHost(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	// Check if project is a Shared VPC host
	project, err := computeService.Projects.Get(projectID).Do()
	if err != nil {
		return
	}

	if project.XpnProjectStatus == "HOST" {
		m.mu.Lock()
		m.SharedVPCs[projectID] = &SharedVPCConfig{
			HostProject:     projectID,
			ServiceProjects: []string{},
			SharedSubnets:   []string{},
			SharedNetworks:  []string{},
		}
		m.mu.Unlock()

		// List service projects
		xpnReq := computeService.Projects.GetXpnResources(projectID)
		err := xpnReq.Pages(ctx, func(page *compute.ProjectsGetXpnResources) error {
			for _, resource := range page.Resources {
				if resource.Type == "PROJECT" {
					m.mu.Lock()
					m.SharedVPCs[projectID].ServiceProjects = append(
						m.SharedVPCs[projectID].ServiceProjects, resource.Id)
					m.mu.Unlock()
				}
			}
			return nil
		})
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
				fmt.Sprintf("Could not list XPN resources in project %s", projectID))
		}

		// Mark host networks
		m.mu.Lock()
		if networks, ok := m.ProjectNetworks[projectID]; ok {
			for i := range networks {
				networks[i].IsSharedVPC = true
				networks[i].SharedVPCRole = "host"
			}
			m.ProjectNetworks[projectID] = networks
		}
		m.mu.Unlock()
	}
}


// ------------------------------
// Helper Functions
// ------------------------------
func (m *NetworkTopologyModule) extractProjectFromURL(url string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}
	if strings.Contains(url, "projects/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *NetworkTopologyModule) extractNetworkName(url string) string {
	// Extract network name from full URL
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func (m *NetworkTopologyModule) extractRegionFromURL(url string) string {
	// Extract region from URL like regions/us-central1
	if strings.Contains(url, "regions/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "regions" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return url
}

// ------------------------------
// ASCII Network Diagram Generator
// ------------------------------

// generateASCIIDiagram creates an ASCII visualization of the network topology
func (m *NetworkTopologyModule) generateASCIIDiagram() string {
	var sb strings.Builder

	// Header
	sb.WriteString(m.drawBox("GCP NETWORK TOPOLOGY MAP - Generated by CloudFox", 90))
	sb.WriteString("\n")

	// Get all data
	allNetworks := m.getAllNetworks()
	allPeerings := m.getAllPeerings()

	// Group networks by project
	networksByProject := make(map[string][]VPCNetwork)
	for _, n := range allNetworks {
		networksByProject[n.ProjectID] = append(networksByProject[n.ProjectID], n)
	}

	// Group subnets by project and network
	subnetsByNetwork := make(map[string][]Subnet) // key: "projectID/networkName"
	for _, subnets := range m.ProjectSubnets {
		for _, s := range subnets {
			networkName := m.extractNetworkName(s.Network)
			key := s.ProjectID + "/" + networkName
			subnetsByNetwork[key] = append(subnetsByNetwork[key], s)
		}
	}

	// Group NATs by project and network
	natsByNetwork := make(map[string][]CloudNATConfig) // key: "projectID/networkName"
	for _, nats := range m.ProjectNATs {
		for _, nat := range nats {
			networkName := m.extractNetworkName(nat.Network)
			key := nat.ProjectID + "/" + networkName
			natsByNetwork[key] = append(natsByNetwork[key], nat)
		}
	}

	// Build peering map for quick lookup
	peeringMap := make(map[string][]VPCPeering) // key: "projectID/networkName"
	for _, p := range allPeerings {
		networkName := m.extractNetworkName(p.Network)
		key := p.ProjectID + "/" + networkName
		peeringMap[key] = append(peeringMap[key], p)
	}

	// Sort projects for consistent output
	var projectIDs []string
	for projectID := range networksByProject {
		projectIDs = append(projectIDs, projectID)
	}
	sort.Strings(projectIDs)

	// Draw each project
	for _, projectID := range projectIDs {
		networks := networksByProject[projectID]
		sb.WriteString(m.drawProjectSection(projectID, networks, subnetsByNetwork, natsByNetwork, peeringMap))
		sb.WriteString("\n")
	}

	// Draw Shared VPC relationships if any
	if len(m.SharedVPCs) > 0 {
		sb.WriteString(m.drawSharedVPCSection())
		sb.WriteString("\n")
	}

	// Draw VPC Peering summary
	if len(allPeerings) > 0 {
		sb.WriteString(m.drawPeeringSummary(allPeerings))
		sb.WriteString("\n")
	}

	// Legend
	sb.WriteString(m.drawLegend())

	return sb.String()
}

// drawBox draws a simple box with centered title
func (m *NetworkTopologyModule) drawBox(title string, width int) string {
	var sb strings.Builder

	// Top border
	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")

	// Title line (centered)
	padding := (width - 4 - len(title)) / 2
	if padding < 0 {
		padding = 0
	}
	sb.WriteString("│ ")
	sb.WriteString(strings.Repeat(" ", padding))
	sb.WriteString(title)
	sb.WriteString(strings.Repeat(" ", width-4-padding-len(title)))
	sb.WriteString(" │\n")

	// Bottom border
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// drawProjectSection draws the network topology for a single project
func (m *NetworkTopologyModule) drawProjectSection(projectID string, networks []VPCNetwork,
	subnetsByNetwork map[string][]Subnet, natsByNetwork map[string][]CloudNATConfig,
	peeringMap map[string][]VPCPeering) string {

	var sb strings.Builder
	width := 90

	projectName := m.GetProjectName(projectID)
	projectTitle := fmt.Sprintf("PROJECT: %s", projectID)
	if projectName != "" && projectName != projectID {
		projectTitle = fmt.Sprintf("PROJECT: %s (%s)", projectID, projectName)
	}

	// Project header
	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, projectTitle))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	// Sort networks
	sort.Slice(networks, func(i, j int) bool {
		return networks[i].Name < networks[j].Name
	})

	// Draw each VPC network
	for _, network := range networks {
		sb.WriteString(m.drawVPCNetwork(network, subnetsByNetwork, natsByNetwork, peeringMap, width))
	}

	// Project footer
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// drawVPCNetwork draws a single VPC network with its subnets
func (m *NetworkTopologyModule) drawVPCNetwork(network VPCNetwork,
	subnetsByNetwork map[string][]Subnet, natsByNetwork map[string][]CloudNATConfig,
	peeringMap map[string][]VPCPeering, outerWidth int) string {

	var sb strings.Builder
	innerWidth := outerWidth - 6

	// VPC header with attributes
	vpcTitle := fmt.Sprintf("VPC: %s", network.Name)
	vpcAttrs := fmt.Sprintf("(%s routing, MTU: %d)", network.RoutingMode, network.MTU)

	// Add Shared VPC indicator
	sharedVPCLabel := ""
	if network.IsSharedVPC {
		sharedVPCLabel = fmt.Sprintf(" [SHARED VPC %s]", strings.ToUpper(network.SharedVPCRole))
	}

	// Peering indicator
	peeringLabel := ""
	if network.PeeringCount > 0 {
		peeringLabel = fmt.Sprintf(" [%d PEERING(s)]", network.PeeringCount)
	}

	sb.WriteString("│                                                                                        │\n")
	sb.WriteString("│  ┌")
	sb.WriteString(strings.Repeat("─", innerWidth-2))
	sb.WriteString("┐  │\n")

	// VPC title line
	titleLine := fmt.Sprintf("%s %s%s%s", vpcTitle, vpcAttrs, sharedVPCLabel, peeringLabel)
	if len(titleLine) > innerWidth-4 {
		titleLine = titleLine[:innerWidth-7] + "..."
	}
	sb.WriteString(fmt.Sprintf("│  │ %-*s │  │\n", innerWidth-4, titleLine))

	sb.WriteString("│  ├")
	sb.WriteString(strings.Repeat("─", innerWidth-2))
	sb.WriteString("┤  │\n")

	// Get subnets for this network
	key := network.ProjectID + "/" + network.Name
	subnets := subnetsByNetwork[key]

	// Group subnets by region
	subnetsByRegion := make(map[string][]Subnet)
	for _, s := range subnets {
		subnetsByRegion[s.Region] = append(subnetsByRegion[s.Region], s)
	}

	// Sort regions
	var regions []string
	for region := range subnetsByRegion {
		regions = append(regions, region)
	}
	sort.Strings(regions)

	if len(subnets) == 0 {
		sb.WriteString(fmt.Sprintf("│  │ %-*s │  │\n", innerWidth-4, "(No subnets)"))
	} else {
		// Draw subnets in a grid layout (3 per row)
		subnetWidth := 26
		subnetsPerRow := 3

		for i := 0; i < len(regions); i += subnetsPerRow {
			// Draw subnet boxes for this row
			endIdx := i + subnetsPerRow
			if endIdx > len(regions) {
				endIdx = len(regions)
			}
			rowRegions := regions[i:endIdx]

			// Top of subnet boxes
			sb.WriteString("│  │  ")
			for j := range rowRegions {
				if j > 0 {
					sb.WriteString("  ")
				}
				sb.WriteString("┌")
				sb.WriteString(strings.Repeat("─", subnetWidth-2))
				sb.WriteString("┐")
			}
			// Pad remaining space
			remaining := innerWidth - 4 - (len(rowRegions) * subnetWidth) - ((len(rowRegions) - 1) * 2)
			sb.WriteString(strings.Repeat(" ", remaining))
			sb.WriteString(" │  │\n")

			// Region name line
			sb.WriteString("│  │  ")
			for j, region := range rowRegions {
				if j > 0 {
					sb.WriteString("  ")
				}
				regionDisplay := region
				if len(regionDisplay) > subnetWidth-4 {
					regionDisplay = regionDisplay[:subnetWidth-7] + "..."
				}
				sb.WriteString(fmt.Sprintf("│ %-*s │", subnetWidth-4, regionDisplay))
			}
			sb.WriteString(strings.Repeat(" ", remaining))
			sb.WriteString(" │  │\n")

			// Separator
			sb.WriteString("│  │  ")
			for j := range rowRegions {
				if j > 0 {
					sb.WriteString("  ")
				}
				sb.WriteString("├")
				sb.WriteString(strings.Repeat("─", subnetWidth-2))
				sb.WriteString("┤")
			}
			sb.WriteString(strings.Repeat(" ", remaining))
			sb.WriteString(" │  │\n")

			// Subnet details for each region
			maxSubnets := 0
			for _, region := range rowRegions {
				if len(subnetsByRegion[region]) > maxSubnets {
					maxSubnets = len(subnetsByRegion[region])
				}
			}

			for subnetIdx := 0; subnetIdx < maxSubnets; subnetIdx++ {
				// Subnet name
				sb.WriteString("│  │  ")
				for j, region := range rowRegions {
					if j > 0 {
						sb.WriteString("  ")
					}
					regionSubnets := subnetsByRegion[region]
					if subnetIdx < len(regionSubnets) {
						s := regionSubnets[subnetIdx]
						name := s.Name
						if len(name) > subnetWidth-4 {
							name = name[:subnetWidth-7] + "..."
						}
						sb.WriteString(fmt.Sprintf("│ %-*s │", subnetWidth-4, name))
					} else {
						sb.WriteString("│")
						sb.WriteString(strings.Repeat(" ", subnetWidth-2))
						sb.WriteString("│")
					}
				}
				sb.WriteString(strings.Repeat(" ", remaining))
				sb.WriteString(" │  │\n")

				// CIDR
				sb.WriteString("│  │  ")
				for j, region := range rowRegions {
					if j > 0 {
						sb.WriteString("  ")
					}
					regionSubnets := subnetsByRegion[region]
					if subnetIdx < len(regionSubnets) {
						s := regionSubnets[subnetIdx]
						sb.WriteString(fmt.Sprintf("│ %-*s │", subnetWidth-4, s.IPCIDRRange))
					} else {
						sb.WriteString("│")
						sb.WriteString(strings.Repeat(" ", subnetWidth-2))
						sb.WriteString("│")
					}
				}
				sb.WriteString(strings.Repeat(" ", remaining))
				sb.WriteString(" │  │\n")

				// Flags (PGA, Logs)
				sb.WriteString("│  │  ")
				for j, region := range rowRegions {
					if j > 0 {
						sb.WriteString("  ")
					}
					regionSubnets := subnetsByRegion[region]
					if subnetIdx < len(regionSubnets) {
						s := regionSubnets[subnetIdx]
						pga := "PGA:N"
						if s.PrivateIPGoogleAccess {
							pga = "PGA:Y"
						}
						logs := "Logs:N"
						if s.FlowLogsEnabled {
							logs = "Logs:Y"
						}
						flags := fmt.Sprintf("[%s][%s]", pga, logs)
						sb.WriteString(fmt.Sprintf("│ %-*s │", subnetWidth-4, flags))
					} else {
						sb.WriteString("│")
						sb.WriteString(strings.Repeat(" ", subnetWidth-2))
						sb.WriteString("│")
					}
				}
				sb.WriteString(strings.Repeat(" ", remaining))
				sb.WriteString(" │  │\n")
			}

			// Bottom of subnet boxes
			sb.WriteString("│  │  ")
			for j := range rowRegions {
				if j > 0 {
					sb.WriteString("  ")
				}
				sb.WriteString("└")
				sb.WriteString(strings.Repeat("─", subnetWidth-2))
				sb.WriteString("┘")
			}
			sb.WriteString(strings.Repeat(" ", remaining))
			sb.WriteString(" │  │\n")
		}
	}

	// Check for Cloud NAT
	nats := natsByNetwork[key]
	if len(nats) > 0 {
		sb.WriteString("│  │                                                                                  │  │\n")
		sb.WriteString("│  │                              ┌────────────────────────┐                          │  │\n")
		for _, nat := range nats {
			natIPs := "AUTO"
			if len(nat.NATIPAddresses) > 0 {
				natIPs = strings.Join(nat.NATIPAddresses, ",")
				if len(natIPs) > 18 {
					natIPs = natIPs[:15] + "..."
				}
			}
			sb.WriteString(fmt.Sprintf("│  │                              │ Cloud NAT: %-11s │                          │  │\n", nat.Name[:min(11, len(nat.Name))]))
			sb.WriteString(fmt.Sprintf("│  │                              │ Region: %-13s │                          │  │\n", nat.Region[:min(13, len(nat.Region))]))
			sb.WriteString(fmt.Sprintf("│  │                              │ IPs: %-16s │                          │  │\n", natIPs))
		}
		sb.WriteString("│  │                              └───────────┬────────────┘                          │  │\n")
		sb.WriteString("│  │                                          │                                       │  │\n")
		sb.WriteString("│  │                                          ▼                                       │  │\n")
		sb.WriteString("│  │                                    [INTERNET]                                    │  │\n")
	}

	// VPC footer
	sb.WriteString("│  │                                                                                  │  │\n")
	sb.WriteString("│  └")
	sb.WriteString(strings.Repeat("─", innerWidth-2))
	sb.WriteString("┘  │\n")

	return sb.String()
}

// drawSharedVPCSection draws Shared VPC host/service relationships
func (m *NetworkTopologyModule) drawSharedVPCSection() string {
	var sb strings.Builder
	width := 90

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "SHARED VPC RELATIONSHIPS"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	for hostProject, config := range m.SharedVPCs {
		sb.WriteString("│                                                                                        │\n")
		sb.WriteString(fmt.Sprintf("│   ┌─────────────────────────────┐                                                    │\n"))
		sb.WriteString(fmt.Sprintf("│   │ HOST PROJECT                │                                                    │\n"))

		hostDisplay := hostProject
		if len(hostDisplay) > 27 {
			hostDisplay = hostDisplay[:24] + "..."
		}
		sb.WriteString(fmt.Sprintf("│   │ %-27s │                                                    │\n", hostDisplay))
		sb.WriteString(fmt.Sprintf("│   └──────────────┬──────────────┘                                                    │\n"))
		sb.WriteString(fmt.Sprintf("│                  │                                                                   │\n"))

		if len(config.ServiceProjects) > 0 {
			// Draw connection lines
			numProjects := len(config.ServiceProjects)
			if numProjects > 6 {
				numProjects = 6 // Limit display
			}

			sb.WriteString("│     ")
			for i := 0; i < numProjects; i++ {
				if i == 0 {
					sb.WriteString("┌")
				} else if i == numProjects-1 {
					sb.WriteString("┬")
				} else {
					sb.WriteString("┬")
				}
				sb.WriteString("────────────")
			}
			if len(config.ServiceProjects) > 6 {
				sb.WriteString("┬────────────")
			}
			sb.WriteString(strings.Repeat(" ", width-6-(numProjects*13)-14))
			sb.WriteString("│\n")

			sb.WriteString("│     ")
			for i := 0; i < numProjects; i++ {
				sb.WriteString("▼            ")
			}
			if len(config.ServiceProjects) > 6 {
				sb.WriteString("             ")
			}
			sb.WriteString(strings.Repeat(" ", width-6-(numProjects*13)-14))
			sb.WriteString("│\n")

			sb.WriteString("│   ")
			for i := 0; i < numProjects && i < len(config.ServiceProjects); i++ {
				proj := config.ServiceProjects[i]
				if len(proj) > 10 {
					proj = proj[:7] + "..."
				}
				sb.WriteString(fmt.Sprintf("┌──────────┐ "))
			}
			if len(config.ServiceProjects) > 6 {
				sb.WriteString("  ...      ")
			}
			sb.WriteString(strings.Repeat(" ", max(0, width-5-(numProjects*13)-12)))
			sb.WriteString("│\n")

			sb.WriteString("│   ")
			for i := 0; i < numProjects && i < len(config.ServiceProjects); i++ {
				proj := config.ServiceProjects[i]
				if len(proj) > 10 {
					proj = proj[:7] + "..."
				}
				sb.WriteString(fmt.Sprintf("│%-10s│ ", proj))
			}
			if len(config.ServiceProjects) > 6 {
				sb.WriteString(fmt.Sprintf("(+%d more) ", len(config.ServiceProjects)-6))
			}
			sb.WriteString(strings.Repeat(" ", max(0, width-5-(numProjects*13)-12)))
			sb.WriteString("│\n")

			sb.WriteString("│   ")
			for i := 0; i < numProjects; i++ {
				sb.WriteString("└──────────┘ ")
			}
			if len(config.ServiceProjects) > 6 {
				sb.WriteString("           ")
			}
			sb.WriteString(strings.Repeat(" ", max(0, width-5-(numProjects*13)-12)))
			sb.WriteString("│\n")

			sb.WriteString(fmt.Sprintf("│   (Service Projects: %d total)                                                        │\n", len(config.ServiceProjects)))
		} else {
			sb.WriteString("│                  │                                                                   │\n")
			sb.WriteString("│                  └── (No service projects found)                                     │\n")
		}
	}

	sb.WriteString("│                                                                                        │\n")
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// drawPeeringSummary draws a summary of all VPC peering relationships
func (m *NetworkTopologyModule) drawPeeringSummary(peerings []VPCPeering) string {
	var sb strings.Builder
	width := 90

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "VPC PEERING CONNECTIONS"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	for _, p := range peerings {
		localNet := m.extractNetworkName(p.Network)
		peerNet := m.extractNetworkName(p.PeerNetwork)

		// Truncate names if too long
		if len(localNet) > 20 {
			localNet = localNet[:17] + "..."
		}
		if len(peerNet) > 20 {
			peerNet = peerNet[:17] + "..."
		}

		stateIcon := "●"
		if p.State != "ACTIVE" {
			stateIcon = "○"
		}

		importRoutes := "N"
		if p.ImportCustomRoute {
			importRoutes = "Y"
		}
		exportRoutes := "N"
		if p.ExportCustomRoute {
			exportRoutes = "Y"
		}

		line := fmt.Sprintf("%s [%s] %s/%s ◄══════► %s/%s [Import:%s Export:%s]",
			stateIcon, p.State[:min(6, len(p.State))],
			p.ProjectID[:min(15, len(p.ProjectID))], localNet,
			p.PeerProjectID[:min(15, len(p.PeerProjectID))], peerNet,
			importRoutes, exportRoutes)

		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}

		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, line))
	}

	sb.WriteString("│                                                                                        │\n")
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// drawLegend draws the diagram legend
func (m *NetworkTopologyModule) drawLegend() string {
	var sb strings.Builder
	width := 90

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "LEGEND"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")
	sb.WriteString(fmt.Sprintf("│ %-42s │ %-42s │\n", "PGA = Private Google Access", "● = Active peering"))
	sb.WriteString(fmt.Sprintf("│ %-42s │ %-42s │\n", "Logs = VPC Flow Logs enabled", "○ = Inactive peering"))
	sb.WriteString(fmt.Sprintf("│ %-42s │ %-42s │\n", "[SHARED VPC HOST] = Shared VPC host project", "◄══► = Peering connection"))
	sb.WriteString(fmt.Sprintf("│ %-42s │ %-42s │\n", "Import/Export = Route exchange settings", "▼ = Traffic flow direction"))
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *NetworkTopologyModule) addNetworkToLoot(projectID string, n VPCNetwork) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# VPC NETWORK: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe network:\n"+
			"gcloud compute networks describe %s --project=%s\n\n"+
			"# List subnets in network:\n"+
			"gcloud compute networks subnets list --network=%s --project=%s\n\n"+
			"# List firewall rules for network:\n"+
			"gcloud compute firewall-rules list --filter=\"network:%s\" --project=%s\n\n",
		n.Name,
		n.ProjectID,
		n.Name, n.ProjectID,
		n.Name, n.ProjectID,
		n.Name, n.ProjectID,
	)
}

func (m *NetworkTopologyModule) addSubnetToLoot(projectID string, s Subnet) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# SUBNET: %s\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Project: %s, Region: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe subnet:\n"+
			"gcloud compute networks subnets describe %s --region=%s --project=%s\n\n"+
			"# Get subnet IAM policy:\n"+
			"gcloud compute networks subnets get-iam-policy %s --region=%s --project=%s\n\n",
		s.Name,
		s.ProjectID, s.Region,
		s.Name, s.Region, s.ProjectID,
		s.Name, s.Region, s.ProjectID,
	)
}

func (m *NetworkTopologyModule) addPeeringToLoot(projectID string, p VPCPeering) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# VPC PEERING: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n"+
			"# Local: %s -> Peer: %s (project: %s)\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# List peerings:\n"+
			"gcloud compute networks peerings list --project=%s\n\n"+
			"# List peering routes (incoming):\n"+
			"gcloud compute networks peerings list-routes %s --project=%s --network=%s --region=REGION --direction=INCOMING\n\n"+
			"# List peering routes (outgoing):\n"+
			"gcloud compute networks peerings list-routes %s --project=%s --network=%s --region=REGION --direction=OUTGOING\n\n",
		p.Name,
		p.ProjectID,
		m.extractNetworkName(p.Network), m.extractNetworkName(p.PeerNetwork), p.PeerProjectID,
		p.ProjectID,
		p.Name, p.ProjectID, m.extractNetworkName(p.Network),
		p.Name, p.ProjectID, m.extractNetworkName(p.Network),
	)
}

func (m *NetworkTopologyModule) addNATToLoot(projectID string, nat CloudNATConfig) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# CLOUD NAT: %s\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Project: %s, Region: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe router with NAT config:\n"+
			"gcloud compute routers describe ROUTER_NAME --region=%s --project=%s\n\n"+
			"# List NAT mappings:\n"+
			"gcloud compute routers get-nat-mapping-info ROUTER_NAME --region=%s --project=%s\n\n",
		nat.Name,
		nat.ProjectID, nat.Region,
		nat.Region, nat.ProjectID,
		nat.Region, nat.ProjectID,
	)
}

func (m *NetworkTopologyModule) addSharedVPCToLoot(projectID string, config *SharedVPCConfig) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# SHARED VPC HOST: %s\n"+
			"# =============================================================================\n"+
			"# Service Projects: %v\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# List Shared VPC resources:\n"+
			"gcloud compute shared-vpc list-associated-resources %s\n\n"+
			"# Get host project for service project:\n"+
			"gcloud compute shared-vpc get-host-project SERVICE_PROJECT_ID\n\n"+
			"# List usable subnets for service project:\n"+
			"gcloud compute networks subnets list-usable --project=%s\n\n",
		projectID,
		config.ServiceProjects,
		projectID,
		projectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *NetworkTopologyModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Generate ASCII diagram and add to loot
	diagram := m.generateASCIIDiagram()
	if diagram != "" {
		// Add diagram to the first project's loot (or create a combined one)
		for projectID := range m.LootMap {
			if m.LootMap[projectID] == nil {
				m.LootMap[projectID] = make(map[string]*internal.LootFile)
			}
			m.LootMap[projectID]["network-topology-diagram"] = &internal.LootFile{
				Name:     "network-topology-diagram",
				Contents: diagram,
			}
			break // Only add once for flat output; hierarchical will duplicate
		}

		// For hierarchical output, add to all projects so it appears in each
		if m.Hierarchy != nil && !m.FlatOutput {
			for projectID := range m.LootMap {
				if m.LootMap[projectID] == nil {
					m.LootMap[projectID] = make(map[string]*internal.LootFile)
				}
				m.LootMap[projectID]["network-topology-diagram"] = &internal.LootFile{
					Name:     "network-topology-diagram",
					Contents: diagram,
				}
			}
		}
	}

	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *NetworkTopologyModule) getNetworksHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Network",
		"Routing Mode",
		"Subnets",
		"Peerings",
		"Shared VPC",
		"MTU",
	}
}

func (m *NetworkTopologyModule) getSubnetsHeader() []string {
	return []string{
		"Project",
		"Subnet",
		"Network",
		"Region",
		"CIDR",
		"Private Google Access",
		"Flow Logs",
		"Purpose",
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

func (m *NetworkTopologyModule) getPeeringsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Local Network",
		"Peer Network",
		"Peer Project",
		"State",
		"Import Routes",
		"Export Routes",
	}
}

func (m *NetworkTopologyModule) getNATHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"Network",
		"NAT IPs",
		"Logging",
	}
}

func (m *NetworkTopologyModule) networksToTableBody(networks []VPCNetwork) [][]string {
	var body [][]string
	for _, n := range networks {
		sharedVPC := "-"
		if n.IsSharedVPC {
			sharedVPC = n.SharedVPCRole
		}

		body = append(body, []string{
			m.GetProjectName(n.ProjectID),
			n.ProjectID,
			n.Name,
			n.RoutingMode,
			fmt.Sprintf("%d", n.SubnetCount),
			fmt.Sprintf("%d", n.PeeringCount),
			sharedVPC,
			fmt.Sprintf("%d", n.MTU),
		})
	}
	return body
}

func (m *NetworkTopologyModule) subnetsToTableBody(subnets []Subnet) [][]string {
	var body [][]string
	for _, s := range subnets {
		purpose := s.Purpose
		if purpose == "" {
			purpose = "PRIVATE"
		}

		if len(s.IAMBindings) > 0 {
			// One row per IAM binding
			for _, binding := range s.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(s.ProjectID),
					s.Name,
					m.extractNetworkName(s.Network),
					s.Region,
					s.IPCIDRRange,
					shared.BoolToYesNo(s.PrivateIPGoogleAccess),
					shared.BoolToYesNo(s.FlowLogsEnabled),
					purpose,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// No IAM bindings - single row
			body = append(body, []string{
				m.GetProjectName(s.ProjectID),
				s.Name,
				m.extractNetworkName(s.Network),
				s.Region,
				s.IPCIDRRange,
				shared.BoolToYesNo(s.PrivateIPGoogleAccess),
				shared.BoolToYesNo(s.FlowLogsEnabled),
				purpose,
				"-",
				"-",
			})
		}
	}
	return body
}

func (m *NetworkTopologyModule) peeringsToTableBody(peerings []VPCPeering) [][]string {
	var body [][]string
	for _, p := range peerings {
		body = append(body, []string{
			m.GetProjectName(p.ProjectID),
			p.ProjectID,
			p.Name,
			m.extractNetworkName(p.Network),
			m.extractNetworkName(p.PeerNetwork),
			p.PeerProjectID,
			p.State,
			shared.BoolToYesNo(p.ImportCustomRoute),
			shared.BoolToYesNo(p.ExportCustomRoute),
		})
	}
	return body
}

func (m *NetworkTopologyModule) natsToTableBody(nats []CloudNATConfig) [][]string {
	var body [][]string
	for _, nat := range nats {
		natIPs := strings.Join(nat.NATIPAddresses, ", ")
		if natIPs == "" {
			natIPs = "AUTO"
		}

		body = append(body, []string{
			m.GetProjectName(nat.ProjectID),
			nat.ProjectID,
			nat.Name,
			nat.Region,
			m.extractNetworkName(nat.Network),
			natIPs,
			shared.BoolToYesNo(nat.EnableLogging),
		})
	}
	return body
}

func (m *NetworkTopologyModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if networks, ok := m.ProjectNetworks[projectID]; ok && len(networks) > 0 {
		sort.Slice(networks, func(i, j int) bool {
			return networks[i].Name < networks[j].Name
		})
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "vpc-networks",
			Header: m.getNetworksHeader(),
			Body:   m.networksToTableBody(networks),
		})
		for _, n := range networks {
			m.addNetworkToLoot(projectID, n)
		}
	}

	if subnets, ok := m.ProjectSubnets[projectID]; ok && len(subnets) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "subnets",
			Header: m.getSubnetsHeader(),
			Body:   m.subnetsToTableBody(subnets),
		})
		for _, s := range subnets {
			m.addSubnetToLoot(projectID, s)
		}
	}

	if peerings, ok := m.ProjectPeerings[projectID]; ok && len(peerings) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "vpc-peerings",
			Header: m.getPeeringsHeader(),
			Body:   m.peeringsToTableBody(peerings),
		})
		for _, p := range peerings {
			m.addPeeringToLoot(projectID, p)
		}
	}

	if nats, ok := m.ProjectNATs[projectID]; ok && len(nats) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "cloud-nat",
			Header: m.getNATHeader(),
			Body:   m.natsToTableBody(nats),
		})
		for _, nat := range nats {
			m.addNATToLoot(projectID, nat)
		}
	}

	// Add Shared VPC loot if this is a host project
	if config, ok := m.SharedVPCs[projectID]; ok {
		m.addSharedVPCToLoot(projectID, config)
	}

	return tableFiles
}

func (m *NetworkTopologyModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectNetworks {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectSubnets {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectPeerings {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectNATs {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = NetworkTopologyOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
	}
}

func (m *NetworkTopologyModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allNetworks := m.getAllNetworks()
	allSubnets := m.getAllSubnets()
	allPeerings := m.getAllPeerings()
	allNATs := m.getAllNATs()

	sort.Slice(allNetworks, func(i, j int) bool {
		if allNetworks[i].ProjectID != allNetworks[j].ProjectID {
			return allNetworks[i].ProjectID < allNetworks[j].ProjectID
		}
		return allNetworks[i].Name < allNetworks[j].Name
	})

	var tables []internal.TableFile

	if len(allNetworks) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vpc-networks",
			Header: m.getNetworksHeader(),
			Body:   m.networksToTableBody(allNetworks),
		})
	}

	if len(allSubnets) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "subnets",
			Header: m.getSubnetsHeader(),
			Body:   m.subnetsToTableBody(allSubnets),
		})
	}

	if len(allPeerings) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vpc-peerings",
			Header: m.getPeeringsHeader(),
			Body:   m.peeringsToTableBody(allPeerings),
		})
	}

	if len(allNATs) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cloud-nat",
			Header: m.getNATHeader(),
			Body:   m.natsToTableBody(allNATs),
		})
	}

	// Populate loot for flat output
	for projectID, networks := range m.ProjectNetworks {
		for _, n := range networks {
			m.addNetworkToLoot(projectID, n)
		}
	}
	for projectID, subnets := range m.ProjectSubnets {
		for _, s := range subnets {
			m.addSubnetToLoot(projectID, s)
		}
	}
	for projectID, peerings := range m.ProjectPeerings {
		for _, p := range peerings {
			m.addPeeringToLoot(projectID, p)
		}
	}
	for projectID, nats := range m.ProjectNATs {
		for _, nat := range nats {
			m.addNATToLoot(projectID, nat)
		}
	}
	for projectID, config := range m.SharedVPCs {
		m.addSharedVPCToLoot(projectID, config)
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := NetworkTopologyOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
