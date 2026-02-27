package diagramservice

import (
	"fmt"
	"sort"
	"strings"
)

// DiagramConfig holds configuration for diagram generation
type DiagramConfig struct {
	Width       int  // Default outer width
	InnerWidth  int  // Default inner width
	ShowLegend  bool // Whether to show legend
	CompactMode bool // Use compact layout
}

// DefaultConfig returns sensible defaults for diagram generation
func DefaultConfig() DiagramConfig {
	return DiagramConfig{
		Width:       90,
		InnerWidth:  84,
		ShowLegend:  true,
		CompactMode: false,
	}
}

// ========================================
// Core Drawing Primitives
// ========================================

// DrawBox draws a simple box with centered title
func DrawBox(title string, width int) string {
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

// DrawBoxWithContent draws a box with title and content lines
func DrawBoxWithContent(title string, content []string, width int) string {
	var sb strings.Builder

	// Top border
	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")

	// Title line
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, title))

	// Separator
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	// Content lines
	for _, line := range content {
		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, line))
	}

	// Bottom border
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// DrawSectionHeader draws a section header box
func DrawSectionHeader(title string, width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, title))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	return sb.String()
}

// DrawSectionFooter draws a section footer
func DrawSectionFooter(width int) string {
	var sb strings.Builder
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")
	return sb.String()
}

// DrawNestedBox draws a box nested inside another (with indentation)
func DrawNestedBox(title string, content []string, outerWidth, indent int) string {
	var sb strings.Builder
	innerWidth := outerWidth - (indent * 2) - 4

	// Padding prefix
	pad := strings.Repeat(" ", indent)

	// Top border
	sb.WriteString(fmt.Sprintf("│%s┌%s┐%s│\n", pad, strings.Repeat("─", innerWidth-2), pad))

	// Title
	titleLine := title
	if len(titleLine) > innerWidth-4 {
		titleLine = titleLine[:innerWidth-7] + "..."
	}
	sb.WriteString(fmt.Sprintf("│%s│ %-*s │%s│\n", pad, innerWidth-4, titleLine, pad))

	// Separator if content exists
	if len(content) > 0 {
		sb.WriteString(fmt.Sprintf("│%s├%s┤%s│\n", pad, strings.Repeat("─", innerWidth-2), pad))

		for _, line := range content {
			if len(line) > innerWidth-4 {
				line = line[:innerWidth-7] + "..."
			}
			sb.WriteString(fmt.Sprintf("│%s│ %-*s │%s│\n", pad, innerWidth-4, line, pad))
		}
	}

	// Bottom border
	sb.WriteString(fmt.Sprintf("│%s└%s┘%s│\n", pad, strings.Repeat("─", innerWidth-2), pad))

	return sb.String()
}

// DrawEmptyLine draws an empty content line
func DrawEmptyLine(width int) string {
	return fmt.Sprintf("│%s│\n", strings.Repeat(" ", width-2))
}

// DrawTextLine draws a text line inside a box
func DrawTextLine(text string, width int) string {
	if len(text) > width-4 {
		text = text[:width-7] + "..."
	}
	return fmt.Sprintf("│ %-*s │\n", width-4, text)
}

// ========================================
// Network Diagram Components
// ========================================

// NetworkInfo represents a VPC network for diagram purposes
type NetworkInfo struct {
	Name          string
	ProjectID     string
	RoutingMode   string
	MTU           int64
	IsSharedVPC   bool
	SharedVPCRole string
	PeeringCount  int
}

// SubnetInfo represents a subnet for diagram purposes
type SubnetInfo struct {
	Name                  string
	Region                string
	IPCIDRRange           string
	PrivateIPGoogleAccess bool
	FlowLogsEnabled       bool
}

// CloudNATInfo represents Cloud NAT for diagram purposes
type CloudNATInfo struct {
	Name           string
	Region         string
	Network        string
	NATIPAddresses []string
}

// FirewallRuleInfo represents a firewall rule for diagram purposes
type FirewallRuleInfo struct {
	Name            string
	Direction       string
	Priority        int64
	SourceRanges    []string
	AllowedPorts    string
	TargetTags      string
	IsPublicIngress bool
	Disabled        bool
}

// LoadBalancerInfo represents a load balancer for diagram purposes
type LoadBalancerInfo struct {
	Name            string
	Type            string
	Scheme          string
	IPAddress       string
	Port            string
	Region          string
	BackendServices []string
	SecurityPolicy  string
	// BackendDetails maps backend service name to its actual backends (instance groups, NEGs, etc.)
	BackendDetails  map[string][]string
}

// VPCPeeringInfo represents VPC peering for diagram purposes
type VPCPeeringInfo struct {
	Name              string
	Network           string
	PeerNetwork       string
	PeerProjectID     string
	State             string
	ExportRoutes      bool
	ImportRoutes      bool
}

// SharedVPCConfig represents shared VPC configuration
type SharedVPCConfig struct {
	HostProject     string
	ServiceProjects []string
	Networks        []string
}

// ========================================
// Network Topology Diagram Functions
// ========================================

// DrawNetworkTopologyDiagram generates a complete network topology ASCII diagram
func DrawNetworkTopologyDiagram(
	networksByProject map[string][]NetworkInfo,
	subnetsByNetwork map[string][]SubnetInfo, // key: "projectID/networkName"
	natsByNetwork map[string][]CloudNATInfo, // key: "projectID/networkName"
	peeringMap map[string][]VPCPeeringInfo, // key: "projectID/networkName"
	sharedVPCs map[string]SharedVPCConfig, // key: hostProjectID
	projectNames map[string]string, // projectID -> displayName
) string {
	var sb strings.Builder
	width := 90

	// Header
	sb.WriteString(DrawBox("GCP NETWORK TOPOLOGY", width))
	sb.WriteString("\n")

	// Sort projects for consistent output
	var projectIDs []string
	for projectID := range networksByProject {
		projectIDs = append(projectIDs, projectID)
	}
	sort.Strings(projectIDs)

	// Draw each project
	for _, projectID := range projectIDs {
		networks := networksByProject[projectID]
		displayName := projectNames[projectID]
		sb.WriteString(drawProjectNetworks(projectID, displayName, networks, subnetsByNetwork, natsByNetwork, peeringMap, width))
		sb.WriteString("\n")
	}

	// Draw Shared VPC relationships if any
	if len(sharedVPCs) > 0 {
		sb.WriteString(drawSharedVPCRelationships(sharedVPCs, width))
		sb.WriteString("\n")
	}

	// Draw VPC Peering summary
	allPeerings := collectAllPeerings(peeringMap)
	if len(allPeerings) > 0 {
		sb.WriteString(drawPeeringSummary(allPeerings, width))
		sb.WriteString("\n")
	}

	// Legend
	sb.WriteString(DrawNetworkLegend(width))

	return sb.String()
}

func drawProjectNetworks(
	projectID, displayName string,
	networks []NetworkInfo,
	subnetsByNetwork map[string][]SubnetInfo,
	natsByNetwork map[string][]CloudNATInfo,
	peeringMap map[string][]VPCPeeringInfo,
	width int,
) string {
	var sb strings.Builder

	projectTitle := fmt.Sprintf("PROJECT: %s", projectID)
	if displayName != "" && displayName != projectID {
		projectTitle = fmt.Sprintf("PROJECT: %s (%s)", projectID, displayName)
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
		sb.WriteString(drawVPCNetwork(network, subnetsByNetwork, natsByNetwork, peeringMap, width))
	}

	// Project footer
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

func drawVPCNetwork(
	network NetworkInfo,
	subnetsByNetwork map[string][]SubnetInfo,
	natsByNetwork map[string][]CloudNATInfo,
	peeringMap map[string][]VPCPeeringInfo,
	outerWidth int,
) string {
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

	sb.WriteString(DrawEmptyLine(outerWidth))
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
	subnetsByRegion := make(map[string][]SubnetInfo)
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
			natName := nat.Name
			if len(natName) > 11 {
				natName = natName[:11]
			}
			natRegion := nat.Region
			if len(natRegion) > 13 {
				natRegion = natRegion[:13]
			}
			sb.WriteString(fmt.Sprintf("│  │                              │ Cloud NAT: %-11s │                          │  │\n", natName))
			sb.WriteString(fmt.Sprintf("│  │                              │ Region: %-13s │                          │  │\n", natRegion))
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

func drawSharedVPCRelationships(sharedVPCs map[string]SharedVPCConfig, width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "SHARED VPC RELATIONSHIPS"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	for hostProject, config := range sharedVPCs {
		sb.WriteString(DrawEmptyLine(width))
		sb.WriteString("│   ┌─────────────────────────────┐                                                    │\n")
		sb.WriteString("│   │ HOST PROJECT                │                                                    │\n")

		hostDisplay := hostProject
		if len(hostDisplay) > 27 {
			hostDisplay = hostDisplay[:24] + "..."
		}
		sb.WriteString(fmt.Sprintf("│   │ %-27s │                                                    │\n", hostDisplay))
		sb.WriteString("│   └──────────────┬──────────────┘                                                    │\n")
		sb.WriteString("│                  │                                                                   │\n")

		if len(config.ServiceProjects) > 0 {
			numProjects := len(config.ServiceProjects)
			if numProjects > 6 {
				numProjects = 6
			}

			sb.WriteString("│     ")
			for i := 0; i < numProjects; i++ {
				if i == 0 {
					sb.WriteString("┌")
				} else {
					sb.WriteString("┬")
				}
				sb.WriteString("────────────")
			}
			if len(config.ServiceProjects) > 6 {
				sb.WriteString("┬────────────")
			}
			sb.WriteString(strings.Repeat(" ", max(0, width-6-(numProjects*13)-14)))
			sb.WriteString("│\n")

			sb.WriteString("│     ")
			for i := 0; i < numProjects; i++ {
				sb.WriteString("▼            ")
			}
			if len(config.ServiceProjects) > 6 {
				sb.WriteString("             ")
			}
			sb.WriteString(strings.Repeat(" ", max(0, width-6-(numProjects*13)-14)))
			sb.WriteString("│\n")

			sb.WriteString("│   ")
			for i := 0; i < numProjects && i < len(config.ServiceProjects); i++ {
				sb.WriteString("┌──────────┐ ")
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
			sb.WriteString(strings.Repeat(" ", max(0, width-5-(numProjects*13)-12+12)))
			sb.WriteString("│\n")
		}
	}

	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

func collectAllPeerings(peeringMap map[string][]VPCPeeringInfo) []VPCPeeringInfo {
	var all []VPCPeeringInfo
	for _, peerings := range peeringMap {
		all = append(all, peerings...)
	}
	return all
}

func drawPeeringSummary(peerings []VPCPeeringInfo, width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "VPC PEERING CONNECTIONS"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	for _, peering := range peerings {
		// Draw peering connection
		networkName := extractNetworkNameFromURL(peering.Network)
		peerNetworkName := extractNetworkNameFromURL(peering.PeerNetwork)

		state := peering.State
		if state == "" {
			state = "ACTIVE"
		}

		routeInfo := ""
		if peering.ExportRoutes && peering.ImportRoutes {
			routeInfo = "[export+import routes]"
		} else if peering.ExportRoutes {
			routeInfo = "[export routes]"
		} else if peering.ImportRoutes {
			routeInfo = "[import routes]"
		}

		line := fmt.Sprintf("  %s  <──────>  %s  (%s) %s", networkName, peerNetworkName, state, routeInfo)
		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, line))
	}

	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// DrawNetworkLegend draws a legend for network topology diagrams
func DrawNetworkLegend(width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "LEGEND"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "PGA:Y/N  = Private Google Access enabled/disabled"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "Logs:Y/N = VPC Flow Logs enabled/disabled"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "[SHARED VPC HOST]    = Project hosts shared VPC networks"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "[SHARED VPC SERVICE] = Project uses shared VPC networks"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "[n PEERING(s)]       = Number of VPC peering connections"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "<──────>             = VPC peering connection"))
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// ========================================
// Firewall Diagram Functions
// ========================================

// DrawFirewallDiagram generates an ASCII diagram showing firewall rules
func DrawFirewallDiagram(
	rules []FirewallRuleInfo,
	networkName string,
	projectID string,
	width int,
) string {
	var sb strings.Builder

	title := fmt.Sprintf("FIREWALL RULES: %s", networkName)
	if projectID != "" {
		title = fmt.Sprintf("FIREWALL RULES: %s (Project: %s)", networkName, projectID)
	}

	sb.WriteString(DrawBox(title, width))
	sb.WriteString("\n")

	// Separate ingress and egress
	var ingressRules, egressRules []FirewallRuleInfo
	for _, rule := range rules {
		if strings.ToUpper(rule.Direction) == "INGRESS" {
			ingressRules = append(ingressRules, rule)
		} else {
			egressRules = append(egressRules, rule)
		}
	}

	// Draw ingress section
	if len(ingressRules) > 0 {
		sb.WriteString(drawFirewallSection("INGRESS (Inbound Traffic)", ingressRules, width))
		sb.WriteString("\n")
	}

	// Draw egress section
	if len(egressRules) > 0 {
		sb.WriteString(drawFirewallSection("EGRESS (Outbound Traffic)", egressRules, width))
		sb.WriteString("\n")
	}

	// Draw traffic flow visualization
	sb.WriteString(drawTrafficFlowDiagram(ingressRules, egressRules, width))

	// Legend
	sb.WriteString(DrawFirewallLegend(width))

	return sb.String()
}

func drawFirewallSection(title string, rules []FirewallRuleInfo, width int) string {
	var sb strings.Builder

	// Sort by priority
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, title))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	for _, rule := range rules {
		// Risk indicator
		riskIndicator := "  "
		if rule.IsPublicIngress {
			riskIndicator = "⚠ "
		}

		// Disabled indicator
		disabledLabel := ""
		if rule.Disabled {
			disabledLabel = " [DISABLED]"
		}

		// Format source ranges
		sources := strings.Join(rule.SourceRanges, ", ")
		if len(sources) > 30 {
			sources = sources[:27] + "..."
		}
		if sources == "" {
			sources = "*"
		}

		// Format targets
		targets := rule.TargetTags
		if targets == "" {
			targets = "ALL"
		}

		// Rule name line
		nameLine := fmt.Sprintf("%s%s (Priority: %d)%s", riskIndicator, rule.Name, rule.Priority, disabledLabel)
		if len(nameLine) > width-4 {
			nameLine = nameLine[:width-7] + "..."
		}
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, nameLine))

		// Details line
		detailLine := fmt.Sprintf("    Sources: %s → Ports: %s → Targets: %s", sources, rule.AllowedPorts, targets)
		if len(detailLine) > width-4 {
			detailLine = detailLine[:width-7] + "..."
		}
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, detailLine))
		sb.WriteString(DrawEmptyLine(width))
	}

	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

func drawTrafficFlowDiagram(ingressRules, egressRules []FirewallRuleInfo, width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "TRAFFIC FLOW VISUALIZATION"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	// Count public ingress
	publicIngress := 0
	for _, r := range ingressRules {
		if r.IsPublicIngress {
			publicIngress++
		}
	}

	// Draw simplified flow
	sb.WriteString("│                                                                                        │\n")
	sb.WriteString("│     ┌─────────────┐          ┌─────────────────────┐          ┌─────────────┐          │\n")
	sb.WriteString("│     │  INTERNET   │  ─────>  │  FIREWALL RULES     │  ─────>  │  VPC/VMs    │          │\n")
	sb.WriteString("│     │  (External) │          │                     │          │  (Internal) │          │\n")
	sb.WriteString("│     └─────────────┘          └─────────────────────┘          └─────────────┘          │\n")
	sb.WriteString("│                                                                                        │\n")

	// Summary stats
	statsLine := fmt.Sprintf("   Ingress Rules: %d (Public: %d)    Egress Rules: %d", len(ingressRules), publicIngress, len(egressRules))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, statsLine))

	if publicIngress > 0 {
		warningLine := "   ⚠ WARNING: Public ingress rules allow traffic from 0.0.0.0/0"
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, warningLine))
	}

	sb.WriteString("│                                                                                        │\n")
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// DrawFirewallLegend draws the firewall diagram legend
func DrawFirewallLegend(width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "LEGEND"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "⚠  = Public ingress rule (0.0.0.0/0 source)"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "Priority = Lower number = higher priority (evaluated first)"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "[DISABLED] = Rule is not active"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "Targets: ALL = Rule applies to all instances in network"))
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// ========================================
// Load Balancer Diagram Functions
// ========================================

// DrawLoadBalancerDiagram generates an ASCII diagram showing load balancer traffic flow
func DrawLoadBalancerDiagram(
	loadBalancers []LoadBalancerInfo,
	projectID string,
	width int,
) string {
	var sb strings.Builder

	title := "LOAD BALANCER TRAFFIC FLOW"
	if projectID != "" {
		title = fmt.Sprintf("LOAD BALANCER TRAFFIC FLOW (Project: %s)", projectID)
	}

	sb.WriteString(DrawBox(title, width))
	sb.WriteString("\n")

	// Separate external and internal
	var externalLBs, internalLBs []LoadBalancerInfo
	for _, lb := range loadBalancers {
		if strings.ToUpper(lb.Scheme) == "EXTERNAL" {
			externalLBs = append(externalLBs, lb)
		} else {
			internalLBs = append(internalLBs, lb)
		}
	}

	// Draw external load balancers with flow
	if len(externalLBs) > 0 {
		sb.WriteString(drawLBFlowSection("EXTERNAL (Internet-facing)", externalLBs, width))
		sb.WriteString("\n")
	}

	// Draw internal load balancers with flow
	if len(internalLBs) > 0 {
		sb.WriteString(drawLBFlowSection("INTERNAL (VPC-only)", internalLBs, width))
		sb.WriteString("\n")
	}

	// Summary stats
	sb.WriteString(drawLBSummary(externalLBs, internalLBs, width))

	// Legend
	sb.WriteString(DrawLoadBalancerLegend(width))

	return sb.String()
}

// drawLBFlowSection draws individual load balancer flows showing frontend -> backend
func drawLBFlowSection(title string, lbs []LoadBalancerInfo, width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, title))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	for i, lb := range lbs {
		// Draw flow for each load balancer
		sb.WriteString(drawSingleLBFlow(lb, width))

		// Add separator between LBs (but not after the last one)
		if i < len(lbs)-1 {
			sb.WriteString("│")
			sb.WriteString(strings.Repeat("─", width-2))
			sb.WriteString("│\n")
		}
	}

	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// drawSingleLBFlow draws a single load balancer's traffic flow
func drawSingleLBFlow(lb LoadBalancerInfo, width int) string {
	var sb strings.Builder

	// Security indicator
	armorLabel := ""
	if lb.SecurityPolicy != "" {
		armorLabel = " [Cloud Armor: " + lb.SecurityPolicy + "]"
	}

	// LB name and type header
	headerLine := fmt.Sprintf("  %s (%s, %s)%s", lb.Name, lb.Type, lb.Region, armorLabel)
	if len(headerLine) > width-4 {
		headerLine = headerLine[:width-7] + "..."
	}
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, headerLine))
	sb.WriteString(DrawEmptyLine(width))

	// Frontend (IP:Port)
	frontendBox := fmt.Sprintf("%s:%s", lb.IPAddress, lb.Port)

	// Build backend lines with actual backend targets
	var backendLines []string
	if len(lb.BackendServices) == 0 {
		backendLines = []string{"(no backends)"}
	} else {
		for _, beSvc := range lb.BackendServices {
			// Check if we have detailed backend info
			if lb.BackendDetails != nil {
				if targets, ok := lb.BackendDetails[beSvc]; ok && len(targets) > 0 {
					// Show backend service with its targets
					backendLines = append(backendLines, fmt.Sprintf("%s:", beSvc))
					for _, target := range targets {
						backendLines = append(backendLines, fmt.Sprintf("  -> %s", target))
					}
				} else {
					backendLines = append(backendLines, beSvc)
				}
			} else {
				backendLines = append(backendLines, beSvc)
			}
		}
	}

	// Calculate dynamic backend width based on longest line
	backendWidth := 35
	for _, line := range backendLines {
		if len(line)+4 > backendWidth {
			backendWidth = len(line) + 4
		}
	}
	// Cap at reasonable max
	maxBackendWidth := width - 35
	if backendWidth > maxBackendWidth {
		backendWidth = maxBackendWidth
	}

	frontendWidth := 23
	arrowWidth := 7
	padding := width - frontendWidth - backendWidth - arrowWidth - 8
	if padding < 0 {
		padding = 0
	}

	// Top of boxes
	sb.WriteString(fmt.Sprintf("│   ┌%s┐       ┌%s┐%s│\n",
		strings.Repeat("─", frontendWidth),
		strings.Repeat("─", backendWidth),
		strings.Repeat(" ", padding)))

	// Frontend label
	sb.WriteString(fmt.Sprintf("│   │ %-*s │       │ %-*s │%s│\n",
		frontendWidth-2, "FRONTEND",
		backendWidth-2, "BACKEND SERVICE -> TARGETS",
		strings.Repeat(" ", padding)))

	// Separator with arrow
	sb.WriteString(fmt.Sprintf("│   ├%s┤  ───> ├%s┤%s│\n",
		strings.Repeat("─", frontendWidth),
		strings.Repeat("─", backendWidth),
		strings.Repeat(" ", padding)))

	// IP:Port line with first backend
	sb.WriteString(fmt.Sprintf("│   │ %-*s │       │ %-*s │%s│\n",
		frontendWidth-2, frontendBox,
		backendWidth-2, safeGetIndex(backendLines, 0),
		strings.Repeat(" ", padding)))

	// Additional backend lines
	for i := 1; i < len(backendLines); i++ {
		sb.WriteString(fmt.Sprintf("│   │ %-*s │       │ %-*s │%s│\n",
			frontendWidth-2, "",
			backendWidth-2, backendLines[i],
			strings.Repeat(" ", padding)))
	}

	// Bottom of boxes
	sb.WriteString(fmt.Sprintf("│   └%s┘       └%s┘%s│\n",
		strings.Repeat("─", frontendWidth),
		strings.Repeat("─", backendWidth),
		strings.Repeat(" ", padding)))

	sb.WriteString(DrawEmptyLine(width))

	return sb.String()
}

// drawLBSummary draws summary statistics
func drawLBSummary(externalLBs, internalLBs []LoadBalancerInfo, width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "SUMMARY"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	// Count with Cloud Armor
	armorCount := 0
	for _, lb := range externalLBs {
		if lb.SecurityPolicy != "" {
			armorCount++
		}
	}

	statsLine := fmt.Sprintf("  External LBs: %d    Internal LBs: %d    With Cloud Armor: %d/%d",
		len(externalLBs), len(internalLBs), armorCount, len(externalLBs))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, statsLine))

	if len(externalLBs) > 0 && armorCount == 0 {
		warningLine := "  ⚠ WARNING: No external load balancers have Cloud Armor protection"
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, warningLine))
	} else if len(externalLBs) > armorCount {
		warningLine := fmt.Sprintf("  ⚠ WARNING: %d external load balancer(s) missing Cloud Armor", len(externalLBs)-armorCount)
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, warningLine))
	}

	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// truncateString truncates a string to maxLen, adding "..." if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// safeGetIndex safely gets an index from a slice, returning empty string if out of bounds
func safeGetIndex(slice []string, index int) string {
	if index < len(slice) {
		return slice[index]
	}
	return ""
}

// DrawLoadBalancerLegend draws the load balancer diagram legend
func DrawLoadBalancerLegend(width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "LEGEND"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "[Cloud Armor] = WAF/DDoS protection enabled"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "EXTERNAL = Internet-facing load balancer"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "INTERNAL = Private/VPC-only load balancer"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "global   = Global anycast load balancer"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "regional = Region-specific load balancer"))
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// ========================================
// VPC Networks Diagram Functions
// ========================================

// DrawVPCNetworksDiagram generates a compact VPC networks overview diagram
func DrawVPCNetworksDiagram(
	networks []NetworkInfo,
	subnetsByNetwork map[string][]SubnetInfo,
	peerings []VPCPeeringInfo,
	projectID string,
	width int,
) string {
	var sb strings.Builder

	title := "VPC NETWORKS OVERVIEW"
	if projectID != "" {
		title = fmt.Sprintf("VPC NETWORKS OVERVIEW (Project: %s)", projectID)
	}

	sb.WriteString(DrawBox(title, width))
	sb.WriteString("\n")

	// Draw each network
	for _, network := range networks {
		sb.WriteString(drawVPCNetworkCompact(network, subnetsByNetwork, width))
		sb.WriteString("\n")
	}

	// Peering summary
	if len(peerings) > 0 {
		sb.WriteString(drawVPCPeeringsCompact(peerings, width))
		sb.WriteString("\n")
	}

	// Legend
	sb.WriteString(DrawVPCNetworkLegend(width))

	return sb.String()
}

func drawVPCNetworkCompact(network NetworkInfo, subnetsByNetwork map[string][]SubnetInfo, width int) string {
	var sb strings.Builder

	// Network header
	sharedLabel := ""
	if network.IsSharedVPC {
		sharedLabel = fmt.Sprintf(" [SHARED VPC %s]", strings.ToUpper(network.SharedVPCRole))
	}
	peeringLabel := ""
	if network.PeeringCount > 0 {
		peeringLabel = fmt.Sprintf(" [%d peerings]", network.PeeringCount)
	}

	title := fmt.Sprintf("VPC: %s (%s routing)%s%s", network.Name, network.RoutingMode, sharedLabel, peeringLabel)

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	if len(title) > width-4 {
		title = title[:width-7] + "..."
	}
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, title))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	// Get subnets
	key := network.ProjectID + "/" + network.Name
	subnets := subnetsByNetwork[key]

	if len(subnets) == 0 {
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "  (No subnets)"))
	} else {
		// Group by region
		byRegion := make(map[string][]SubnetInfo)
		for _, s := range subnets {
			byRegion[s.Region] = append(byRegion[s.Region], s)
		}

		var regions []string
		for r := range byRegion {
			regions = append(regions, r)
		}
		sort.Strings(regions)

		for _, region := range regions {
			regionSubnets := byRegion[region]
			regionLine := fmt.Sprintf("  📍 %s:", region)
			sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, regionLine))

			for _, s := range regionSubnets {
				pga := "-"
				if s.PrivateIPGoogleAccess {
					pga = "PGA"
				}
				logs := "-"
				if s.FlowLogsEnabled {
					logs = "Logs"
				}
				subnetLine := fmt.Sprintf("      %s (%s) [%s][%s]", s.Name, s.IPCIDRRange, pga, logs)
				if len(subnetLine) > width-4 {
					subnetLine = subnetLine[:width-7] + "..."
				}
				sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, subnetLine))
			}
		}
	}

	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

func drawVPCPeeringsCompact(peerings []VPCPeeringInfo, width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "VPC PEERINGS"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")

	for _, p := range peerings {
		networkName := extractNetworkNameFromURL(p.Network)
		peerNetworkName := extractNetworkNameFromURL(p.PeerNetwork)
		routes := ""
		if p.ExportRoutes && p.ImportRoutes {
			routes = " [↔ routes]"
		} else if p.ExportRoutes {
			routes = " [→ export]"
		} else if p.ImportRoutes {
			routes = " [← import]"
		}
		line := fmt.Sprintf("  %s ←→ %s (%s)%s", networkName, peerNetworkName, p.State, routes)
		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, line))
	}

	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// DrawVPCNetworkLegend draws the VPC network diagram legend
func DrawVPCNetworkLegend(width int) string {
	var sb strings.Builder

	sb.WriteString("┌")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┐\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "LEGEND"))
	sb.WriteString("├")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┤\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "PGA  = Private Google Access enabled"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "Logs = VPC Flow Logs enabled"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "←→   = VPC Peering connection"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "📍   = Region location"))
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width-2))
	sb.WriteString("┘\n")

	return sb.String()
}

// ========================================
// Helper Functions
// ========================================

// extractNetworkNameFromURL extracts network name from full URL
func extractNetworkNameFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
