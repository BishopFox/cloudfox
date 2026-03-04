package commands

import (
	"github.com/BishopFox/cloudfox/gcp/shared"
	"context"
	"fmt"
	"strings"
	"sync"

	diagramservice "github.com/BishopFox/cloudfox/gcp/services/diagramService"
	NetworkService "github.com/BishopFox/cloudfox/gcp/services/networkService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPFirewallCommand = &cobra.Command{
	Use:     globals.GCP_FIREWALL_MODULE_NAME,
	Aliases: []string{"fw", "firewall-rules", "network-security"},
	Short:   "Enumerate VPC networks and firewall rules with security analysis",
	Long: `Enumerate VPC networks, subnets, and firewall rules across projects with security analysis.

Features:
- Lists all VPC networks and their peering relationships
- Shows all subnets with CIDR ranges and configurations
- Enumerates firewall rules with security risk analysis
- Identifies overly permissive rules (0.0.0.0/0 ingress)
- Detects exposed sensitive ports (SSH, RDP, databases)
- Generates gcloud commands for remediation

Security Columns:
- Risk: HIGH, MEDIUM, LOW based on exposure analysis
- Direction: INGRESS or EGRESS
- Source: Source IP ranges (0.0.0.0/0 = internet)
- Ports: Allowed ports and protocols
- Issues: Detected security misconfigurations

Attack Surface:
- 0.0.0.0/0 ingress allows internet access to resources
- All ports allowed means no port restrictions
- No target tags means rule applies to ALL instances
- VPC peering may expose internal resources`,
	Run: runGCPFirewallCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type FirewallModule struct {
	gcpinternal.BaseGCPModule

	// Per-project data for hierarchical output
	ProjectNetworks      map[string][]NetworkService.VPCInfo
	ProjectSubnets       map[string][]NetworkService.SubnetInfo
	ProjectFirewallRules map[string][]NetworkService.FirewallRuleInfo
	LootMap              map[string]map[string]*internal.LootFile
	mu                   sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type FirewallOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FirewallOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FirewallOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPFirewallCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_FIREWALL_MODULE_NAME)
	if err != nil {
		return
	}

	module := &FirewallModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectNetworks:      make(map[string][]NetworkService.VPCInfo),
		ProjectSubnets:       make(map[string][]NetworkService.SubnetInfo),
		ProjectFirewallRules: make(map[string][]NetworkService.FirewallRuleInfo),
		LootMap:              make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *FirewallModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_FIREWALL_MODULE_NAME, m.processProject)

	// Get all data for stats
	allNetworks := m.getAllNetworks()
	allSubnets := m.getAllSubnets()
	allRules := m.getAllFirewallRules()

	if len(allRules) == 0 && len(allNetworks) == 0 {
		logger.InfoM("No networks or firewall rules found", globals.GCP_FIREWALL_MODULE_NAME)
		return
	}

	// Count public ingress rules and peerings
	publicIngressCount := 0
	for _, rule := range allRules {
		if rule.IsPublicIngress {
			publicIngressCount++
		}
	}

	peeringCount := 0
	for _, network := range allNetworks {
		peeringCount += len(network.Peerings)
	}

	msg := fmt.Sprintf("Found %d network(s), %d subnet(s), %d firewall rule(s)",
		len(allNetworks), len(allSubnets), len(allRules))
	if publicIngressCount > 0 {
		msg += fmt.Sprintf(" [%d public ingress]", publicIngressCount)
	}
	if peeringCount > 0 {
		msg += fmt.Sprintf(" [%d peerings]", peeringCount)
	}
	logger.SuccessM(msg, globals.GCP_FIREWALL_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllNetworks returns all networks from all projects
func (m *FirewallModule) getAllNetworks() []NetworkService.VPCInfo {
	var all []NetworkService.VPCInfo
	for _, networks := range m.ProjectNetworks {
		all = append(all, networks...)
	}
	return all
}

// getAllSubnets returns all subnets from all projects
func (m *FirewallModule) getAllSubnets() []NetworkService.SubnetInfo {
	var all []NetworkService.SubnetInfo
	for _, subnets := range m.ProjectSubnets {
		all = append(all, subnets...)
	}
	return all
}

// getAllFirewallRules returns all firewall rules from all projects
func (m *FirewallModule) getAllFirewallRules() []NetworkService.FirewallRuleInfo {
	var all []NetworkService.FirewallRuleInfo
	for _, rules := range m.ProjectFirewallRules {
		all = append(all, rules...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *FirewallModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating networks and firewall in project: %s", projectID), globals.GCP_FIREWALL_MODULE_NAME)
	}

	ns := NetworkService.New()

	// Initialize loot for this project
	m.mu.Lock()
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["firewall-commands"] = &internal.LootFile{
			Name:     "firewall-commands",
			Contents: "# Firewall Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
	m.mu.Unlock()

	var networks []NetworkService.VPCInfo
	var subnets []NetworkService.SubnetInfo
	var rules []NetworkService.FirewallRuleInfo

	// Get networks
	var err error
	networks, err = ns.Networks(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FIREWALL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate networks in project %s", projectID))
	}

	// Get subnets
	subnets, err = ns.Subnets(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FIREWALL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate subnets in project %s", projectID))
	}

	// Get firewall rules
	rules, err = ns.FirewallRulesEnhanced(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FIREWALL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate firewall rules in project %s", projectID))
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectNetworks[projectID] = networks
	m.ProjectSubnets[projectID] = subnets
	m.ProjectFirewallRules[projectID] = rules

	for _, network := range networks {
		m.addNetworkToLoot(projectID, network)
	}
	for _, rule := range rules {
		m.addFirewallRuleToLoot(projectID, rule)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d network(s), %d subnet(s), %d rule(s) in project %s",
			len(networks), len(subnets), len(rules), projectID), globals.GCP_FIREWALL_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *FirewallModule) addNetworkToLoot(projectID string, network NetworkService.VPCInfo) {
	lootFile := m.LootMap[projectID]["firewall-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# NETWORK: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n\n"+
			"gcloud compute networks describe %s --project=%s\n"+
			"gcloud compute networks subnets list --network=%s --project=%s\n"+
			"gcloud compute firewall-rules list --filter=\"network:%s\" --project=%s\n\n",
		network.Name,
		network.ProjectID,
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
	)
}

func (m *FirewallModule) addFirewallRuleToLoot(projectID string, rule NetworkService.FirewallRuleInfo) {
	lootFile := m.LootMap[projectID]["firewall-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# RULE: %s\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Network: %s\n"+
			"# Project: %s\n"+
			"# Direction: %s\n"+
			"# Priority: %d\n"+
			"# Disabled: %v\n",
		rule.Name, rule.Network, rule.ProjectID,
		rule.Direction, rule.Priority, rule.Disabled,
	)

	lootFile.Contents += fmt.Sprintf(
		"\n# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe rule:\n"+
			"gcloud compute firewall-rules describe %s --project=%s\n\n"+
			"# List all rules for this network:\n"+
			"gcloud compute firewall-rules list --filter=\"network:%s\" --project=%s --sort-by=priority\n\n",
		rule.Name, rule.ProjectID,
		rule.Network, rule.ProjectID,
	)

	// Exploit commands
	lootFile.Contents += fmt.Sprintf(
		"# === EXPLOIT COMMANDS ===\n\n"+
			"# Disable this firewall rule:\n"+
			"gcloud compute firewall-rules update %s --disabled --project=%s\n\n"+
			"# Create a permissive rule to allow all inbound traffic:\n"+
			"gcloud compute firewall-rules create cloudfox-allow-all --network=%s --allow=tcp,udp,icmp --source-ranges=0.0.0.0/0 --priority=1 --project=%s\n\n"+
			"# Create rule to allow SSH from your IP:\n"+
			"gcloud compute firewall-rules create cloudfox-ssh --network=%s --allow=tcp:22 --source-ranges=YOUR_IP/32 --priority=100 --project=%s\n\n"+
			"# Delete this firewall rule:\n"+
			"gcloud compute firewall-rules delete %s --project=%s\n\n",
		rule.Name, rule.ProjectID,
		rule.Network, rule.ProjectID,
		rule.Network, rule.ProjectID,
		rule.Name, rule.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *FirewallModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Generate ASCII diagram and add to loot
	diagram := m.generateFirewallDiagram()
	if diagram != "" {
		// Add diagram to the first project's loot (or create a combined one)
		for projectID := range m.LootMap {
			if m.LootMap[projectID] == nil {
				m.LootMap[projectID] = make(map[string]*internal.LootFile)
			}
			m.LootMap[projectID]["firewall-diagram"] = &internal.LootFile{
				Name:     "firewall-diagram",
				Contents: diagram,
			}
			break // Only add once for flat output
		}

		// For hierarchical output, add to all projects
		if m.Hierarchy != nil && !m.FlatOutput {
			for projectID := range m.LootMap {
				if m.LootMap[projectID] == nil {
					m.LootMap[projectID] = make(map[string]*internal.LootFile)
				}
				m.LootMap[projectID]["firewall-diagram"] = &internal.LootFile{
					Name:     "firewall-diagram",
					Contents: diagram,
				}
			}
		}
	}

	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// Table headers
func (m *FirewallModule) getRulesHeader() []string {
	return []string{
		"Project", "Rule Name", "Network", "Direction",
		"Priority", "Source Ranges", "Allowed", "Targets", "Disabled", "Logging",
	}
}

func (m *FirewallModule) getNetworksHeader() []string {
	return []string{
		"Project", "Network Name", "Routing Mode",
		"Subnets", "Peerings", "Auto Subnets",
	}
}

func (m *FirewallModule) getSubnetsHeader() []string {
	return []string{
		"Project", "Network", "Subnet Name",
		"Region", "CIDR Range", "Private Google Access",
	}
}

// rulesToTableBody converts rules to table body rows
func (m *FirewallModule) rulesToTableBody(rules []NetworkService.FirewallRuleInfo) [][]string {
	var body [][]string
	for _, rule := range rules {
		sources := strings.Join(rule.SourceRanges, ", ")
		if sources == "" {
			sources = "-"
		}

		allowed := formatProtocols(rule.AllowedProtocols)
		if allowed == "" {
			allowed = "-"
		}

		targets := "-"
		if len(rule.TargetTags) > 0 {
			targets = strings.Join(rule.TargetTags, ", ")
		} else if len(rule.TargetSAs) > 0 {
			targets = strings.Join(rule.TargetSAs, ", ")
		} else {
			targets = "ALL"
		}

		body = append(body, []string{
			m.GetProjectName(rule.ProjectID),
			rule.Name,
			rule.Network,
			rule.Direction,
			fmt.Sprintf("%d", rule.Priority),
			sources,
			allowed,
			targets,
			shared.BoolToYesNo(rule.Disabled),
			shared.BoolToYesNo(rule.LoggingEnabled),
		})
	}
	return body
}

// networksToTableBody converts networks to table body rows
func (m *FirewallModule) networksToTableBody(networks []NetworkService.VPCInfo) [][]string {
	var body [][]string
	for _, network := range networks {
		subnetCount := len(network.Subnetworks)

		peerings := "-"
		if len(network.Peerings) > 0 {
			var peerNames []string
			for _, p := range network.Peerings {
				peerNames = append(peerNames, p.Name)
			}
			peerings = strings.Join(peerNames, ", ")
		}

		body = append(body, []string{
			m.GetProjectName(network.ProjectID),
			network.Name,
			network.RoutingMode,
			fmt.Sprintf("%d", subnetCount),
			peerings,
			shared.BoolToYesNo(network.AutoCreateSubnetworks),
		})
	}
	return body
}

// subnetsToTableBody converts subnets to table body rows
func (m *FirewallModule) subnetsToTableBody(subnets []NetworkService.SubnetInfo) [][]string {
	var body [][]string
	for _, subnet := range subnets {
		body = append(body, []string{
			m.GetProjectName(subnet.ProjectID),
			subnet.Network,
			subnet.Name,
			subnet.Region,
			subnet.IPCidrRange,
			shared.BoolToYesNo(subnet.PrivateIPGoogleAccess),
		})
	}
	return body
}

// buildTablesForProject builds all tables for given project data
func (m *FirewallModule) buildTablesForProject(networks []NetworkService.VPCInfo, subnets []NetworkService.SubnetInfo, rules []NetworkService.FirewallRuleInfo) []internal.TableFile {
	var tableFiles []internal.TableFile

	rulesBody := m.rulesToTableBody(rules)
	if len(rulesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FIREWALL_MODULE_NAME + "-rules",
			Header: m.getRulesHeader(),
			Body:   rulesBody,
		})
	}

	networksBody := m.networksToTableBody(networks)
	if len(networksBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FIREWALL_MODULE_NAME + "-networks",
			Header: m.getNetworksHeader(),
			Body:   networksBody,
		})
	}

	subnetsBody := m.subnetsToTableBody(subnets)
	if len(subnetsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FIREWALL_MODULE_NAME + "-subnets",
			Header: m.getSubnetsHeader(),
			Body:   subnetsBody,
		})
	}

	return tableFiles
}

// writeHierarchicalOutput writes output to per-project directories
func (m *FirewallModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all projects with data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectNetworks {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectSubnets {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectFirewallRules {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		networks := m.ProjectNetworks[projectID]
		subnets := m.ProjectSubnets[projectID]
		rules := m.ProjectFirewallRules[projectID]

		tableFiles := m.buildTablesForProject(networks, subnets, rules)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = FirewallOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_FIREWALL_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *FirewallModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allNetworks := m.getAllNetworks()
	allSubnets := m.getAllSubnets()
	allRules := m.getAllFirewallRules()

	tableFiles := m.buildTablesForProject(allNetworks, allSubnets, allRules)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := FirewallOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_FIREWALL_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// ------------------------------
// Diagram Generation
// ------------------------------

// generateFirewallDiagram creates an ASCII visualization of firewall rules
func (m *FirewallModule) generateFirewallDiagram() string {
	allRules := m.getAllFirewallRules()
	if len(allRules) == 0 {
		return ""
	}

	// Group rules by network
	rulesByNetwork := make(map[string][]NetworkService.FirewallRuleInfo)
	for _, rule := range allRules {
		key := rule.ProjectID + "/" + rule.Network
		rulesByNetwork[key] = append(rulesByNetwork[key], rule)
	}

	var sb strings.Builder
	width := 90

	// Header
	sb.WriteString(diagramservice.DrawBox("GCP FIREWALL RULES DIAGRAM - Generated by CloudFox", width))
	sb.WriteString("\n")

	// Draw diagram for each network
	for key, rules := range rulesByNetwork {
		parts := strings.SplitN(key, "/", 2)
		projectID := ""
		networkName := key
		if len(parts) == 2 {
			projectID = parts[0]
			networkName = parts[1]
		}

		// Convert to diagram service types
		diagramRules := make([]diagramservice.FirewallRuleInfo, 0, len(rules))
		for _, r := range rules {
			allowedPorts := formatProtocols(r.AllowedProtocols)
			if allowedPorts == "" {
				allowedPorts = "*"
			}

			targets := "ALL"
			if len(r.TargetTags) > 0 {
				targets = strings.Join(r.TargetTags, ", ")
			} else if len(r.TargetSAs) > 0 {
				targets = strings.Join(r.TargetSAs, ", ")
			}

			diagramRules = append(diagramRules, diagramservice.FirewallRuleInfo{
				Name:            r.Name,
				Direction:       r.Direction,
				Priority:        r.Priority,
				SourceRanges:    r.SourceRanges,
				AllowedPorts:    allowedPorts,
				TargetTags:      targets,
				IsPublicIngress: r.IsPublicIngress,
				Disabled:        r.Disabled,
			})
		}

		sb.WriteString(diagramservice.DrawFirewallDiagram(diagramRules, networkName, projectID, width))
		sb.WriteString("\n")
	}

	return sb.String()
}

// Helper functions

// formatProtocols formats allowed/denied protocols for display
func formatProtocols(protocols map[string][]string) string {
	var parts []string
	for proto, ports := range protocols {
		if len(ports) == 0 {
			parts = append(parts, proto+":all")
		} else {
			parts = append(parts, proto+":"+strings.Join(ports, ","))
		}
	}
	return strings.Join(parts, "; ")
}

