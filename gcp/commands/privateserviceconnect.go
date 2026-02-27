package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	networkendpointsservice "github.com/BishopFox/cloudfox/gcp/services/networkEndpointsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPrivateServiceConnectCommand = &cobra.Command{
	Use:     "private-service-connect",
	Aliases: []string{"psc", "private-endpoints", "internal-endpoints"},
	Short:   "Enumerate Private Service Connect endpoints and service attachments",
	Long: `Enumerate Private Service Connect (PSC) endpoints, private connections, and service attachments.

Private Service Connect allows private connectivity to Google APIs and services,
as well as to services hosted by other organizations.

Security Relevance:
- PSC endpoints provide internal network paths to external services
- Service attachments expose internal services to other projects
- Private connections (VPC peering for managed services) provide access to Cloud SQL, etc.
- These can be used for lateral movement or data exfiltration

What this module finds:
- PSC forwarding rules (consumer endpoints)
- Service attachments (producer endpoints)
- Private service connections (e.g., to Cloud SQL private IPs)
- Connection acceptance policies (auto vs manual)

Output includes nmap commands for scanning internal endpoints.`,
	Run: runGCPPrivateServiceConnectCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type PrivateServiceConnectModule struct {
	gcpinternal.BaseGCPModule

	ProjectPSCEndpoints       map[string][]networkendpointsservice.PrivateServiceConnectEndpoint // projectID -> endpoints
	ProjectPrivateConnections map[string][]networkendpointsservice.PrivateConnection             // projectID -> connections
	ProjectServiceAttachments map[string][]networkendpointsservice.ServiceAttachment             // projectID -> attachments
	LootMap                   map[string]map[string]*internal.LootFile                           // projectID -> loot files
	mu                        sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type PrivateServiceConnectOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivateServiceConnectOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivateServiceConnectOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPPrivateServiceConnectCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, "private-service-connect")
	if err != nil {
		return
	}

	module := &PrivateServiceConnectModule{
		BaseGCPModule:             gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPSCEndpoints:       make(map[string][]networkendpointsservice.PrivateServiceConnectEndpoint),
		ProjectPrivateConnections: make(map[string][]networkendpointsservice.PrivateConnection),
		ProjectServiceAttachments: make(map[string][]networkendpointsservice.ServiceAttachment),
		LootMap:                   make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *PrivateServiceConnectModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, "private-service-connect", m.processProject)

	allEndpoints := m.getAllPSCEndpoints()
	allConnections := m.getAllPrivateConnections()
	allAttachments := m.getAllServiceAttachments()

	totalFindings := len(allEndpoints) + len(allConnections) + len(allAttachments)

	if totalFindings == 0 {
		logger.InfoM("No private service connect endpoints found", "private-service-connect")
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d PSC endpoint(s), %d private connection(s), %d service attachment(s)",
		len(allEndpoints), len(allConnections), len(allAttachments)), "private-service-connect")

	// Count high-risk findings
	autoAcceptCount := 0
	for _, sa := range allAttachments {
		if sa.ConnectionPreference == "ACCEPT_AUTOMATIC" {
			autoAcceptCount++
		}
	}
	if autoAcceptCount > 0 {
		logger.InfoM(fmt.Sprintf("[High] %d service attachment(s) auto-accept connections from any project", autoAcceptCount), "private-service-connect")
	}

	m.writeOutput(ctx, logger)
}

func (m *PrivateServiceConnectModule) getAllPSCEndpoints() []networkendpointsservice.PrivateServiceConnectEndpoint {
	var all []networkendpointsservice.PrivateServiceConnectEndpoint
	for _, endpoints := range m.ProjectPSCEndpoints {
		all = append(all, endpoints...)
	}
	return all
}

func (m *PrivateServiceConnectModule) getAllPrivateConnections() []networkendpointsservice.PrivateConnection {
	var all []networkendpointsservice.PrivateConnection
	for _, conns := range m.ProjectPrivateConnections {
		all = append(all, conns...)
	}
	return all
}

func (m *PrivateServiceConnectModule) getAllServiceAttachments() []networkendpointsservice.ServiceAttachment {
	var all []networkendpointsservice.ServiceAttachment
	for _, attachments := range m.ProjectServiceAttachments {
		all = append(all, attachments...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *PrivateServiceConnectModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking private service connect in project: %s", projectID), "private-service-connect")
	}

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["private-service-connect-commands"] = &internal.LootFile{
			Name: "private-service-connect-commands",
			Contents: "# Private Service Connect Commands\n" +
				"# Generated by CloudFox\n" +
				"# WARNING: Only use with proper authorization\n" +
				"# NOTE: These are internal IPs - you must be on the VPC network to reach them\n\n",
		}
	}
	m.mu.Unlock()

	svc := networkendpointsservice.New()

	// Get PSC endpoints
	pscEndpoints, err := svc.GetPrivateServiceConnectEndpoints(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "private-service-connect",
			fmt.Sprintf("Could not get PSC endpoints in project %s", projectID))
	}

	// Get private connections
	privateConns, err := svc.GetPrivateConnections(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "private-service-connect",
			fmt.Sprintf("Could not get private connections in project %s", projectID))
	}

	// Get service attachments
	attachments, err := svc.GetServiceAttachments(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "private-service-connect",
			fmt.Sprintf("Could not get service attachments in project %s", projectID))
	}

	m.mu.Lock()
	m.ProjectPSCEndpoints[projectID] = append(m.ProjectPSCEndpoints[projectID], pscEndpoints...)
	m.ProjectPrivateConnections[projectID] = append(m.ProjectPrivateConnections[projectID], privateConns...)
	m.ProjectServiceAttachments[projectID] = append(m.ProjectServiceAttachments[projectID], attachments...)

	for _, endpoint := range pscEndpoints {
		m.addPSCEndpointToLoot(projectID, endpoint)
	}
	for _, conn := range privateConns {
		m.addPrivateConnectionToLoot(projectID, conn)
	}
	for _, attachment := range attachments {
		m.addServiceAttachmentToLoot(projectID, attachment)
	}
	m.mu.Unlock()
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *PrivateServiceConnectModule) addPSCEndpointToLoot(projectID string, endpoint networkendpointsservice.PrivateServiceConnectEndpoint) {
	lootFile := m.LootMap[projectID]["private-service-connect-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# PSC ENDPOINT: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Region: %s\n"+
			"# Network: %s, Subnet: %s\n"+
			"# Target Type: %s, Target: %s\n"+
			"# State: %s, IP: %s\n\n",
		endpoint.Name, endpoint.ProjectID, endpoint.Region,
		endpoint.Network, endpoint.Subnetwork,
		endpoint.TargetType, endpoint.Target,
		endpoint.ConnectionState, endpoint.IPAddress,
	)

	lootFile.Contents += "# === ENUMERATION COMMANDS ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"# Describe forwarding rule:\n"+
			"gcloud compute forwarding-rules describe %s --region=%s --project=%s\n\n",
		endpoint.Name, endpoint.Region, endpoint.ProjectID,
	)

	if endpoint.IPAddress != "" {
		lootFile.Contents += "# === EXPLOIT COMMANDS ===\n\n"
		lootFile.Contents += fmt.Sprintf(
			"# Scan internal endpoint (from within VPC):\n"+
				"nmap -sV -Pn %s\n\n",
			endpoint.IPAddress,
		)
	}
}

func (m *PrivateServiceConnectModule) addPrivateConnectionToLoot(projectID string, conn networkendpointsservice.PrivateConnection) {
	lootFile := m.LootMap[projectID]["private-service-connect-commands"]
	if lootFile == nil {
		return
	}
	reservedRanges := "-"
	if len(conn.ReservedRanges) > 0 {
		reservedRanges = strings.Join(conn.ReservedRanges, ", ")
	}
	accessibleServices := "-"
	if len(conn.AccessibleServices) > 0 {
		accessibleServices = strings.Join(conn.AccessibleServices, ", ")
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# PRIVATE CONNECTION: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n"+
			"# Network: %s, Service: %s\n"+
			"# Peering: %s\n"+
			"# Reserved Ranges: %s\n"+
			"# Accessible Services: %s\n\n",
		conn.Name, conn.ProjectID,
		conn.Network, conn.Service,
		conn.PeeringName,
		reservedRanges,
		accessibleServices,
	)

	lootFile.Contents += "# === ENUMERATION COMMANDS ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"# List private connections:\n"+
			"gcloud services vpc-peerings list --network=%s --project=%s\n\n",
		conn.Network, conn.ProjectID,
	)

	// Add nmap commands for each reserved range
	if len(conn.ReservedRanges) > 0 {
		lootFile.Contents += "# === EXPLOIT COMMANDS ===\n\n"
	}
	for _, ipRange := range conn.ReservedRanges {
		lootFile.Contents += fmt.Sprintf(
			"# Scan private connection range (from within VPC):\n"+
				"nmap -sV -Pn %s\n\n",
			ipRange,
		)
	}
}

func (m *PrivateServiceConnectModule) addServiceAttachmentToLoot(projectID string, attachment networkendpointsservice.ServiceAttachment) {
	lootFile := m.LootMap[projectID]["private-service-connect-commands"]
	if lootFile == nil {
		return
	}
	natSubnets := "-"
	if len(attachment.NatSubnets) > 0 {
		natSubnets = strings.Join(attachment.NatSubnets, ", ")
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# SERVICE ATTACHMENT: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Region: %s\n"+
			"# Target Service: %s\n"+
			"# Connection Preference: %s\n"+
			"# Connected Endpoints: %d\n"+
			"# NAT Subnets: %s\n",
		attachment.Name,
		attachment.ProjectID, attachment.Region,
		attachment.TargetService,
		attachment.ConnectionPreference,
		attachment.ConnectedEndpoints,
		natSubnets,
	)

	if len(attachment.ConsumerAcceptLists) > 0 {
		lootFile.Contents += fmt.Sprintf("# Accept List: %s\n", strings.Join(attachment.ConsumerAcceptLists, ", "))
	}
	if len(attachment.ConsumerRejectLists) > 0 {
		lootFile.Contents += fmt.Sprintf("# Reject List: %s\n", strings.Join(attachment.ConsumerRejectLists, ", "))
	}

	// Add IAM bindings info
	if len(attachment.IAMBindings) > 0 {
		lootFile.Contents += "# IAM Bindings:\n"
		for _, binding := range attachment.IAMBindings {
			lootFile.Contents += fmt.Sprintf("#   %s -> %s\n", binding.Role, binding.Member)
		}
	}

	lootFile.Contents += "\n# === ENUMERATION COMMANDS ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"# Describe service attachment:\n"+
			"gcloud compute service-attachments describe %s --region=%s --project=%s\n\n"+
			"# Get IAM policy:\n"+
			"gcloud compute service-attachments get-iam-policy %s --region=%s --project=%s\n\n",
		attachment.Name, attachment.Region, attachment.ProjectID,
		attachment.Name, attachment.Region, attachment.ProjectID,
	)

	// If auto-accept, add exploitation command
	if attachment.ConnectionPreference == "ACCEPT_AUTOMATIC" {
		lootFile.Contents += "# === EXPLOIT COMMANDS ===\n\n"
		lootFile.Contents += fmt.Sprintf(
			"# [HIGH RISK] This service attachment accepts connections from ANY project!\n"+
				"# To connect from another project:\n"+
				"gcloud compute forwarding-rules create attacker-psc-endpoint \\\n"+
				"  --region=%s \\\n"+
				"  --network=ATTACKER_VPC \\\n"+
				"  --address=RESERVED_IP \\\n"+
				"  --target-service-attachment=projects/%s/regions/%s/serviceAttachments/%s\n\n",
			attachment.Region,
			attachment.ProjectID, attachment.Region, attachment.Name,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PrivateServiceConnectModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *PrivateServiceConnectModule) getPSCEndpointsHeader() []string {
	return []string{
		"Project", "Name", "Region", "Network",
		"Subnet", "IP Address", "Target Type", "Target", "State",
	}
}

func (m *PrivateServiceConnectModule) getPrivateConnectionsHeader() []string {
	return []string{
		"Project", "Name", "Network", "Service",
		"Peering Name", "Reserved Ranges", "Accessible Services",
	}
}

func (m *PrivateServiceConnectModule) getServiceAttachmentsHeader() []string {
	return []string{
		"Project", "Name", "Region", "Target Service",
		"Accept Policy", "Connected", "NAT Subnets", "IAM Binding Role", "IAM Binding Principal",
	}
}

func (m *PrivateServiceConnectModule) pscEndpointsToTableBody(endpoints []networkendpointsservice.PrivateServiceConnectEndpoint) [][]string {
	var body [][]string
	for _, ep := range endpoints {
		body = append(body, []string{
			m.GetProjectName(ep.ProjectID), ep.Name, ep.Region,
			ep.Network, ep.Subnetwork, ep.IPAddress, ep.TargetType, ep.Target, ep.ConnectionState,
		})
	}
	return body
}

func (m *PrivateServiceConnectModule) privateConnectionsToTableBody(conns []networkendpointsservice.PrivateConnection) [][]string {
	var body [][]string
	for _, conn := range conns {
		reservedRanges := "-"
		if len(conn.ReservedRanges) > 0 {
			reservedRanges = strings.Join(conn.ReservedRanges, ", ")
		}
		accessibleServices := "-"
		if len(conn.AccessibleServices) > 0 {
			accessibleServices = strings.Join(conn.AccessibleServices, ", ")
		}
		body = append(body, []string{
			m.GetProjectName(conn.ProjectID), conn.Name, conn.Network,
			conn.Service, conn.PeeringName, reservedRanges, accessibleServices,
		})
	}
	return body
}

func (m *PrivateServiceConnectModule) serviceAttachmentsToTableBody(attachments []networkendpointsservice.ServiceAttachment) [][]string {
	var body [][]string
	for _, att := range attachments {
		natSubnets := "-"
		if len(att.NatSubnets) > 0 {
			natSubnets = strings.Join(att.NatSubnets, ", ")
		}
		if len(att.IAMBindings) > 0 {
			for _, binding := range att.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(att.ProjectID), att.Name, att.Region,
					att.TargetService, att.ConnectionPreference, fmt.Sprintf("%d", att.ConnectedEndpoints),
					natSubnets, binding.Role, binding.Member,
				})
			}
		} else {
			body = append(body, []string{
				m.GetProjectName(att.ProjectID), att.Name, att.Region,
				att.TargetService, att.ConnectionPreference, fmt.Sprintf("%d", att.ConnectedEndpoints),
				natSubnets, "-", "-",
			})
		}
	}
	return body
}

func (m *PrivateServiceConnectModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if eps, ok := m.ProjectPSCEndpoints[projectID]; ok && len(eps) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name: "psc-endpoints", Header: m.getPSCEndpointsHeader(), Body: m.pscEndpointsToTableBody(eps),
		})
	}
	if conns, ok := m.ProjectPrivateConnections[projectID]; ok && len(conns) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name: "private-connections", Header: m.getPrivateConnectionsHeader(), Body: m.privateConnectionsToTableBody(conns),
		})
	}
	if atts, ok := m.ProjectServiceAttachments[projectID]; ok && len(atts) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name: "service-attachments", Header: m.getServiceAttachmentsHeader(), Body: m.serviceAttachmentsToTableBody(atts),
		})
	}
	return tableFiles
}

func (m *PrivateServiceConnectModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectPSCEndpoints {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectPrivateConnections {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectServiceAttachments {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		tableFiles := m.buildTablesForProject(projectID)
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# NOTE: These are internal IPs - you must be on the VPC network to reach them\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}
		outputData.ProjectLevelData[projectID] = PrivateServiceConnectOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()
	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), "private-service-connect")
	}
}

func (m *PrivateServiceConnectModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	allEndpoints := m.getAllPSCEndpoints()
	if len(allEndpoints) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "psc-endpoints", Header: m.getPSCEndpointsHeader(), Body: m.pscEndpointsToTableBody(allEndpoints),
		})
	}

	allConns := m.getAllPrivateConnections()
	if len(allConns) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "private-connections", Header: m.getPrivateConnectionsHeader(), Body: m.privateConnectionsToTableBody(allConns),
		})
	}

	allAtts := m.getAllServiceAttachments()
	if len(allAtts) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "service-attachments", Header: m.getServiceAttachmentsHeader(), Body: m.serviceAttachmentsToTableBody(allAtts),
		})
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# NOTE: These are internal IPs - you must be on the VPC network to reach them\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := PrivateServiceConnectOutput{Table: tables, Loot: lootFiles}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), "private-service-connect")
		m.CommandCounter.Error++
	}
}
