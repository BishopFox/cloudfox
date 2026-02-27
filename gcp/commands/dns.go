package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	DNSService "github.com/BishopFox/cloudfox/gcp/services/dnsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPDNSCommand = &cobra.Command{
	Use:     globals.GCP_DNS_MODULE_NAME,
	Aliases: []string{"zones", "cloud-dns"},
	Short:   "Enumerate Cloud DNS zones and records with security analysis",
	Long: `Enumerate Cloud DNS managed zones and records across projects.

Features:
- Lists all DNS managed zones (public and private)
- Shows zone configuration (DNSSEC, visibility, peering)
- Enumerates DNS records for each zone
- Identifies interesting records (A, CNAME, TXT, MX)
- Shows private zone VPC bindings
- Generates gcloud commands for DNS management

Security Columns:
- Visibility: public or private
- DNSSEC: Whether DNSSEC is enabled
- Networks: VPC networks for private zones
- Peering: Cross-project DNS peering

Attack Surface:
- Public zones expose domain infrastructure
- TXT records may contain sensitive info (SPF, DKIM, verification)
- Private zones indicate internal network structure
- DNS forwarding may expose internal resolvers`,
	Run: runGCPDNSCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type DNSModule struct {
	gcpinternal.BaseGCPModule

	ProjectZones   map[string][]DNSService.ZoneInfo          // projectID -> zones
	ProjectRecords map[string][]DNSService.RecordInfo        // projectID -> records
	TakeoverRisks  []DNSService.TakeoverRisk                 // kept global for summary
	LootMap        map[string]map[string]*internal.LootFile  // projectID -> loot files
	mu             sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type DNSOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DNSOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DNSOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDNSCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_DNS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DNSModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectZones:   make(map[string][]DNSService.ZoneInfo),
		ProjectRecords: make(map[string][]DNSService.RecordInfo),
		TakeoverRisks:  []DNSService.TakeoverRisk{},
		LootMap:        make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DNSModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_DNS_MODULE_NAME, m.processProject)

	allZones := m.getAllZones()
	allRecords := m.getAllRecords()

	if len(allZones) == 0 {
		logger.InfoM("No DNS zones found", globals.GCP_DNS_MODULE_NAME)
		return
	}

	// Count zone types and security issues
	publicCount := 0
	privateCount := 0
	transferModeCount := 0
	dnssecOffCount := 0

	for _, zone := range allZones {
		if zone.Visibility == "public" {
			publicCount++
			// Check DNSSEC status for public zones
			if zone.DNSSECState == "" || zone.DNSSECState == "off" {
				dnssecOffCount++
			} else if zone.DNSSECState == "transfer" {
				transferModeCount++
			}
		} else {
			privateCount++
		}
	}

	// Check for subdomain takeover risks
	ds := DNSService.New()
	m.TakeoverRisks = ds.CheckTakeoverRisks(allRecords)

	msg := fmt.Sprintf("Found %d zone(s), %d record(s)", len(allZones), len(allRecords))
	if publicCount > 0 {
		msg += fmt.Sprintf(" [%d public]", publicCount)
	}
	if privateCount > 0 {
		msg += fmt.Sprintf(" [%d private]", privateCount)
	}
	logger.SuccessM(msg, globals.GCP_DNS_MODULE_NAME)

	// Log security warnings
	if dnssecOffCount > 0 {
		logger.InfoM(fmt.Sprintf("[SECURITY] %d public zone(s) have DNSSEC disabled", dnssecOffCount), globals.GCP_DNS_MODULE_NAME)
	}
	if transferModeCount > 0 {
		logger.InfoM(fmt.Sprintf("[SECURITY] %d zone(s) in DNSSEC transfer mode (vulnerable during migration)", transferModeCount), globals.GCP_DNS_MODULE_NAME)
	}
	if len(m.TakeoverRisks) > 0 {
		logger.InfoM(fmt.Sprintf("[SECURITY] %d potential subdomain takeover risk(s) detected", len(m.TakeoverRisks)), globals.GCP_DNS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// getAllZones returns all zones from all projects
func (m *DNSModule) getAllZones() []DNSService.ZoneInfo {
	var all []DNSService.ZoneInfo
	for _, zones := range m.ProjectZones {
		all = append(all, zones...)
	}
	return all
}

// getAllRecords returns all records from all projects
func (m *DNSModule) getAllRecords() []DNSService.RecordInfo {
	var all []DNSService.RecordInfo
	for _, records := range m.ProjectRecords {
		all = append(all, records...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DNSModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating DNS in project: %s", projectID), globals.GCP_DNS_MODULE_NAME)
	}

	ds := DNSService.New()

	// Get zones
	zones, err := ds.Zones(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DNS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate DNS zones in project %s", projectID))
		return
	}

	var projectRecords []DNSService.RecordInfo

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["dns-commands"] = &internal.LootFile{
			Name:     "dns-commands",
			Contents: "# Cloud DNS Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
	m.mu.Unlock()

	for _, zone := range zones {
		m.mu.Lock()
		m.addZoneToLoot(projectID, zone)
		m.mu.Unlock()

		// Get records for each zone (outside of lock to avoid holding mutex across API call)
		records, err := ds.Records(projectID, zone.Name)
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_DNS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate DNS records in zone %s", zone.Name))
			continue
		}

		projectRecords = append(projectRecords, records...)
	}

	m.mu.Lock()
	m.ProjectZones[projectID] = zones
	m.ProjectRecords[projectID] = projectRecords
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d zone(s) in project %s", len(zones), projectID), globals.GCP_DNS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DNSModule) addZoneToLoot(projectID string, zone DNSService.ZoneInfo) {
	lootFile := m.LootMap[projectID]["dns-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# DNS ZONE: %s (%s)\n"+
			"# =============================================================================\n"+
			"# Project: %s, Visibility: %s\n",
		zone.Name, zone.DNSName,
		zone.ProjectID, zone.Visibility,
	)

	lootFile.Contents += fmt.Sprintf(`
# === ENUMERATION COMMANDS ===

# Describe zone:
gcloud dns managed-zones describe %s --project=%s

# List all record sets:
gcloud dns record-sets list --zone=%s --project=%s

# Export all records (for offline analysis):
gcloud dns record-sets export /tmp/dns-%s.zone --zone=%s --project=%s

# List DNSSEC config:
gcloud dns managed-zones describe %s --project=%s --format=json | jq '.dnssecConfig'

`, zone.Name, zone.ProjectID,
		zone.Name, zone.ProjectID,
		zone.Name, zone.Name, zone.ProjectID,
		zone.Name, zone.ProjectID,
	)

	// === EXPLOIT COMMANDS ===
	lootFile.Contents += "# === EXPLOIT COMMANDS ===\n\n"

	// DNS validation and takeover checks
	lootFile.Contents += fmt.Sprintf(
		"# Validate DNS resolution for the zone:\n"+
			"dig %s ANY +short\n"+
			"nslookup %s\n\n"+
			"# Check for dangling CNAME records (subdomain takeover):\n"+
			"gcloud dns record-sets list --zone=%s --project=%s --filter=\"type=CNAME\" --format=\"table(name,rrdatas)\"\n\n"+
			"# Test each CNAME for dangling records:\n"+
			"# for cname in $(gcloud dns record-sets list --zone=%s --project=%s --filter=\"type=CNAME\" --format=\"value(rrdatas)\"); do\n"+
			"#   echo -n \"$cname: \"; dig +short $cname || echo \"DANGLING - potential takeover!\"\n"+
			"# done\n\n"+
			"# Check NS records (for delegation attacks):\n"+
			"dig %s NS +short\n\n",
		zone.DNSName, zone.DNSName,
		zone.Name, zone.ProjectID,
		zone.Name, zone.ProjectID,
		zone.DNSName,
	)

	// Zone modification commands
	lootFile.Contents += fmt.Sprintf(
		"# Add a DNS record (requires dns.changes.create):\n"+
			"gcloud dns record-sets create test.%s --zone=%s --type=A --ttl=300 --rrdatas=YOUR_IP --project=%s\n\n"+
			"# Modify existing record (DNS hijacking):\n"+
			"gcloud dns record-sets update www.%s --zone=%s --type=A --ttl=300 --rrdatas=YOUR_IP --project=%s\n\n",
		zone.DNSName, zone.Name, zone.ProjectID,
		zone.DNSName, zone.Name, zone.ProjectID,
	)

	if zone.Visibility == "public" {
		lootFile.Contents += "# [FINDING] This is a PUBLIC zone - records are resolvable from the internet\n\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *DNSModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getZonesHeader returns the header for the zones table
func (m *DNSModule) getZonesHeader() []string {
	return []string{
		"Project",
		"Zone Name",
		"DNS Name",
		"Visibility",
		"DNSSEC",
		"Security",
		"Networks/Peering",
		"Forwarding",
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

// getRecordsHeader returns the header for the records table
func (m *DNSModule) getRecordsHeader() []string {
	return []string{
		"Zone",
		"Name",
		"Type",
		"TTL",
		"Data",
		"Takeover Risk",
	}
}

// zonesToTableBody converts zones to table body rows
func (m *DNSModule) zonesToTableBody(zones []DNSService.ZoneInfo) [][]string {
	var body [][]string
	for _, zone := range zones {
		dnssec := zone.DNSSECState
		if dnssec == "" {
			dnssec = "off"
		}

		security := "-"
		if zone.Visibility == "public" {
			if zone.DNSSECState == "" || zone.DNSSECState == "off" {
				security = "DNSSEC Disabled"
			} else if zone.DNSSECState == "transfer" {
				security = "Transfer Mode (Vulnerable)"
			} else if zone.DNSSECState == "on" {
				security = "OK"
			}
		}

		networkInfo := "-"
		if len(zone.PrivateNetworks) > 0 {
			networkInfo = strings.Join(zone.PrivateNetworks, ", ")
		} else if zone.PeeringNetwork != "" {
			networkInfo = fmt.Sprintf("Peering: %s", zone.PeeringNetwork)
			if zone.PeeringTargetProject != "" {
				networkInfo += fmt.Sprintf(" (%s)", zone.PeeringTargetProject)
			}
		}

		forwarding := "-"
		if len(zone.ForwardingTargets) > 0 {
			forwarding = strings.Join(zone.ForwardingTargets, ", ")
		}

		if len(zone.IAMBindings) > 0 {
			for _, binding := range zone.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(zone.ProjectID), zone.Name, zone.DNSName,
					zone.Visibility, dnssec, security, networkInfo, forwarding, binding.Role, binding.Member,
				})
			}
		} else {
			body = append(body, []string{
				m.GetProjectName(zone.ProjectID), zone.Name, zone.DNSName,
				zone.Visibility, dnssec, security, networkInfo, forwarding, "-", "-",
			})
		}
	}
	return body
}

// recordsToTableBody converts records to table body rows
func (m *DNSModule) recordsToTableBody(records []DNSService.RecordInfo) [][]string {
	takeoverRiskMap := make(map[string]DNSService.TakeoverRisk)
	for _, risk := range m.TakeoverRisks {
		takeoverRiskMap[risk.RecordName] = risk
	}

	var body [][]string
	interestingTypes := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "SRV": true}
	for _, record := range records {
		if !interestingTypes[record.Type] {
			continue
		}

		data := strings.Join(record.RRDatas, ", ")
		takeoverRisk := "-"
		if risk, exists := takeoverRiskMap[record.Name]; exists {
			takeoverRisk = fmt.Sprintf("%s (%s)", risk.RiskLevel, risk.Service)
		}

		body = append(body, []string{
			record.ZoneName, record.Name, record.Type, fmt.Sprintf("%d", record.TTL), data, takeoverRisk,
		})
	}
	return body
}

// buildTablesForProject builds table files for a single project
func (m *DNSModule) buildTablesForProject(projectID string) []internal.TableFile {
	zones := m.ProjectZones[projectID]
	records := m.ProjectRecords[projectID]

	zonesBody := m.zonesToTableBody(zones)
	recordsBody := m.recordsToTableBody(records)

	var tableFiles []internal.TableFile
	if len(zonesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_DNS_MODULE_NAME + "-zones",
			Header: m.getZonesHeader(),
			Body:   zonesBody,
		})
	}
	if len(recordsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_DNS_MODULE_NAME + "-records",
			Header: m.getRecordsHeader(),
			Body:   recordsBody,
		})
	}
	return tableFiles
}

// writeHierarchicalOutput writes output to per-project directories
func (m *DNSModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all projects with data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectZones {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectRecords {
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

		outputData.ProjectLevelData[projectID] = DNSOutput{Table: tableFiles, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_DNS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *DNSModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allZones := m.getAllZones()
	allRecords := m.getAllRecords()

	zonesBody := m.zonesToTableBody(allZones)
	recordsBody := m.recordsToTableBody(allRecords)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	var tableFiles []internal.TableFile
	if len(zonesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_DNS_MODULE_NAME + "-zones",
			Header: m.getZonesHeader(),
			Body:   zonesBody,
		})
	}
	if len(recordsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_DNS_MODULE_NAME + "-records",
			Header: m.getRecordsHeader(),
			Body:   recordsBody,
		})
	}

	output := DNSOutput{Table: tableFiles, Loot: lootFiles}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_DNS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
