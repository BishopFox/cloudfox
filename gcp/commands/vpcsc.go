package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	vpcscservice "github.com/BishopFox/cloudfox/gcp/services/vpcscService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var orgID string

var GCPVPCSCCommand = &cobra.Command{
	Use:     globals.GCP_VPCSC_MODULE_NAME,
	Aliases: []string{"vpcsc", "service-controls", "sc"},
	Short:   "Enumerate VPC Service Controls",
	Long: `Enumerate VPC Service Controls configuration.

Features:
- Lists access policies for the organization
- Enumerates service perimeters (regular and bridge)
- Shows access levels and their conditions
- Identifies overly permissive configurations
- Analyzes ingress/egress policies

Note: Organization ID is auto-discovered from project ancestry. Use --org flag to override.`,
	Run: runGCPVPCSCCommand,
}

func init() {
	GCPVPCSCCommand.Flags().StringVar(&orgID, "org", "", "Organization ID (auto-discovered if not provided)")
}

type VPCSCModule struct {
	gcpinternal.BaseGCPModule
	OrgID        string
	Policies     []vpcscservice.AccessPolicyInfo
	Perimeters   []vpcscservice.ServicePerimeterInfo
	AccessLevels []vpcscservice.AccessLevelInfo
	LootMap      map[string]*internal.LootFile
	mu           sync.Mutex
}

type VPCSCOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o VPCSCOutput) TableFiles() []internal.TableFile { return o.Table }
func (o VPCSCOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPVPCSCCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_VPCSC_MODULE_NAME)
	if err != nil {
		return
	}

	// Auto-discover org ID if not provided
	effectiveOrgID := orgID
	if effectiveOrgID == "" {
		cmdCtx.Logger.InfoM("Auto-discovering organization ID...", globals.GCP_VPCSC_MODULE_NAME)
		orgsSvc := orgsservice.New()

		// Method 1: Try to get org ID from project ancestry
		if len(cmdCtx.ProjectIDs) > 0 {
			discoveredOrgID, err := orgsSvc.GetOrganizationIDFromProject(cmdCtx.ProjectIDs[0])
			if err == nil {
				effectiveOrgID = discoveredOrgID
				cmdCtx.Logger.InfoM(fmt.Sprintf("Discovered organization ID from project ancestry: %s", effectiveOrgID), globals.GCP_VPCSC_MODULE_NAME)
			}
		}

		// Method 2: Fallback to searching for accessible organizations
		if effectiveOrgID == "" {
			orgs, err := orgsSvc.SearchOrganizations()
			if err == nil && len(orgs) > 0 {
				// Extract org ID from name (format: "organizations/ORGID")
				effectiveOrgID = strings.TrimPrefix(orgs[0].Name, "organizations/")
				cmdCtx.Logger.InfoM(fmt.Sprintf("Discovered organization ID from search: %s (%s)", effectiveOrgID, orgs[0].DisplayName), globals.GCP_VPCSC_MODULE_NAME)
			}
		}

		// If still no org ID found, error out
		if effectiveOrgID == "" {
			cmdCtx.Logger.ErrorM("Could not auto-discover organization ID. Use --org flag to specify.", globals.GCP_VPCSC_MODULE_NAME)
			return
		}
	}

	module := &VPCSCModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		OrgID:         effectiveOrgID,
		Policies:      []vpcscservice.AccessPolicyInfo{},
		Perimeters:    []vpcscservice.ServicePerimeterInfo{},
		AccessLevels:  []vpcscservice.AccessLevelInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *VPCSCModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating VPC Service Controls for organization: %s", m.OrgID), globals.GCP_VPCSC_MODULE_NAME)

	svc := vpcscservice.New()

	// List access policies
	policies, err := svc.ListAccessPolicies(m.OrgID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_VPCSC_MODULE_NAME,
			fmt.Sprintf("Could not list access policies for organization %s", m.OrgID))
		return
	}
	m.Policies = policies

	if len(m.Policies) == 0 {
		logger.InfoM("No access policies found", globals.GCP_VPCSC_MODULE_NAME)
		return
	}

	// For each policy, list perimeters and access levels
	for _, policy := range m.Policies {
		perimeters, err := svc.ListServicePerimeters(policy.Name)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_VPCSC_MODULE_NAME,
				fmt.Sprintf("Could not list perimeters for policy %s", policy.Name))
		} else {
			m.Perimeters = append(m.Perimeters, perimeters...)
		}

		levels, err := svc.ListAccessLevels(policy.Name)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_VPCSC_MODULE_NAME,
				fmt.Sprintf("Could not list access levels for policy %s", policy.Name))
		} else {
			m.AccessLevels = append(m.AccessLevels, levels...)
		}
	}

	m.addAllToLoot()

	logger.SuccessM(fmt.Sprintf("Found %d access policy(ies), %d perimeter(s), %d access level(s)",
		len(m.Policies), len(m.Perimeters), len(m.AccessLevels)), globals.GCP_VPCSC_MODULE_NAME)
	m.writeOutput(ctx, logger)
}

func (m *VPCSCModule) initializeLootFiles() {
	m.LootMap["vpcsc-commands"] = &internal.LootFile{
		Name:     "vpcsc-commands",
		Contents: "# VPC Service Controls Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *VPCSCModule) addAllToLoot() {
	// Add policies to loot
	for _, policy := range m.Policies {
		m.LootMap["vpcsc-commands"].Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# POLICY: %s\n"+
				"# =============================================================================\n"+
				"# Title: %s\n"+
				"# Parent: %s\n"+
				"\n# Describe access policy:\n"+
				"gcloud access-context-manager policies describe %s\n\n"+
				"# List perimeters:\n"+
				"gcloud access-context-manager perimeters list --policy=%s\n\n"+
				"# List access levels:\n"+
				"gcloud access-context-manager levels list --policy=%s\n\n",
			policy.Name, policy.Title, policy.Parent,
			policy.Name, policy.Name, policy.Name,
		)
	}

	// Add perimeters to loot
	for _, perimeter := range m.Perimeters {
		m.LootMap["vpcsc-commands"].Contents += fmt.Sprintf(
			"# -----------------------------------------------------------------------------\n"+
				"# PERIMETER: %s (Policy: %s)\n"+
				"# -----------------------------------------------------------------------------\n"+
				"# Title: %s\n"+
				"# Type: %s\n"+
				"# Resources: %d\n"+
				"# Restricted Services: %d\n"+
				"# Ingress Policies: %d\n"+
				"# Egress Policies: %d\n"+
				"\n# === ENUMERATION COMMANDS ===\n\n"+
				"# Describe perimeter:\n"+
				"gcloud access-context-manager perimeters describe %s --policy=%s\n\n"+
				"# List protected resources:\n"+
				"gcloud access-context-manager perimeters describe %s --policy=%s --format=\"value(status.resources)\"\n\n"+
				"# List restricted services:\n"+
				"gcloud access-context-manager perimeters describe %s --policy=%s --format=json | jq '.status.restrictedServices'\n\n"+
				"# List ingress policies (who can access from outside):\n"+
				"gcloud access-context-manager perimeters describe %s --policy=%s --format=json | jq '.status.ingressPolicies'\n\n"+
				"# List egress policies (what can leave the perimeter):\n"+
				"gcloud access-context-manager perimeters describe %s --policy=%s --format=json | jq '.status.egressPolicies'\n\n",
			perimeter.Name, perimeter.PolicyName,
			perimeter.Title, perimeter.PerimeterType,
			len(perimeter.Resources), len(perimeter.RestrictedServices),
			perimeter.IngressPolicyCount, perimeter.EgressPolicyCount,
			perimeter.Name, perimeter.PolicyName,
			perimeter.Name, perimeter.PolicyName,
			perimeter.Name, perimeter.PolicyName,
			perimeter.Name, perimeter.PolicyName,
			perimeter.Name, perimeter.PolicyName,
		)

		// Exploit/bypass commands
		m.LootMap["vpcsc-commands"].Contents += "# === EXPLOIT / BYPASS COMMANDS ===\n\n"

		if perimeter.IngressPolicyCount > 0 {
			m.LootMap["vpcsc-commands"].Contents += fmt.Sprintf(
				"# Ingress policies exist - check for overly permissive access:\n"+
					"# Review which identities/access levels are allowed ingress\n"+
					"gcloud access-context-manager perimeters describe %s --policy=%s --format=json | jq '.status.ingressPolicies[] | {from: .ingressFrom, to: .ingressTo}'\n\n",
				perimeter.Name, perimeter.PolicyName,
			)
		}

		if perimeter.EgressPolicyCount > 0 {
			m.LootMap["vpcsc-commands"].Contents += fmt.Sprintf(
				"# Egress policies exist - check for data exfil paths:\n"+
					"# Review what services/resources can send data outside the perimeter\n"+
					"gcloud access-context-manager perimeters describe %s --policy=%s --format=json | jq '.status.egressPolicies[] | {from: .egressFrom, to: .egressTo}'\n\n",
				perimeter.Name, perimeter.PolicyName,
			)
		}

		if perimeter.PerimeterType == "PERIMETER_TYPE_BRIDGE" {
			m.LootMap["vpcsc-commands"].Contents += "# [FINDING] This is a BRIDGE perimeter - it connects two perimeters\n" +
				"# Bridge perimeters can be used to exfiltrate data between perimeters\n" +
				"# Check which perimeters are bridged and what services flow between them\n\n"
		}

		// Common bypass techniques
		m.LootMap["vpcsc-commands"].Contents += fmt.Sprintf(
			"# VPC-SC Bypass Techniques:\n"+
				"# 1. If you have access to a project INSIDE the perimeter, use it as a pivot\n"+
				"# 2. Check if any access levels use overly permissive IP ranges\n"+
				"# 3. Look for services NOT in the restricted list (data can flow through unrestricted services)\n"+
				"# 4. Check for ingress policies that allow specific identities you control\n"+
				"# 5. Use Cloud Shell (if accessible) - it may bypass VPC-SC\n\n"+
				"# Test if you're inside the perimeter:\n"+
				"gcloud storage ls gs://BUCKET_IN_PERIMETER 2>&1 | grep -i 'Request is prohibited by organization'\n\n"+
				"# Check dry-run mode (violations logged but not blocked):\n"+
				"gcloud access-context-manager perimeters describe %s --policy=%s --format=json | jq '.useExplicitDryRunSpec'\n\n",
			perimeter.Name, perimeter.PolicyName,
		)
	}

	// Add access levels to loot
	for _, level := range m.AccessLevels {
		ipSubnets := "-"
		if len(level.IPSubnetworks) > 0 {
			ipSubnets = strings.Join(level.IPSubnetworks, ", ")
		}
		regions := "-"
		if len(level.Regions) > 0 {
			regions = strings.Join(level.Regions, ", ")
		}

		m.LootMap["vpcsc-commands"].Contents += fmt.Sprintf(
			"# -----------------------------------------------------------------------------\n"+
				"# ACCESS LEVEL: %s (Policy: %s)\n"+
				"# -----------------------------------------------------------------------------\n"+
				"# Title: %s\n"+
				"# IP Subnets: %s\n"+
				"# Regions: %s\n"+
				"# Members: %d\n"+
				"\n# Describe access level:\n"+
				"gcloud access-context-manager levels describe %s --policy=%s\n\n",
			level.Name, level.PolicyName,
			level.Title, ipSubnets, regions, len(level.Members),
			level.Name, level.PolicyName,
		)
	}
}

func (m *VPCSCModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *VPCSCModule) buildTables() []internal.TableFile {
	var tables []internal.TableFile

	// Access Policies table
	if len(m.Policies) > 0 {
		policyHeader := []string{"Policy", "Title", "Parent", "Created", "Updated"}
		var policyBody [][]string
		for _, policy := range m.Policies {
			policyBody = append(policyBody, []string{
				policy.Name,
				policy.Title,
				policy.Parent,
				policy.CreateTime,
				policy.UpdateTime,
			})
		}
		tables = append(tables, internal.TableFile{
			Name:   "vpcsc-policies",
			Header: policyHeader,
			Body:   policyBody,
		})
	}

	// Service Perimeters table
	if len(m.Perimeters) > 0 {
		perimeterHeader := []string{
			"Policy", "Name", "Title", "Type", "Resources", "Restricted Services",
			"Ingress Policies", "Egress Policies",
		}
		var perimeterBody [][]string
		for _, perimeter := range m.Perimeters {
			perimeterBody = append(perimeterBody, []string{
				perimeter.PolicyName,
				perimeter.Name,
				perimeter.Title,
				perimeter.PerimeterType,
				fmt.Sprintf("%d", len(perimeter.Resources)),
				fmt.Sprintf("%d", len(perimeter.RestrictedServices)),
				fmt.Sprintf("%d", perimeter.IngressPolicyCount),
				fmt.Sprintf("%d", perimeter.EgressPolicyCount),
			})
		}
		tables = append(tables, internal.TableFile{
			Name:   "vpcsc-perimeters",
			Header: perimeterHeader,
			Body:   perimeterBody,
		})
	}

	// Access Levels table - one row per member
	if len(m.AccessLevels) > 0 {
		levelHeader := []string{"Policy", "Name", "Title", "IP Subnets", "Regions", "Member"}
		var levelBody [][]string
		for _, level := range m.AccessLevels {
			ipSubnets := "-"
			if len(level.IPSubnetworks) > 0 {
				ipSubnets = strings.Join(level.IPSubnetworks, ", ")
			}
			regions := "-"
			if len(level.Regions) > 0 {
				regions = strings.Join(level.Regions, ", ")
			}

			if len(level.Members) > 0 {
				// One row per member
				for _, member := range level.Members {
					levelBody = append(levelBody, []string{
						level.PolicyName,
						level.Name,
						level.Title,
						ipSubnets,
						regions,
						member,
					})
				}
			} else {
				// Access level with no members
				levelBody = append(levelBody, []string{
					level.PolicyName,
					level.Name,
					level.Title,
					ipSubnets,
					regions,
					"-",
				})
			}
		}
		tables = append(tables, internal.TableFile{
			Name:   "vpcsc-access-levels",
			Header: levelHeader,
			Body:   levelBody,
		})
	}

	return tables
}

func (m *VPCSCModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *VPCSCModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := VPCSCOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output location - prefer org-level, fall back to project-level
	orgID := ""
	if m.OrgID != "" {
		orgID = m.OrgID
	} else if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	if orgID != "" {
		// Place at org level
		outputData.OrgLevelData[orgID] = output
	} else if len(m.ProjectIDs) > 0 {
		// Fall back to first project level if no org discovered
		outputData.ProjectLevelData[m.ProjectIDs[0]] = output
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_VPCSC_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *VPCSCModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := VPCSCOutput{Table: tables, Loot: lootFiles}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"org", []string{m.OrgID}, []string{m.OrgID}, m.Account, output)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_VPCSC_MODULE_NAME,
			"Could not write output")
	}
}
